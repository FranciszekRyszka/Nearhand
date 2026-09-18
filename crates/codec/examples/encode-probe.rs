//! Capture the desktop, hardware-encode it, and report on the stream.
//!
//! The second instrument for the M0 measurements, after `capture-probe`: it
//! times the encoder, checks the bitstream is what the viewer will expect, and
//! writes it to a raw `.h264` file that any player or decoder can open.
//!
//! ```text
//! cargo run --release -p nearhand-codec --example encode-probe
//! cargo run --release -p nearhand-codec --example encode-probe -- --seconds 10 --out screen.h264
//! ```
//!
//! Scroll some text or drag a window while it runs; an idle desktop produces
//! almost nothing to encode, which is the point.

use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

use nearhand_codec::EncoderConfig;
use nearhand_codec::h264::{NalType, nal_units, sps_profile_level};
use nearhand_core::Codec;

struct Args {
    seconds: u64,
    display: u8,
    bitrate_kbps: u32,
    fps: u8,
    out: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        seconds: 5,
        display: 0,
        bitrate_kbps: 8_000,
        fps: 60,
        out: "encode-probe.h264".to_owned(),
    };
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        let value = raw.get(i + 1);
        match raw[i].as_str() {
            "--seconds" => {
                args.seconds = value.and_then(|v| v.parse().ok()).unwrap_or(args.seconds)
            }
            "--display" => {
                args.display = value.and_then(|v| v.parse().ok()).unwrap_or(args.display)
            }
            "--bitrate" => {
                args.bitrate_kbps = value
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(args.bitrate_kbps)
            }
            "--fps" => args.fps = value.and_then(|v| v.parse().ok()).unwrap_or(args.fps),
            "--out" => args.out = value.cloned().unwrap_or(args.out),
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!(
                    "usage: encode-probe [--seconds N] [--display N] [--bitrate KBPS] [--fps N] [--out FILE]"
                );
                std::process::exit(2);
            }
        }
        i += 2;
    }
    args
}

fn fail(what: &str, e: impl std::fmt::Display) -> ! {
    eprintln!("{what}: {e}");
    std::process::exit(1);
}

fn main() {
    let args = parse_args();

    let mut capturer = nearhand_capture::open(args.display)
        .unwrap_or_else(|e| fail(&format!("could not open display {}", args.display), e));

    // The first acquire after duplication starts returns the full desktop
    // straight away, so this also tells us the encode size.
    let first = loop {
        match capturer.next_frame(Duration::from_millis(500)) {
            Ok(Some(frame)) => break frame,
            Ok(None) => continue,
            Err(e) => fail("capture failed", e),
        }
    };

    let config = EncoderConfig {
        codec: Codec::H264,
        width: first.width,
        height: first.height,
        bitrate_kbps: args.bitrate_kbps,
        max_fps: args.fps,
    };
    println!(
        "encoding display {} at {}x{}, {} kbps, {} fps cap, for {}s",
        args.display, first.width, first.height, args.bitrate_kbps, args.fps, args.seconds
    );
    println!("scroll or drag something to give the encoder work\n");

    let mut encoder =
        nearhand_codec::encoder(config).unwrap_or_else(|e| fail("could not open encoder", e));
    let mut out = File::create(&args.out).unwrap_or_else(|e| fail("could not create output", e));

    let mut stats = Stats::default();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.seconds);
    let keyframe_request_at = started + Duration::from_secs(args.seconds) / 2;
    let mut keyframe_requested = false;

    let mut frame = Some(first);
    loop {
        if let Some(captured) = frame.take() {
            let t0 = Instant::now();
            let result = encoder.encode(&captured);
            let spent = t0.elapsed();
            stats.frames_in += 1;

            match result {
                Ok(Some(encoded)) => {
                    // The first call also builds the hardware session; keep it
                    // out of the steady-state numbers.
                    if stats.first_encode.is_none() {
                        stats.first_encode = Some(spent);
                    } else {
                        stats.encode_times.push(spent);
                    }
                    stats.frames_out += 1;
                    stats.bytes += encoded.data.len();
                    if encoded.keyframe {
                        stats.keyframes += 1;
                        if stats.awaiting_forced_keyframe {
                            stats.forced_keyframe_honoured = true;
                            stats.awaiting_forced_keyframe = false;
                        }
                    } else if stats.awaiting_forced_keyframe {
                        // The frame right after the request was not an IDR.
                        stats.awaiting_forced_keyframe = false;
                    }
                    if encoded.capture_ts_us != captured.capture_ts_us {
                        stats.timestamp_mismatches += 1;
                    }
                    stats.inspect(&encoded.data);
                    if let Err(e) = out.write_all(&encoded.data) {
                        fail("could not write output", e);
                    }
                }
                Ok(None) => stats.late += 1,
                Err(e) => {
                    stats.errors += 1;
                    println!("encode error: {e}");
                }
            }
        }

        if Instant::now() >= deadline {
            break;
        }
        if !keyframe_requested && Instant::now() >= keyframe_request_at {
            encoder.request_keyframe();
            keyframe_requested = true;
            stats.awaiting_forced_keyframe = true;
        }

        match capturer.next_frame(Duration::from_millis(16)) {
            Ok(next) => frame = next,
            Err(e) => {
                stats.errors += 1;
                println!("capture error: {e}");
            }
        }
    }

    stats.report(started.elapsed(), &args.out, keyframe_requested);
}

#[derive(Default)]
struct Stats {
    frames_in: u32,
    frames_out: u32,
    late: u32,
    errors: u32,
    keyframes: u32,
    bytes: usize,
    first_encode: Option<Duration>,
    encode_times: Vec<Duration>,
    timestamp_mismatches: u32,
    awaiting_forced_keyframe: bool,
    forced_keyframe_honoured: bool,
    sps: u32,
    pps: u32,
    idr: u32,
    slices: u32,
    profile_level: Option<(u8, u8)>,
}

impl Stats {
    fn inspect(&mut self, access_unit: &[u8]) {
        for nal in nal_units(access_unit) {
            match nal.kind {
                NalType::Sps => {
                    self.sps += 1;
                    self.profile_level = self.profile_level.or(sps_profile_level(&nal));
                }
                NalType::Pps => self.pps += 1,
                NalType::Idr => self.idr += 1,
                NalType::Slice => self.slices += 1,
                _ => {}
            }
        }
    }

    fn report(&mut self, elapsed: Duration, out: &str, keyframe_requested: bool) {
        let secs = elapsed.as_secs_f64();
        println!("--- {secs:.1}s ---");
        println!("frames in:       {}", self.frames_in);
        println!(
            "frames out:      {} ({} late, {} errors)",
            self.frames_out, self.late, self.errors
        );
        println!("keyframes:       {}", self.keyframes);
        if keyframe_requested {
            // Still awaiting means no frame came after the request at all — the
            // desktop was idle, which says nothing about the encoder.
            let verdict = match (self.awaiting_forced_keyframe, self.forced_keyframe_honoured) {
                (true, _) => "untested (no frame arrived after the request)",
                (false, true) => "honoured on the next frame",
                (false, false) => "NOT honoured on the next frame",
            };
            println!("forced keyframe: {verdict}");
        }
        println!(
            "output:          {} KiB, {:.0} kbps average",
            self.bytes / 1024,
            self.bytes as f64 * 8.0 / 1000.0 / secs
        );

        if let Some(first) = self.first_encode {
            println!(
                "first frame:     {:.1} ms, including encoder setup",
                first.as_secs_f64() * 1000.0
            );
        }
        if !self.encode_times.is_empty() {
            self.encode_times.sort();
            let pick = |q: f64| {
                let i = ((self.encode_times.len() - 1) as f64 * q).round() as usize;
                self.encode_times[i].as_secs_f64() * 1000.0
            };
            println!(
                "encode time:     p50 {:.2} ms, p95 {:.2} ms, max {:.2} ms ({} frames)",
                pick(0.5),
                pick(0.95),
                pick(1.0),
                self.encode_times.len()
            );
        }

        println!(
            "NAL units:       {} SPS, {} PPS, {} IDR, {} P slices",
            self.sps, self.pps, self.idr, self.slices
        );
        if let Some((profile, level)) = self.profile_level {
            let name = match profile {
                66 => "Baseline",
                77 => "Main",
                100 => "High",
                _ => "other",
            };
            println!(
                "SPS:             profile {profile} ({name}), level {:.1}",
                level as f64 / 10.0
            );
        }
        if self.timestamp_mismatches > 0 {
            println!(
                "timestamps:      {} outputs did not carry their capture time",
                self.timestamp_mismatches
            );
        } else if self.frames_out > 0 {
            println!("timestamps:      every output carried its capture time");
        }
        println!("written to:      {out}");
    }
}

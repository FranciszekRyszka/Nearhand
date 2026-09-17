//! Capture the desktop for a few seconds and report what came back.
//!
//! This is the instrument for the M0 measurements: it answers "does capture
//! work on this machine", "how many frames does a given workload produce", and
//! "does an idle desktop really cost nothing".
//!
//! ```text
//! cargo run -p nearhand-capture --example capture-probe
//! cargo run -p nearhand-capture --example capture-probe -- --seconds 10 --display 1
//! ```
//!
//! Leave the desktop alone for one run and scroll a page of text for another:
//! the first should report almost no frames, the second a steady stream with
//! small dirty rectangles.

use std::time::{Duration, Instant};

fn main() {
    let mut seconds = 5u64;
    let mut display = 0u8;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seconds" | "-s" => {
                i += 1;
                seconds = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(seconds);
            }
            "--display" | "-d" => {
                i += 1;
                display = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(display);
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("usage: capture-probe [--seconds N] [--display N]");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let mut capturer = match nearhand_capture::open(display) {
        Ok(capturer) => capturer,
        Err(e) => {
            eprintln!("could not open display {display}: {e}");
            std::process::exit(1);
        }
    };

    match capturer.displays() {
        Ok(displays) if displays.is_empty() => println!("no displays attached"),
        Ok(displays) => {
            println!("displays:");
            for d in displays {
                let primary = if d.primary { " (primary)" } else { "" };
                println!(
                    "  [{}] {}x{} at {},{}{primary}",
                    d.id, d.width, d.height, d.x, d.y
                );
            }
        }
        Err(e) => println!("could not enumerate displays: {e}"),
    }

    println!("\ncapturing display {display} for {seconds}s — move a window or scroll something\n");

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let started = Instant::now();

    let mut frames = 0u32;
    let mut idle_polls = 0u32;
    let mut errors = 0u32;
    let mut total_dirty = 0usize;
    let mut full_frames = 0u32;
    let mut first_ts_us = None;
    let mut last_ts_us = 0u64;
    let mut largest_gap = Duration::ZERO;
    let mut last_frame_at = Instant::now();

    while Instant::now() < deadline {
        match capturer.next_frame(Duration::from_millis(100)) {
            Ok(Some(frame)) => {
                frames += 1;
                total_dirty += frame.dirty.len();
                if frame.dirty.is_empty() {
                    full_frames += 1;
                }
                if first_ts_us.is_none() {
                    first_ts_us = Some(frame.capture_ts_us);
                    println!("first frame: {}x{}", frame.width, frame.height);
                }
                last_ts_us = frame.capture_ts_us;

                let gap = last_frame_at.elapsed();
                if gap > largest_gap {
                    largest_gap = gap;
                }
                last_frame_at = Instant::now();
            }
            // Nothing changed within the timeout: the desktop is idle.
            Ok(None) => idle_polls += 1,
            Err(e) => {
                errors += 1;
                println!("error: {e}");
            }
        }
    }

    let elapsed = started.elapsed();
    println!("\n--- {:.1}s ---", elapsed.as_secs_f64());
    println!(
        "frames:          {frames} ({:.1}/s)",
        frames as f64 / elapsed.as_secs_f64()
    );
    println!("idle polls:      {idle_polls}");
    println!("errors:          {errors}");

    if frames > 0 {
        println!(
            "dirty rects:     {total_dirty} total, {:.1} per frame",
            total_dirty as f64 / frames as f64
        );
        println!("full frames:     {full_frames} (no dirty metadata)");
        println!(
            "largest gap:     {:.1} ms",
            largest_gap.as_secs_f64() * 1000.0
        );

        if let Some(first) = first_ts_us {
            // The capture clock is the performance counter, so this only has to
            // be self-consistent — it is compared against itself, never against
            // the viewer's wall clock.
            let span_us = last_ts_us.saturating_sub(first);
            println!(
                "capture clock:   spanned {:.2}s across the run",
                span_us as f64 / 1_000_000.0
            );
        }
    }

    if frames == 0 && errors == 0 {
        println!("\nNo frames, no errors: the desktop never changed. Try again while scrolling.");
    }
}

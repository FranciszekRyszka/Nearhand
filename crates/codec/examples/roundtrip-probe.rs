//! Capture → encode → decode → convert, on one machine, and measure the result.
//!
//! Proves the decoder independently of any window or network: it times decode
//! and colour conversion, then reads one original frame and its round-tripped
//! twin back from the GPU and compares them. PSNR says whether the pixels
//! survived; a wrong colour matrix or a misread surface shows up as a number
//! far below what encoding loss alone produces.
//!
//! ```text
//! cargo run --release -p nearhand-codec --example roundtrip-probe -- --seconds 5
//! ```
//!
//! With `--save DIR`, the compared pair is also written as `original.ppm` and
//! `decoded.ppm` for a look by eye.

#[cfg(not(windows))]
fn main() {
    eprintln!("roundtrip-probe needs the Windows capture, encode and decode backends");
}

#[cfg(windows)]
fn main() {
    if let Err(e) = windows_probe::run() {
        eprintln!("roundtrip-probe: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows_probe {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use nearhand_codec::mediafoundation::convert::{Conversion, create_texture};
    use nearhand_codec::mediafoundation::{MfDecoder, VideoConverter};
    use nearhand_codec::{Decoder, EncoderConfig};
    use nearhand_core::Codec;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CPU_ACCESS_READ,
        D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
        ID3D11Device, ID3D11Texture2D,
    };
    use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};

    type Error = Box<dyn std::error::Error>;

    struct Args {
        seconds: u64,
        display: u8,
        save: Option<PathBuf>,
    }

    fn parse_args() -> Args {
        let mut args = Args {
            seconds: 5,
            display: 0,
            save: None,
        };
        let raw: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < raw.len() {
            let value = raw.get(i + 1);
            match raw[i].as_str() {
                "--seconds" => args.seconds = value.and_then(|v| v.parse().ok()).unwrap_or(5),
                "--display" => args.display = value.and_then(|v| v.parse().ok()).unwrap_or(0),
                "--save" => args.save = value.map(PathBuf::from),
                other => {
                    eprintln!("unknown argument: {other}");
                    std::process::exit(2);
                }
            }
            i += 2;
        }
        args
    }

    pub fn run() -> Result<(), Error> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let args = parse_args();
        let mut capturer = nearhand_capture::open(args.display)?;
        let first = loop {
            if let Some(frame) = capturer.next_frame(Duration::from_millis(500))? {
                break frame;
            }
        };
        let size = (u32::from(first.width), u32::from(first.height));
        let device = unsafe { first.surface.GetDevice() }?;

        let mut encoder = nearhand_codec::encoder(EncoderConfig {
            codec: Codec::H264,
            width: first.width,
            height: first.height,
            bitrate_kbps: 10_000,
            max_fps: 60,
        })?;
        let mut decoder = MfDecoder::new(&device, size)?;
        let mut converter = VideoConverter::new(&device, Conversion::NV12_TO_RGB, size, 60)?;
        let bind = (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32;
        let presented = create_texture(&device, size, DXGI_FORMAT_B8G8R8A8_UNORM, bind, 0)?;

        println!(
            "round-tripping display {} at {}x{} for {}s — scroll something",
            args.display, size.0, size.1, args.seconds
        );

        let mut decode_ms = Vec::new();
        let mut convert_ms = Vec::new();
        let (mut frames_in, mut frames_out, mut late, mut ts_mismatch) = (0u32, 0u32, 0u32, 0u32);
        // Which stage lags: the encoder handing back an older frame, or the
        // decoder doing so.
        let (mut encoder_none, mut encoder_older, mut decoder_older) = (0u32, 0u32, 0u32);
        let mut sample_taken = None;
        let midpoint = Instant::now() + Duration::from_secs(args.seconds) / 2;
        let deadline = Instant::now() + Duration::from_secs(args.seconds);

        let mut pending = Some(first);
        while Instant::now() < deadline {
            let Some(frame) = pending.take() else {
                pending = capturer.next_frame(Duration::from_millis(16))?;
                continue;
            };
            frames_in += 1;

            // Snapshot one original before anything else touches it: the
            // capturer reuses its texture for the next frame.
            let original = if sample_taken.is_none() && Instant::now() >= midpoint {
                Some(read_back(&device, &frame.surface)?)
            } else {
                None
            };

            let Some(encoded) = encoder.encode(&frame)? else {
                encoder_none += 1;
                pending = capturer.next_frame(Duration::from_millis(16))?;
                continue;
            };
            if encoded.capture_ts_us != frame.capture_ts_us {
                encoder_older += 1;
            }

            let t0 = Instant::now();
            let decoded = decoder.decode(&encoded)?;
            let t1 = Instant::now();
            let Some(decoded) = decoded else {
                late += 1;
                pending = capturer.next_frame(Duration::from_millis(16))?;
                continue;
            };
            if decoded.capture_ts_us != encoded.capture_ts_us {
                decoder_older += 1;
            }
            converter.convert(
                &decoded.surface.texture,
                decoded.surface.slice,
                (decoded.width, decoded.height),
                &presented,
            )?;
            // Conversion is queued on the GPU; a read-back would wait for it,
            // so time only the CPU-side submission here.
            let t2 = Instant::now();
            frames_out += 1;
            decode_ms.push((t1 - t0).as_secs_f64() * 1000.0);
            convert_ms.push((t2 - t1).as_secs_f64() * 1000.0);
            if decoded.capture_ts_us != frame.capture_ts_us {
                ts_mismatch += 1;
            }

            // Only compare a frame with itself; an older decoded frame paired
            // with this capture would measure the difference between frames.
            if let Some(original) = original
                && decoded.capture_ts_us == frame.capture_ts_us
            {
                let roundtrip = read_back(&device, &presented)?;
                sample_taken = Some((original, roundtrip, decoded.width, decoded.height));
            }

            pending = capturer.next_frame(Duration::from_millis(16))?;
        }

        println!("--- results ---");
        println!(
            "frames:          {frames_in} captured, {frames_out} decoded, {late} held back by the decoder"
        );
        println!(
            "encoder:         {encoder_none} inputs gave no output, {encoder_older} outputs were an older frame"
        );
        println!(
            "decoder:         {late} inputs gave no output, {decoder_older} outputs were an older frame"
        );
        report("decode", &mut decode_ms);
        report("convert submit", &mut convert_ms);
        println!(
            "timestamps:      {}",
            if ts_mismatch == 0 {
                "every decoded frame kept its capture time".to_owned()
            } else {
                format!("{ts_mismatch} frames lost their capture time")
            }
        );

        match sample_taken {
            Some((original, roundtrip, w, h)) => {
                let psnr = psnr(&original, &roundtrip, w, h);
                println!(
                    "fidelity:        PSNR {psnr:.1} dB over {w}x{h} (original vs round trip)"
                );
                if let Some(dir) = args.save {
                    std::fs::create_dir_all(&dir)?;
                    write_ppm(&dir.join("original.ppm"), &original, w, h)?;
                    write_ppm(&dir.join("decoded.ppm"), &roundtrip, w, h)?;
                    println!("saved:           {}", dir.display());
                }
            }
            None => println!("fidelity:        no frame arrived after the midpoint to compare"),
        }
        Ok(())
    }

    fn report(what: &str, samples: &mut [f64]) {
        if samples.is_empty() {
            return;
        }
        samples.sort_by(f64::total_cmp);
        let at = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
        println!(
            "{what:<16} p50 {:.2} ms, p95 {:.2} ms, max {:.2} ms",
            at(0.5),
            at(0.95),
            at(1.0)
        );
    }

    /// Copy a BGRA texture into CPU memory, tightly packed.
    fn read_back(device: &ID3D11Device, texture: &ID3D11Texture2D) -> Result<Vec<u8>, Error> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { texture.GetDesc(&mut desc) };
        let staging_desc = D3D11_TEXTURE2D_DESC {
            MipLevels: 1,
            ArraySize: 1,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
            ..desc
        };
        let mut staging = None;
        unsafe { device.CreateTexture2D(&staging_desc, None, Some(&mut staging)) }?;
        let staging = staging.ok_or("no staging texture")?;
        let context = unsafe { device.GetImmediateContext() }?;
        unsafe { context.CopyResource(&staging, texture) };

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe { context.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped)) }?;
        let (w, h) = (desc.Width as usize, desc.Height as usize);
        let mut pixels = Vec::with_capacity(w * h * 4);
        for row in 0..h {
            let start = unsafe { (mapped.pData as *const u8).add(row * mapped.RowPitch as usize) };
            pixels.extend_from_slice(unsafe { std::slice::from_raw_parts(start, w * 4) });
        }
        unsafe { context.Unmap(&staging, 0) };
        Ok(pixels)
    }

    /// Peak signal-to-noise ratio over the RGB channels of two BGRA images.
    fn psnr(a: &[u8], b: &[u8], w: u32, h: u32) -> f64 {
        let (w, h) = (w as usize, h as usize);
        let stride = a.len() / h.max(1);
        let mut sum = 0f64;
        let mut n = 0u64;
        for y in 0..h {
            for x in 0..w {
                let i = y * stride + x * 4;
                for c in 0..3 {
                    let d = f64::from(a[i + c]) - f64::from(b[i + c]);
                    sum += d * d;
                    n += 1;
                }
            }
        }
        let mse = sum / n.max(1) as f64;
        if mse == 0.0 {
            return f64::INFINITY;
        }
        10.0 * (255.0 * 255.0 / mse).log10()
    }

    fn write_ppm(path: &std::path::Path, bgra: &[u8], w: u32, h: u32) -> Result<(), Error> {
        let stride = bgra.len() / (h as usize).max(1);
        let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = y * stride + x * 4;
                out.extend_from_slice(&[bgra[i + 2], bgra[i + 1], bgra[i]]);
            }
        }
        std::fs::write(path, out)?;
        Ok(())
    }
}

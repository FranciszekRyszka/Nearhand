# Performance

Measurements behind the M0 exit criterion: capture to screen in under 80 ms on
a LAN. Every figure here names how it was taken, and each measured change was
kept only if the numbers held up.

## Setup

| | |
| --- | --- |
| Machine | Windows 11, AMD Radeon RX 6600 XT |
| Displays | 2560×1440 primary, 1920×1080 secondary |
| Encoder | `AMDh264Encoder` (hardware MFT), H.264 High, CBR 10 Mbit/s, no B-frames |
| Decoder | Microsoft H.264 MFT with DXVA |
| Presentation | `wgpu` on Direct3D 12, mailbox, maximum frame latency 1 |
| Network | **Loopback** — agent and viewer on the same machine |
| Build | release |

Load: a small always-on-top window scrolling text and moving a block at about
60 Hz, plus whatever else was on screen.

## Capture to present

Measured by the viewer on every frame and reported every two seconds. The
agent stamps each frame with DXGI's `LastPresentTime`; the viewer places it on
its own clock with a Ping/Pong offset estimate and subtracts it from the time
its own present call returned.

| Stage | p50 |
| --- | --- |
| **Total, capture → present** | **12.5–12.8 ms** (p95 18–21 ms) |
| Capture + encode + send + reassemble | 11.5–11.8 ms |
| Decode + convert | 0.4 ms |
| Render + present call | 0.6 ms |

58.5 fps at 2560×1440, no loss, 0 superseded frames in steady state. The
encoder is most of the first stage: 7.7 ms p50 in isolation (`encode-probe`).

**Against the 80 ms target, this is about a sixth.**

### What the number includes and leaves out

* **Included:** DWM composition to capture, colour conversion, hardware
  encode, packetisation, QUIC, reassembly, hardware decode, conversion back,
  the render and the present call.
* **Not included: the display's scan-out** after the present call — up to one
  refresh (16.7 ms at 60 Hz), half of one on average. Software cannot see it.
  Adding that average gives an estimated glass-to-glass of **~21 ms p50**.
* **Loopback, not a LAN.** A wired LAN adds roughly its round trip, typically
  well under a millisecond, but this has not yet been measured on two machines.
* **Clock offset.** On loopback both ends read the same performance counter,
  so the true offset is exactly zero. The estimator reported **+0.01 ms ±
  0.09**, which is the check that it works. Between two machines its error is
  bounded by half the best round trip.

## Stage measurements

| Probe | Result |
| --- | --- |
| `capture-probe` | 0.6% of one core capturing 137 frames in 8 s |
| `encode-probe` | encode p50 7.73 ms, p95 8.66 ms over 284 frames; 5.4% of one core for capture, conversion and encode |
| `roundtrip-probe` | 431 frames in, 431 out; decode submit p50 0.19 ms; PSNR 37.5 dB against the original frame |

## Found by measuring

Each of these was invisible in the code and obvious in the numbers.

| Problem | Effect | Fix |
| --- | --- | --- |
| Decoder low-latency mode set as `VT_BOOL`, as documented | rejected silently; decoder held ~7 frames | pass it as `VT_UI4` |
| Byte-stream decoder waits for the next picture to begin | every frame shown 2 frames late (17–36 ms) | end each frame with an access unit delimiter |
| Decoder invents output timestamps once delimiters are added | timestamps drifted tens of ms | pair outputs with inputs in order |
| Frame-rate cap measured from the end of encoding | 40 fps instead of 60; p50 18.5 ms instead of 12.8 | measure from capture |

## Known weakness

Recovery from packet loss collapses at realistic loss rates: at 2% simulated
datagram loss only 19 of 312 frames were delivered, because a 1440p keyframe is
about 200 datagrams and rarely arrives whole. Wired LAN loss is near zero, so
the figures above are unaffected. See `docs/protocol.md` for the options; this
has to be fixed before M2.

## Reproducing

```bash
nearhand-agent listen --bind 127.0.0.1:4433
nearhand-viewer direct 127.0.0.1:4433 --fingerprint <printed> --seconds 10
```

The viewer prints a latency summary every two seconds, and the overlay (F1)
shows the same figures live.

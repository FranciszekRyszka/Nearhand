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

## Under packet loss

Lost video chunks are asked for again and resent (`docs/protocol.md`, "Repair").
Measured on loopback with `--simulate-loss`, which discards that share of the
datagrams arriving at the viewer, repairs included. Release build, watching the
2560×1440 monitor while a small window on it animated text and a block at
about 30 fps, 12 s per run:

| Loss | Frames delivered | Repaired | Given up | Keyframe requests | Latency p50 | p95 |
| --- | --- | --- | --- | --- | --- | --- |
| 0% | 352 | 0 | 0 | 0 | 10–11 ms | 18–22 ms |
| 2% | 367 | 98 | 0 | 0 | 10–12 ms | 23–29 ms |
| 5% | 352 | 174 | 0 | 0 | 10–14 ms | 35–40 ms |

The frame rate is untouched and no frame was given up. A repaired frame, and
the frames queued behind it, arrive one repair later, which shows in p95 rather
than p50.

Before repair, loss was answered only with a keyframe. At 2% loss that
delivered 19 of 312 frames (2.3 fps), because a 1440p keyframe is about 200
datagrams and arrived whole about 0.98²⁰⁰ ≈ 2% of the time.

On loopback the round trip is under a millisecond, so these runs show the
mechanism rather than its cost on a real WAN. There, each repair costs about
one round trip on top.

## Rate control

The agent re-decides the video bitrate and frame rate every 500 ms
(`crates/agent/src/rate.rs`). Its signals, in order:

1. **Its own send backlog.** Video waiting in QUIC's datagram buffer is exact
   and immediate. Over about 150 ms of it, the sender stops taking frames, so
   capture pauses rather than queueing stale frames.
2. **Queueing delay.** This is QUIC's smoothed round trip over the lowest
   smoothed value of the last 10 s.
3. **Loss**, as QUIC counts it. Repairable random loss up to 10% holds the
   rate rather than cutting it.

The frame rate follows how much of the budget the encoder uses: it goes up
when there is room, and down only when frames would get too few bits for sharp
text. The encoder's rate-control buffer is capped at 250 ms, so a keyframe
cannot burst to many times the average frame.

Measured through `netem` (below) on loopback, release build, 2560×1440 under
the same ~30 fps load, 30 s per run. The agent's ceiling is 10 Mbit/s:

| Link | Frames (fps) | Given up | Keyframe requests | Latency p50 / p95 | Bitrate target |
| --- | --- | --- | --- | --- | --- |
| No limit, no delay | 1353 (43) | 0 | 0 | 16 / 27 ms | 10 Mbit/s throughout |
| 3 Mbit/s, 20 ms each way, 100 ms queue | 846 (27) | 25 | 8 | 51 / 98 ms | 0.7–4.5 Mbit/s |
| 20 ms each way, 5% loss both ways | 1135 (36) | 19 | 8 | 89 / 169 ms | 10 Mbit/s throughout |

The latency figures include the link's own 40 ms round trip.

What it took to get there, each step found by measuring:

| Problem | Effect | Fix |
| --- | --- | --- |
| QUIC's 4 MB datagram buffer filled during an early burst, then drained at link rate for seconds | the link's queue stayed full long after the target had dropped; target fell to the 300 kbit/s floor at 5 fps | read the backlog; back off on it and stop taking frames while it is long |
| Kept cutting while the queue was already draining | same collapse, more slowly | never back off while the round trip is falling; wait 1 s between back-offs |
| Frame rate derived from pixel count, as if every frame changed the whole screen | 11 fps while using a third of the budget | frame rate follows budget use |
| Baseline was QUIC's lifetime minimum RTT, one lucky sample | ordinary jitter read as a queue | lowest smoothed RTT of the last 10 s |
| Uncapped keyframes of several hundred KB | each overflowed a 3 Mbit/s link's queue and asked for the next | 250 ms rate-control buffer |
| Climbed 8% a step straight through the level that last overflowed | a sawtooth with latency spikes | 2% steps near that level for 10 s |
| quinn's default Cubic treats every loss as congestion | at 5% random loss: 6.5 fps and a 300 kbit/s target | BBR |

On BBR: with Cubic instead, the 3 Mbit/s link does a little better (1 frame
given up, 3 keyframe requests, p95 76 ms). BBR briefly probes about 25% above
the link rate, which a queue as shallow as 100 ms punishes. But at 5% random
loss Cubic delivers 6.5 fps where BBR delivers 36, and random loss is what
Wi-Fi does. quinn marks its BBR as experimental. It decides only how fast
packets leave, never what they say.

Known limit: a queue that stands for more than 10 s becomes the new baseline.
Loss and the send backlog still catch the overflow, but later than delay would.

## Reproducing

```bash
nearhand-agent listen --bind 127.0.0.1:4433
nearhand-viewer direct 127.0.0.1:4433 --fingerprint <printed> --seconds 10
```

The viewer prints a latency summary every two seconds, and the overlay
(Ctrl+Shift+F1) shows the same figures live. `--simulate-loss N` makes the
viewer discard N% of arriving video datagrams.

For a slower or lossier link, put the `netem` example between the two. It is a
UDP forwarder with a bandwidth cap, a tail-drop queue, delay and loss:

```bash
cargo run --release -p nearhand-transport --example netem -- \
    --listen 127.0.0.1:5000 --upstream 127.0.0.1:4433 \
    --down-kbps 3000 --delay-ms 20 --queue-ms 100 --loss 0
nearhand-viewer direct 127.0.0.1:5000 --fingerprint <printed>
```

`nearhand-agent listen -v` logs every rate-control interval: target, what was
sent, round trip, and how the interval was read.

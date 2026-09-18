# Protocol

> **Status: v0, unstable.** The wire format may change without notice until 1.0.
> The types live in `crates/core/src/proto.rs`; this document explains them.

## Versioning

Every connection opens with `Control::Hello { version, caps }`. `PROTOCOL_VERSION`
is bumped on any incompatible change while we are pre-1.0 — there is no
compatibility shim, a mismatch simply closes the connection.

Encoding is [`postcard`](https://docs.rs/postcard). Moving to protobuf before 1.0
is still open, and depends on whether third-party clients turn out to matter.

## Transport

One QUIC connection carries everything. The channel split is the whole point of
choosing QUIC:

| Channel | QUIC primitive | Why |
| --- | --- | --- |
| Video | Unreliable datagrams | A late frame is useless; on loss, ask for a keyframe instead of retransmitting |
| Input | Reliable stream, highest priority | A lost key-up event means a stuck key |
| Cursor shape + position | Reliable stream | The viewer draws the cursor locally, so it feels instant |
| Clipboard | Reliable stream, low priority | Must never starve video |
| Control | Reliable stream | Rare and small |

For the browser viewer the same messages travel over WebTransport, with a
WebSocket fallback where WebTransport is unavailable.

## Session

The TLS handshake negotiates ALPN `nearhand/0`, so a peer on a different
protocol version fails there rather than mid-stream. The viewer then opens one
bidirectional stream for control and speaks first:

```text
viewer                         agent
  Hello { version, caps }  ──▶
                           ◀──  Hello { version, caps }
                           ◀──  MonitorList
  StartVideo               ──▶
                           ◀══  video datagrams …
  RequestKeyframe / SetQuality / StartVideo (another monitor) / Bye
```

Messages on streams carry a 4-byte little-endian length prefix, then the
postcard body; bodies over 64 KiB are refused before anything is allocated
(`core::wire`).

Either side can end the session. The one that sends `Bye` waits briefly for the
other to close the connection, because closing at once would discard the `Bye`
itself. Close codes (`core::proto::close`) travel with a readable reason:

| Code | Meaning |
| --- | --- |
| 0 | Normal goodbye |
| 1 | Protocol violation |
| 2 | Protocol version mismatch |
| 3 | Agent busy with another viewer |
| 4 | Capture or encoding failed; the reason says which |

In M0 the agent's certificate is self-signed and generated per run. The viewer
pins its SHA-256 fingerprint, and the handshake still proves the agent holds the
key. From M2 the fingerprint comes from the server instead.

## Video framing

One encoded frame is split into `VideoChunk` datagrams (`core::video`). Chunks
are sized from the connection's current datagram limit, which QUIC's path MTU
discovery raises over time, minus 32 bytes reserved for the chunk header.

A frame is complete when chunks `0..chunks` for one `frame_id` have arrived.
Nothing is retransmitted. A frame missing chunks is abandoned when a newer frame
completes, or after 100 ms with no datagrams at all.

Every encoded frame consumes a `frame_id`, sent or not, and ids continue across
monitor switches. The viewer detects loss by gaps. After any loss it drops every
frame until a keyframe arrives, because a P-frame decoded against a missing
reference comes out corrupted. It asks for a keyframe at most every 250 ms, and
the agent re-encodes its last frame if the desktop is idle, so a keyframe does
not wait for the screen to change.

`capture_ts_us` rides along for the latency overlay: capture-to-present is
measured end to end, RTT-corrected when the clocks are not synced.

### Known weakness: keyframe recovery under loss

Keyframe-only recovery does not survive realistic loss. At 1440p a keyframe is
about 200 datagrams, and at 2% datagram loss all of them arrive only
0.98²⁰⁰ ≈ 2% of the time. Measured on loopback with 2% simulated loss: 19 of
312 frames delivered, 2.3 fps, even though every one of 31 requested keyframes
was sent. The frames that were delivered were correct.

Wired LAN loss is close to zero, so M0 measurements are unaffected. Wi-Fi and
WAN are not. The fix has to come before M2; options are retransmitting missing
chunks within a short deadline, forward error correction, or intra refresh /
long-term references so a loss costs part of a frame rather than a keyframe.

## Input

Coordinates are normalised to `0..=65535`, so the viewer never needs to know the
host resolution and nothing breaks on a resolution change mid-session.

Keys are physical scancodes; the host applies its own layout. `Input::Text` is
the fallback for what does not map — dead keys, AltGr combinations, and the
Polish characters that motivated the fallback in the first place.

## To document before 1.0

- [ ] Handshake sequence diagram, including the server-issued session ticket
- [ ] Capability negotiation rules when codec sets do not intersect
- [ ] Clipboard message shapes
- [ ] Cursor shape encoding
- [ ] Error and close codes

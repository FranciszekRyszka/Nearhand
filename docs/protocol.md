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

## Video framing

One encoded frame is split into `VideoChunk` datagrams. `MAX_DATAGRAM_PAYLOAD`
(1200 bytes) keeps a chunk inside the QUIC datagram limit on any path, so
nothing fragments.

A frame is complete when chunks `0..chunks` for one `frame_id` have arrived. An
incomplete frame is dropped — never held — and the viewer sends
`Control::RequestKeyframe` if it cannot decode.

`capture_ts_us` rides along for the latency overlay: capture-to-present is
measured end to end, RTT-corrected when the clocks are not synced.

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

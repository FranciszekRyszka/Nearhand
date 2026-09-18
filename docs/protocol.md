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

## Finding a device: the server

A viewer reaches an agent by its ten-digit device ID, through the server both
are configured with. The server speaks its own protocol, ALPN
`nearhand-server/1` (`core::rendezvous`), and steps out once the two are
introduced:

```text
agent            server             viewer
  Register  ──▶                                  (agent presents its certificate)
            ◀──  Registered { id }
                             ◀──  Connect { id }
            ◀──  Incoming { session, viewer's addresses }
  (sends a packet to each, opening its own firewall to them)
  Ready     ──▶
                             ──▶  Peer { fingerprint, agent's addresses }
  ◀═══════ QUIC, viewer to agent, pinned to the fingerprint ═══════
```

* The agent connects with its certificate as a TLS client certificate. The
  server derives the agent's ID from it, so an agent cannot register under an
  ID that is not its own.
* A device ID is the first 64 bits of the certificate's SHA-256, modulo 10¹⁰,
  shown as `123 456 7890`. It is stable for as long as the key is, and it is a
  name, not a proof: see `docs/security.md`.
* Each side reports the local address it would use toward the server, and the
  server adds the address it sees. The viewer tries them all at once, from
  the same socket it reached the server from.
* The agent never listens on a fixed port. It accepts the viewer on the socket
  it uses for the server, after sending a packet to each of the viewer's
  addresses: a stateful firewall lets packets in only from where something
  went out to.
* The server allows each viewer address 10 introductions a minute.

## Session

The TLS handshake negotiates ALPN `nearhand/2`, so a peer on a different
protocol version fails there rather than mid-stream. The viewer then opens one
bidirectional stream for control and speaks first:

```text
viewer                         agent
  Hello { version, caps }  ──▶
                           ◀──  Hello { version, caps }
                           ◀──  AuthRequired           (portable agents only)
  Authenticate { password } ──▶
                           ◀──  MonitorList
  StartVideo               ──▶
                           ◀══  video datagrams …
  Nack / RequestKeyframe / SetQuality / StartVideo (another monitor) / Bye

  (own stream) Input …     ──▶
                           ◀──  Cursor …  (own stream)
  (own stream) Clipboard … ◀─▶  Clipboard …  (own stream)
```

Messages on streams carry a 4-byte little-endian length prefix, then the
postcard body; bodies over 320 KiB are refused before anything is allocated
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
| 5 | Wrong password |

Every certificate is self-signed over an Ed25519 key. The viewer pins the
agent's certificate by its SHA-256 fingerprint, which the server reports (or,
with `direct`, is copied by hand). The handshake still proves the agent holds
the key. A certificate is a pure function of its key, so a key kept on disk
gives the same fingerprint on every run.

## Video framing

One encoded frame is split into `VideoChunk` datagrams (`core::video`). Chunks
are sized from the connection's current datagram limit, which QUIC's path MTU
discovery raises over time, minus 32 bytes reserved for the chunk header.

A frame is complete when chunks `0..chunks` for one `frame_id` have arrived.
Every encoded frame consumes a `frame_id`, sent or not, and ids continue across
monitor switches. Frames go to the decoder strictly in id order, because each
P-frame is decoded against the one before it.

`capture_ts_us` rides along for the latency overlay: capture-to-present is
measured end to end, RTT-corrected when the clocks are not synced.

### Repair

The viewer asks for lost chunks again with `Nack { frame_id, chunks }`; an
empty list means the whole frame, for a frame of which nothing arrived. The
agent keeps the datagrams of the last 64 frames (at most 16 MiB) and resends
what is asked for. It ignores frames it no longer holds. Newer frames wait in
the viewer until the repair lands.

A chunk counts as lost, and is asked for, as soon as a later chunk of its frame
or any chunk of a newer frame has arrived. A frame's trailing chunks count as
lost after a quiet spell of one round trip plus 5 ms. A frame is asked for
again after 1.5 round trips plus 10 ms. The viewer gives up on a frame once it
has made no progress for 3 round trips plus 60 ms. The core keeps no clock: the
viewer passes the time in and derives these timings from the round trip.

A frame given up on breaks the reference chain. From then on the viewer drops
every frame until a keyframe arrives, because a P-frame decoded against a
missing reference comes out corrupted. It asks for a keyframe at most every
250 ms, and the agent re-encodes its last frame if the desktop is idle, so a
keyframe does not wait for the screen to change. A complete keyframe already
waiting behind a stuck frame is jumped to at once.

Before repair existed, keyframes were the only recovery, and 2% loss let 19 of
312 frames through. `docs/performance.md` has the measurements before and
after.

### Rate

The agent picks the bitrate and frame rate itself, from what QUIC reports and
its own send backlog (`docs/performance.md`, "Rate control"). `SetQuality`
from the viewer sets a ceiling that rate control stays under, not a fixed
rate. The frame rate asked for in `StartVideo` is a ceiling too.

### Switching monitors

`StartVideo` for another monitor mid-session stops capture and encoding on
the old one and starts them on the new one. Frame ids carry on, and the new
stream opens with a keyframe. The new picture size travels only in that
keyframe's sequence parameter set, so a viewer's decoder must follow a
resolution change mid-stream. The native viewer sizes its frame textures for
the largest monitor in `MonitorList`, so a switch never rebuilds them.

## Input

The viewer opens a unidirectional stream whenever it likes, at the highest
priority of its streams, and writes `StreamKind::Input` as the first message.
Every later message on it is an `Input`, framed like the control stream. Every
unidirectional stream starts with a `StreamKind`, so clipboard and file
transfer can get streams of their own later. The agent closes the connection
with a protocol error if a stream starts with anything else, or if an input
message cannot be decoded.

Coordinates are normalised to `0..=65535` on the watched monitor, where 65535
is the last pixel. The viewer never needs to know the host resolution, and
nothing breaks on a resolution change mid-session. Input goes to the monitor
the viewer last asked for in `StartVideo`, and to the primary monitor before
that.

Keys are physical positions: USB HID usages from the keyboard page (0x07),
whatever the viewer's platform. The host maps them to its own scancodes and
applies its own layout. A held key is sent down again for each auto-repeat.
`Input::Text` is the fallback for keys that have no usage.

| Message | Units |
| --- | --- |
| `MouseButton` | 0 left, 1 right, 2 middle, 3 back, 4 forward (`proto::mouse`) |
| `Wheel` | 120 per detent (`WHEEL_NOTCH`); positive `dy` scrolls up, positive `dx` right |

Neither side trusts the other to release what it pressed. The viewer sends
key-ups for everything it holds when its window loses focus. The agent
releases everything still held when the session ends, however it ends.

## Clipboard

Each side opens one unidirectional stream tagged `StreamKind::Clipboard`, the
first time its clipboard changes during the session, at the lowest priority
of its streams. Every message on it is a `Clipboard::Text`.

* Only changes are sent, never the contents at connect, so starting a session
  does not overwrite what the other side has copied.
* Text travels with `\n` line endings; each side converts to its own.
* At most 256 KiB of UTF-8 (`Clipboard::MAX_TEXT`). A larger copy stays local,
  and receiving one is a protocol error.
* Each side remembers the last text that crossed in either direction and
  never sends that text back, so a paste does not echo.

Each side notices a change by polling its clipboard's change counter four
times a second, for the length of the session only.

## Cursor

The agent opens a unidirectional stream tagged `StreamKind::Cursor` at the
start of the session and keeps it across monitor switches. It carries the
host pointer's shape whenever it changes, and whether the pointer is visible on
the watched monitor.

The viewer uses the shape as its own pointer over the window instead of
drawing it into the picture. The pointer then follows the local mouse with no
round trip. It is shown at its own size, not scaled with the video.

Shapes are straight RGBA, at most 256 pixels a side, with the hotspot inside
the image. The viewer checks this before handing the image to the OS, and
closes the connection with a protocol error if it is not so. Windows pointer
pixels that invert the screen beneath them, like the text I-beam, cannot be
expressed in RGBA. They arrive black, outlined in white, so they stay visible
on any background.

DXGI reports the pointer only when it moves or changes. Until the host's
pointer first moves, the viewer shows its own default arrow.

## To document before 1.0

- [ ] Handshake sequence diagram, including the server-issued session ticket
- [ ] Capability negotiation rules when codec sets do not intersect
- [ ] Error and close codes

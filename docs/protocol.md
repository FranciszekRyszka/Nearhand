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

The browser viewer runs this same connection, byte for byte, inside a
WebTransport session with the server: a browser cannot open raw QUIC or
punch holes, so it always takes the relay, and its session's datagrams are
the tunnel (see *The relay* below).

Where WebTransport is not there — a browser without it, or a network that
blocks UDP — the page carries the same tunnel over a WebSocket to
`/api/v1/relay` on the console's own port instead, and says so beside the
frame rate. The first message asks to be introduced (`ToServer::Connect`),
the answer comes back as one message, and every message after that is one
packet of the session, exactly as a datagram would be. The signed-in
account and the console's origin are what the server checks before it
opens the tunnel; what runs inside it is still end-to-end encrypted to the
agent's key. TCP retransmits, so a lost packet holds up the ones behind
it: video is smoother over WebTransport where it works.

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
* The server reports the address it sees the agent at when the viewer asks,
  not when the agent registered: a NAT may have moved it since.
* The server allows each viewer address 10 introductions a minute.
* A viewer with an account sends `ConnectAs { id, addresses, token }`,
  `token` being an API token, instead of `Connect`. The server answers
  `Granted(signed grant)` before `Peer` if the user has a grant for the
  device, and `Refused(NotSignedIn)` or `Refused(NotAllowed)` if not —
  saying nothing about whether the device is online.
* A browser opens a WebTransport session to `https://<server>:<QUIC
  port>/nearhand` — the server tells the QUIC side's ALPNs apart, `h3` for
  browsers — sends `Connect { id, addresses: [] }` on its first stream, and
  reads `Peer` or `Refused` to the end of it. From then on the session's
  datagrams carry its relay tunnel, as a native viewer's connection's do.
  Its grant comes from the REST API (`POST /api/v1/devices/{id}/grant`),
  since WebTransport carries no cookie.
* An installed agent may also enroll, once, on a connection of its own with
  its certificate: `Enroll { token, name, os, version }` ──▶, answered by
  `Enrolled { id }` or `Refused(Enrollment)`. That records the device in the
  server's list; it registers as above either way. An enrolled device takes
  its ID from another key holding it.
* An agent follows `Register` with `Running { os, version }` on the same
  stream. A managed device's entry in the server's list follows it, so a
  device that updated itself is listed as what it became. A server older
  than the agent does not know the message and drops the connection, so a
  server is upgraded before its agents — which is the order anyway, since
  agents take their updates from it.
* An installed agent asks for updates the same way, with its certificate:
  `Update { product, platform, version }` ──▶, answered by `Offered(None)`,
  or `Offered(Some(signed release))` when the server's administrators offer
  a release newer than `version` (`core::release`). To take it, the agent
  sends `Fetch` ──▶, and the server writes the package's bytes on the stream
  and finishes it. The agent reads at most the size the signed release
  gives, and installs the package only if the release key built into it
  signed the release, the package's SHA-256 matches, and it is newer than
  what runs. A server sending packages to eight agents already answers
  `Refused(Busy)` instead of offering.

### Through NATs

The address the server sees is the one a NAT maps each side's socket to, so
the same exchange gets a direct connection through most NATs. The agent's
packet opens its NAT to the viewer, and the viewer's connection attempt opens
its own NAT to the agent's answer. Whether that works depends on the two NATs:

| Agent's NAT | Viewer's NAT | Direct connection |
|---|---|---|
| none, or one port per socket (most home routers) | none, or one port per socket | yes |
| one port per socket, answers only from that address and port | a new port per destination ("symmetric") | no |
| one port per socket, answers from any port of that address | symmetric | yes |
| symmetric | any | no |
| same network as the viewer | — | yes, over the local address |

Each row is a test, run against the real server, agent and viewer code over
a simulated network (`crates/server/src/netsim.rs`). Where there is no direct
path, the relay carries the session.

### The relay

The relay needs no port or connection of its own. The viewer's connection to
the server stays open after the introduction, and the server forwards QUIC
datagrams between it and the agent's registration connection:

```text
viewer ══ QUIC to the server ══ server ══ QUIC to the server ══ agent
          datagram: packet                datagram: session (u64, big-endian), packet
       └──────────────── QUIC, viewer to agent, pinned to the agent's key ────────────────┘
```

* Each datagram carries one whole packet of the viewer-to-agent connection,
  which runs inside exactly as it would directly: same handshake, same pinned
  key, same streams and datagrams. The server forwards ciphertext.
* On the agent's side, one connection carries every relayed viewer, so its
  datagrams start with the session number. The server adds it towards the
  agent and strips it towards the viewer. To QUIC, a relayed peer's address
  is in `100::/64`, a range reserved for discarding traffic, with the session
  number in the low 64 bits.
* A relayed packet is at least 1200 bytes, QUIC's minimum, so connections to
  the server start at a 1280-byte packet size to fit it with their own framing.
  The connection inside keeps to 1200 bytes, and its datagrams — video — are
  sized to fit.
* The viewer tries the direct addresses and the relay at once. A direct
  connection wins if it is made within a second of the relayed one being
  ready; otherwise, or once every direct attempt has failed, the relayed one
  is used. Connecting takes about a second at most when there is no direct
  path. When direct wins, the viewer closes its server connection, and the
  relay with it.
* The server forwards only between the two connections it paired, and only
  after the agent has answered `Ready`.

The relay costs one extra hop and a second layer of encryption. On loopback it
added about 0.2 ms to the round trip, with the frame rate unchanged.

## Session

The TLS handshake negotiates ALPN `nearhand/6`, so a peer on a different
protocol version fails there rather than mid-stream. The viewer then opens one
bidirectional stream for control and speaks first:

```text
viewer                         agent
  Hello { version, caps }  ──▶
                           ◀──  Hello { version, caps }
                           ◀──  AuthRequired { secret } (portable and installed agents)
  AuthStart { pake }       ──▶                          (proving a password)
                           ◀──  AuthAnswer { pake }
  AuthProve { proof }      ──▶
                           ◀──  AuthProved { proof }
    or Present { grant }   ──▶                          (installed with a token)
                           ◀──  AwaitingApproval       (when someone at the host decides)
                           ◀──  MonitorList
  StartVideo               ──▶
                           ◀══  video datagrams …
  Nack / RequestKeyframe / SetQuality / StartVideo (another monitor) / Bye

  (own stream) Input …     ──▶
                           ◀──  Cursor …  (own stream)
  (own stream) Clipboard … ◀─▶  Clipboard …  (own stream)
```

A password is never sent — not to the agent, and so not to anything between
the two. `AuthRequired` says what the password is and how to prepare it:
`OneTime` for the six digits a portable agent shows, used as they are read
out, or `Access { salt, iterations }` for an installed agent, which holds
only a PBKDF2-HMAC-SHA256 hash of its access password and so runs the
exchange with that hash; the viewer stretches what was typed the same way.
Both sides then run SPAKE2 over that material (`core::access`) and prove to
each other that they arrived at the same key.

The proofs are MACs over the transcript, keyed from the exchange with
keying material exported from the connection's TLS session as the salt (RFC
5705, label `nearhand access binding v1`, 32 bytes). Both ends of one
connection derive the same bytes; a server holding one connection to each
end does not, so it cannot pass an exchange through and stay in the middle.
The agent checks the viewer's proof first — a wrong one closes with code 5,
and counts against the agent's lockouts — and answers with its own, which
the viewer checks before it shows anything: without that, a viewer would
know the password reached *something*, not that it reached the device.
`secret` is `None` when an agent has no password at all, and only a grant
will do.

`Present` carries a grant the server signed (`core::grant`): the agent checks
it against the server key it pinned, and the grant's role limits the session
(`docs/security.md`).

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
| 5 | Wrong password, or a grant refused; the reason says why |
| 6 | The person at the host declined, or did not answer |
| 7 | The person at the host ended the session |

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

`Input::SecureAttention` is Ctrl+Alt+Del. No key injection can produce it,
and the viewer's own system keeps the real combination for itself, so the
viewer sends it for Ctrl+Alt+End, as Remote Desktop does. The agent passes it
to Windows' `SendSAS`, which acts on it only for an agent running as the
service.

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

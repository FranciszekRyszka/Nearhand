# Nearhand

A self-hosted, open-source remote desktop — an alternative to TeamViewer, AnyDesk and RustDesk that stays lightweight, minimal and fast.

There is no Nearhand-run infrastructure. Every install points at a server you run yourself.

> **Status: pre-alpha.** The workspace is scaffolded and the protocol types are in place; nothing connects to anything yet. See the roadmap below.

## Targets

Every design choice is judged against these:

| Target | Goal |
| --- | --- |
| Lightweight | Agent < 15 MB on disk, < 40 MB RAM idle, 0% CPU with no session |
| Fast | < 80 ms glass-to-glass on LAN, < 150 ms typical WAN, 60 fps at 1080p with hardware encode |
| Minimal | One agent binary, one viewer binary, one server binary, no runtime dependencies |
| Self-hosted | Server runs on 1 vCPU / 512 MB, SQLite by default, x86_64 and ARM64 |

Rust everywhere, so the protocol is implemented exactly once and the browser viewer is the same code compiled to WASM. Capture and encoding use what the OS already ships — no bundled libwebrtc, no bundled FFmpeg.

## Layout

One Cargo workspace:

| Crate | Kind | What it is |
| --- | --- | --- |
| `crates/core` | lib | Protocol, crypto, session state machine. No OS code; must compile to wasm32. |
| `crates/capture` | lib | Screen capture — DXGI on Windows, ScreenCaptureKit on macOS |
| `crates/codec` | lib | Encode and decode — Media Foundation, VideoToolbox, `openh264` fallback |
| `crates/input` | lib | Input injection — `SendInput`, `CGEvent` |
| `crates/agent` | bin | Runs on the controlled machine |
| `crates/viewer` | bin | Native controlling app |
| `crates/server` | bin | API, console, signaling, relay |

`capture`, `codec` and `input` are separate from `agent` because the viewer needs `codec` but not `capture`, platform `cfg` code stays out of the protocol crate, and each can be benchmarked alone.

## Documentation

- [docs/protocol.md](docs/protocol.md) — wire format and versioning
- [docs/security.md](docs/security.md) — threat model
- [docs/self-hosting.md](docs/self-hosting.md) — running your own server

## Building

Needs the stable Rust toolchain (`rust-toolchain.toml` pins it), plus the MSVC build tools on Windows or the Xcode command line tools on macOS.

```bash
cargo build --workspace
cargo test --workspace
```

What CI enforces, and what to run before pushing:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p nearhand-core --target wasm32-unknown-unknown
cargo deny check      # cargo install cargo-deny
```

## Roadmap

Ordered so the biggest unknown — end-to-end latency — is proven first.

| # | Milestone | Done when |
| --- | --- | --- |
| M0 | Latency proof of concept | Windows capture → HW encode → QUIC → native viewer on LAN, measured < 80 ms |
| M1 | Usable session | Mouse, keyboard, local cursor, clipboard text, multi-monitor, adaptive bitrate |
| M2 | Server + connectivity | Signaling, hole punching, relay, key pinning, attended quick-support |
| M3 | Windows unattended | Service, session switching, UAC + login screen, signed MSI |
| M4 | macOS agent + viewer | ScreenCaptureKit, VideoToolbox, permissions flow, notarized PKG |
| M5 | Managed devices | Accounts, TOTP, enrollment, groups, grants, audit log, console, REST API |
| M6 | Web viewer + v1.0 | WASM + WebCodecs over WebTransport, auto-update, Docker image, security review |

If M0 cannot get under about 80 ms on LAN, the pipeline is revisited before anything is built on top of it.

## Security

Built in from the start, not added later: Ed25519 device keys, TLS 1.3 between viewer and agent with pinned keys on both sides, the relay only ever forwarding ciphertext, outbound-only agent connections, and a visible indicator on the host for every session — there is no hidden mode, ever.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

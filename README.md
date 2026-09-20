# Nearhand

A self-hosted, open-source remote desktop — an alternative to TeamViewer, AnyDesk and RustDesk that stays lightweight, minimal and fast.

There is no Nearhand-run infrastructure. Every install points at a server you run yourself.

> **Status: pre-alpha.** Windows works end to end; macOS has not started. Use it for testing, not for anything that matters.

What works today, on Windows:

- **The session.** Capture, hardware encode, QUIC, hardware decode: **12.5 ms capture-to-present p50** at 2560×1440 on loopback, against an 80 ms target ([details](docs/performance.md)). Keyboard and mouse, the host's pointer drawn locally, clipboard text both ways, multiple monitors (Ctrl+Shift+F2), lost video repaired, bitrate and frame rate following the link. Machines without a hardware encoder — a VM — encode in software instead.
- **Quick support.** A portable agent shows an ID and a one-time password, asks the person at the machine before letting anyone in, and says on screen for as long as a session lasts that the computer is being controlled ([how](docs/self-hosting.md)). It connects directly through most home NATs, and through the server's relay where it cannot.
- **Unattended access.** The agent installs as a Windows service from an MSI, reachable with an access password ([how](docs/self-hosting.md#unattended-access-windows)). It follows the user onto the sign-in screen and UAC prompts (Ctrl+Alt+End sends Ctrl+Alt+Del), and shows an indicator for every session.
- **Managed devices.** Accounts with Argon2id passwords, TOTP and API tokens; agents enroll into a device list with groups and presence ([how](docs/self-hosting.md#enrollment)); users reach them with grants the agent checks against the server's key ([how](docs/self-hosting.md#grants)); a web console and an audit log cover it all ([how](docs/self-hosting.md#the-web-console)).
- **From a browser.** The same QUIC session compiled to WebAssembly, end-to-end encrypted to the agent, decoded with WebCodecs, with keyboard, mouse, clipboard text and the device's pointer ([how](docs/self-hosting.md#the-web-viewer)). It runs over WebTransport, or over a WebSocket where UDP does not get through.
- **Updates.** Releases are signed with the project's key; you upload one to your server and choose when to offer it, and agents install it themselves — never a package they cannot verify, and never during a session ([how](docs/self-hosting.md#updating-agents)).
- **The server.** One binary, or a Docker image with one volume ([how](docs/self-hosting.md#in-docker)).

Not there yet: macOS, and the security review before 1.0.

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
| `crates/codec` | lib | Encode and decode — Media Foundation (hardware, or Windows' software encoder), VideoToolbox |
| `crates/input` | lib | Input injection — `SendInput`, `CGEvent` |
| `crates/clipboard` | lib | Clipboard text sync — Win32 clipboard, `NSPasteboard` |
| `crates/transport` | lib | QUIC for the native binaries: endpoints, key pinning, stream framing |
| `crates/agent` | bin | Runs on the controlled machine |
| `crates/viewer` | bin | Native controlling app |
| `crates/server` | bin | API, console, signaling, relay |
| `crates/web-viewer` | lib (wasm32) | The browser viewer's session: QUIC to the agent and the protocol, compiled to WebAssembly |

`capture`, `codec` and `input` are separate from `agent` because the viewer needs `codec` but not `capture`, platform `cfg` code stays out of the protocol crate, and each can be benchmarked alone. `transport` is separate from `core` because it depends on `quinn` and tokio, while `core` has to compile for the browser viewer, which speaks WebTransport instead.

## Documentation

- [docs/protocol.md](docs/protocol.md) — wire format and versioning
- [docs/security.md](docs/security.md) — threat model
- [docs/self-hosting.md](docs/self-hosting.md) — running your own server
- [docs/performance.md](docs/performance.md) — latency measurements and how they were taken
- [docs/api.md](docs/api.md) — the REST API the console is built on
- [docs/releasing.md](docs/releasing.md) — how a release is built and signed

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
cargo check --manifest-path fuzz/Cargo.toml --all-targets
cargo deny check      # cargo install cargo-deny
```

The decoders are fuzzed too, weekly in CI and on demand: see
[fuzz/README.md](fuzz/README.md). It needs a nightly toolchain, so it is not
part of a normal build.

The web viewer is built separately, into `crates/server/web/pkg`, from where
the server's build embeds it (without it, the server builds and its `/view`
page says the viewer is missing). It needs the `wasm32-unknown-unknown`
target, `wasm-bindgen-cli` at the version in `Cargo.lock`, and clang for
`ring`:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.128 --locked
packaging/web/build.sh        # or packaging\web\build.ps1 -Llvm <an LLVM folder>
cargo build -p nearhand-server
```

## Roadmap

Ordered so the biggest unknown — end-to-end latency — is proven first.

| # | Milestone | Done when | State |
| --- | --- | --- | --- |
| M0 | Latency proof of concept | Windows capture → HW encode → QUIC → native viewer on LAN, measured < 80 ms | done |
| M1 | Usable session | Mouse, keyboard, local cursor, clipboard text, multi-monitor, adaptive bitrate | done |
| M2 | Server + connectivity | Signaling, hole punching, relay, key pinning, attended quick-support | done |
| M3 | Windows unattended | Service, session switching, UAC + login screen, signed MSI | done but for Authenticode signing |
| M4 | macOS agent + viewer | ScreenCaptureKit, VideoToolbox, permissions flow, notarized PKG | not started |
| M5 | Managed devices | Accounts, TOTP, enrollment, groups, grants, audit log, console, REST API | done |
| M6 | Web viewer + v1.0 | WASM + WebCodecs over WebTransport, auto-update, Docker image, security review | security review left |

If M0 cannot get under about 80 ms on LAN, the pipeline is revisited before anything is built on top of it.

## Security

Built in from the start, not added later: Ed25519 device keys, TLS 1.3 between viewer and agent with pinned keys on both sides, the relay only ever forwarding ciphertext, outbound-only agent connections, and a visible indicator on the host for every session — there is no hidden mode, ever.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

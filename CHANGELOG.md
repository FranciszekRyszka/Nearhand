# Changelog

What changed in each release, and what it means for machines already
running. Versions are `major.minor.patch`; before 1.0 the minor number
carries the breaking changes.

Two kinds of compatibility matter here, and they are not the same:

- **Session protocol** — between a viewer and an agent. Both ends must
  speak the same version; a mismatch fails in the TLS handshake with a
  clear reason rather than halfway through a session.
- **Server protocol** — between an agent or viewer and its server. It
  changes far less often, so an older agent can usually still register with
  a newer server, and take its self-update from it.

The order to upgrade in, when both change: the **server** first, then the
**agents** (offer them the new release in the console and they install it
themselves), then the **viewers**.

## Unreleased

Passwords are no longer sent anywhere, a machine can ask for a grant *and*
its password, viewers remember which key a device had, and both ends have a
`doctor` command that says what is in the way.

**Session protocol 5 → 6.** A viewer of this version cannot talk to an
agent of an older one, or the other way round: the handshake refuses, and
says so. The server protocol is unchanged, so an older agent still
registers with a newer server and still takes its self-update — which is
how agents get to this version.

### Security

- **Passwords are proved, never sent.** A viewer and an agent run SPAKE2
  over the password and then prove to each other that they reached the same
  key. The proofs are tied to the connection by keying material exported
  from its TLS session, so a server that answered with a key of its own and
  stood in the middle cannot pass the exchange through: it gets one guess
  per connection and learns nothing to use later. An installed agent still
  keeps only the PBKDF2 hash of its access password — that hash is what the
  exchange runs with, and the stretching moves to the viewer.
- **A grant *and* the password, where that is wanted.**
  `nearhand-agent install --password-with-grant` (or `set-password
  --with-grant`, or `PASSWORD_WITH_GRANT=1` for the MSI) makes a machine
  ask for both, so a management server that was taken over cannot open it
  by signing itself a grant. The grant still decides what the session may
  do.
- **Viewers remember a device's key.** The first time a viewer reaches a
  device it writes the fingerprint down; a later session under the same ID
  with another key stops before it starts. The native viewer needs
  `--trust-new-key` to go on; the browser asks. A reinstall does not trip
  it — a machine that loses its key gets a new ID with it.
  `nearhand-viewer known` lists what a viewer remembers, and
  `nearhand-viewer forget <id>` drops one device's key.
- **Fuzzing.** Five `cargo-fuzz` targets over everything that decodes bytes
  from elsewhere, weekly and on demand in CI, alongside the hostile-input
  test that runs on every build.

### Added

- **Viewers come back.** When an installed agent stops to start again —
  someone signing out or in, or the service restarting — it says it is going away
  (close code 8) rather than goodbye, and the native and browser viewers
  reconnect by themselves for up to two minutes. A refusal, a goodbye, or a
  failure before the first picture is final, as before. The native viewer's
  window says so across the top while it tries, and why once it stops,
  instead of freezing on the last picture without a word.
- **Type the clipboard.** Ctrl+Shift+F3 in the native viewer, and a *Type
  clipboard* button in the browser, type this computer's clipboard on the
  device as keystrokes — for the sign-in screen, a UAC prompt, or a console
  that takes no paste, where clipboard sync cannot reach. Line breaks and
  tabs go as Enter and Tab; up to 4096 characters at a time. Nothing
  changes on the agent.
- `nearhand-agent doctor` — the configuration, the device key, the service,
  the server's name and key, whether UDP gets out, and the end of the logs.
- `nearhand-server doctor` — the data folder, the key's fingerprint, the
  database, the certificate, both ports, and whether agents are told an
  address they could use. It changes nothing.
- `nearhand-server health` — whether the server on this machine answers on
  both ports: a QUIC handshake pinned to its own key, and the console's
  `/api/v1/health`. The Docker image uses it as its `HEALTHCHECK`, since a
  distroless image has no shell or `curl` to check with.
- `nearhand-server backup <folder>` — the server key and a consistent copy
  of the database, taken while the server serves. The distroless image has
  no shell to run `sqlite3` in, and a plain copy of a database in WAL mode
  can be short of the most recent writes.
- [docs/troubleshooting.md](docs/troubleshooting.md).
- `GET /api/v1/metrics`, in Prometheus' text format, for an
  administrator's API token: agents online, devices enrolled,
  introductions and refusals by reason, relay tunnels open and bytes
  relayed, ceilings reached, and agent packages sent. Counts only; no
  device, user or address appears on it.
- `nearhand-viewer devices` — the devices your user holds a grant for on a
  server, with their IDs, whether each is online and your role on it, over
  the same pinned connection the viewer connects through. A new message in
  the server protocol, added without changing its version: a server older
  than the viewer drops the question, and the viewer says the server may be
  older. With a token, `nearhand-viewer connect` takes a device's name
  from that list as well as its ID. `nearhand-viewer` on its own now
  prints its usage.

### Changed

- The relay carries at most `relay.max_gb` for one session — 100 GB by
  default, both directions together, 0 to lift it — and then lets the
  tunnel go. A session at the agent's default bitrate would take a day to
  reach that; an endless one run through someone else's server cannot.
- The server sweeps daily: console sessions and setup links past their
  time, and audit entries older than `audit.keep_days` — a year by
  default, 0 to keep them for ever. Nothing pruned them before, on a
  server meant to run for years on one small machine.
- The agent's logs turn over while it runs: past 10 MB a log becomes
  `<name>.1`, replacing the one before, and a new one starts. Before, the
  size was checked only when the agent started, so one that ran for months
  kept growing, and a restart past the limit wiped the log that led up to
  it.
- Settings from the environment may be numbers and true/false, not only
  text: `NEARHAND_AUDIT_KEEP_DAYS=30` works as the file's `keep_days = 30`
  does.

### Fixed

- A device's version in the console followed it after a self-update: an
  agent now reports what it runs every time it registers, rather than only
  at enrollment.
- The native viewer showed nothing — the last picture, or black — once the
  host's screen grew bigger than any of its monitors had been at the start:
  a change of resolution, or a session come back to at another size. It
  now rebuilds its frame slots for the new size and carries on, without
  waiting for a keyframe.

## 0.2.0 — 2026-09-20

The same code as 0.1.0 under a new version number, cut to prove that an
installed agent updates itself: a server offered it, an agent downloaded
it, checked the release key and the hash, installed it and came back nine
seconds later.

## 0.1.0 — 2026-09-20

The first release. Windows only; macOS is next.

- **Sessions.** DXGI Desktop Duplication into a hardware H.264 encoder,
  over QUIC, with software encode where there is no hardware one. Mouse,
  keyboard, local cursor, clipboard text, multiple monitors, adaptive
  bitrate, and repair of lost chunks instead of waiting for a keyframe.
- **Connectivity.** A server that introduces a viewer to a device by its
  ten-digit ID, hole punching, and a relay for the paths that cannot be
  punched — the relay only ever forwards ciphertext.
- **Quick support.** A portable agent with a one-time password and a window
  the person at the machine allows each session from.
- **Unattended Windows.** An MSI that installs a service, an access
  password the server never sees, capture that follows the user onto the
  sign-in screen and UAC prompts, and an indicator for every session.
- **Managed devices.** Accounts with Argon2id passwords, TOTP and API
  tokens; enrollment into a device list with groups and presence; grants
  the agent checks against the server's key; an audit log; a web console
  and the REST API under it.
- **Browser viewer.** WebAssembly and WebCodecs over WebTransport, with a
  WebSocket fallback for networks that block UDP.
- **Self-update.** Releases signed with the project's key, held and offered
  by your own server; agents install only what that key signed and only
  something newer than they run.
- **Packaging.** A Docker image for the server, and a signed release built
  from a tag.

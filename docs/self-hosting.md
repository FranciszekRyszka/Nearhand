# Self-hosting

> **Status: early.** The server introduces agents to viewers by device ID,
> relays sessions that cannot go direct, and has user accounts behind a REST
> API. Enrollment, groups and grants, the console and a Docker image are still
> to come (M5, M6); the sections about them say so.

## What works today

```bash
# On the server — prints the fingerprint agents and viewers pin:
nearhand-server serve --bind 0.0.0.0:443 --key /var/lib/nearhand/server.key

# On the machine to be helped — opens a window with an ID and a password,
# and asks there before letting anyone in (--console: no window, no asking):
nearhand-agent portable --server 203.0.113.10:443 --server-fingerprint <fingerprint>

# On the helper's machine:
nearhand-viewer connect "123 456 7890" --server 203.0.113.10:443 \
    --server-fingerprint <fingerprint> --password <password>
```

Viewer and agent connect directly where they can: on the same network, or
across the internet through the NATs of most home connections ([which
ones](protocol.md#through-nats)). Where they cannot — often on mobile networks
and in offices — the server relays the session, still end-to-end encrypted
between the two. The viewer says which way it went. A relayed session's video
passes through the server, so the server's bandwidth matters then: a few
Mbit/s per session, both ways combined. `--relay-only` on the viewer forces the
relay, to test it.

### Unattended access (Windows)

On a machine that should be reachable with no one at it, install the agent
as a service, from an administrator terminal:

```bat
nearhand-agent install --server 203.0.113.10:443 --server-fingerprint <fingerprint>
```

It asks for an access password (at least 10 characters), prints the
machine's ID, and starts the `Nearhand` service, which keeps the agent
running in whichever session is at the console. The viewer connects with the
ID and the access password, as with the portable agent. Because the agent
runs as SYSTEM, the viewer also sees and controls the sign-in and lock
screens and UAC prompts; Ctrl+Alt+End in the viewer sends Ctrl+Alt+Del. `nearhand-agent
status` shows the ID again, `set-password` changes the password, and
`uninstall` removes the service (`--purge` also removes the key, and so the
ID). Its files — key, configuration, logs — are in `%ProgramData%\Nearhand`,
readable by administrators only. While a session lasts, a small window on
the user's desktop says so, and can end it.

Or install the MSI (built by `packaging/windows/build-msi.ps1`, and by CI on
every push), which does the same and suits a silent rollout:

```bat
msiexec /i nearhand-agent-0.1.0-x64.msi /qn SERVER=203.0.113.10:443 ^
    SERVER_FINGERPRINT=<fingerprint> ACCESS_PASSWORD=<password>
```

An MSI installation is removed from *Installed apps* (or `msiexec /x`), not
with `nearhand-agent uninstall`; both keep the key, and so the ID. The MSI is
not signed yet, so Windows warns before running it.

Testing it: [docs/testing-on-windows.md](testing-on-windows.md).

There is no Nearhand-run infrastructure — no project ID server, no project
relay. Every install points at a server you run.

## Requirements

One static binary, x86_64 or ARM64. It is built to run on **1 vCPU and 512 MB**
with SQLite, which covers a small fleet comfortably.

## Ports

| Port | Protocol | Carries |
| --- | --- | --- |
| 443 | TCP | Console, REST API, WebSocket fallback |
| 443 | UDP | QUIC: control, WebTransport, relay |

**UDP 443 must reach the server directly.** A reverse proxy can front the TCP
side, but QUIC cannot be proxied by nginx or Caddy in the usual sense — if UDP
does not pass through, every session falls back to TCP and gets slower.

## Configuration

One TOML file, `nearhand.toml` in the working folder unless `--config` says
otherwise, and every setting in it can come from the environment instead:
`NEARHAND_<SECTION>_<KEY>`, for example `NEARHAND_HTTP_BIND`. No file at all
means the defaults.

```toml
[data]
dir = "/var/lib/nearhand"      # server.key, nearhand.db, https.crt/.key

[quic]
bind = "0.0.0.0:443"           # UDP: agents, viewers, the relay

[http]
bind = "0.0.0.0:443"           # TCP: the REST API (and the console, to come)
tls = "self-signed"            # made on first start; browsers warn about it
# tls = "files"                # a real certificate:
# cert = "/etc/letsencrypt/live/desk.example.com/fullchain.pem"
# key = "/etc/letsencrypt/live/desk.example.com/privkey.pem"
# tls = "none"                 # plain HTTP behind a reverse proxy; bind to 127.0.0.1
public_url = "https://desk.example.com"   # for the links the server prints
```

The HTTPS certificate is separate from the server key agents and viewers pin:
browsers do not accept the Ed25519 certificate that key makes. Built-in ACME
(Let's Encrypt) is planned; until then use `tls = "files"` with a certificate
from certbot or similar, or a reverse proxy for the TCP side.

## Running it

The binary, as a service — a systemd unit, or a Windows service wrapper.
(A Docker image comes with M6.)

```bash
nearhand-server serve                 # or: --config /etc/nearhand/nearhand.toml
```

The first start, with no users, prints how to create the first
administrator: one API call with a one-time token, valid for 24 hours.
`nearhand-server admin-link` prints a new one. The console will turn this into
a link to click.

### The REST API

Everything is under `/api/v1`, JSON in and out; [api.md](api.md) lists it.
Scripts authenticate with an API token (`Authorization: Bearer nht_…`), which
any user makes for themselves (`POST /api/v1/me/tokens`) and which is shown
once. Passwords are Argon2id hashes; TOTP (any authenticator app) can be
turned on per user; wrong passwords are limited per address and per name.

## Enrollment

> Not yet: this is the next step of M5.

An admin creates a token — single-use or multi-use, with an expiry and a target
group — and the agent registers against it:

```bash
nearhand-agent install --server desk.example.com --token <token>
```

The server can also generate **pre-configured installers** (MSI or PKG with the
address and token baked in) for rollout through GPO, Intune or MDM.

## Backup

The data folder: the SQLite file (`nearhand.db`, with its `-wal` file while
the server runs — or stop it first, or use `sqlite3 nearhand.db ".backup
copy.db"`) and the server key. That is the whole backup.

**Losing the server key means re-enrolling every device**, because agents pin it.
Back it up somewhere other than the server.

# Self-hosting

> **Status: early.** Today the server introduces portable agents to viewers
> by device ID, and nothing else. The rest of this page is the shape it is being
> built to: relay (M2), and accounts, enrollment and the console (M5).

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

One TOML file, with environment variables overriding it. TLS is either built-in
ACME or a certificate you supply.

## Running it

Either `docker compose up` with a single volume, or the binary plus a systemd
unit. The volume holds the SQLite file and the server key.

The first start prints a one-time admin setup link.

## Enrollment

An admin creates a token — single-use or multi-use, with an expiry and a target
group — and the agent registers against it:

```bash
nearhand-agent install --server desk.example.com --token <token>
```

The server can also generate **pre-configured installers** (MSI or PKG with the
address and token baked in) for rollout through GPO, Intune or MDM.

## Backup

The SQLite file and the server key. That is the whole backup.

**Losing the server key means re-enrolling every device**, because agents pin it.
Back it up somewhere other than the server.

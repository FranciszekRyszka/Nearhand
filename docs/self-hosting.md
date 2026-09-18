# Self-hosting

> **Status: early.** Today the server introduces portable agents to viewers
> by device ID, and nothing else. The rest of this page is the shape it is being
> built to: relay (M2), and accounts, enrollment and the console (M5).

## What works today

```bash
# On the server — prints the fingerprint agents and viewers pin:
nearhand-server serve --bind 0.0.0.0:443 --key /var/lib/nearhand/server.key

# On the machine to be helped — prints an ID and a password:
nearhand-agent portable --server 203.0.113.10:443 --server-fingerprint <fingerprint>

# On the helper's machine:
nearhand-viewer connect "123 456 7890" --server 203.0.113.10:443 \
    --server-fingerprint <fingerprint> --password <password>
```

The connection between viewer and agent is direct, never through the server.
For now it works when the viewer can reach one of the agent's addresses: on
the same network, or when the agent's side of the internet does not block the
way in. Hole punching across NATs, and the relay for when that fails, are the
next steps.

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

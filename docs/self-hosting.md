# Self-hosting

> **Status: early.** The server introduces agents to viewers by device ID,
> relays sessions that cannot go direct, has user accounts behind a REST API,
> enrolls installed agents into a device list with groups, lets users at
> them with grants, keeps an audit log, and has a web console for all of it.
> It runs as a binary or in Docker.

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
nearhand-agent install --server desk.example.com --server-fingerprint <fingerprint>
```

`--server` is a name or an IP address, with `:port` when it is not 443; the
agent looks a name up each time it starts. Add `--token` to enroll the
machine in the server's device list ([Enrollment](#enrollment)): then the
server's users reach it with [grants](#grants), and the access password is
optional (`set-password --none` removes one).

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
msiexec /i nearhand-agent-0.1.0-x64.msi /qn SERVER=desk.example.com ^
    SERVER_FINGERPRINT=<fingerprint> ACCESS_PASSWORD=<password> ^
    ENROLL_TOKEN=<token>
```

`ENROLL_TOKEN` is optional, and so is `DEVICE_NAME`, the name to list the
machine under instead of its computer name. With `ENROLL_TOKEN`,
`ACCESS_PASSWORD` may be left out.

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
public_address = "desk.example.com:443"   # for install commands; default:
                                          # public_url's host, bind's port

[http]
bind = "0.0.0.0:443"           # TCP: the web console and the REST API
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

The binary, as a service — a systemd unit, or a Windows service wrapper:

```bash
nearhand-server serve                 # or: --config /etc/nearhand/nearhand.toml
```

It stops cleanly on Ctrl+C or SIGTERM.

### In Docker

`packaging/docker` has the image — the server with the web viewer in it, on
a distroless base, running unprivileged — and a Compose file. Set
`NEARHAND_HTTP_PUBLIC_URL` in `compose.yaml` to how people will reach the
console, then, from that folder:

```bash
docker compose up -d
docker compose logs nearhand          # the fingerprint and the first-administrator link
```

Everything the server keeps is in the `nearhand` volume, mounted at `/data`:
back that up. Settings come from the environment (`NEARHAND_<SECTION>_<KEY>`,
as above) or from a file mounted at `/etc/nearhand/nearhand.toml`; for a real
certificate, mount its files and set `NEARHAND_HTTP_TLS=files` with
`NEARHAND_HTTP_CERT` and `NEARHAND_HTTP_KEY` (the Compose file has these,
commented out). `docker compose exec nearhand nearhand-server admin-link`
makes a new setup link.

Both 443/TCP and **443/UDP** must be published, and UDP must reach the
container as it is: agents' QUIC, the relay and the web viewer's
WebTransport all use it. On Linux, Docker keeps the addresses of the agents
it forwards; Docker Desktop on Windows and macOS does not, which costs
direct connections between agents on different networks — use it to try the
server out, not to run it. `packaging/docker/smoke-test.sh` builds the image
and checks it, as CI does on every push.

The first start, with no users, prints a link for creating the first
administrator in the web console (or the API call that does the same),
valid for 24 hours; `nearhand-server admin-link` prints a new one.

### The web console

`https://<public_url>/`: sign in, and administrators get the devices (with
who is online), enrollment tokens, users, user and device groups, grants and
the audit log; everyone gets the devices their grants reach, their password,
two-step sign-in and API tokens. It is a page over the REST API below, so
anything it does a script can do too. For the TOTP set-up, add the key it
shows to the authenticator app by hand, or open the `otpauth://` link on the
phone: the console draws no QR code.

### The web viewer

Beside each device a user has a grant for, and which is online, the console
shows **View**: the device in the browser tab, in current Chrome, Edge or
Firefox, to watch — or, with a `control` or `full` grant, to use. It runs
the same session as the native viewer, end-to-end encrypted to the agent,
carried over WebTransport on the QUIC port through the server's relay — so
it works wherever the console does, as long as UDP reaches the QUIC port.

- Click the picture to type into it. Keys go by position, so the device's
  own layout applies. **Ctrl+Alt+Del** is a button (or Ctrl+Alt+End).
- Shortcuts the browser keeps — Ctrl+W, Ctrl+T, Alt+Tab — stay with it,
  except in **Full screen**, where Chrome and Edge hand them to the device
  too.
- The device's pointer shape shows as the browser's own over the picture.
- Clipboard text: what is copied on the device lands in the browser's
  clipboard; what is copied here goes to the device when the picture gets
  focus, once the browser has been allowed to read the clipboard — it asks
  the first time.

Browsers do not accept the server's own QUIC certificate, so WebTransport
connections get another: the HTTPS certificate files with `tls = "files"`,
else a self-signed one the server makes and renews by itself every six
days, which the page accepts by its hash. With `tls = "none"` behind a
reverse proxy the proxy does not carry this — WebTransport is UDP, straight
to the QUIC port — and the self-signed certificate applies.

### The REST API

Everything is under `/api/v1`, JSON in and out; [api.md](api.md) lists it.
Scripts authenticate with an API token (`Authorization: Bearer nht_…`), which
any user makes for themselves (`POST /api/v1/me/tokens`) and which is shown
once. Passwords are Argon2id hashes; TOTP (any authenticator app) can be
turned on per user; wrong passwords are limited per address and per name.

## Enrollment

Enrolled machines make up the server's device list: their names, groups,
operating system and agent version, whether they are online now, and when
and from where they were last seen. An administrator makes an enrollment
token — for one device or any number, lasting 1 to 90 days, optionally
putting devices into a group:

```bash
curl https://desk.example.com/api/v1/enroll-tokens -H "authorization: Bearer nht_..." \
    -H 'content-type: application/json' \
    -d '{"name": "front office", "uses": null, "expires_in_days": 7, "group_id": 1}'
```

The answer holds the token, shown this once, and the commands that use it:

```bat
nearhand-agent install --server desk.example.com --server-fingerprint <fingerprint> --token nhe_...
```

or the MSI with `ENROLL_TOKEN=nhe_...`. Installing enrolls straight away; if
the server cannot be reached then, the agent keeps the token (readable by
administrators only) and enrolls as soon as it can, then forgets it. A
wrong, expired or used-up token makes installing fail, with the reason.

Enrolling is on top of registering, not instead: an enrolled agent is found
by its ID as before. Removing a device from the list does not stop it, and
it still takes grants; a new token enrolls it again. An enrolled device also keeps its ID against any
other key that claims it ([security](security.md#what-the-device-id-is-and-is-not)).

A killed agent, or one whose network vanished, shows as offline within 15
seconds.

Still to come: the server generating **pre-configured installers** (MSI or
PKG with the address and token baked in) for GPO, Intune or MDM.

## Grants

Who may connect to which enrolled machines. Users go in user groups, devices
in device groups, and a grant lets a user group at a device group with a
role: `view` (watch only), `control` (keyboard, mouse, clipboard) or `full`.
A user's role on a device is the highest their grants give. Administrators
set it all up, and need a grant themselves to connect:

```bash
api() { curl -s "https://desk.example.com/api/v1$1" -H "authorization: Bearer $ADMIN" "${@:2}"; }
api /user-groups -H 'content-type: application/json' -d '{"name": "Helpdesk"}'       # → id 1
api /user-groups/1/members/2 -X PUT                                                  # user 2 joins
api /grants -H 'content-type: application/json' \
    -d '{"user_group_id": 1, "device_group_id": 1, "role": "control"}'
```

Users see the devices they may reach, with their role, at `GET /devices`,
and connect with an API token of their own instead of a password:

```bash
NEARHAND_TOKEN=nht_... nearhand-viewer connect "123 456 7890" \
    --server desk.example.com:443 --server-fingerprint <fingerprint>
```

The server hands the viewer a grant for that device, signed with its key and
good for five minutes; the agent checks it against the server key it pinned
and lets the viewer in with the grant's role, without asking the server. See
[security](security.md#authorisation) for what that trusts the server
with.

## Updating agents

Installed agents update themselves from **this** server, and from nowhere
else. They install only a package that the project's release key signed,
whose hash matches, and whose version is newer than the one they run — so
you choose when your machines update, and to which release, and a server
can do no more to them than that ([security](security.md#supply-chain)).

Every Nearhand release comes as an MSI with a `.release` file beside it,
both from the project's CI. Upload the pair, then offer it:

```bash
api() { curl -s "https://desk.example.com/api/v1$1" -H "authorization: Bearer $ADMIN" "${@:2}"; }
api /releases -F package=@nearhand-agent-0.2.0-x64.msi \
              -F signature=@nearhand-agent-0.2.0-x64.msi.release   # → id 1
api /releases/1/offer -X POST        # from now on, agents older than 0.2.0 take it
api /releases/1/offer -X DELETE      # stop offering it; those already updated stay
```

One release is offered per product and platform. Agents ask a few minutes
after starting and every six hours after that, and install only when no
session is running, so nobody is cut off mid-session; the machine's service
restarts as the installer replaces it. `%ProgramData%\Nearhand\logs` holds
the agent's log and the installer's `update.log`.

A machine that should not update itself — one on a change-controlled
rollout — takes `updates = false` in its `agent.toml`.

`nearhand-release verify nearhand-agent-0.2.0-x64.msi` checks a package
against the release key before you upload it.

## Backup

The data folder: the SQLite file (`nearhand.db`, with its `-wal` file while
the server runs — or stop it first, or use `sqlite3 nearhand.db ".backup
copy.db"`) and the server key. That is the whole backup.

**Losing the server key means re-enrolling every device**, because agents pin it.
Back it up somewhere other than the server.

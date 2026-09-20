# Troubleshooting

What to do when a session will not start, or will not stay. Most of it
comes down to six things: the service is not running, UDP does not get out,
the server moved or was rebuilt, the password or grant is not what the
machine asks for, the clocks disagree, or the browser lacks something.

## Start on the machine being helped

```powershell
nearhand-agent doctor      # as administrator
```

It looks at the configuration, the device key, the service, the server's
name and its key, whether the server can be reached over UDP with the key
this machine pinned, and what the agent last wrote in its log. It only
looks: it registers nothing and changes nothing, so it is safe to run while
a session is on.

`nearhand-agent status` is the short version — service state, way in, and
the device ID.

Its files are in `%ProgramData%\Nearhand`, readable by administrators only:

| | |
| --- | --- |
| `agent.toml` | server, its fingerprint, the access password's hash |
| `device.key` | the key the ID is made from — back it up, or the ID changes |
| `logs\agent.log` | the agent that serves sessions |
| `logs\service.log` | the service that keeps it running |
| `logs\update.log` | the last installer `msiexec` ran |
| `updates\` | packages downloaded to update with |

## A viewer cannot find the device

The viewer says the device is not online, or the server refuses.

1. **Is the service running?** `sc query Nearhand`, or `doctor`. A service
   that stops on its own writes why in `logs\service.log`; Windows starts it
   again after a few seconds, three failures running.
2. **Does UDP get out?** The agent makes one outbound QUIC connection to the
   server's UDP port and keeps it. A network that allows only TCP stops it
   dead, and `doctor` says so ("did not answer"). There is no TCP fallback
   for the agent — only the browser viewer has one.
3. **Has the server moved?** The agent looks its address up each time it
   starts. A name that now points elsewhere is fine; a different port is
   not, and neither is a new server key.
4. **Was the server rebuilt?** A new `server.key` means a new fingerprint,
   and every agent pinned the old one. `doctor` reports the key it was
   offered is not the one pinned. Installing again with the new fingerprint
   is the fix — keep the server's key backed up to avoid it.
5. **Is it enrolled?** A device installed with `--token` takes its ID over
   from anyone who registered it first; one installed without a token does
   not. `nearhand-agent status` says which.

## It connects, then refuses

- **"wrong password"** — after five wrong ones in a row an installed agent
  refuses everything for 30 seconds, doubling to 15 minutes; a portable
  agent replaces its six digits after three. Wait it out, or set a new
  password with `nearhand-agent set-password`.
- **"this device needs a grant from its server as well as its password"** —
  the machine was installed with `--password-with-grant`. Sign in to the
  server (`--token`, or the console) *and* give the password.
- **"the grant has expired; ask the server for a new one"** or **"the grant
  is not valid yet; check the clocks"** — a grant lives five minutes, with
  two minutes of clock difference forgiven. If the machine's clock is out
  by more than that, nothing works: `w32tm /resync` on Windows, or check
  the host's clock in a VM that was suspended.
- **"the grant was used already"** — each grant is good once. The viewer
  asks the server for a new one; if you are scripting, do not keep one.
- **"the agent cannot prove it knows the password"** — the agent on the
  other end did not arrive at the same key. Either the password is wrong on
  one side, or something is standing between the viewer and the device;
  [security](security.md#what-the-device-id-is-and-is-not) says what that
  means.

## "answered with another key than last time"

A viewer remembers which key each device ID answered with. A device that is
reinstalled keeps its key, and one that loses its key gets a new ID with it,
so the same ID with another key does not happen by itself: either the server
introduced another machine, or someone is in the middle.

Check with whoever runs the device — its ID and fingerprint are in
`nearhand-agent status` and `doctor`. If it really did change, the native
viewer takes `--trust-new-key` once, and the browser asks. To forget a
device instead, delete its line from `known-devices` beside the viewer's
other files (`%LOCALAPPDATA%\Nearhand` on Windows).

## The picture stops, or the session drops

- **At the sign-in screen, the lock screen or a UAC prompt.** The agent
  follows the user onto the secure desktop, which means dropping its
  capture and taking a new one. It recovers by itself, and says so in
  `logs\agent.log`: "followed the input desktop", then "capture source
  changed; continuing".
- **The session ends when someone signs out.** The service starts a new
  agent in the next console session; the viewer reconnects.
- **The picture freezes but the mouse still works.** That is capture, not
  the connection: the log says why. Send the last few hundred lines of
  `agent.log` — it names the display adapter and what it did.
- **A slow or lossy link.** The viewer's overlay (Ctrl+Shift+F1) shows the
  bitrate, the frame rate, lost datagrams and repairs. Rate control drops
  the bitrate before the frame rate, so text stays sharp.

## The browser viewer

- **"This browser lacks WebCodecs"** — use a current Chrome, Edge or
  Firefox, or the native viewer. Safari is not there yet.
- **The page says "over TCP".** WebTransport did not work — UDP blocked, or
  the certificate refused — and the session went over a WebSocket instead.
  It works, and costs some smoothness on a lossy link. `?transport=tcp`
  forces it for testing.
- **It asks for a password although you signed in.** The device is one that
  asks for a grant *and* its access password.
- **Nothing appears and the console shows an error.** The browser's
  developer console has the reason; the server's log has the other half.

## Updates do not arrive

An agent asks its own server, five minutes after it starts and every six
hours after that, and installs only a release that server offers.

- The console's **Agent updates** tab must *offer* the release, not merely
  hold it: a release that is uploaded but not offered is sent to nobody.
- It never updates while a session is on; it tries again in fifteen
  minutes.
- Eight downloads at a time; the rest are told to come back.
- The install itself is `msiexec`, and its log is `logs\update.log`. The
  service stops for a few seconds while it runs.
- `agent.toml` with `updates = false` turns it off altogether.

See [self-hosting](self-hosting.md#updating-agents) for the server's side.

## The server

```bash
nearhand-server --config /etc/nearhand/nearhand.toml doctor
```

It prints the fingerprint agents pin — which otherwise only appears in the
log at startup — and looks at the data folder, the key, the database, the
certificate, both ports and the address agents are told to come back to. It
neither migrates the database nor holds the ports, so it is safe to run on
a server that is serving.

- **Ports.** UDP 443 for agents, viewers and the relay; TCP 443 for the API
  and the console. Both, on the same port number by default.
- **Behind a reverse proxy.** The TCP side proxies like any HTTPS service.
  The UDP side does not: QUIC must reach the server itself, so forward the
  UDP port rather than terminating it.
- **The certificate.** Agents and viewers pin the *server key*, not its TLS
  certificate, so a browser warning about a self-signed certificate is a
  separate matter from the fingerprint agents use. `tls = "files"` in
  `nearhand.toml` takes a real certificate for browsers.
- **The first administrator.** The one-time link is printed at first start
  and lasts 24 hours; `nearhand-server admin-link` prints another.
- **In Docker.** The data folder is `/data`; keep it on a volume, because
  it holds the server key — losing it means reconfiguring every agent.
  `nearhand-server backup /data/backups/<date>` takes a copy of the key and
  the database while the server runs; the image has no shell, so this is
  the way to get one out of it.

## What to send when asking for help

- `nearhand-agent doctor` output from the machine being helped.
- The last few hundred lines of `logs\agent.log` and `logs\service.log`.
- The versions at both ends (`nearhand-agent --version`,
  `nearhand-viewer --version`) and the server's.
- What the viewer printed, or the browser's console.

Logs hold device IDs, user names and addresses, but no passwords, no keys
and nothing of what was on screen.

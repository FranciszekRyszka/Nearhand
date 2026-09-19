# Security

> **Status: partly implemented.** Device keys, pinning, the relay, the
> portable agent's one-time password and accept prompt, the installed
> agent's access password, session indicators for both, server accounts
> (Argon2id, TOTP, API tokens), enrollment, signed grants, the audit log
> and the web console exist; signed releases do not yet.
> Track the gap against the roadmap in the README.

Nearhand hands one machine full control of another. The threat model is built in
from the start rather than bolted on, because retrofitting any of it would mean
changing the wire format.

## Identity and keys

- Each agent generates an **Ed25519** keypair on first run. The device ID is
  derived from the public key.
- Viewer ↔ agent is **TLS 1.3 with both sides pinning** the key delivered
  through the server. A changed key blocks the connection and raises an alert,
  the way SSH does — it is not a warning the user can click through.
- The agent pins the **server key** at install; enrolling does not change
  it.

### What the device ID is, and is not

A device ID is ten digits derived from the device's key. That makes it stable
without the server storing anything, but it is a name, not a proof. Ten digits
are about 33 bits, and a malicious server could find another key with the same
ID in minutes. What the viewer pins is the full fingerprint the server reports,
so for an attended session the viewer trusts the server to report it
honestly. The one-time password then decides who gets in, and only the agent
checks it.

Someone could also register a key of their own under a device's ID first,
to keep the device from being found: first come, first served, and the
device is refused (M2). An **enrolled** device outranks such a stranger — it
takes its ID over when it registers — so this works only against devices
that are not enrolled.

## Enrollment

- Enrollment tokens are random 256-bit values, shown once and stored as
  their SHA-256, for a number of devices and at most 90 days. Only
  administrators make them.
- The agent enrolls on a connection that presents its own certificate, so a
  token enrolls the key that uses it and no other; tries are limited per
  address like introductions.
- A token not yet used waits in the agent's configuration, readable only by
  SYSTEM and administrators, and is deleted once used or refused. The MSI
  keeps `ENROLL_TOKEN` out of its logs.
- Installing with a token also makes the machine take grants from its
  server (below); installing without one never does.

## Accounts

People sign in to the server — the console, and the REST API — with an
account (M5).

- Passwords are at least 10 characters and stored as Argon2id hashes
  (19 MiB, two passes). Signing in with an unknown name costs the same time
  as with a known one, so the answer does not say which names exist.
- Wrong passwords are limited to ten per quarter of an hour per address,
  and ten per account name from anywhere.
- TOTP (RFC 6238, any authenticator app) can be turned on per account; each
  code works once, and turning it off takes a current code.
- A console sign-in is a random 256-bit token in a cookie marked `HttpOnly`,
  `Secure` and `SameSite=Strict`, for 12 hours. Requests that change
  anything with that cookie must also not come from another site's page.
  Changing the password or disabling the account ends its sign-ins.
- Scripts use API tokens instead, which each user makes and deletes. Sign-in
  and API tokens are stored only as their SHA-256, so a copy of the
  database does not let anyone in.
- The first administrator is made with a one-time token the server prints
  on its first start; there is no default password.
- The last active administrator cannot be demoted, disabled or deleted.

## Authorisation

- **Unattended** sessions require a grant signed by the pinned server key.
  - *Implemented:* users are put in user groups and devices in device
    groups; a grant lets a user group at a device group as `view` (watch
    only), `control` (keyboard, mouse, clipboard) or `full` (control, plus
    privacy mode and file transfer when they come). Administrators manage
    grants and are no exception to them.
  - A viewer signed in with an API token asks the server for a device; the
    server checks the user's grants and, if one covers the device, signs a
    grant for that one device and user, with the role, valid for five
    minutes and marked with a random nonce. A user with no grant learns
    nothing about the device, not even whether it is online.
  - The agent checks the grant itself: signed by the key of the server it
    pinned at install (the certificate is sent along and must hash to the
    pinned fingerprint), for this device, within its five minutes (two
    minutes' clock difference forgiven), and not presented before. It
    never asks the server. The role then limits the session: with `view`,
    the viewer's keyboard, mouse and clipboard are ignored and this
    machine's clipboard is not sent.
  - Only machines installed with an enrollment token take grants. One
    installed with only an access password never does, so its server
    alone cannot open it, as before.
  - A grant is for connecting, not a lease: removing someone's grant stops
    their next connection, not a session they already have. The person at
    the machine sees whose session it is and can end it.
- An optional **per-device access password** is verified by the agent itself, so
  a compromised server alone is not enough to take over a machine.
  - *Implemented:* an installed agent lets in anyone with its access
    password. On a machine installed with a token the password is optional,
    and is a second way in beside grants, not a second factor. The
    password is set at install, at least 10 characters, and kept
    only as a salted PBKDF2-HMAC-SHA256 hash (600,000 rounds) in a folder
    only SYSTEM and administrators can read, beside the device key. Each
    check takes a noticeable fraction of a second. After five wrong
    passwords in a row the agent refuses every attempt for 30 seconds,
    doubling up to 15 minutes, so guessing online is hopeless. The server
    never sees the password.
  - No one at the machine is asked, with a password or a grant. The password
    should be treated like an administrator's password.
- **Attended** sessions require the person at the host to accept, or a one-time
  password. Attempts are rate-limited.
  - *Implemented:* the portable agent shows six random digits. The agent
    checks them and the server never sees them. Each wrong guess costs a
    whole connection, and three wrong guesses replace the password. The
    server also limits each viewer address to 10 introductions a minute.
  - *Implemented:* with its window showing, the portable agent asks the
    person at the host to allow each viewer who gave the right password.
    No answer within 30 seconds counts as no, and so does the viewer
    leaving. "New" replaces the password at any time.
  - Run with `--console` there is no window, and no one to ask: the password
    alone lets a viewer in, for as long as the agent runs. That mode is for
    testing and for people at a terminal. It announces each session there.
- The **relay** forwards only for sessions holding a server-issued ticket, so it
  cannot be turned into an open proxy. It only ever sees ciphertext — the
  QUIC/TLS handshake is between viewer and agent.
  - *Implemented:* the relay runs inside the server. It forwards only between
    a viewer's connection and the agent it was introduced to, once that agent
    has said it is ready. The pairing is the ticket; a relay on a separate
    host, which cannot see the pairing, will need a signed one.
  - *Not yet:* limits on how much one session may relay. Only an agent that
    accepted the session can receive its traffic, but a server open to
    everyone carries whatever that pair sends.

## Exposure

- The agent makes **outbound connections only**. It never listens on a port.
- Privileged service code is kept small. Capture and encode run in the user
  session, not in the service.
- The host **always shows a visible indicator** during a session. There is no
  hidden mode, ever. Beyond being the right default, it is also what keeps
  antivirus vendors from classifying the agent as a trojan.
  - *Implemented, for the portable agent:* for as long as a session lasts,
    its window says the computer is being controlled, by whom, and for how
    long, with a button to end it. The window stays on top and comes back
    if minimised; closing it stops the agent.
  - *Implemented, for the installed agent:* a small window on the user's
    desktop, shown only during a session, says the computer is being
    controlled remotely, by whom and for how long, with a button to end it.
    It stays on top, comes back if minimised, and refuses to close (Alt+F4
    included). It is not on the sign-in screen or UAC prompts, which the
    person at the machine is looking at then.
  - *Limit:* on a machine whose graphics cannot show a window at all — a VM
    with no display adapter — the indicator fails, the agent logs it, and
    sessions still work. Refusing sessions there would make headless
    machines unreachable; the log is the record.

## Audit log and console

- The server records every change an administrator makes, every sign-in
  and failed one, every device enrolled, and every session a grant opened
  or a missing grant refused: when, who, from which address, what, to
  what. Rows are only ever added; administrators read them (`GET
  /api/v1/audit`, or the console). A failure to write one is logged, and
  does not stop what it records.
- It is kept in the same database as everything else, so it tells what
  happened, not what a server's administrator — or someone who took the
  server — chose to erase. Shipping it somewhere else as it is written is a
  possible later addition.
- What it does not see: sessions by password (the server never learns
  them), and what happens inside any session.
- The **web viewer** runs the same session as the native one, compiled to
  WebAssembly: QUIC and TLS 1.3 to the agent, pinned to its fingerprint,
  carried in WebTransport datagrams through the relay, which sees only
  ciphertext. The page checks that the fingerprint the server introduces is
  the one in the grant the API issued, and the agent checks the grant as
  for any viewer. Its page may compile WebAssembly (`'wasm-unsafe-eval'`,
  which permits nothing for JavaScript) and show `data:` images — the
  device's pointer; the console's may do neither.
- The web viewer reads this machine's clipboard only with the browser's
  permission, only while its tab has focus, and only when the picture gets
  focus; a `view` grant sends nothing, since the agent takes no input or
  clipboard from a watcher.
- WebTransport uses a certificate browsers accept, not the pinned server
  key: CA-issued, or self-signed for at most 13 days and accepted by the
  hash the console hands over HTTPS. Whoever can serve the console could
  therefore hand another hash — but they could equally serve other code,
  so the browser's trust is the console's HTTPS certificate either way.
- The web console is a page over the same REST API, served from the binary:
  no endpoint of its own, nothing loaded from elsewhere. Its
  Content-Security-Policy allows only this server's own script, style and
  API, no inline script and no framing, and the page puts everything the
  server sends on screen as text, never as HTML. Tokens are shown once, when
  made. The first administrator's link carries its token after `#`, which
  browsers do not send, so it stays out of any proxy's logs.

## Supply chain

- Releases are signed with the project's release key, an Ed25519 key of
  its own — not a server's, not a device's. Its public half is built into
  every agent (`nearhand_core::release::KEY`); its private half is a CI
  secret, given only to the one step that signs, after everything is
  built, on pushes to `main`. The signature covers the package's product,
  version, platform, size and SHA-256 (`nearhand-release verify` checks
  one).
- Agents will update only from their own server, and install only a
  package whose release the built-in key verifies and whose hash matches,
  never an older version than they run. A server chooses when its agents
  update, and to which of the project's releases; it cannot make them run
  anything else.
- `cargo-deny` and `cargo-audit` run in CI.
- The protocol decoder gets fuzzed (`cargo-fuzz`) before 1.0.
- External review before 1.0.

## Known limits

A **malicious server** can put itself between a viewer and an agent.
It can report its own key as the device's, since the ID does not pin the key.
It can then relay the password the viewer types to the real agent. The
password protects against anyone who is not the server; it does not protect
against the server itself. For an installed agent this is worse than for a
portable one: the access password lasts, so a server that captured it once
could use it again later. A password-authenticated key exchange (PAKE) would
close this gap, and is worth adding before 1.0.

A **fully compromised management server** could issue itself a grant, and
open every machine enrolled with it. Machines installed with only an access
password, which the server never learns, are out of its reach; the audit log
shows what happened, unless the attacker erased it. Requiring a grant *and* the password on
the same machine is a possible later option. This is stated rather than
solved; a server you do not trust is a server you should not enroll
against.

## Reporting a vulnerability

Not yet established — this is pre-alpha software with no releases. Until a
disclosure process exists, open a regular issue for anything you find, and
please do not rely on Nearhand for anything that matters.

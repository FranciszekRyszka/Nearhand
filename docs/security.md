# Security

> **Status: partly implemented.** Device keys, pinning, the relay, the
> portable agent's one-time password and accept prompt, the installed
> agent's access password, and session indicators for both exist;
> enrollment, grants and signed releases do not yet.
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
- The agent pins the **server key** at enrollment.

### What the device ID is, and is not

A device ID is ten digits derived from the device's key. That makes it stable
without the server storing anything, but it is a name, not a proof. Ten digits
are about 33 bits, and a malicious server could find another key with the same
ID in minutes. What the viewer pins is the full fingerprint the server reports,
so for an attended session the viewer trusts the server to report it
honestly. The one-time password then decides who gets in, and only the agent
checks it.

## Authorisation

- **Unattended** sessions require a grant signed by the pinned server key.
- An optional **per-device access password** is verified by the agent itself, so
  a compromised server alone is not enough to take over a machine.
  - *Implemented, in place of grants until accounts arrive (M5):* an
    installed agent lets in anyone with its access password, and nobody
    else. The password is set at install, at least 10 characters, and kept
    only as a salted PBKDF2-HMAC-SHA256 hash (600,000 rounds) in a folder
    only SYSTEM and administrators can read, beside the device key. Each
    check takes a noticeable fraction of a second. After five wrong
    passwords in a row the agent refuses every attempt for 30 seconds,
    doubling up to 15 minutes, so guessing online is hopeless. The server
    never sees the password.
  - Until then the password is the *only* check: there is no grant, and no
    one at the machine is asked. It should be treated like an
    administrator's password.
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

## Supply chain

- Releases are signed. Agents update only from their own server, and verify
  signatures against a key baked into the binary.
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

A **fully compromised management server** could issue itself a grant. The
mitigations are the per-device access password, which the server never learns,
and the audit log. This is stated rather than solved; a server you do not trust
is a server you should not enroll against.

## Reporting a vulnerability

Not yet established — this is pre-alpha software with no releases. Until a
disclosure process exists, open a regular issue for anything you find, and
please do not rely on Nearhand for anything that matters.

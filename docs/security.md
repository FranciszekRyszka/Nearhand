# Security

> **Status: partly implemented.** Device keys, pinning, the portable agent's
> one-time password and the relay exist; enrollment, grants, the per-device
> access password, signed releases and the session indicator do not yet.
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
- **Attended** sessions require the person at the host to accept, or a one-time
  password. Attempts are rate-limited.
  - *Implemented:* the portable agent shows six random digits. The agent
    checks them and the server never sees them. Each wrong guess costs a
    whole connection, and three wrong guesses replace the password. The
    server also limits each viewer address to 10 introductions a minute.
  - *Not yet:* the accept prompt, which comes with the portable agent's
    window. Until then the password stays valid while the agent runs. A
    viewer who has had it can come back without asking again.
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

## Supply chain

- Releases are signed. Agents update only from their own server, and verify
  signatures against a key baked into the binary.
- `cargo-deny` and `cargo-audit` run in CI.
- The protocol decoder gets fuzzed (`cargo-fuzz`) before 1.0.
- External review before 1.0.

## Known limits

A **malicious server** can put itself between a viewer and a portable agent.
It can report its own key as the device's, since the ID does not pin the key.
It can then relay the password the viewer types to the real agent. The
password protects against anyone who is not the server; it does not protect
against the server itself. A password-authenticated key exchange (PAKE) would
close this gap, and is worth adding before 1.0.

A **fully compromised management server** could issue itself a grant. The
mitigations are the per-device access password, which the server never learns,
and the audit log. This is stated rather than solved; a server you do not trust
is a server you should not enroll against.

## Reporting a vulnerability

Not yet established — this is pre-alpha software with no releases. Until a
disclosure process exists, open a regular issue for anything you find, and
please do not rely on Nearhand for anything that matters.

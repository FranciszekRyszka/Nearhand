# Security

> **Status: design, not yet implemented.** This describes what the code must do;
> track the gap against the roadmap in the README.

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

## Authorisation

- **Unattended** sessions require a grant signed by the pinned server key.
- An optional **per-device access password** is verified by the agent itself, so
  a compromised server alone is not enough to take over a machine.
- **Attended** sessions require the person at the host to accept, or a one-time
  password. Attempts are rate-limited.
- The **relay** forwards only for sessions holding a server-issued ticket, so it
  cannot be turned into an open proxy. It only ever sees ciphertext — the
  QUIC/TLS handshake is between viewer and agent.

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

A **fully compromised management server** could issue itself a grant. The
mitigations are the per-device access password, which the server never learns,
and the audit log. This is stated rather than solved; a server you do not trust
is a server you should not enroll against.

## Reporting a vulnerability

Not yet established — this is pre-alpha software with no releases. Until a
disclosure process exists, open a regular issue for anything you find, and
please do not rely on Nearhand for anything that matters.

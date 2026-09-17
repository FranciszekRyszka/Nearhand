# Docker packaging

`Dockerfile` and `docker-compose.yml` for the server: one static binary, one
volume holding the SQLite file and the server key.

Note that 443/UDP must reach the container directly — QUIC, WebTransport and the
relay all run on it, and a reverse proxy can only handle the TCP side.

Scheduled for M2.

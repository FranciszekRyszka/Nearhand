# Docker packaging

The server's image and a Compose file for it: one volume, `/data`, holding
the SQLite file, the server key and the certificates.

- `Dockerfile` — builds the web viewer and the server, and puts the server
  on a distroless base, running unprivileged. Build from the repository
  root: `docker build -f packaging/docker/Dockerfile -t nearhand-server .`
- `compose.yaml` — set the console's address in it, then `docker compose up -d`.
- `smoke-test.sh` — builds the image, starts it, and checks it serves, keeps
  its key across a restart and stops cleanly. CI runs it.

443/UDP must reach the container directly — QUIC, WebTransport and the relay
all run on it, and a reverse proxy can only handle the TCP side. More in
[docs/self-hosting.md](../../docs/self-hosting.md#in-docker).

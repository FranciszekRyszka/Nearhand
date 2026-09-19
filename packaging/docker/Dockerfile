# syntax=docker/dockerfile:1
#
# The server, with the web viewer inside it. From the repository root:
#
#   docker build -f packaging/docker/Dockerfile -t nearhand-server .
#
# Or `docker compose up` beside compose.yaml. Everything the server keeps —
# database, server key, HTTPS and WebTransport certificates — is in /data.

FROM rust:1-bookworm AS build
# The web viewer compiles ring's C for wasm32: clang and llvm-ar.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# The toolchain rust-toolchain.toml names, with the wasm target.
COPY rust-toolchain.toml ./
RUN rustup toolchain install stable --profile minimal \
    --component rustfmt,clippy --target wasm32-unknown-unknown
# wasm-bindgen-cli must be the version of wasm-bindgen in Cargo.lock.
COPY Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    version="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, ""); print }' Cargo.lock)" \
    && cargo install wasm-bindgen-cli --version "$version" --locked
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    sh packaging/web/build.sh \
    && cargo build --release --locked -p nearhand-server \
    && mkdir -p /out/data \
    && cp target/release/nearhand-server /out/

# glibc and libgcc, nothing else: no shell, no package manager.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/nearhand-server /usr/local/bin/nearhand-server
# Owned by the user the server runs as, so a new named volume is too.
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV NEARHAND_DATA_DIR=/data
VOLUME /data
# TCP: web console and REST API. UDP: agents, viewers, the relay and
# WebTransport — it must reach the container directly, not through a proxy.
EXPOSE 443/tcp 443/udp
ENTRYPOINT ["/usr/local/bin/nearhand-server", "--config", "/etc/nearhand/nearhand.toml"]
CMD ["serve"]

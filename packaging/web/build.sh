#!/bin/sh
# Build the web viewer into crates/server/web/pkg; see build.ps1. Needs the
# wasm32 target, wasm-bindgen-cli at the version in Cargo.lock, and clang.
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
export CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-clang}"
export AR_wasm32_unknown_unknown="${AR_wasm32_unknown_unknown:-llvm-ar}"
unset RUSTFLAGS
cargo build --release -p nearhand-web --target wasm32-unknown-unknown --manifest-path "$root/Cargo.toml"
wasm-bindgen --target web --no-typescript --out-dir "$root/crates/server/web/pkg" \
    "$root/target/wasm32-unknown-unknown/release/nearhand_web.wasm"
ls -l "$root/crates/server/web/pkg"

# Build the web viewer: the session compiled to WebAssembly, and the
# JavaScript that loads it, into crates/server/web/pkg, from where the
# server's build embeds them. Without them the server still builds, and
# its /view page says the web viewer is missing.
#
# Needs the wasm32 target (rustup target add wasm32-unknown-unknown),
# wasm-bindgen-cli at the version in Cargo.lock
# (cargo install wasm-bindgen-cli --version <it> --locked), and clang for
# ring's C: -Llvm points at an LLVM folder when clang is not on the PATH.
param(
    [string]$Llvm = "$env:LOCALAPPDATA\Nearhand-dev\llvm"
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."

if (Test-Path "$Llvm\bin\clang.exe") {
    $env:CC_wasm32_unknown_unknown = "$Llvm\bin\clang.exe"
    $env:AR_wasm32_unknown_unknown = "$Llvm\bin\llvm-ar.exe"
}
# The workspace's RUSTFLAGS are for native builds.
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue

cargo build --release -p nearhand-web --target wasm32-unknown-unknown --manifest-path "$root\Cargo.toml"
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
wasm-bindgen --target web --no-typescript --out-dir "$root\crates\server\web\pkg" `
    "$root\target\wasm32-unknown-unknown\release\nearhand_web.wasm"
if ($LASTEXITCODE -ne 0) { throw "wasm-bindgen failed" }
Get-ChildItem "$root\crates\server\web\pkg" | Select-Object Name, Length

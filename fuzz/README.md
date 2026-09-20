# Fuzzing

Four [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) targets over
everything Nearhand decodes from somewhere else. They exist because an
agent decodes bytes from whoever is on the other end of a connection, and a
panic there is a machine that stops answering.

| Target | What it feeds |
| --- | --- |
| `wire` | Every message type off a QUIC stream, and the length-prefixed reader path |
| `video` | The reassembler, as a run of datagrams with the clock stepped between them |
| `signature_file` | The two-line signature file beside a release package |
| `signatures` | Checking a grant's and a release's signature, with the certificate, body and signature all arbitrary |

`crates/core/tests/hostile.rs` is the same idea on stable, without
coverage feedback: it runs in every build, in under a second. This
directory is the deeper pass — `.github/workflows/fuzz.yml` runs it weekly
and on demand.

## Running it

`cargo-fuzz` needs a nightly toolchain and, on Windows, does not build
libFuzzer at all; Linux or macOS then.

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked

cd fuzz
cargo +nightly fuzz run wire                 # until Ctrl+C
cargo +nightly fuzz run video -- -max_total_time=60
cargo +nightly fuzz list                     # the targets
```

The corpus it builds up lands in `fuzz/corpus/<target>`, and is not
committed: CI carries its own between runs, and a local one is yours.

## When it finds something

libFuzzer writes the input to `fuzz/artifacts/<target>/crash-<hash>` and
prints the path; the CI job uploads that folder as an artifact. To see it
again:

```sh
cargo +nightly fuzz run wire fuzz/artifacts/wire/crash-<hash>
```

Then fix it, and add the case to `crates/core/tests/hostile.rs` so every
build checks it from then on — the fuzzer's corpus is not a regression
test.

# Releasing

What a release is, how one is made, and what the pieces are for. For
running a server, see [self-hosting](self-hosting.md); for what the
signing protects against, [security](security.md#supply-chain).

## Cutting one

1. Set the version in the crates that carry it — the agent's is the one
   releases are named after — and commit that on `main`.
2. Tag it and push the tag:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. CI builds everything, signs the installer, and leaves a **draft**
   release. Look it over and publish it when it reads right.

The tag and the agent's version must match, or the build stops before it
makes anything: agents compare versions to decide whether to update, and a
release whose name disagrees with its contents would make that a lie.

`workflow_dispatch` on the same workflow rehearses all of it for a tag that
exists already, up to the draft.

## What comes out

| File | What it is |
| --- | --- |
| `nearhand-agent-<version>-x64.msi` | the Windows agent's installer |
| `nearhand-agent-<version>-x64.msi.release` | its signature, which agents check before updating |
| `nearhand-windows-x86_64.zip` | server, viewer and portable agent for Windows |
| `nearhand-linux-x86_64.tar.gz` | the server for Linux |
| `SHA256SUMS` | over everything above |
| `ghcr.io/<owner>/nearhand-server:<version>` | the server's image, also tagged `latest` |

The MSI and its `.release` file are the pair an administrator uploads to
their own server, in the console's **Agent updates** — that is how agents
get it ([how](self-hosting.md#updating-agents)).

## The release key

The project's Ed25519 release key signs each package. Its public half is
built into every agent (`nearhand_core::release::KEY`); its private half is
the repository's `NEARHAND_RELEASE_KEY` secret, and nothing else has it.
The signing step is a job of its own, so the key is given only to the step
that signs, after everything has been compiled — a dependency's build
script never runs while it is in the environment.

The signature is checked twice after that: once in CI against the key
agents carry, so a wrong secret fails the build, and again by every agent
before it installs anything.

```bash
# Checking a package by hand, against the key this build trusts:
cargo run -p nearhand-release -- verify nearhand-agent-0.2.0-x64.msi
```

**If the key is lost**, agents in the field will take no further updates:
they trust that key alone, and a new one only reaches them in a build they
cannot install. Replacing it means reinstalling every agent by hand. GitHub
does not show a secret again once set, so the key exists only there.

## What is not signed yet

The MSI has no Authenticode signature, so Windows warns before running it,
and antivirus vendors have nothing to recognise. That needs a code-signing
certificate, and it is what M3 is still missing.

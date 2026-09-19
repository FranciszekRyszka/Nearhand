//! `nearhand-release`: the project's release key, and signing packages
//! with it (`nearhand_core::release`).
//!
//! ```text
//! nearhand-release keygen --out release.key     # once, ever
//! nearhand-release sign --version 0.2.0 nearhand-agent-0.2.0-x64.msi
//! nearhand-release verify nearhand-agent-0.2.0-x64.msi
//! ```
//!
//! `sign` takes the private key from `NEARHAND_RELEASE_KEY` (hex, as
//! `keygen` writes it) or `--key-file`, and writes `<package>.release`
//! beside the package: what servers take, and agents check.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nearhand_core::release::{self, Package, Release, SignedRelease, Version};
use nearhand_transport::release as signing;

#[derive(Parser, Debug)]
#[command(name = "nearhand-release", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Make a new release key: the private half into `--out`, the public
    /// half printed, for `nearhand_core::release::KEY`.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a package, writing `<package>.release` beside it.
    Sign {
        /// The package's version, `major.minor.patch`.
        #[arg(long)]
        version: Version,
        #[arg(long, default_value = release::AGENT)]
        product: String,
        #[arg(long, default_value = release::WINDOWS_X86_64)]
        platform: String,
        /// The private key, hex; instead of `NEARHAND_RELEASE_KEY`.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Sign with a key agents do not trust: for tests.
        #[arg(long)]
        other_key: bool,
        package: PathBuf,
    },
    /// Check a package against its `.release` file and the release key
    /// agents trust.
    Verify {
        package: PathBuf,
        /// The signature file, if not `<package>.release`.
        #[arg(long)]
        signature: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { out } => keygen(&out),
        Command::Sign {
            version,
            product,
            platform,
            key_file,
            other_key,
            package,
        } => {
            let key = private_key(key_file.as_deref())?;
            let public = signing::public_key(&key)?;
            if public != release::KEY && !other_key {
                bail!(
                    "this key is not the release key agents trust (its public half is {}); \
                     --other-key signs anyway, for tests",
                    hex(&public)
                );
            }
            let data = std::fs::read(&package)
                .with_context(|| format!("reading {}", package.display()))?;
            let signed = signing::sign(
                &key,
                &Release {
                    product,
                    version,
                    platform,
                    package: package_kind(&package)?,
                    sha256: signing::sha256(&data),
                    size: data.len() as u64,
                },
            )?;
            let out = signature_path(&package);
            std::fs::write(&out, signed.to_text())
                .with_context(|| format!("writing {}", out.display()))?;
            println!("signed: {}", out.display());
            Ok(())
        }
        Command::Verify { package, signature } => {
            let signature = signature.unwrap_or_else(|| signature_path(&package));
            let text = std::fs::read_to_string(&signature)
                .with_context(|| format!("reading {}", signature.display()))?;
            let signed = SignedRelease::from_text(&text).map_err(anyhow::Error::msg)?;
            let release = signing::verify(&signed, &release::KEY)?;
            let data = std::fs::read(&package)
                .with_context(|| format!("reading {}", package.display()))?;
            signing::check_package(&release, &data)?;
            println!(
                "good: {} {} for {}, {} bytes",
                release.product, release.version, release.platform, release.size
            );
            Ok(())
        }
    }
}

fn keygen(out: &Path) -> Result<()> {
    let (private, public) = signing::generate_key()?;
    // Never over an existing key: that one may be the only copy.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .with_context(|| format!("creating {} (it must not exist yet)", out.display()))?;
    std::io::Write::write_all(&mut file, format!("{}\n", hex(&private)).as_bytes())
        .with_context(|| format!("writing {}", out.display()))?;
    println!("private key: {} (keep it secret)", out.display());
    println!("public key: {}", hex(&public));
    println!("as nearhand_core::release::KEY:");
    println!("{}", rust_array(&public));
    Ok(())
}

/// The private key, from `--key-file` or `NEARHAND_RELEASE_KEY`.
fn private_key(file: Option<&Path>) -> Result<Vec<u8>> {
    let text = match file {
        Some(file) => {
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?
        }
        None => std::env::var("NEARHAND_RELEASE_KEY")
            .context("no key: set NEARHAND_RELEASE_KEY or pass --key-file")?,
    };
    unhex(text.trim()).context("the release key is not hex")
}

/// What kind of package a file is, from its name.
fn package_kind(path: &Path) -> Result<Package> {
    match path.extension().and_then(|e| e.to_str()) {
        Some(e) if e.eq_ignore_ascii_case("msi") => Ok(Package::Msi),
        _ => bail!("{} is not a package releases know: .msi", path.display()),
    }
}

fn signature_path(package: &Path) -> PathBuf {
    let mut name = package.as_os_str().to_owned();
    name.push(".release");
    PathBuf::from(name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        bail!("odd length or not ASCII");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("not a hex digit"))
        .collect()
}

/// `[0x12, 0x34, …]`, eight to a line, as `rustfmt` would have it.
fn rust_array(bytes: &[u8]) -> String {
    let lines: Vec<String> = bytes
        .chunks(8)
        .map(|chunk| {
            let items: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x},")).collect();
            format!("    {}", items.join(" "))
        })
        .collect();
    format!("[\n{}\n]", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_hex() {
        let (private, _) = signing::generate_key().expect("key");
        assert_eq!(unhex(&hex(&private)).expect("unhex"), private);
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
    }

    #[test]
    fn signature_files_sit_beside_packages() {
        assert_eq!(
            signature_path(Path::new("out/nearhand-agent-0.2.0-x64.msi")),
            PathBuf::from("out/nearhand-agent-0.2.0-x64.msi.release")
        );
        assert_eq!(package_kind(Path::new("a.MSI")).expect("msi"), Package::Msi);
        assert!(package_kind(Path::new("a.exe")).is_err());
    }
}

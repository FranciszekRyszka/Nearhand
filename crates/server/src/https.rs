//! TLS for the REST API and console (TCP 443).
//!
//! Not the server's Ed25519 key that agents and viewers pin: browsers do not
//! accept Ed25519 certificates. So HTTPS has a certificate of its own —
//! given as files, or made on first start (ECDSA P-256) and kept in the data
//! folder, which browsers warn about until it is replaced with a real one.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::{Config, Tls};

/// The TLS configuration to serve with; `None` for plain HTTP.
pub fn server_config(config: &Config) -> Result<Option<Arc<rustls::ServerConfig>>> {
    let (cert, key) = match config.http.tls {
        Tls::None => return Ok(None),
        Tls::Files => (
            config.http.cert.clone().context("http.cert")?,
            config.http.key.clone().context("http.key")?,
        ),
        Tls::SelfSigned => self_signed(config)?,
    };
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("reading {}", cert.display()))?;
    let key =
        PrivateKeyDer::from_pem_file(&key).with_context(|| format!("reading {}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the HTTPS certificate and key do not go together")?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(Arc::new(tls)))
}

/// The self-signed certificate in the data folder, made if missing: for
/// `localhost` and the host in `http.public_url`.
fn self_signed(config: &Config) -> Result<(PathBuf, PathBuf)> {
    let cert = config.data.dir.join("https.crt");
    let key = config.data.dir.join("https.key");
    if cert.exists() && key.exists() {
        return Ok((cert, key));
    }
    let mut names = vec!["localhost".to_owned()];
    if let Some(host) = config.http.public_url.as_deref().and_then(host_of) {
        names.push(host);
    }
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let certificate = rcgen::CertificateParams::new(names.clone())?.self_signed(&pair)?;
    write_private(&key, pair.serialize_pem().as_bytes())?;
    std::fs::write(&cert, certificate.pem())
        .with_context(|| format!("writing {}", cert.display()))?;
    tracing::info!(?names, path = %cert.display(), "made a self-signed HTTPS certificate");
    Ok((cert, key))
}

/// `desk.example.com` from `https://desk.example.com:8443/path`.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split('/').next()?;
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    };
    (!host.is_empty()).then(|| host.trim_matches(['[', ']']).to_owned())
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("writing {}", path.display()))?;
        file.write_all(contents)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_come_out_of_urls() {
        assert_eq!(
            host_of("https://desk.example.com").as_deref(),
            Some("desk.example.com")
        );
        assert_eq!(
            host_of("https://desk.example.com:8443/x").as_deref(),
            Some("desk.example.com")
        );
        assert_eq!(
            host_of("https://[2001:db8::1]:443").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(host_of("https://").as_deref(), None);
    }

    #[test]
    fn a_self_signed_certificate_is_made_once_and_reused() {
        let dir = std::env::temp_dir().join(format!("nearhand-https-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let mut config = Config::default();
        config.data.dir = dir.clone();
        config.http.public_url = Some("https://desk.example.com".into());

        assert!(server_config(&config).expect("make").is_some());
        let first = std::fs::read(dir.join("https.crt")).expect("cert");
        assert!(server_config(&config).expect("reuse").is_some());
        assert_eq!(std::fs::read(dir.join("https.crt")).expect("cert"), first);

        config.http.tls = Tls::None;
        assert!(server_config(&config).expect("plain").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

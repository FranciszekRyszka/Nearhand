//! `nearhand-server health`: whether the server running on this machine
//! answers, for a container's health check or a service monitor.
//!
//! Both sides are asked, over loopback: the QUIC port with a handshake
//! pinned to the server's own key — which proves it is this server, with
//! its key, and not merely something on the port — and the HTTP port for
//! `/api/v1/health`. Exit status 0 means both answered.
//!
//! The HTTPS certificate is not checked. The request goes to this machine
//! and carries nothing, and a certificate for the public name would not
//! match `localhost` anyway; the QUIC side is the one that proves identity.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nearhand_transport::{Identity, client_endpoint, connect_server};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::config::{Config, Tls};

/// How long either side has to answer.
const WAIT: Duration = Duration::from_secs(5);

pub async fn run(config: Config) -> Result<()> {
    let quic = local(config.quic.bind);
    let key = config.key_path();
    if !key.exists() {
        bail!(
            "no server key at {}: has the server started?",
            key.display()
        );
    }
    let identity = Identity::load_or_create(&key)
        .with_context(|| format!("reading the server key at {}", key.display()))?;
    tokio::time::timeout(WAIT, handshake(quic, &identity))
        .await
        .map_err(|_| anyhow::anyhow!("UDP {quic}: no answer within {WAIT:?}"))?
        .with_context(|| format!("UDP {quic}"))?;

    let http = local(config.http.bind);
    let tls = config.http.tls != Tls::None;
    let status = tokio::task::spawn_blocking(move || get_health(http, tls))
        .await
        .context("the HTTP check stopped")?
        .with_context(|| format!("TCP {http}"))?;
    if status != 200 {
        bail!("TCP {http}: /api/v1/health answered {status}");
    }
    println!("healthy: UDP {quic} answered with this server's key, TCP {http} with 200");
    Ok(())
}

/// Where to reach a server bound to `bind` from this machine.
fn local(bind: SocketAddr) -> SocketAddr {
    let ip = match bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, bind.port())
}

async fn handshake(to: SocketAddr, identity: &Identity) -> Result<()> {
    let endpoint = client_endpoint(to)?;
    let conn = connect_server(&endpoint, to, identity.fingerprint(), None).await?;
    conn.close(0u32.into(), b"healthy");
    endpoint.wait_idle().await;
    Ok(())
}

/// `GET /api/v1/health`, and the status it answered with.
fn get_health(to: SocketAddr, tls: bool) -> Result<u16> {
    let tcp = TcpStream::connect_timeout(&to, WAIT)?;
    tcp.set_read_timeout(Some(WAIT))?;
    tcp.set_write_timeout(Some(WAIT))?;
    let request = format!(
        "GET /api/v1/health HTTP/1.1\r\nHost: {to}\r\nConnection: close\r\nUser-Agent: nearhand-server health\r\n\r\n"
    );
    let mut answer = Vec::new();
    if tls {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        let name = ServerName::from(to.ip());
        let conn = rustls::ClientConnection::new(Arc::new(config), name)?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        stream.write_all(request.as_bytes())?;
        read_head(&mut stream, &mut answer)?;
    } else {
        let mut stream = tcp;
        stream.write_all(request.as_bytes())?;
        read_head(&mut stream, &mut answer)?;
    }
    status(&answer)
}

/// Read until the status line is in, or the other side stops.
fn read_head(stream: &mut impl Read, into: &mut Vec<u8>) -> Result<()> {
    let mut buf = [0u8; 512];
    while !into.contains(&b'\n') && into.len() < 4096 {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        into.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

/// The status code in an HTTP/1.1 answer's first line.
fn status(answer: &[u8]) -> Result<u16> {
    let line = answer
        .split(|&b| b == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default();
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .filter(|_| line.starts_with("HTTP/"))
        .with_context(|| format!("not an HTTP answer: {:?}", line.trim()))
}

/// Takes whatever certificate it is shown, and checks only that the
/// handshake is signed by it; see the module docs for why that is enough
/// here and nowhere else.
#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_bind_is_reached_on_loopback() {
        let v4: SocketAddr = "0.0.0.0:443".parse().expect("addr");
        assert_eq!(local(v4), "127.0.0.1:443".parse().expect("addr"));
        let v6: SocketAddr = "[::]:8443".parse().expect("addr");
        assert_eq!(local(v6), "[::1]:8443".parse().expect("addr"));
        let given: SocketAddr = "192.0.2.7:443".parse().expect("addr");
        assert_eq!(local(given), given);
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("a free port")
            .port()
    }

    /// The whole server, started as `serve` starts it, answers; and one that
    /// is not there does not.
    #[tokio::test]
    async fn a_running_server_is_healthy_and_a_missing_one_is_not() {
        let dir =
            std::env::temp_dir().join(format!("nearhand-server-health-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut config = Config::default();
        config.data.dir = dir.clone();
        // One port number for both, as by default; UDP and TCP are apart.
        let port = free_port();
        config.quic.bind = SocketAddr::from(([127, 0, 0, 1], port));
        config.http.bind = SocketAddr::from(([127, 0, 0, 1], port));
        config.quic.public_address = Some(format!("127.0.0.1:{port}"));

        assert!(run(config.clone()).await.is_err(), "nothing is running yet");

        let server = tokio::spawn(crate::serve(config.clone(), config.key_path()));
        let healthy = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match run(config.clone()).await {
                    Ok(()) => break,
                    Err(e) if server.is_finished() => panic!("the server stopped: {e:#}"),
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        })
        .await;
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
        healthy.expect("the server comes up healthy");
    }

    #[test]
    fn the_status_is_read_from_the_first_line() {
        assert_eq!(
            status(b"HTTP/1.1 200 OK\r\ncontent-type: x\r\n").expect("ok"),
            200
        );
        assert_eq!(
            status(b"HTTP/1.1 503 Service Unavailable\r\n").expect("ok"),
            503
        );
        assert!(status(b"SSH-2.0-OpenSSH\r\n").is_err());
        assert!(status(b"").is_err());
    }
}

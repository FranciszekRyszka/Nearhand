//! QUIC plumbing shared by the native agent and viewer: endpoint setup, key
//! pinning, and message framing on streams.
//!
//! Separate from `nearhand-core` because it depends on `quinn` and tokio, and
//! `core` must stay usable from the browser viewer, which speaks WebTransport.
//!
//! ## Trust model, M0
//!
//! The agent generates a self-signed certificate at startup and prints its
//! SHA-256 fingerprint. The viewer is given that fingerprint and accepts exactly
//! that certificate — no CA, no hostname check, but also no "accept anything":
//! the TLS handshake still proves the agent holds the matching private key.
//! From M2 the fingerprint arrives through the server instead of by hand, and
//! the key persists as the device identity (`docs/security.md`).

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use nearhand_core::{ALPN, StreamKind, wire};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig,
    TransportConfig,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The name the agent's certificate is issued to. Nothing resolves it — the
/// fingerprint is what identifies the agent — but TLS requires a name.
pub const SERVER_NAME: &str = "nearhand-agent";

/// Room for a whole keyframe burst. `send_datagram` discards the oldest queued
/// datagrams when this fills, which is the right policy for video, but it must
/// not trigger on a single keyframe: a 300 KB IDR frame is ~250 datagrams.
///
/// On a slow link this much is seconds of video, so the agent never lets it
/// fill: it reads the backlog (this minus `datagram_send_buffer_space`) and
/// stops taking frames while it is long.
pub const DATAGRAM_BUFFER: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("generating the certificate: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("connecting: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("reading a stream: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("writing a stream: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("{0}")]
    Protocol(#[from] nearhand_core::Error),
    #[error("invalid fingerprint: {0}")]
    Fingerprint(String),
    #[error("QUIC configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// SHA-256 of a certificate's DER encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(cert: &CertificateDer<'_>) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, cert.as_ref());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_ref());
        Self(bytes)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    /// Accepts 64 hex digits, optionally split by `:` or spaces the way
    /// fingerprints are often displayed.
    fn from_str(s: &str) -> Result<Self> {
        let hex: String = s
            .chars()
            .filter(|c| !matches!(c, ':' | ' ' | '-'))
            .collect();
        if hex.len() != 64 {
            return Err(Error::Fingerprint(format!(
                "expected 64 hex digits, got {}",
                hex.len()
            )));
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::Fingerprint(format!("not hex: {s}")))?;
        }
        Ok(Self(bytes))
    }
}

/// A certificate and its private key.
pub struct Identity {
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    fingerprint: Fingerprint,
}

impl Identity {
    /// A fresh self-signed identity. M0 generates one per run.
    pub fn generate() -> Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])?;
        let cert = certified.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let fingerprint = Fingerprint::of(&cert);
        Ok(Self {
            cert,
            key,
            fingerprint,
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
}

/// A QUIC endpoint that accepts viewers, presenting `identity`.
pub fn server_endpoint(bind: SocketAddr, identity: &Identity) -> Result<Endpoint> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.cert.clone()],
            PrivateKeyDer::Pkcs8(identity.key.clone_key()),
        )?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = QuicServerConfig::try_from(tls).map_err(|e| Error::Config(e.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));
    Ok(Endpoint::server(config, bind)?)
}

/// A client endpoint suited to reaching `remote`: same address family, any
/// local port.
pub fn client_endpoint(remote: SocketAddr) -> Result<Endpoint> {
    let bind: SocketAddr = if remote.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    Ok(Endpoint::client(bind)?)
}

/// Connect to an agent, accepting only the certificate with `fingerprint`.
pub async fn connect(
    endpoint: &Endpoint,
    remote: SocketAddr,
    fingerprint: Fingerprint,
) -> Result<Connection> {
    let provider = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer {
            fingerprint,
            provider,
        }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = QuicClientConfig::try_from(tls).map_err(|e| Error::Config(e.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));

    Ok(endpoint.connect_with(config, remote, SERVER_NAME)?.await?)
}

/// Write one length-prefixed message to a stream.
pub async fn send_message<T: Serialize>(send: &mut SendStream, message: &T) -> Result<()> {
    let bytes = wire::encode(message)?;
    send.write_all(&bytes).await?;
    Ok(())
}

/// Send every message from `messages` on a unidirectional stream tagged
/// `kind`, until the channel closes. The stream is opened with the first
/// message, so a channel that never carries anything costs nothing.
///
/// `priority` orders this stream against the connection's others; higher
/// goes first.
pub async fn send_all<T: Serialize>(
    conn: &Connection,
    kind: StreamKind,
    priority: i32,
    mut messages: tokio::sync::mpsc::UnboundedReceiver<T>,
) -> Result<()> {
    let Some(first) = messages.recv().await else {
        return Ok(());
    };
    let mut send = conn.open_uni().await?;
    // Fails only if the stream is already gone, which the write reports.
    let _ = send.set_priority(priority);
    send_message(&mut send, &kind).await?;
    send_message(&mut send, &first).await?;
    while let Some(message) = messages.recv().await {
        send_message(&mut send, &message).await?;
    }
    let _ = send.finish();
    Ok(())
}

/// Read one length-prefixed message. `Ok(None)` when the peer finished the
/// stream cleanly between messages.
pub async fn recv_message<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<Option<T>> {
    let mut header = [0u8; wire::HEADER_LEN];
    match recv.read_exact(&mut header).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut body = vec![0u8; wire::body_len(header)?];
    recv.read_exact(&mut body).await?;
    Ok(Some(wire::decode(&body)?))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport_config() -> Result<TransportConfig> {
    let mut config = TransportConfig::default();
    config
        // Keeps NAT bindings alive and notices a vanished peer promptly.
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(15))
                .map_err(|e| Error::Config(e.to_string()))?,
        ))
        .datagram_send_buffer_size(DATAGRAM_BUFFER)
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    // BBR rather than quinn's default Cubic. Cubic reads every lost packet as
    // congestion, so random loss alone caps it: on a 40 ms path with 5% loss
    // it could not send more than about 1.5 Mbit/s, and video fell to 6.5 fps.
    // BBR paces to the bandwidth it measures and held 36 fps at full bitrate
    // on the same path (docs/performance.md). quinn marks its BBR
    // experimental; it only shapes how fast packets leave, not what they say.
    config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Ok(config)
}

/// Accepts exactly one certificate, identified by its SHA-256.
///
/// Signatures are still checked against the pinned certificate's key, so a
/// peer that merely copied the certificate cannot complete the handshake.
#[derive(Debug)]
struct PinnedServer {
    fingerprint: Fingerprint,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if Fingerprint::of(end_entity) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_roundtrip_through_text() {
        let identity = Identity::generate().expect("identity");
        let text = identity.fingerprint().to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(
            text.parse::<Fingerprint>().expect("parse"),
            identity.fingerprint()
        );
    }

    #[test]
    fn fingerprints_accept_common_separators() {
        let plain = "00".repeat(31) + "ff";
        let colons = plain
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).expect("ascii"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            plain.parse::<Fingerprint>().expect("plain"),
            colons.parse::<Fingerprint>().expect("colons")
        );
    }

    #[test]
    fn malformed_fingerprints_are_rejected() {
        assert!("abc".parse::<Fingerprint>().is_err());
        assert!("zz".repeat(32).parse::<Fingerprint>().is_err());
    }

    #[test]
    fn identities_are_distinct() {
        let a = Identity::generate().expect("a");
        let b = Identity::generate().expect("b");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }
}

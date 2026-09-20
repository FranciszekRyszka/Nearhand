//! Browsers, over WebTransport on the QUIC port.
//!
//! A browser cannot speak raw QUIC, nor punch holes, so the web viewer
//! always comes through the relay. It opens a WebTransport session to
//! `https://<server>:<quic port>/nearhand`, asks on its first stream to be
//! introduced to a device (`ToServer::Connect`), and is answered as a native
//! viewer is (`FromServer::Peer`, or `Refused`). From then on the session's
//! datagrams are its tunnel: inside them runs the same QUIC connection to
//! the agent a native viewer runs, pinned to the agent's key, so the server
//! forwards packets it cannot read.
//!
//! Grants come from the REST API, where the browser is signed in
//! (`POST /api/v1/devices/{id}/grant`): WebTransport does not carry the
//! console's cookie.
//!
//! Browsers do not accept the server's Ed25519 certificate. WebTransport
//! connections get another ([`Web`]): the HTTPS certificate files when
//! configured, which browsers trust as they do the console's, or else a
//! self-signed ECDSA one that browsers take by its SHA-256 — which the
//! console hands them, over HTTPS — if it is valid for at most two weeks.
//! So the server makes a new one every few days, in memory.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use nearhand_core::rendezvous::{FromServer, Refusal, ToServer};
use nearhand_core::wire;
use nearhand_transport::WebCertificate;
use nearhand_transport::relay::Carrier;
use quinn::Connection;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::{Config, Tls};
use crate::rendezvous::{Registry, arrange};

/// Where on the server WebTransport sessions are accepted.
pub const PATH: &str = "/nearhand";
/// How long a browser has to open its session and say what it wants.
const FIRST_MESSAGE: Duration = Duration::from_secs(10);
/// A self-signed certificate's life: browsers take one by hash only if it
/// is valid for at most 14 days, counted from `not_before`.
const LIFETIME: time::Duration = time::Duration::days(13);
/// How often a new self-signed certificate is made. Pages ask for the hash
/// each time they connect, so a new one needs no warning.
const RENEW_EVERY: Duration = Duration::from_secs(6 * 24 * 3600);

/// The certificate browsers are shown, and what they are told about it.
pub struct Web {
    pub certificate: Arc<WebCertificate>,
    /// Hostnames a self-signed certificate is made for.
    names: Vec<String>,
    /// SHA-256 of the self-signed certificate; none when it is from a CA.
    hash: RwLock<Option<[u8; 32]>>,
}

impl Web {
    pub fn new(config: &Config) -> Result<Arc<Self>> {
        let mut names = vec!["localhost".to_owned()];
        if let Some(host) = crate::https::host_of(&config.public_address())
            && !names.contains(&host)
        {
            names.push(host);
        }
        let web = Arc::new(Self {
            certificate: Arc::default(),
            names,
            hash: RwLock::default(),
        });
        if config.http.tls == Tls::Files {
            let cert = config.http.cert.clone().context("http.cert")?;
            let key = config.http.key.clone().context("http.key")?;
            let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert)
                .with_context(|| format!("reading {}", cert.display()))?
                .collect::<Result<_, _>>()
                .with_context(|| format!("reading {}", cert.display()))?;
            let key = PrivateKeyDer::from_pem_file(&key)
                .with_context(|| format!("reading {}", key.display()))?;
            web.certificate
                .set(chain, key)
                .context("the HTTPS certificate, for WebTransport")?;
        } else {
            web.renew()?;
        }
        Ok(web)
    }

    /// The hash browsers must be told to accept, if the certificate is
    /// self-signed.
    pub fn hash(&self) -> Option<[u8; 32]> {
        *self.hash.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Make new self-signed certificates for as long as the server runs.
    pub async fn keep_renewing(self: Arc<Self>) {
        if self.hash().is_none() {
            return;
        }
        loop {
            tokio::time::sleep(RENEW_EVERY).await;
            if let Err(e) = self.renew() {
                tracing::error!(error = %format!("{e:#}"), "could not renew the WebTransport certificate");
            }
        }
    }

    fn renew(&self) -> Result<()> {
        let (chain, key, hash) = self_signed(&self.names)?;
        self.certificate.set(chain, key)?;
        *self.hash.write().unwrap_or_else(|p| p.into_inner()) = Some(hash);
        tracing::debug!(names = ?self.names, "new WebTransport certificate");
        Ok(())
    }
}

/// A self-signed ECDSA P-256 certificate for `names`, valid from an hour
/// ago for [`LIFETIME`], and its SHA-256.
pub(crate) fn self_signed(
    names: &[String],
) -> Result<(
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    [u8; 32],
)> {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(names.to_vec())?;
    // An hour's slack for a browser whose clock is a little behind.
    let from = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_before = from;
    params.not_after = from + LIFETIME;
    let certificate = params.self_signed(&pair)?;
    let der = certificate.der().clone();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, &der).as_ref());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der()));
    Ok((vec![der], key, hash))
}

/// Serve one browser: the WebTransport handshake on `conn`, then one
/// introduction and its relay.
pub async fn serve(conn: Connection, registry: &Registry) -> Result<()> {
    let observed = conn.remote_address();
    let request = tokio::time::timeout(FIRST_MESSAGE, web_transport_quinn::Request::accept(conn))
        .await
        .context("no WebTransport request in time")??;
    if request.url.path() != PATH {
        let path = request.url.path().to_owned();
        let _ = request.reject(axum::http::StatusCode::NOT_FOUND).await;
        bail!("WebTransport request for {path}");
    }
    let session = request.ok().await?;
    let (mut send, mut recv) = tokio::time::timeout(FIRST_MESSAGE, session.accept_bi())
        .await
        .context("no stream in time")??;
    let first = tokio::time::timeout(FIRST_MESSAGE, read::<ToServer>(&mut recv))
        .await
        .context("no first message in time")??;
    // A browser cannot be reached directly, so it gives no addresses.
    let result = match first {
        ToServer::Connect { id, .. } => arrange(registry, observed, id, Vec::new(), None).await,
        _ => Err(Refusal::Protocol),
    };
    let introduction = match result {
        Ok(introduction) => introduction,
        Err(refusal) => {
            write(&mut send, &FromServer::Refused(refusal)).await?;
            let _ = send.finish();
            // Let the browser read it before the session goes.
            let _ = tokio::time::timeout(Duration::from_secs(5), session.closed()).await;
            return Ok(());
        }
    };
    for message in introduction.messages() {
        write(&mut send, &message).await?;
    }
    let _ = send.finish();
    introduction.relay(Arc::new(Browser(session))).await;
    Ok(())
}

/// A browser's WebTransport session, as the viewer's side of a tunnel.
struct Browser(web_transport_quinn::Session);

impl Carrier for Browser {
    fn send_datagram(&self, datagram: Bytes) -> bool {
        self.0.send_datagram(datagram).is_ok()
    }

    fn read_datagram(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Bytes>> + Send + '_>> {
        Box::pin(async move { self.0.read_datagram().await.ok() })
    }

    fn describe(&self) -> String {
        "a browser".to_owned()
    }
}

async fn write<T: Serialize>(
    send: &mut web_transport_quinn::SendStream,
    message: &T,
) -> Result<()> {
    send.write_all(&wire::encode(message)?).await?;
    Ok(())
}

async fn read<T: DeserializeOwned>(recv: &mut web_transport_quinn::RecvStream) -> Result<T> {
    let mut header = [0u8; wire::HEADER_LEN];
    recv.read_exact(&mut header).await?;
    let mut body = vec![0u8; wire::body_len(header)?];
    recv.read_exact(&mut body).await?;
    Ok(wire::decode(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::serve as serve_quic;
    use crate::testkit::testing;
    use nearhand_core::rendezvous::DeviceId;
    use nearhand_transport::relay::{endpoint_over, relayed_address};
    use nearhand_transport::rendezvous::{Registration, stay_registered};
    use nearhand_transport::{
        Fingerprint, Identity, connect, rendezvous_server_config_with_web, server_endpoint,
    };

    #[test]
    fn self_signed_certificates_last_under_two_weeks() {
        let (chain, _, hash) = self_signed(&["localhost".to_owned()]).expect("certificate");
        assert_eq!(
            hash.as_slice(),
            ring::digest::digest(&ring::digest::SHA256, &chain[0]).as_ref()
        );
        assert!(LIFETIME < time::Duration::days(14));
        let (_, _, again) = self_signed(&["localhost".to_owned()]).expect("certificate");
        assert_ne!(hash, again, "a new key each time");
    }

    /// The browser's side, for the test: a WebTransport session as a tunnel.
    struct Session(web_transport_quinn::Session);

    impl Carrier for Session {
        fn send_datagram(&self, datagram: Bytes) -> bool {
            self.0.send_datagram(datagram).is_ok()
        }

        fn read_datagram(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Bytes>> + Send + '_>>
        {
            Box::pin(async move { self.0.read_datagram().await.ok() })
        }

        fn describe(&self) -> String {
            "test session".to_owned()
        }
    }

    /// Accept connections on `endpoint`, echoing each one's first stream.
    fn echo(endpoint: quinn::Endpoint) {
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await
                        && let Ok(data) = recv.read_to_end(64 * 1024).await
                    {
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                    }
                    conn.closed().await;
                });
            }
        });
    }

    /// A server with WebTransport, an agent registered with it, and a
    /// WebTransport client that trusts the server's certificate by hash.
    async fn world() -> (
        std::net::SocketAddr,
        DeviceId,
        Fingerprint,
        web_transport_quinn::Client,
    ) {
        let server_identity = Identity::generate().expect("server key");
        let web = Arc::new(WebCertificate::default());
        let (chain, key, hash) = self_signed(&["localhost".to_owned()]).expect("certificate");
        web.set(chain, key).expect("set");
        let server = quinn::Endpoint::server(
            rendezvous_server_config_with_web(&server_identity, web).expect("config"),
            ([127, 0, 0, 1], 0).into(),
        )
        .expect("server");
        let server_addr = server.local_addr().expect("addr");
        let registry = Arc::new(Registry::default());
        tokio::spawn(serve_quic(server, registry.clone()));

        let identity = Arc::new(Identity::generate().expect("agent key"));
        let agent = server_endpoint(([127, 0, 0, 1], 0).into(), &identity).expect("agent");
        let fp = server_identity.fingerprint();
        {
            let identity = identity.clone();
            tokio::spawn(async move {
                let events = |event| {
                    if let Registration::Registered { relay } = event {
                        echo(relay);
                    }
                };
                stay_registered(&agent, server_addr, fp, &identity, &testing(), events).await
            });
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while registry.online(&identity.fingerprint()).is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the agent registers");

        let client = web_transport_quinn::ClientBuilder::new()
            .with_server_certificate_hashes(vec![hash.to_vec()])
            .expect("client");
        (
            server_addr,
            identity.device_id(),
            identity.fingerprint(),
            client,
        )
    }

    async fn introduce(session: &web_transport_quinn::Session, id: DeviceId) -> FromServer {
        let (mut send, mut recv) = session.open_bi().await.expect("stream");
        write(
            &mut send,
            &ToServer::Connect {
                id,
                addresses: Vec::new(),
            },
        )
        .await
        .expect("ask");
        read(&mut recv).await.expect("answer")
    }

    #[tokio::test]
    async fn a_browser_reaches_an_agent_end_to_end_through_webtransport() {
        let (server, id, agent_fp, client) = world().await;
        let url: url::Url = format!("https://127.0.0.1:{}{PATH}", server.port())
            .parse()
            .expect("url");
        let session = client.connect(url).await.expect("WebTransport session");
        let FromServer::Peer { fingerprint, .. } = introduce(&session, id).await else {
            panic!("not introduced");
        };
        assert_eq!(Fingerprint::from_bytes(fingerprint), agent_fp);

        // The agent's own QUIC connection, inside the session's datagrams,
        // pinned to the agent's key.
        let tunnel = endpoint_over(Arc::new(Session(session)), false, None).expect("tunnel");
        let conn = tokio::time::timeout(
            Duration::from_secs(5),
            connect(&tunnel, relayed_address(0), agent_fp),
        )
        .await
        .expect("in time")
        .expect("end-to-end connection");
        let message: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let (mut send, mut recv) = conn.open_bi().await.expect("stream");
        send.write_all(&message).await.expect("write");
        send.finish().expect("finish");
        let echoed = recv.read_to_end(64 * 1024).await.expect("echo");
        assert_eq!(echoed, message, "through the browser's tunnel and back");
    }

    #[tokio::test]
    async fn browsers_are_refused_what_viewers_are() {
        let (server, _, _, client) = world().await;
        let url: url::Url = format!("https://127.0.0.1:{}{PATH}", server.port())
            .parse()
            .expect("url");
        let session = client.connect(url).await.expect("session");
        let nobody: DeviceId = "000 000 0001".parse().expect("id");
        assert_eq!(
            introduce(&session, nobody).await,
            FromServer::Refused(Refusal::Offline)
        );

        let elsewhere: url::Url = format!("https://127.0.0.1:{}/other", server.port())
            .parse()
            .expect("url");
        assert!(client.connect(elsewhere).await.is_err(), "only {PATH}");
    }
}

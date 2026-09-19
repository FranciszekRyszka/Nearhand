//! One viewing session, as a state machine with no I/O of its own: the
//! page feeds it the datagrams that arrive on its WebTransport session and
//! sends the ones it produces, calls [`Session::tick`] when
//! [`Session::next_wakeup`] comes, and takes [`Event`]s out — frames to
//! decode above all.
//!
//! Inside is a QUIC client (`quinn-proto`) connecting to the agent as a
//! native viewer does through the relay: TLS 1.3 pinned to the agent's
//! certificate fingerprint, the same ALPN, the same control protocol. The
//! relay sees only its packets.

use std::collections::VecDeque;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use nearhand_core::grant::SignedGrant;
use nearhand_core::proto::close;
use nearhand_core::video::{Reassembler, Timing, decode_chunk};
use nearhand_core::{ALPN, Caps, Codec, Control, Monitor, PROTOCOL_VERSION, wire};
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::{
    ClientConfig, Connection, ConnectionError, ConnectionHandle, DatagramEvent, Dir, Endpoint,
    EndpointConfig, IdleTimeout, StreamEvent, StreamId, TransportConfig, VarInt,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use web_time::Instant;

/// The name agents' certificates carry; see `nearhand_transport`.
const SERVER_NAME: &str = "nearhand-agent";
/// Keyframes are expensive: ask at most this often.
const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(250);
/// The largest packet this side sends. It must fit, with the WebTransport
/// and QUIC framing around it, in one datagram of the browser's connection
/// to the server; QUIC's minimum is 1200, and that is all it may use.
const MTU: u16 = 1200;
/// How often the session looks after itself without anything arriving.
const TICK: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("QUIC: {0}")]
    Connect(#[from] quinn_proto::ConnectError),
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Protocol(#[from] nearhand_core::Error),
}

/// How the viewer proves it may watch.
pub enum Auth {
    /// A grant from the server, for this device.
    Grant(SignedGrant),
    /// The password the agent shows, or its access password.
    Password(String),
}

/// What the page is told.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// The encrypted connection to the agent is up.
    Connected,
    /// The person at the device has been asked to allow the session.
    AwaitingApproval,
    /// In, and these are the device's monitors: start one's video.
    Monitors(Vec<Monitor>),
    /// A whole encoded frame, H.264 Annex B.
    Frame {
        keyframe: bool,
        capture_ts_us: u64,
        data: Bytes,
    },
    /// The session is over, and why.
    Closed(String),
}

pub struct Session {
    endpoint: Endpoint,
    conn: Connection,
    handle: ConnectionHandle,
    /// Where the agent is, as far as QUIC can tell: every packet goes into
    /// the one tunnel anyway.
    remote: SocketAddr,
    started: Instant,
    auth: Option<Auth>,
    max_fps: u8,
    control: Option<StreamId>,
    /// Bytes read from the control stream, not yet a whole message.
    control_in: Vec<u8>,
    /// Bytes for the control stream, not yet taken by QUIC.
    control_out: VecDeque<u8>,
    /// Packets to send that the endpoint made, not the connection.
    outgoing: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    reassembler: Reassembler,
    keyframe_needed: bool,
    last_keyframe_request: Option<Instant>,
    closed: bool,
}

impl Session {
    /// A session with the agent whose certificate has SHA-256
    /// `fingerprint`, connecting at once.
    pub fn new(fingerprint: [u8; 32], auth: Auth, max_fps: u8) -> Result<Self, Error> {
        let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None);
        let remote = SocketAddr::new(Ipv6Addr::from(0x0100u128 << 112).into(), 443);
        let now = Instant::now();
        let (handle, conn) =
            endpoint.connect(now, client_config(fingerprint)?, remote, SERVER_NAME)?;
        Ok(Self {
            endpoint,
            conn,
            handle,
            remote,
            started: now,
            auth: Some(auth),
            max_fps: max_fps.max(1),
            control: None,
            control_in: Vec::new(),
            control_out: VecDeque::new(),
            outgoing: VecDeque::new(),
            events: VecDeque::new(),
            reassembler: Reassembler::new(),
            keyframe_needed: false,
            last_keyframe_request: None,
            closed: false,
        })
    }

    /// A datagram from the tunnel.
    pub fn receive(&mut self, datagram: &[u8]) {
        let now = Instant::now();
        let mut buf = Vec::new();
        let event = self.endpoint.handle(
            now,
            self.remote,
            None,
            None,
            BytesMut::from(datagram),
            &mut buf,
        );
        match event {
            Some(DatagramEvent::ConnectionEvent(handle, event)) if handle == self.handle => {
                self.conn.handle_event(event);
            }
            Some(DatagramEvent::Response(transmit)) => {
                self.outgoing.push_back(buf[..transmit.size].to_vec());
            }
            _ => {}
        }
        self.drive();
    }

    /// The next packet for the tunnel, if there is one.
    pub fn transmit(&mut self) -> Option<Vec<u8>> {
        if let Some(packet) = self.outgoing.pop_front() {
            return Some(packet);
        }
        let mut buf = Vec::new();
        let transmit = self.conn.poll_transmit(Instant::now(), 1, &mut buf)?;
        buf.truncate(transmit.size);
        Some(buf)
    }

    /// When [`Session::tick`] should next be called.
    pub fn next_wakeup(&mut self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        let tick = Instant::now() + TICK;
        let quic = self.conn.poll_timeout();
        let repair = self
            .reassembler
            .next_deadline(&self.timing())
            .map(|at_us| self.started + Duration::from_micros(at_us));
        [Some(tick), quic, repair].into_iter().flatten().min()
    }

    /// Timers: QUIC's, and repairs of frames still missing chunks.
    pub fn tick(&mut self) {
        let now = Instant::now();
        if self.conn.poll_timeout().is_some_and(|at| at <= now) {
            self.conn.handle_timeout(now);
        }
        let now_us = self.now_us();
        let timing = self.timing();
        self.request_repairs(now_us);
        self.reassembler.expire(now_us, &timing);
        self.deliver();
        self.drive();
    }

    /// The next thing the page should know.
    pub fn event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Watch monitor `monitor`: video starts with a keyframe.
    pub fn start_video(&mut self, monitor: u8) {
        self.send_control(&Control::StartVideo {
            monitor,
            codec: Codec::H264,
            max_fps: self.max_fps,
        });
        self.drive();
    }

    /// Ask for a keyframe, after the decoder lost its footing.
    pub fn request_keyframe(&mut self) {
        self.keyframe_needed = true;
        self.drive();
    }

    /// Say goodbye to the agent.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.send_control(&Control::Bye);
        self.flush_control();
        self.conn.close(
            Instant::now(),
            VarInt::from_u32(close::NORMAL),
            Bytes::from_static(b"viewer leaving"),
        );
    }

    /// The round-trip time to the agent, through the relay.
    pub fn rtt(&self) -> Duration {
        self.conn.rtt()
    }

    fn now_us(&self) -> u64 {
        self.started.elapsed().as_micros() as u64
    }

    fn timing(&self) -> Timing {
        let rtt_us = self.conn.rtt().as_micros() as u64;
        Timing {
            quiet_us: rtt_us + 5_000,
            retry_us: rtt_us * 3 / 2 + 10_000,
            give_up_us: rtt_us * 3 + 60_000,
        }
    }

    /// Everything that follows from what just happened.
    fn drive(&mut self) {
        let now = Instant::now();
        while let Some(event) = self.conn.poll_endpoint_events() {
            if let Some(event) = self.endpoint.handle_event(self.handle, event) {
                self.conn.handle_event(event);
            }
        }
        while let Some(event) = self.conn.poll() {
            match event {
                quinn_proto::Event::Connected => self.connected(),
                quinn_proto::Event::Stream(StreamEvent::Readable { id }) => self.read(id),
                quinn_proto::Event::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                    // The agent's cursor and clipboard streams: not shown
                    // yet, so read and dropped.
                    while let Some(id) = self.conn.streams().accept(Dir::Uni) {
                        self.read(id);
                    }
                }
                quinn_proto::Event::DatagramReceived => self.datagrams(),
                quinn_proto::Event::ConnectionLost { reason } => self.lost(reason),
                _ => {}
            }
        }
        let wants_keyframe = self.keyframe_needed || self.reassembler.take_keyframe_request();
        let may_ask = self
            .last_keyframe_request
            .is_none_or(|t| now.duration_since(t) >= KEYFRAME_REQUEST_INTERVAL);
        if wants_keyframe && may_ask && self.control.is_some() {
            self.send_control(&Control::RequestKeyframe);
            self.last_keyframe_request = Some(now);
            self.keyframe_needed = false;
        } else {
            self.keyframe_needed = wants_keyframe;
        }
        self.flush_control();
    }

    fn connected(&mut self) {
        self.events.push_back(Event::Connected);
        let Some(id) = self.conn.streams().open(Dir::Bi) else {
            self.fail("no stream to the agent");
            return;
        };
        self.control = Some(id);
        self.send_control(&Control::Hello {
            version: PROTOCOL_VERSION,
            caps: Caps {
                codecs: vec![Codec::H264],
                max_width: u16::MAX,
                max_height: u16::MAX,
                max_fps: self.max_fps,
            },
        });
    }

    fn read(&mut self, id: StreamId) {
        let control = Some(id) == self.control;
        let mut stream = self.conn.recv_stream(id);
        let Ok(mut chunks) = stream.read(true) else {
            return;
        };
        let mut finished = false;
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) if control => self.control_in.extend_from_slice(&chunk.bytes),
                Ok(Some(_)) => {}
                Ok(None) => {
                    finished = true;
                    break;
                }
                Err(_) => break,
            }
        }
        let _ = chunks.finalize();
        if control {
            self.parse_control();
            if finished && !self.closed {
                self.fail("the agent ended the session");
            }
        }
    }

    fn parse_control(&mut self) {
        while self.control_in.len() >= wire::HEADER_LEN {
            let mut header = [0u8; wire::HEADER_LEN];
            header.copy_from_slice(&self.control_in[..wire::HEADER_LEN]);
            let len = match wire::body_len(header) {
                Ok(len) => len,
                Err(e) => {
                    self.fail(&e.to_string());
                    return;
                }
            };
            if self.control_in.len() < wire::HEADER_LEN + len {
                return;
            }
            let body: Vec<u8> = self.control_in.drain(..wire::HEADER_LEN + len).collect();
            match wire::decode::<Control>(&body[wire::HEADER_LEN..]) {
                Ok(message) => self.control_message(message),
                Err(e) => {
                    self.fail(&e.to_string());
                    return;
                }
            }
        }
    }

    fn control_message(&mut self, message: Control) {
        match message {
            Control::Hello { version, .. } if version != PROTOCOL_VERSION => {
                self.fail(&format!(
                    "the agent speaks protocol {version}, this viewer {PROTOCOL_VERSION}"
                ));
            }
            Control::Hello { caps, .. } if !caps.codecs.contains(&Codec::H264) => {
                self.fail("the agent offers no H.264 encoder");
            }
            Control::Hello { .. } => {}
            Control::AuthRequired => {
                let answer = match self.auth.take() {
                    Some(Auth::Grant(grant)) => Control::Present { grant },
                    Some(Auth::Password(password)) => Control::Authenticate { password },
                    None => {
                        self.fail("the agent asked twice to be let in");
                        return;
                    }
                };
                self.send_control(&answer);
            }
            Control::AwaitingApproval => self.events.push_back(Event::AwaitingApproval),
            Control::MonitorList(monitors) => self.events.push_back(Event::Monitors(monitors)),
            _ => {}
        }
    }

    fn datagrams(&mut self) {
        let now_us = self.now_us();
        while let Some(datagram) = self.conn.datagrams().recv() {
            if let Ok(chunk) = decode_chunk(&datagram) {
                self.reassembler.push(chunk, now_us);
            }
        }
        self.deliver();
        self.request_repairs(now_us);
    }

    fn deliver(&mut self) {
        while let Some(frame) = self.reassembler.pop() {
            self.events.push_back(Event::Frame {
                keyframe: frame.keyframe,
                capture_ts_us: frame.capture_ts_us,
                data: frame.data,
            });
        }
    }

    fn request_repairs(&mut self, now_us: u64) {
        if self.control.is_none() {
            return;
        }
        let timing = self.timing();
        for missing in self.reassembler.nacks(now_us, &timing) {
            self.send_control(&Control::Nack {
                frame_id: missing.frame_id,
                chunks: missing.chunks,
            });
        }
    }

    fn send_control(&mut self, message: &Control) {
        match wire::encode(message) {
            Ok(bytes) => self.control_out.extend(bytes),
            Err(e) => self.fail(&e.to_string()),
        }
    }

    fn flush_control(&mut self) {
        let Some(id) = self.control else {
            return;
        };
        while !self.control_out.is_empty() {
            let (front, _) = self.control_out.as_slices();
            match self.conn.send_stream(id).write(front) {
                Ok(0) | Err(_) => break,
                Ok(written) => {
                    self.control_out.drain(..written);
                }
            }
        }
    }

    fn lost(&mut self, reason: ConnectionError) {
        let why = match reason {
            ConnectionError::ApplicationClosed(close) => {
                let text = String::from_utf8_lossy(&close.reason).into_owned();
                if u64::from(close.error_code) == u64::from(close::NORMAL) {
                    format!("the session ended ({text})")
                } else {
                    format!("the agent closed the connection: {text}")
                }
            }
            ConnectionError::TimedOut => "the agent stopped answering".to_owned(),
            ConnectionError::LocallyClosed => "the session ended".to_owned(),
            other => other.to_string(),
        };
        self.closed = true;
        self.events.push_back(Event::Closed(why));
    }

    fn fail(&mut self, why: &str) {
        if self.closed {
            return;
        }
        self.conn.close(
            Instant::now(),
            VarInt::from_u32(close::PROTOCOL),
            Bytes::copy_from_slice(why.as_bytes()),
        );
        self.closed = true;
        self.events.push_back(Event::Closed(why.to_owned()));
    }
}

/// A QUIC client configuration that accepts only the certificate with
/// SHA-256 `fingerprint`, speaking the viewer-to-agent protocol.
fn client_config(fingerprint: [u8; 32]) -> Result<ClientConfig, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            fingerprint,
            provider,
        }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).map_err(|e| Error::Config(e.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(15))
                .map_err(|e| Error::Config(e.to_string()))?,
        ))
        .datagram_receive_buffer_size(Some(16 * 1024 * 1024))
        .initial_mtu(MTU)
        .min_mtu(MTU)
        // Larger packets would not fit the tunnel's datagrams.
        .mtu_discovery_config(None);
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Accepts the one certificate whose SHA-256 is `fingerprint`, and checks
/// the handshake's signatures as usual: the agent must hold its key.
#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity);
        if digest.as_ref() == self.fingerprint {
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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

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
//!
//! Keyboard and mouse go on a stream of their own at the highest priority,
//! clipboard text on another at the lowest, as the native viewer sends
//! them; the agent's pointer shape and clipboard come back the same way.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use nearhand_core::access;
use nearhand_core::grant::SignedGrant;
use nearhand_core::held::Held;
use nearhand_core::proto::close;
use nearhand_core::video::{Reassembler, Timing, decode_chunk};
use nearhand_core::{
    ALPN, Caps, Clipboard, Codec, Control, Cursor, CursorShape, Input, Monitor, PROTOCOL_VERSION,
    StreamKind, wire,
};
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::{
    ClientConfig, Connection, ConnectionError, ConnectionHandle, DatagramEvent, Dir, Endpoint,
    EndpointConfig, IdleTimeout, StreamEvent, StreamId, TransportConfig, VarInt,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use serde::de::DeserializeOwned;
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
/// Stream priorities, as the native viewer sets them: input first,
/// clipboard text last so a large paste never holds up a keystroke.
const INPUT_PRIORITY: i32 = 1;
const CLIPBOARD_PRIORITY: i32 = -1;

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

/// How the viewer proves it may watch: a grant from the server, the
/// password the agent shows or its access password — or, where the device
/// asks for both, a grant and the password together.
pub struct Auth {
    pub grant: Option<SignedGrant>,
    pub password: Option<String>,
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
    /// The agent's pointer looks like this now; checked for sense.
    CursorShape(CursorShape),
    /// Whether the agent shows a pointer on the watched monitor.
    CursorVisible(bool),
    /// Text copied on the device.
    Clipboard(String),
    /// The session is over, and why.
    Closed(String),
    /// The device asks for its access password as well as a grant, and
    /// this viewer was given only the grant. Nothing has been presented,
    /// so the grant is still good: ask for the password and start again.
    PasswordAlsoNeeded,
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
    /// The password exchange, between its messages.
    proving: Option<Proving>,
    max_fps: u8,
    control: Option<StreamId>,
    /// Bytes read from the control stream, not yet a whole message.
    control_in: Vec<u8>,
    /// Bytes for the control stream, not yet taken by QUIC.
    control_out: VecDeque<u8>,
    input: Outgoing,
    clipboard: Outgoing,
    /// Streams from the agent: what each carries, once its first message
    /// says, and bytes not yet a whole message.
    incoming: HashMap<StreamId, (Option<StreamKind>, Vec<u8>)>,
    /// What this viewer holds down, to let go of when it loses focus.
    held: Held,
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
            proving: None,
            max_fps: max_fps.max(1),
            control: None,
            control_in: Vec::new(),
            control_out: VecDeque::new(),
            input: Outgoing::new(StreamKind::Input, INPUT_PRIORITY),
            clipboard: Outgoing::new(StreamKind::Clipboard, CLIPBOARD_PRIORITY),
            incoming: HashMap::new(),
            held: Held::default(),
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

    /// Keyboard or mouse. Key and button presses are remembered, so that
    /// [`Session::release_all`] can let go of them.
    pub fn input(&mut self, event: Input) {
        match &event {
            Input::Key { scancode, down } => {
                let was_down = self.held.key(*scancode, *down);
                // A release of a key this viewer never pressed is not the
                // agent's business.
                if !down && !was_down {
                    return;
                }
            }
            Input::MouseButton { button, down } => self.held.button(*button, *down),
            _ => {}
        }
        if self.control.is_none() {
            return;
        }
        if let Err(e) = self.input.push(&event) {
            self.fail(&e.to_string());
        }
        self.drive();
    }

    /// Let go of every key and button held: the page lost focus, and the
    /// releases would go elsewhere.
    pub fn release_all(&mut self) {
        let (keys, buttons) = self.held.take();
        for scancode in keys {
            let _ = self.input.push(&Input::Key {
                scancode,
                down: false,
            });
        }
        for button in buttons {
            let _ = self.input.push(&Input::MouseButton {
                button,
                down: false,
            });
        }
        self.drive();
    }

    /// Text copied in the browser, for the device's clipboard.
    pub fn clipboard(&mut self, text: String) {
        if text.is_empty() || text.len() > Clipboard::MAX_TEXT || self.control.is_none() {
            return;
        }
        let text = text.replace("\r\n", "\n");
        if let Err(e) = self.clipboard.push(&Clipboard::Text(text)) {
            self.fail(&e.to_string());
        }
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
                    while let Some(id) = self.conn.streams().accept(Dir::Uni) {
                        self.incoming.insert(id, (None, Vec::new()));
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
        if let Err(e) = self.input.flush(&mut self.conn) {
            self.fail(&e);
        }
        if let Err(e) = self.clipboard.flush(&mut self.conn) {
            self.fail(&e);
        }
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
        let mut received = Vec::new();
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => received.extend_from_slice(&chunk.bytes),
                Ok(None) => {
                    finished = true;
                    break;
                }
                Err(_) => break,
            }
        }
        let _ = chunks.finalize();
        if control {
            self.control_in.extend_from_slice(&received);
            self.parse_control();
            if finished && !self.closed {
                self.fail("the agent ended the session");
            }
        } else {
            self.read_incoming(id, &received);
            if finished {
                self.incoming.remove(&id);
            }
        }
    }

    /// Messages on one of the agent's own streams: pointer or clipboard.
    fn read_incoming(&mut self, id: StreamId, received: &[u8]) {
        let Some((kind, buffer)) = self.incoming.get_mut(&id) else {
            return;
        };
        buffer.extend_from_slice(received);
        let mut messages = Vec::new();
        let mut broken = None;
        loop {
            match kind {
                None => match take::<StreamKind>(buffer) {
                    Ok(Some(k)) => *kind = Some(k),
                    Ok(None) => break,
                    Err(e) => {
                        broken = Some(e);
                        break;
                    }
                },
                Some(StreamKind::Cursor) => match take::<Cursor>(buffer) {
                    Ok(Some(Cursor::Shape(shape))) if shape.is_valid() => {
                        messages.push(Event::CursorShape(shape));
                    }
                    Ok(Some(Cursor::Shape(_))) => {}
                    Ok(Some(Cursor::Visible(visible))) => {
                        messages.push(Event::CursorVisible(visible));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        broken = Some(e);
                        break;
                    }
                },
                Some(StreamKind::Clipboard) => match take::<Clipboard>(buffer) {
                    Ok(Some(Clipboard::Text(text))) if text.len() <= Clipboard::MAX_TEXT => {
                        messages.push(Event::Clipboard(text));
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(e) => {
                        broken = Some(e);
                        break;
                    }
                },
                // Not a stream the agent sends: ignore what it carries.
                Some(StreamKind::Input) => {
                    buffer.clear();
                    break;
                }
            }
        }
        self.events.extend(messages);
        if let Some(e) = broken {
            self.fail(&e);
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
            Control::AuthRequired { required } => self.asked_for(required),
            Control::AuthAnswer { pake } => self.prove(&pake),
            Control::AuthProved { proof } => self.check_the_agent(&proof),
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

    /// Answer what the agent asks for: a grant from its server, the
    /// password, either, or both (`nearhand_core::access::Required`).
    fn asked_for(&mut self, required: access::Required) {
        let Some(auth) = self.auth.take() else {
            return self.fail("the agent asked twice to be let in");
        };
        match (auth.grant, auth.password) {
            (Some(grant), password) => {
                if !required.takes_grants() {
                    return self.fail("this device takes a password, not a grant from a server");
                }
                // Nothing is presented until the viewer can finish: a grant
                // is good once, and this one is still unused.
                if required.password_after_grant() && password.is_none() {
                    self.closed = true;
                    self.conn.close(
                        Instant::now(),
                        VarInt::from_u32(close::NORMAL),
                        Bytes::from_static(b"a password is needed as well"),
                    );
                    return self.events.push_back(Event::PasswordAlsoNeeded);
                }
                self.send_control(&Control::Present { grant });
                if let (true, Some(secret), Some(password)) = (
                    required.password_after_grant(),
                    required.secret(),
                    password.as_deref(),
                ) {
                    let secret = secret.clone();
                    self.start_proving(&secret, password);
                }
            }
            (None, Some(password)) => {
                match required.secret().filter(|_| required.password_is_enough()) {
                    Some(secret) => {
                        let secret = secret.clone();
                        self.start_proving(&secret, &password);
                    }
                    None => {
                        self.fail("this device needs a grant from its server; sign in to it first")
                    }
                }
            }
            (None, None) => self.fail("nothing to be let in with"),
        }
    }

    /// Begin proving the password without sending it: the exchange in
    /// `nearhand_core::access`, tied to this connection, so that whatever
    /// introduced this viewer to the agent cannot stand in the middle of
    /// it.
    fn start_proving(&mut self, secret: &access::Secret, password: &str) {
        let binding = match self.binding() {
            Ok(binding) => binding,
            Err(why) => return self.fail(&why),
        };
        let seed = match seed() {
            Ok(seed) => seed,
            Err(why) => return self.fail(&why),
        };
        // Stretching an access password is slow on purpose — the agent
        // stored it that way — and there is nothing else for this viewer to
        // be doing until it is in.
        let material = match secret.material(password) {
            Ok(material) => material,
            Err(e) => return self.fail(&e.to_string()),
        };
        let (viewer, start) = access::Viewer::start(&material, &binding, seed);
        self.proving = Some(Proving::Started(viewer));
        self.send_control(&Control::AuthStart { pake: start });
    }

    /// The agent's half of the exchange: prove the password to it.
    fn prove(&mut self, pake: &[u8]) {
        let Some(Proving::Started(viewer)) = self.proving.take() else {
            return self.fail("the agent answered a password exchange that never started");
        };
        match viewer.prove(pake) {
            Ok((proven, proof)) => {
                self.proving = Some(Proving::Proven(proven));
                self.send_control(&Control::AuthProve {
                    proof: proof.to_vec(),
                });
            }
            Err(e) => self.fail(&e.to_string()),
        }
    }

    /// The agent's proof in return. Without it this viewer would know the
    /// password reached something, not that it reached the device.
    fn check_the_agent(&mut self, proof: &[u8]) {
        let Some(Proving::Proven(proven)) = self.proving.take() else {
            return self.fail("the agent proved a password exchange that never started");
        };
        if proven.check(proof).is_err() {
            self.fail(
                "the agent cannot prove it knows the password:                  something is standing between this viewer and the device",
            );
        }
    }

    /// Keying material only the two ends of this connection can derive.
    fn binding(&self) -> Result<[u8; access::BINDING_LEN], String> {
        let mut out = [0u8; access::BINDING_LEN];
        self.conn
            .crypto_session()
            .export_keying_material(&mut out, access::BINDING_LABEL, b"")
            .map_err(|_| "this connection carries no password exchange".to_owned())?;
        Ok(out)
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

/// The password exchange, between the messages that carry it.
enum Proving {
    Started(access::Viewer),
    Proven(access::Proven),
}

/// Randomness for one exchange, from the browser — the same source TLS
/// here draws on.
fn seed() -> Result<access::Seed, String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 64];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "this browser gave no random numbers".to_owned())?;
    Ok(access::Seed(bytes))
}

/// One whole message off the front of `buffer`, if it holds one.
fn take<T: DeserializeOwned>(buffer: &mut Vec<u8>) -> Result<Option<T>, String> {
    if buffer.len() < wire::HEADER_LEN {
        return Ok(None);
    }
    let mut header = [0u8; wire::HEADER_LEN];
    header.copy_from_slice(&buffer[..wire::HEADER_LEN]);
    let len = wire::body_len(header).map_err(|e| e.to_string())?;
    if buffer.len() < wire::HEADER_LEN + len {
        return Ok(None);
    }
    let message =
        wire::decode(&buffer[wire::HEADER_LEN..wire::HEADER_LEN + len]).map_err(|e| e.to_string());
    buffer.drain(..wire::HEADER_LEN + len);
    message.map(Some)
}

/// A stream from this viewer to the agent, opened when first needed: its
/// kind first, then its messages.
struct Outgoing {
    kind: StreamKind,
    priority: i32,
    id: Option<StreamId>,
    /// Bytes QUIC has not taken yet.
    queue: VecDeque<u8>,
}

impl Outgoing {
    fn new(kind: StreamKind, priority: i32) -> Self {
        Self {
            kind,
            priority,
            id: None,
            queue: VecDeque::new(),
        }
    }

    fn push<T: Serialize>(&mut self, message: &T) -> Result<(), nearhand_core::Error> {
        if self.id.is_none() && self.queue.is_empty() {
            self.queue.extend(wire::encode(&self.kind)?);
        }
        self.queue.extend(wire::encode(message)?);
        Ok(())
    }

    /// Hand QUIC what it will take, opening the stream if need be.
    fn flush(&mut self, conn: &mut Connection) -> Result<(), String> {
        if self.queue.is_empty() {
            return Ok(());
        }
        let id = match self.id {
            Some(id) => id,
            None => {
                // No stream to be had yet: the agent has not allowed one.
                let Some(id) = conn.streams().open(Dir::Uni) else {
                    return Ok(());
                };
                let _ = conn.send_stream(id).set_priority(self.priority);
                self.id = Some(id);
                id
            }
        };
        while !self.queue.is_empty() {
            let (front, _) = self.queue.as_slices();
            match conn.send_stream(id).write(front) {
                Ok(0) => break,
                Ok(written) => {
                    self.queue.drain(..written);
                }
                Err(quinn_proto::WriteError::Blocked) => break,
                Err(e) => return Err(format!("{:?} stream: {e}", self.kind)),
            }
        }
        Ok(())
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

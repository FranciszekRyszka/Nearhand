//! The browser's session, run natively against a stand-in agent over UDP:
//! the same QUIC and protocol a real agent speaks, with a frame to watch.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use nearhand_core::proto::close;
use nearhand_core::video::{encode_chunk, packetize};
use nearhand_core::{Caps, Codec, Control, Monitor, PROTOCOL_VERSION};
use nearhand_transport::{Identity, recv_message, send_message, server_endpoint};
use nearhand_web::session::{Auth, Event, Session};
use tokio::net::UdpSocket;

const PASSWORD: &str = "correct horse battery";

/// A frame's worth of bytes, recognisable when it comes back whole.
fn picture() -> Bytes {
    (0..20_000u32)
        .map(|i| (i * 7) as u8)
        .collect::<Vec<u8>>()
        .into()
}

/// An agent that lets in whoever has [`PASSWORD`], lists one monitor, and on
/// `StartVideo` sends [`picture`] as a keyframe — its third chunk only when
/// asked again, to be sure repairs work.
fn agent(identity: &Identity) -> SocketAddr {
    let endpoint = server_endpoint(([127, 0, 0, 1], 0).into(), identity).expect("agent endpoint");
    let address = endpoint.local_addr().expect("address");
    tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("connection");
        let (mut send, mut recv) = conn.accept_bi().await.expect("control stream");
        let Some(Control::Hello { version, .. }) = recv_message(&mut recv).await.expect("hello")
        else {
            panic!("expected Hello");
        };
        assert_eq!(version, PROTOCOL_VERSION);
        let caps = Caps {
            codecs: vec![Codec::H264],
            max_width: 1920,
            max_height: 1080,
            max_fps: 60,
        };
        send_message(&mut send, &Control::Hello { version, caps })
            .await
            .expect("hello");
        send_message(&mut send, &Control::AuthRequired)
            .await
            .expect("auth");
        match recv_message(&mut recv).await.expect("answer") {
            Some(Control::Authenticate { password }) if password == PASSWORD => {}
            other => {
                conn.close(close::AUTH_FAILED.into(), b"wrong password");
                panic!("unexpected {other:?}");
            }
        }
        let monitor = Monitor {
            id: 0,
            width: 1920,
            height: 1080,
            x: 0,
            y: 0,
            primary: true,
        };
        send_message(&mut send, &Control::MonitorList(vec![monitor]))
            .await
            .expect("monitors");
        let chunks = loop {
            match recv_message(&mut recv).await.expect("message") {
                Some(Control::StartVideo { .. }) => {
                    break packetize(1, true, 42, &picture(), 1100).expect("packetize");
                }
                Some(_) => {}
                None => return,
            }
        };
        for chunk in chunks.iter().filter(|c| c.chunk != 2) {
            let _ = conn.send_datagram(encode_chunk(chunk).expect("encode").into());
        }
        while let Ok(Some(message)) = recv_message::<Control>(&mut recv).await {
            if let Control::Nack {
                frame_id: 1,
                chunks: missing,
            } = message
            {
                for chunk in chunks.iter().filter(|c| missing.contains(&c.chunk)) {
                    let _ = conn.send_datagram(encode_chunk(chunk).expect("encode").into());
                }
            }
        }
        conn.closed().await;
    });
    address
}

/// Run `session` against `agent` over a real UDP socket until an event
/// satisfies `until`, or give up after a few seconds.
async fn run_until(
    session: &mut Session,
    socket: &UdpSocket,
    agent: SocketAddr,
    mut until: impl FnMut(&Event) -> bool,
) -> Vec<Event> {
    let mut seen = Vec::new();
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        while let Some(packet) = session.transmit() {
            socket.send_to(&packet, agent).await.expect("send");
        }
        while let Some(event) = session.event() {
            let done = until(&event);
            seen.push(event);
            if done {
                return seen;
            }
        }
        let wake = session
            .next_wakeup()
            .map(|at| at.saturating_duration_since(web_time::Instant::now()))
            .unwrap_or(Duration::from_millis(50));
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (len, _) = received.expect("receive");
                session.receive(&buf[..len]);
            }
            () = tokio::time::sleep(wake) => session.tick(),
            () = tokio::time::sleep_until(deadline) => panic!("gave up; saw {seen:?}"),
        }
    }
}

#[tokio::test]
async fn a_session_authenticates_and_receives_a_whole_frame() {
    let identity = Identity::generate().expect("agent key");
    let agent = agent(&identity);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("socket");
    let mut session = Session::new(
        *identity.fingerprint().as_bytes(),
        Auth::Password(PASSWORD.to_owned()),
        60,
    )
    .expect("session");

    let seen = run_until(&mut session, &socket, agent, |e| {
        matches!(e, Event::Monitors(_))
    })
    .await;
    assert_eq!(seen.first(), Some(&Event::Connected));
    let Some(Event::Monitors(monitors)) = seen.last() else {
        panic!("no monitors");
    };
    assert_eq!(monitors[0].width, 1920);

    session.start_video(0);
    let seen = run_until(&mut session, &socket, agent, |e| {
        matches!(e, Event::Frame { .. })
    })
    .await;
    let Some(Event::Frame {
        keyframe,
        capture_ts_us,
        data,
    }) = seen.last()
    else {
        panic!("no frame");
    };
    assert!(*keyframe);
    assert_eq!(*capture_ts_us, 42);
    assert_eq!(data, &picture(), "whole, the missing chunk repaired");
}

#[tokio::test]
async fn a_session_pinned_to_another_key_never_connects() {
    let identity = Identity::generate().expect("agent key");
    let agent = agent(&identity);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("socket");
    let other = Identity::generate().expect("another key");
    let mut session = Session::new(
        *other.fingerprint().as_bytes(),
        Auth::Password(PASSWORD.to_owned()),
        60,
    )
    .expect("session");
    let seen = run_until(&mut session, &socket, agent, |e| {
        matches!(e, Event::Closed(_))
    })
    .await;
    assert!(!seen.contains(&Event::Connected), "{seen:?}");
    let Some(Event::Closed(why)) = seen.last() else {
        panic!("not closed");
    };
    assert!(!why.is_empty());
}

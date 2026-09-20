//! Real QUIC handshakes over loopback: the pinning has to hold on the wire, not
//! just in a unit test of the verifier.

use std::net::SocketAddr;

use nearhand_core::Control;
use nearhand_transport::{
    Fingerprint, Identity, client_endpoint, connect, recv_message, send_message, server_endpoint,
};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("address")
}

#[tokio::test]
async fn pinned_fingerprint_connects_and_carries_messages() {
    let identity = Identity::generate().expect("identity");
    let server = server_endpoint(loopback(), &identity).expect("server");
    let addr = server.local_addr().expect("server address");

    let accept = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("handshake");
        let (mut send, mut recv) = conn.accept_bi().await.expect("stream");
        let hello: Control = recv_message(&mut recv)
            .await
            .expect("read")
            .expect("message");
        send_message(&mut send, &hello).await.expect("echo");
        send.finish().expect("finish");
        // Hold the connection until the client has read the echo.
        conn.closed().await;
    });

    let client = client_endpoint(addr).expect("client");
    let conn = connect(&client, addr, identity.fingerprint())
        .await
        .expect("connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("stream");

    let hello = Control::Bye;
    send_message(&mut send, &hello).await.expect("send");
    let echo: Control = recv_message(&mut recv)
        .await
        .expect("read")
        .expect("message");
    assert_eq!(echo, hello);
    // The server finished its side: the next read is a clean end, not an error.
    assert!(
        recv_message::<Control>(&mut recv)
            .await
            .expect("read")
            .is_none()
    );

    conn.close(0u32.into(), b"done");
    let _ = accept.await;
}

#[tokio::test]
async fn wrong_fingerprint_is_refused() {
    let identity = Identity::generate().expect("identity");
    let server = server_endpoint(loopback(), &identity).expect("server");
    let addr = server.local_addr().expect("server address");
    tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });

    let impostor: Fingerprint = "ab".repeat(32).parse().expect("fingerprint");
    let client = client_endpoint(addr).expect("client");
    let result = connect(&client, addr, impostor).await;
    assert!(
        result.is_err(),
        "connected to a certificate that was not pinned"
    );
}

#[tokio::test]
async fn another_agents_certificate_is_refused() {
    // A real, valid certificate — just not the one we pinned.
    let genuine = Identity::generate().expect("genuine");
    let other = Identity::generate().expect("other");
    let server = server_endpoint(loopback(), &other).expect("server");
    let addr = server.local_addr().expect("server address");
    tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });

    let client = client_endpoint(addr).expect("client");
    assert!(connect(&client, addr, genuine.fingerprint()).await.is_err());
}

/// The password exchange in `nearhand_core::access` is tied to one
/// connection by keying material exported from its TLS session. What makes
/// that worth anything is here: both ends of a connection derive the same
/// bytes, and another connection — a server's own to each side, say —
/// derives different ones.
#[tokio::test]
async fn keying_material_is_this_connection_and_no_other() {
    let identity = Identity::generate().expect("identity");
    let server = server_endpoint(loopback(), &identity).expect("server");
    let addr = server.local_addr().expect("server address");

    let accept = tokio::spawn(async move {
        let mut bindings = Vec::new();
        for _ in 0..2 {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            bindings.push(nearhand_transport::access::binding(&conn).expect("binding"));
            // Held open: a closed connection exports nothing.
            tokio::spawn(async move { conn.closed().await });
        }
        bindings
    });

    let client = client_endpoint(addr).expect("client");
    let mut ours = Vec::new();
    let mut connections = Vec::new();
    for _ in 0..2 {
        let conn = connect(&client, addr, identity.fingerprint())
            .await
            .expect("connect");
        // A connection's keys are ready once it is, so a stream is not
        // needed; open one anyway, as a session would.
        let (mut send, _recv) = conn.open_bi().await.expect("stream");
        send_message(&mut send, &Control::Bye).await.expect("send");
        ours.push(nearhand_transport::access::binding(&conn).expect("binding"));
        connections.push(conn);
    }
    let theirs = accept.await.expect("accepting");

    assert_eq!(ours[0], theirs[0], "the two ends of one connection");
    assert_eq!(ours[1], theirs[1], "the two ends of the other");
    assert_ne!(ours[0], ours[1], "two connections, one binding");
    assert_ne!(ours[0], [0; 32]);

    for conn in connections {
        conn.close(0u32.into(), b"done");
    }
}

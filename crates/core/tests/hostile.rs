//! What the decoders do with rubbish.
//!
//! Every byte the protocol decodes comes off a network, and some of it
//! comes from whoever is on the other end. None of it may panic a process:
//! a malformed message is an error, and the caller closes the connection.
//!
//! This is not a fuzzer — it is the standing check that runs on every
//! build. It feeds random bytes, and mutations of real messages, to each
//! decoder, and drives the video reassembler with chunks no sane sender
//! would produce. The fuzzer proper is in `fuzz/`, on nightly and weekly;
//! what it finds belongs here afterwards, as a case every build sees.

use nearhand_core::grant::{Grant, Role, SignedGrant};
use nearhand_core::release::{Package, Release, SignedRelease, Version};
use nearhand_core::rendezvous::{Enrollment, FromServer, ToServer};
use nearhand_core::video::{Reassembler, Timing, decode_chunk, encode_chunk, packetize};
use nearhand_core::{Clipboard, Control, Cursor, Input, Monitor, StreamKind, wire};

/// As a viewer sets them from a round trip of a few milliseconds.
const TIMING: Timing = Timing {
    quiet_us: 10_000,
    retry_us: 20_000,
    give_up_us: 100_000,
};

/// Deterministic, so a failure can be reproduced from the seed printed
/// with it.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*: small, and good enough to shake a decoder.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> 24) as u8).collect()
    }
}

/// Decode `bytes` as each kind of message the wire carries. Any of them may
/// fail; none may panic.
fn decode_every_way(bytes: &[u8]) {
    let _ = wire::decode::<Control>(bytes);
    let _ = wire::decode::<ToServer>(bytes);
    let _ = wire::decode::<FromServer>(bytes);
    let _ = wire::decode::<Input>(bytes);
    let _ = wire::decode::<Clipboard>(bytes);
    let _ = wire::decode::<Cursor>(bytes);
    let _ = wire::decode::<StreamKind>(bytes);
    let _ = wire::decode::<Enrollment>(bytes);
    let _ = wire::decode::<Vec<Monitor>>(bytes);
    let _ = Grant::from_bytes(bytes);
    let _ = Release::from_bytes(bytes);
    let _ = decode_chunk(bytes);
    if let Ok(header) = bytes[..wire::HEADER_LEN.min(bytes.len())].try_into() {
        let _ = wire::body_len(header);
    }
}

/// Messages of each kind, as a sender really encodes them.
fn real_messages() -> Vec<Vec<u8>> {
    let grant = Grant {
        device: [7; 32],
        user: "ada".into(),
        role: Role::Control,
        issued_at: 1_000,
        expires_at: 1_300,
        nonce: [3; 16],
    };
    let release = Release {
        product: "nearhand-agent".into(),
        version: Version {
            major: 0,
            minor: 2,
            patch: 0,
        },
        platform: "windows-x86_64".into(),
        package: Package::Msi,
        sha256: [9; 32],
        size: 6_000_000,
    };
    vec![
        wire::encode(&Control::Bye).expect("encode"),
        wire::encode(&Control::RequestKeyframe).expect("encode"),
        wire::encode(&Control::Ping { viewer_us: 12 }).expect("encode"),
        wire::encode(&Control::MonitorList(vec![Monitor {
            id: 0,
            width: 2560,
            height: 1440,
            x: 0,
            y: 0,
            primary: true,
        }]))
        .expect("encode"),
        wire::encode(&Control::Present {
            grant: SignedGrant {
                grant: grant.to_bytes().expect("encode"),
                signature: vec![1; 64],
                server_certificate: vec![2; 300],
            },
        })
        .expect("encode"),
        wire::encode(&ToServer::Register {
            addresses: vec!["198.51.100.7:50000".parse().expect("address")],
        })
        .expect("encode"),
        wire::encode(&ToServer::Update {
            product: "nearhand-agent".into(),
            platform: "windows-x86_64".into(),
            version: Version {
                major: 0,
                minor: 1,
                patch: 0,
            },
        })
        .expect("encode"),
        wire::encode(&FromServer::Offered(Some(SignedRelease {
            release: release.to_bytes().expect("encode"),
            signature: vec![4; 64],
        })))
        .expect("encode"),
        wire::encode(&Clipboard::Text("ważne".into())).expect("encode"),
        grant.to_bytes().expect("encode"),
        release.to_bytes().expect("encode"),
        encode_chunk(
            &packetize(7, true, 1_000, &vec![0xAB; 4000].into(), 1200).expect("packetize")[0],
        )
        .expect("encode"),
    ]
}

#[test]
fn random_bytes_decode_to_errors_not_panics() {
    let mut rng = Rng(0x5EED_1234_5678_9ABC);
    for _ in 0..20_000 {
        let len = rng.below(600);
        decode_every_way(&rng.bytes(len));
    }
}

/// Real messages with bytes flipped, lengths changed and tails cut: the
/// shapes a decoder is likeliest to trip over.
#[test]
fn mangled_messages_decode_to_errors_not_panics() {
    let mut rng = Rng(0xD15E_A5ED_0000_0001);
    let messages = real_messages();
    for round in 0..20_000 {
        let mut message = messages[round % messages.len()].clone();
        if message.is_empty() {
            continue;
        }
        match rng.below(4) {
            // One byte somewhere becomes another.
            0 => {
                let at = rng.below(message.len());
                message[at] ^= (rng.next() as u8) | 1;
            }
            // Cut short, where a length says there is more.
            1 => message.truncate(rng.below(message.len())),
            // More bytes than the message says.
            2 => {
                let extra = rng.below(32);
                message.extend(rng.bytes(extra));
            }
            // A length field made huge.
            _ => {
                let at = rng.below(message.len());
                message[at] = 0xFF;
            }
        }
        decode_every_way(&message);
        // The header path, as a reader takes it off a stream.
        if message.len() >= wire::HEADER_LEN {
            let header: [u8; wire::HEADER_LEN] =
                message[..wire::HEADER_LEN].try_into().expect("header");
            if let Ok(len) = wire::body_len(header) {
                assert!(len <= wire::MAX_MESSAGE_LEN, "a body longer than the limit");
                let body = &message[wire::HEADER_LEN..];
                decode_every_way(&body[..len.min(body.len())]);
            }
        }
    }
}

/// The video reassembler, fed chunks a sender would never send: frames out
/// of order, wild indices and counts, duplicates, and ids that wrap.
#[test]
fn hostile_video_chunks_are_survived() {
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    let mut reassembler = Reassembler::new();
    let timing = TIMING;
    let mut now = 0u64;
    for _ in 0..20_000 {
        now += rng.below(40_000) as u64;
        let datagram = if rng.below(3) == 0 {
            let len = rng.below(80);
            rng.bytes(len)
        } else {
            // A real chunk, then broken on purpose.
            let len = rng.below(3000);
            let payload = rng.bytes(len);
            let chunks = packetize(
                rng.next() as u32,
                rng.below(4) == 0,
                now,
                &payload.into(),
                200 + rng.below(1200),
            )
            .unwrap_or_default();
            match chunks.first() {
                Some(chunk) => {
                    let mut bytes = encode_chunk(chunk).expect("encode");
                    if !bytes.is_empty() && rng.below(2) == 0 {
                        let at = rng.below(bytes.len());
                        bytes[at] ^= 0x80;
                    }
                    bytes
                }
                None => continue,
            }
        };
        if let Ok(chunk) = decode_chunk(&datagram) {
            reassembler.push(chunk, now);
        }
        let _ = reassembler.pop();
        let _ = reassembler.nacks(now, &timing);
        reassembler.expire(now, &timing);
        let _ = reassembler.next_deadline(&timing);
        let _ = reassembler.take_keyframe_request();
    }
    // Whatever it was fed, it is still usable: it still takes a good frame
    // and gives it back.
    let payload: Vec<u8> = (0..900u32).map(|i| i as u8).collect();
    for chunk in packetize(1, true, now, &payload.clone().into(), 1200).expect("packetize") {
        let chunk = decode_chunk(&encode_chunk(&chunk).expect("encode")).expect("decode");
        reassembler.push(chunk, now);
    }
    let frame = reassembler.pop().expect("a good frame still comes through");
    assert_eq!(frame.data.as_ref(), payload.as_slice());
}

/// Signature files come from a person's disk, and go through the same
/// parser on the server and in the tool.
#[test]
fn mangled_signature_files_are_errors_not_panics() {
    let mut rng = Rng(0xFACE_0FF1_CE00_0001);
    let good = SignedRelease {
        release: vec![1, 2, 3],
        signature: vec![4; 64],
    }
    .to_text();
    for _ in 0..20_000 {
        let mut text = good.clone().into_bytes();
        let at = rng.below(text.len());
        text[at] = (rng.next() >> 16) as u8;
        if let Ok(text) = String::from_utf8(text) {
            let _ = SignedRelease::from_text(&text);
        }
        let len = rng.below(200);
        let _ = SignedRelease::from_text(&String::from_utf8_lossy(&rng.bytes(len)));
    }
}

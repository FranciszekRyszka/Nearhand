//! Framing for messages on reliable streams.
//!
//! A QUIC stream is a byte stream, so each message carries its own length: a
//! 4-byte little-endian prefix, then the postcard body. Reading is split in two
//! — [`body_len`] on the prefix, [`decode`] on the body — so that callers can
//! use whatever async read they have without this crate depending on it.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Error;

/// Length prefix size in bytes.
pub const HEADER_LEN: usize = 4;

/// Largest message body we will accept.
///
/// Control and input messages are tens of bytes; a monitor list is a few
/// hundred. The cap exists so a hostile or broken peer cannot make us allocate
/// gigabytes by sending a large length prefix.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Serialise a message with its length prefix, ready to write to a stream.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, Error> {
    // Serialise straight after a placeholder prefix, then fill the prefix in.
    let mut out = postcard::to_extend(message, vec![0u8; HEADER_LEN]).map_err(Error::Encode)?;
    let body_len = out.len() - HEADER_LEN;
    if body_len > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLarge(body_len));
    }
    out[..HEADER_LEN].copy_from_slice(&(body_len as u32).to_le_bytes());
    Ok(out)
}

/// Read the body length from a prefix, rejecting anything over the cap before
/// the caller allocates for it.
pub fn body_len(header: [u8; HEADER_LEN]) -> Result<usize, Error> {
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLarge(len));
    }
    Ok(len)
}

/// Decode a message body (without its prefix).
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    postcard::from_bytes(body).map_err(Error::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Control, Input};

    fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug>(message: T) {
        let bytes = encode(&message).expect("encode");
        let header: [u8; HEADER_LEN] = bytes[..HEADER_LEN].try_into().expect("header");
        let len = body_len(header).expect("length");
        assert_eq!(len, bytes.len() - HEADER_LEN);
        let decoded: T = decode(&bytes[HEADER_LEN..]).expect("decode");
        assert_eq!(decoded, message);
    }

    #[test]
    fn messages_survive_framing() {
        roundtrip(Control::RequestKeyframe);
        roundtrip(Control::SetQuality {
            bitrate_kbps: 12_000,
            fps: 60,
        });
        roundtrip(Input::Text("zażółć".to_owned()));
    }

    #[test]
    fn oversized_length_is_rejected_before_allocation() {
        let header = ((MAX_MESSAGE_LEN + 1) as u32).to_le_bytes();
        assert!(matches!(body_len(header), Err(Error::MessageTooLarge(_))));
        assert!(matches!(
            body_len(u32::MAX.to_le_bytes()),
            Err(Error::MessageTooLarge(_))
        ));
    }

    #[test]
    fn oversized_message_is_refused_on_encode() {
        let huge = Input::Text("x".repeat(MAX_MESSAGE_LEN + 1));
        assert!(matches!(encode(&huge), Err(Error::MessageTooLarge(_))));
    }

    #[test]
    fn garbage_body_is_an_error_not_a_panic() {
        assert!(decode::<Control>(&[0xFF, 0xFF, 0xFF]).is_err());
    }
}

//! Time-based one-time passwords (RFC 6238), as authenticator apps make
//! them: HMAC-SHA1, six digits, a new code every 30 seconds. HMAC-SHA1 is
//! what every authenticator app supports; its known weaknesses are in
//! collisions, which a MAC does not rely on.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

const STEP_SECONDS: u64 = 30;
const DIGITS: u32 = 6;
/// Codes from one step either side are accepted too: phones' clocks drift.
const SKEW_STEPS: u64 = 1;
/// 160 bits, as RFC 4226 recommends.
const SECRET_LEN: usize = 20;

pub fn new_secret() -> anyhow::Result<Vec<u8>> {
    let mut secret = vec![0u8; SECRET_LEN];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| anyhow::anyhow!("the system random number generator failed"))?;
    Ok(secret)
}

/// The code for `secret` in the 30-second step that contains `unix_time`.
pub(crate) fn code_at(secret: &[u8], unix_time: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let counter = (unix_time / STEP_SECONDS).to_be_bytes();
    let tag = hmac::sign(&key, &counter);
    let digest = tag.as_ref();
    // Dynamic truncation (RFC 4226, 5.3).
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    binary % 10u32.pow(DIGITS)
}

/// The step `code` belongs to, if it is right for `secret` at `unix_time`.
/// The caller keeps the last step used, so a code works only once.
pub fn verify(secret: &[u8], code: &str, unix_time: u64) -> Option<u64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let now = unix_time / STEP_SECONDS;
    (now.saturating_sub(SKEW_STEPS)..=now + SKEW_STEPS)
        .find(|&step| constant_time_eq(code_at(secret, step * STEP_SECONDS), wanted))
}

/// Without an early exit, so the time taken says nothing about which
/// digits were right.
fn constant_time_eq(a: u32, b: u32) -> bool {
    (a ^ b) == 0
}

/// The `otpauth://` link an authenticator app reads, from a QR code or
/// pasted.
pub fn uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let issuer = percent_encode(issuer);
    format!(
        "otpauth://totp/{issuer}:{}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
        percent_encode(account),
        base32(secret)
    )
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, unpadded, as authenticator apps expect.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
pub fn from_base32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in text.chars().filter(|c| *c != '=' && !c.is_whitespace()) {
        let value = BASE32
            .iter()
            .position(|&b| b as char == c.to_ascii_uppercase())?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238, appendix B: the SHA-1 column, whose secret is the ASCII
    /// "12345678901234567890". The RFC gives eight digits; six are the last
    /// six of those.
    #[test]
    fn matches_the_rfc_test_vectors() {
        let secret = b"12345678901234567890";
        for (time, eight_digits) in [
            (59u64, 94287082u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ] {
            assert_eq!(code_at(secret, time), eight_digits % 1_000_000, "at {time}");
        }
    }

    #[test]
    fn codes_are_accepted_a_step_either_side_and_not_further() {
        let secret = b"12345678901234567890";
        let now = 1_234_567_890;
        let code = format!("{:06}", code_at(secret, now));
        assert!(verify(secret, &code, now).is_some());
        assert!(verify(secret, &code, now + 30).is_some());
        assert!(verify(secret, &code, now - 30).is_some());
        assert!(verify(secret, &code, now + 90).is_none());
        assert!(verify(secret, "12345", now).is_none());
        assert!(verify(secret, "abcdef", now).is_none());
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(verify(secret, &spaced, now).is_some(), "as apps show it");
    }

    #[test]
    fn base32_roundtrips_and_matches_rfc_4648() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(from_base32("MZXW6YTBOI======").expect("decode"), b"foobar");
        let secret = new_secret().expect("secret");
        assert_eq!(from_base32(&base32(&secret)).expect("decode"), secret);
        assert!(from_base32("not base32!").is_none());
    }

    #[test]
    fn the_uri_is_what_authenticator_apps_read() {
        let uri = uri(b"foobar", "Nearhand", "ada@example.com");
        assert_eq!(
            uri,
            "otpauth://totp/Nearhand:ada%40example.com?secret=MZXW6YTBOI&issuer=Nearhand&algorithm=SHA1&digits=6&period=30"
        );
    }
}

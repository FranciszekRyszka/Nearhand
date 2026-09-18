//! Just enough H.264 Annex B parsing to reason about a stream without decoding
//! it: split it into NAL units and tell parameter sets and keyframes apart.
//!
//! Every hardware encoder we use emits Annex B — NAL units separated by
//! `00 00 01` or `00 00 00 01` start codes, with SPS and PPS repeated in front
//! of each IDR frame. The viewer needs this to know when it can start decoding;
//! the encode probe uses it to check what the encoder actually produced.

/// `nal_unit_type` values we care about (ITU-T H.264, table 7-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalType {
    /// Coded slice of a non-IDR picture — an ordinary P frame for us.
    Slice,
    /// Coded slice of an IDR picture: decoding can start here.
    Idr,
    /// Supplemental enhancement information.
    Sei,
    /// Sequence parameter set.
    Sps,
    /// Picture parameter set.
    Pps,
    /// Access unit delimiter.
    Aud,
    Other(u8),
}

impl NalType {
    fn from_header(byte: u8) -> Self {
        match byte & 0x1F {
            1 => Self::Slice,
            5 => Self::Idr,
            6 => Self::Sei,
            7 => Self::Sps,
            8 => Self::Pps,
            9 => Self::Aud,
            other => Self::Other(other),
        }
    }
}

/// One NAL unit, header byte included, start code excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nal<'a> {
    pub kind: NalType,
    pub data: &'a [u8],
}

/// Split an Annex B byte stream into NAL units.
///
/// Tolerates both start-code lengths and ignores bytes before the first start
/// code. Empty units (two start codes back to back) are skipped.
pub fn nal_units(stream: &[u8]) -> Vec<Nal<'_>> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= stream.len() {
        if stream[i] == 0 && stream[i + 1] == 0 && stream[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }

    let mut units = Vec::with_capacity(starts.len());
    for (n, &start) in starts.iter().enumerate() {
        let mut end = match starts.get(n + 1) {
            // The next unit's start code begins three bytes before its payload.
            Some(&next) => next - 3,
            None => stream.len(),
        };
        // A four-byte start code leaves its leading zero on the previous unit;
        // so can trailing_zero_8bits. Neither belongs to the payload.
        while end > start && stream[end - 1] == 0 {
            end -= 1;
        }
        if end > start {
            let data = &stream[start..end];
            units.push(Nal {
                kind: NalType::from_header(data[0]),
                data,
            });
        }
    }
    units
}

/// True when the access unit contains an IDR slice, i.e. a decoder can start
/// from it with no history.
pub fn is_keyframe(access_unit: &[u8]) -> bool {
    nal_units(access_unit)
        .iter()
        .any(|nal| nal.kind == NalType::Idr)
}

/// Profile and level from an SPS, as `(profile_idc, level_idc)`.
///
/// Both sit at fixed byte offsets ahead of any exp-Golomb field, so no bit
/// reader is needed. `level_idc` is ten times the level: 42 means level 4.2.
pub fn sps_profile_level(sps: &Nal<'_>) -> Option<(u8, u8)> {
    if sps.kind != NalType::Sps || sps.data.len() < 4 {
        return None;
    }
    Some((sps.data[1], sps.data[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // SPS, PPS and the start of an IDR slice, with mixed start-code lengths.
    const KEYFRAME: &[u8] = &[
        0, 0, 0, 1, 0x67, 0x64, 0x00, 0x2A, 0xAC, // SPS: High profile, level 4.2
        0, 0, 0, 1, 0x68, 0xEE, 0x3C, 0x80, // PPS
        0, 0, 1, 0x65, 0x88, 0x84, 0x00, // IDR slice
    ];

    const DELTA: &[u8] = &[0, 0, 0, 1, 0x41, 0x9A, 0x02, 0x04];

    #[test]
    fn splits_parameter_sets_and_slices() {
        let kinds: Vec<_> = nal_units(KEYFRAME).iter().map(|n| n.kind).collect();
        assert_eq!(kinds, [NalType::Sps, NalType::Pps, NalType::Idr]);
    }

    #[test]
    fn four_byte_start_codes_do_not_leak_a_zero() {
        let units = nal_units(KEYFRAME);
        assert_eq!(units[0].data, &[0x67, 0x64, 0x00, 0x2A, 0xAC]);
        assert_eq!(units[1].data, &[0x68, 0xEE, 0x3C, 0x80]);
    }

    #[test]
    fn tells_keyframes_from_delta_frames() {
        assert!(is_keyframe(KEYFRAME));
        assert!(!is_keyframe(DELTA));
    }

    #[test]
    fn reads_profile_and_level() {
        let units = nal_units(KEYFRAME);
        assert_eq!(sps_profile_level(&units[0]), Some((100, 42)));
        assert_eq!(sps_profile_level(&units[1]), None);
    }

    #[test]
    fn ignores_garbage_and_empty_input() {
        assert!(nal_units(&[]).is_empty());
        assert!(nal_units(&[0xFF, 0x00, 0x12]).is_empty());
        // Back-to-back start codes produce no empty unit.
        assert_eq!(nal_units(&[0, 0, 1, 0, 0, 1, 0x41, 0x01]).len(), 1);
    }
}

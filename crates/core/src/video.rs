//! Video over unreliable datagrams: splitting encoded frames into chunks, and
//! putting them back together on the other side.
//!
//! The rules follow from "a late frame is useless":
//!
//! * Nothing is retransmitted. A frame missing a chunk is abandoned as soon as
//!   a newer frame completes — or when the caller decides it has waited long
//!   enough — never held for a repair.
//! * H.264 P-frames depend on the frame before them, so after any loss the
//!   decoder's reference chain is broken. From then on every frame is dropped
//!   until a keyframe arrives, and the reassembler asks for one.
//! * Late chunks, duplicates and malformed chunks are counted and ignored.
//!
//! None of this needs a clock, which keeps it usable from the browser viewer.
//! Timing decisions (how long to wait, how often to re-ask for a keyframe) are
//! the caller's.

use bytes::{Bytes, BytesMut};

use crate::{Error, VideoChunk};

/// Bytes reserved in every datagram for the [`VideoChunk`] header.
///
/// Worst case with postcard's varints: frame id 5, chunk index 3, chunk count
/// 3, keyframe flag 1, timestamp 10, payload length 3 — 25 bytes. The margin
/// is so a new header field does not silently overflow the path MTU.
pub const CHUNK_OVERHEAD: usize = 32;

/// Smallest datagram size we will split for. Anything smaller means the path
/// is broken, and chunking would produce absurd numbers of tiny packets.
pub const MIN_DATAGRAM: usize = CHUNK_OVERHEAD + 256;

/// How many incomplete frames are tracked at once. Chunks for more than this
/// many frames in flight means the older ones are not going to complete.
const MAX_PARTIAL: usize = 4;

/// Split an encoded frame into chunks that each serialise to at most
/// `max_datagram` bytes.
///
/// Chunks share the frame's buffer; no payload bytes are copied.
pub fn packetize(
    frame_id: u32,
    keyframe: bool,
    capture_ts_us: u64,
    data: &Bytes,
    max_datagram: usize,
) -> Result<Vec<VideoChunk>, Error> {
    if max_datagram < MIN_DATAGRAM {
        return Err(Error::DatagramTooSmall(max_datagram));
    }
    let payload = max_datagram - CHUNK_OVERHEAD;
    let count = data.len().div_ceil(payload).max(1);
    let chunks = u16::try_from(count).map_err(|_| Error::FrameTooLarge(data.len()))?;

    Ok((0..chunks)
        .map(|chunk| {
            let start = usize::from(chunk) * payload;
            let end = (start + payload).min(data.len());
            VideoChunk {
                frame_id,
                chunk,
                chunks,
                keyframe,
                capture_ts_us,
                data: data.slice(start..end),
            }
        })
        .collect())
}

/// Serialise one chunk as a datagram payload.
pub fn encode_chunk(chunk: &VideoChunk) -> Result<Vec<u8>, Error> {
    postcard::to_stdvec(chunk).map_err(Error::Encode)
}

/// Parse a datagram payload back into a chunk.
pub fn decode_chunk(datagram: &[u8]) -> Result<VideoChunk, Error> {
    postcard::from_bytes(datagram).map_err(Error::Decode)
}

/// A frame put back together, ready for the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledFrame {
    pub frame_id: u32,
    pub keyframe: bool,
    pub capture_ts_us: u64,
    pub data: Bytes,
}

/// Running counts, for the viewer's statistics overlay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReassemblyStats {
    /// Frames delivered to the decoder.
    pub delivered: u64,
    /// Frames abandoned with chunks missing.
    pub incomplete: u64,
    /// Complete frames dropped because the reference chain was broken.
    pub dropped_waiting_for_keyframe: u64,
    /// Chunks for a frame already delivered or abandoned.
    pub late_chunks: u64,
    pub duplicate_chunks: u64,
    /// Chunks whose header contradicts itself or earlier chunks.
    pub invalid_chunks: u64,
}

#[derive(Debug)]
struct Partial {
    frame_id: u32,
    keyframe: bool,
    capture_ts_us: u64,
    parts: Vec<Option<Bytes>>,
    received: usize,
    bytes: usize,
}

#[derive(Debug)]
pub struct Reassembler {
    partial: Vec<Partial>,
    /// Newest frame delivered or given up on. Anything at or before it is late.
    last_settled: Option<u32>,
    /// True from the start and after any loss, until a keyframe completes.
    waiting_for_keyframe: bool,
    keyframe_wanted: bool,
    stats: ReassemblyStats,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            partial: Vec::with_capacity(MAX_PARTIAL),
            last_settled: None,
            // A decoder cannot start on a P-frame.
            waiting_for_keyframe: true,
            keyframe_wanted: false,
            stats: ReassemblyStats::default(),
        }
    }

    /// Feed one chunk. Returns a frame when this chunk completed one that the
    /// decoder can use.
    pub fn push(&mut self, chunk: VideoChunk) -> Option<AssembledFrame> {
        if chunk.chunks == 0 || chunk.chunk >= chunk.chunks {
            self.stats.invalid_chunks += 1;
            return None;
        }
        if let Some(settled) = self.last_settled
            && !is_newer(chunk.frame_id, settled)
        {
            self.stats.late_chunks += 1;
            return None;
        }

        let index = match self
            .partial
            .iter()
            .position(|p| p.frame_id == chunk.frame_id)
        {
            Some(index) => index,
            None => self.start_partial(&chunk),
        };

        let partial = &mut self.partial[index];
        if usize::from(chunk.chunks) != partial.parts.len() || chunk.keyframe != partial.keyframe {
            self.stats.invalid_chunks += 1;
            return None;
        }
        let slot = &mut partial.parts[usize::from(chunk.chunk)];
        if slot.is_some() {
            self.stats.duplicate_chunks += 1;
            return None;
        }
        partial.bytes += chunk.data.len();
        partial.received += 1;
        *slot = Some(chunk.data);

        if partial.received < partial.parts.len() {
            return None;
        }
        let complete = self.partial.swap_remove(index);
        self.complete(complete)
    }

    /// Give up on every frame still missing chunks.
    ///
    /// For when chunks stop arriving: without a newer frame to reveal the loss,
    /// a partial frame would otherwise wait forever — and the viewer would keep
    /// showing the frame before it while the host has moved on.
    pub fn abandon_partials(&mut self) {
        for partial in std::mem::take(&mut self.partial) {
            self.settle(partial.frame_id);
            self.stats.incomplete += 1;
            self.lost();
        }
    }

    /// Whether any frame is waiting for chunks.
    pub fn has_partial(&self) -> bool {
        !self.partial.is_empty()
    }

    /// True when a keyframe should be requested from the agent.
    ///
    /// Reset by the call. It keeps coming back true for as long as frames are
    /// being dropped, so a request that got lost is repeated; the caller
    /// decides how often it is actually sent.
    pub fn take_keyframe_request(&mut self) -> bool {
        std::mem::take(&mut self.keyframe_wanted)
    }

    pub fn stats(&self) -> ReassemblyStats {
        self.stats
    }

    fn start_partial(&mut self, chunk: &VideoChunk) -> usize {
        if self.partial.len() == MAX_PARTIAL {
            // Evict the oldest: it has had the longest to complete.
            let oldest = (1..self.partial.len()).fold(0, |oldest, i| {
                if is_newer(self.partial[oldest].frame_id, self.partial[i].frame_id) {
                    i
                } else {
                    oldest
                }
            });
            let evicted = self.partial.swap_remove(oldest);
            self.settle(evicted.frame_id);
            self.stats.incomplete += 1;
            self.lost();
        }
        self.partial.push(Partial {
            frame_id: chunk.frame_id,
            keyframe: chunk.keyframe,
            capture_ts_us: chunk.capture_ts_us,
            parts: vec![None; usize::from(chunk.chunks)],
            received: 0,
            bytes: 0,
        });
        self.partial.len() - 1
    }

    fn complete(&mut self, frame: Partial) -> Option<AssembledFrame> {
        // Everything older than this frame can no longer be decoded in order.
        let before = self.partial.len();
        self.partial
            .retain(|p| is_newer(p.frame_id, frame.frame_id));
        let abandoned = before - self.partial.len();
        if abandoned > 0 {
            self.stats.incomplete += abandoned as u64;
            self.lost();
        }

        // A gap in frame ids is a frame we never saw a single chunk of.
        if let Some(settled) = self.last_settled
            && frame.frame_id != settled.wrapping_add(1)
        {
            self.lost();
        }
        self.settle(frame.frame_id);

        if frame.keyframe {
            self.waiting_for_keyframe = false;
        } else if self.waiting_for_keyframe {
            self.stats.dropped_waiting_for_keyframe += 1;
            self.keyframe_wanted = true;
            return None;
        }

        self.stats.delivered += 1;
        let data = if frame.parts.len() == 1 {
            frame.parts.into_iter().flatten().next().unwrap_or_default()
        } else {
            let mut data = BytesMut::with_capacity(frame.bytes);
            for part in frame.parts.into_iter().flatten() {
                data.extend_from_slice(&part);
            }
            data.freeze()
        };
        Some(AssembledFrame {
            frame_id: frame.frame_id,
            keyframe: frame.keyframe,
            capture_ts_us: frame.capture_ts_us,
            data,
        })
    }

    fn settle(&mut self, frame_id: u32) {
        if self
            .last_settled
            .is_none_or(|settled| is_newer(frame_id, settled))
        {
            self.last_settled = Some(frame_id);
        }
    }

    fn lost(&mut self) {
        self.waiting_for_keyframe = true;
        self.keyframe_wanted = true;
    }
}

/// Frame-id order that survives wrapping past `u32::MAX`.
fn is_newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATAGRAM: usize = 1200;

    fn frame(id: u32, keyframe: bool, len: usize) -> (Bytes, Vec<VideoChunk>) {
        let data: Bytes = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>().into();
        let chunks =
            packetize(id, keyframe, u64::from(id) * 16_000, &data, DATAGRAM).expect("packetize");
        (data, chunks)
    }

    fn feed(r: &mut Reassembler, chunks: Vec<VideoChunk>) -> Option<AssembledFrame> {
        let mut out = None;
        for chunk in chunks {
            if let Some(frame) = r.push(chunk) {
                assert!(out.is_none(), "one frame produced twice");
                out = Some(frame);
            }
        }
        out
    }

    #[test]
    fn every_chunk_fits_its_datagram() {
        let (_, chunks) = frame(u32::MAX, true, 300_000);
        for chunk in &chunks {
            let encoded = encode_chunk(chunk).expect("encode");
            assert!(encoded.len() <= DATAGRAM, "{} > {DATAGRAM}", encoded.len());
        }
    }

    #[test]
    fn datagrams_roundtrip() {
        let (_, chunks) = frame(7, false, 3_000);
        let encoded = encode_chunk(&chunks[1]).expect("encode");
        assert_eq!(decode_chunk(&encoded).expect("decode"), chunks[1]);
        assert!(decode_chunk(&[0xFF; 3]).is_err());
    }

    #[test]
    fn packetize_refuses_impossible_inputs() {
        let data = Bytes::from_static(&[1, 2, 3]);
        assert!(matches!(
            packetize(0, true, 0, &data, 100),
            Err(Error::DatagramTooSmall(100))
        ));
        // One chunk past what a u16 chunk count can address.
        let payload = MIN_DATAGRAM - CHUNK_OVERHEAD;
        let huge = Bytes::from(vec![0u8; payload * 65_536]);
        assert!(matches!(
            packetize(0, true, 0, &huge, MIN_DATAGRAM),
            Err(Error::FrameTooLarge(_))
        ));
    }

    #[test]
    fn reassembles_in_order_frames() {
        let mut r = Reassembler::new();
        let (data, chunks) = frame(0, true, 5_000);
        assert!(chunks.len() > 1);
        let out = feed(&mut r, chunks).expect("keyframe delivered");
        assert_eq!(out.data, data);
        assert!(out.keyframe);
        assert_eq!(out.capture_ts_us, 0);

        let (data, chunks) = frame(1, false, 800);
        assert_eq!(chunks.len(), 1);
        assert_eq!(feed(&mut r, chunks).expect("P-frame delivered").data, data);
        assert_eq!(r.stats().delivered, 2);
        assert!(!r.take_keyframe_request());
    }

    #[test]
    fn reorders_chunks_within_a_frame() {
        let mut r = Reassembler::new();
        let (data, mut chunks) = frame(0, true, 6_000);
        chunks.reverse();
        assert_eq!(feed(&mut r, chunks).expect("delivered").data, data);
    }

    #[test]
    fn will_not_start_on_a_p_frame() {
        let mut r = Reassembler::new();
        let (_, chunks) = frame(0, false, 500);
        assert!(feed(&mut r, chunks).is_none());
        assert!(r.take_keyframe_request());
        assert_eq!(r.stats().dropped_waiting_for_keyframe, 1);

        let (_, chunks) = frame(1, true, 500);
        assert!(feed(&mut r, chunks).is_some());
    }

    #[test]
    fn a_lost_chunk_breaks_the_chain_until_a_keyframe() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");

        // Frame 1 loses a chunk.
        let (_, mut chunks) = frame(1, false, 4_000);
        chunks.remove(1);
        assert!(feed(&mut r, chunks).is_none());

        // Frame 2 completes: frame 1 is abandoned, and 2 cannot be decoded.
        assert!(feed(&mut r, frame(2, false, 500).1).is_none());
        assert!(r.take_keyframe_request());
        assert_eq!(r.stats().incomplete, 1);

        // Still broken, still asking.
        assert!(feed(&mut r, frame(3, false, 500).1).is_none());
        assert!(r.take_keyframe_request());

        // The keyframe repairs it, and normal frames flow again.
        assert!(feed(&mut r, frame(4, true, 500).1).is_some());
        assert!(feed(&mut r, frame(5, false, 500).1).is_some());
        assert!(!r.take_keyframe_request());
        assert_eq!(r.stats().dropped_waiting_for_keyframe, 2);
    }

    #[test]
    fn a_wholly_missing_frame_is_noticed_by_its_gap() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        // Frame 1 never arrives at all.
        assert!(feed(&mut r, frame(2, false, 500).1).is_none());
        assert!(r.take_keyframe_request());
    }

    #[test]
    fn late_and_duplicate_chunks_are_ignored() {
        let mut r = Reassembler::new();
        let (_, chunks) = frame(0, true, 3_000);
        let replay = chunks[0].clone();
        feed(&mut r, chunks).expect("delivered");
        assert!(r.push(replay).is_none());
        assert_eq!(r.stats().late_chunks, 1);

        let (_, chunks) = frame(1, false, 3_000);
        assert!(r.push(chunks[0].clone()).is_none());
        assert!(r.push(chunks[0].clone()).is_none());
        assert_eq!(r.stats().duplicate_chunks, 1);
    }

    #[test]
    fn malformed_chunks_are_counted_not_trusted() {
        let mut r = Reassembler::new();
        let bad = |chunk, chunks| VideoChunk {
            frame_id: 0,
            chunk,
            chunks,
            keyframe: true,
            capture_ts_us: 0,
            data: Bytes::new(),
        };
        assert!(r.push(bad(0, 0)).is_none());
        assert!(r.push(bad(3, 3)).is_none());
        // Chunk count changing mid-frame.
        assert!(r.push(bad(0, 2)).is_none());
        assert!(r.push(bad(1, 5)).is_none());
        assert_eq!(r.stats().invalid_chunks, 3);
    }

    #[test]
    fn abandoning_a_stalled_frame_requests_a_keyframe() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        let (_, chunks) = frame(1, false, 4_000);
        r.push(chunks[0].clone());
        assert!(r.has_partial());

        r.abandon_partials();
        assert!(!r.has_partial());
        assert!(r.take_keyframe_request());
        // Its remaining chunks now count as late.
        assert!(r.push(chunks[1].clone()).is_none());
        assert_eq!(r.stats().late_chunks, 1);
    }

    #[test]
    fn too_many_frames_in_flight_evicts_the_oldest() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        for id in 1..=(MAX_PARTIAL as u32 + 1) {
            let (_, chunks) = frame(id, false, 4_000);
            r.push(chunks[0].clone());
        }
        assert_eq!(r.stats().incomplete, 1);
        assert!(r.take_keyframe_request());
    }

    #[test]
    fn frame_ids_wrap_around() {
        assert!(is_newer(0, u32::MAX));
        assert!(!is_newer(u32::MAX, 0));

        let mut r = Reassembler::new();
        feed(&mut r, frame(u32::MAX, true, 500).1).expect("before the wrap");
        feed(&mut r, frame(0, false, 500).1).expect("after the wrap");
        assert!(!r.take_keyframe_request());
    }
}

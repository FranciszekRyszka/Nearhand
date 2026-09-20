//! Video over unreliable datagrams: splitting encoded frames into chunks, and
//! putting them back together on the other side.
//!
//! The rules:
//!
//! * Frames reach the decoder strictly in order, because each H.264 P-frame
//!   is decoded against the one before it.
//! * A lost chunk is repaired, not waited out: the reassembler works out
//!   which chunks are missing ([`Reassembler::nacks`]), the viewer asks the
//!   agent to send them again, and newer frames are held until the repair
//!   lands. At 1440p a keyframe is some 200 datagrams; without repair a 2%
//!   loss rate let one arrive whole about 2% of the time.
//! * A frame that stops making progress is given up on
//!   ([`Reassembler::expire`]). The reference chain is then broken, so every
//!   frame is dropped until a keyframe arrives, and the reassembler asks for
//!   one. A complete keyframe that is already waiting is jumped to at once.
//! * Late chunks, duplicates and malformed chunks are counted and ignored.
//!
//! None of this reads a clock, which keeps it usable from the browser viewer:
//! callers pass the time in, and choose the timings from the round trip.

use std::collections::VecDeque;

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

/// How many frames are held at once. More than this in flight means the
/// oldest is not going to be repaired in time to matter.
const MAX_PENDING: usize = 64;

/// How many wholly missing frames one call to [`Reassembler::nacks`] asks for.
const MAX_GAP_NACKS: u32 = 32;

/// How many of those are remembered as asked for. Ids run in order, so the
/// list clears itself as frames settle; a sender whose ids jump about — a
/// broken one, or a hostile one — must not make it grow without end.
const MAX_REMEMBERED_GAPS: usize = 4 * MAX_GAP_NACKS as usize;

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

/// Chunks to ask the agent to send again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    pub frame_id: u32,
    /// Empty when not a single chunk of the frame arrived, so its size is
    /// unknown: the whole frame, please.
    pub chunks: Vec<u16>,
}

/// When to ask for repairs and when to stop waiting, in microseconds. The
/// caller derives them from the round-trip time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// A frame's trailing chunks count as lost after this long without any
    /// chunk of it arriving. Chunks before one that has arrived, or of a frame
    /// older than one that has, count as lost at once.
    pub quiet_us: u64,
    /// Ask again for chunks still missing after this long.
    pub retry_us: u64,
    /// Give up on the frame the decoder is waiting for once it has made no
    /// progress for this long.
    pub give_up_us: u64,
}

/// Running counts, for the viewer's statistics overlay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReassemblyStats {
    /// Frames delivered to the decoder.
    pub delivered: u64,
    /// Frames delivered only thanks to chunks sent again.
    pub repaired: u64,
    /// Frames given up on with chunks missing.
    pub incomplete: u64,
    /// Complete frames dropped because the reference chain was broken.
    pub dropped_waiting_for_keyframe: u64,
    /// Chunks for a frame already delivered or given up on.
    pub late_chunks: u64,
    pub duplicate_chunks: u64,
    /// Chunks whose header contradicts itself or earlier chunks.
    pub invalid_chunks: u64,
    /// Repair requests made, counting each frame once per request.
    pub nacks: u64,
}

#[derive(Debug)]
struct Pending {
    frame_id: u32,
    keyframe: bool,
    capture_ts_us: u64,
    parts: Vec<Option<Bytes>>,
    received: usize,
    bytes: usize,
    /// Highest chunk index received: anything below it that is missing was
    /// lost rather than still on its way.
    highest: u16,
    first_us: u64,
    last_chunk_us: u64,
    nacked_us: Option<u64>,
}

impl Pending {
    fn complete(&self) -> bool {
        self.received == self.parts.len()
    }
}

/// Puts frames back together and hands them to the decoder strictly in order,
/// holding newer frames while an older one is repaired.
#[derive(Debug)]
pub struct Reassembler {
    /// Frames after `last_settled`, complete or not.
    pending: Vec<Pending>,
    ready: VecDeque<AssembledFrame>,
    /// Newest frame delivered or given up on. Anything at or before it is late.
    last_settled: Option<u32>,
    /// Frames of which nothing arrived, and when they were last asked for.
    gap_nacks: Vec<(u32, u64)>,
    /// True from the start and after any loss, until a keyframe arrives.
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
            pending: Vec::new(),
            ready: VecDeque::new(),
            last_settled: None,
            gap_nacks: Vec::new(),
            // A decoder cannot start on a P-frame.
            waiting_for_keyframe: true,
            keyframe_wanted: false,
            stats: ReassemblyStats::default(),
        }
    }

    /// Feed one chunk that arrived at `now_us`. Frames it makes deliverable
    /// come out of [`Reassembler::pop`].
    pub fn push(&mut self, chunk: VideoChunk, now_us: u64) {
        if chunk.chunks == 0 || chunk.chunk >= chunk.chunks {
            self.stats.invalid_chunks += 1;
            return;
        }
        if let Some(settled) = self.last_settled
            && !is_newer(chunk.frame_id, settled)
        {
            self.stats.late_chunks += 1;
            return;
        }

        let index = match self
            .pending
            .iter()
            .position(|p| p.frame_id == chunk.frame_id)
        {
            Some(index) => index,
            None => {
                // No longer a gap, if it was one.
                self.gap_nacks.retain(|(id, _)| *id != chunk.frame_id);
                if self.pending.len() >= MAX_PENDING {
                    // Far more in flight than any repair could wait for.
                    self.give_up_expected();
                }
                self.pending.push(Pending {
                    frame_id: chunk.frame_id,
                    keyframe: chunk.keyframe,
                    capture_ts_us: chunk.capture_ts_us,
                    parts: vec![None; usize::from(chunk.chunks)],
                    received: 0,
                    bytes: 0,
                    highest: 0,
                    first_us: now_us,
                    last_chunk_us: now_us,
                    nacked_us: None,
                });
                self.pending.len() - 1
            }
        };

        let pending = &mut self.pending[index];
        if usize::from(chunk.chunks) != pending.parts.len() || chunk.keyframe != pending.keyframe {
            self.stats.invalid_chunks += 1;
            return;
        }
        let slot = &mut pending.parts[usize::from(chunk.chunk)];
        if slot.is_some() {
            self.stats.duplicate_chunks += 1;
            return;
        }
        pending.bytes += chunk.data.len();
        pending.received += 1;
        pending.highest = pending.highest.max(chunk.chunk);
        pending.last_chunk_us = now_us;
        *slot = Some(chunk.data);

        if pending.complete() {
            self.drain();
        }
    }

    /// The next frame for the decoder, in frame-id order.
    pub fn pop(&mut self) -> Option<AssembledFrame> {
        self.ready.pop_front()
    }

    /// What to ask the agent to send again, as of `now_us`. Each frame is
    /// asked for at most once per `timing.retry_us`, so this can be called as
    /// often as convenient.
    pub fn nacks(&mut self, now_us: u64, timing: &Timing) -> Vec<Missing> {
        let mut out = Vec::new();
        let newest = self.newest_pending();
        let due =
            |asked: Option<u64>| asked.is_none_or(|t| now_us.saturating_sub(t) >= timing.retry_us);

        for pending in &mut self.pending {
            // A P-frame is useless while the chain is broken anyway.
            if pending.complete() || (self.waiting_for_keyframe && !pending.keyframe) {
                continue;
            }
            let newer_seen = newest.is_some_and(|n| is_newer(n, pending.frame_id));
            let quiet = now_us.saturating_sub(pending.last_chunk_us) >= timing.quiet_us;
            let chunks: Vec<u16> = (0..pending.parts.len())
                .filter(|&i| pending.parts[i].is_none())
                .map(|i| i as u16)
                .filter(|&i| i < pending.highest || newer_seen || quiet)
                .collect();
            if !chunks.is_empty() && due(pending.nacked_us) {
                pending.nacked_us = Some(now_us);
                out.push(Missing {
                    frame_id: pending.frame_id,
                    chunks,
                });
            }
        }

        // Frames that left no trace but a gap in the ids. Their type is
        // unknown, so they are worth asking for only while the chain holds.
        if let (Some(expected), Some(newest)) = (self.expected(), newest)
            && !self.waiting_for_keyframe
        {
            let mut id = expected;
            let mut checked = 0;
            while is_newer(newest, id) && checked < MAX_GAP_NACKS {
                if !self.pending.iter().any(|p| p.frame_id == id) {
                    let asked = self.gap_nacks.iter().position(|(g, _)| *g == id);
                    if due(asked.map(|i| self.gap_nacks[i].1)) {
                        match asked {
                            Some(i) => self.gap_nacks[i].1 = now_us,
                            None => {
                                // The stalest goes: it was asked for
                                // longest ago, so it is the least likely to
                                // still be worth repairing.
                                if self.gap_nacks.len() >= MAX_REMEMBERED_GAPS
                                    && let Some(stalest) = self
                                        .gap_nacks
                                        .iter()
                                        .enumerate()
                                        .min_by_key(|(_, (_, asked))| *asked)
                                        .map(|(i, _)| i)
                                {
                                    self.gap_nacks.swap_remove(stalest);
                                }
                                self.gap_nacks.push((id, now_us));
                            }
                        }
                        out.push(Missing {
                            frame_id: id,
                            chunks: Vec::new(),
                        });
                    }
                }
                id = id.wrapping_add(1);
                checked += 1;
            }
        }
        self.stats.nacks += out.len() as u64;
        out
    }

    /// Give up on the frame the decoder is waiting for if it has made no
    /// progress for `timing.give_up_us`, and on each one after it that is
    /// just as stuck.
    pub fn expire(&mut self, now_us: u64, timing: &Timing) {
        while let Some(expected) = self.expected() {
            let waiting = self.pending.iter().find(|p| p.frame_id == expected);
            let (stuck_since, gap_to) = match waiting {
                Some(pending) => (pending.last_chunk_us, None),
                // Nothing of it arrived: stuck since the oldest frame
                // waiting turned up, and every id between the two is gone
                // with it. They are given up together — walking the gap one
                // id at a time would be endless against a sender whose
                // numbering jumps, whether it is broken or malicious.
                None => match self.oldest_pending() {
                    Some((id, first_us)) => (first_us, Some(id)),
                    None => return,
                },
            };
            if now_us.saturating_sub(stuck_since) < timing.give_up_us {
                return;
            }
            match gap_to {
                None => self.give_up_expected(),
                Some(id) => {
                    self.stats.incomplete += 1;
                    self.settle(id.wrapping_sub(1));
                    self.lost();
                    self.drain();
                }
            }
        }
    }

    /// The earliest time at which [`Reassembler::nacks`] or
    /// [`Reassembler::expire`] could do something, if anything is waiting.
    /// Lets the caller wake exactly then instead of polling: a lost final
    /// chunk otherwise shows up only when the next frame begins.
    pub fn next_deadline(&self, timing: &Timing) -> Option<u64> {
        let repairs = self
            .pending
            .iter()
            .filter(|p| !p.complete() && (p.keyframe || !self.waiting_for_keyframe))
            .map(|p| match p.nacked_us {
                None => p.last_chunk_us + timing.quiet_us,
                // Not before a chunk could count as lost again, either: a
                // deadline at which `nacks` then does nothing would spin the
                // caller.
                Some(asked) => (asked + timing.retry_us).max(p.last_chunk_us + timing.quiet_us),
            });
        let gaps = self
            .gap_nacks
            .iter()
            .filter(|_| !self.waiting_for_keyframe)
            .map(|(_, asked)| asked + timing.retry_us);
        let give_up = self.expected().and_then(|expected| {
            let stuck_since = match self.pending.iter().find(|p| p.frame_id == expected) {
                Some(pending) => pending.last_chunk_us,
                None => self.pending.iter().map(|p| p.first_us).min()?,
            };
            Some(stuck_since + timing.give_up_us)
        });
        repairs.chain(gaps).chain(give_up).min()
    }

    /// Whether any frame is waiting for chunks or for an older frame.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
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

    /// The frame the decoder needs next.
    fn expected(&self) -> Option<u32> {
        match self.last_settled {
            Some(settled) => Some(settled.wrapping_add(1)),
            None => self
                .pending
                .iter()
                .map(|p| p.frame_id)
                .reduce(|a, b| if is_newer(a, b) { b } else { a }),
        }
    }

    /// The frame waiting with the oldest id, and when the first of it
    /// arrived.
    fn oldest_pending(&self) -> Option<(u32, u64)> {
        self.pending
            .iter()
            .map(|p| (p.frame_id, p.first_us))
            .reduce(|a, b| if is_newer(a.0, b.0) { b } else { a })
    }

    fn newest_pending(&self) -> Option<u32> {
        self.pending
            .iter()
            .map(|p| p.frame_id)
            .reduce(|a, b| if is_newer(a, b) { a } else { b })
    }

    /// Deliver every frame that is now next in line and complete.
    fn drain(&mut self) {
        while let Some(expected) = self.expected() {
            if let Some(index) = self
                .pending
                .iter()
                .position(|p| p.frame_id == expected && p.complete())
            {
                let frame = self.pending.swap_remove(index);
                self.deliver(frame);
                continue;
            }
            // Stuck on an older frame, but a complete keyframe is already
            // here: it needs nothing before it, so skip straight to it — in
            // one step, however far ahead its id is. Walking the ids
            // between would be endless against a sender whose numbering
            // jumps, whether it is broken or malicious.
            if let Some(keyframe) = self
                .pending
                .iter()
                .filter(|p| p.keyframe && p.complete())
                .map(|p| p.frame_id)
                .reduce(|a, b| if is_newer(a, b) { b } else { a })
            {
                let settled = keyframe.wrapping_sub(1);
                let before = self.pending.len();
                self.pending.retain(|p| is_newer(p.frame_id, settled));
                // What was skipped is one loss, however many ids it spans.
                self.stats.incomplete += (before - self.pending.len()).max(1) as u64;
                self.settle(settled);
                continue;
            }
            return;
        }
    }

    /// Settle the expected frame as lost, then deliver what that unblocks.
    fn give_up_expected(&mut self) {
        self.give_up_expected_quietly();
        self.lost();
        self.drain();
    }

    fn give_up_expected_quietly(&mut self) {
        let Some(expected) = self.expected() else {
            return;
        };
        self.pending.retain(|p| p.frame_id != expected);
        self.stats.incomplete += 1;
        self.settle(expected);
    }

    fn deliver(&mut self, frame: Pending) {
        self.settle(frame.frame_id);
        if frame.keyframe {
            self.waiting_for_keyframe = false;
        } else if self.waiting_for_keyframe {
            self.stats.dropped_waiting_for_keyframe += 1;
            self.keyframe_wanted = true;
            return;
        }

        self.stats.delivered += 1;
        if frame.nacked_us.is_some() {
            self.stats.repaired += 1;
        }
        let data = if frame.parts.len() == 1 {
            frame.parts.into_iter().flatten().next().unwrap_or_default()
        } else {
            let mut data = BytesMut::with_capacity(frame.bytes);
            for part in frame.parts.into_iter().flatten() {
                data.extend_from_slice(&part);
            }
            data.freeze()
        };
        self.ready.push_back(AssembledFrame {
            frame_id: frame.frame_id,
            keyframe: frame.keyframe,
            capture_ts_us: frame.capture_ts_us,
            data,
        });
    }

    fn settle(&mut self, frame_id: u32) {
        if self
            .last_settled
            .is_none_or(|settled| is_newer(frame_id, settled))
        {
            self.last_settled = Some(frame_id);
        }
        self.gap_nacks.retain(|(id, _)| is_newer(*id, frame_id));
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

    const TIMING: Timing = Timing {
        quiet_us: 10_000,
        retry_us: 20_000,
        give_up_us: 100_000,
    };

    fn frame(id: u32, keyframe: bool, len: usize) -> (Bytes, Vec<VideoChunk>) {
        let data: Bytes = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>().into();
        let chunks =
            packetize(id, keyframe, u64::from(id) * 16_000, &data, DATAGRAM).expect("packetize");
        (data, chunks)
    }

    fn feed(r: &mut Reassembler, chunks: Vec<VideoChunk>) -> Option<AssembledFrame> {
        for chunk in chunks {
            r.push(chunk, 0);
        }
        let out = r.pop();
        assert!(r.pop().is_none(), "one frame produced twice");
        out
    }

    fn feed_at(r: &mut Reassembler, chunks: Vec<VideoChunk>, now_us: u64) -> Vec<AssembledFrame> {
        for chunk in chunks {
            r.push(chunk, now_us);
        }
        std::iter::from_fn(|| r.pop()).collect()
    }

    fn ids(frames: &[AssembledFrame]) -> Vec<u32> {
        frames.iter().map(|f| f.frame_id).collect()
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
    fn a_lost_chunk_is_asked_for_and_the_repair_releases_what_waited() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");

        // Frame 1 loses its second chunk; frames 2 and 3 arrive whole.
        let (data1, mut chunks) = frame(1, false, 4_000);
        let lost = chunks.remove(1);
        assert!(feed_at(&mut r, chunks, 1_000).is_empty());
        assert!(
            feed_at(&mut r, frame(2, false, 500).1, 2_000).is_empty(),
            "held behind 1"
        );
        assert!(feed_at(&mut r, frame(3, false, 500).1, 3_000).is_empty());

        let asked = r.nacks(3_000, &TIMING);
        assert_eq!(
            asked,
            [Missing {
                frame_id: 1,
                chunks: vec![1]
            }]
        );
        // Not again before the retry interval…
        assert!(r.nacks(10_000, &TIMING).is_empty());
        // …but again after it, if the repair got lost too.
        assert_eq!(r.nacks(30_000, &TIMING).len(), 1);

        let out = feed_at(&mut r, vec![lost], 35_000);
        assert_eq!(ids(&out), [1, 2, 3]);
        assert_eq!(out[0].data, data1);
        assert_eq!(r.stats().repaired, 1);
        assert_eq!(r.stats().incomplete, 0);
        assert!(!r.take_keyframe_request());
    }

    #[test]
    fn trailing_chunks_are_asked_for_only_after_a_quiet_spell() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        let (_, mut chunks) = frame(1, false, 4_000);
        let last = chunks.pop().expect("chunks");
        feed_at(&mut r, chunks, 1_000);
        // Still arriving, as far as anyone can tell.
        assert!(r.nacks(5_000, &TIMING).is_empty());
        let asked = r.nacks(12_000, &TIMING);
        assert_eq!(asked[0].chunks, [last.chunk]);
    }

    #[test]
    fn a_wholly_missing_frame_is_asked_for_whole() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        // Frame 1 never arrives at all; 2 does.
        assert!(feed_at(&mut r, frame(2, false, 500).1, 1_000).is_empty());
        assert_eq!(
            r.nacks(1_000, &TIMING),
            [Missing {
                frame_id: 1,
                chunks: vec![]
            }]
        );
        let out = feed_at(&mut r, frame(1, false, 500).1, 5_000);
        assert_eq!(ids(&out), [1, 2]);
    }

    #[test]
    fn an_unrepaired_frame_is_given_up_and_breaks_the_chain() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        let (_, mut chunks) = frame(1, false, 4_000);
        chunks.remove(1);
        feed_at(&mut r, chunks, 1_000);
        feed_at(&mut r, frame(2, false, 500).1, 2_000);

        r.expire(50_000, &TIMING);
        assert!(r.pop().is_none(), "not yet");
        assert_eq!(r.stats().incomplete, 0);
        r.expire(101_000, &TIMING);
        assert_eq!(r.stats().incomplete, 1);
        // Frame 2 cannot be decoded without 1.
        assert!(r.pop().is_none());
        assert_eq!(r.stats().dropped_waiting_for_keyframe, 1);
        assert!(r.take_keyframe_request());

        // While the chain is broken, P-frames are not worth repairing.
        let (_, mut chunks) = frame(3, false, 4_000);
        chunks.remove(0);
        feed_at(&mut r, chunks, 102_000);
        assert!(r.nacks(200_000, &TIMING).is_empty());

        // A keyframe skips past the stuck frame at once, and normal frames
        // flow again.
        let out = feed_at(&mut r, frame(4, true, 500).1, 203_000);
        assert_eq!(ids(&out), [4]);
        assert!(feed(&mut r, frame(5, false, 500).1).is_some());
    }

    #[test]
    fn a_complete_keyframe_is_not_held_behind_a_broken_frame() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        let (_, mut chunks) = frame(1, false, 4_000);
        chunks.remove(1);
        feed_at(&mut r, chunks, 1_000);
        let out = feed_at(&mut r, frame(2, true, 500).1, 2_000);
        assert_eq!(ids(&out), [2]);
        assert_eq!(r.stats().incomplete, 1);
        assert!(!r.take_keyframe_request());
    }

    #[test]
    fn progress_postpones_giving_up() {
        // A large keyframe arriving slowly is not stuck.
        let mut r = Reassembler::new();
        let (_, chunks) = frame(0, true, 40_000);
        for (i, chunk) in chunks.into_iter().enumerate() {
            let now = i as u64 * 60_000;
            r.expire(now, &TIMING);
            r.push(chunk, now);
        }
        assert!(r.pop().is_some());
        assert_eq!(r.stats().incomplete, 0);
    }

    #[test]
    fn the_next_deadline_is_the_first_repair_or_give_up_due() {
        let mut r = Reassembler::new();
        assert_eq!(r.next_deadline(&TIMING), None);
        feed(&mut r, frame(0, true, 500).1).expect("start");
        assert_eq!(r.next_deadline(&TIMING), None, "nothing waiting");

        let (_, mut chunks) = frame(1, false, 4_000);
        chunks.pop();
        feed_at(&mut r, chunks, 1_000);
        assert_eq!(r.next_deadline(&TIMING), Some(1_000 + TIMING.quiet_us));
        r.nacks(1_000 + TIMING.quiet_us, &TIMING);
        assert_eq!(
            r.next_deadline(&TIMING),
            Some(1_000 + TIMING.quiet_us + TIMING.retry_us)
        );
    }

    #[test]
    fn late_and_duplicate_chunks_are_ignored() {
        let mut r = Reassembler::new();
        let (_, chunks) = frame(0, true, 3_000);
        let replay = chunks[0].clone();
        feed(&mut r, chunks).expect("delivered");
        r.push(replay, 0);
        assert_eq!(r.stats().late_chunks, 1);

        let (_, chunks) = frame(1, false, 3_000);
        r.push(chunks[0].clone(), 0);
        r.push(chunks[0].clone(), 0);
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
        r.push(bad(0, 0), 0);
        r.push(bad(3, 3), 0);
        // Chunk count changing mid-frame.
        r.push(bad(0, 2), 0);
        r.push(bad(1, 5), 0);
        assert_eq!(r.stats().invalid_chunks, 3);
        assert!(r.pop().is_none());
    }

    #[test]
    fn too_many_frames_in_flight_gives_up_the_oldest() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        for id in 1..=(MAX_PENDING as u32 + 1) {
            let (_, chunks) = frame(id, false, 4_000);
            r.push(chunks[0].clone(), 0);
        }
        assert_eq!(r.stats().incomplete, 1);
        assert!(r.take_keyframe_request());
    }

    /// A frame id far ahead of the last one leaves a gap of millions. It is
    /// given up as one, not walked: walking it would hang the viewer.
    #[test]
    fn a_huge_gap_in_frame_ids_is_given_up_at_once() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(7, true, 500).1).expect("start");
        // The next frame the sender numbers is most of the id space away,
        // and arrives whole.
        let far = 7u32.wrapping_add(2_000_000_000);
        let (data, chunks) = frame(far, true, 4_000);
        for chunk in chunks {
            r.push(chunk, 0);
        }

        let started = std::time::Instant::now();
        r.expire(TIMING.give_up_us * 2, &TIMING);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "expire walked the gap"
        );
        // Everything in the gap counts as one frame lost, and the frame
        // that did arrive is delivered rather than waited on for ever.
        assert_eq!(r.stats().incomplete, 1);
        assert_eq!(r.pop().expect("the far frame").data, data);
    }

    /// A sender whose frame ids jump about leaves gaps that are asked for
    /// and never settle. What is remembered about them is bounded.
    #[test]
    fn scattered_frame_ids_do_not_grow_the_gap_list() {
        let mut r = Reassembler::new();
        feed(&mut r, frame(0, true, 500).1).expect("start");
        let mut now = 0;
        for round in 0..500u32 {
            // Ids far apart, so each round leaves a fresh run of gaps.
            let (_, chunks) = frame(round.wrapping_mul(10_000).wrapping_add(1), false, 4_000);
            r.push(chunks[0].clone(), now);
            now += TIMING.retry_us * 2;
            let _ = r.nacks(now, &TIMING);
            r.expire(now, &TIMING);
        }
        assert!(
            r.gap_nacks.len() <= MAX_REMEMBERED_GAPS,
            "gap list grew to {}",
            r.gap_nacks.len()
        );
        assert!(r.pending.len() <= MAX_PENDING);
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

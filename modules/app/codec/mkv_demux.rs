// Matroska (MKV) demuxer — clean-room implementation from RFC 8794
// (EBML) and the Matroska specification (matroska.org). No reference
// code consulted; ffprobe is the behavioural oracle (see
// .context/h264_mkv_codec_plan.md).
//
// Scope (video-first): locate the first video track carrying
// V_MPEG4/ISO/AVC essence, surface its CodecPrivate (avcC) once, then
// stream every SimpleBlock / BlockGroup>Block payload for that track
// to the sink with cluster-resolved timestamps. Audio tracks, lacing,
// seeking, Cues and chapters are out of scope for phase 1 (channel
// input is a pipe — strictly forward parse, O(1) memory).
//
// The parser is incremental: `feed()` accepts arbitrary chunk sizes
// and never requires the caller to buffer a whole element. Block
// payloads are streamed through `on_frame_data` in whatever pieces
// arrive; only small leaf values (track numbers, codec id/private,
// timestamps) are accumulated internally in fixed buffers.

#![allow(
    dead_code,
    reason = "shared between module and host replica; each build uses a subset"
)]

// ============================================================================
// Element IDs (with EBML marker bits, as they appear on the wire)
// ============================================================================

const ID_EBML: u32 = 0x1A45_DFA3;
const ID_SEGMENT: u32 = 0x1853_8067;
const ID_SEEK_HEAD: u32 = 0x114D_9B74;
const ID_INFO: u32 = 0x1549_A966;
const ID_TIMESTAMP_SCALE: u32 = 0x002A_D7B1;
const ID_TRACKS: u32 = 0x1654_AE6B;
const ID_TRACK_ENTRY: u32 = 0x0000_00AE;
const ID_TRACK_NUMBER: u32 = 0x0000_00D7;
const ID_TRACK_TYPE: u32 = 0x0000_0083;
const ID_CODEC_ID: u32 = 0x0000_0086;
const ID_CODEC_PRIVATE: u32 = 0x0000_63A2;
const ID_VIDEO: u32 = 0x0000_00E0;
const ID_PIXEL_WIDTH: u32 = 0x0000_00B0;
const ID_PIXEL_HEIGHT: u32 = 0x0000_00BA;
const ID_CLUSTER: u32 = 0x1F43_B675;
const ID_CLUSTER_TIMESTAMP: u32 = 0x0000_00E7;
const ID_SIMPLE_BLOCK: u32 = 0x0000_00A3;
const ID_BLOCK_GROUP: u32 = 0x0000_00A0;
const ID_BLOCK: u32 = 0x0000_00A1;
const ID_VOID: u32 = 0x0000_00EC;
const ID_CRC32: u32 = 0x0000_00BF;

/// Track type value for video in the TrackType element.
const TRACK_TYPE_VIDEO: u64 = 1;

/// EBML / Matroska file magic — first four bytes of any MKV/WebM file.
pub const MKV_MAGIC: [u8; 4] = [0x1A, 0x45, 0xDF, 0xA3];

/// Default TimestampScale: ticks are nanoseconds × this (1 ms).
const DEFAULT_TIMESTAMP_SCALE: u64 = 1_000_000;

// ============================================================================
// Public surface
// ============================================================================

/// Codec kinds this demuxer recognises on video tracks.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum VideoCodec {
    /// `V_MPEG4/ISO/AVC` — H.264, CodecPrivate is an avcC box.
    H264,
    /// `V_MPEGH/ISO/HEVC` — H.265, CodecPrivate is an hvcC box.
    H265,
    /// Anything else (surfaced so the caller can report, then ignore).
    Unknown,
}

/// Upper bound for a CodecPrivate we retain. avcC is tiny (tens of
/// bytes); hvcC carries full VPS/SPS/PPS arrays (a UHD BluRay remux
/// measures ~800 B) — 2 KiB covers both with margin.
pub const CODEC_PRIVATE_MAX: usize = 2048;

/// Description of the selected video track, delivered once.
pub struct VideoTrackInfo<'a> {
    pub codec: VideoCodec,
    pub pixel_width: u32,
    pub pixel_height: u32,
    /// Raw CodecPrivate payload (avcC for H.264).
    pub codec_private: &'a [u8],
    /// Nanoseconds per timestamp tick (TimestampScale).
    pub timestamp_scale: u64,
}

/// Demux errors. All are fatal for the current stream; the caller
/// resets the demuxer (or the whole codec) to recover.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum MkvError {
    /// Malformed EBML structure (bad varint, child overruns parent).
    Structure,
    /// Element nesting deeper than our fixed stack.
    TooDeep,
    /// Laced block on the video track (unsupported in phase 1).
    Lacing,
    /// CodecPrivate larger than CODEC_PRIVATE_MAX.
    PrivateTooBig,
}

/// Event sink. The demuxer pushes; the wrapper (module or replica)
/// owns buffering policy.
pub trait MkvSink {
    /// The first matching video track was fully described (fires at
    /// TrackEntry end, before any frame data).
    fn on_video_track(&mut self, info: &VideoTrackInfo<'_>);
    /// A block for the selected video track begins. `timestamp_ticks`
    /// is cluster-absolute (scale via `timestamp_scale`). `keyframe`
    /// is the SimpleBlock flag (false for BlockGroup Blocks — the
    /// H.264 layer keys off IDR NALs anyway).
    fn on_frame_begin(&mut self, timestamp_ticks: i64, keyframe: bool);
    /// Payload bytes for the current block, in stream order. The
    /// payload is a sequence of length-prefixed NAL units (avcC
    /// framing, length size from the codec private).
    fn on_frame_data(&mut self, data: &[u8]);
    /// Current block is complete.
    fn on_frame_end(&mut self);
    /// Fatal demux error; no further events will fire.
    fn on_error(&mut self, err: MkvError);
}

// ============================================================================
// Parser state
// ============================================================================

const STACK_DEPTH: usize = 8;
/// Fixed buffer for small leaf payloads (codec id, integers). Codec
/// private gets its own dedicated buffer.
const LEAF_BUF: usize = 64;

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// Accumulating an element ID (1–4 bytes).
    Id,
    /// Accumulating an element size varint (1–8 bytes).
    Size,
    /// Capturing a small leaf payload into `leaf` / `private_buf`.
    Leaf,
    /// Parsing a block's internal header (track varint + ts + flags).
    BlockHeader,
    /// Streaming block payload to the sink.
    BlockData,
    /// Discarding `remaining` payload bytes.
    Skip,
    /// Terminal error state.
    Error,
}

#[derive(Clone, Copy)]
struct StackEntry {
    id: u32,
    /// Absolute end offset, or u64::MAX for unknown-size masters.
    end: u64,
}

/// Per-TrackEntry accumulation, adopted at TrackEntry close.
#[derive(Clone, Copy)]
struct PendingTrack {
    number: u64,
    track_type: u64,
    is_h264: bool,
    is_h265: bool,
    codec_id_seen: bool,
    pixel_width: u32,
    pixel_height: u32,
    private_len: u32,
}

impl PendingTrack {
    const fn new() -> Self {
        PendingTrack {
            number: 0,
            track_type: 0,
            is_h264: false,
            is_h265: false,
            codec_id_seen: false,
            pixel_width: 0,
            pixel_height: 0,
            private_len: 0,
        }
    }
}

#[repr(C)]
pub struct MkvDemux {
    phase: Phase,
    /// Absolute offset of the next byte `feed` will consume.
    offset: u64,

    // --- varint accumulation (Id / Size phases) ---
    vint_buf: [u8; 8],
    vint_len: u8,
    vint_need: u8,
    /// ID parsed while waiting for its size.
    cur_id: u32,

    // --- element stack ---
    stack: [StackEntry; STACK_DEPTH],
    depth: u8,

    // --- leaf capture ---
    leaf: [u8; LEAF_BUF],
    leaf_len: u32,
    /// Total payload size of the leaf being captured.
    leaf_total: u64,
    /// Leaf bytes beyond the capture buffer are discarded (only legal
    /// for CodecPrivate overflow detection; others are tiny).
    remaining: u64,

    // --- block state ---
    /// Bytes of block-internal header consumed so far.
    blk_hdr: [u8; 12],
    blk_hdr_len: u8,
    /// Payload bytes left in the current block element (incl. header).
    blk_remaining: u64,
    /// Block belongs to the selected video track and is being streamed.
    blk_active: bool,

    // --- stream-level results ---
    timestamp_scale: u64,
    cluster_timestamp: u64,
    /// Selected video track number; 0 = none yet.
    video_track: u64,
    video_codec: VideoCodec,
    video_width: u32,
    video_height: u32,
    /// True once on_video_track has fired.
    track_reported: bool,

    // --- TrackEntry accumulation ---
    pending: PendingTrack,
    in_track_entry: bool,
    /// True while `Leaf` phase is capturing into `private_buf`.
    capturing_private: bool,
    private_buf: [u8; CODEC_PRIVATE_MAX],
}

impl MkvDemux {
    pub const fn new() -> Self {
        MkvDemux {
            phase: Phase::Id,
            offset: 0,
            vint_buf: [0; 8],
            vint_len: 0,
            vint_need: 0,
            cur_id: 0,
            stack: [StackEntry { id: 0, end: 0 }; STACK_DEPTH],
            depth: 0,
            leaf: [0; LEAF_BUF],
            leaf_len: 0,
            leaf_total: 0,
            remaining: 0,
            blk_hdr: [0; 12],
            blk_hdr_len: 0,
            blk_remaining: 0,
            blk_active: false,
            timestamp_scale: DEFAULT_TIMESTAMP_SCALE,
            cluster_timestamp: 0,
            video_track: 0,
            video_codec: VideoCodec::Unknown,
            video_width: 0,
            video_height: 0,
            track_reported: false,
            pending: PendingTrack::new(),
            in_track_entry: false,
            capturing_private: false,
            private_buf: [0; CODEC_PRIVATE_MAX],
        }
    }

    pub fn reset(&mut self) {
        *self = MkvDemux::new();
    }

    /// Feed a chunk. Events fire on `sink` as elements complete.
    /// After an error the parser latches Phase::Error and ignores
    /// further input.
    pub fn feed(&mut self, data: &[u8], sink: &mut impl MkvSink) {
        let mut pos = 0usize;
        while pos < data.len() {
            match self.phase {
                Phase::Error => return,
                Phase::Id => pos = self.feed_id(data, pos, sink),
                Phase::Size => pos = self.feed_size(data, pos, sink),
                Phase::Leaf => pos = self.feed_leaf(data, pos, sink),
                Phase::BlockHeader => pos = self.feed_block_header(data, pos, sink),
                Phase::BlockData => pos = self.feed_block_data(data, pos, sink),
                Phase::Skip => pos = self.feed_skip(data, pos, sink),
            }
        }
    }

    // ------------------------------------------------------------------
    // Phase handlers. Each consumes >= 1 byte or transitions phase, and
    // returns the new position.
    // ------------------------------------------------------------------

    fn fail(&mut self, err: MkvError, sink: &mut impl MkvSink) {
        self.phase = Phase::Error;
        sink.on_error(err);
    }

    fn feed_id(&mut self, data: &[u8], mut pos: usize, sink: &mut impl MkvSink) -> usize {
        if self.vint_len == 0 {
            let b = data[pos];
            let n = ebml_len_from_marker(b);
            if n == 0 || n > 4 {
                self.fail(MkvError::Structure, sink);
                return pos;
            }
            self.vint_need = n;
        }
        while (self.vint_len as usize) < (self.vint_need as usize) && pos < data.len() {
            self.vint_buf[self.vint_len as usize] = data[pos];
            self.vint_len += 1;
            pos += 1;
            self.offset += 1;
        }
        if self.vint_len == self.vint_need {
            // ID keeps its marker bits.
            let mut id: u32 = 0;
            for i in 0..self.vint_len as usize {
                id = (id << 8) | self.vint_buf[i] as u32;
            }
            self.cur_id = id;
            self.vint_len = 0;
            self.vint_need = 0;
            self.phase = Phase::Size;
        }
        pos
    }

    fn feed_size(&mut self, data: &[u8], mut pos: usize, sink: &mut impl MkvSink) -> usize {
        if self.vint_len == 0 {
            let b = data[pos];
            let n = ebml_len_from_marker(b);
            if n == 0 {
                self.fail(MkvError::Structure, sink);
                return pos;
            }
            self.vint_need = n;
        }
        while (self.vint_len as usize) < (self.vint_need as usize) && pos < data.len() {
            self.vint_buf[self.vint_len as usize] = data[pos];
            self.vint_len += 1;
            pos += 1;
            self.offset += 1;
        }
        if self.vint_len == self.vint_need {
            let n = self.vint_len as usize;
            // Strip marker bit, accumulate.
            // n == 8 ⇒ the first byte is pure marker (0x01); the mask
            // must be 0 — `0xFF >> 8` would be an overflowing shift.
            let first_mask: u8 = if n >= 8 { 0 } else { 0xFF >> n };
            let mut size: u64 = (self.vint_buf[0] & first_mask) as u64;
            let all_ones = {
                let mask = first_mask;
                let mut ones = (self.vint_buf[0] & mask) == mask;
                for i in 1..n {
                    ones &= self.vint_buf[i] == 0xFF;
                }
                ones
            };
            for i in 1..n {
                size = (size << 8) | self.vint_buf[i] as u64;
            }
            self.vint_len = 0;
            self.vint_need = 0;
            let unknown = all_ones;
            self.dispatch_element(size, unknown, sink);
        }
        pos
    }

    /// An element header (id + size) is complete: decide how to treat
    /// the payload.
    fn dispatch_element(&mut self, size: u64, unknown_size: bool, sink: &mut impl MkvSink) {
        let id = self.cur_id;

        // Close any parents whose extent this element starts at or
        // beyond (known-size masters).
        self.close_finished(sink);

        // An unknown-size master is terminated by the next element
        // that is not a valid child of it. For our scope: an
        // unknown-size Segment ends at nothing we care about (EOF);
        // an unknown-size Cluster ends at the next Cluster or any
        // Segment-level element.
        if self.top_id() == ID_CLUSTER && self.top_unknown() {
            match id {
                ID_CLUSTER_TIMESTAMP | ID_SIMPLE_BLOCK | ID_BLOCK_GROUP | ID_VOID | ID_CRC32 => {}
                _ => self.pop(sink),
            }
        }

        let is_master = matches!(
            id,
            ID_SEGMENT
                | ID_TRACKS
                | ID_TRACK_ENTRY
                | ID_VIDEO
                | ID_CLUSTER
                | ID_BLOCK_GROUP
                | ID_INFO
        );

        if is_master {
            if (self.depth as usize) >= STACK_DEPTH {
                self.fail(MkvError::TooDeep, sink);
                return;
            }
            let end = if unknown_size {
                u64::MAX
            } else {
                self.offset + size
            };
            self.stack[self.depth as usize] = StackEntry { id, end };
            self.depth += 1;
            if id == ID_TRACK_ENTRY {
                self.pending = PendingTrack::new();
                self.in_track_entry = true;
            }
            if id == ID_CLUSTER {
                self.cluster_timestamp = 0;
            }
            self.phase = Phase::Id;
            return;
        }

        if unknown_size {
            // Unknown size is only legal on masters.
            self.fail(MkvError::Structure, sink);
            return;
        }

        // Leaf elements we capture.
        let capture = match id {
            ID_TIMESTAMP_SCALE | ID_CLUSTER_TIMESTAMP => true,
            ID_TRACK_NUMBER | ID_TRACK_TYPE | ID_CODEC_ID | ID_PIXEL_WIDTH | ID_PIXEL_HEIGHT
                if self.in_track_entry =>
            {
                true
            }
            ID_CODEC_PRIVATE if self.in_track_entry => true,
            _ => false,
        };

        if capture {
            self.capturing_private = id == ID_CODEC_PRIVATE;
            if self.capturing_private {
                if size as usize > CODEC_PRIVATE_MAX {
                    self.fail(MkvError::PrivateTooBig, sink);
                    return;
                }
            } else if size as usize > LEAF_BUF {
                self.fail(MkvError::Structure, sink);
                return;
            }
            self.leaf_len = 0;
            self.leaf_total = size;
            self.remaining = size;
            self.phase = if size == 0 { Phase::Id } else { Phase::Leaf };
            if size == 0 {
                self.finish_leaf(sink);
            }
            return;
        }

        // Blocks on the (potential) video track.
        if id == ID_SIMPLE_BLOCK || id == ID_BLOCK {
            self.blk_hdr_len = 0;
            self.blk_remaining = size;
            self.blk_active = false;
            self.phase = Phase::BlockHeader;
            return;
        }

        // Everything else: skip payload.
        self.remaining = size;
        self.phase = if size == 0 { Phase::Id } else { Phase::Skip };
    }

    fn feed_leaf(&mut self, data: &[u8], pos: usize, sink: &mut impl MkvSink) -> usize {
        let avail = data.len() - pos;
        let take = if (self.remaining as usize) < avail {
            self.remaining as usize
        } else {
            avail
        };
        for i in 0..take {
            let b = data[pos + i];
            if self.capturing_private {
                if (self.leaf_len as usize) < CODEC_PRIVATE_MAX {
                    self.private_buf[self.leaf_len as usize] = b;
                    self.leaf_len += 1;
                }
            } else if (self.leaf_len as usize) < LEAF_BUF {
                self.leaf[self.leaf_len as usize] = b;
                self.leaf_len += 1;
            }
        }
        self.remaining -= take as u64;
        self.offset += take as u64;
        if self.remaining == 0 {
            self.finish_leaf(sink);
            self.phase = Phase::Id;
            self.close_finished(sink);
        }
        pos + take
    }

    fn finish_leaf(&mut self, _sink: &mut impl MkvSink) {
        let id = self.cur_id;
        // During CodecPrivate capture `leaf_len` counts bytes in
        // `private_buf`, not `leaf` — indexing `leaf` with it would
        // walk off the 64-byte buffer for any private > LEAF_BUF
        // (hvcC records are ~800 B). No integer leaf uses the
        // private path, so 0 is fine.
        let val = if self.capturing_private {
            0
        } else {
            uint_from(&self.leaf[..self.leaf_len as usize])
        };
        match id {
            ID_TIMESTAMP_SCALE => {
                self.timestamp_scale = if val == 0 {
                    DEFAULT_TIMESTAMP_SCALE
                } else {
                    val
                }
            }
            ID_CLUSTER_TIMESTAMP => self.cluster_timestamp = val,
            ID_TRACK_NUMBER => self.pending.number = val,
            ID_TRACK_TYPE => self.pending.track_type = val,
            ID_PIXEL_WIDTH => self.pending.pixel_width = val as u32,
            ID_PIXEL_HEIGHT => self.pending.pixel_height = val as u32,
            ID_CODEC_ID => {
                self.pending.codec_id_seen = true;
                let id_bytes = &self.leaf[..self.leaf_len as usize];
                self.pending.is_h264 = id_bytes == b"V_MPEG4/ISO/AVC";
                self.pending.is_h265 = id_bytes == b"V_MPEGH/ISO/HEVC";
            }
            ID_CODEC_PRIVATE => {
                self.pending.private_len = self.leaf_len;
            }
            _ => {}
        }
        self.capturing_private = false;
    }

    fn feed_block_header(&mut self, data: &[u8], mut pos: usize, sink: &mut impl MkvSink) -> usize {
        // Block header: track number (EBML varint, value), then 2-byte
        // signed relative timestamp, then 1 flags byte.
        while pos < data.len() && self.blk_remaining > 0 {
            let need = {
                if self.blk_hdr_len == 0 {
                    1
                } else {
                    let tn_len = ebml_len_from_marker(self.blk_hdr[0]);
                    if tn_len == 0 || tn_len > 8 {
                        self.fail(MkvError::Structure, sink);
                        return pos;
                    }
                    tn_len as usize + 3
                }
            };
            if (self.blk_hdr_len as usize) < need {
                self.blk_hdr[self.blk_hdr_len as usize] = data[pos];
                self.blk_hdr_len += 1;
                pos += 1;
                self.offset += 1;
                self.blk_remaining -= 1;
                continue;
            }
            break;
        }
        // Re-check completeness (need is dynamic on first byte).
        if self.blk_hdr_len >= 1 {
            let tn_len = ebml_len_from_marker(self.blk_hdr[0]) as usize;
            if tn_len == 0 {
                self.fail(MkvError::Structure, sink);
                return pos;
            }
            let full = tn_len + 3;
            if (self.blk_hdr_len as usize) == full {
                // Parse.
                let tn_mask: u8 = if tn_len >= 8 { 0 } else { 0xFF >> tn_len };
                let mut track: u64 = (self.blk_hdr[0] & tn_mask) as u64;
                for i in 1..tn_len {
                    track = (track << 8) | self.blk_hdr[i] as u64;
                }
                let rel_ts = i16::from_be_bytes([self.blk_hdr[tn_len], self.blk_hdr[tn_len + 1]]);
                let flags = self.blk_hdr[tn_len + 2];
                let lacing = (flags >> 1) & 0x03;
                let keyframe = self.cur_id == ID_SIMPLE_BLOCK && (flags & 0x80) != 0;

                if self.video_track != 0 && track == self.video_track {
                    if lacing != 0 {
                        self.fail(MkvError::Lacing, sink);
                        return pos;
                    }
                    let ts = self.cluster_timestamp as i64 + rel_ts as i64;
                    self.blk_active = true;
                    sink.on_frame_begin(ts, keyframe);
                } else {
                    self.blk_active = false;
                }
                self.phase = if self.blk_remaining == 0 {
                    Phase::Id
                } else {
                    Phase::BlockData
                };
                if self.blk_remaining == 0 {
                    if self.blk_active {
                        sink.on_frame_end();
                    }
                    self.close_finished(sink);
                }
            }
        }
        pos
    }

    fn feed_block_data(&mut self, data: &[u8], pos: usize, sink: &mut impl MkvSink) -> usize {
        let avail = data.len() - pos;
        let take = if (self.blk_remaining as usize) < avail {
            self.blk_remaining as usize
        } else {
            avail
        };
        if self.blk_active && take > 0 {
            sink.on_frame_data(&data[pos..pos + take]);
        }
        self.blk_remaining -= take as u64;
        self.offset += take as u64;
        if self.blk_remaining == 0 {
            if self.blk_active {
                sink.on_frame_end();
                self.blk_active = false;
            }
            self.phase = Phase::Id;
            self.close_finished(sink);
        }
        pos + take
    }

    fn feed_skip(&mut self, data: &[u8], pos: usize, sink: &mut impl MkvSink) -> usize {
        let avail = data.len() - pos;
        let take = if (self.remaining as usize) < avail {
            self.remaining as usize
        } else {
            avail
        };
        self.remaining -= take as u64;
        self.offset += take as u64;
        if self.remaining == 0 {
            self.phase = Phase::Id;
            self.close_finished(sink);
        }
        pos + take
    }

    // ------------------------------------------------------------------
    // Stack helpers
    // ------------------------------------------------------------------

    fn top_id(&self) -> u32 {
        if self.depth == 0 {
            0
        } else {
            self.stack[self.depth as usize - 1].id
        }
    }

    fn top_unknown(&self) -> bool {
        self.depth > 0 && self.stack[self.depth as usize - 1].end == u64::MAX
    }

    /// Pop all known-size masters whose end we have reached.
    fn close_finished(&mut self, sink: &mut impl MkvSink) {
        while self.depth > 0 {
            let top = self.stack[self.depth as usize - 1];
            if top.end != u64::MAX && self.offset >= top.end {
                self.pop(sink);
            } else {
                break;
            }
        }
    }

    fn pop(&mut self, sink: &mut impl MkvSink) {
        if self.depth == 0 {
            return;
        }
        let top = self.stack[self.depth as usize - 1];
        self.depth -= 1;
        if top.id == ID_TRACK_ENTRY {
            self.in_track_entry = false;
            let p = self.pending;
            // Adopt only SUPPORTED video codecs: claiming the first
            // video track regardless of codec would let an
            // unsupported leading track (attached-cover video, VC-1,
            // …) permanently block discovery of a playable H.264/
            // H.265 track later in the Tracks element. Unsupported
            // video tracks are skipped exactly like audio tracks; a
            // file with no supported video track simply never fires
            // on_video_track and ends as EOF-without-track.
            if self.video_track == 0
                && p.track_type == TRACK_TYPE_VIDEO
                && p.codec_id_seen
                && p.number != 0
                && (p.is_h264 || p.is_h265)
            {
                self.video_track = p.number;
                self.video_codec = if p.is_h264 {
                    VideoCodec::H264
                } else {
                    VideoCodec::H265
                };
                self.video_width = p.pixel_width;
                self.video_height = p.pixel_height;
                if !self.track_reported {
                    self.track_reported = true;
                    let info = VideoTrackInfo {
                        codec: self.video_codec,
                        pixel_width: p.pixel_width,
                        pixel_height: p.pixel_height,
                        codec_private: &self.private_buf[..p.private_len as usize],
                        timestamp_scale: self.timestamp_scale,
                    };
                    sink.on_video_track(&info);
                }
            }
        }
    }
}

// ============================================================================
// Small helpers
// ============================================================================

/// Number of bytes in an EBML varint, from its first byte (position of
/// the marker bit). 0 = invalid (first byte 0x00 ⇒ length > 8).
fn ebml_len_from_marker(b: u8) -> u8 {
    if b == 0 {
        return 0;
    }
    (b.leading_zeros() + 1) as u8
}

/// Big-endian unsigned integer from an EBML leaf payload (0–8 bytes).
fn uint_from(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &b in bytes.iter().take(8) {
        v = (v << 8) | b as u64;
    }
    v
}

// ============================================================================
// avcC (AVCDecoderConfigurationRecord) — parameter-set extraction
// ============================================================================

/// Parsed avcC header. SPS/PPS payloads are borrowed from the record.
pub struct AvcC<'a> {
    /// Bytes per NAL length prefix in block payloads (1, 2 or 4).
    pub nal_length_size: u8,
    pub sps: &'a [u8],
    pub pps: &'a [u8],
}

/// Parse an avcC record, returning the first SPS and PPS. Multiple
/// parameter sets per record are not produced by our encode path;
/// extras are ignored (h264bsd activates by id anyway when they are
/// fed, so callers wanting them can walk the record themselves).
pub fn parse_avcc(rec: &[u8]) -> Option<AvcC<'_>> {
    if rec.len() < 7 || rec[0] != 1 {
        return None;
    }
    let nal_length_size = (rec[4] & 0x03) + 1;
    let num_sps = (rec[5] & 0x1F) as usize;
    let mut off = 6usize;
    let mut sps: &[u8] = &[];
    for i in 0..num_sps {
        if off + 2 > rec.len() {
            return None;
        }
        let len = u16::from_be_bytes([rec[off], rec[off + 1]]) as usize;
        off += 2;
        if off + len > rec.len() {
            return None;
        }
        if i == 0 {
            sps = &rec[off..off + len];
        }
        off += len;
    }
    if off >= rec.len() {
        return None;
    }
    let num_pps = rec[off] as usize;
    off += 1;
    let mut pps: &[u8] = &[];
    for i in 0..num_pps {
        if off + 2 > rec.len() {
            return None;
        }
        let len = u16::from_be_bytes([rec[off], rec[off + 1]]) as usize;
        off += 2;
        if off + len > rec.len() {
            return None;
        }
        if i == 0 {
            pps = &rec[off..off + len];
        }
        off += len;
    }
    if sps.is_empty() || pps.is_empty() {
        return None;
    }
    Some(AvcC {
        nal_length_size,
        sps,
        pps,
    })
}

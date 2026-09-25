// Contract: encoded — the record stream on the `AudioEncoded` and
// `VideoEncoded` content types.
//
// Layer: contracts (public, stable).
//
// Three records, all little-endian:
//
//   STREAM  [kind=1][codec:u8][packing:u8][channels:u8]
//           [clock_rate:u32][config_len:u32][config: config_len bytes]
//   UNIT    [kind=2][flags:u8][len:u32][pts:i64][pts_minus_dts:i32]
//           [payload: len bytes]
//   END     [kind=3]
//
// THE STREAM DESCRIBES ITSELF. Codec, packing, clock rate, channel count and
// the codec configuration (AudioSpecificConfig, avcC/hvcC, OpusHead) arrive in
// a `STREAM` record before the first unit. A compose-time fact cannot say what
// a demuxer will find in a file or what an RTP peer negotiated, so the runtime
// truth is in-band; the `audio.encoded` / `video.encoded` port facts are the
// build-time check on top of it. The codec and packing bytes are positions in
// `fluxor_contracts::vocabulary::CODECS` / `PACKINGS`, pinned against the
// constants below.
//
// SEQUENCE. A stream opens with `STREAM`. A `STREAM` after units starts a new
// stream — the next playlist entry, a renegotiated call — and a consumer
// resets on it. `END` closes the stream and tells a decoder to flush what it
// holds for reordering; that is distinct from the channel going quiet. A
// `UNIT` before any `STREAM` is a fault. `Sequence` below enforces all of it.
//
// UNITS MAY BE FRAGMENTED. An access unit is one or more contiguous `UNIT`
// records; every fragment but the last sets `CONTINUES`. A 1080p keyframe is
// hundreds of kilobytes — more than a small target's ring, and more than a
// consumer should have to hold to start decoding — and an MPEG-TS video PES
// does not even know its own length up front. Fragments repeat the unit's
// `pts` and `pts_minus_dts`; `KEY` and `DISCONTINUITY` are set on the first
// fragment only. A producer splits at NAL boundaries where it can. `STREAM`
// or `END` between fragments is a fault.
//
// FLAGS.
//   KEY            — the unit decodes without earlier units. Every audio unit
//                    carries it.
//   DISCONTINUITY  — units before this one were lost; a decoder conceals.
//   CONTINUES      — more fragments of this unit follow.
//   TRUNCATED      — on a unit's last fragment only: the unit lost data in
//                    flight and must be discarded, not decoded.
//
// TIME. `pts` is presentation time in ticks at the stream's `clock_rate`,
// signed because edit lists and codec delay (Opus pre-skip) put the first
// presented sample after time zero. `pts - pts_minus_dts` is the decode time;
// zero for streams without reordering, which is every audio codec and every
// RTP source. Units arrive in decode order. Ticks are never normalised to a
// common unit: on a target without a divide unit that is a software 64-bit
// division per unit, sixty-four passes of shift-and-subtract through
// `__aeabi_uldivmod`, and every consumer wants the stream's own clock anyway —
// an RTP timestamp is ticks at the payload clock, and a decoder counts samples.
//
// READING. Both content types are `Streamed`: a write is all-or-nothing, but a
// read may return any split of the byte stream. A consumer keeps a carry buffer,
// appends what it reads, and calls `parse` until it answers `NeedMore`, then
// compacts — the shape `gpu_pump` uses for `GpuCommand`. Records are never
// interleaved from two producers: the composer refuses fan-in onto an encoded
// input port.
//
// Geometry and sample rate are not in the record. They are properties of the
// bitstream (SPS, VP8 keyframe header, AudioSpecificConfig) and a decoder
// reads them there; a second copy here could only disagree with it.

/// Record kinds.
pub const KIND_STREAM: u8 = 1;
pub const KIND_UNIT: u8 = 2;
pub const KIND_END: u8 = 3;

/// Fixed header bytes of each record.
pub const STREAM_HEADER: usize = 12;
pub const UNIT_HEADER: usize = 18;
pub const END_LEN: usize = 1;

/// Codec wire bytes — positions in `vocabulary::CODECS`.
pub const CODEC_PCMU: u8 = 0;
pub const CODEC_AAC: u8 = 1;
pub const CODEC_MP3: u8 = 2;
pub const CODEC_OPUS: u8 = 3;
pub const CODEC_H264: u8 = 4;
pub const CODEC_H265: u8 = 5;
pub const CODEC_VP8: u8 = 6;
pub const CODEC_PCMA: u8 = 7;
/// Number of allocated codec bytes.
pub const CODEC_COUNT: u8 = 8;

/// Packing wire bytes — positions in `vocabulary::PACKINGS`.
pub const PACKING_RAW: u8 = 0;
pub const PACKING_FRAMED: u8 = 1;
pub const PACKING_ANNEXB: u8 = 2;
pub const PACKING_LENGTH_PREFIXED: u8 = 3;

/// `UNIT` flags.
pub const FLAG_KEY: u8 = 0x01;
pub const FLAG_DISCONTINUITY: u8 = 0x02;
pub const FLAG_CONTINUES: u8 = 0x04;
pub const FLAG_TRUNCATED: u8 = 0x08;
const FLAGS_KNOWN: u8 = FLAG_KEY | FLAG_DISCONTINUITY | FLAG_CONTINUES | FLAG_TRUNCATED;
/// Flags a fragment after the first may carry.
const FLAGS_LATER_FRAGMENT: u8 = FLAG_CONTINUES | FLAG_TRUNCATED;

/// Whether `codec` is an audio codec (`AudioEncoded`).
pub const fn is_audio(codec: u8) -> bool {
    matches!(
        codec,
        CODEC_PCMU | CODEC_AAC | CODEC_MP3 | CODEC_OPUS | CODEC_PCMA
    )
}

/// Whether `codec` is a video codec (`VideoEncoded`).
pub const fn is_video(codec: u8) -> bool {
    matches!(codec, CODEC_H264 | CODEC_H265 | CODEC_VP8)
}

/// Whether a `STREAM` description is one this contract admits: a known codec
/// in a packing it can take, a non-zero clock, a channel count for audio and
/// none for video, and the configuration the packing requires.
///
/// Checked by producers before writing and by consumers on receipt, so a
/// description that no consumer could honour never reaches one.
pub fn stream_is_valid(
    codec: u8,
    packing: u8,
    channels: u8,
    clock_rate: u32,
    config: &[u8],
) -> bool {
    if clock_rate == 0 {
        return false;
    }
    if is_audio(codec) && channels == 0 || is_video(codec) && channels != 0 {
        return false;
    }
    match (codec, packing) {
        (CODEC_PCMU | CODEC_PCMA, PACKING_RAW) => config.is_empty(),
        // Raw AAC is undecodable without its AudioSpecificConfig (two bytes at
        // minimum); ADTS carries the same facts in every frame header.
        (CODEC_AAC, PACKING_RAW) => config.len() >= 2,
        (CODEC_AAC, PACKING_FRAMED) => config.is_empty(),
        (CODEC_MP3, PACKING_FRAMED) => config.is_empty(),
        // RFC 7587 carries no OpusHead: absent means mapping family 0 with the
        // channel count above and no pre-skip. A file's OpusHead is the 19-byte
        // RFC 7845 identification header.
        (CODEC_OPUS, PACKING_RAW) => {
            config.is_empty() || (config.len() >= 19 && &config[..8] == b"OpusHead")
        }
        (CODEC_H264 | CODEC_H265, PACKING_ANNEXB) => config.is_empty(),
        // The length-prefix width and the parameter sets live in the
        // decoder configuration record: avcC is at least 7 bytes, hvcC 23.
        (CODEC_H264, PACKING_LENGTH_PREFIXED) => config.len() >= 7,
        (CODEC_H265, PACKING_LENGTH_PREFIXED) => config.len() >= 23,
        (CODEC_VP8, PACKING_RAW) => config.is_empty(),
        _ => false,
    }
}

/// A stream description, borrowing its configuration from the read buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream<'a> {
    pub codec: u8,
    pub packing: u8,
    pub channels: u8,
    pub clock_rate: u32,
    pub config: &'a [u8],
}

/// One access-unit fragment, borrowing its payload from the read buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unit<'a> {
    pub flags: u8,
    pub pts: i64,
    pub pts_minus_dts: i32,
    pub payload: &'a [u8],
}

impl Unit<'_> {
    /// Whether this is the unit's last fragment.
    pub const fn is_last(&self) -> bool {
        self.flags & FLAG_CONTINUES == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record<'a> {
    Stream(Stream<'a>),
    Unit(Unit<'a>),
    End,
}

/// Why a stream cannot be read further. Every fault is terminal: the reader
/// has lost the record boundary or been sent something no consumer can
/// honour, and the producer must start a new stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A kind byte outside `KIND_*`.
    UnknownKind,
    /// A `STREAM` that `stream_is_valid` refuses.
    BadStream,
    /// Unknown flag bits, or `TRUNCATED` together with `CONTINUES`.
    BadFlags,
    /// A record declaring more bytes than the reader can ever hold.
    Oversize,
    /// A record out of order: a unit before any stream, a stream or end
    /// inside a fragmented unit, or a fragment that disagrees with its unit.
    Sequence,
}

/// The outcome of `parse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parse<'a> {
    /// A whole record, and how many bytes of the buffer it occupied.
    Record {
        record: Record<'a>,
        consumed: usize,
    },
    /// The buffer ends inside a record; read more and call again.
    NeedMore,
    Fault(Fault),
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Parse the record at the front of `buf`.
///
/// `capacity` is the size of the caller's carry buffer: a record whose
/// declared length cannot fit it would leave the reader waiting forever, so
/// it is refused as `Oversize` as soon as its header is readable.
pub fn parse(buf: &[u8], capacity: usize) -> Parse<'_> {
    let Some(&kind) = buf.first() else {
        return Parse::NeedMore;
    };
    match kind {
        KIND_STREAM => {
            if buf.len() < STREAM_HEADER {
                return Parse::NeedMore;
            }
            let config_len = u32_at(buf, 8) as usize;
            let Some(total) = STREAM_HEADER.checked_add(config_len) else {
                return Parse::Fault(Fault::Oversize);
            };
            if total > capacity {
                return Parse::Fault(Fault::Oversize);
            }
            if buf.len() < total {
                return Parse::NeedMore;
            }
            let stream = Stream {
                codec: buf[1],
                packing: buf[2],
                channels: buf[3],
                clock_rate: u32_at(buf, 4),
                config: &buf[STREAM_HEADER..total],
            };
            if !stream_is_valid(
                stream.codec,
                stream.packing,
                stream.channels,
                stream.clock_rate,
                stream.config,
            ) {
                return Parse::Fault(Fault::BadStream);
            }
            Parse::Record {
                record: Record::Stream(stream),
                consumed: total,
            }
        }
        KIND_UNIT => {
            if buf.len() < UNIT_HEADER {
                return Parse::NeedMore;
            }
            let flags = buf[1];
            if flags & !FLAGS_KNOWN != 0
                || flags & FLAG_TRUNCATED != 0 && flags & FLAG_CONTINUES != 0
            {
                return Parse::Fault(Fault::BadFlags);
            }
            let len = u32_at(buf, 2) as usize;
            let Some(total) = UNIT_HEADER.checked_add(len) else {
                return Parse::Fault(Fault::Oversize);
            };
            if total > capacity {
                return Parse::Fault(Fault::Oversize);
            }
            if buf.len() < total {
                return Parse::NeedMore;
            }
            let mut pts = [0u8; 8];
            pts.copy_from_slice(&buf[6..14]);
            let unit = Unit {
                flags,
                pts: i64::from_le_bytes(pts),
                pts_minus_dts: u32_at(buf, 14) as i32,
                payload: &buf[UNIT_HEADER..total],
            };
            Parse::Record {
                record: Record::Unit(unit),
                consumed: total,
            }
        }
        KIND_END => Parse::Record {
            record: Record::End,
            consumed: END_LEN,
        },
        _ => Parse::Fault(Fault::UnknownKind),
    }
}

/// Write a `STREAM` record. `None` when `out` is too small or the description
/// is one `stream_is_valid` refuses — never a partial record.
pub fn write_stream(
    out: &mut [u8],
    codec: u8,
    packing: u8,
    channels: u8,
    clock_rate: u32,
    config: &[u8],
) -> Option<usize> {
    if !stream_is_valid(codec, packing, channels, clock_rate, config) {
        return None;
    }
    let total = STREAM_HEADER.checked_add(config.len())?;
    if out.len() < total {
        return None;
    }
    out[0] = KIND_STREAM;
    out[1] = codec;
    out[2] = packing;
    out[3] = channels;
    out[4..8].copy_from_slice(&clock_rate.to_le_bytes());
    out[8..12].copy_from_slice(&(config.len() as u32).to_le_bytes());
    out[STREAM_HEADER..total].copy_from_slice(config);
    Some(total)
}

/// Write just a `UNIT` header, for a producer that sends the header and the
/// payload as separate writes of one record — a video fragment already sitting
/// in a decoder or DMA buffer is not worth copying to frame. The two writes
/// must go to the channel back to back; `write_unit` is the single-buffer form.
pub fn write_unit_header(
    out: &mut [u8],
    flags: u8,
    len: u32,
    pts: i64,
    pts_minus_dts: i32,
) -> Option<usize> {
    if flags & !FLAGS_KNOWN != 0 || flags & FLAG_TRUNCATED != 0 && flags & FLAG_CONTINUES != 0 {
        return None;
    }
    if out.len() < UNIT_HEADER {
        return None;
    }
    out[0] = KIND_UNIT;
    out[1] = flags;
    out[2..6].copy_from_slice(&len.to_le_bytes());
    out[6..14].copy_from_slice(&pts.to_le_bytes());
    out[14..18].copy_from_slice(&pts_minus_dts.to_le_bytes());
    Some(UNIT_HEADER)
}

/// Write a whole `UNIT` record. `None` when `out` cannot hold it.
pub fn write_unit(
    out: &mut [u8],
    flags: u8,
    pts: i64,
    pts_minus_dts: i32,
    payload: &[u8],
) -> Option<usize> {
    let total = UNIT_HEADER.checked_add(payload.len())?;
    if out.len() < total || payload.len() > u32::MAX as usize {
        return None;
    }
    write_unit_header(out, flags, payload.len() as u32, pts, pts_minus_dts)?;
    out[UNIT_HEADER..total].copy_from_slice(payload);
    Some(total)
}

/// Write an `END` record.
pub fn write_end(out: &mut [u8]) -> Option<usize> {
    let slot = out.first_mut()?;
    *slot = KIND_END;
    Some(END_LEN)
}

/// Where a reader is in the record sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    /// No stream is open.
    Closed,
    /// A stream is open, between units.
    BetweenUnits,
    /// Inside a fragmented unit with this `pts` and `pts_minus_dts`.
    InUnit { pts: i64, pts_minus_dts: i32 },
}

/// The record-order rules, enforced. A consumer admits every parsed record
/// through one of these; a `Fault` ends the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sequence {
    at: Position,
}

impl Default for Sequence {
    fn default() -> Self {
        Self::new()
    }
}

impl Sequence {
    pub const fn new() -> Self {
        Self {
            at: Position::Closed,
        }
    }

    /// Whether a stream is open.
    pub const fn is_open(&self) -> bool {
        !matches!(self.at, Position::Closed)
    }

    /// Admit `record`, or refuse it as out of order.
    pub fn admit(&mut self, record: &Record<'_>) -> Result<(), Fault> {
        self.at = match (self.at, record) {
            (Position::InUnit { .. }, Record::Stream(_) | Record::End) => {
                return Err(Fault::Sequence)
            }
            (_, Record::Stream(_)) => Position::BetweenUnits,
            (Position::Closed, Record::Unit(_)) => return Err(Fault::Sequence),
            (_, Record::End) => Position::Closed,
            (Position::BetweenUnits, Record::Unit(u)) => {
                if u.is_last() {
                    Position::BetweenUnits
                } else {
                    Position::InUnit {
                        pts: u.pts,
                        pts_minus_dts: u.pts_minus_dts,
                    }
                }
            }
            (Position::InUnit { pts, pts_minus_dts }, Record::Unit(u)) => {
                if u.flags & !FLAGS_LATER_FRAGMENT != 0
                    || u.pts != pts
                    || u.pts_minus_dts != pts_minus_dts
                {
                    return Err(Fault::Sequence);
                }
                if u.is_last() {
                    Position::BetweenUnits
                } else {
                    self.at
                }
            }
        };
        Ok(())
    }
}

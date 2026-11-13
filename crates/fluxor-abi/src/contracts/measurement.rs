// Contract: measurement — block-per-acquisition surface (the
// `MeasurementStream` content type).
//
// Layer: contracts (public, stable).
//
// One acquisition per record: a fixed 16-byte header, then the block.
//
//   [seq: u32] [block_len: u32] [t_micros: u64] [block: block_len bytes]
//
// All little-endian, like every other record on this surface. `t_micros` sits
// third rather than second so every field is naturally aligned within the
// header and the block starts on an 8-byte boundary — the decode reads
// byte-at-a-time and does not need it, but a consumer casting the block to
// 16- or 32-bit samples does, and on a Cortex-M0+ an unaligned load faults
// rather than being fixed up.
//
// WHAT IS IN THE BLOCK is not in the record. The sample encoding, the channel
// count and the samples per channel are CAPABILITY FACTS on the producing port
// (`measurement.stream`, facts `encoding` / `channels` /
// `samples_per_channel` / `period_ms` / `max_payload`).
//
// That split is the whole design, and the reason is the same one
// `sensor.sample` gives for keeping the quantity out of the reading: those three
// values are constant for the life of a stream. Putting them in every frame
// would spend bandwidth restating what never changes, on producers that are
// already the bandwidth-heavy ones — and, more importantly, it would move the
// check to runtime. A consumer that de-interleaves three antennas from a stream
// that turns out to carry one does not fail; it reads plausible data from the
// wrong antenna. As facts, the composer refuses that binding at build time.
//
// `block_len` IS per-frame, even though the facts determine it. A driver's last
// frame before a reconfiguration, a replay's final short block, a FIFO drained
// early on a watermark — these are real and they are short. A consumer that
// trusted the computed length would read past the block into the next frame's
// header. The facts say what to expect; the header says what arrived, and
// `expected_block_len` below is how a consumer compares them.
//
// WHY NOT ONE `SensorSample` PER SAMPLE. A 3-antenna BGT60TR13C frame at the
// default configuration is thousands of samples. As 24-byte records that is two
// orders of magnitude more bytes than the packed block, and it would present a
// rules engine with samples it cannot act on individually — nothing fires on one
// 12-bit sample of an FMCW sweep. The block is the unit of meaning, so it is the
// unit of the record.
//
// TIME IS INTEGER MICROSECONDS, never float seconds. A float timestamp converts
// at every consumer and evaluates differently on different silicon; chronicle's
// deterministic VM has no float, and the RP2040 has no unit to convert one in. A module that must present seconds to a
// non-fluxor consumer — a browser, a recorded file format — converts at THAT
// boundary, where the cost is paid once and the wire compatibility is the point.
//
// FRAMED, not streamed: a consumer handed half a record would read the next
// frame's header bytes as sample data. The sequence number is also how a dropped
// acquisition is detected, and a torn frame would show up as a sequence gap AND
// corrupt samples, which are not distinguishable after the fact.

/// Header bytes before the block.
pub const HEADER_SIZE: usize = 16;

/// Byte offsets, so a producer and a consumer cannot disagree about layout.
pub const OFF_SEQ: usize = 0;
pub const OFF_BLOCK_LEN: usize = 4;
pub const OFF_T_MICROS: usize = 8;
pub const OFF_BLOCK: usize = 16;

/// One acquisition's header. The block is left as a borrowed slice of the
/// caller's buffer rather than copied: these records are the large ones on this
/// surface, and a contract that forced a copy would be a per-frame memcpy on the
/// producers least able to afford one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub seq: u32,
    pub t_micros: u64,
    pub block_len: u32,
}

/// Write a header into `out`, returning the bytes written, or `None` if `out`
/// cannot hold the header and the block it claims — never a partial frame,
/// because a truncated frame is indistinguishable from a whole one.
pub fn encode_header(out: &mut [u8], seq: u32, t_micros: u64, block_len: u32) -> Option<usize> {
    if out.len() < HEADER_SIZE + block_len as usize {
        return None;
    }
    encode_header_only(out, seq, t_micros, block_len)
}

/// Write just the 16 header bytes, for a producer that emits the header and the
/// block from SEPARATE buffers.
///
/// That is the shape a large block wants: a radar frame is tens of kilobytes
/// already sitting in a DMA or FIFO staging buffer, and copying it into a second
/// buffer so one call could frame it would double the driver's state — on the
/// producers least able to afford it — without changing a byte of what arrives.
/// `encode_header` is for the single-buffer case and checks the block fits;
/// this one cannot check that, because the block is not here.
pub fn encode_header_only(
    out: &mut [u8],
    seq: u32,
    t_micros: u64,
    block_len: u32,
) -> Option<usize> {
    if out.len() < HEADER_SIZE {
        return None;
    }
    out[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&seq.to_le_bytes());
    out[OFF_BLOCK_LEN..OFF_BLOCK_LEN + 4].copy_from_slice(&block_len.to_le_bytes());
    out[OFF_T_MICROS..OFF_T_MICROS + 8].copy_from_slice(&t_micros.to_le_bytes());
    Some(HEADER_SIZE)
}

/// Decode a header and borrow its block. `None` when the record is shorter than
/// the header, or shorter than the block the header claims — a frame that claims
/// more than it carries is refused whole rather than truncated, because reading
/// the short block would read the next frame's bytes as samples.
pub fn decode(b: &[u8]) -> Option<(Header, &[u8])> {
    if b.len() < HEADER_SIZE {
        return None;
    }
    let block_len = u32::from_le_bytes([
        b[OFF_BLOCK_LEN],
        b[OFF_BLOCK_LEN + 1],
        b[OFF_BLOCK_LEN + 2],
        b[OFF_BLOCK_LEN + 3],
    ]);
    let end = HEADER_SIZE.checked_add(block_len as usize)?;
    if b.len() < end {
        return None;
    }
    let h = Header {
        seq: u32::from_le_bytes([b[OFF_SEQ], b[OFF_SEQ + 1], b[OFF_SEQ + 2], b[OFF_SEQ + 3]]),
        t_micros: u64::from_le_bytes([
            b[OFF_T_MICROS],
            b[OFF_T_MICROS + 1],
            b[OFF_T_MICROS + 2],
            b[OFF_T_MICROS + 3],
            b[OFF_T_MICROS + 4],
            b[OFF_T_MICROS + 5],
            b[OFF_T_MICROS + 6],
            b[OFF_T_MICROS + 7],
        ]),
        block_len,
    };
    Some((h, &b[OFF_BLOCK..end]))
}

/// Bits per sample for each `encoding` fact value, or `None` for a name this
/// build does not know.
///
/// Bits rather than bytes because `u12le_packed2x3` is the encoding that matters
/// on the wire and it is not a whole number of bytes. Rounding it to 2 is how a
/// buffer ends up a third too large on exactly the producer that counts.
pub fn encoding_bits(encoding: &str) -> Option<u32> {
    Some(match encoding {
        "u12le_packed2x3" => 12,
        "u8" | "i8" => 8,
        "u16le" | "i16le" => 16,
        "u32le" | "i32le" | "f32le" => 32,
        "f64le" => 64,
        _ => return None,
    })
}

/// The block length the facts imply: `channels × samples_per_channel` samples
/// at `encoding`'s width, rounded UP to whole bytes.
///
/// Rounding up is the packed case: an odd sample count at 12 bits leaves half a
/// byte, and the producer sends the padding byte because it cannot send half of
/// one. A consumer computing the exact bit count and expecting that many bytes
/// would reject every odd-count frame.
///
/// This is what a consumer sizes its buffer from, and what it compares a frame's
/// `block_len` against. It is NOT a substitute for reading `block_len` — see the
/// short-frame cases in the module header.
pub fn expected_block_len(encoding: &str, channels: u32, samples_per_channel: u32) -> Option<u32> {
    let bits = encoding_bits(encoding)?;
    let samples = channels.checked_mul(samples_per_channel)?;
    let total_bits = samples.checked_mul(bits)?;
    Some(total_bits.div_ceil(8))
}

/// The whole record a producer must be able to emit for one acquisition: the
/// header plus the expected block. This is the number a manifest declares as the
/// port's `max_record` and as the `max_payload` fact, so the two agree by
/// derivation rather than by both being typed correctly.
pub fn expected_frame_len(encoding: &str, channels: u32, samples_per_channel: u32) -> Option<u32> {
    expected_block_len(encoding, channels, samples_per_channel)?.checked_add(HEADER_SIZE as u32)
}

// The offsets are a layout commitment, so their arithmetic is asserted rather
// than trusted: a field widened without moving the ones after it would encode
// over its neighbour and decode plausible garbage. Every adjacency is covered,
// in field order — a gap in this list is a pair of fields free to overlap.
const _: () = assert!(OFF_SEQ == 0);
const _: () = assert!(OFF_SEQ + 4 == OFF_BLOCK_LEN);
const _: () = assert!(OFF_BLOCK_LEN + 4 == OFF_T_MICROS);
const _: () = assert!(OFF_T_MICROS + 8 == OFF_BLOCK);
const _: () = assert!(OFF_BLOCK == HEADER_SIZE);

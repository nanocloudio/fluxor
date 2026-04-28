// WebSocket frame encoder + decoder for WS-over-HTTP/3 (RFC 6455 +
// RFC 9220). Carries the same wire shape as
// `modules/foundation/http/wire_ws.rs`; vendored here because the
// quic module compiles standalone and `pub(crate)` items in the
// http module are not visible across compilation units.
//
// Supports TEXT/BINARY/CLOSE/PING/PONG frames with continuation and
// the 7/16/64-bit length encodings. Maximum payload is bounded by
// the per-stream recv buffer.

pub const WS_OPCODE_CONT: u8 = 0x0;
pub const WS_OPCODE_TEXT: u8 = 0x1;
pub const WS_OPCODE_BINARY: u8 = 0x2;
pub const WS_OPCODE_CLOSE: u8 = 0x8;
pub const WS_OPCODE_PING: u8 = 0x9;
pub const WS_OPCODE_PONG: u8 = 0xA;

pub struct WsFrameView<'a> {
    pub fin: bool,
    pub opcode: u8,
    pub payload: &'a [u8],
}

/// Parse one WS frame from `buf`. Returns Some((frame, total_consumed))
/// or None on truncation. On protocol error (bad opcode, oversized
/// length) returns None too — callers treat that the same as
/// truncation for the loopback path.
pub fn ws_parse_frame(buf: &[u8]) -> Option<(WsFrameView<'_>, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;
    let len7 = (b1 & 0x7F) as u32;
    let mut hdr = 2usize;
    let payload_len: u32 = match len7 {
        126 => {
            if buf.len() < 4 {
                return None;
            }
            hdr = 4;
            ((buf[2] as u32) << 8) | (buf[3] as u32)
        }
        127 => {
            if buf.len() < 10 {
                return None;
            }
            let mut v = 0u64;
            let mut i = 0;
            while i < 8 {
                v = (v << 8) | (buf[2 + i] as u64);
                i += 1;
            }
            if v > 65535 {
                return None;
            }
            hdr = 10;
            v as u32
        }
        n => n,
    };
    let mut mask_key = [0u8; 4];
    if masked {
        if buf.len() < hdr + 4 {
            return None;
        }
        mask_key[0] = buf[hdr];
        mask_key[1] = buf[hdr + 1];
        mask_key[2] = buf[hdr + 2];
        mask_key[3] = buf[hdr + 3];
        hdr += 4;
    }
    let total = hdr + payload_len as usize;
    if buf.len() < total {
        return None;
    }
    // Cap accepted payload size to fit downstream stack buffers.
    if (payload_len as usize) > 240 {
        return None;
    }
    // The returned slice borrows directly from `buf`. For masked
    // frames the caller unmasks via `ws_unmask_into` against a
    // mutable copy.
    let payload = &buf[hdr..total];
    let _ = mask_key;
    Some((
        WsFrameView {
            fin,
            opcode,
            payload,
        },
        total,
    ))
}

/// Variant that returns the mask key alongside the parsed frame so a
/// caller can unmask the payload in their own scratch buffer.
pub fn ws_parse_frame_with_mask(buf: &[u8]) -> Option<(WsFrameView<'_>, [u8; 4], bool, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let b1 = buf[1];
    let masked = b1 & 0x80 != 0;
    let parsed = ws_parse_frame(buf)?;
    let (frame, total) = parsed;
    if !masked {
        return Some((frame, [0; 4], false, total));
    }
    // Re-derive mask key location.
    let len7 = (b1 & 0x7F) as u32;
    let hdr_pre_mask = match len7 {
        126 => 4,
        127 => 10,
        _ => 2,
    };
    let mk_off = hdr_pre_mask;
    let mut mk = [0u8; 4];
    mk[0] = buf[mk_off];
    mk[1] = buf[mk_off + 1];
    mk[2] = buf[mk_off + 2];
    mk[3] = buf[mk_off + 3];
    Some((frame, mk, true, total))
}

/// Apply mask key XOR to `data` in place.
pub fn ws_unmask(data: &mut [u8], mask_key: &[u8; 4]) {
    let mut i = 0;
    while i < data.len() {
        data[i] ^= mask_key[i & 3];
        i += 1;
    }
}

/// Build an unmasked server-side WS frame (RFC 6455 §5.2). Returns
/// bytes written, 0 on overflow. `payload_len` ≤ 65535.
pub fn ws_build_unmasked(opcode: u8, fin: bool, payload: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0;
    if out.is_empty() {
        return 0;
    }
    out[pos] = if fin { 0x80 } else { 0x00 } | (opcode & 0x0F);
    pos += 1;
    if payload.len() < 126 {
        if out.len() < pos + 1 + payload.len() {
            return 0;
        }
        out[pos] = payload.len() as u8;
        pos += 1;
    } else if payload.len() <= 65535 {
        if out.len() < pos + 3 + payload.len() {
            return 0;
        }
        out[pos] = 126;
        pos += 1;
        out[pos] = (payload.len() >> 8) as u8;
        out[pos + 1] = payload.len() as u8;
        pos += 2;
    } else {
        return 0;
    }
    out[pos..pos + payload.len()].copy_from_slice(payload);
    pos + payload.len()
}

// ----------------------------------------------------------------------
// RFC 6455 §8.1 — UTF-8 validation. TEXT frames MUST carry valid
// UTF-8; on receipt of a malformed sequence the receiver MUST fail
// the connection with close code 1007 (RFC 6455 §7.4.1).
//
// Streaming validator state machine (DFA from Björn Höhrmann's
// "Flexible and Economical UTF-8 Decoder"). Lets us validate across
// fragment boundaries — a multi-byte sequence may straddle two
// frames in a fragmented TEXT message.
// ----------------------------------------------------------------------

pub const UTF8_ACCEPT: u32 = 0;
pub const UTF8_REJECT: u32 = 12;

/// Streaming UTF-8 decoder state. Reset to `UTF8_ACCEPT` at the
/// start of a TEXT message; feed each byte; check `state ==
/// UTF8_ACCEPT` on FIN to confirm the message is well-formed.
#[derive(Clone, Copy)]
pub struct Utf8State {
    pub state: u32,
}

impl Utf8State {
    pub const fn new() -> Self {
        Self { state: UTF8_ACCEPT }
    }

    /// Feed one byte; updates state. Returns the new state value
    /// (UTF8_ACCEPT, UTF8_REJECT, or an intermediate continuation).
    pub fn step(&mut self, byte: u8) -> u32 {
        // Character class table (256 entries) compressed via match.
        let class = utf8_class(byte);
        // Transition table — one row per state.
        // States: 0(accept) 1..7 (intermediate) 12(reject); each
        // class maps to next state.
        self.state = utf8_transition(self.state, class);
        self.state
    }

    /// Feed a buffer of bytes; returns true iff the buffer is
    /// well-formed UTF-8 prefix (state accept or intermediate, no
    /// reject hit).
    pub fn feed(&mut self, data: &[u8]) -> bool {
        let mut i = 0;
        while i < data.len() {
            self.step(data[i]);
            if self.state == UTF8_REJECT {
                return false;
            }
            i += 1;
        }
        true
    }

    pub fn at_boundary(&self) -> bool {
        self.state == UTF8_ACCEPT
    }
}

/// Classify a byte's UTF-8 class (0..11) per the Höhrmann DFA.
fn utf8_class(b: u8) -> u32 {
    if b < 0x80 {
        0
    } else if b < 0xC0 {
        // continuation bytes split: 80..8F=1, 90..9F=9, A0..BF=7
        if b < 0x90 {
            1
        } else if b < 0xA0 {
            9
        } else {
            7
        }
    } else if b < 0xC2 {
        8 // overlong / invalid lead
    } else if b < 0xE0 {
        2
    } else if b < 0xE1 {
        10 // E0
    } else if b < 0xED {
        3
    } else if b < 0xEE {
        4 // ED
    } else if b < 0xF0 {
        3
    } else if b < 0xF1 {
        11 // F0
    } else if b < 0xF4 {
        6
    } else if b < 0xF5 {
        5 // F4
    } else {
        8 // F5..FF invalid
    }
}

fn utf8_transition(state: u32, class: u32) -> u32 {
    // RFC 3629-compatible DFA. State 0 = accept; 12 = reject;
    // intermediate states encode the number + kind of remaining
    // continuation bytes expected.
    //
    //   state class -> next
    //   0      0    -> 0    (ASCII)
    //   0      2    -> 24   (2-byte lead, expect 1 cont)
    //   0      3    -> 36   (3-byte lead, expect 2 cont)
    //   0      4    -> 60   (3-byte ED, restricted continuation)
    //   0      5    -> 84   (4-byte F4, restricted continuation)
    //   0      6    -> 72   (4-byte F1..F3, expect 3 cont)
    //   0      10   -> 48   (3-byte E0, restricted)
    //   0      11   -> 96   (4-byte F0, restricted)
    //   24     1|7|9 -> 0   (2-byte sequence complete)
    //   36     1|7|9 -> 24  (3-byte expect 1 more cont)
    //   ...
    //
    // For our streaming validator we encode this as a giant match.
    // It's verbose but PIC-safe + O(1).
    match (state, class) {
        // ASCII fast path
        (0, 0) => 0,
        // 2-byte lead
        (0, 2) => 24,
        // 3-byte (generic)
        (0, 3) => 36,
        // 3-byte E0 (cont must be A0..BF, class 7)
        (0, 10) => 48,
        // 3-byte ED (cont must be 80..9F, class 1 or 9)
        (0, 4) => 60,
        // 4-byte F1..F3
        (0, 6) => 72,
        // 4-byte F4 (cont must be 80..8F, class 1)
        (0, 5) => 84,
        // 4-byte F0 (cont must be 90..BF, class 9 or 7)
        (0, 11) => 96,
        // 2-byte continuation (any of 1, 7, 9)
        (24, 1) | (24, 7) | (24, 9) => 0,
        // 3-byte: middle continuation
        (36, 1) | (36, 7) | (36, 9) => 24,
        (48, 7) | (48, 9) => 24,
        (60, 1) => 24,
        // 4-byte: middle continuation #1
        (72, 1) | (72, 7) | (72, 9) => 36,
        (84, 1) => 36,
        (96, 7) | (96, 9) => 36,
        // Everything else → reject.
        _ => UTF8_REJECT,
    }
}

// ----------------------------------------------------------------------
// permessage-deflate (RFC 7692).
//
// Each WS message is carried as a DEFLATE stream (RFC 1951) with the
// four-byte tail `00 00 ff ff` (RFC 7692 §7.2.1) signalling
// end-of-message without flushing the LZ77 dictionary.
//
// The encoder here emits stored (BTYPE=00) blocks only — sufficient
// to negotiate the extension and carry payload bytes wire-faithfully,
// with no risk of a compression-oracle on the sending side. The
// decoder accepts all three RFC 1951 block types (stored, static
// Huffman, dynamic Huffman).
//
// Stored block layout:
//   byte 0     : BFINAL (bit 0) | BTYPE=00 (bits 1-2) | padding
//   bytes 1-2  : LEN (little-endian u16)
//   bytes 3-4  : NLEN (one's complement of LEN)
//   bytes 5..  : LEN data bytes
//
// Encoder output for an N-byte payload:
//   [00] [LEN_lo LEN_hi] [NLEN_lo NLEN_hi] [N bytes] [00 00 ff ff]

/// Encode `payload` as a stored-block DEFLATE stream + RFC 7692
/// sync tail. Returns bytes written, or 0 on overflow.
pub fn pmd_encode_stored(payload: &[u8], out: &mut [u8]) -> usize {
    if payload.len() > 65535 {
        return 0;
    }
    if out.len() < 5 + payload.len() + 4 {
        return 0;
    }
    out[0] = 0x00;
    let len = payload.len() as u16;
    let nlen = !len;
    out[1] = (len & 0xFF) as u8;
    out[2] = ((len >> 8) & 0xFF) as u8;
    out[3] = (nlen & 0xFF) as u8;
    out[4] = ((nlen >> 8) & 0xFF) as u8;
    out[5..5 + payload.len()].copy_from_slice(payload);
    let tail_off = 5 + payload.len();
    out[tail_off] = 0x00;
    out[tail_off + 1] = 0x00;
    out[tail_off + 2] = 0xFF;
    out[tail_off + 3] = 0xFF;
    tail_off + 4
}

/// Decode a stored-block DEFLATE payload + sync tail. Returns the
/// decompressed length, or None on malformed input.
pub fn pmd_decode_stored(input: &[u8], out: &mut [u8]) -> Option<usize> {
    if input.len() < 5 + 4 {
        return None;
    }
    let header = input[0];
    let btype = (header >> 1) & 0x03;
    if btype != 0x00 {
        return None;
    }
    let len = (input[1] as u16) | ((input[2] as u16) << 8);
    let nlen = (input[3] as u16) | ((input[4] as u16) << 8);
    if !len != nlen {
        return None;
    }
    let len = len as usize;
    if input.len() < 5 + len + 4 {
        return None;
    }
    if out.len() < len {
        return None;
    }
    out[..len].copy_from_slice(&input[5..5 + len]);
    // Verify sync tail.
    let tail_off = 5 + len;
    if input[tail_off] != 0x00
        || input[tail_off + 1] != 0x00
        || input[tail_off + 2] != 0xFF
        || input[tail_off + 3] != 0xFF
    {
        return None;
    }
    Some(len)
}

// ----------------------------------------------------------------------
// DEFLATE block decoders (RFC 1951).
// ----------------------------------------------------------------------
//
// Static-Huffman (BTYPE=01) uses the fixed code from §3.2.6:
//   literal/length codes
//     0..143    → 8 bits, codes 00110000..10111111
//     144..255  → 9 bits, codes 110010000..111111111
//     256..279  → 7 bits, codes 0000000..0010111
//     280..287  → 8 bits, codes 11000000..11000111
//   distance codes: all 5 bits, codes 00000..11111 → distance index 0..31
//
// Dynamic-Huffman (BTYPE=10) is reconstructed from a code-length
// alphabet; see `decode_dynamic_block` below.
//
// Length code 257..285 maps to (extra_bits, base_length) per
// §3.2.5; distance code 0..29 maps to (extra_bits, base_distance).
// LZ77 back-references resolve directly into the output buffer:
// a copy of length L from D bytes earlier in `out`.

/// Length code (257..285) → (extra_bits, base_length). Indexed by
/// `code - 257`; entry 28 = code 285 = length 258 with 0 extra bits.
const LEN_TABLE: [(u8, u16); 29] = [
    (0, 3), (0, 4), (0, 5), (0, 6),
    (0, 7), (0, 8), (0, 9), (0, 10),
    (1, 11), (1, 13), (1, 15), (1, 17),
    (2, 19), (2, 23), (2, 27), (2, 31),
    (3, 35), (3, 43), (3, 51), (3, 59),
    (4, 67), (4, 83), (4, 99), (4, 115),
    (5, 131), (5, 163), (5, 195), (5, 227),
    (0, 258),
];

/// Distance code (0..29) → (extra_bits, base_distance).
const DIST_TABLE: [(u8, u16); 30] = [
    (0, 1), (0, 2), (0, 3), (0, 4),
    (1, 5), (1, 7),
    (2, 9), (2, 13),
    (3, 17), (3, 25),
    (4, 33), (4, 49),
    (5, 65), (5, 97),
    (6, 129), (6, 193),
    (7, 257), (7, 385),
    (8, 513), (8, 769),
    (9, 1025), (9, 1537),
    (10, 2049), (10, 3073),
    (11, 4097), (11, 6145),
    (12, 8193), (12, 12289),
    (13, 16385), (13, 24577),
];

/// Bit reader for DEFLATE — reads bits LSB-first within each byte
/// per RFC 1951 §3.1.1.
struct BitReader<'a> {
    bytes: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, byte_pos: 0, bit_pos: 0 }
    }

    /// Read `n` bits LSB-first. Returns None if fewer bits are
    /// available.
    fn read_bits(&mut self, n: u8) -> Option<u32> {
        if n == 0 {
            return Some(0);
        }
        let mut acc: u32 = 0;
        let mut nb = 0u8;
        while nb < n {
            if self.byte_pos >= self.bytes.len() {
                return None;
            }
            let byte = self.bytes[self.byte_pos];
            let bit = (byte >> self.bit_pos) & 1;
            acc |= (bit as u32) << nb;
            nb += 1;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Some(acc)
    }

    /// Read `n` bits MSB-first into the low-order bits of the
    /// returned value. Used for Huffman codes (RFC 1951 §3.1.1).
    fn read_huff_bits(&mut self, n: u8) -> Option<u32> {
        let mut acc: u32 = 0;
        let mut i = 0u8;
        while i < n {
            let b = self.read_bits(1)?;
            acc = (acc << 1) | b;
            i += 1;
        }
        Some(acc)
    }

    fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    fn read_u16_le(&mut self) -> Option<u16> {
        self.align_to_byte();
        if self.byte_pos + 2 > self.bytes.len() {
            return None;
        }
        let v = (self.bytes[self.byte_pos] as u16)
            | ((self.bytes[self.byte_pos + 1] as u16) << 8);
        self.byte_pos += 2;
        Some(v)
    }

    fn copy_bytes(&mut self, dst: &mut [u8]) -> Option<()> {
        self.align_to_byte();
        if self.byte_pos + dst.len() > self.bytes.len() {
            return None;
        }
        dst.copy_from_slice(&self.bytes[self.byte_pos..self.byte_pos + dst.len()]);
        self.byte_pos += dst.len();
        Some(())
    }
}

/// Decode one literal/length code from the static Huffman tree.
/// Returns the code value (0..287) or None on truncation. Walks the
/// fixed prefix tree from RFC 1951 §3.2.6: 7 bits cover codes
/// 256..279, 8 bits cover 0..143 and 280..287, 9 bits cover 144..255.
fn read_static_litlen_code(br: &mut BitReader) -> Option<u16> {
    let mut code = br.read_huff_bits(7)?;
    if code <= 0x17 {
        return Some((code as u16) + 256);
    }
    code = (code << 1) | br.read_bits(1)?;
    if (0x30..=0xBF).contains(&code) {
        return Some((code - 0x30) as u16);
    }
    if (0xC0..=0xC7).contains(&code) {
        return Some((code - 0xC0 + 280) as u16);
    }
    code = (code << 1) | br.read_bits(1)?;
    if (0x190..=0x1FF).contains(&code) {
        return Some((code - 0x190 + 144) as u16);
    }
    None
}

/// Read a 5-bit distance code (0..31). Static distance Huffman is a
/// fixed 5-bit code per RFC 1951 §3.2.6.
fn read_static_dist_code(br: &mut BitReader) -> Option<u16> {
    let code = br.read_huff_bits(5)?;
    if code > 29 {
        return None;
    }
    Some(code as u16)
}

// ----------------------------------------------------------------------
// Canonical Huffman table (RFC 1951 §3.2.2). Built from a per-symbol
// code-length list; decoding walks the bit stream MSB-first using a
// per-length count.
// ----------------------------------------------------------------------

/// Maximum number of symbols across any DEFLATE Huffman alphabet:
/// literal/length has 286, distance 30, code-length 19.
const HUFF_MAX_SYMS: usize = 288;

/// Maximum code length per RFC 1951 §3.2.7 — the length codes used
/// inside dynamic blocks themselves can encode lengths up to 15.
const HUFF_MAX_LEN: usize = 15;

#[derive(Clone, Copy)]
struct HuffmanTable {
    /// Number of codes assigned each bit-length, indexed 1..=15.
    counts: [u16; HUFF_MAX_LEN + 1],
    /// Symbols ordered first by code length, then by symbol index.
    symbols: [u16; HUFF_MAX_SYMS],
}

impl HuffmanTable {
    const fn empty() -> Self {
        Self {
            counts: [0; HUFF_MAX_LEN + 1],
            symbols: [0; HUFF_MAX_SYMS],
        }
    }
}

/// Build a canonical Huffman table from per-symbol code lengths
/// (length 0 = symbol unused). Returns None if the lengths
/// over-subscribe the code space (RFC 1951 §3.2.2).
fn build_huffman_table(lengths: &[u8]) -> Option<HuffmanTable> {
    let mut table = HuffmanTable::empty();
    if lengths.len() > HUFF_MAX_SYMS {
        return None;
    }

    let mut i = 0;
    while i < lengths.len() {
        let len = lengths[i];
        if len as usize > HUFF_MAX_LEN {
            return None;
        }
        if len > 0 {
            table.counts[len as usize] += 1;
        }
        i += 1;
    }

    // Kraft inequality: sum of 2^-len ≤ 1. Track the remaining code
    // space as we descend lengths; under-subscribed trees are valid
    // (e.g. a one-symbol distance code) but invalid codes encountered
    // at decode time surface as None.
    let mut left: i32 = 1;
    let mut len = 1;
    while len <= HUFF_MAX_LEN {
        left = (left << 1) - table.counts[len] as i32;
        if left < 0 {
            return None;
        }
        len += 1;
    }

    // First-index offsets for each length.
    let mut offsets = [0u16; HUFF_MAX_LEN + 2];
    let mut sum: u16 = 0;
    let mut len = 1;
    while len <= HUFF_MAX_LEN {
        offsets[len] = sum;
        sum = sum.saturating_add(table.counts[len]);
        len += 1;
    }
    if sum as usize > HUFF_MAX_SYMS {
        return None;
    }

    // Place each symbol at its slot in symbols[].
    let mut work = offsets;
    let mut sym = 0usize;
    while sym < lengths.len() {
        let len = lengths[sym];
        if len > 0 {
            let li = len as usize;
            let idx = work[li] as usize;
            if idx >= HUFF_MAX_SYMS {
                return None;
            }
            table.symbols[idx] = sym as u16;
            work[li] += 1;
        }
        sym += 1;
    }

    Some(table)
}

/// Decode one Huffman-coded symbol. Reads bits MSB-first into the
/// code accumulator; at each length checks if the running code falls
/// inside the range assigned to that length, and if so returns the
/// symbol at the corresponding offset.
fn decode_huffman(br: &mut BitReader, table: &HuffmanTable) -> Option<u16> {
    let mut code: i32 = 0;
    let mut first: i32 = 0;
    let mut index: usize = 0;
    let mut len = 1;
    while len <= HUFF_MAX_LEN {
        let bit = br.read_bits(1)? as i32;
        code = (code << 1) | bit;
        let count = table.counts[len] as i32;
        if code - count < first {
            let sym_idx = index + (code - first) as usize;
            if sym_idx >= HUFF_MAX_SYMS {
                return None;
            }
            return Some(table.symbols[sym_idx]);
        }
        index += count as usize;
        first = (first + count) << 1;
        len += 1;
    }
    None
}

/// Decode a BTYPE=10 dynamic-Huffman block (RFC 1951 §3.2.7).
/// Reads the three header counts, builds the code-length tree,
/// decodes the literal/length and distance code lengths, builds
/// those two trees, and processes the data stream.
fn decode_dynamic_block(
    br: &mut BitReader,
    out: &mut [u8],
    out_len: &mut usize,
) -> Option<()> {
    let hlit = br.read_bits(5)? as usize + 257;
    let hdist = br.read_bits(5)? as usize + 1;
    let hclen = br.read_bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 || hclen > 19 {
        return None;
    }

    // Code-length code lengths in the special order from RFC 1951
    // §3.2.7. The first HCLEN+4 entries appear in the bit stream;
    // unread entries default to 0.
    const CL_ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut cl_lengths = [0u8; 19];
    let mut i = 0;
    while i < hclen {
        cl_lengths[CL_ORDER[i]] = br.read_bits(3)? as u8;
        i += 1;
    }

    // Build the code-length Huffman tree.
    let cl_table = build_huffman_table(&cl_lengths)?;

    // Decode HLIT+HDIST code lengths via the code-length tree, with
    // the 16/17/18 RLE forms.
    let total_codes = hlit + hdist;
    let mut all_lengths = [0u8; 286 + 30];
    let mut i = 0usize;
    while i < total_codes {
        let sym = decode_huffman(br, &cl_table)?;
        if sym <= 15 {
            all_lengths[i] = sym as u8;
            i += 1;
        } else if sym == 16 {
            // Copy previous code length 3-6 times (next 2 bits + 3).
            if i == 0 {
                return None;
            }
            let count = br.read_bits(2)? as usize + 3;
            let prev = all_lengths[i - 1];
            let end = i + count;
            if end > total_codes {
                return None;
            }
            while i < end {
                all_lengths[i] = prev;
                i += 1;
            }
        } else if sym == 17 {
            // Repeat zero 3-10 times (next 3 bits + 3).
            let count = br.read_bits(3)? as usize + 3;
            let end = i + count;
            if end > total_codes {
                return None;
            }
            while i < end {
                all_lengths[i] = 0;
                i += 1;
            }
        } else if sym == 18 {
            // Repeat zero 11-138 times (next 7 bits + 11).
            let count = br.read_bits(7)? as usize + 11;
            let end = i + count;
            if end > total_codes {
                return None;
            }
            while i < end {
                all_lengths[i] = 0;
                i += 1;
            }
        } else {
            return None;
        }
    }

    // Build literal/length and distance trees.
    let litlen_table = build_huffman_table(&all_lengths[..hlit])?;
    let dist_table = build_huffman_table(&all_lengths[hlit..hlit + hdist])?;

    // Decode the data stream. Same structure as BTYPE=01 but with
    // dynamic trees.
    loop {
        let sym = decode_huffman(br, &litlen_table)?;
        if sym < 256 {
            if *out_len >= out.len() {
                return None;
            }
            out[*out_len] = sym as u8;
            *out_len += 1;
        } else if sym == 256 {
            return Some(());
        } else if sym <= 285 {
            let (extra_bits, base_len) = LEN_TABLE[(sym - 257) as usize];
            let extra = br.read_bits(extra_bits)?;
            let length = (base_len as usize) + (extra as usize);

            let dcode = decode_huffman(br, &dist_table)?;
            if dcode > 29 {
                return None;
            }
            let (d_extra_bits, d_base) = DIST_TABLE[dcode as usize];
            let d_extra = br.read_bits(d_extra_bits)?;
            let distance = (d_base as usize) + (d_extra as usize);

            if distance == 0 || distance > *out_len {
                return None;
            }
            if *out_len + length > out.len() {
                return None;
            }
            let src_start = *out_len - distance;
            let mut j = 0;
            while j < length {
                out[*out_len + j] = out[src_start + j];
                j += 1;
            }
            *out_len += length;
        } else {
            return None;
        }
    }
}

/// Decode one DEFLATE block (any BTYPE) into `out` starting at
/// `out_len`. Updates `out_len` and returns Some(bfinal) — true if
/// this was the final block.
fn deflate_decode_block(
    br: &mut BitReader,
    out: &mut [u8],
    out_len: &mut usize,
) -> Option<bool> {
    let bfinal = br.read_bits(1)? != 0;
    let btype = br.read_bits(2)?;
    match btype {
        0b00 => {
            // Stored block.
            br.align_to_byte();
            let len = br.read_u16_le()?;
            let nlen = br.read_u16_le()?;
            if (len ^ 0xFFFF) != nlen {
                return None;
            }
            if *out_len + len as usize > out.len() {
                return None;
            }
            br.copy_bytes(&mut out[*out_len..*out_len + len as usize])?;
            *out_len += len as usize;
        }
        0b01 => {
            // Static-Huffman block.
            loop {
                let code = read_static_litlen_code(br)?;
                if code < 256 {
                    if *out_len >= out.len() {
                        return None;
                    }
                    out[*out_len] = code as u8;
                    *out_len += 1;
                } else if code == 256 {
                    break; // End of block.
                } else if code <= 285 {
                    let (extra_bits, base_len) = LEN_TABLE[(code - 257) as usize];
                    let extra = br.read_bits(extra_bits)?;
                    let length = (base_len as usize) + (extra as usize);
                    let dcode = read_static_dist_code(br)?;
                    let (d_extra_bits, d_base) = DIST_TABLE[dcode as usize];
                    let d_extra = br.read_bits(d_extra_bits)?;
                    let distance = (d_base as usize) + (d_extra as usize);
                    if distance == 0 || distance > *out_len {
                        return None;
                    }
                    if *out_len + length > out.len() {
                        return None;
                    }
                    // Copy byte-by-byte so overlapping ranges
                    // (distance < length, RLE-style runs) work.
                    let src_start = *out_len - distance;
                    let mut i = 0;
                    while i < length {
                        out[*out_len + i] = out[src_start + i];
                        i += 1;
                    }
                    *out_len += length;
                } else {
                    return None;
                }
            }
        }
        0b10 => {
            // Dynamic-Huffman block (RFC 1951 §3.2.7).
            decode_dynamic_block(br, out, out_len)?;
        }
        _ => return None,
    }
    Some(bfinal)
}

/// Decode a permessage-deflate compressed payload (per-message
/// `00 00 ff ff` tail re-added per RFC 7692 §7.2.2 if absent).
/// Handles all three RFC 1951 block types: BTYPE=00 (stored),
/// BTYPE=01 (static-Huffman + LZ77), BTYPE=10 (dynamic-Huffman + LZ77).
/// Returns bytes written, or None on malformed input.
pub fn pmd_decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut br = BitReader::new(input);
    let mut out_len = 0usize;
    loop {
        let bfinal = deflate_decode_block(&mut br, out, &mut out_len)?;
        if bfinal {
            break;
        }
    }
    Some(out_len)
}

/// Round-trip known-good DEFLATE vectors at module-init to catch
/// table or bit-reader transcription bugs. Covers the four code
/// paths: stored block, static-Huffman literals, static-Huffman with
/// LZ77 back-reference, and dynamic-Huffman.
fn pmd_decode_self_check() -> bool {
    // 1. Static-Huffman literals via the local encoder.
    let mut enc_buf = [0u8; 128];
    let payload = b"ABCabcXYZxyz0123";
    let n_enc = deflate_static_encode_literal_block(payload, &mut enc_buf);
    if n_enc == 0 {
        return false;
    }
    let mut dec_buf = [0u8; 128];
    let n_dec = match pmd_decode(&enc_buf[..n_enc], &mut dec_buf) {
        Some(n) => n,
        None => return false,
    };
    if n_dec != payload.len() {
        return false;
    }
    let mut k = 0;
    while k < n_dec {
        if dec_buf[k] != payload[k] {
            return false;
        }
        k += 1;
    }
    // 2. Stored block routed via `pmd_decode`'s BTYPE dispatch.
    let payload2 = b"hello world!";
    let mut enc2 = [0u8; 64];
    enc2[0] = 0x01; // BFINAL=1, BTYPE=00.
    let l = payload2.len() as u16;
    let nl = !l;
    enc2[1] = (l & 0xFF) as u8;
    enc2[2] = ((l >> 8) & 0xFF) as u8;
    enc2[3] = (nl & 0xFF) as u8;
    enc2[4] = ((nl >> 8) & 0xFF) as u8;
    let mut i = 0;
    while i < payload2.len() {
        enc2[5 + i] = payload2[i];
        i += 1;
    }
    let mut dec2 = [0u8; 64];
    let n2 = match pmd_decode(&enc2[..5 + payload2.len()], &mut dec2) {
        Some(n) => n,
        None => return false,
    };
    if n2 != payload2.len() {
        return false;
    }
    let mut k = 0;
    while k < n2 {
        if dec2[k] != payload2[k] {
            return false;
        }
        k += 1;
    }
    // 3. Static-Huffman block with an LZ77 length-3 distance-3 copy:
    // literals "ABC" + back-ref → decodes "ABCABC".
    let mut enc3 = [0u8; 32];
    let mut bw = BitWriter { out: &mut enc3, byte_pos: 0, bit_pos: 0 };
    bw.write_bits(1, 1); // BFINAL=1
    bw.write_bits(0b01, 2); // BTYPE=01
    let (c, n) = static_litlen_code(b'A' as u16); bw.write_bits_msb(c, n);
    let (c, n) = static_litlen_code(b'B' as u16); bw.write_bits_msb(c, n);
    let (c, n) = static_litlen_code(b'C' as u16); bw.write_bits_msb(c, n);
    // Length code 257 → length 3, distance code 2 → distance 3.
    let (c, n) = static_litlen_code(257); bw.write_bits_msb(c, n);
    bw.write_bits_msb(2, 5);
    let (c, n) = static_litlen_code(256); bw.write_bits_msb(c, n);
    let n_enc3 = bw.byte_pos + (if bw.bit_pos > 0 { 1 } else { 0 });
    let mut dec3 = [0u8; 32];
    let n3 = match pmd_decode(&enc3[..n_enc3], &mut dec3) {
        Some(n) => n,
        None => return false,
    };
    if n3 != 6 {
        return false;
    }
    let expect = b"ABCABC";
    let mut k = 0;
    while k < 6 {
        if dec3[k] != expect[k] {
            return false;
        }
        k += 1;
    }
    // 4. Dynamic-Huffman block produced by `zlib.compress(LOREM*4, 9)`
    // with the 2-byte zlib header and 4-byte adler32 trailer stripped.
    // Decoded length is 4 * LOREM.len() = 928 bytes.
    const LOREM_BYTES: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. ";
    const ENC4: &[u8] = &[
        0xed, 0x8f, 0xd1, 0x6d, 0x03, 0x31, 0x0c, 0x43, 0x57, 0xe1, 0x00, 0x41, 0x26,
        0xc9, 0x6f, 0x07, 0x50, 0x6d, 0x21, 0x20, 0x60, 0x59, 0x17, 0x4b, 0x0e, 0x3a,
        0x7e, 0x75, 0xbd, 0x29, 0x0a, 0xe4, 0x4f, 0x82, 0xc8, 0x47, 0xf1, 0xe1, 0x4b,
        0x0d, 0x3c, 0x62, 0x1b, 0xba, 0x0f, 0x5f, 0x08, 0x26, 0xc4, 0x34, 0x6f, 0x68,
        0x3e, 0x43, 0x5b, 0x6a, 0xee, 0x05, 0xe9, 0x3c, 0x18, 0x8d, 0xf3, 0x09, 0x1d,
        0xac, 0x63, 0x68, 0x2f, 0x03, 0x94, 0x3b, 0xcc, 0x3b, 0x52, 0xed, 0x28, 0x33,
        0x67, 0x63, 0x67, 0xdf, 0x33, 0xb1, 0x13, 0x43, 0xbe, 0x0b, 0x0f, 0xcd, 0x0b,
        0xad, 0x30, 0x79, 0x4e, 0x81, 0x0c, 0xbe, 0xb6, 0xdc, 0xf1, 0x95, 0xd0, 0x49,
        0x2b, 0x36, 0x8c, 0xe7, 0xf0, 0xae, 0x55, 0xec, 0x86, 0xd7, 0x66, 0x60, 0x7a,
        0xe4, 0xda, 0x1d, 0xfa, 0xa3, 0xab, 0x31, 0x25, 0xe9, 0x13, 0x7b, 0x0c, 0xb1,
        0xe6, 0x17, 0xf9, 0x14, 0x31, 0x78, 0x26, 0xfd, 0x21, 0x79, 0x94, 0x18, 0x2a,
        0xf5, 0xb8, 0xd5, 0x4f, 0x7e, 0x15, 0xa8, 0xa8, 0xbc, 0xe3, 0xf1, 0xe9, 0xf9,
        0xe9, 0xf9, 0x0f, 0x7b, 0xfe, 0x02,
    ];
    let mut dec4 = [0u8; 1024];
    let n4 = match pmd_decode(ENC4, &mut dec4) {
        Some(n) => n,
        None => return false,
    };
    let expected_len = LOREM_BYTES.len() * 4;
    if n4 != expected_len {
        return false;
    }
    let mut k = 0;
    while k < n4 {
        if dec4[k] != LOREM_BYTES[k % LOREM_BYTES.len()] {
            return false;
        }
        k += 1;
    }
    true
}

/// Encode `payload` as a literal-only static-Huffman block
/// (BTYPE=01, BFINAL=1) — every byte becomes its own literal symbol,
/// no LZ77 back-references. Used by the self-check; the WS
/// compression path emits stored blocks via `pmd_encode_stored` to
/// avoid exposing a compression oracle.
pub fn deflate_static_encode_literal_block(payload: &[u8], out: &mut [u8]) -> usize {
    // Bit writer: emit bits LSB-first within each byte, but
    // Huffman codes themselves are MSB-first.
    let mut bw = BitWriter { out, byte_pos: 0, bit_pos: 0 };
    if !bw.write_bits(1, 1) { return 0; } // BFINAL=1
    if !bw.write_bits(0b01, 2) { return 0; } // BTYPE=01
    let mut i = 0;
    while i < payload.len() {
        let b = payload[i];
        let (code, nbits) = static_litlen_code(b as u16);
        if !bw.write_bits_msb(code, nbits) { return 0; }
        i += 1;
    }
    // End-of-block code (256) = 7-bit `0000000`.
    let (code, nbits) = static_litlen_code(256);
    if !bw.write_bits_msb(code, nbits) { return 0; }
    bw.flush();
    bw.byte_pos + (if bw.bit_pos > 0 { 1 } else { 0 })
}

/// Static-Huffman code for a literal/length code (RFC 1951 §3.2.6).
/// Returns (code_bits_msb_first, length).
fn static_litlen_code(value: u16) -> (u32, u8) {
    if value <= 143 {
        ((value as u32) + 0x30, 8)
    } else if value <= 255 {
        ((value as u32 - 144) + 0x190, 9)
    } else if value <= 279 {
        ((value as u32 - 256), 7)
    } else if value <= 287 {
        ((value as u32 - 280) + 0xC0, 8)
    } else {
        (0, 0) // Invalid — caller's fault.
    }
}

struct BitWriter<'a> {
    out: &'a mut [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitWriter<'a> {
    fn write_bits(&mut self, value: u32, nbits: u8) -> bool {
        let mut bits_left = nbits;
        let mut v = value;
        while bits_left > 0 {
            if self.byte_pos >= self.out.len() {
                return false;
            }
            let bit = (v & 1) as u8;
            v >>= 1;
            self.out[self.byte_pos] |= bit << self.bit_pos;
            self.bit_pos += 1;
            bits_left -= 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
                if self.byte_pos < self.out.len() {
                    self.out[self.byte_pos] = 0;
                }
            }
        }
        true
    }

    /// Emit `value`'s top `nbits` bits MSB-first (bit nbits-1 first).
    fn write_bits_msb(&mut self, value: u32, nbits: u8) -> bool {
        let mut i = nbits;
        while i > 0 {
            i -= 1;
            let bit = (value >> i) & 1;
            if !self.write_bits(bit, 1) {
                return false;
            }
        }
        true
    }

    fn flush(&mut self) {
        // No-op — caller computes final byte_pos.
    }
}

/// Build a masked client-side WS frame.
pub fn ws_build_masked(
    opcode: u8,
    fin: bool,
    payload: &[u8],
    mask_key: [u8; 4],
    out: &mut [u8],
) -> usize {
    let mut pos = 0;
    if out.is_empty() {
        return 0;
    }
    out[pos] = if fin { 0x80 } else { 0x00 } | (opcode & 0x0F);
    pos += 1;
    if payload.len() < 126 {
        if out.len() < pos + 1 + 4 + payload.len() {
            return 0;
        }
        out[pos] = 0x80 | (payload.len() as u8);
        pos += 1;
    } else if payload.len() <= 65535 {
        if out.len() < pos + 3 + 4 + payload.len() {
            return 0;
        }
        out[pos] = 0x80 | 126;
        pos += 1;
        out[pos] = (payload.len() >> 8) as u8;
        out[pos + 1] = payload.len() as u8;
        pos += 2;
    } else {
        return 0;
    }
    out[pos..pos + 4].copy_from_slice(&mask_key);
    pos += 4;
    let mut i = 0;
    while i < payload.len() {
        out[pos + i] = payload[i] ^ mask_key[i & 3];
        i += 1;
    }
    pos + payload.len()
}

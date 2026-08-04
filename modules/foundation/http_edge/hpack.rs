//! HPACK header compression — RFC 7541.
//!
//! This implementation supports the static table (61 entries), integer
//! and literal string primitives, and the four representation forms
//! (indexed, literal-with-incremental-indexing, literal-without-
//! indexing, literal-never-indexing), plus Huffman string decoding
//! (RFC 7541 Appendix B, `huffman_decode`) — real peers (e.g. gRPC
//! servers) Huffman-encode header/trailer names and values. The
//! encoder always emits literal-without-indexing form (§6.2.2, no
//! Huffman): no dynamic-table state to manage on the send side.
//!
//! Dynamic-table-on-decode is also not implemented; we advertise
//! `SETTINGS_HEADER_TABLE_SIZE = 0` so the peer must not attempt
//! incremental indexing. Some clients still send the indexing form
//! (the wire encoding works regardless of dynamic table size); we
//! treat those bytes as literal-without-indexing equivalents from a
//! semantic standpoint, ignoring the indexing instruction.

// ── Static table (RFC 7541 Appendix A) ────────────────────────────────────
//
// The 61-entry static table is *not* stored as a Rust constant array
// of tuples. PIC modules in this codebase don't carry runtime
// relocations, so a `const &[(&[u8], &[u8])]` would freeze each entry's
// pointer fields at compile-time link addresses that no longer hold
// after the module is loaded. Computing the slice references from byte
// literals at call time keeps every pointer PC-relative and correct
// regardless of load address.

/// Lookup a static-table entry by 1-based index. RFC 7541 Appendix A.
fn static_lookup(idx: u32) -> Option<(&'static [u8], &'static [u8])> {
    Some(match idx {
        1 => (b":authority", b""),
        2 => (b":method", b"GET"),
        3 => (b":method", b"POST"),
        4 => (b":path", b"/"),
        5 => (b":path", b"/index.html"),
        6 => (b":scheme", b"http"),
        7 => (b":scheme", b"https"),
        8 => (b":status", b"200"),
        9 => (b":status", b"204"),
        10 => (b":status", b"206"),
        11 => (b":status", b"304"),
        12 => (b":status", b"400"),
        13 => (b":status", b"404"),
        14 => (b":status", b"500"),
        15 => (b"accept-charset", b""),
        16 => (b"accept-encoding", b"gzip, deflate"),
        17 => (b"accept-language", b""),
        18 => (b"accept-ranges", b""),
        19 => (b"accept", b""),
        20 => (b"access-control-allow-origin", b""),
        21 => (b"age", b""),
        22 => (b"allow", b""),
        23 => (b"authorization", b""),
        24 => (b"cache-control", b""),
        25 => (b"content-disposition", b""),
        26 => (b"content-encoding", b""),
        27 => (b"content-language", b""),
        28 => (b"content-length", b""),
        29 => (b"content-location", b""),
        30 => (b"content-range", b""),
        31 => (b"content-type", b""),
        32 => (b"cookie", b""),
        33 => (b"date", b""),
        34 => (b"etag", b""),
        35 => (b"expect", b""),
        36 => (b"expires", b""),
        37 => (b"from", b""),
        38 => (b"host", b""),
        39 => (b"if-match", b""),
        40 => (b"if-modified-since", b""),
        41 => (b"if-none-match", b""),
        42 => (b"if-range", b""),
        43 => (b"if-unmodified-since", b""),
        44 => (b"last-modified", b""),
        45 => (b"link", b""),
        46 => (b"location", b""),
        47 => (b"max-forwards", b""),
        48 => (b"proxy-authenticate", b""),
        49 => (b"proxy-authorization", b""),
        50 => (b"range", b""),
        51 => (b"referer", b""),
        52 => (b"refresh", b""),
        53 => (b"retry-after", b""),
        54 => (b"server", b""),
        55 => (b"set-cookie", b""),
        56 => (b"strict-transport-security", b""),
        57 => (b"transfer-encoding", b""),
        58 => (b"user-agent", b""),
        59 => (b"vary", b""),
        60 => (b"via", b""),
        61 => (b"www-authenticate", b""),
        _ => return None,
    })
}

// ── Integer codec (§5.1) ──────────────────────────────────────────────────

/// Decode an HPACK integer with `prefix_bits` significant bits in the
/// first byte. Returns `(value, bytes_consumed)` or `Err(())` if
/// truncated or overflow.
pub(crate) unsafe fn decode_integer(
    buf: *const u8,
    len: usize,
    prefix_bits: u8,
) -> Result<(u32, usize), ()> {
    if len == 0 {
        return Err(());
    }
    let max_prefix: u32 = (1u32 << prefix_bits) - 1;
    let first = (*buf as u32) & max_prefix;
    if first < max_prefix {
        return Ok((first, 1));
    }
    // Multi-byte form: continue reading while the high bit is set,
    // accumulating 7 bits per byte (§5.1).
    let mut value: u32 = max_prefix;
    let mut shift: u32 = 0;
    let mut i: usize = 1;
    loop {
        if i >= len {
            return Err(());
        }
        let b = *buf.add(i);
        i += 1;
        let chunk = (b as u32) & 0x7F;
        if shift >= 32 {
            return Err(()); // overflow guard
        }
        let add = chunk.checked_shl(shift).ok_or(())?;
        value = value.checked_add(add).ok_or(())?;
        shift += 7;
        if (b & 0x80) == 0 {
            return Ok((value, i));
        }
        if i > 5 {
            // 5 bytes of continuation = 35 bits, more than enough for u32.
            return Err(());
        }
    }
}

/// Encode an HPACK integer with `prefix_bits` significant bits. The
/// `prefix` byte's high `8-prefix_bits` bits carry the representation
/// type and must already be set by the caller; this function ORs the
/// integer prefix in and writes any continuation bytes.
pub(crate) unsafe fn encode_integer(
    dst: *mut u8,
    dst_cap: usize,
    prefix: u8,
    prefix_bits: u8,
    value: u32,
) -> usize {
    if dst_cap == 0 {
        return 0;
    }
    let max_prefix: u32 = (1u32 << prefix_bits) - 1;
    if value < max_prefix {
        *dst = prefix | (value as u8);
        return 1;
    }
    *dst = prefix | (max_prefix as u8);
    let mut o = 1usize;
    let mut rem = value - max_prefix;
    while rem >= 128 {
        if o >= dst_cap {
            return 0;
        }
        *dst.add(o) = ((rem & 0x7F) as u8) | 0x80;
        o += 1;
        rem >>= 7;
    }
    if o >= dst_cap {
        return 0;
    }
    *dst.add(o) = rem as u8;
    o + 1
}

// ── String codec (§5.2) ───────────────────────────────────────────────────

/// Decode an HPACK string literal. Returns `(value_offset,
/// value_length, bytes_consumed_including_length_prefix, huffman)` or
/// `Err(())` if truncated or malformed.
///
/// The payload is not Huffman-decoded here — when the returned flag is
/// set the caller runs `huffman_decode` over the raw bytes.
pub(crate) unsafe fn decode_string(
    buf: *const u8,
    len: usize,
) -> Result<(usize, usize, usize, bool), ()> {
    if len == 0 {
        return Err(());
    }
    let h_flag = (*buf & 0x80) != 0;
    let (slen, hdr) = decode_integer(buf, len, 7)?;
    let total = hdr + slen as usize;
    if total > len {
        return Err(());
    }
    Ok((hdr, slen as usize, total, h_flag))
}

/// Encode an HPACK string literal (no Huffman). Writes the 7-bit
/// length prefix (with H=0) followed by the raw bytes. Returns total
/// bytes written, or 0 if `dst_cap` is insufficient.
pub(crate) unsafe fn encode_string(
    dst: *mut u8,
    dst_cap: usize,
    s: *const u8,
    s_len: usize,
) -> usize {
    let n = encode_integer(dst, dst_cap, 0x00, 7, s_len as u32);
    if n == 0 {
        return 0;
    }
    if n + s_len > dst_cap {
        return 0;
    }
    if s_len > 0 {
        core::ptr::copy_nonoverlapping(s, dst.add(n), s_len);
    }
    n + s_len
}

// ── Header decoding ──────────────────────────────────────────────────────

/// Decode an HPACK header block fragment. The `sink` closure is called
/// once per decoded header with `(name, value)` byte slices. Generic
/// over the closure type so we never construct a `&mut dyn FnMut` —
/// PIC modules can't reliably relocate the vtable that a trait-object
/// closure call would dispatch through.
///
/// Returns `Err(())` on any malformed input; callers respond with a
/// connection-level COMPRESSION_ERROR GOAWAY. We don't maintain a
/// dynamic table — `SETTINGS_HEADER_TABLE_SIZE = 0` is advertised at
/// connection setup. Dynamic-table-size-update directives (§6.3) are
/// still parsed and discarded so non-conforming peers see a clean
/// accept.
pub(crate) unsafe fn decode_block<F>(buf: *const u8, len: usize, mut sink: F) -> Result<(), ()>
where
    F: FnMut(&[u8], &[u8]),
{
    let mut i = 0usize;
    while i < len {
        let b = *buf.add(i);
        if (b & 0x80) != 0 {
            // §6.1 Indexed Header Field
            let (idx, n) = decode_integer(buf.add(i), len - i, 7)?;
            i += n;
            let (name, value) = static_lookup(idx).ok_or(())?;
            sink(name, value);
        } else if (b & 0xC0) == 0x40 {
            // §6.2.1 Literal Header Field with Incremental Indexing
            i += decode_literal(buf, len, i, 6, &mut sink)?;
        } else if (b & 0xE0) == 0x20 {
            // §6.3 Dynamic Table Size Update — parse and discard
            let (_sz, n) = decode_integer(buf.add(i), len - i, 5)?;
            i += n;
        } else if (b & 0xF0) == 0x10 {
            // §6.2.3 Literal Header Field Never Indexed
            i += decode_literal(buf, len, i, 4, &mut sink)?;
        } else {
            // §6.2.2 Literal Header Field without Indexing
            i += decode_literal(buf, len, i, 4, &mut sink)?;
        }
    }
    Ok(())
}

/// Decode a literal-form header (§6.2.x). `prefix_bits` is the integer
/// prefix used to encode the indexed name (6 for incremental, 4 for
/// never/without). Returns the total number of bytes consumed.
// ── Huffman (RFC 7541 Appendix B) ──────────────────────────────────────────
//
// `(code, bit-length)` per symbol 0..=255; index 256 is the EOS marker. Used
// to decode Huffman-coded header strings on the response path (real gRPC
// servers Huffman-encode trailer names/values such as `grpc-status`). The
// encoder only emits literal-without-indexing (see module header).
// The table is guarded by `huffman_table_valid` (Kraft equality + prefix-free)
// so a transcription slip can't ship silently.
#[rustfmt::skip]
static HUFF: [(u32, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// Longest header name/value we Huffman-decode into a scratch buffer; longer
/// entries are dropped (like any header the callsite doesn't consume).
pub(crate) const HUFF_SCRATCH: usize = 256;

/// Decode an HPACK Huffman string `src` into `out`, returning the number of
/// bytes written. `None` on: overflow of `out`, an EOS symbol in the stream,
/// an over-long (>30-bit) dangling code, or invalid (non-all-ones) padding.
/// Greedy bit-walk: prefix-free codes mean the first length at which the
/// accumulated bits match a code is the unique symbol.
pub fn huffman_decode(src: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut cur: u32 = 0;
    let mut nbits: u8 = 0;
    let mut o = 0usize;
    for &byte in src {
        let mut b = 8;
        while b > 0 {
            b -= 1;
            cur = (cur << 1) | ((byte >> b) & 1) as u32;
            nbits += 1;
            if nbits > 30 {
                return None;
            }
            let mut sym = 0usize;
            while sym < HUFF.len() {
                if HUFF[sym].1 == nbits && HUFF[sym].0 == cur {
                    if sym == 256 {
                        return None; // EOS must never appear in the encoding
                    }
                    if o >= out.len() {
                        return None;
                    }
                    out[o] = sym as u8;
                    o += 1;
                    cur = 0;
                    nbits = 0;
                    break;
                }
                sym += 1;
            }
        }
    }
    // Any leftover bits must be a strict prefix (<8 bits) of EOS (all ones).
    if nbits >= 8 {
        return None;
    }
    if nbits > 0 && cur != (1u32 << nbits) - 1 {
        return None;
    }
    Some(o)
}

/// Self-check for the Huffman table: Kraft equality (a complete prefix code
/// satisfies Σ 2^-len == 1) and prefix-freedom (no code is a prefix of
/// another). Exercised by a host test so a bad transcription fails the build,
/// not a live decode.
pub fn huffman_table_valid() -> bool {
    // Kraft: Σ 2^(30-len) must equal 2^30 across all 257 codes.
    let mut kraft: u64 = 0;
    for &(_, len) in HUFF.iter() {
        if len == 0 || len > 30 {
            return false;
        }
        kraft += 1u64 << (30 - len as u32);
    }
    if kraft != (1u64 << 30) {
        return false;
    }
    // Prefix-free: left-align each code to 32 bits; sorted, each aligned code
    // must advance past the previous code's whole span (no shared prefix).
    let mut aligned: [(u32, u8); 257] = [(0, 0); 257];
    for (i, &(code, len)) in HUFF.iter().enumerate() {
        aligned[i] = (code << (32 - len as u32), len);
    }
    aligned.sort_unstable();
    let mut i = 1;
    while i < aligned.len() {
        let (pcode, plen) = aligned[i - 1];
        let (ccode, _) = aligned[i];
        // Next code must not start within the previous code's prefix span.
        if ccode < pcode + (1u32 << (32 - plen as u32)) {
            return false;
        }
        i += 1;
    }
    true
}

unsafe fn decode_literal<F>(
    buf: *const u8,
    len: usize,
    start: usize,
    prefix_bits: u8,
    sink: &mut F,
) -> Result<usize, ()>
where
    F: FnMut(&[u8], &[u8]),
{
    let (name_idx, n) = decode_integer(buf.add(start), len - start, prefix_bits)?;
    let mut consumed = n;

    let mut name_huffman = false;
    let (name_buf, name_off, name_len): (*const u8, usize, usize) = if name_idx == 0 {
        let (off, sl, total, h) = decode_string(buf.add(start + consumed), len - start - consumed)?;
        let raw = buf.add(start + consumed);
        consumed += total;
        name_huffman = h;
        (raw, off, sl)
    } else {
        let (nm, _v) = static_lookup(name_idx).ok_or(())?;
        (nm.as_ptr(), 0, nm.len())
    };

    let (val_off, val_len, val_total, val_huffman) =
        decode_string(buf.add(start + consumed), len - start - consumed)?;
    let val_raw = buf.add(start + consumed);
    consumed += val_total;

    // Huffman-decode name and/or value into stack scratch when flagged.
    // A decode failure or an entry longer than the scratch is dropped
    // (callsites ignore headers they don't consume), never surfaced as
    // raw Huffman bytes.
    let mut name_scratch = [0u8; HUFF_SCRATCH];
    let mut val_scratch = [0u8; HUFF_SCRATCH];

    let name_slice: &[u8] = if name_huffman {
        let raw = core::slice::from_raw_parts(name_buf.add(name_off), name_len);
        match huffman_decode(raw, &mut name_scratch) {
            Some(n) => &name_scratch[..n],
            None => return Ok(consumed),
        }
    } else {
        core::slice::from_raw_parts(name_buf.add(name_off), name_len)
    };

    let value_slice: &[u8] = if val_huffman {
        let raw = core::slice::from_raw_parts(val_raw.add(val_off), val_len);
        match huffman_decode(raw, &mut val_scratch) {
            Some(n) => &val_scratch[..n],
            None => return Ok(consumed),
        }
    } else {
        core::slice::from_raw_parts(val_raw.add(val_off), val_len)
    };
    sink(name_slice, value_slice);
    Ok(consumed)
}

// ── Header encoding ──────────────────────────────────────────────────────

/// Encode one header as literal-without-indexing (§6.2.2). If `name`
/// matches a static-table entry, its index is used; otherwise the name
/// is emitted as a literal string. The value is always literal.
///
/// Returns the number of bytes written, or 0 on insufficient capacity.
pub(crate) unsafe fn encode_header(
    dst: *mut u8,
    dst_cap: usize,
    name: &[u8],
    value: &[u8],
) -> usize {
    let idx = static_name_index(name);
    let o = if idx > 0 {
        let n = encode_integer(dst, dst_cap, 0x00, 4, idx);
        if n == 0 {
            return 0;
        }
        n
    } else {
        if dst_cap < 1 {
            return 0;
        }
        *dst = 0x00;
        let n = encode_string(dst.add(1), dst_cap - 1, name.as_ptr(), name.len());
        if n == 0 {
            return 0;
        }
        1 + n
    };
    let n = encode_string(dst.add(o), dst_cap - o, value.as_ptr(), value.len());
    if n == 0 {
        return 0;
    }
    o + n
}

/// Look up a name's static-table index. Driven off `static_lookup`
/// rather than a parallel const table so all byte literals are
/// PC-relative.
fn static_name_index(name: &[u8]) -> u32 {
    let mut i: u32 = 1;
    while i <= 61 {
        if let Some((nm, _)) = static_lookup(i) {
            if names_eq(nm, name) {
                return i;
            }
        }
        i += 1;
    }
    0
}

/// Byte-by-byte slice equality without `memcmp`. Used by
/// `static_name_index` so we don't pull in an external symbol the PIC
/// loader can't satisfy.
fn names_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len();
    if n != b.len() {
        return false;
    }
    let ap = a.as_ptr();
    let bp = b.as_ptr();
    let mut i = 0usize;
    while i < n {
        // SAFETY: `n = a.len().min(b.len())` (computed above); `i < n`
        // is the loop invariant so both `add(i)` reads stay in-bounds.
        unsafe {
            if *ap.add(i) != *bp.add(i) {
                return false;
            }
        }
        i += 1;
    }
    true
}

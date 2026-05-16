// DEFLATE (RFC 1951) inflater — used by the PNG decoder to
// decompress IDAT chunks. Stored / fixed-Huffman / dynamic-Huffman
// block types are all supported. Bit stream is LSB-first.
//
// Memory: two heap-allocated Huffman lookup tables (one for the
// literal/length alphabet, one for distances) plus a 32 KiB sliding
// window are alloc'd in `inflate` and freed before return. The
// output is written directly into the caller-supplied buffer (no
// internal copy of the inflated stream).
//
// Limits / behaviour:
//   * Window size fixed at 32 KiB (the DEFLATE maximum).
//   * Max code length 15 bits (per the spec).
//   * Output buffer must be large enough for the full inflated
//     stream — the inflater fails loudly on overrun rather than
//     truncating.

use super::abi::SyscallTable;

const MAX_CODE_LEN: usize = 15;
const LIT_SYMS: usize = 288;
const DIST_SYMS: usize = 32;
const WINDOW_SIZE: usize = 32 * 1024;

/// Huffman lookup table — flat array indexed by symbol; each entry
/// is `(code_length, code_bits)` packed into a u32 (length << 16 |
/// code). For decode we build a canonical-code → symbol table
/// instead; see `HuffDec` below.
struct HuffDec {
    /// `counts[i]` = number of codes of length `i`.
    counts: [u16; MAX_CODE_LEN + 1],
    /// `symbols` arranged in canonical order: shortest first.
    symbols: [u16; LIT_SYMS],
}

impl HuffDec {
    const fn new() -> Self {
        Self {
            counts: [0; MAX_CODE_LEN + 1],
            symbols: [0; LIT_SYMS],
        }
    }

    /// Build a canonical Huffman decoder from per-symbol code
    /// lengths. Returns false if the code is over-subscribed (a
    /// well-formed code uses ≤ 1.0 of the 2^max_len code space).
    fn build(&mut self, lengths: &[u8]) -> bool {
        for c in self.counts.iter_mut() {
            *c = 0;
        }
        for &len in lengths {
            if len as usize > MAX_CODE_LEN {
                return false;
            }
            self.counts[len as usize] += 1;
        }
        if self.counts[0] as usize == lengths.len() {
            // No symbols — treat as a valid empty table.
            return true;
        }
        // Verify the code isn't over-subscribed.
        let mut left = 1i32;
        for len in 1..=MAX_CODE_LEN {
            left <<= 1;
            left -= self.counts[len] as i32;
            if left < 0 {
                return false;
            }
        }

        let mut offsets = [0u16; MAX_CODE_LEN + 2];
        for len in 1..=MAX_CODE_LEN {
            offsets[len + 1] = offsets[len] + self.counts[len];
        }
        for sym in 0..lengths.len() {
            let len = lengths[sym] as usize;
            if len != 0 {
                let slot = offsets[len] as usize;
                if slot >= self.symbols.len() {
                    return false;
                }
                self.symbols[slot] = sym as u16;
                offsets[len] += 1;
            }
        }
        true
    }

    /// Pull one symbol from `br`. Returns None on stream end / table
    /// inconsistency.
    fn decode(&self, br: &mut BitReader) -> Option<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: usize = 0;
        for len in 1..=MAX_CODE_LEN {
            let bit = br.read_bits(1)? as i32;
            code = (code << 1) | bit;
            let count = self.counts[len] as i32;
            if code - count < first {
                let slot = index + (code - first) as usize;
                return Some(self.symbols[slot]);
            }
            index += count as usize;
            first = (first + count) << 1;
        }
        None
    }
}

/// LSB-first bit reader. Pulls bytes from `src` and accumulates them
/// into a u32 accumulator.
struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,
    buf: u32,
    n: u32,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            buf: 0,
            n: 0,
        }
    }

    fn read_bits(&mut self, count: u32) -> Option<u32> {
        while self.n < count {
            if self.pos >= self.src.len() {
                return None;
            }
            self.buf |= (self.src[self.pos] as u32) << self.n;
            self.pos += 1;
            self.n += 8;
        }
        let v = self.buf & ((1u32 << count) - 1);
        self.buf >>= count;
        self.n -= count;
        Some(v)
    }

    fn align_to_byte(&mut self) {
        let drop = self.n & 7;
        self.buf >>= drop;
        self.n -= drop;
    }

    /// Read `count` raw bytes (caller has already byte-aligned).
    fn read_bytes(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.n != 0 {
            return None;
        }
        if self.pos + count > self.src.len() {
            return None;
        }
        let start = self.pos;
        self.pos += count;
        Some(&self.src[start..start + count])
    }
}

// ── Static tables (RFC 1951 §3.2.5) ─────────────────────────────────────

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

const CODE_LEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Inflate a DEFLATE stream from `src` into `dst[..dst_len]`. The
/// `src` slice should NOT include the zlib header/Adler32 — strip
/// those before calling. Returns true on success.
pub unsafe fn inflate(
    src: &[u8],
    dst: *mut u8,
    dst_len: usize,
    syscalls: *const SyscallTable,
) -> bool {
    // Tables for the literal/length and distance alphabets. We
    // rebuild them per dynamic block; fixed blocks use the
    // RFC-prescribed lengths.
    let lit_tbl = ((*syscalls).heap_alloc)(core::mem::size_of::<HuffDec>() as u32) as *mut HuffDec;
    let dist_tbl = ((*syscalls).heap_alloc)(core::mem::size_of::<HuffDec>() as u32) as *mut HuffDec;
    if lit_tbl.is_null() || dist_tbl.is_null() {
        if !lit_tbl.is_null() {
            ((*syscalls).heap_free)(lit_tbl as *mut u8);
        }
        if !dist_tbl.is_null() {
            ((*syscalls).heap_free)(dist_tbl as *mut u8);
        }
        return false;
    }
    core::ptr::write(lit_tbl, HuffDec::new());
    core::ptr::write(dist_tbl, HuffDec::new());

    let window_raw = ((*syscalls).heap_alloc)(WINDOW_SIZE as u32);
    if window_raw.is_null() {
        ((*syscalls).heap_free)(lit_tbl as *mut u8);
        ((*syscalls).heap_free)(dist_tbl as *mut u8);
        return false;
    }
    let window = core::slice::from_raw_parts_mut(window_raw, WINDOW_SIZE);
    let mut win_pos: usize = 0;

    let mut br = BitReader::new(src);
    let mut out_pos: usize = 0;

    let ok = loop {
        let bfinal = match br.read_bits(1) {
            Some(v) => v,
            None => break false,
        };
        let btype = match br.read_bits(2) {
            Some(v) => v,
            None => break false,
        };
        let block_ok = match btype {
            0 => inflate_stored(&mut br, dst, &mut out_pos, dst_len, window, &mut win_pos),
            1 => {
                build_fixed_tables(&mut *lit_tbl, &mut *dist_tbl);
                inflate_huff(
                    &mut br,
                    &*lit_tbl,
                    &*dist_tbl,
                    dst,
                    &mut out_pos,
                    dst_len,
                    window,
                    &mut win_pos,
                )
            }
            2 => {
                if !build_dynamic_tables(&mut br, &mut *lit_tbl, &mut *dist_tbl) {
                    break false;
                }
                inflate_huff(
                    &mut br,
                    &*lit_tbl,
                    &*dist_tbl,
                    dst,
                    &mut out_pos,
                    dst_len,
                    window,
                    &mut win_pos,
                )
            }
            _ => false,
        };
        if !block_ok {
            break false;
        }
        if bfinal != 0 {
            break out_pos == dst_len;
        }
    };

    ((*syscalls).heap_free)(window_raw);
    core::ptr::drop_in_place(lit_tbl);
    core::ptr::drop_in_place(dist_tbl);
    ((*syscalls).heap_free)(lit_tbl as *mut u8);
    ((*syscalls).heap_free)(dist_tbl as *mut u8);
    ok
}

// ── Stored block (BTYPE=0) ──────────────────────────────────────────────

unsafe fn inflate_stored(
    br: &mut BitReader,
    dst: *mut u8,
    out_pos: &mut usize,
    dst_len: usize,
    window: &mut [u8],
    win_pos: &mut usize,
) -> bool {
    br.align_to_byte();
    let header = match br.read_bytes(4) {
        Some(b) => b,
        None => return false,
    };
    let len = u16::from_le_bytes([header[0], header[1]]) as usize;
    let nlen = u16::from_le_bytes([header[2], header[3]]);
    if (len as u16) != !nlen {
        return false;
    }
    let body = match br.read_bytes(len) {
        Some(b) => b,
        None => return false,
    };
    if *out_pos + len > dst_len {
        return false;
    }
    for &b in body {
        *dst.add(*out_pos) = b;
        *out_pos += 1;
        window[*win_pos] = b;
        *win_pos = (*win_pos + 1) % WINDOW_SIZE;
    }
    true
}

// ── Fixed Huffman block (BTYPE=1) ───────────────────────────────────────

fn build_fixed_tables(lit: &mut HuffDec, dist: &mut HuffDec) {
    let mut lens = [0u8; LIT_SYMS];
    for i in 0..144 {
        lens[i] = 8;
    }
    for i in 144..256 {
        lens[i] = 9;
    }
    for i in 256..280 {
        lens[i] = 7;
    }
    for i in 280..288 {
        lens[i] = 8;
    }
    lit.build(&lens);
    let dlens = [5u8; DIST_SYMS];
    dist.build(&dlens);
}

// ── Dynamic Huffman block (BTYPE=2) ─────────────────────────────────────

fn build_dynamic_tables(br: &mut BitReader, lit: &mut HuffDec, dist: &mut HuffDec) -> bool {
    let hlit = match br.read_bits(5) {
        Some(v) => v,
        None => return false,
    } as usize
        + 257;
    let hdist = match br.read_bits(5) {
        Some(v) => v,
        None => return false,
    } as usize
        + 1;
    let hclen = match br.read_bits(4) {
        Some(v) => v,
        None => return false,
    } as usize
        + 4;
    if hlit > LIT_SYMS || hdist > DIST_SYMS {
        return false;
    }

    // Read the code-length-code lengths in the prescribed order.
    let mut cl_lens = [0u8; 19];
    for i in 0..hclen {
        let v = match br.read_bits(3) {
            Some(v) => v,
            None => return false,
        };
        cl_lens[CODE_LEN_ORDER[i]] = v as u8;
    }
    let mut cl_tbl = HuffDec::new();
    if !cl_tbl.build(&cl_lens) {
        return false;
    }

    // Now use the code-length code to decode the lit/dist lengths.
    let mut lens = [0u8; LIT_SYMS + DIST_SYMS];
    let total = hlit + hdist;
    let mut i = 0;
    while i < total {
        let sym = match cl_tbl.decode(br) {
            Some(s) => s,
            None => return false,
        };
        match sym {
            0..=15 => {
                lens[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return false;
                }
                let rep = match br.read_bits(2) {
                    Some(v) => v as usize + 3,
                    None => return false,
                };
                let v = lens[i - 1];
                if i + rep > total {
                    return false;
                }
                for _ in 0..rep {
                    lens[i] = v;
                    i += 1;
                }
            }
            17 => {
                let rep = match br.read_bits(3) {
                    Some(v) => v as usize + 3,
                    None => return false,
                };
                if i + rep > total {
                    return false;
                }
                for _ in 0..rep {
                    lens[i] = 0;
                    i += 1;
                }
            }
            18 => {
                let rep = match br.read_bits(7) {
                    Some(v) => v as usize + 11,
                    None => return false,
                };
                if i + rep > total {
                    return false;
                }
                for _ in 0..rep {
                    lens[i] = 0;
                    i += 1;
                }
            }
            _ => return false,
        }
    }

    if !lit.build(&lens[..hlit]) {
        return false;
    }
    if !dist.build(&lens[hlit..hlit + hdist]) {
        return false;
    }
    true
}

// ── Huffman block body (BTYPE=1 or 2) ───────────────────────────────────

unsafe fn inflate_huff(
    br: &mut BitReader,
    lit: &HuffDec,
    dist: &HuffDec,
    dst: *mut u8,
    out_pos: &mut usize,
    dst_len: usize,
    window: &mut [u8],
    win_pos: &mut usize,
) -> bool {
    loop {
        let sym = match lit.decode(br) {
            Some(s) => s,
            None => return false,
        };
        if sym < 256 {
            if *out_pos >= dst_len {
                return false;
            }
            *dst.add(*out_pos) = sym as u8;
            *out_pos += 1;
            window[*win_pos] = sym as u8;
            *win_pos = (*win_pos + 1) % WINDOW_SIZE;
        } else if sym == 256 {
            return true; // end-of-block
        } else {
            let li = (sym - 257) as usize;
            if li >= LENGTH_BASE.len() {
                return false;
            }
            let extra_len = LENGTH_EXTRA[li] as u32;
            let extra = if extra_len > 0 {
                match br.read_bits(extra_len) {
                    Some(v) => v,
                    None => return false,
                }
            } else {
                0
            };
            let length = LENGTH_BASE[li] as usize + extra as usize;

            let dsym = match dist.decode(br) {
                Some(s) => s,
                None => return false,
            };
            let di = dsym as usize;
            if di >= DIST_BASE.len() {
                return false;
            }
            let dextra_len = DIST_EXTRA[di] as u32;
            let dextra = if dextra_len > 0 {
                match br.read_bits(dextra_len) {
                    Some(v) => v,
                    None => return false,
                }
            } else {
                0
            };
            let distance = DIST_BASE[di] as usize + dextra as usize;
            if distance == 0 || distance > WINDOW_SIZE || *out_pos + length > dst_len {
                return false;
            }
            // Copy `length` bytes from `distance` back in the window,
            // honouring overlap (length may exceed distance).
            for _ in 0..length {
                let src_pos = (*win_pos + WINDOW_SIZE - distance) % WINDOW_SIZE;
                let b = window[src_pos];
                *dst.add(*out_pos) = b;
                *out_pos += 1;
                window[*win_pos] = b;
                *win_pos = (*win_pos + 1) % WINDOW_SIZE;
            }
        }
    }
}

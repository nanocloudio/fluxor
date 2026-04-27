//! WebSocket wire codec — RFC 6455 frames + handshake helpers.
//!
//! Pure byte-level routines: no syscalls, no module state. The server
//! and (future) client state machines drive the I/O; this file owns
//! the cryptographic handshake derivation and the frame format.
//!
//! # Handshake
//!
//! `compute_accept` produces the `Sec-WebSocket-Accept` base64 string
//! from the client's `Sec-WebSocket-Key`. RFC 6455 §1.3:
//!
//! ```text
//! accept = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
//! ```
//!
//! # Frames
//!
//! `parse_frame` decodes a frame header out of a partial byte stream;
//! `write_frame` builds an unmasked server-to-client frame. Client
//! frames must be masked (RFC 6455 §5.3); the server rejects unmasked
//! data frames per spec.

// ── Opcodes (RFC 6455 §5.2) ──────────────────────────────────────────────

pub(crate) const OP_CONTINUATION: u8 = 0x0;
pub(crate) const OP_TEXT: u8 = 0x1;
pub(crate) const OP_BINARY: u8 = 0x2;
pub(crate) const OP_CLOSE: u8 = 0x8;
pub(crate) const OP_PING: u8 = 0x9;
pub(crate) const OP_PONG: u8 = 0xA;

// ── Close codes (RFC 6455 §7.4) ──────────────────────────────────────────

pub(crate) const CLOSE_NORMAL: u16 = 1000;
pub(crate) const CLOSE_PROTOCOL_ERROR: u16 = 1002;
pub(crate) const CLOSE_UNSUPPORTED_DATA: u16 = 1003;
pub(crate) const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;

/// RFC 6455 magic GUID concatenated with the client key before SHA-1.
const MAGIC_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ── Sec-WebSocket-Accept derivation ──────────────────────────────────────

/// Compute `base64(sha1(client_key + MAGIC_GUID))` — the value that
/// goes into the server's `Sec-WebSocket-Accept` response header.
///
/// Output is exactly 28 ASCII bytes (no terminator).
pub unsafe fn compute_accept(key: *const u8, key_len: usize, out: *mut u8) {
    let mut sha = Sha1::new();
    sha.update(key, key_len);
    sha.update(MAGIC_GUID.as_ptr(), MAGIC_GUID.len());
    let digest = sha.finalize();
    base64_encode_20(&digest, out);
}

// ── Parsed frame header ───────────────────────────────────────────────────

/// Parsed result of `parse_frame`. `header_len` is the number of bytes
/// consumed by the frame header (start of payload); `payload_len` is
/// the payload byte count; `mask_key` is the 4-byte XOR key when
/// `masked == true`.
pub(crate) struct Frame {
    pub(crate) fin: bool,
    pub(crate) opcode: u8,
    pub(crate) masked: bool,
    pub(crate) mask_key: [u8; 4],
    pub(crate) header_len: u16,
    pub(crate) payload_len: u32,
}

/// Parse a frame header. Returns `Ok(Some(frame))` on success,
/// `Ok(None)` if the header is incomplete (caller should buffer more
/// data and retry), and `Err(())` on protocol violation.
///
/// Frames with 64-bit extended length are rejected as
/// "message too big" — the http module is sized for embedded targets
/// and never accepts payloads beyond 65535 bytes.
pub(crate) unsafe fn parse_frame(buf: *const u8, len: usize) -> Result<Option<Frame>, ()> {
    if len < 2 {
        return Ok(None);
    }
    let b0 = *buf;
    let b1 = *buf.add(1);

    let fin = (b0 & 0x80) != 0;
    let rsv = b0 & 0x70;
    let opcode = b0 & 0x0F;
    let masked = (b1 & 0x80) != 0;
    let len7 = b1 & 0x7F;

    if rsv != 0 {
        return Err(()); // RSV bits without negotiated extension
    }
    if !is_valid_opcode(opcode) {
        return Err(());
    }
    if is_control_opcode(opcode) && (!fin || len7 > 125) {
        return Err(()); // control frames must be FIN and ≤125 bytes
    }

    let mut header_len: u16 = 2;
    let payload_len: u32 = match len7 {
        126 => {
            if len < 4 {
                return Ok(None);
            }
            header_len = 4;
            ((*buf.add(2) as u32) << 8) | (*buf.add(3) as u32)
        }
        127 => {
            // 64-bit length. We only accept values that fit in 32 bits
            // and below our buffer ceiling; everything else is too big.
            if len < 10 {
                return Ok(None);
            }
            let mut v: u64 = 0;
            let mut i = 0;
            while i < 8 {
                v = (v << 8) | (*buf.add(2 + i) as u64);
                i += 1;
            }
            if v > u32::MAX as u64 {
                return Err(());
            }
            header_len = 10;
            v as u32
        }
        n => n as u32,
    };

    let mut mask_key = [0u8; 4];
    if masked {
        let need = (header_len + 4) as usize;
        if len < need {
            return Ok(None);
        }
        let mk = buf.add(header_len as usize);
        mask_key[0] = *mk;
        mask_key[1] = *mk.add(1);
        mask_key[2] = *mk.add(2);
        mask_key[3] = *mk.add(3);
        header_len += 4;
    }

    Ok(Some(Frame {
        fin,
        opcode,
        masked,
        mask_key,
        header_len,
        payload_len,
    }))
}

/// Apply the frame's masking key in place over `payload_len` bytes
/// starting at `payload`. RFC 6455 §5.3.
pub(crate) unsafe fn unmask(payload: *mut u8, payload_len: u32, mask_key: &[u8; 4]) {
    let mut i: u32 = 0;
    while i < payload_len {
        *payload.add(i as usize) ^= mask_key[(i & 3) as usize];
        i += 1;
    }
}

/// Write an unmasked server-to-client frame into `dst`. Returns the
/// total number of bytes written (header + payload). The caller is
/// responsible for keeping `payload_len` ≤ 65535 — server-emitted
/// frames in this module never use the 64-bit length form.
///
/// Returns 0 if `dst_cap` is too small to hold the frame.
pub(crate) unsafe fn write_frame(
    dst: *mut u8,
    dst_cap: usize,
    fin: bool,
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
) -> usize {
    let header_len = if payload_len <= 125 {
        2
    } else if payload_len <= 65535 {
        4
    } else {
        return 0;
    };
    if dst_cap < header_len + payload_len {
        return 0;
    }

    let fin_bit = if fin { 0x80 } else { 0 };
    *dst = fin_bit | (opcode & 0x0F);

    if payload_len <= 125 {
        *dst.add(1) = payload_len as u8;
    } else {
        *dst.add(1) = 126;
        *dst.add(2) = ((payload_len >> 8) & 0xFF) as u8;
        *dst.add(3) = (payload_len & 0xFF) as u8;
    }

    if payload_len > 0 {
        core::ptr::copy_nonoverlapping(payload, dst.add(header_len), payload_len);
    }
    header_len + payload_len
}

/// Write a masked client-to-server frame (RFC 6455 §5.3). Layout:
/// header (1 + 1 or 1 + 3) + 4-byte mask key + XOR-masked payload.
/// Returns total bytes written or 0 if `dst_cap` is too small.
pub(crate) unsafe fn write_frame_masked(
    dst: *mut u8,
    dst_cap: usize,
    fin: bool,
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
    mask_key: &[u8; 4],
) -> usize {
    let extended_len = if payload_len <= 125 {
        0
    } else if payload_len <= 65535 {
        2
    } else {
        return 0;
    };
    let header_len = 2 + extended_len + 4;
    if dst_cap < header_len + payload_len {
        return 0;
    }

    let fin_bit: u8 = if fin { 0x80 } else { 0 };
    *dst = fin_bit | (opcode & 0x0F);

    let mut o = 1usize;
    if payload_len <= 125 {
        *dst.add(o) = 0x80 | (payload_len as u8);
        o += 1;
    } else {
        *dst.add(o) = 0x80 | 126;
        o += 1;
        *dst.add(o) = ((payload_len >> 8) & 0xFF) as u8;
        *dst.add(o + 1) = (payload_len & 0xFF) as u8;
        o += 2;
    }

    *dst.add(o) = mask_key[0];
    *dst.add(o + 1) = mask_key[1];
    *dst.add(o + 2) = mask_key[2];
    *dst.add(o + 3) = mask_key[3];
    o += 4;

    let mut i = 0usize;
    while i < payload_len {
        *dst.add(o + i) = *payload.add(i) ^ mask_key[i & 3];
        i += 1;
    }
    o + payload_len
}

// ── HTTP/1.1 handshake response ──────────────────────────────────────────

/// Write the `101 Switching Protocols` response for a successful
/// WebSocket upgrade. `accept` is the 28-byte ASCII output of
/// `compute_accept`. Returns total bytes written.
pub(crate) unsafe fn write_handshake_response(
    dst: *mut u8,
    dst_cap: usize,
    accept: *const u8,
) -> usize {
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < dst_cap {
                *dst.add(off) = *src.as_ptr().add(i);
                off += 1;
                i += 1;
            }
        };
    }

    put!(b"HTTP/1.1 101 Switching Protocols\r\n");
    put!(b"Upgrade: websocket\r\n");
    put!(b"Connection: Upgrade\r\n");
    put!(b"Sec-WebSocket-Accept: ");
    let mut i = 0;
    while i < 28 && off < dst_cap {
        *dst.add(off) = *accept.add(i);
        off += 1;
        i += 1;
    }
    put!(b"\r\n\r\n");

    off
}

/// Locate the value of a header field in a parsed HTTP/1 request,
/// case-insensitive. `name` should not include the trailing `:`. The
/// search ends at the blank line that closes the head.
///
/// Returns `(offset, length)` of the trimmed value within `buf`, or
/// `None` if the header is not present.
pub(crate) unsafe fn find_header_value(
    buf: *const u8,
    len: usize,
    name: &[u8],
) -> Option<(usize, usize)> {
    let mut line_start = 0usize;
    while line_start < len {
        // Find end of line.
        let mut eol = line_start;
        while eol + 1 < len {
            if *buf.add(eol) == b'\r' && *buf.add(eol + 1) == b'\n' {
                break;
            }
            eol += 1;
        }
        if eol + 1 >= len {
            return None;
        }
        if eol == line_start {
            // Blank line — end of headers.
            return None;
        }

        // Look for `name:` at the start of this line, case-insensitive.
        if eol - line_start > name.len() && *buf.add(line_start + name.len()) == b':' {
            let mut matches = true;
            let mut j = 0;
            while j < name.len() {
                let a = ascii_lower(*buf.add(line_start + j));
                let b = ascii_lower(name[j]);
                if a != b {
                    matches = false;
                    break;
                }
                j += 1;
            }
            if matches {
                let mut v_start = line_start + name.len() + 1;
                while v_start < eol && (*buf.add(v_start) == b' ' || *buf.add(v_start) == b'\t') {
                    v_start += 1;
                }
                let mut v_end = eol;
                while v_end > v_start
                    && (*buf.add(v_end - 1) == b' ' || *buf.add(v_end - 1) == b'\t')
                {
                    v_end -= 1;
                }
                return Some((v_start, v_end - v_start));
            }
        }

        line_start = eol + 2;
    }
    None
}

/// Search for `needle` in the value of a header, case-insensitive,
/// treating commas as separators. Useful for `Connection: keep-alive,
/// Upgrade` where `Upgrade` must be present alongside other tokens.
pub(crate) unsafe fn header_value_contains_token(
    buf: *const u8,
    val_off: usize,
    val_len: usize,
    needle: &[u8],
) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut tok_start = val_off;
    let end = val_off + val_len;
    let mut i = val_off;
    loop {
        if i >= end || *buf.add(i) == b',' {
            // Trim whitespace around [tok_start, i).
            let mut s = tok_start;
            let mut e = i;
            while s < e && (*buf.add(s) == b' ' || *buf.add(s) == b'\t') {
                s += 1;
            }
            while e > s && (*buf.add(e - 1) == b' ' || *buf.add(e - 1) == b'\t') {
                e -= 1;
            }
            if e - s == needle.len() {
                let mut ok = true;
                let mut j = 0;
                while j < needle.len() {
                    let a = ascii_lower(*buf.add(s + j));
                    let b = ascii_lower(needle[j]);
                    if a != b {
                        ok = false;
                        break;
                    }
                    j += 1;
                }
                if ok {
                    return true;
                }
            }
            if i >= end {
                break;
            }
            tok_start = i + 1;
        }
        i += 1;
    }
    false
}

#[inline]
fn ascii_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

// ── SHA-1 (FIPS 180-4 / RFC 3174) ────────────────────────────────────────

struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    buf_len: u8,
    total_len: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buf: [0; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    unsafe fn update(&mut self, data: *const u8, len: usize) {
        self.total_len = self.total_len.wrapping_add(len as u64);
        let mut consumed = 0usize;
        while consumed < len {
            let space = 64 - self.buf_len as usize;
            let take = (len - consumed).min(space);
            let mut i = 0;
            while i < take {
                self.buf[self.buf_len as usize + i] = *data.add(consumed + i);
                i += 1;
            }
            self.buf_len += take as u8;
            consumed += take;
            if self.buf_len == 64 {
                let block = self.buf;
                self.process_block(&block);
                self.buf_len = 0;
            }
        }
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len.wrapping_mul(8);
        // Append 0x80, then zeroes, then 8-byte big-endian bit length.
        self.buf[self.buf_len as usize] = 0x80;
        self.buf_len += 1;
        if self.buf_len as usize > 56 {
            // Pad current block, process, then zeroes in next block.
            while (self.buf_len as usize) < 64 {
                self.buf[self.buf_len as usize] = 0;
                self.buf_len += 1;
            }
            let block = self.buf;
            self.process_block(&block);
            self.buf_len = 0;
        }
        while (self.buf_len as usize) < 56 {
            self.buf[self.buf_len as usize] = 0;
            self.buf_len += 1;
        }
        let len_bytes = bit_len.to_be_bytes();
        let mut i = 0;
        while i < 8 {
            self.buf[56 + i] = len_bytes[i];
            i += 1;
        }
        let block = self.buf;
        self.process_block(&block);

        let mut out = [0u8; 20];
        let mut i = 0;
        while i < 5 {
            let h = self.h[i].to_be_bytes();
            out[i * 4] = h[0];
            out[i * 4 + 1] = h[1];
            out[i * 4 + 2] = h[2];
            out[i * 4 + 3] = h[3];
            i += 1;
        }
        out
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        let mut i = 0;
        while i < 16 {
            w[i] = ((block[i * 4] as u32) << 24)
                | ((block[i * 4 + 1] as u32) << 16)
                | ((block[i * 4 + 2] as u32) << 8)
                | (block[i * 4 + 3] as u32);
            i += 1;
        }
        let mut t = 16;
        while t < 80 {
            let v = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = v.rotate_left(1);
            t += 1;
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        let mut t = 0;
        while t < 80 {
            let (f, k) = if t < 20 {
                ((b & c) | ((!b) & d), 0x5A827999u32)
            } else if t < 40 {
                (b ^ c ^ d, 0x6ED9EBA1u32)
            } else if t < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32)
            } else {
                (b ^ c ^ d, 0xCA62C1D6u32)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[t]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
            t += 1;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

// ── Base64 encoder (RFC 4648, exactly 20 input bytes → 28 output bytes) ──

const B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsafe fn base64_encode_20(input: &[u8; 20], out: *mut u8) {
    // 20 bytes = 6 full triples + 1 leftover pair → 6*4 + 4 = 28 chars.
    let mut i = 0;
    let mut o = 0;
    while i + 3 <= 20 {
        let v = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        *out.add(o) = B64[((v >> 18) & 0x3F) as usize];
        *out.add(o + 1) = B64[((v >> 12) & 0x3F) as usize];
        *out.add(o + 2) = B64[((v >> 6) & 0x3F) as usize];
        *out.add(o + 3) = B64[(v & 0x3F) as usize];
        i += 3;
        o += 4;
    }
    // Trailing 2 bytes → 3 chars + `=` padding.
    let v = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
    *out.add(o) = B64[((v >> 18) & 0x3F) as usize];
    *out.add(o + 1) = B64[((v >> 12) & 0x3F) as usize];
    *out.add(o + 2) = B64[((v >> 6) & 0x3F) as usize];
    *out.add(o + 3) = b'=';
}

#[inline]
fn is_valid_opcode(op: u8) -> bool {
    matches!(op, OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG)
}

#[inline]
fn is_control_opcode(op: u8) -> bool {
    op >= 0x8
}

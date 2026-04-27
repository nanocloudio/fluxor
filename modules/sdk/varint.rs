// QUIC variable-length integer codec (RFC 9000 §16).
//
// Used by QUIC framing, HTTP/3 framing (RFC 9114), and QPACK (RFC 9204).
//
// Length is signaled by the top 2 bits of the first byte:
//
// | 2MSB | length | range                                     |
// |------|--------|-------------------------------------------|
// | 00   | 1B     | 0..=63                                    |
// | 01   | 2B     | 0..=16_383                                |
// | 10   | 4B     | 0..=1_073_741_823                         |
// | 11   | 8B     | 0..=4_611_686_018_427_387_903 (2^62 − 1)  |
//
// Numbers are big-endian on the wire after the length prefix.
//
// PIC-safe: raw-pointer writes/reads to avoid panic stubs from slice
// bounds checks. Round-trips u64 in the 0..=2^62-1 range.
//
// Pull this in via:
//
//     #[path = "../../sdk/varint.rs"]
//     mod varint;

/// Maximum representable varint value (2^62 - 1).
pub(crate) const VARINT_MAX: u64 = (1u64 << 62) - 1;

/// Number of bytes a value requires when encoded. Returns 0 if the
/// value exceeds `VARINT_MAX`.
#[inline]
pub(crate) fn varint_size(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else if value <= VARINT_MAX {
        8
    } else {
        0
    }
}

/// Number of bytes the encoded form occupies, given just the first
/// byte. Used by the decoder before it has read the rest.
#[inline]
pub(crate) fn varint_size_from_first(b: u8) -> usize {
    1usize << ((b >> 6) as usize)
}

/// Encode `value` into the buffer. Returns the number of bytes
/// written, or 0 if `dst_cap` is too small or the value is too large.
///
/// # Safety
/// `dst` must be valid for writes of at least `dst_cap` bytes.
pub(crate) unsafe fn varint_encode(dst: *mut u8, dst_cap: usize, value: u64) -> usize {
    if value < (1 << 6) {
        if dst_cap < 1 {
            return 0;
        }
        *dst = value as u8;
        1
    } else if value < (1 << 14) {
        if dst_cap < 2 {
            return 0;
        }
        *dst = 0x40 | ((value >> 8) as u8 & 0x3F);
        *dst.add(1) = value as u8;
        2
    } else if value < (1 << 30) {
        if dst_cap < 4 {
            return 0;
        }
        *dst = 0x80 | ((value >> 24) as u8 & 0x3F);
        *dst.add(1) = (value >> 16) as u8;
        *dst.add(2) = (value >> 8) as u8;
        *dst.add(3) = value as u8;
        4
    } else if value <= VARINT_MAX {
        if dst_cap < 8 {
            return 0;
        }
        *dst = 0xC0 | ((value >> 56) as u8 & 0x3F);
        *dst.add(1) = (value >> 48) as u8;
        *dst.add(2) = (value >> 40) as u8;
        *dst.add(3) = (value >> 32) as u8;
        *dst.add(4) = (value >> 24) as u8;
        *dst.add(5) = (value >> 16) as u8;
        *dst.add(6) = (value >> 8) as u8;
        *dst.add(7) = value as u8;
        8
    } else {
        0
    }
}

/// Decode a varint from `src`. Returns `(value, bytes_consumed)` on
/// success, or `None` if `src_len` is shorter than the encoded form.
///
/// # Safety
/// `src` must be valid for reads of at least `src_len` bytes.
pub(crate) unsafe fn varint_decode(src: *const u8, src_len: usize) -> Option<(u64, usize)> {
    if src_len < 1 {
        return None;
    }
    let b0 = *src;
    let n = 1usize << ((b0 >> 6) as usize);
    if src_len < n {
        return None;
    }
    let masked = (b0 & 0x3F) as u64;
    let value = match n {
        1 => masked,
        2 => (masked << 8) | (*src.add(1) as u64),
        4 => {
            (masked << 24)
                | ((*src.add(1) as u64) << 16)
                | ((*src.add(2) as u64) << 8)
                | (*src.add(3) as u64)
        }
        8 => {
            (masked << 56)
                | ((*src.add(1) as u64) << 48)
                | ((*src.add(2) as u64) << 40)
                | ((*src.add(3) as u64) << 32)
                | ((*src.add(4) as u64) << 24)
                | ((*src.add(5) as u64) << 16)
                | ((*src.add(6) as u64) << 8)
                | (*src.add(7) as u64)
        }
        _ => return None,
    };
    Some((value, n))
}

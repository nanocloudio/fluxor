// UTF-8 text inside wire records.
//
// A record that carries text states it as UTF-8 bytes, and its parser hands
// the bytes on as `&str`. The checks here are written out over bytes: a
// module links no `core::str` validation or scalar iteration, so every
// reader of a text field, in a module or in the kernel, goes through these.
//
// Reached as `fluxor_abi::wire::utf8_text`.

/// Whether `b` is well-formed UTF-8: shortest-form sequences, no
/// surrogates, nothing past U+10FFFF. Accepts exactly what
/// `core::str::from_utf8` accepts.
pub fn valid(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c < 0x80 {
            i += 1;
            continue;
        }
        // Sequence length, and the range the first continuation byte must
        // fall in for this lead byte.
        let (n, lo, hi) = match c {
            0xC2..=0xDF => (2, 0x80, 0xBF),
            0xE0 => (3, 0xA0, 0xBF),
            0xE1..=0xEC | 0xEE..=0xEF => (3, 0x80, 0xBF),
            0xED => (3, 0x80, 0x9F),
            0xF0 => (4, 0x90, 0xBF),
            0xF1..=0xF3 => (4, 0x80, 0xBF),
            0xF4 => (4, 0x80, 0x8F),
            _ => return false,
        };
        if b.len() - i < n || b[i + 1] < lo || b[i + 1] > hi {
            return false;
        }
        let mut k = 2;
        while k < n {
            if b[i + k] & 0xC0 != 0x80 {
                return false;
            }
            k += 1;
        }
        i += n;
    }
    true
}

/// `b` as text; `None` when it is not well-formed UTF-8.
pub fn text(b: &[u8]) -> Option<&str> {
    if !valid(b) {
        return None;
    }
    // SAFETY: `valid` accepted every byte of `b` as well-formed UTF-8.
    Some(unsafe { core::str::from_utf8_unchecked(b) })
}

/// Whether `byte` continues a sequence (is not the first byte of a scalar).
const fn continues(byte: u8) -> bool {
    byte & 0xC0 == 0x80
}

/// The number of Unicode scalar values in `s`: its bytes that open a
/// sequence.
pub fn scalars(s: &str) -> usize {
    let b = s.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i < b.len() {
        if !continues(b[i]) {
            n += 1;
        }
        i += 1;
    }
    n
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a
/// scalar boundary.
pub fn prefix_within(s: &str, max: usize) -> &str {
    let b = s.as_bytes();
    if b.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && continues(b[end]) {
        end -= 1;
    }
    // SAFETY: `end` is zero or indexes a byte that opens a sequence of the
    // well-formed `s`, so the bytes before it are whole sequences.
    unsafe { core::str::from_utf8_unchecked(&b[..end]) }
}

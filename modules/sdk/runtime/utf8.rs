// ============================================================================
// UTF-8 validation
// ============================================================================

/// Whether `b` is well-formed UTF-8: shortest-form sequences, no
/// surrogates, nothing past U+10FFFF. Accepts exactly what
/// `core::str::from_utf8` accepts; a PIC module cannot link that, so
/// modules validate names, paths and keys here.
pub fn utf8_valid(b: &[u8]) -> bool {
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

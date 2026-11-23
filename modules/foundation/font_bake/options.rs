//! The baker's params, as text: `sizes` (comma-separated whole pixel sizes),
//! `scales` (comma-separated device pixel ratios in eighths: `1`, `1.25`,
//! `1.5`, `2`, …; each strike is a size times a scale, rounded to the nearest
//! whole pixel per em), `format`
//! (a `GLYPH_FORMATS` name) and `chars` (CSS `unicode-range` syntax:
//! `U+0020-007E, U+00A0-00FF, U+2026`; empty keeps every code point the font
//! maps).

use super::gp;

pub const MAX_PPEMS: usize = 64;

/// Why the params are refused (messages are the module's `OPTION_ERRORS`).
pub const E_FORMAT: u8 = 0;
pub const E_SIZES: u8 = 1;
pub const E_SCALES: u8 = 2;
pub const E_STRIKES: u8 = 3;
pub const E_CHARS: u8 = 4;
pub const E_RANGES: u8 = 5;
pub const MAX_RANGES: usize = 64;

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

fn number(s: &[u8]) -> Option<u32> {
    let s = trim(s);
    if s.is_empty() || s.len() > 6 {
        return None;
    }
    let mut v = 0u32;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u32;
    }
    Some(v)
}

/// A scale in eighths: a whole number, or one with a fraction that is a
/// whole number of eighths (`1.5` is 12, `1.125` is 9); `None` for any other
/// text, `1.3` among it.
fn eighths(s: &[u8]) -> Option<u32> {
    let s = trim(s);
    let (whole, frac) = match s.iter().position(|&c| c == b'.') {
        Some(dot) if dot + 1 < s.len() => (&s[..dot], &s[dot + 1..]),
        Some(_) => return None,
        None => (s, &b""[..]),
    };
    if (whole.is_empty() && frac.is_empty()) || frac.len() > 3 {
        return None;
    }
    let whole = if whole.is_empty() { 0 } else { number(whole)? };
    // The fraction in thousandths; an eighth is 125 of them.
    let mut thousandths = 0u32;
    for i in 0..3 {
        let d = match frac.get(i) {
            Some(&c) if c.is_ascii_digit() => (c - b'0') as u32,
            Some(_) => return None,
            None => 0,
        };
        thousandths = thousandths * 10 + d;
    }
    thousandths
        .is_multiple_of(125)
        .then(|| whole * 8 + thousandths / 125)
}

fn hex(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 6 {
        return None;
    }
    let mut v = 0u32;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = v << 4 | d as u32;
    }
    Some(v)
}

fn list(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    s.split(|&c| c == b',').map(trim).filter(|p| !p.is_empty())
}

/// One `unicode-range` item: `U+X`, `U+X-Y`, or `U+X??` (wildcards).
fn range(s: &[u8]) -> Option<(u32, u32)> {
    let s = trim(s);
    let body = match s {
        [b'U' | b'u', b'+', rest @ ..] => rest,
        _ => return None,
    };
    if let Some(dash) = body.iter().position(|&c| c == b'-') {
        let (a, b) = (hex(&body[..dash])?, hex(&body[dash + 1..])?);
        return (a <= b && b <= 0x10_FFFF).then_some((a, b));
    }
    let q = body.iter().filter(|&&c| c == b'?').count();
    if q > 0 {
        let digits = &body[..body.len() - q];
        if body[body.len() - q..].iter().any(|&c| c != b'?') {
            return None;
        }
        let base = if digits.is_empty() { 0 } else { hex(digits)? } << (4 * q);
        let top = base | ((1u32 << (4 * q)) - 1);
        return (top <= 0x10_FFFF).then_some((base, top));
    }
    let a = hex(body)?;
    (a <= 0x10_FFFF).then_some((a, a))
}

/// Why the params are refused: one of the `E_*` codes, and the item it
/// refuses (empty when the refusal is of the whole list).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal<'a> {
    pub code: u8,
    pub item: &'a [u8],
}

/// The format byte, the number of ppems and of ranges; or why the params
/// are refused.
pub fn parse<'a>(
    sizes: &'a [u8],
    scales: &'a [u8],
    format: &'a [u8],
    chars: &'a [u8],
    ppems: &mut [u16; MAX_PPEMS],
    ranges: &mut [(u32, u32); MAX_RANGES],
) -> Result<(u8, usize, usize), Refusal<'a>> {
    let refuse = |code: u8, item: &'a [u8]| Refusal { code, item };
    let format = match trim(format) {
        b"" | b"a8" => gp::FORMAT_A8,
        b"a1" => gp::FORMAT_A1,
        other => return Err(refuse(E_FORMAT, other)),
    };
    let sizes = if trim(sizes).is_empty() {
        b"16" as &[u8]
    } else {
        sizes
    };
    let scales = if trim(scales).is_empty() {
        b"1" as &[u8]
    } else {
        scales
    };
    let mut n = 0;
    for size_text in list(sizes) {
        let size = number(size_text)
            .filter(|&v| v > 0 && v <= 1024)
            .ok_or(refuse(E_SIZES, size_text))?;
        for scale_text in list(scales) {
            let scale = eighths(scale_text)
                .filter(|&v| v > 0 && v <= 64)
                .ok_or(refuse(E_SCALES, scale_text))?;
            // The nearest whole pixel; a half rounds up.
            let ppem = ((size * scale + 4) / 8) as u16;
            if !ppems[..n].contains(&ppem) {
                if n == MAX_PPEMS {
                    return Err(refuse(E_STRIKES, b""));
                }
                ppems[n] = ppem;
                n += 1;
            }
        }
    }
    // Insertion sort: core's sorts reference a panic PIC modules cannot link.
    for i in 1..n {
        let mut j = i;
        while j > 0 && ppems[j - 1] > ppems[j] {
            ppems.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut k = 0;
    for item in list(chars) {
        let r = range(item).ok_or(refuse(E_CHARS, item))?;
        if k == MAX_RANGES {
            return Err(refuse(E_RANGES, b""));
        }
        ranges[k] = r;
        k += 1;
    }
    Ok((format, n, k))
}

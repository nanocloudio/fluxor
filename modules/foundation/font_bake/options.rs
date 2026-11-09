//! The baker's params, as text: `sizes` and `scales` (comma-separated whole
//! numbers; each strike is a size times a scale, in pixels per em), `format`
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

/// The format byte, the number of ppems and of ranges; or why the params
/// are refused.
pub fn parse(
    sizes: &[u8],
    scales: &[u8],
    format: &[u8],
    chars: &[u8],
    ppems: &mut [u16; MAX_PPEMS],
    ranges: &mut [(u32, u32); MAX_RANGES],
) -> Result<(u8, usize, usize), u8> {
    let format = match trim(format) {
        b"" | b"a8" => gp::FORMAT_A8,
        b"a1" => gp::FORMAT_A1,
        _ => return Err(E_FORMAT),
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
    for size in list(sizes) {
        let size = number(size)
            .filter(|&v| v > 0 && v <= 1024)
            .ok_or(E_SIZES)?;
        for scale in list(scales) {
            let scale = number(scale).filter(|&v| v > 0 && v <= 8).ok_or(E_SCALES)?;
            let ppem = (size * scale) as u16;
            if !ppems[..n].contains(&ppem) {
                if n == MAX_PPEMS {
                    return Err(E_STRIKES);
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
        let r = range(item).ok_or(E_CHARS)?;
        if k == MAX_RANGES {
            return Err(E_RANGES);
        }
        ranges[k] = r;
        k += 1;
    }
    Ok((format, n, k))
}

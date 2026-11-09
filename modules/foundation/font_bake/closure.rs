//! The `GSUB` closure of a glyph set: every glyph a substitution can produce
//! from glyphs in the set, so a strike can draw whatever a shaper makes.
//!
//! The closure is a superset. Every lookup is applied as if its feature were
//! on and its context matched; a contextual lookup's nested lookups are
//! lookups in the same list, so they are applied in their own right.

use super::ttf::{be16, be32};

/// A set of glyph ids, a bit each.
pub struct GlyphSet<'a> {
    pub bits: &'a mut [u8],
    pub glyphs: u16,
}

impl GlyphSet<'_> {
    pub fn has(&self, g: u16) -> bool {
        g < self.glyphs && self.bits[g as usize / 8] & (1 << (g % 8)) != 0
    }

    /// Add `g`; whether it was new.
    pub fn add(&mut self, g: u16) -> bool {
        if g >= self.glyphs || self.has(g) {
            return false;
        }
        self.bits[g as usize / 8] |= 1 << (g % 8);
        true
    }

    pub fn count(&self) -> usize {
        (0..self.glyphs).filter(|&g| self.has(g)).count()
    }
}

/// Call `f(glyph, coverage index)` for every glyph a coverage table covers.
fn covered<F: FnMut(u16, usize)>(t: &[u8], at: usize, f: &mut F) {
    match be16(t, at) {
        Some(1) => {
            let n = be16(t, at + 2).unwrap_or(0) as usize;
            for i in 0..n {
                if let Some(g) = be16(t, at + 4 + i * 2) {
                    f(g, i);
                }
            }
        }
        Some(2) => {
            let n = be16(t, at + 2).unwrap_or(0) as usize;
            for i in 0..n {
                let r = at + 4 + i * 6;
                let (Some(s), Some(e), Some(ci)) = (be16(t, r), be16(t, r + 2), be16(t, r + 4))
                else {
                    return;
                };
                if e < s {
                    continue;
                }
                for g in s..=e {
                    f(g, ci as usize + (g - s) as usize);
                }
            }
        }
        _ => {}
    }
}

/// Close `set` over the `GSUB` table `gsub`.
pub fn close(gsub: &[u8], set: &mut GlyphSet) {
    let Some(list) = be16(gsub, 8).map(|v| v as usize) else {
        return;
    };
    let lookups = be16(gsub, list).unwrap_or(0) as usize;
    for _pass in 0..16 {
        let mut grew = false;
        for l in 0..lookups {
            let Some(off) = be16(gsub, list + 2 + l * 2) else {
                continue;
            };
            let lk = list + off as usize;
            let kind = be16(gsub, lk).unwrap_or(0);
            let subs = be16(gsub, lk + 4).unwrap_or(0) as usize;
            for s in 0..subs {
                let Some(so) = be16(gsub, lk + 6 + s * 2) else {
                    continue;
                };
                let mut at = lk + so as usize;
                let mut kind = kind;
                if kind == 7 {
                    kind = be16(gsub, at + 2).unwrap_or(0);
                    at += be32(gsub, at + 4).unwrap_or(0) as usize;
                }
                grew |= subtable(gsub, kind, at, set);
            }
        }
        if !grew {
            return;
        }
    }
}

/// Apply one subtable to the set; whether it grew.
fn subtable(t: &[u8], kind: u16, at: usize, set: &mut GlyphSet) -> bool {
    let format = be16(t, at).unwrap_or(0);
    let cov = at + be16(t, at + 2).unwrap_or(0) as usize;
    let mut out: [u16; 64] = [0; 64];
    let mut n = 0usize;
    let mut grew = false;
    let mut flush = |out: &[u16], set: &mut GlyphSet| {
        for &g in out {
            grew |= set.add(g);
        }
    };
    match (kind, format) {
        (1, 1) => {
            let delta = be16(t, at + 4).unwrap_or(0);
            covered(t, cov, &mut |g, _| {
                if set.has(g) && n < out.len() {
                    out[n] = g.wrapping_add(delta);
                    n += 1;
                }
                if n == out.len() {
                    flush(&out[..n], set);
                    n = 0;
                }
            });
        }
        (1, 2) => {
            covered(t, cov, &mut |g, i| {
                if set.has(g) {
                    if let Some(s) = be16(t, at + 6 + i * 2) {
                        out[n] = s;
                        n += 1;
                    }
                }
                if n == out.len() {
                    flush(&out[..n], set);
                    n = 0;
                }
            });
        }
        // Multiple and alternate: every glyph of the sequence or set.
        (2, 1) | (3, 1) => {
            covered(t, cov, &mut |g, i| {
                if !set.has(g) {
                    return;
                }
                let Some(so) = be16(t, at + 6 + i * 2) else {
                    return;
                };
                let seq = at + so as usize;
                let c = be16(t, seq).unwrap_or(0) as usize;
                for k in 0..c {
                    if let Some(s) = be16(t, seq + 2 + k * 2) {
                        out[n] = s;
                        n += 1;
                        if n == out.len() {
                            flush(&out[..n], set);
                            n = 0;
                        }
                    }
                }
            });
        }
        // Ligature: when every component is in the set.
        (4, 1) => {
            covered(t, cov, &mut |g, i| {
                if !set.has(g) {
                    return;
                }
                let Some(so) = be16(t, at + 6 + i * 2) else {
                    return;
                };
                let ls = at + so as usize;
                let c = be16(t, ls).unwrap_or(0) as usize;
                for k in 0..c {
                    let Some(lo) = be16(t, ls + 2 + k * 2) else {
                        continue;
                    };
                    let lig = ls + lo as usize;
                    let (Some(glyph), Some(comps)) = (be16(t, lig), be16(t, lig + 2)) else {
                        continue;
                    };
                    let all = (1..comps as usize)
                        .all(|j| be16(t, lig + 4 + (j - 1) * 2).is_some_and(|c| set.has(c)));
                    if all {
                        out[n] = glyph;
                        n += 1;
                        if n == out.len() {
                            flush(&out[..n], set);
                            n = 0;
                        }
                    }
                }
            });
        }
        // Reverse chaining single: substitutes by coverage index.
        (8, 1) => {
            let back = be16(t, at + 4).unwrap_or(0) as usize;
            let ahead_at = at + 6 + back * 2;
            let ahead = be16(t, ahead_at).unwrap_or(0) as usize;
            let subs_at = ahead_at + 2 + ahead * 2 + 2;
            covered(t, cov, &mut |g, i| {
                if set.has(g) {
                    if let Some(s) = be16(t, subs_at + i * 2) {
                        out[n] = s;
                        n += 1;
                    }
                }
                if n == out.len() {
                    flush(&out[..n], set);
                    n = 0;
                }
            });
        }
        _ => {}
    }
    flush(&out[..n], set);
    grew
}

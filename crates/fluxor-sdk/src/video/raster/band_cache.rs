//! A cache of finished RGB565 bands: each band as the panel received it,
//! encoded as runs and literals, so a consumer that shows one frame for
//! many refreshes copies a band back instead of drawing it again.
//!
//! A band's encoding is a stream of 16-bit tokens, little-endian:
//!
//! - a run, `[0x8000 | n][pixel]`: `n` pixels of one value;
//! - a literal, `[n][pixel × n]`: `n` pixels as they are;
//!
//! with `n` from 1 to 32,767. Decoding a band's tokens gives back the exact
//! bytes encoded: the cache holds output, not drawing, so what it replays
//! is byte for byte what the live path produced.
//!
//! The memory is the caller's: a table of one start offset a band (four
//! bytes each) and the tokens after it. Bands are added in the order they
//! are encoded while they fit; one that does not fit is not cached and the
//! caller draws it live. The cache holds one picture: `clear` drops every
//! band at once.

/// Bytes of the start table, a band.
pub const START_BYTES: usize = 4;

/// The start of a band that is not cached.
const ABSENT: u32 = u32::MAX;
/// The flag of a run token.
const RUN: u16 = 0x8000;
/// The most pixels one token counts.
const MAX_COUNT: usize = 0x7FFF;
/// The shortest run worth a token of its own: a run of three costs what it
/// saves inside a literal, and decodes as a fill.
const MIN_RUN: usize = 3;

/// One token of a band's encoding.
#[derive(Clone, Copy)]
enum Token {
    /// `count` pixels of `value`.
    Run { count: usize, value: u16 },
    /// `count` pixels from pixel `first` of the band.
    Literal { first: usize, count: usize },
}

impl Token {
    /// Bytes the token takes.
    const fn bytes(self) -> usize {
        match self {
            Token::Run { .. } => 4,
            Token::Literal { count, .. } => 2 + 2 * count,
        }
    }
}

/// Pixel `i` of an RGB565 band.
fn pixel(pixels: &[u8], i: usize) -> u16 {
    match pixels.get(2 * i..2 * i + 2) {
        Some(&[lo, hi]) => u16::from_le_bytes([lo, hi]),
        _ => 0,
    }
}

/// Hand `emit` the literal tokens of pixels `first..end`. Whether every
/// one was taken.
fn literal(first: usize, end: usize, emit: &mut impl FnMut(Token) -> bool) -> bool {
    let mut at = first;
    while at < end {
        let count = (end - at).min(MAX_COUNT);
        if !emit(Token::Literal { first: at, count }) {
            return false;
        }
        at += count;
    }
    true
}

/// Hand every token of `pixels` (RGB565, two bytes a pixel) to `emit`, in
/// order, stopping when it answers false. Whether every token was taken.
///
/// One pass over the pixels: each maximal run of one value (cut at
/// `MAX_COUNT`) of at least `MIN_RUN` pixels is a run token, and what lies
/// between runs is literals.
fn walk(pixels: &[u8], mut emit: impl FnMut(Token) -> bool) -> bool {
    let mut values = pixels.chunks_exact(2).map(|p| match p {
        [lo, hi] => u16::from_le_bytes([*lo, *hi]),
        _ => 0,
    });
    let Some(mut value) = values.next() else {
        return true;
    };
    // The pending literal starts at `first`; the run in hand at `start`.
    let (mut first, mut start, mut i) = (0usize, 0usize, 1usize);
    for v in values {
        if v != value || i - start == MAX_COUNT {
            if !end_run(&mut first, start, i, value, &mut emit) {
                return false;
            }
            start = i;
            value = v;
        }
        i += 1;
    }
    end_run(&mut first, start, i, value, &mut emit) && literal(first, i, &mut emit)
}

/// The run of `value` over pixels `start..end` has ended: when it is long
/// enough, hand `emit` the literal before it and the run, and start the
/// next literal after it. Whether every token was taken.
fn end_run(
    first: &mut usize,
    start: usize,
    end: usize,
    value: u16,
    emit: &mut impl FnMut(Token) -> bool,
) -> bool {
    if end - start < MIN_RUN {
        return true;
    }
    let whole = literal(*first, start, emit)
        && emit(Token::Run {
            count: end - start,
            value,
        });
    *first = end;
    whole
}

/// Bytes `pixels` (an RGB565 band) takes encoded.
pub fn encoded_bytes(pixels: &[u8]) -> usize {
    let mut total = 0;
    walk(pixels, |t| {
        total += t.bytes();
        true
    });
    total
}

/// Write `value` at `at` of `out`, little-endian. Whether it fit.
fn put(out: &mut [u8], at: usize, value: u16) -> bool {
    match out.get_mut(at..at + 2) {
        Some(slot) => {
            for (dst, src) in slot.iter_mut().zip(value.to_le_bytes()) {
                *dst = src;
            }
            true
        }
        None => false,
    }
}

/// The finished bands of one picture, encoded, in the caller's memory.
pub struct BandCache<'a> {
    starts: &'a mut [u8],
    tokens: &'a mut [u8],
    used: usize,
    cached: u16,
}

impl<'a> BandCache<'a> {
    /// Bytes of the start table of `bands` bands.
    pub const fn table_bytes(bands: u16) -> usize {
        bands as usize * START_BYTES
    }

    /// A cache of `bands` bands in `memory`: the start table, then the
    /// tokens. `None` when `memory` does not hold the table.
    pub fn new(memory: &'a mut [u8], bands: u16) -> Option<BandCache<'a>> {
        let (starts, tokens) = memory.split_at_mut_checked(Self::table_bytes(bands))?;
        let mut cache = BandCache {
            starts,
            tokens,
            used: 0,
            cached: 0,
        };
        cache.clear();
        Some(cache)
    }

    /// Drop every band.
    pub fn clear(&mut self) {
        self.starts.fill(0xFF);
        self.used = 0;
        self.cached = 0;
    }

    /// Bytes the tokens may take.
    pub fn capacity(&self) -> usize {
        self.tokens.len()
    }

    /// Bytes the cached bands take.
    pub fn used(&self) -> usize {
        self.used
    }

    /// Bands cached.
    pub fn cached(&self) -> u16 {
        self.cached
    }

    fn start(&self, band: u16) -> Option<usize> {
        let at = usize::from(band) * START_BYTES;
        match self.starts.get(at..at + START_BYTES) {
            Some(&[a, b, c, d]) => {
                let start = u32::from_le_bytes([a, b, c, d]);
                (start != ABSENT).then_some(start as usize)
            }
            _ => None,
        }
    }

    /// Whether band `band` is cached.
    pub fn holds(&self, band: u16) -> bool {
        self.start(band).is_some()
    }

    /// Cache band `band` from `pixels`, the RGB565 bytes it was sent as.
    /// Whether it is cached: false when it already is, when its number is
    /// past the table, or when its encoding does not fit what is left.
    pub fn encode(&mut self, band: u16, pixels: &[u8]) -> bool {
        let entry = usize::from(band) * START_BYTES;
        if self.starts.get(entry..entry + START_BYTES).is_none() || self.holds(band) {
            return false;
        }
        let start = self.used;
        let Ok(start32) = u32::try_from(start) else {
            return false;
        };
        let tokens = &mut *self.tokens;
        let mut at = start;
        let whole = walk(pixels, |t| {
            if at + t.bytes() > tokens.len() {
                return false;
            }
            match t {
                Token::Run { count, value } => {
                    put(tokens, at, RUN | count as u16);
                    put(tokens, at + 2, value);
                }
                Token::Literal { first, count } => {
                    put(tokens, at, count as u16);
                    let (from, to) = (2 * first, at + 2);
                    if let (Some(src), Some(dst)) = (
                        pixels.get(from..from + 2 * count),
                        tokens.get_mut(to..to + 2 * count),
                    ) {
                        // SAFETY: both are `2 * count` bytes; `src` is the
                        // caller's band and `dst` the cache's memory, which
                        // the caller cannot hold while `self` is borrowed.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                src.as_ptr(),
                                dst.as_mut_ptr(),
                                src.len(),
                            )
                        };
                    }
                }
            }
            at += t.bytes();
            true
        });
        if !whole {
            return false;
        }
        if let Some(slot) = self.starts.get_mut(entry..entry + START_BYTES) {
            for (dst, src) in slot.iter_mut().zip(start32.to_le_bytes()) {
                *dst = src;
            }
        }
        self.used = at;
        self.cached += 1;
        true
    }

    /// Write band `band` into `out`, the bytes it was encoded from, whole.
    /// Whether it was cached; `out` is untouched when it was not.
    pub fn decode(&self, band: u16, out: &mut [u8]) -> bool {
        let Some(mut at) = self.start(band) else {
            return false;
        };
        let tokens = &*self.tokens;
        let word = |at: usize| pixel(tokens.get(at..).unwrap_or(&[]), 0);
        let mut done = 0;
        while done < out.len() {
            let head = word(at);
            let count = usize::from(head & !RUN);
            if count == 0 {
                return true;
            }
            let bytes = 2 * count;
            let Some(dst) = out.get_mut(done..done + bytes) else {
                return true;
            };
            if head & RUN != 0 {
                let value = word(at + 2);
                fill(dst, value);
                at += 4;
            } else {
                let Some(src) = tokens.get(at + 2..at + 2 + bytes) else {
                    return true;
                };
                // SAFETY: `src` and `dst` are `bytes` long, and `src` lies
                // in the cache's memory, which `out` cannot alias while
                // `self` is borrowed.
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), bytes) };
                at += 2 + bytes;
            }
            done += bytes;
        }
        true
    }
}

/// Fill `out` with RGB565 `value`, two pixels a word.
fn fill(out: &mut [u8], value: u16) {
    let pair = (u32::from(value) | u32::from(value) << 16).to_le_bytes();
    let mut words = out.chunks_exact_mut(4);
    for word in &mut words {
        if let Ok(w) = <&mut [u8; 4]>::try_from(word) {
            *w = pair;
        }
    }
    for (dst, src) in words.into_remainder().iter_mut().zip(pair) {
        *dst = src;
    }
}

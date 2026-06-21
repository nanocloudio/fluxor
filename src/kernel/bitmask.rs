//! Width-parameterized module bitmask (rfc_k8s.md §10.4).
//!
//! A single `u64` holds one bit per module but hard-caps `MAX_MODULES` at 64.
//! `ModuleMask` generalises that bitmap to any `MAX_MODULES` by backing it with
//! `[u64; MODULE_MASK_WORDS]`, while collapsing to a single word — identical
//! codegen to a bare `u64` — when `MAX_MODULES <= 64`.
//!
//! The `from_u64`/`as_u64` shims bridge call sites that still hold a bare `u64`
//! mask, so each can adopt `ModuleMask` independently.

use crate::kernel::config::MAX_MODULES;

/// Number of 64-bit words needed to hold one bit per module.
pub const MODULE_MASK_WORDS: usize = MAX_MODULES.div_ceil(64);

const _: () = assert!(
    MODULE_MASK_WORDS * 64 >= MAX_MODULES,
    "MODULE_MASK_WORDS must cover MAX_MODULES"
);

/// A fixed-width bitmap with one bit per module index `0..MAX_MODULES`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ModuleMask {
    words: [u64; MODULE_MASK_WORDS],
}

impl ModuleMask {
    /// All bits clear.
    pub const EMPTY: ModuleMask = ModuleMask {
        words: [0; MODULE_MASK_WORDS],
    };

    /// Construct an empty mask.
    #[inline]
    pub const fn new() -> Self {
        Self::EMPTY
    }

    /// Set the bit for `idx`.
    #[inline]
    pub fn set(&mut self, idx: usize) {
        debug_assert!(idx < MAX_MODULES, "module index out of range");
        self.words[idx / 64] |= 1u64 << (idx % 64);
    }

    /// Clear the bit for `idx`.
    #[inline]
    pub fn clear(&mut self, idx: usize) {
        debug_assert!(idx < MAX_MODULES, "module index out of range");
        self.words[idx / 64] &= !(1u64 << (idx % 64));
    }

    /// Test the bit for `idx`.
    #[inline]
    pub fn test(&self, idx: usize) -> bool {
        debug_assert!(idx < MAX_MODULES, "module index out of range");
        (self.words[idx / 64] >> (idx % 64)) & 1 != 0
    }

    /// Clear every bit.
    #[inline]
    pub fn clear_all(&mut self) {
        self.words = [0; MODULE_MASK_WORDS];
    }

    /// True when no bit is set.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    /// Number of set bits.
    #[inline]
    pub fn count_ones(&self) -> u32 {
        self.words.iter().map(|w| w.count_ones()).sum()
    }

    /// `self |= other`.
    #[inline]
    pub fn or_assign(&mut self, other: &ModuleMask) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a |= *b;
        }
    }

    /// `self &= other`.
    #[inline]
    pub fn and_assign(&mut self, other: &ModuleMask) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a &= *b;
        }
    }

    /// Iterate set bit indices in ascending order. Cost is O(set bits):
    /// all-zero words are skipped a word at a time.
    pub fn iter_set(&self) -> impl Iterator<Item = usize> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(w, &word)| BitIter { word, base: w * 64 })
    }

    /// True when `self` and `other` share at least one set bit. Replaces the
    /// `(a & b) != 0` idiom on the old `u64` masks.
    #[inline]
    pub fn intersects(&self, other: &ModuleMask) -> bool {
        self.words
            .iter()
            .zip(other.words.iter())
            .any(|(a, b)| (a & b) != 0)
    }

    /// Build directly from raw words (used by the multi-word atomic
    /// event-wake path in `kernel/event.rs`).
    #[inline]
    pub fn from_words(words: [u64; MODULE_MASK_WORDS]) -> Self {
        ModuleMask { words }
    }

    /// Build from a raw `u64` (migration shim for the single-word case).
    #[inline]
    pub fn from_u64(bits: u64) -> Self {
        let mut m = Self::EMPTY;
        m.words[0] = bits;
        m
    }

    /// Low 64 bits (migration shim for call sites still on `u64`).
    #[inline]
    pub fn as_u64(&self) -> u64 {
        self.words[0]
    }
}

impl Default for ModuleMask {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Iterator over the set bits of a single word, offset by `base`.
struct BitIter {
    word: u64,
    base: usize,
}

impl Iterator for BitIter {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.word == 0 {
            return None;
        }
        let bit = self.word.trailing_zeros() as usize;
        self.word &= self.word - 1; // clear lowest set bit
        Some(self.base + bit)
    }
}

//! A fixed pool of pages with a bitmap: first-fit runs, a real free.
//!
//! The isolated-module arena is one ([`crate::kernel::module::loader`]): an
//! isolated module's state, heap and EL0 stack each own whole pages, which
//! go back to the pool when the module goes, so a node can admit and reap
//! workloads for its whole life. The map holds only which pages are held;
//! the memory and its zeroing are the owner's.

/// `WORDS × 64` pages, one bit each, set while held.
pub struct PageMap<const WORDS: usize> {
    bits: [u64; WORDS],
}

impl<const WORDS: usize> Default for PageMap<WORDS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const WORDS: usize> PageMap<WORDS> {
    /// Pages in the map.
    pub const PAGES: usize = WORDS * 64;

    /// Every page free.
    pub const fn new() -> Self {
        Self { bits: [0; WORDS] }
    }

    /// Whether `page` is held.
    pub fn held(&self, page: usize) -> bool {
        self.bits[page / 64] & (1u64 << (page % 64)) != 0
    }

    fn mark(&mut self, first: usize, n: usize, held: bool) {
        for page in first..first + n {
            if held {
                self.bits[page / 64] |= 1u64 << (page % 64);
            } else {
                self.bits[page / 64] &= !(1u64 << (page % 64));
            }
        }
    }

    /// Hold the first run of `n` free pages: its first page, or `None` when
    /// no run holds `n` (or `n` is 0).
    pub fn alloc(&mut self, n: usize) -> Option<usize> {
        if n == 0 {
            return None;
        }
        let mut run = 0usize;
        for page in 0..Self::PAGES {
            if self.held(page) {
                run = 0;
            } else {
                run += 1;
                if run == n {
                    let first = page + 1 - n;
                    self.mark(first, n, true);
                    return Some(first);
                }
            }
        }
        None
    }

    /// Whether all `n` pages from `first` are held (and in range).
    pub fn holds(&self, first: usize, n: usize) -> bool {
        first
            .checked_add(n)
            .is_some_and(|end| n != 0 && end <= Self::PAGES && (first..end).all(|p| self.held(p)))
    }

    /// Free `n` pages from `first`. `false`, freeing nothing, when the run
    /// is out of range or not wholly held: a double or stray free.
    pub fn free(&mut self, first: usize, n: usize) -> bool {
        if !self.holds(first, n) {
            return false;
        }
        self.mark(first, n, false);
        true
    }

    /// Pages held.
    pub fn in_use(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Every page free.
    pub fn clear(&mut self) {
        self.bits = [0; WORDS];
    }
}

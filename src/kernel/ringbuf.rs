//! Shared ring buffer state for FIFO channels.
/// Tracks head/tail/len for a circular byte buffer.
///
/// Storage is external — callers pass a `&[u8]` or `&mut [u8]` slice
/// that backs the ring. Used by channel FIFOs (arena-allocated buffer,
/// capacity set at open time).
///
/// Capacity MUST be a power of two. This allows wrap-around to use
/// bitwise AND (`& cap_mask`) instead of modulo division — saving
/// ~20-40 cycles per read/write on Cortex-M33 (no hardware divider).
pub struct RingBufState {
    head: usize,
    tail: usize,
    len: usize,
    cap: usize,
    /// cap - 1, used for wrapping: `index & cap_mask` instead of `index % cap`
    cap_mask: usize,
}
impl Default for RingBufState {
    fn default() -> Self {
        Self::new()
    }
}
impl RingBufState {
    /// Create a zero-capacity state (must call `init` before use).
    pub const fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            len: 0,
            cap: 0,
            cap_mask: 0,
        }
    }
    /// Create a state with known capacity (for inline buffers).
    /// `cap` must be a power of two.
    pub const fn with_capacity(cap: usize) -> Self {
        Self {
            head: 0,
            tail: 0,
            len: 0,
            cap,
            cap_mask: if cap > 0 { cap - 1 } else { 0 },
        }
    }
    /// (Re-)initialise with a given capacity and reset pointers.
    /// `cap` must be a power of two.
    pub fn init(&mut self, cap: usize) {
        debug_assert!(
            cap == 0 || cap.is_power_of_two(),
            "ring buffer cap must be power of 2"
        );
        self.head = 0;
        self.tail = 0;
        self.len = 0;
        self.cap = cap;
        self.cap_mask = if cap > 0 { cap - 1 } else { 0 };
    }
    /// Write `data` into `storage`, returning bytes written.
    pub fn write(&mut self, storage: &mut [u8], data: &[u8]) -> usize {
        let cap = self.cap;
        if cap == 0 {
            return 0;
        }
        // Defensive normalisation. The wrap arithmetic below relies
        // on `head/tail < cap` and `len <= cap`; if any field
        // desyncs from its `& cap_mask` invariant (rogue write,
        // corrupted state, future code bypassing `write`), an
        // unbounded index could panic and a corrupted `len > cap`
        // would underflow `cap - self.len` into a huge `avail`. The
        // debug assert catches corruption at its source; release
        // builds silently re-establish the invariants.
        debug_assert!(
            self.tail < cap && self.head < cap && self.len <= cap,
            "ringbuf: head/tail/len invariants (head={}, tail={}, len={}, cap={})",
            self.head,
            self.tail,
            self.len,
            cap,
        );
        self.tail &= self.cap_mask;
        self.head &= self.cap_mask;
        if self.len > cap {
            self.len = cap;
        }
        let avail = cap - self.len;
        // All-or-nothing: partial writes corrupt byte-stream framing
        // (e.g. net_proto between NIC driver and IP module).
        if data.len() > avail {
            return 0;
        }
        let total = data.len();
        if total == 0 {
            return 0;
        }
        let first = total.min(cap - self.tail);
        storage[self.tail..self.tail + first].copy_from_slice(&data[..first]);
        if first < total {
            let second = total - first;
            storage[..second].copy_from_slice(&data[first..first + second]);
        }
        self.tail = (self.tail + total) & self.cap_mask;
        self.len += total;
        total
    }
    /// Read into `out` from `storage`, returning bytes read.
    pub fn read(&mut self, storage: &[u8], out: &mut [u8]) -> usize {
        let cap = self.cap;
        if cap == 0 {
            return 0;
        }
        // See `write` — same defensive normalisation against any
        // desync of head/tail/len with their invariants.
        debug_assert!(
            self.tail < cap && self.head < cap && self.len <= cap,
            "ringbuf: head/tail/len invariants (head={}, tail={}, len={}, cap={})",
            self.head,
            self.tail,
            self.len,
            cap,
        );
        self.tail &= self.cap_mask;
        self.head &= self.cap_mask;
        if self.len > cap {
            self.len = cap;
        }
        let total = out.len().min(self.len);
        if total == 0 {
            return 0;
        }
        let first = total.min(cap - self.head);
        out[..first].copy_from_slice(&storage[self.head..self.head + first]);
        if first < total {
            let second = total - first;
            out[first..first + second].copy_from_slice(&storage[..second]);
        }
        self.head = (self.head + total) & self.cap_mask;
        self.len -= total;
        total
    }
    /// Copy up to `out.len()` bytes from the head of the ring into
    /// `out` WITHOUT advancing the read pointer. Used by frame-aware
    /// fan modules to inspect a length-prefixed header before
    /// committing to consume the full frame. Returns bytes copied.
    pub fn peek(&self, storage: &[u8], out: &mut [u8]) -> usize {
        let cap = self.cap;
        if cap == 0 {
            return 0;
        }
        // Clamp len to cap and head via the mask. `peek` is `&self`
        // so we can't normalise the fields in place, but we can
        // bound the slice indices computed from them.
        let safe_len = self.len.min(cap);
        let safe_head = self.head & self.cap_mask;
        let total = out.len().min(safe_len);
        if total == 0 {
            return 0;
        }
        let first = total.min(cap - safe_head);
        out[..first].copy_from_slice(&storage[safe_head..safe_head + first]);
        if first < total {
            let second = total - first;
            out[first..first + second].copy_from_slice(&storage[..second]);
        }
        total
    }
    /// Bytes available to read. Clamps to `cap` so a corrupted
    /// `len > cap` cannot propagate an oversized "readable" report
    /// through `channel_readable_bytes` to module code.
    #[inline]
    pub fn len(&self) -> usize {
        self.len.min(self.cap)
    }
    /// True when no bytes are available to read.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Buffer capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }
    /// Free space available for writing. `saturating_sub` matches
    /// the other accessors so a corrupted `len > cap` cannot
    /// underflow into a wildly oversized free-space report visible
    /// through `channel_space`.
    #[inline]
    pub fn space(&self) -> usize {
        self.cap.saturating_sub(self.len)
    }
    #[inline]
    pub fn is_readable(&self) -> bool {
        self.len > 0
    }
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.cap > 0 && self.len < self.cap
    }
    /// Reset pointers without changing capacity.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }
}

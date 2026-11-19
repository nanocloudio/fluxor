//! Shared ring buffer state for FIFO channels.
//!
//! The ring holds records: every [`RingBufState::write`] stores
//! `[len u16 LE][payload]`, a write over [`RECORD_MAX`] bytes as several
//! records. Reads, peeks and skips are a byte stream over the payload that
//! consume a prefix as they cross it, so a consumer that frames by its own
//! headers sees what it always saw, and one that frames by records asks
//! [`RingBufState::record_len`].

/// Bytes of ring a record's length prefix takes.
pub const RECORD_PREFIX: usize = fluxor_contracts::ring_size::RECORD_PREFIX_BYTES as usize;
/// The longest record one prefix states; a longer write is several records.
pub const RECORD_MAX: usize = fluxor_contracts::ring_size::RECORD_MAX_BYTES as usize;
const _: () = assert!(RECORD_MAX <= u16::MAX as usize);

/// Ring bytes a write of `n` payload bytes takes: the payload and one prefix
/// per record it becomes.
pub const fn record_footprint(n: usize) -> usize {
    n + RECORD_PREFIX * n.div_ceil(RECORD_MAX)
}

/// The largest write `space` free bytes of ring take whole.
pub const fn payload_fits(space: usize) -> usize {
    let whole = space / (RECORD_MAX + RECORD_PREFIX);
    let rest = space % (RECORD_MAX + RECORD_PREFIX);
    whole * RECORD_MAX + rest.saturating_sub(RECORD_PREFIX)
}

/// Tracks head/tail and the records of a circular byte buffer.
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
    /// Ring bytes in use: payload and the prefixes not yet consumed.
    used: usize,
    /// Payload bytes buffered.
    data: usize,
    /// Unread payload bytes of the record at the head whose prefix has been
    /// consumed; 0 when the next byte at the head is a prefix.
    rec_left: usize,
    cap: usize,
    /// cap - 1, used for wrapping: `index & cap_mask` instead of `index % cap`
    cap_mask: usize,
}
impl Default for RingBufState {
    fn default() -> Self {
        Self::new()
    }
}

/// Copy `out.len()` bytes of the ring from `at` (wrapping).
#[inline]
fn copy_out(storage: &[u8], cap: usize, at: usize, out: &mut [u8]) {
    let first = out.len().min(cap - at);
    out[..first].copy_from_slice(&storage[at..at + first]);
    if first < out.len() {
        let rest = out.len() - first;
        out[first..].copy_from_slice(&storage[..rest]);
    }
}

/// Copy `bytes` into the ring at `at` (wrapping).
#[inline]
fn copy_in(storage: &mut [u8], cap: usize, at: usize, bytes: &[u8]) {
    let first = bytes.len().min(cap - at);
    storage[at..at + first].copy_from_slice(&bytes[..first]);
    if first < bytes.len() {
        let rest = bytes.len() - first;
        storage[..rest].copy_from_slice(&bytes[first..]);
    }
}

impl RingBufState {
    /// Create a zero-capacity state (must call `init` before use).
    pub const fn new() -> Self {
        Self::with_capacity(0)
    }
    /// Create a state with known capacity (for inline buffers).
    /// `cap` must be a power of two.
    pub const fn with_capacity(cap: usize) -> Self {
        Self {
            head: 0,
            tail: 0,
            used: 0,
            data: 0,
            rec_left: 0,
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
        *self = Self::with_capacity(cap);
    }

    /// Whether the fields hold the ring's invariants. Every mutator checks
    /// it first and refuses to act on a ring that does not: an index past
    /// the capacity would panic, and a count past it would underflow.
    #[inline]
    fn sound(&self) -> bool {
        let ok = self.cap > 0
            && self.head < self.cap
            && self.tail < self.cap
            && self.used <= self.cap
            && self.data <= self.used
            && self.rec_left <= self.data;
        debug_assert!(
            self.cap == 0 || ok,
            "ringbuf invariants (head={}, tail={}, used={}, data={}, rec_left={}, cap={})",
            self.head,
            self.tail,
            self.used,
            self.data,
            self.rec_left,
            self.cap,
        );
        ok
    }

    /// The length prefix at the head (the caller knows one is there).
    #[inline]
    fn prefix_at_head(&self, storage: &[u8]) -> usize {
        let mut p = [0u8; RECORD_PREFIX];
        copy_out(storage, self.cap, self.head, &mut p);
        u16::from_le_bytes(p) as usize
    }

    /// Write `data` into `storage` as one record (several past
    /// [`RECORD_MAX`]), whole or not at all: returns `data.len()`, or 0 when
    /// it does not fit (a partial write would corrupt the stream's framing)
    /// or is empty.
    pub fn write(&mut self, storage: &mut [u8], data: &[u8]) -> usize {
        if data.is_empty() || !self.sound() {
            return 0;
        }
        if record_footprint(data.len()) > self.cap - self.used {
            return 0;
        }
        for rec in data.chunks(RECORD_MAX) {
            copy_in(
                storage,
                self.cap,
                self.tail,
                &(rec.len() as u16).to_le_bytes(),
            );
            self.tail = (self.tail + RECORD_PREFIX) & self.cap_mask;
            copy_in(storage, self.cap, self.tail, rec);
            self.tail = (self.tail + rec.len()) & self.cap_mask;
            self.used += RECORD_PREFIX + rec.len();
        }
        self.data += data.len();
        data.len()
    }

    /// Walk `n` payload bytes from the head, crossing prefixes, without
    /// changing anything: hands each payload run's ring offset and length to
    /// `f`, and answers the head, `used`, `rec_left` the walk ends at.
    /// `n` must be at most `self.data`.
    #[inline]
    fn walk(
        &self,
        storage: &[u8],
        mut n: usize,
        mut f: impl FnMut(usize, usize),
    ) -> (usize, usize, usize) {
        let (mut head, mut used, mut rec_left) = (self.head, self.used, self.rec_left);
        while n > 0 {
            if rec_left == 0 {
                let mut p = [0u8; RECORD_PREFIX];
                copy_out(storage, self.cap, head, &mut p);
                rec_left = u16::from_le_bytes(p) as usize;
                head = (head + RECORD_PREFIX) & self.cap_mask;
                used -= RECORD_PREFIX;
            }
            let take = n.min(rec_left);
            f(head, take);
            head = (head + take) & self.cap_mask;
            used -= take;
            rec_left -= take;
            n -= take;
        }
        (head, used, rec_left)
    }

    /// Read into `out` from `storage`, returning payload bytes read.
    pub fn read(&mut self, storage: &[u8], out: &mut [u8]) -> usize {
        if !self.sound() {
            return 0;
        }
        let total = out.len().min(self.data);
        let mut at = 0;
        let cap = self.cap;
        let (head, used, rec_left) = self.walk(storage, total, |from, len| {
            copy_out(storage, cap, from, &mut out[at..at + len]);
            at += len;
        });
        self.head = head;
        self.used = used;
        self.rec_left = rec_left;
        self.data -= total;
        self.settle();
        total
    }

    /// Copy up to `out.len()` payload bytes from the head of the ring into
    /// `out` WITHOUT advancing the read pointer. Used by frame-aware
    /// consumers to inspect a header before committing to consume the full
    /// frame. Returns bytes copied.
    pub fn peek(&self, storage: &[u8], out: &mut [u8]) -> usize {
        if !self.sound() {
            return 0;
        }
        let total = out.len().min(self.data);
        let mut at = 0;
        let cap = self.cap;
        self.walk(storage, total, |from, len| {
            copy_out(storage, cap, from, &mut out[at..at + len]);
            at += len;
        });
        total
    }

    /// Drop exactly `n` payload bytes from the head of the ring without
    /// copying them. All or nothing: returns `true` and advances the head
    /// when `n` bytes are buffered, `false` and leaves the ring untouched
    /// when fewer are. A skip that crosses a record boundary reads the next
    /// record's prefix from `storage`.
    pub fn skip(&mut self, storage: &[u8], n: usize) -> bool {
        if n == 0 {
            return true;
        }
        if !self.sound() || n > self.data {
            return false;
        }
        let (head, used, rec_left) = self.walk(storage, n, |_, _| {});
        self.head = head;
        self.used = used;
        self.rec_left = rec_left;
        self.data -= n;
        self.settle();
        true
    }

    /// An empty ring starts over at offset 0, so the next record lands whole
    /// in one run where it can.
    #[inline]
    fn settle(&mut self) {
        if self.used == 0 {
            self.head = 0;
            self.tail = 0;
        }
    }

    /// The unread payload bytes of the record at the head, or 0 when nothing
    /// is buffered.
    pub fn record_len(&self, storage: &[u8]) -> usize {
        if !self.sound() || self.data == 0 {
            return 0;
        }
        if self.rec_left > 0 {
            self.rec_left
        } else {
            self.prefix_at_head(storage)
        }
    }

    /// Payload bytes available to read.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.min(self.cap)
    }
    /// True when no bytes are available to read.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data == 0
    }
    /// Buffer capacity in ring bytes.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }
    /// Free ring bytes: prefixes included, so a write takes up to
    /// [`RingBufState::writable`] of payload.
    #[inline]
    pub fn space(&self) -> usize {
        self.cap.saturating_sub(self.used)
    }
    /// The largest write that fits now.
    #[inline]
    pub fn writable(&self) -> usize {
        payload_fits(self.space())
    }
    #[inline]
    pub fn is_readable(&self) -> bool {
        self.data > 0
    }
    /// Whether a one-byte write fits.
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.cap > 0 && self.space() > RECORD_PREFIX
    }
    /// Reset pointers without changing capacity.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.used = 0;
        self.data = 0;
        self.rec_left = 0;
    }
}

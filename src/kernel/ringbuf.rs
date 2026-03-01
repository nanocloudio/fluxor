//! Shared ring buffer state for FIFO channels and sockets.

/// Tracks head/tail/len for a circular byte buffer.
///
/// Storage is external — callers pass a `&[u8]` or `&mut [u8]` slice
/// that backs the ring. This lets the same logic serve both:
/// - channel FIFO (arena-allocated buffer, capacity set at open time)
/// - socket TX/RX (inline `[u8; N]` array)
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

impl RingBufState {
    /// Create a zero-capacity state (must call `init` before use).
    pub const fn new() -> Self {
        Self { head: 0, tail: 0, len: 0, cap: 0, cap_mask: 0 }
    }

    /// Create a state with known capacity (for inline buffers).
    /// `cap` must be a power of two.
    pub const fn with_capacity(cap: usize) -> Self {
        Self { head: 0, tail: 0, len: 0, cap, cap_mask: if cap > 0 { cap - 1 } else { 0 } }
    }

    /// (Re-)initialise with a given capacity and reset pointers.
    /// `cap` must be a power of two.
    pub fn init(&mut self, cap: usize) {
        debug_assert!(cap == 0 || cap.is_power_of_two(), "ring buffer cap must be power of 2");
        self.head = 0;
        self.tail = 0;
        self.len = 0;
        self.cap = cap;
        self.cap_mask = if cap > 0 { cap - 1 } else { 0 };
    }

    /// Write `data` into `storage`, returning bytes written.
    pub fn write(&mut self, storage: &mut [u8], data: &[u8]) -> usize {
        let cap = self.cap;
        if cap == 0 { return 0; }
        let avail = cap - self.len;
        let total = data.len().min(avail);
        if total == 0 { return 0; }

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
        if cap == 0 { return 0; }
        let total = out.len().min(self.len);
        if total == 0 { return 0; }

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

    /// Bytes available to read.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Buffer capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Free space available for writing.
    #[inline]
    pub fn space(&self) -> usize {
        self.cap - self.len
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_zero_capacity() {
        let r = RingBufState::new();
        assert_eq!(r.capacity(), 0);
        assert_eq!(r.len(), 0);
        assert_eq!(r.space(), 0);
        assert!(!r.is_readable());
        assert!(!r.is_writable());
    }

    #[test]
    fn with_capacity_sets_cap() {
        let r = RingBufState::with_capacity(64);
        assert_eq!(r.capacity(), 64);
        assert_eq!(r.len(), 0);
        assert_eq!(r.space(), 64);
        assert!(!r.is_readable());
        assert!(r.is_writable());
    }

    #[test]
    fn write_read_basic() {
        let mut r = RingBufState::with_capacity(8);
        let mut storage = [0u8; 8];

        let written = r.write(&mut storage, &[1, 2, 3]);
        assert_eq!(written, 3);
        assert_eq!(r.len(), 3);
        assert_eq!(r.space(), 5);

        let mut out = [0u8; 4];
        let read = r.read(&storage, &mut out);
        assert_eq!(read, 3);
        assert_eq!(&out[..3], &[1, 2, 3]);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn write_clamps_to_available_space() {
        let mut r = RingBufState::with_capacity(4);
        let mut storage = [0u8; 4];

        let written = r.write(&mut storage, &[1, 2, 3, 4, 5, 6]);
        assert_eq!(written, 4);
        assert_eq!(r.len(), 4);
        assert!(!r.is_writable());
    }

    #[test]
    fn read_clamps_to_available_data() {
        let mut r = RingBufState::with_capacity(8);
        let mut storage = [0u8; 8];
        r.write(&mut storage, &[10, 20]);

        let mut out = [0u8; 8];
        let read = r.read(&storage, &mut out);
        assert_eq!(read, 2);
        assert_eq!(&out[..2], &[10, 20]);
    }

    #[test]
    fn wrap_around_write_read() {
        let mut r = RingBufState::with_capacity(4);
        let mut storage = [0u8; 4];

        // Fill and partially drain to advance head/tail
        r.write(&mut storage, &[1, 2, 3]);
        let mut out = [0u8; 2];
        r.read(&storage, &mut out);
        assert_eq!(&out, &[1, 2]);
        // head=2, tail=3, len=1

        // Write wraps around end of buffer
        let written = r.write(&mut storage, &[4, 5, 6]);
        assert_eq!(written, 3); // space was 3
        assert_eq!(r.len(), 4);

        // Read wraps around end of buffer
        let mut out2 = [0u8; 4];
        let read = r.read(&storage, &mut out2);
        assert_eq!(read, 4);
        assert_eq!(&out2, &[3, 4, 5, 6]);
    }

    #[test]
    fn zero_capacity_operations_are_nops() {
        let mut r = RingBufState::new();
        let mut storage = [0u8; 0];
        assert_eq!(r.write(&mut storage, &[1, 2]), 0);
        let mut out = [0u8; 2];
        assert_eq!(r.read(&storage, &mut out), 0);
    }

    #[test]
    fn clear_resets_pointers_keeps_capacity() {
        let mut r = RingBufState::with_capacity(8);
        let mut storage = [0u8; 8];
        r.write(&mut storage, &[1, 2, 3]);

        r.clear();
        assert_eq!(r.capacity(), 8);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn multiple_small_writes_and_reads() {
        let mut r = RingBufState::with_capacity(8);
        let mut storage = [0u8; 8];

        r.write(&mut storage, &[1]);
        r.write(&mut storage, &[2]);
        r.write(&mut storage, &[3]);
        assert_eq!(r.len(), 3);

        let mut out = [0u8; 1];
        r.read(&storage, &mut out);
        assert_eq!(out[0], 1);
        r.read(&storage, &mut out);
        assert_eq!(out[0], 2);
        r.read(&storage, &mut out);
        assert_eq!(out[0], 3);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn full_cycle_stress() {
        let mut r = RingBufState::with_capacity(4);
        let mut storage = [0u8; 4];
        let mut out = [0u8; 4];

        // Repeatedly fill and drain to exercise wrap-around
        for cycle in 0u8..20 {
            let data = [cycle, cycle + 1, cycle + 2, cycle + 3];
            assert_eq!(r.write(&mut storage, &data), 4);
            assert_eq!(r.read(&storage, &mut out), 4);
            assert_eq!(out, data);
            assert_eq!(r.len(), 0);
        }
    }
}

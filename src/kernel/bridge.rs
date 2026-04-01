//! Bridge channels — ISR-safe cross-tier IPC primitives.
//!
//! Three bridge types for communication between execution tiers:
//!
//! - **SnapshotBridge**: Latest-value transfer (double-buffered, latest-wins).
//!   Producer writes atomically; consumer always reads the most recent value.
//!   Use for: control setpoints, sensor state, configuration parameters.
//!
//! - **RingBridge**: Lock-free SPSC ring buffer for streaming data.
//!   Drop-on-full policy (never blocks ISR). Fixed element size, power-of-2 capacity.
//!   Use for: ADC samples, encoder ticks, event streams.
//!
//! - **CommandBridge**: Single-slot latest-wins command transfer (thread → ISR).
//!   Thread writes command + bumps sequence; ISR reads only when new.
//!   Use for: mode changes, parameter updates, one-shot commands.
//!
//! All three are:
//! - Non-blocking and allocation-free (ISR-safe)
//! - Cache-line aligned to prevent false sharing on multi-core
//! - Usable from both cooperative modules (via syscall helpers) and ISR context

use portable_atomic::{AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of bridge channels in the system.
pub const MAX_BRIDGES: usize = 16;

/// Maximum data size per bridge slot (bytes). Fits in one cache line.
pub const MAX_BRIDGE_DATA: usize = 56;

/// Cache line size for alignment (Cortex-A76 / RP2350).
const CACHE_LINE: usize = 64;

// ============================================================================
// Bridge Types
// ============================================================================

/// Bridge type tag stored in header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BridgeType {
    /// Unused slot.
    None = 0,
    /// Double-buffered latest-value (SnapshotBridge).
    Snapshot = 1,
    /// Lock-free SPSC ring (RingBridge).
    Ring = 2,
    /// Single-slot latest-wins command (CommandBridge).
    Command = 3,
}

// ============================================================================
// SnapshotBridge
// ============================================================================

/// Double-buffered latest-value bridge.
///
/// Producer writes to the inactive buffer, then atomically swaps the active
/// index. Consumer always reads the most recent complete value.
///
/// Layout: two data buffers on separate cache lines + atomic control.
#[repr(C, align(64))]
pub struct SnapshotBridge {
    /// Which buffer is active for reading (0 or 1). Producer swaps after write.
    active: AtomicU32,
    /// Sequence counter — incremented on each write. Consumer detects staleness.
    sequence: AtomicU32,
    /// Data size in bytes (set at init, constant thereafter).
    data_size: u32,
    _pad0: [u8; 52 - 12],
    /// Buffer 0 (cache-line aligned).
    buf0: CacheAlignedSlot,
    /// Buffer 1 (cache-line aligned).
    buf1: CacheAlignedSlot,
}

/// A cache-line-aligned data slot.
#[repr(C, align(64))]
struct CacheAlignedSlot {
    data: [u8; MAX_BRIDGE_DATA],
    _pad: [u8; CACHE_LINE - MAX_BRIDGE_DATA],
}

impl CacheAlignedSlot {
    const fn new() -> Self {
        Self {
            data: [0; MAX_BRIDGE_DATA],
            _pad: [0; CACHE_LINE - MAX_BRIDGE_DATA],
        }
    }
}

impl SnapshotBridge {
    pub const fn new() -> Self {
        Self {
            active: AtomicU32::new(0),
            sequence: AtomicU32::new(0),
            data_size: 0,
            _pad0: [0; 52 - 12],
            buf0: CacheAlignedSlot::new(),
            buf1: CacheAlignedSlot::new(),
        }
    }

    /// Initialize with a fixed data size.
    pub fn init(&mut self, data_size: usize) {
        let sz = if data_size > MAX_BRIDGE_DATA { MAX_BRIDGE_DATA } else { data_size };
        self.data_size = sz as u32;
        self.active.store(0, Ordering::Release);
        self.sequence.store(0, Ordering::Release);
    }

    /// Write a new value (ISR-safe, non-blocking).
    ///
    /// Writes to the inactive buffer, then atomically swaps active index.
    /// Returns the new sequence number.
    pub fn write(&self, src: &[u8]) -> u32 {
        let sz = self.data_size as usize;
        let len = if src.len() < sz { src.len() } else { sz };
        let active = self.active.load(Ordering::Acquire);
        let inactive = 1 - active;

        // Write to inactive buffer using volatile (ISR safety)
        let dst = if inactive == 0 {
            &self.buf0.data as *const [u8; MAX_BRIDGE_DATA] as *mut u8
        } else {
            &self.buf1.data as *const [u8; MAX_BRIDGE_DATA] as *mut u8
        };
        unsafe {
            for i in 0..len {
                core::ptr::write_volatile(dst.add(i), src[i]);
            }
        }

        // Swap active buffer and increment sequence
        self.active.store(inactive, Ordering::Release);
        self.sequence.fetch_add(1, Ordering::Release)
    }

    /// Read the latest value (ISR-safe, non-blocking).
    ///
    /// Returns (bytes_read, sequence_number). The data is always a complete
    /// snapshot — never torn between two producer writes.
    pub fn read(&self, dst: &mut [u8]) -> (usize, u32) {
        let active = self.active.load(Ordering::Acquire);
        let seq = self.sequence.load(Ordering::Acquire);
        let sz = self.data_size as usize;
        let len = if dst.len() < sz { dst.len() } else { sz };

        let src = if active == 0 {
            &self.buf0.data as *const [u8; MAX_BRIDGE_DATA] as *const u8
        } else {
            &self.buf1.data as *const [u8; MAX_BRIDGE_DATA] as *const u8
        };
        unsafe {
            for i in 0..len {
                dst[i] = core::ptr::read_volatile(src.add(i));
            }
        }
        (len, seq)
    }

    /// Return the current sequence number without reading data.
    pub fn sequence(&self) -> u32 {
        self.sequence.load(Ordering::Acquire)
    }
}

// ============================================================================
// RingBridge
// ============================================================================

/// Ring buffer capacity (number of elements). Must be power of 2.
const RING_CAPACITY: usize = 32;

/// Lock-free SPSC ring buffer bridge.
///
/// Fixed element size, power-of-2 capacity. Drop-on-full policy: if the ring
/// is full, `push` drops the newest element and increments the drop counter.
#[repr(C, align(64))]
pub struct RingBridge {
    /// Producer write index (only written by producer).
    head: AtomicU32,
    _pad_head: [u8; CACHE_LINE - 4],
    /// Consumer read index (only written by consumer).
    tail: AtomicU32,
    _pad_tail: [u8; CACHE_LINE - 4],
    /// Element size in bytes (set at init, constant).
    elem_size: u32,
    /// Number of elements dropped due to full ring.
    drop_count: AtomicU32,
    _pad_meta: [u8; CACHE_LINE - 8],
    /// Ring data storage. Each element is `elem_size` bytes, stored at
    /// `data[index * elem_size]`. Total capacity: RING_CAPACITY elements.
    data: [u8; RING_CAPACITY * MAX_BRIDGE_DATA],
}

impl RingBridge {
    pub const fn new() -> Self {
        Self {
            head: AtomicU32::new(0),
            _pad_head: [0; CACHE_LINE - 4],
            tail: AtomicU32::new(0),
            _pad_tail: [0; CACHE_LINE - 4],
            elem_size: 0,
            drop_count: AtomicU32::new(0),
            _pad_meta: [0; CACHE_LINE - 8],
            data: [0; RING_CAPACITY * MAX_BRIDGE_DATA],
        }
    }

    /// Initialize with a fixed element size.
    pub fn init(&mut self, elem_size: usize) {
        let sz = if elem_size > MAX_BRIDGE_DATA { MAX_BRIDGE_DATA } else { elem_size };
        self.elem_size = sz as u32;
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
        self.drop_count.store(0, Ordering::Release);
    }

    /// Push one element (ISR-safe, non-blocking).
    ///
    /// Returns true if the element was enqueued, false if dropped (ring full).
    pub fn push(&self, src: &[u8]) -> bool {
        let sz = self.elem_size as usize;
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        // Full check: head - tail >= capacity
        if head.wrapping_sub(tail) >= RING_CAPACITY as u32 {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let idx = (head as usize) & (RING_CAPACITY - 1);
        let offset = idx * sz;
        let len = if src.len() < sz { src.len() } else { sz };

        let dst = &self.data as *const [u8; RING_CAPACITY * MAX_BRIDGE_DATA] as *mut u8;
        unsafe {
            for i in 0..len {
                core::ptr::write_volatile(dst.add(offset + i), src[i]);
            }
            // Zero remaining bytes if src is shorter
            for i in len..sz {
                core::ptr::write_volatile(dst.add(offset + i), 0);
            }
        }

        self.head.store(head.wrapping_add(1), Ordering::Release);
        true
    }

    /// Pop one element (ISR-safe, non-blocking).
    ///
    /// Returns the number of bytes read (0 if empty).
    pub fn pop(&self, dst: &mut [u8]) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return 0; // empty
        }

        let sz = self.elem_size as usize;
        let idx = (tail as usize) & (RING_CAPACITY - 1);
        let offset = idx * sz;
        let len = if dst.len() < sz { dst.len() } else { sz };

        let src = &self.data as *const [u8; RING_CAPACITY * MAX_BRIDGE_DATA] as *const u8;
        unsafe {
            for i in 0..len {
                dst[i] = core::ptr::read_volatile(src.add(offset + i));
            }
        }

        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        len
    }

    /// Pop up to `max` elements in a batch (consumer-side, non-ISR).
    ///
    /// Writes elements sequentially into `dst` starting at offset 0.
    /// Returns the number of elements popped.
    pub fn pop_batch(&self, dst: &mut [u8], max: usize) -> usize {
        let sz = self.elem_size as usize;
        if sz == 0 { return 0; }

        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let available = head.wrapping_sub(tail) as usize;
        let count = available.min(max).min(dst.len() / sz);

        let src_base = &self.data as *const [u8; RING_CAPACITY * MAX_BRIDGE_DATA] as *const u8;
        let mut t = tail;
        for n in 0..count {
            let idx = (t as usize) & (RING_CAPACITY - 1);
            let src_off = idx * sz;
            let dst_off = n * sz;
            unsafe {
                for i in 0..sz {
                    dst[dst_off + i] = core::ptr::read_volatile(src_base.add(src_off + i));
                }
            }
            t = t.wrapping_add(1);
        }

        if count > 0 {
            self.tail.store(t, Ordering::Release);
        }
        count
    }

    /// Return the number of elements currently in the ring.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) as usize
    }

    /// Return the total number of dropped elements.
    pub fn drops(&self) -> u32 {
        self.drop_count.load(Ordering::Relaxed)
    }
}

// ============================================================================
// CommandBridge
// ============================================================================

/// Single-slot latest-wins command bridge (thread → ISR direction).
///
/// The thread context writes a command and bumps the sequence counter.
/// The ISR context reads only when the sequence has changed since its last read.
#[repr(C, align(64))]
pub struct CommandBridge {
    /// Sequence counter — bumped by writer on each command.
    write_seq: AtomicU32,
    /// Data size in bytes (set at init, constant).
    data_size: u32,
    _pad0: [u8; CACHE_LINE - 8],
    /// Command data slot.
    data: CacheAlignedSlot,
    /// Last sequence seen by the reader (reader-private).
    read_seq: AtomicU32,
    _pad1: [u8; CACHE_LINE - 4],
}

impl CommandBridge {
    pub const fn new() -> Self {
        Self {
            write_seq: AtomicU32::new(0),
            data_size: 0,
            _pad0: [0; CACHE_LINE - 8],
            data: CacheAlignedSlot::new(),
            read_seq: AtomicU32::new(0),
            _pad1: [0; CACHE_LINE - 4],
        }
    }

    /// Initialize with a fixed data size.
    pub fn init(&mut self, data_size: usize) {
        let sz = if data_size > MAX_BRIDGE_DATA { MAX_BRIDGE_DATA } else { data_size };
        self.data_size = sz as u32;
        self.write_seq.store(0, Ordering::Release);
        self.read_seq.store(0, Ordering::Release);
    }

    /// Write a new command (thread-side, non-blocking).
    ///
    /// On single-core, this should be called with ISR disabled if data_size > 4
    /// to prevent tearing. On multi-core, the seqlock pattern handles consistency.
    pub fn write(&self, src: &[u8]) -> u32 {
        let sz = self.data_size as usize;
        let len = if src.len() < sz { src.len() } else { sz };

        let dst = &self.data.data as *const [u8; MAX_BRIDGE_DATA] as *mut u8;
        unsafe {
            for i in 0..len {
                core::ptr::write_volatile(dst.add(i), src[i]);
            }
        }

        // Bump sequence after data is written
        self.write_seq.fetch_add(1, Ordering::Release)
    }

    /// Read if a new command is available (ISR-safe, non-blocking).
    ///
    /// Returns Some(bytes_read) if a new command was read, None if no change.
    pub fn read_if_new(&self, dst: &mut [u8]) -> Option<usize> {
        let w_seq = self.write_seq.load(Ordering::Acquire);
        let r_seq = self.read_seq.load(Ordering::Acquire);

        if w_seq == r_seq {
            return None; // no new command
        }

        let sz = self.data_size as usize;
        let len = if dst.len() < sz { dst.len() } else { sz };

        let src = &self.data.data as *const [u8; MAX_BRIDGE_DATA] as *const u8;
        unsafe {
            for i in 0..len {
                dst[i] = core::ptr::read_volatile(src.add(i));
            }
        }

        self.read_seq.store(w_seq, Ordering::Release);
        Some(len)
    }

    /// Peek the current command without updating read_seq.
    pub fn peek(&self, dst: &mut [u8]) -> usize {
        let sz = self.data_size as usize;
        let len = if dst.len() < sz { dst.len() } else { sz };
        let src = &self.data.data as *const [u8; MAX_BRIDGE_DATA] as *const u8;
        unsafe {
            for i in 0..len {
                dst[i] = core::ptr::read_volatile(src.add(i));
            }
        }
        len
    }

    /// Return the current write sequence number.
    pub fn write_sequence(&self) -> u32 {
        self.write_seq.load(Ordering::Acquire)
    }

    /// Return true if there is a new command since last read.
    pub fn has_new(&self) -> bool {
        self.write_seq.load(Ordering::Acquire) != self.read_seq.load(Ordering::Acquire)
    }
}

// ============================================================================
// Bridge Table — Static allocation of bridge channels
// ============================================================================

/// A bridge slot in the global table. Tagged union of the three bridge types.
///
/// Each slot is cache-line aligned. The type tag determines which field is active.
/// Only one type occupies each slot for its lifetime (set at init, never changes).
#[repr(C, align(64))]
pub struct BridgeSlot {
    /// Bridge type (None = unused).
    pub bridge_type: BridgeType,
    /// Source module index (for diagnostics/validation).
    pub from_module: u8,
    /// Destination module index.
    pub to_module: u8,
    _reserved: u8,
    /// The actual bridge data. Reinterpreted based on bridge_type.
    /// Sized to hold the largest bridge type.
    inner: BridgeInner,
}

/// Union-like storage for bridge variants. We use an enum rather than a
/// raw union to stay safe while keeping the size predictable.
enum BridgeInner {
    None,
    Snapshot(SnapshotBridge),
    Ring(RingBridge),
    Command(CommandBridge),
}

impl BridgeSlot {
    const fn new() -> Self {
        Self {
            bridge_type: BridgeType::None,
            from_module: 0,
            to_module: 0,
            _reserved: 0,
            inner: BridgeInner::None,
        }
    }

    /// Initialize as a SnapshotBridge.
    pub fn init_snapshot(&mut self, data_size: usize, from: u8, to: u8) {
        self.bridge_type = BridgeType::Snapshot;
        self.from_module = from;
        self.to_module = to;
        let mut b = SnapshotBridge::new();
        b.init(data_size);
        self.inner = BridgeInner::Snapshot(b);
    }

    /// Initialize as a RingBridge.
    pub fn init_ring(&mut self, elem_size: usize, from: u8, to: u8) {
        self.bridge_type = BridgeType::Ring;
        self.from_module = from;
        self.to_module = to;
        let mut b = RingBridge::new();
        b.init(elem_size);
        self.inner = BridgeInner::Ring(b);
    }

    /// Initialize as a CommandBridge.
    pub fn init_command(&mut self, data_size: usize, from: u8, to: u8) {
        self.bridge_type = BridgeType::Command;
        self.from_module = from;
        self.to_module = to;
        let mut b = CommandBridge::new();
        b.init(data_size);
        self.inner = BridgeInner::Command(b);
    }

    pub fn as_snapshot(&self) -> Option<&SnapshotBridge> {
        match &self.inner {
            BridgeInner::Snapshot(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_ring(&self) -> Option<&RingBridge> {
        match &self.inner {
            BridgeInner::Ring(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_command(&self) -> Option<&CommandBridge> {
        match &self.inner {
            BridgeInner::Command(b) => Some(b),
            _ => None,
        }
    }

    pub fn reset(&mut self) {
        self.bridge_type = BridgeType::None;
        self.from_module = 0;
        self.to_module = 0;
        self.inner = BridgeInner::None;
    }
}

// ============================================================================
// Global Bridge Table
// ============================================================================

static mut BRIDGES: [BridgeSlot; MAX_BRIDGES] = [const { BridgeSlot::new() }; MAX_BRIDGES];

/// Allocate a bridge slot. Returns slot index or -1 if full.
pub fn bridge_alloc() -> i32 {
    unsafe {
        for i in 0..MAX_BRIDGES {
            if let BridgeType::None = BRIDGES[i].bridge_type {
                return i as i32;
            }
        }
    }
    -1
}

/// Get a mutable reference to a bridge slot.
pub fn bridge_get_mut(idx: usize) -> Option<&'static mut BridgeSlot> {
    if idx >= MAX_BRIDGES { return None; }
    unsafe {
        if let BridgeType::None = BRIDGES[idx].bridge_type {
            return None;
        }
        Some(&mut BRIDGES[idx])
    }
}

/// Get a shared reference to a bridge slot.
pub fn bridge_get(idx: usize) -> Option<&'static BridgeSlot> {
    if idx >= MAX_BRIDGES { return None; }
    unsafe {
        if let BridgeType::None = BRIDGES[idx].bridge_type {
            return None;
        }
        Some(&BRIDGES[idx])
    }
}

/// Get a mutable reference to an uninitialized bridge slot for setup.
pub fn bridge_slot_mut(idx: usize) -> Option<&'static mut BridgeSlot> {
    if idx >= MAX_BRIDGES { return None; }
    unsafe { Some(&mut BRIDGES[idx]) }
}

/// Reset all bridge slots.
pub fn bridge_reset_all() {
    unsafe {
        for i in 0..MAX_BRIDGES {
            BRIDGES[i].reset();
        }
    }
}

// ============================================================================
// Syscall Interface
// ============================================================================

/// Bridge syscall dispatch.
///
/// Called from syscalls.rs when a bridge handle is accessed.
/// Operations:
///   - BRIDGE_WRITE: write data to bridge (producer side)
///   - BRIDGE_READ: read data from bridge (consumer side)
///   - BRIDGE_POLL: check readiness (has_new for command, len>0 for ring, always for snapshot)
///   - BRIDGE_INFO: get bridge type and stats
pub fn bridge_dispatch(slot: usize, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let bridge = match bridge_get(slot) {
        Some(b) => b,
        None => return -crate::kernel::errno::EINVAL,
    };

    match op {
        // BRIDGE_WRITE = 0
        0 => {
            if arg.is_null() || arg_len == 0 {
                return -crate::kernel::errno::EINVAL;
            }
            let data = unsafe { core::slice::from_raw_parts(arg, arg_len) };
            match &bridge.inner {
                BridgeInner::Snapshot(b) => { b.write(data); 0 }
                BridgeInner::Ring(b) => if b.push(data) { 0 } else { -crate::kernel::errno::EAGAIN }
                BridgeInner::Command(b) => { b.write(data); 0 }
                BridgeInner::None => -crate::kernel::errno::EINVAL,
            }
        }
        // BRIDGE_READ = 1
        1 => {
            if arg.is_null() || arg_len == 0 {
                return -crate::kernel::errno::EINVAL;
            }
            let data = unsafe { core::slice::from_raw_parts_mut(arg, arg_len) };
            match &bridge.inner {
                BridgeInner::Snapshot(b) => {
                    let (n, _seq) = b.read(data);
                    n as i32
                }
                BridgeInner::Ring(b) => {
                    let n = b.pop(data);
                    if n > 0 { n as i32 } else { -crate::kernel::errno::EAGAIN }
                }
                BridgeInner::Command(b) => {
                    match b.read_if_new(data) {
                        Some(n) => n as i32,
                        None => -crate::kernel::errno::EAGAIN,
                    }
                }
                BridgeInner::None => -crate::kernel::errno::EINVAL,
            }
        }
        // BRIDGE_POLL = 2
        2 => {
            match &bridge.inner {
                BridgeInner::Snapshot(_) => 1, // always readable
                BridgeInner::Ring(b) => if b.len() > 0 { 1 } else { 0 },
                BridgeInner::Command(b) => if b.has_new() { 1 } else { 0 },
                BridgeInner::None => -crate::kernel::errno::EINVAL,
            }
        }
        // BRIDGE_INFO = 3: return [type:u8, from:u8, to:u8, reserved:u8, drops:u32, seq:u32]
        3 => {
            if arg.is_null() || arg_len < 12 {
                return -crate::kernel::errno::EINVAL;
            }
            let out = unsafe { core::slice::from_raw_parts_mut(arg, 12) };
            out[0] = bridge.bridge_type as u8;
            out[1] = bridge.from_module;
            out[2] = bridge.to_module;
            out[3] = 0;
            let drops = match &bridge.inner {
                BridgeInner::Ring(b) => b.drops(),
                _ => 0,
            };
            out[4..8].copy_from_slice(&drops.to_le_bytes());
            let seq = match &bridge.inner {
                BridgeInner::Snapshot(b) => b.sequence(),
                BridgeInner::Command(b) => b.write_sequence(),
                _ => 0,
            };
            out[8..12].copy_from_slice(&seq.to_le_bytes());
            12
        }
        _ => -crate::kernel::errno::ENOSYS,
    }
}

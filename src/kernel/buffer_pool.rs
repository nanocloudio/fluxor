//! Arena-Backed Buffer Registry for Inter-Module Data Flow
//!
//! Channel buffers are allocated from a dedicated buffer arena, separate from
//! the module state arena. This prevents channel buffer sizes from competing
//! with module state for memory — important for compute-heavy modules (e.g.
//! emulators) that need large state allocations.
//!
//! Each channel gets exactly the buffer size its module requests via channel hints.
//!
//! ## Concurrency
//!
//! `BUFFER_ARENA` and `BUFFER_ARENA_OFFSET` are boot-only (channel
//! allocation happens in `prepare_graph` on core 0). Each
//! `BUFFER_REGISTRY` slot is touched on every step from any core, so
//! its fields are atomic. See `docs/architecture/concurrency.md`.
//!
//! ## Buffer Modes
//!
//! Each buffer supports two usage modes:
//!
//! **FIFO (streaming):** Ring buffer for continuous byte streams (audio data).
//! Uses channel_write/channel_read with copy semantics.
//!
//! **Mailbox (zero-copy):** Single-message handoff between producer and consumer.
//! Uses buffer_acquire_write/release_write/acquire_read/release_read.
//! Enabled automatically for aliased (buffer_group) channels.
//!
//! ## Mailbox State Machine
//!
//! ```text
//!   STREAMING ──acquire_write──► PRODUCER ──release_write──► READY
//!       ▲                                                     │
//!       │                                                     ├──acquire_read──► CONSUMER ──release_read──► STREAMING
//!       │                                                     │
//!       │                                          acquire_inplace──► (READY_PROCESSED)──release_write──► STREAMING
//!       │                                                                │
//!       └────────────────────── mailbox_flush ◄───────────────────────────┘
//! ```
//!
//! - **STREAMING**: idle, available for next produce/consume cycle
//! - **PRODUCER**: writer holds buffer, filling with data
//! - **READY**: data available; acquire_read or acquire_inplace may proceed
//! - **CONSUMER**: reader holds buffer (read-only via acquire_read)
//! - **READY_PROCESSED**: in-place module has processed; prevents double-processing
//! - **mailbox_flush**: force-resets any state to STREAMING (clears len, inplace_flag)
//! - **mailbox_cancel_read**: CONSUMER → READY without consuming (preserves payload)
//!
//! ## In-place processing limit
//!
//! `acquire_inplace` only accepts READY (not READY_PROCESSED). After an in-place
//! module releases, the buffer transitions to READY_PROCESSED, which prevents a
//! second in-place module from re-processing the same data. At most one in-place
//! transform is supported per alias chain. For multiple transforms, insert a FIFO
//! copy step between them or change the state machine.
//!
//! ## Usage paths
//!
//! Mailbox acquire/release is used directly for zero-copy paths (e.g.
//! I2S DMA via `acquire_read`). Modules using `channel_read`/`channel_write`
//! get mailbox support transparently, but with a copy — not zero-copy.
//!
//! Both modes use the same arena-allocated buffer.
//!
//! ## FIFO→Mailbox chaining
//!
//! A pipeline can mix FIFO and mailbox channels. A mailbox chain starts at the
//! first module that produces whole buffers; prior stages use FIFO copy. See
//! `docs/architecture/pipeline.md` §FIFO→Mailbox for the full pattern.

use portable_atomic::{AtomicI8, AtomicU32, AtomicU8, Ordering};

use crate::kernel::errno;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of buffer registry slots.
/// Must be >= MAX_CHANNELS plus headroom for dynamic allocations.
/// Bumped from 56 to 256 to fit Quantum's 42-module graph (~110 channels).
pub const MAX_BUFFER_SLOTS: usize = 256;

/// Default buffer size for channels without hints (audio channels).
/// Derived from the canonical constant in abi.rs.
pub const BUFFER_SIZE: usize = crate::abi::CHANNEL_BUFFER_SIZE;

/// Buffer arena size — from silicon TOML [kernel] section.
/// RP2350: 32 KB, RP2040: 16 KB.
const BUFFER_ARENA_SIZE: usize = super::chip::BUFFER_ARENA_SIZE;

// ============================================================================
// Buffer Arena (separate from module state arena)
// ============================================================================

#[repr(C, align(4))]
struct AlignedBufferArena([u8; BUFFER_ARENA_SIZE]);
static mut BUFFER_ARENA: AlignedBufferArena = AlignedBufferArena([0; BUFFER_ARENA_SIZE]);
static mut BUFFER_ARENA_OFFSET: usize = 0;

/// Allocate a buffer from the dedicated buffer arena.
///
/// Returns pointer to zeroed buffer, aligned to 4 bytes.
fn alloc_buffer(size: usize) -> Option<*mut u8> {
    unsafe {
        let aligned = (BUFFER_ARENA_OFFSET + 3) & !3;
        if aligned + size > BUFFER_ARENA_SIZE {
            log::error!(
                "[buf] arena full need={} used={} cap={}",
                size,
                aligned,
                BUFFER_ARENA_SIZE
            );
            return None;
        }
        let ptr = core::ptr::addr_of_mut!(BUFFER_ARENA.0)
            .cast::<u8>()
            .add(aligned);
        core::ptr::write_bytes(ptr, 0, size);
        BUFFER_ARENA_OFFSET = aligned + size;
        Some(ptr)
    }
}

/// Reset the buffer arena for a new graph configuration.
pub fn reset_buffer_arena() {
    unsafe {
        BUFFER_ARENA_OFFSET = 0;
    }
}

/// Return current buffer arena usage: (used_bytes, total_bytes).
pub fn buffer_arena_usage() -> (usize, usize) {
    unsafe { (BUFFER_ARENA_OFFSET, BUFFER_ARENA_SIZE) }
}

// ============================================================================
// Buffer States
// ============================================================================

/// Buffer slot is unused (no arena memory assigned)
pub const STATE_FREE: u8 = 0;

/// Buffer is owned by producer (being written) — zero-copy mode
pub const STATE_PRODUCER: u8 = 1;

/// Buffer has data ready for consumer — zero-copy mode
pub const STATE_READY: u8 = 2;

/// Buffer is owned by consumer (being read) — zero-copy mode
pub const STATE_CONSUMER: u8 = 3;

/// Buffer is allocated for streaming FIFO (owned by a channel)
pub const STATE_STREAMING: u8 = 4;

/// Buffer processed by in-place module, ready for consumer read.
/// Like READY but acquire_inplace won't accept it, preventing double-processing.
pub const STATE_READY_PROCESSED: u8 = 5;

// ============================================================================
// Error Codes
// ============================================================================

/// Success
pub const BUF_OK: i32 = errno::OK;

/// No buffer available
pub const BUF_EAGAIN: i32 = errno::EAGAIN;

/// Invalid argument
pub const BUF_EINVAL: i32 = errno::EINVAL;

/// Buffer in wrong state for operation
pub const BUF_EBUSY: i32 = errno::EBUSY;

// ============================================================================
// Buffer Registry Slot
// ============================================================================

/// A registry entry tracking an arena-allocated buffer.
///
/// The actual buffer data lives in the buffer arena; this slot only holds
/// metadata (pointer, capacity, state). ~20 bytes per slot vs 2KB+ before.
struct BufferRegistrySlot {
    /// Pointer to arena-allocated buffer data (null if not allocated)
    data_ptr: core::cell::UnsafeCell<*mut u8>,
    /// Buffer capacity in bytes (set at allocation time)
    capacity: AtomicU32,
    /// Current valid data length (set by producer on release)
    len: AtomicU32,
    /// Buffer state (FREE/PRODUCER/READY/CONSUMER/STREAMING/READY_PROCESSED)
    state: AtomicU8,
    /// Owner channel handle (-1 if not associated)
    owner_channel: AtomicI8,
    /// Set when current PRODUCER was acquired via in-place (not fresh write)
    inplace_flag: AtomicU8,
    /// Producer module index (0xFF if unknown). The scheduler reads this to
    /// compute a per-module channel-buffer range for an MPU/MMU region.
    producer_module: AtomicU8,
}

unsafe impl Sync for BufferRegistrySlot {}

impl BufferRegistrySlot {
    const fn new() -> Self {
        Self {
            data_ptr: core::cell::UnsafeCell::new(core::ptr::null_mut()),
            capacity: AtomicU32::new(0),
            len: AtomicU32::new(0),
            state: AtomicU8::new(STATE_FREE),
            owner_channel: AtomicI8::new(-1),
            inplace_flag: AtomicU8::new(0),
            producer_module: AtomicU8::new(0xFF),
        }
    }

    #[inline]
    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    #[inline]
    fn owner(&self) -> i8 {
        self.owner_channel.load(Ordering::Acquire)
    }

    #[inline]
    fn get_capacity(&self) -> u32 {
        self.capacity.load(Ordering::Acquire)
    }

    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        unsafe { *self.data_ptr.get() }
    }

    /// Assign arena-allocated memory to this slot.
    fn assign(&self, ptr: *mut u8, capacity: usize, channel: i8) {
        unsafe {
            *self.data_ptr.get() = ptr;
        }
        self.capacity.store(capacity as u32, Ordering::Release);
        self.owner_channel.store(channel, Ordering::Release);
        self.len.store(0, Ordering::Release);
    }

    /// Try mailbox acquire write (STREAMING -> PRODUCER) — for channel's own buffer
    fn try_mailbox_acquire_write(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_STREAMING,
                STATE_PRODUCER,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Try in-place acquire (READY -> PRODUCER) — for aliased buffer chains.
    /// The in-place module reads and modifies the same buffer without
    /// going through CONSUMER -> STREAMING intermediate states.
    fn try_inplace_acquire(&self) -> bool {
        if self
            .state
            .compare_exchange(
                STATE_READY,
                STATE_PRODUCER,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.inplace_flag.store(1, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Release after writing (PRODUCER -> READY or READY_PROCESSED)
    ///
    /// If the current PRODUCER was acquired via in-place, releases to
    /// READY_PROCESSED to prevent another in-place module from re-processing.
    fn release_write(&self, data_len: u32) -> bool {
        if self.state.load(Ordering::Acquire) != STATE_PRODUCER {
            return false;
        }
        let cap = self.capacity.load(Ordering::Acquire);
        self.len.store(data_len.min(cap), Ordering::Release);
        let was_inplace = self.inplace_flag.swap(0, Ordering::AcqRel);
        let next_state = if was_inplace != 0 {
            STATE_READY_PROCESSED
        } else {
            STATE_READY
        };
        self.state.store(next_state, Ordering::Release);
        true
    }

    /// Try mailbox acquire read (READY/READY_PROCESSED -> CONSUMER) — ignores channel ownership
    fn try_mailbox_acquire_read(&self) -> bool {
        // Accept both READY (from fresh write) and READY_PROCESSED (from in-place)
        self.state
            .compare_exchange(
                STATE_READY,
                STATE_CONSUMER,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            || self
                .state
                .compare_exchange(
                    STATE_READY_PROCESSED,
                    STATE_CONSUMER,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    /// Release after reading — return to STREAMING (mailbox) or FREE (pool)
    fn release_read_to_streaming(&self) -> bool {
        if self.state.load(Ordering::Acquire) != STATE_CONSUMER {
            return false;
        }
        self.len.store(0, Ordering::Release);
        self.state.store(STATE_STREAMING, Ordering::Release);
        true
    }

    fn reset(&self) {
        self.state.store(STATE_FREE, Ordering::Release);
        self.owner_channel.store(-1, Ordering::Release);
        self.capacity.store(0, Ordering::Release);
        self.len.store(0, Ordering::Release);
        self.inplace_flag.store(0, Ordering::Release);
        self.producer_module.store(0xFF, Ordering::Release);
        unsafe {
            *self.data_ptr.get() = core::ptr::null_mut();
        }
    }
}

// ============================================================================
// Buffer Registry
// ============================================================================

/// Registry of buffer slots — metadata only, data lives in the buffer arena.
static BUFFER_REGISTRY: [BufferRegistrySlot; MAX_BUFFER_SLOTS] =
    [const { BufferRegistrySlot::new() }; MAX_BUFFER_SLOTS];

fn valid_slot(slot: i32) -> bool {
    slot >= 0 && (slot as usize) < MAX_BUFFER_SLOTS
}

// ============================================================================
// Streaming Mode — FIFO channel buffers (arena-allocated)
// ============================================================================

/// Allocate a streaming buffer from the dedicated buffer arena.
///
/// `capacity` specifies the buffer size in bytes (e.g. 2048 for audio, 256 for events).
/// Returns buffer slot index, or -1 if no slot or arena space available.
pub fn alloc_streaming(channel: i8, capacity: usize) -> i32 {
    alloc_streaming_for_module(channel, capacity, 0xFF)
}

/// Allocate a streaming buffer tagged with its producer module.
///
/// When channels for the same producer are opened consecutively during graph
/// setup, the bump allocator places them contiguously so
/// `compute_module_buffer_range` can report a tight `(base, size)` for a
/// per-module MPU/MMU region. Interleaved allocations widen the reported
/// range into a conservative superset — still safe, but may include a peer
/// module's buffer.
pub fn alloc_streaming_for_module(channel: i8, capacity: usize, producer_module: u8) -> i32 {
    for (i, slot) in BUFFER_REGISTRY.iter().enumerate() {
        if slot
            .state
            .compare_exchange(
                STATE_FREE,
                STATE_STREAMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            match alloc_buffer(capacity) {
                Some(ptr) => {
                    slot.assign(ptr, capacity, channel);
                    slot.producer_module
                        .store(producer_module, Ordering::Release);
                    return i as i32;
                }
                None => {
                    // Roll back the slot claim so it can be retried for a
                    // smaller capacity.
                    slot.state.store(STATE_FREE, Ordering::Release);
                    log::warn!("[buf] arena exhausted size={}", capacity);
                    return -1;
                }
            }
        }
    }
    log::warn!("[buf] no free slots ch={}", channel);
    -1
}

/// Compute the buffer-address range occupied by a given producer module.
/// Returns `(base_ptr, size_bytes)`; size is 0 if the module owns no buffers.
/// Used to register a per-module MPU region for channel buffers.
pub fn compute_module_buffer_range(module_idx: u8) -> (usize, usize) {
    let mut lo = usize::MAX;
    let mut hi: usize = 0;
    for slot in BUFFER_REGISTRY.iter() {
        if slot.producer_module.load(Ordering::Acquire) != module_idx {
            continue;
        }
        let ptr = slot.data_ptr() as usize;
        if ptr == 0 {
            continue;
        }
        let cap = slot.get_capacity() as usize;
        if ptr < lo {
            lo = ptr;
        }
        if ptr + cap > hi {
            hi = ptr + cap;
        }
    }
    if hi == 0 {
        (0, 0)
    } else {
        (lo, hi - lo)
    }
}

/// Free a streaming buffer slot.
///
/// Note: The arena memory is not individually freed (bump allocator).
/// It will be reclaimed on the next reset_buffer_arena() call.
pub fn free_streaming(slot: i32) {
    if valid_slot(slot) {
        let buf = &BUFFER_REGISTRY[slot as usize];
        let prev_state = buf.state();
        // Unconditionally reset: a mailbox buffer may be in PRODUCER, READY,
        // or CONSUMER state when the channel is closed.  Only gating on
        // STATE_STREAMING would orphan the slot permanently.
        if prev_state != STATE_FREE {
            buf.reset();
        }
    }
}

/// Get raw data pointer for a streaming buffer.
///
/// Returns pointer to buffer data, or null if invalid/wrong state.
pub fn get_streaming_ptr(slot: i32) -> *mut u8 {
    if !valid_slot(slot) {
        return core::ptr::null_mut();
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    let state = buf.state();
    // Only allow access in STREAMING state (FIFO ring buffer).
    // Mailbox mode uses dedicated acquire functions, not this path.
    if state != STATE_STREAMING {
        return core::ptr::null_mut();
    }
    buf.data_ptr()
}

/// Check if a slot is in streaming mode
pub fn is_streaming(slot: i32) -> bool {
    valid_slot(slot) && BUFFER_REGISTRY[slot as usize].state() == STATE_STREAMING
}

/// Check if a mailbox buffer has data ready for reading (READY or READY_PROCESSED).
/// Used by channel_poll to report POLL_IN for mailbox channels.
pub fn mailbox_has_data(slot: i32) -> bool {
    valid_slot(slot)
        && matches!(
            BUFFER_REGISTRY[slot as usize].state(),
            STATE_READY | STATE_READY_PROCESSED
        )
}

/// Check if a mailbox buffer is available for writing (STREAMING state).
/// Used by channel_poll to report POLL_OUT for mailbox channels.
pub fn mailbox_can_write(slot: i32) -> bool {
    valid_slot(slot) && BUFFER_REGISTRY[slot as usize].state() == STATE_STREAMING
}

/// Force-reset a mailbox buffer back to STREAMING state.
/// Used by IOCTL_FLUSH to unstick a mailbox buffer that's in READY/CONSUMER/PRODUCER.
/// Returns true if the slot was valid and reset.
pub fn mailbox_flush(slot: i32) -> bool {
    if !valid_slot(slot) {
        return false;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    buf.len.store(0, Ordering::Release);
    buf.inplace_flag.store(0, Ordering::Release);
    buf.state.store(STATE_STREAMING, Ordering::Release);
    true
}

// ============================================================================
// Zero-Copy Mailbox Mode — uses channel's own buffer
// ============================================================================

/// Acquire write access to a buffer slot's data (STREAMING → PRODUCER).
///
/// Returns (data_ptr, capacity) or (null, 0) if unavailable.
pub fn mailbox_acquire_write(slot: i32) -> (*mut u8, u32) {
    if !valid_slot(slot) {
        return (core::ptr::null_mut(), 0);
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if buf.try_mailbox_acquire_write() {
        buf.len.store(0, Ordering::Release);
        (buf.data_ptr(), buf.get_capacity())
    } else {
        (core::ptr::null_mut(), 0)
    }
}

/// Release write on a buffer slot (PRODUCER → READY).
pub fn mailbox_release_write(slot: i32, len: u32) -> i32 {
    if !valid_slot(slot) {
        return BUF_EINVAL;
    }
    if BUFFER_REGISTRY[slot as usize].release_write(len) {
        BUF_OK
    } else {
        BUF_EBUSY
    }
}

/// Acquire read access to a buffer slot (READY → CONSUMER).
///
/// Returns (data_ptr, data_len) or (null, 0) if no data ready.
pub fn mailbox_acquire_read(slot: i32) -> (*const u8, u32) {
    if !valid_slot(slot) {
        return (core::ptr::null(), 0);
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if buf.try_mailbox_acquire_read() {
        let ptr = buf.data_ptr() as *const u8;
        let len = buf.len.load(Ordering::Acquire);
        (ptr, len)
    } else {
        (core::ptr::null(), 0)
    }
}

/// Acquire in-place access to a buffer slot (READY → PRODUCER).
///
/// For aliased buffer chains: the in-place module gets a mutable pointer
/// to the existing data. It reads, modifies in-place, then calls
/// `mailbox_release_write` to transition back to READY.
///
/// Returns (data_ptr, data_len) or (null, 0) if buffer not in READY state.
pub fn mailbox_acquire_inplace(slot: i32) -> (*mut u8, u32) {
    if !valid_slot(slot) {
        return (core::ptr::null_mut(), 0);
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if buf.try_inplace_acquire() {
        let len = buf.len.load(Ordering::Acquire);
        (buf.data_ptr(), len)
    } else {
        (core::ptr::null_mut(), 0)
    }
}

/// Release read on a buffer slot (CONSUMER → STREAMING).
pub fn mailbox_release_read(slot: i32) -> i32 {
    if !valid_slot(slot) {
        return BUF_EINVAL;
    }
    if BUFFER_REGISTRY[slot as usize].release_read_to_streaming() {
        BUF_OK
    } else {
        BUF_EBUSY
    }
}

/// Cancel a mailbox read without consuming data (CONSUMER → READY).
///
/// Used when channel_read discovers the caller's buffer is too small.
/// The payload stays intact for a subsequent read with a larger buffer.
pub fn mailbox_cancel_read(slot: i32) -> i32 {
    if !valid_slot(slot) {
        return BUF_EINVAL;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if buf
        .state
        .compare_exchange(
            STATE_CONSUMER,
            STATE_READY,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        BUF_OK
    } else {
        BUF_EBUSY
    }
}

// ============================================================================
// Utility
// ============================================================================

/// Get buffer capacity for a slot.
pub fn get_capacity(slot: i32) -> u32 {
    if !valid_slot(slot) {
        return 0;
    }
    BUFFER_REGISTRY[slot as usize].get_capacity()
}

/// Check if a channel has a ready buffer (includes in-place processed buffers)
pub fn has_ready(channel: i8) -> bool {
    BUFFER_REGISTRY
        .iter()
        .any(|s| s.owner() == channel && matches!(s.state(), STATE_READY | STATE_READY_PROCESSED))
}

/// Check if registry has any free slots
pub fn has_free() -> bool {
    BUFFER_REGISTRY.iter().any(|s| s.state() == STATE_FREE)
}

/// Get pool statistics (free, producer, ready, consumer, streaming counts)
pub fn stats() -> (u8, u8, u8, u8, u8) {
    let mut free = 0u8;
    let mut producer = 0u8;
    let mut ready = 0u8;
    let mut consumer = 0u8;
    let mut streaming = 0u8;

    for slot in BUFFER_REGISTRY.iter() {
        match slot.state() {
            STATE_FREE => free += 1,
            STATE_PRODUCER => producer += 1,
            STATE_READY | STATE_READY_PROCESSED => ready += 1,
            STATE_CONSUMER => consumer += 1,
            STATE_STREAMING => streaming += 1,
            _ => {}
        }
    }

    (free, producer, ready, consumer, streaming)
}

/// Reset all buffer slots (for testing/cleanup).
/// Does NOT free buffer arena memory — that happens via reset_buffer_arena().
pub fn reset_all() {
    for slot in BUFFER_REGISTRY.iter() {
        slot.reset();
    }
}

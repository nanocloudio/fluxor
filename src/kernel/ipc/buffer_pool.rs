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
//! The arena allocator (`alloc_buffer` / `release_buffer`) runs under one
//! spin lock: channels open and close at graph build, on live graph changes
//! and from module calls on any core. Each `BUFFER_REGISTRY` slot is touched
//! on every step from any core, so its fields are atomic. See
//! `docs/architecture/concurrency.md`.
//!
//! ## Arena reuse
//!
//! Closing a channel returns its buffer to the arena: the region is merged
//! with any free neighbours and either lowers the high-water mark or joins a
//! bounded free list that later allocations take from (best fit, split). A
//! node that admits and reaps workloads indefinitely therefore holds its
//! buffer arena at a fixed point instead of exhausting it.
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
//! - **mailbox_flush**: force-resets a slot holding a buffer to STREAMING (clears len, inplace_flag)
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

use portable_atomic::{
    AtomicBool, AtomicI16, AtomicU16, AtomicU32, AtomicU8, AtomicUsize, Ordering,
};

use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};

use crate::kernel::ipc::channel::MAX_CHANNELS;
use crate::kernel::sys::errno;

// ============================================================================
// Constants
// ============================================================================

/// Buffer registry slots: one per channel, derived rather than chosen.
///
/// `ChannelSlot.buffer_slot` holds a single id and every allocation path takes
/// the owning channel, so a channel owns at most one buffer — a slot past the
/// channel table is one nothing can reach, and a pool short of the table makes
/// the table's upper range unallocatable. A literal here is free to drift from
/// `MAX_CHANNELS`, and when it does the channel count becomes a ceiling that
/// lies: `channel_open` starts refusing while the table still has free slots.
pub const MAX_BUFFER_SLOTS: usize = MAX_CHANNELS;

// Buffer slot ids are stored in `i16` fields on the channel side
// (`ChannelSlot.buffer_slot`) with `-1` reserved as the unallocated
// sentinel; the valid range is therefore `[0, i16::MAX]`. Widening
// `MAX_BUFFER_SLOTS` past this range requires widening
// `ChannelSlot.buffer_slot` and `BufferRegistrySlot.owner_channel`
// together; the assert below fails the build if that invariant is
// broken.
const _: () = assert!(
    MAX_BUFFER_SLOTS <= i16::MAX as usize + 1,
    "MAX_BUFFER_SLOTS exceeds i16 sentinel-aware range; widen ChannelSlot.buffer_slot \
     and BufferRegistrySlot.owner_channel storage before increasing this limit"
);

/// The ring a channel opened without a size gets: the module ABI's
/// `CHANNEL_BUFFER_SIZE`, which is the default ring the composer charges an
/// unsized edge (`ring_size::DEFAULT_RING_BYTES`).
pub const BUFFER_SIZE: usize = crate::abi::CHANNEL_BUFFER_SIZE;
const _: () = assert!(BUFFER_SIZE == super::ring_size::DEFAULT_RING_BYTES as usize);

/// Buffer arena size: the kernel profile's (`kernel::config`), which on the
/// RP parts is the silicon TOML's `[kernel] buffer_arena_kb`.
const BUFFER_ARENA_SIZE: usize = crate::kernel::config::BUFFER_ARENA_SIZE;

// ============================================================================
// Buffer Arena (separate from module state arena)
// ============================================================================

/// Alignment of every channel buffer: one cache line (`ring_size::RING_ALIGN`,
/// the alignment the composer charges each ring at). Capacities are powers of
/// two of at least 64 bytes (`channel_open`), so every buffer starts and ends
/// on a line boundary: two channels never share a line, and cache maintenance
/// on one buffer (a DMA-owned edge) never touches its neighbour.
const BUFFER_ALIGN: usize = super::ring_size::RING_ALIGN as usize;

#[repr(C, align(64))]
struct AlignedBufferArena([u8; BUFFER_ARENA_SIZE]);
const _: () = assert!(core::mem::align_of::<AlignedBufferArena>() == BUFFER_ALIGN);
const _: () = assert!(core::mem::align_of::<AlignedBufferArena>() == BUFFER_ALIGN);
static mut BUFFER_ARENA: AlignedBufferArena = AlignedBufferArena([0; BUFFER_ARENA_SIZE]);

/// Bump high-water mark: `[0, offset)` has been handed out at some point;
/// the returned regions inside it are on the free list. Written only under
/// `ARENA_LOCK`; read without it by `arena_usage`.
static BUFFER_ARENA_OFFSET: AtomicUsize = AtomicUsize::new(0);

/// Serialises the arena allocator. A buffer is allocated when a channel
/// opens and returned when it closes; both happen at graph build, on a live
/// graph change, when the kernel closes a channel whose block lends came back
/// (core 0, peers running), and on a module's own `channel::OPEN` / `CLOSE`
/// from whichever core steps it.
static ARENA_LOCK: AtomicBool = AtomicBool::new(false);

/// A returned region of the arena, below the high-water mark.
#[derive(Clone, Copy)]
struct FreeRegion {
    offset: u32,
    size: u32,
}

/// Bounded free list of returned regions, kept coalesced: no two entries are
/// adjacent, and none ends at the high-water mark (that region lowers the
/// mark instead). A node that admits and reaps workloads for its whole life
/// closes channels for its whole life; the free list is what lets each reaped
/// workload's buffers serve the next one, whatever its capacities. A region
/// returned while the list is full is leaked (counted in `leaked`) until the
/// next `reset_buffer_arena`.
const MAX_FREE_REGIONS: usize = 128;

struct FreeList {
    regions: [FreeRegion; MAX_FREE_REGIONS],
    count: usize,
    leaked: usize,
}

static mut FREE_LIST: FreeList = FreeList {
    regions: [FreeRegion { offset: 0, size: 0 }; MAX_FREE_REGIONS],
    count: 0,
    leaked: 0,
};

/// Run `f` on the free list with `ARENA_LOCK` held.
fn with_arena<R>(f: impl FnOnce(&mut FreeList) -> R) -> R {
    while ARENA_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `ARENA_LOCK` is held, so this is the only reference.
    let r = f(unsafe { &mut *core::ptr::addr_of_mut!(FREE_LIST) });
    ARENA_LOCK.store(false, Ordering::Release);
    r
}

/// Bytes an allocation of `size` occupies in the arena.
fn arena_need(size: usize) -> Option<usize> {
    size.checked_add(BUFFER_ALIGN - 1)
        .map(|n| n & !(BUFFER_ALIGN - 1))
}

impl FreeList {
    fn remove(&mut self, i: usize) {
        self.regions[i] = self.regions[self.count - 1];
        self.count -= 1;
    }

    /// Best fit: the smallest region that holds `need`, split if larger.
    /// Returns its offset.
    fn take(&mut self, need: usize) -> Option<usize> {
        let i = (0..self.count)
            .filter(|&i| self.regions[i].size as usize >= need)
            .min_by_key(|&i| self.regions[i].size)?;
        let r = self.regions[i];
        if r.size as usize == need {
            self.remove(i);
        } else {
            self.regions[i] = FreeRegion {
                offset: r.offset + need as u32,
                size: r.size - need as u32,
            };
        }
        Some(r.offset as usize)
    }

    /// Return `[offset, offset + need)`: merge it with the free neighbours on
    /// either side, then either lower the high-water mark (the region reaches
    /// it) or record it.
    fn give(&mut self, offset: usize, need: usize) {
        let mut start = offset;
        let mut end = offset + need;
        let mut i = 0;
        while i < self.count {
            let r = self.regions[i];
            let (r_start, r_end) = (r.offset as usize, (r.offset + r.size) as usize);
            if r_end == start {
                start = r_start;
                self.remove(i);
            } else if r_start == end {
                end = r_end;
                self.remove(i);
            } else {
                i += 1;
            }
        }
        if end == BUFFER_ARENA_OFFSET.load(Ordering::Relaxed) {
            BUFFER_ARENA_OFFSET.store(start, Ordering::Relaxed);
        } else if self.count < MAX_FREE_REGIONS {
            self.regions[self.count] = FreeRegion {
                offset: start as u32,
                size: (end - start) as u32,
            };
            self.count += 1;
        } else {
            self.leaked += end - start;
        }
    }
}

/// Bump high-water mark: `(used_bytes, total_bytes)` — resource-ledger
/// sample for `POOL_BUFFER_ARENA`. Regions on the free list are inside
/// `used_bytes`; `buffer_free_list_usage` reports them.
pub fn arena_usage() -> (usize, usize) {
    (
        BUFFER_ARENA_OFFSET.load(Ordering::Relaxed),
        BUFFER_ARENA_SIZE,
    )
}

/// Returned-region occupancy: `(regions, region_bytes, leaked_bytes)`.
pub fn buffer_free_list_usage() -> (usize, usize, usize) {
    with_arena(|l| {
        let bytes = l.regions[..l.count].iter().map(|r| r.size as usize).sum();
        (l.count, bytes, l.leaked)
    })
}

/// Allocate a zeroed, `BUFFER_ALIGN`-aligned buffer of `size` bytes: the best
/// fitting returned region if one holds it, otherwise from the high-water
/// mark.
fn alloc_buffer(size: usize) -> Option<*mut u8> {
    let need = arena_need(size)?;
    let got = with_arena(|l| {
        if let Some(off) = l.take(need) {
            return Ok(off);
        }
        let off = BUFFER_ARENA_OFFSET.load(Ordering::Relaxed);
        if off + need > BUFFER_ARENA_SIZE
            || !crate::kernel::sys::resource_ledger::enforced_allows(
                crate::abi::contracts::resource::POOL_BUFFER_ARENA,
                (off + need) as u32,
            )
        {
            return Err(off);
        }
        BUFFER_ARENA_OFFSET.store(off + need, Ordering::Relaxed);
        Ok(off)
    });
    match got {
        Ok(off) => {
            // SAFETY: `off + need <= BUFFER_ARENA_SIZE` (checked at the bump,
            // and every free region lies below the mark), and the range is
            // this caller's alone once it left the allocator.
            unsafe {
                let ptr = core::ptr::addr_of_mut!(BUFFER_ARENA.0)
                    .cast::<u8>()
                    .add(off);
                core::ptr::write_bytes(ptr, 0, size);
                Some(ptr)
            }
        }
        Err(used) => {
            log::error!("[buf] arena full need={need} used={used} cap={BUFFER_ARENA_SIZE}");
            crate::kernel::sys::resource_ledger::deny(
                crate::abi::contracts::resource::POOL_BUFFER_ARENA,
            );
            None
        }
    }
}

/// Return a buffer `alloc_buffer` handed out for `size` bytes.
///
/// # Safety
/// `ptr` came from `alloc_buffer(size)` and nothing reaches it any more: no
/// registry slot names it and no lend of it is outstanding.
unsafe fn release_buffer(ptr: *mut u8, size: usize) {
    let base = core::ptr::addr_of_mut!(BUFFER_ARENA.0).cast::<u8>() as usize;
    let addr = ptr as usize;
    let Some(need) = arena_need(size) else { return };
    if size == 0 || addr < base || addr + need > base + BUFFER_ARENA_SIZE {
        return;
    }
    with_arena(|l| l.give(addr - base, need));
}

/// Account a buffer that cannot be returned (it is still lent out) as leaked
/// until the next `reset_buffer_arena`.
fn abandon_buffer(size: usize) {
    if let Some(need) = arena_need(size) {
        with_arena(|l| l.leaked += need);
    }
}

/// Reset the buffer arena for a new graph configuration.
pub fn reset_buffer_arena() {
    with_arena(|l| {
        l.count = 0;
        l.leaked = 0;
        BUFFER_ARENA_OFFSET.store(0, Ordering::Relaxed);
    });
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

/// Slot being freed (`free_streaming`): no transition starts from it, and it
/// becomes FREE once the slot is cleared.
const STATE_CLOSING: u8 = 6;

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
/// metadata (pointer, capacity, state).
struct BufferRegistrySlot {
    /// Pointer to arena-allocated buffer data (null if not allocated)
    data_ptr: core::cell::UnsafeCell<*mut u8>,
    /// Buffer capacity in bytes (set at allocation time)
    capacity: AtomicU32,
    /// Current valid data length (set by producer on release)
    len: AtomicU32,
    /// Buffer state (FREE/PRODUCER/READY/CONSUMER/STREAMING/READY_PROCESSED)
    state: AtomicU8,
    /// Owner channel handle (-1 if not associated). Stored as `i16` so the
    /// full configured `MAX_CHANNELS` range fits without silent narrowing.
    owner_channel: AtomicI16,
    /// Set when current PRODUCER was acquired via in-place (not fresh write)
    inplace_flag: AtomicU8,
    /// Producer module index (`NO_MODULE` if unknown). The scheduler reads this to
    /// compute a per-module channel-buffer range for an MPU/MMU region.
    producer_module: AtomicU16,
}

// SAFETY: The `data_ptr` UnsafeCell is mutated only via dedicated
// state-transitioning helpers (claim/release/migrate) that take
// `&mut self` from the global registry while holding the
// `state`/`owner_channel` atomic guards. All other fields are atomics.
unsafe impl Sync for BufferRegistrySlot {}

impl BufferRegistrySlot {
    const fn new() -> Self {
        Self {
            data_ptr: core::cell::UnsafeCell::new(core::ptr::null_mut()),
            capacity: AtomicU32::new(0),
            len: AtomicU32::new(0),
            state: AtomicU8::new(STATE_FREE),
            owner_channel: AtomicI16::new(-1),
            inplace_flag: AtomicU8::new(0),
            producer_module: AtomicU16::new(NO_MODULE),
        }
    }

    #[inline]
    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    #[inline]
    fn owner(&self) -> i16 {
        self.owner_channel.load(Ordering::Acquire)
    }

    #[inline]
    fn get_capacity(&self) -> u32 {
        self.capacity.load(Ordering::Acquire)
    }

    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: `data_ptr` is an `UnsafeCell<*mut u8>`; reading a copy
        // of the raw pointer is a single load. The producer/consumer
        // handshake uses the atomic `len`/`owner_channel` fields to
        // synchronise access to the pointed-at memory.
        unsafe { *self.data_ptr.get() }
    }

    /// Assign arena-allocated memory to this slot.
    fn assign(&self, ptr: *mut u8, capacity: usize, channel: i16) {
        // SAFETY: the caller claimed this slot (FREE -> STREAMING) and has
        // not yet published it to a channel, so nothing else reads it.
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
    ///
    /// Oversized writes (`data_len > capacity`) are rejected by returning
    /// `false` and leaving the slot in `STATE_PRODUCER`; callers translate
    /// to `EINVAL`. Sizing each write to fit the buffer is a caller
    /// contract — silently truncating would drop the tail of the writer's
    /// data and corrupt the consumer's view.
    fn release_write(&self, data_len: u32) -> bool {
        if self.state.load(Ordering::Acquire) != STATE_PRODUCER {
            return false;
        }
        let cap = self.capacity.load(Ordering::Acquire);
        if data_len > cap {
            return false;
        }
        self.len.store(data_len, Ordering::Release);
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

    /// Clear the slot and mark it FREE. The state goes last, so a claimant
    /// that wins the slot after it reads FREE finds nothing of the old
    /// buffer to clobber its own.
    fn reset(&self) {
        self.owner_channel.store(-1, Ordering::Release);
        self.capacity.store(0, Ordering::Release);
        self.len.store(0, Ordering::Release);
        self.inplace_flag.store(0, Ordering::Release);
        self.producer_module.store(NO_MODULE, Ordering::Release);
        // SAFETY: the slot's channel has detached it (`ChannelSlot::reset`
        // under the ring lock) or the whole graph is being torn down; nothing
        // reaches the slot through a channel any more.
        unsafe {
            *self.data_ptr.get() = core::ptr::null_mut();
        }
        self.state.store(STATE_FREE, Ordering::Release);
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
pub fn alloc_streaming(channel: i16, capacity: usize) -> i32 {
    alloc_streaming_for_module(channel, capacity, NO_MODULE)
}

/// Allocate a streaming buffer tagged with its producer module.
pub fn alloc_streaming_for_module(channel: i16, capacity: usize, producer_module: ModuleId) -> i32 {
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
            let buf = alloc_buffer(capacity);
            match buf {
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
                    log::warn!("[buf] arena exhausted size={capacity}");
                    return -1;
                }
            }
        }
    }
    log::warn!("[buf] no free slots ch={channel}");
    -1
}

/// Free a buffer slot and return its arena memory for reuse.
///
/// A mailbox buffer may be in any state when its channel closes. One that is
/// lent out — a writer in `PRODUCER` or a reader in `CONSUMER` holds its
/// pointer — is not returned: the holder may still touch it, and memory
/// handed to the next channel would take that write. It stays spent (counted
/// as leaked) until the next `reset_buffer_arena`. Any other state means no
/// pointer to it is outstanding.
pub fn free_streaming(slot: i32) {
    if !valid_slot(slot) {
        return;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    // Take the slot out of every state a mailbox transition starts from, so
    // the state judged below is the one it was freed in.
    let mut prev_state = buf.state();
    loop {
        if prev_state == STATE_FREE || prev_state == STATE_CLOSING {
            return;
        }
        match buf.state.compare_exchange_weak(
            prev_state,
            STATE_CLOSING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(now) => prev_state = now,
        }
    }
    let ptr = buf.data_ptr();
    let size = buf.capacity.load(Ordering::Acquire) as usize;
    buf.reset();
    if matches!(prev_state, STATE_PRODUCER | STATE_CONSUMER) {
        abandon_buffer(size);
    } else {
        // SAFETY: the slot no longer names the buffer, its channel is
        // closed, and no mailbox lend of it is outstanding.
        unsafe { release_buffer(ptr, size) };
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
/// Returns true if the slot holds a buffer and was reset.
pub fn mailbox_flush(slot: i32) -> bool {
    if !valid_slot(slot) {
        return false;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    let mut cur = buf.state();
    loop {
        // A slot with no buffer behind it stays as it is.
        if cur == STATE_FREE || cur == STATE_CLOSING {
            return false;
        }
        match buf.state.compare_exchange_weak(
            cur,
            STATE_STREAMING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(now) => cur = now,
        }
    }
    buf.len.store(0, Ordering::Release);
    buf.inplace_flag.store(0, Ordering::Release);
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
pub fn has_ready(channel: i16) -> bool {
    BUFFER_REGISTRY
        .iter()
        .any(|s| s.owner() == channel && matches!(s.state(), STATE_READY | STATE_READY_PROCESSED))
}

/// Check if registry has any free slots
pub fn has_free() -> bool {
    BUFFER_REGISTRY.iter().any(|s| s.state() == STATE_FREE)
}

/// Snapshot of buffer-pool slot occupancy. Counters are `usize` so a
/// fully-occupied 256-slot pool fits without overflow; the `capacity`
/// field equals `MAX_BUFFER_SLOTS` and lets callers sanity-check the
/// sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferPoolStats {
    /// Slots in `STATE_FREE` — available for `alloc_streaming`.
    pub free: usize,
    /// Slots in `STATE_PRODUCER` — mailbox writer holds an exclusive
    /// acquire.
    pub producer: usize,
    /// Slots in `STATE_READY` or `STATE_READY_PROCESSED` — data is
    /// queued for the consumer.
    pub ready: usize,
    /// Slots in `STATE_CONSUMER` — mailbox reader holds the slot.
    pub consumer: usize,
    /// Slots in `STATE_STREAMING` — FIFO-style pipe channel buffers.
    pub streaming: usize,
    /// Total slots in the registry (== `MAX_BUFFER_SLOTS`).
    pub capacity: usize,
}

/// Get pool statistics for diagnostics.
pub fn stats() -> BufferPoolStats {
    let mut s = BufferPoolStats {
        free: 0,
        producer: 0,
        ready: 0,
        consumer: 0,
        streaming: 0,
        capacity: MAX_BUFFER_SLOTS,
    };

    for slot in BUFFER_REGISTRY.iter() {
        match slot.state() {
            STATE_FREE => s.free += 1,
            STATE_PRODUCER => s.producer += 1,
            STATE_READY | STATE_READY_PROCESSED => s.ready += 1,
            STATE_CONSUMER => s.consumer += 1,
            STATE_STREAMING => s.streaming += 1,
            _ => {}
        }
    }

    s
}

/// Reset every buffer slot at a graph rebuild. The arena memory is reclaimed
/// separately, wholesale, by `reset_buffer_arena`.
pub fn reset_all() {
    for slot in BUFFER_REGISTRY.iter() {
        slot.reset();
    }
}

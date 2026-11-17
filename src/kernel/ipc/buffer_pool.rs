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
//! Each buffer serves one of two modes:
//!
//! **FIFO (ring):** the channel's ring of records, read and written with copy
//! semantics (`channel_read` / `channel_write`). The record stays IDLE.
//!
//! **Mailbox:** one record handed from producer to consumer, lent rather than
//! copied (`ACQUIRE_WRITE` / `RELEASE_WRITE` / `ACQUIRE_READ` /
//! `RELEASE_READ` / `ACQUIRE_INPLACE`). Enabled for aliased (`buffer_group`)
//! channels.
//!
//! ## The record machine
//!
//! ```text
//!             acquire_write              publish(len>0)             acquire_read
//!    IDLE ─────────────────► WRITING ─────────────────► READY ─────────────────► READING
//!     ▲  ◄── cancel_write ──────┘ ▲                       │ ▲                      │
//!     │     (len == 0)            │ acquire_inplace       │ └──── cancel_read ─────┤
//!     │                           └─ (READY && !processed)┘     (bit untouched)    │
//!     │◄────────────────────────── release_read ──────────────────────────────────┘
//!     │◄── flush (READY only; processed = 0)       flush on WRITING/READING = EBUSY
//! ```
//!
//! - A lend (WRITING or READING) names its `holder`; only the holder ends it,
//!   by release or cancel. Otherwise it ends when the holder retires
//!   ([`release_lends_of`]) or the channel closes ([`free_streaming`], which
//!   abandons the memory rather than hand it to the next channel).
//! - `processed` is set when a WRITING that began as an in-place acquire
//!   publishes, and cleared when the record leaves READY for IDLE: at most
//!   one in-place transform runs per record.
//!
//! Both modes use the same arena-allocated buffer.

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

/// Buffer arena size: the kernel profile's (`kernel::config`). On the RP parts
/// the arena is no static: each graph's plan carves it from the kernel's
/// static pool at the plan's `buffer_arena` ceiling (the silicon TOML's
/// `[kernel] buffer_arena_kb` by default), [`install_arena`].
#[cfg(not(feature = "rp"))]
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

#[cfg(not(feature = "rp"))]
#[repr(C, align(64))]
struct AlignedBufferArena([u8; BUFFER_ARENA_SIZE]);
#[cfg(not(feature = "rp"))]
const _: () = assert!(core::mem::align_of::<AlignedBufferArena>() == BUFFER_ALIGN);
#[cfg(not(feature = "rp"))]
static mut BUFFER_ARENA: AlignedBufferArena = AlignedBufferArena([0; BUFFER_ARENA_SIZE]);

/// RP: the arena the graph's plan carved, `[base, base + cap)`; `(0, 0)` while
/// a plan is in progress, when no buffer can be handed out.
#[cfg(feature = "rp")]
static ARENA_BASE: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "rp")]
static ARENA_CAP: AtomicUsize = AtomicUsize::new(0);

/// The arena's first byte.
#[inline]
fn arena_base() -> *mut u8 {
    #[cfg(feature = "rp")]
    {
        ARENA_BASE.load(Ordering::Acquire) as *mut u8
    }
    #[cfg(not(feature = "rp"))]
    // SAFETY: an address computation on the arena static; nothing is read or
    // written through it here.
    unsafe {
        core::ptr::addr_of_mut!(BUFFER_ARENA.0).cast::<u8>()
    }
}

/// The arena's capacity in bytes.
#[inline]
fn arena_cap() -> usize {
    #[cfg(feature = "rp")]
    {
        ARENA_CAP.load(Ordering::Acquire)
    }
    #[cfg(not(feature = "rp"))]
    {
        BUFFER_ARENA_SIZE
    }
}

/// RP: give the arena the block the graph's plan carved for it
/// (`kernel::mem::carve::place_arenas`), empty.
#[cfg(feature = "rp")]
pub fn install_arena(base: *mut u8, cap: usize) {
    with_arena(|l| {
        l.count = 0;
        l.leaked = 0;
        BUFFER_ARENA_OFFSET.store(0, Ordering::Relaxed);
        ARENA_BASE.store(base as usize, Ordering::Release);
        ARENA_CAP.store(cap, Ordering::Release);
    });
}

/// RP: the plan starts over (`kernel::mem::carve::begin_plan`); nothing in
/// the arena is live at a rebuild.
#[cfg(feature = "rp")]
pub fn uninstall_arena() {
    with_arena(|l| {
        l.count = 0;
        l.leaked = 0;
        BUFFER_ARENA_OFFSET.store(0, Ordering::Relaxed);
        ARENA_BASE.store(0, Ordering::Release);
        ARENA_CAP.store(0, Ordering::Release);
    });
}

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
    (BUFFER_ARENA_OFFSET.load(Ordering::Relaxed), arena_cap())
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
        if off + need > arena_cap()
            || !crate::kernel::sys::resource_ledger::enforced_allows(
                crate::abi::contracts::resource::POOL_BUFFER_ARENA,
                (off + need) as u64,
            )
        {
            return Err(off);
        }
        BUFFER_ARENA_OFFSET.store(off + need, Ordering::Relaxed);
        Ok(off)
    });
    match got {
        Ok(off) => {
            // SAFETY: `off + need <= arena_cap()` (checked at the bump, and
            // every free region lies below the mark), and the range is this
            // caller's alone once it left the allocator.
            unsafe {
                let ptr = arena_base().add(off);
                core::ptr::write_bytes(ptr, 0, size);
                Some(ptr)
            }
        }
        Err(used) => {
            log::error!(
                "[buf] arena full need={need} used={used} cap={}",
                arena_cap()
            );
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
    let base = arena_base() as usize;
    let addr = ptr as usize;
    let Some(need) = arena_need(size) else { return };
    if size == 0 || base == 0 || addr < base || addr + need > base + arena_cap() {
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
// Record states
// ============================================================================

/// Slot unused (no arena memory assigned).
pub const STATE_FREE: u8 = 0;
/// The holder is writing the record.
pub const STATE_WRITING: u8 = 1;
/// The record is published, waiting for its reader.
pub const STATE_READY: u8 = 2;
/// The holder is reading the record.
pub const STATE_READING: u8 = 3;
/// No record: a mailbox between records, or a ring's buffer.
pub const STATE_IDLE: u8 = 4;
/// Slot being freed (`free_streaming`): no transition starts from it, and it
/// becomes FREE once the slot is cleared.
const STATE_CLOSING: u8 = 6;

/// Success
pub const BUF_OK: i32 = errno::OK;
/// Nothing to lend now.
pub const BUF_EAGAIN: i32 = errno::EAGAIN;
/// Invalid argument
pub const BUF_EINVAL: i32 = errno::EINVAL;
/// Record in the wrong state, or lent to someone else.
pub const BUF_EBUSY: i32 = errno::EBUSY;

// ============================================================================
// Buffer Registry Slot
// ============================================================================

/// A registry entry tracking an arena-allocated buffer.
///
/// The actual buffer data lives in the buffer arena; this slot only holds
/// metadata (pointer, capacity, record state).
struct BufferRegistrySlot {
    /// Pointer to arena-allocated buffer data (null if not allocated)
    data_ptr: core::cell::UnsafeCell<*mut u8>,
    /// Buffer capacity in bytes (set at allocation time)
    capacity: AtomicU32,
    /// The record's length (set when it is published)
    len: AtomicU32,
    /// Record state (FREE/IDLE/WRITING/READY/READING/CLOSING)
    state: AtomicU8,
    /// Owner channel slot (-1 if not associated). Stored as `i16` so the
    /// full configured `MAX_CHANNELS` range fits without silent narrowing.
    owner_channel: AtomicI16,
    /// The current WRITING began as an in-place acquire.
    inplace: AtomicBool,
    /// An in-place writer has processed the record.
    processed: AtomicBool,
    /// The module a lend (WRITING or READING) is lent to.
    holder: AtomicU16,
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
            inplace: AtomicBool::new(false),
            processed: AtomicBool::new(false),
            holder: AtomicU16::new(NO_MODULE),
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
        // of the raw pointer is a single load. The record state machine
        // synchronises access to the pointed-at memory.
        unsafe { *self.data_ptr.get() }
    }

    /// Assign arena-allocated memory to this slot.
    fn assign(&self, ptr: *mut u8, capacity: usize, channel: i16) {
        // SAFETY: the caller claimed this slot (FREE -> IDLE) and has
        // not yet published it to a channel, so nothing else reads it.
        unsafe {
            *self.data_ptr.get() = ptr;
        }
        self.capacity.store(capacity as u32, Ordering::Release);
        self.owner_channel.store(channel, Ordering::Release);
        self.len.store(0, Ordering::Release);
        self.inplace.store(false, Ordering::Release);
        self.processed.store(false, Ordering::Release);
        self.holder.store(NO_MODULE, Ordering::Release);
    }

    #[inline]
    fn cas(&self, from: u8, to: u8) -> bool {
        self.state
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Whether the record is in `state` and lent to `caller` (the kernel,
    /// `NO_MODULE`, may end any lend).
    #[inline]
    fn lent_to(&self, state: u8, caller: ModuleId) -> bool {
        self.state() == state
            && (caller == NO_MODULE || self.holder.load(Ordering::Acquire) == caller)
    }

    /// Clear the slot and mark it FREE. The state goes last, so a claimant
    /// that wins the slot after it reads FREE finds nothing of the old
    /// buffer to clobber its own.
    fn reset(&self) {
        self.owner_channel.store(-1, Ordering::Release);
        self.capacity.store(0, Ordering::Release);
        self.len.store(0, Ordering::Release);
        self.inplace.store(false, Ordering::Release);
        self.processed.store(false, Ordering::Release);
        self.holder.store(NO_MODULE, Ordering::Release);
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
/// One registry slot per channel slot: sized with the channel table
/// (`channel::size`) where the plan sizes it, the profile's static array on
/// wasm.
static BUFFER_REGISTRY: crate::kernel::mem::table::Table<BufferRegistrySlot, MAX_BUFFER_SLOTS> = crate::boot_table!(
    MAX_BUFFER_SLOTS,
    BufferRegistrySlot::new(),
    crate::abi::contracts::resource::POOL_CHANNELS
);

/// Reserve the registry for `ceiling` slots (the channel table's) and commit
/// `live`.
///
/// # Safety
/// Graph-preparation context: no reference into the registry is live.
pub unsafe fn size_registry(
    ceiling: usize,
    live: usize,
) -> Result<(), crate::kernel::mem::table::TableError> {
    BUFFER_REGISTRY.reserve(ceiling)?;
    BUFFER_REGISTRY.grow(live)
}

/// Commit registry slots until `n` are live, beside a channel-table growth.
pub fn grow_registry(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    BUFFER_REGISTRY.grow(n)
}

fn valid_slot(slot: i32) -> bool {
    slot >= 0 && (slot as usize) < BUFFER_REGISTRY.len()
}

// ============================================================================
// Channel buffers (arena-allocated)
// ============================================================================

/// Allocate a channel's buffer from the dedicated buffer arena, its record
/// IDLE.
///
/// `capacity` specifies the buffer size in bytes (e.g. 2048 for audio, 256 for events).
/// Returns buffer slot index, or -1 if no slot or arena space available.
pub fn alloc_streaming(channel: i16, capacity: usize) -> i32 {
    for (i, slot) in BUFFER_REGISTRY.iter().enumerate() {
        if slot.cas(STATE_FREE, STATE_IDLE) {
            let buf = alloc_buffer(capacity);
            match buf {
                Some(ptr) => {
                    slot.assign(ptr, capacity, channel);
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
/// A mailbox record may be in any state when its channel closes. One that is
/// lent out — WRITING or READING, its holder holding the pointer — is not
/// returned: the holder may still touch it, and memory handed to the next
/// channel would take that write. It stays spent (counted as leaked) until
/// the next `reset_buffer_arena`. Any other state means no pointer to it is
/// outstanding.
pub fn free_streaming(slot: i32) {
    if !valid_slot(slot) {
        return;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    // Take the slot out of every state a transition starts from, so the
    // state judged below is the one it was freed in.
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
    if matches!(prev_state, STATE_WRITING | STATE_READING) {
        abandon_buffer(size);
    } else {
        // SAFETY: the slot no longer names the buffer, its channel is
        // closed, and no lend of it is outstanding.
        unsafe { release_buffer(ptr, size) };
    }
}

/// The buffer behind a ring: its data, while the record is IDLE (a ring's
/// buffer never leaves IDLE). Null for an invalid slot or a lent mailbox.
pub fn get_streaming_ptr(slot: i32) -> *mut u8 {
    if !valid_slot(slot) {
        return core::ptr::null_mut();
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if buf.state() != STATE_IDLE {
        return core::ptr::null_mut();
    }
    buf.data_ptr()
}

/// Whether the slot's record is IDLE.
pub fn is_streaming(slot: i32) -> bool {
    valid_slot(slot) && BUFFER_REGISTRY[slot as usize].state() == STATE_IDLE
}

/// Whether a mailbox holds a published record (READY).
pub fn mailbox_has_data(slot: i32) -> bool {
    valid_slot(slot) && BUFFER_REGISTRY[slot as usize].state() == STATE_READY
}

/// Whether a mailbox takes a write now (IDLE).
pub fn mailbox_can_write(slot: i32) -> bool {
    valid_slot(slot) && BUFFER_REGISTRY[slot as usize].state() == STATE_IDLE
}

/// The READY record's length, while one is published.
pub fn mailbox_ready_len(slot: i32) -> Option<u32> {
    if !valid_slot(slot) {
        return None;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    // Read the length, then confirm the record was READY before and after:
    // `len` is stored before READY is (Release) and cleared after it is left.
    if buf.state() != STATE_READY {
        return None;
    }
    let len = buf.len.load(Ordering::Acquire);
    (buf.state() == STATE_READY).then_some(len)
}

/// Drop a published record: READY → IDLE (`processed` cleared), IDLE stays.
/// `EBUSY` while the record is lent (WRITING or READING): a flush never ends
/// a lend. A slot with no buffer (FREE, CLOSING) answers 0.
pub fn flush(slot: i32) -> i32 {
    if !valid_slot(slot) {
        return BUF_EINVAL;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    loop {
        match buf.state() {
            STATE_READY => {
                if buf.cas(STATE_READY, STATE_WRITING) {
                    // Held exclusively for the instant it takes to clear it.
                    buf.len.store(0, Ordering::Release);
                    buf.processed.store(false, Ordering::Release);
                    buf.state.store(STATE_IDLE, Ordering::Release);
                    return BUF_OK;
                }
            }
            STATE_WRITING | STATE_READING => return BUF_EBUSY,
            _ => return BUF_OK,
        }
    }
}

// ============================================================================
// Lends — a mailbox's record lent to its holder
// ============================================================================

/// Lend the record for writing (IDLE → WRITING) to `holder`: `(data, capacity)`,
/// or `None` when it is not IDLE.
pub fn acquire_write(slot: i32, holder: ModuleId) -> Option<(*mut u8, u32)> {
    if !valid_slot(slot) {
        return None;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if !buf.cas(STATE_IDLE, STATE_WRITING) {
        return None;
    }
    buf.holder.store(holder, Ordering::Release);
    buf.inplace.store(false, Ordering::Release);
    buf.len.store(0, Ordering::Release);
    Some((buf.data_ptr(), buf.get_capacity()))
}

/// Lend the READY record for rewriting in place (READY → WRITING) to
/// `holder`, when no in-place writer has processed it: `(data, len)`.
pub fn acquire_inplace(slot: i32, holder: ModuleId) -> Option<(*mut u8, u32)> {
    if !valid_slot(slot) {
        return None;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if buf.processed.load(Ordering::Acquire) || !buf.cas(STATE_READY, STATE_WRITING) {
        return None;
    }
    // `processed` changes only while the record is WRITING or leaving READY
    // for IDLE, both exclusive: read again now that this is exclusive.
    if buf.processed.load(Ordering::Acquire) {
        buf.state.store(STATE_READY, Ordering::Release);
        return None;
    }
    buf.holder.store(holder, Ordering::Release);
    buf.inplace.store(true, Ordering::Release);
    Some((buf.data_ptr(), buf.len.load(Ordering::Acquire)))
}

/// The record `caller` holds for writing: `(data, capacity)`, or `EBUSY`
/// when the record is not WRITING or is lent to someone else.
pub fn writing(slot: i32, caller: ModuleId) -> Result<(*mut u8, u32), i32> {
    if !valid_slot(slot) {
        return Err(BUF_EINVAL);
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if !buf.lent_to(STATE_WRITING, caller) {
        return Err(BUF_EBUSY);
    }
    Ok((buf.data_ptr(), buf.get_capacity()))
}

/// End a write lend `writing` confirmed: publish `len` bytes (WRITING →
/// READY, `processed` set when the lend was in place), or with `drop`, end
/// it without a record (WRITING → IDLE).
pub fn finish_write(slot: i32, len: u32, drop: bool) {
    if !valid_slot(slot) {
        return;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    let inplace = buf.inplace.swap(false, Ordering::AcqRel);
    buf.holder.store(NO_MODULE, Ordering::Release);
    // A close that took the record meanwhile (WRITING → CLOSING) keeps it:
    // the transition below is a CAS from WRITING, never a store.
    if drop {
        buf.len.store(0, Ordering::Release);
        buf.processed.store(false, Ordering::Release);
        buf.cas(STATE_WRITING, STATE_IDLE);
        return;
    }
    if inplace {
        buf.processed.store(true, Ordering::Release);
    }
    buf.len.store(len, Ordering::Release);
    // The record's bytes, its length and `processed` are visible before
    // READY is: the reader's acquire CAS pairs with this one.
    buf.cas(STATE_WRITING, STATE_READY);
}

/// Cancel `caller`'s write lend (WRITING → IDLE), publishing nothing.
pub fn cancel_write(slot: i32, caller: ModuleId) -> i32 {
    match writing(slot, caller) {
        Ok(_) => {
            finish_write(slot, 0, true);
            BUF_OK
        }
        Err(e) => e,
    }
}

/// Lend the READY record for reading (READY → READING) to `holder`:
/// `(data, len)`, or `None` when none is published.
pub fn acquire_read(slot: i32, holder: ModuleId) -> Option<(*const u8, u32)> {
    if !valid_slot(slot) {
        return None;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if !buf.cas(STATE_READY, STATE_READING) {
        return None;
    }
    buf.holder.store(holder, Ordering::Release);
    Some((buf.data_ptr() as *const u8, buf.len.load(Ordering::Acquire)))
}

/// End `caller`'s read lend, consuming the record (READING → IDLE,
/// `processed` cleared).
pub fn release_read(slot: i32, caller: ModuleId) -> i32 {
    if !valid_slot(slot) {
        return BUF_EINVAL;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if !buf.lent_to(STATE_READING, caller) {
        return BUF_EBUSY;
    }
    buf.holder.store(NO_MODULE, Ordering::Release);
    buf.len.store(0, Ordering::Release);
    buf.processed.store(false, Ordering::Release);
    buf.cas(STATE_READING, STATE_IDLE);
    BUF_OK
}

/// End `caller`'s read lend without consuming the record (READING → READY,
/// `processed` untouched): the record is as it was before the acquire.
pub fn cancel_read(slot: i32, caller: ModuleId) -> i32 {
    if !valid_slot(slot) {
        return BUF_EINVAL;
    }
    let buf = &BUFFER_REGISTRY[slot as usize];
    if !buf.lent_to(STATE_READING, caller) {
        return BUF_EBUSY;
    }
    buf.holder.store(NO_MODULE, Ordering::Release);
    buf.cas(STATE_READING, STATE_READY);
    BUF_OK
}

/// End every lend `module` holds, as its retirement does: a write lend is
/// cancelled (nothing published), a read lend returned unconsumed.
pub fn release_lends_of(module: ModuleId) {
    if module == NO_MODULE {
        return;
    }
    for (i, buf) in BUFFER_REGISTRY.iter().enumerate() {
        if buf.holder.load(Ordering::Acquire) != module {
            continue;
        }
        match buf.state() {
            STATE_WRITING => {
                cancel_write(i as i32, module);
            }
            STATE_READING => {
                cancel_read(i as i32, module);
            }
            _ => {}
        }
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

/// Whether a channel's record is published (READY).
pub fn has_ready(channel: i16) -> bool {
    BUFFER_REGISTRY
        .iter()
        .any(|s| s.owner() == channel && s.state() == STATE_READY)
}

/// Check if registry has any free slots
pub fn has_free() -> bool {
    BUFFER_REGISTRY.iter().any(|s| s.state() == STATE_FREE)
}

/// Snapshot of buffer-pool slot occupancy. Counters are `usize` so a
/// fully-occupied pool fits without overflow; the `capacity` field is the
/// registry's live slot count and lets callers sanity-check the sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferPoolStats {
    /// Slots in `STATE_FREE` — available for `alloc_streaming`.
    pub free: usize,
    /// Records WRITING — lent to their writer.
    pub writing: usize,
    /// Records READY — published, waiting for their reader.
    pub ready: usize,
    /// Records READING — lent to their reader.
    pub reading: usize,
    /// Records IDLE — ring buffers and empty mailboxes.
    pub idle: usize,
    /// Total slots in the registry.
    pub capacity: usize,
}

/// Get pool statistics for diagnostics.
pub fn stats() -> BufferPoolStats {
    let mut s = BufferPoolStats {
        free: 0,
        writing: 0,
        ready: 0,
        reading: 0,
        idle: 0,
        capacity: BUFFER_REGISTRY.len(),
    };

    for slot in BUFFER_REGISTRY.iter() {
        match slot.state() {
            STATE_FREE => s.free += 1,
            STATE_WRITING => s.writing += 1,
            STATE_READY => s.ready += 1,
            STATE_READING => s.reading += 1,
            STATE_IDLE => s.idle += 1,
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

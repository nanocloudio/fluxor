//! Channel - kernel-managed pipes for inter-module data flow.
//!
//! A channel joins one producer to one consumer. The kernel opens channels
//! when it builds the graph or adds to it live, binds each one's ends to the
//! modules at either side of its edge, and hands the modules handles.
//! Closing a channel (a live removal, or the next rebuild) returns its buffer
//! to the buffer arena for the next one.
//!
//! ## Two modes, one commit
//!
//! - **Ring (FIFO):** `channel_write` lands one record, whole or not at all
//!   (`ringbuf` keeps each record's length, so `RECORD_LEN` can answer it);
//!   `channel_read` is a byte stream over the records' payload and MAY be
//!   partial.
//! - **Mailbox:** one record lent rather than copied (`ACQUIRE_WRITE` /
//!   `RELEASE_WRITE` / `ACQUIRE_READ` / `RELEASE_READ` / `ACQUIRE_INPLACE`,
//!   `buffer_pool`'s record machine). Enabled only for an edge the scheduler
//!   aliases through `buffer_group` (`scheduler::open_channels`).
//!   `channel_read` / `channel_write` work on a mailbox too, copying: a read
//!   needs room for the whole record (else `EINVAL`, the record left in
//!   place), and a write larger than the buffer is refused (`EINVAL`).
//!
//! Every successful write — ring or mailbox, copied or lent, with its reader
//! gone or not — ends in [`committed`]: WROTE set, the tap's copy, the
//! consumer's wake. A lent write's only exit is [`publish`].
//!
//! ## Ends
//!
//! Every op is checked against the caller's end of the channel, by op side:
//! reads, peeks, discards, `RECORD_LEN` and the read and in-place lends are
//! the consumer's (or an alias chain's in-place relay's); writes, `SET_HUP`,
//! `WRITABLE` and the write lend the producer's; poll, flush and close either
//! end's. The kernel (`NO_MODULE`) acts on every channel. The `channel_*`
//! functions here are the kernel's own; a module's calls come through the
//! syscall-table entries and the channel provider, which pass the caller.
//!
//! ## In-place processing
//!
//! `ACQUIRE_INPLACE` lets a module in an alias chain rewrite the READY record
//! (READY → WRITING); its `RELEASE_WRITE` publishes the record marked
//! processed, which no second in-place acquire takes. At most one in-place
//! module runs per alias chain. See `docs/architecture/pipeline.md`
//! §FIFO→Mailbox for mixing the modes in a pipeline.

use core::cell::UnsafeCell;
use portable_atomic::{AtomicBool, AtomicI16, AtomicI32, AtomicU16, AtomicU32, AtomicU8, Ordering};

use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};

use crate::kernel::boot::config::MAX_GRAPH_EDGES;
use crate::kernel::ipc::buffer_pool::{self, BUFFER_SIZE};
use crate::kernel::ipc::ringbuf::RingBufState;
use crate::kernel::sys::errno;
use log::{debug, trace};

/// Maximum channels matches max graph edges to support fan-in/out expansion
pub const MAX_CHANNELS: usize = MAX_GRAPH_EDGES;

// Channel ids are stored in `i16`-typed fields (notably
// `BufferRegistrySlot.owner_channel`) with `-1` reserved as the
// no-owner sentinel; the valid range is `[0, i16::MAX]`. Widening
// `MAX_CHANNELS` past this requires widening the owner-channel
// storage; the assert below fails the build if that invariant is
// broken.
const _: () = assert!(
    MAX_CHANNELS <= i16::MAX as usize + 1,
    "MAX_CHANNELS exceeds i16 sentinel-aware range; widen ChannelSlot.buffer_slot \
     and BufferRegistrySlot.owner_channel storage before increasing this limit"
);

// Poll flags — re-exported from abi::poll for kernel-internal use.
pub use crate::abi::poll::ERR as POLL_ERR;
pub use crate::abi::poll::HUP as POLL_HUP;
pub use crate::abi::poll::IN as POLL_IN;
pub use crate::abi::poll::OUT as POLL_OUT;
pub use crate::abi::poll::WROTE as POLL_WROTE;

pub const CHAN_OK: i32 = errno::OK;
pub const CHAN_EAGAIN: i32 = errno::EAGAIN;
pub const CHAN_EBUSY: i32 = errno::EBUSY;
pub const CHAN_EINVAL: i32 = errno::EINVAL;

// ============================================================================
// Channel Storage
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChannelState {
    Free = 0,
    Open = 1,
}

/// `events` bits: the stream's end, as the producer stated it.
const EV_HUP: u8 = POLL_HUP as u8;
/// `events` bits: the producer failed.
const EV_ERR: u8 = POLL_ERR as u8;

/// The side of the channel an op acts from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// Writes, `SET_HUP`, `WRITABLE`, the write lend.
    Producer,
    /// Reads, peeks, discards, `RECORD_LEN`, the read and in-place lends.
    Consumer,
    /// Poll, flush, close, and the end of a lend (its holder is checked).
    Either,
}

/// FIFO state for circular buffer operations.
///
/// Uses shared `RingBufState` from `kernel::ipc::ringbuf`.
/// `capacity` is set at channel open time from the arena-allocated buffer size.
type FifoState = RingBufState;

struct ChannelSlot {
    state: AtomicU8,
    lock: AtomicBool,
    /// Set by the first successful write since the last flush, and
    /// never cleared except by `FLUSH` / slot reset.
    ///
    /// HUP alone cannot tell a stream that ended from one that never
    /// started: a producer terminated or retired before its first write
    /// hangs up its outputs exactly as a finished one does. Reported as
    /// `POLL_WROTE` so a consumer can pair it with `POLL_HUP` and tell the
    /// two apart.
    ever_written: AtomicBool,
    /// The consumer has finished: nothing will read this channel again.
    /// Set by the scheduler when it retires a module, for every channel
    /// that module read from. A finished reader's ring would otherwise
    /// fill and stay full, and back-pressure is transitive -- through a
    /// tee it stops the producer for every OTHER consumer too. A channel
    /// in this state commits every write and keeps none of it.
    reader_gone: AtomicBool,
    /// Channel is in mailbox mode (one lent record). Set by the scheduler
    /// for aliased channels (`buffer_group != 0`).
    mailbox: AtomicBool,
    /// Bytes `channel_discard` still owes the stream: dropped from the front
    /// of each write as it arrives, before anything lands in the ring. Read
    /// and written only under the ring lock.
    discard_owed: AtomicU32,
    /// Index into buffer registry (-1 if no buffer allocated).
    buffer_slot: AtomicI16,
    /// Consumer module to event-wake on a successful write (`wake: true`
    /// edges), -1 for none. Bound via `channel_set_wake_module`.
    wake_module: AtomicI16,
    /// FIFO state for circular buffer operations
    fifo: UnsafeCell<FifoState>,
    /// A tap: the channel every successful write here is also copied into,
    /// or -1. Lossy by design — a copy that does not fit whole is dropped,
    /// so an observer can never back-pressure or stall the producer.
    mirror: AtomicI32,
    /// The generation a handle to this slot carries; moved on every open.
    generation: AtomicU16,
    /// The module that writes the channel (`NO_MODULE`: the kernel alone).
    producer: AtomicU16,
    /// The module that reads it.
    consumer: AtomicU16,
    /// An alias chain's in-place module: it reads (in place) what the
    /// producer wrote and hands it on to the consumer on the same record.
    relay: AtomicU16,
    /// `HUP | ERR` as the producer (or its retirement) stated them.
    events: AtomicU8,
    /// The producer has retired: HUP holds whatever a flush does.
    producer_gone: AtomicBool,
}

// SAFETY: `ChannelSlot` interior is split between the atomics
// (`state`, `lock`, `buffer_slot`, etc., all `Sync`) and the
// `UnsafeCell<FifoState>` guarded by the spin-lock in `with_lock`.
// Every mutation of `fifo` happens under that lock, so cross-thread
// access is sequenced.
unsafe impl Sync for ChannelSlot {}

/// What an attempt to claim one channel slot came to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotClaim {
    Claimed,
    /// Another channel holds the slot; the next one may be free.
    Taken,
    /// The slot was free but the buffer arena could not back it. Every
    /// other free slot would fail the same way.
    NoBuffer,
}

impl ChannelSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(ChannelState::Free as u8),
            lock: AtomicBool::new(false),
            ever_written: AtomicBool::new(false),
            reader_gone: AtomicBool::new(false),
            mailbox: AtomicBool::new(false),
            discard_owed: AtomicU32::new(0),
            buffer_slot: AtomicI16::new(-1),
            wake_module: AtomicI16::new(-1),
            fifo: UnsafeCell::new(FifoState::new()),
            mirror: AtomicI32::new(-1),
            generation: AtomicU16::new(0),
            producer: AtomicU16::new(NO_MODULE),
            consumer: AtomicU16::new(NO_MODULE),
            relay: AtomicU16::new(NO_MODULE),
            events: AtomicU8::new(0),
            producer_gone: AtomicBool::new(false),
        }
    }

    /// Claim the slot (Free → Open) with a buffer of `buf_capacity` bytes,
    /// both ends `end`. No handle names the slot at its current generation
    /// until this returns: the close before it moved the generation on.
    fn try_claim(&self, idx: usize, buf_capacity: usize, end: ModuleId) -> SlotClaim {
        if self
            .state
            .compare_exchange(
                ChannelState::Free as u8,
                ChannelState::Open as u8,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return SlotClaim::Taken;
        }
        let buf_slot = buffer_pool::alloc_streaming(idx as i16, buf_capacity);
        if buf_slot < 0 {
            self.state
                .store(ChannelState::Free as u8, Ordering::Release);
            return SlotClaim::NoBuffer;
        }
        self.producer.store(end, Ordering::Relaxed);
        self.consumer.store(end, Ordering::Relaxed);
        self.relay.store(NO_MODULE, Ordering::Relaxed);
        self.events.store(0, Ordering::Relaxed);
        self.producer_gone.store(false, Ordering::Relaxed);
        // SAFETY: `self.fifo` is an `UnsafeCell<FifoState>` owned by this
        // slot; the claim above means no other reader/writer holds a
        // reference, and no handle names the slot yet.
        unsafe {
            (*self.fifo.get()).init(buf_capacity);
        }
        self.buffer_slot.store(buf_slot as i16, Ordering::Release);
        SlotClaim::Claimed
    }

    fn reset(&self) {
        // A handle to the closing channel names nothing from here on, and
        // the next channel in the slot is told apart from this one.
        self.generation.store(
            self.generation.load(Ordering::Relaxed).wrapping_add(1)
                & crate::abi::kernel_abi::handle::GEN_MASK,
            Ordering::Release,
        );
        // Detach the buffer under the ring lock: a reader or writer on
        // another core either finishes with it first or finds no buffer. Only
        // then does it go back to the arena, where the next channel may take
        // it.
        let buf_slot = self.with_lock(|fifo, _| {
            *fifo = FifoState::new();
            self.discard_owed.store(0, Ordering::Relaxed);
            self.buffer_slot.swap(-1, Ordering::AcqRel)
        });
        if buf_slot >= 0 {
            buffer_pool::free_streaming(buf_slot as i32);
        }
        self.ever_written.store(false, Ordering::Release);
        self.reader_gone.store(false, Ordering::Release);
        self.mailbox.store(false, Ordering::Release);
        self.wake_module.store(-1, Ordering::Release);
        self.mirror.store(-1, Ordering::Release);
        self.producer.store(NO_MODULE, Ordering::Release);
        self.consumer.store(NO_MODULE, Ordering::Release);
        self.relay.store(NO_MODULE, Ordering::Release);
        self.events.store(0, Ordering::Release);
        self.producer_gone.store(false, Ordering::Release);
        self.state
            .store(ChannelState::Free as u8, Ordering::Release);
    }

    /// Whether `caller` acts from `end` of this channel: the module bound to
    /// that end, the kernel (`NO_MODULE`) from every end, and an alias
    /// chain's relay from the consumer's. An either-end op compares only the
    /// bound ends inline and admits the kernel and the relay out of line.
    #[inline]
    fn admits(&self, caller: ModuleId, end: End) -> bool {
        match end {
            End::Producer => caller == NO_MODULE || self.producer.load(Ordering::Relaxed) == caller,
            End::Consumer => {
                caller == NO_MODULE
                    || self.consumer.load(Ordering::Relaxed) == caller
                    || self.relay.load(Ordering::Relaxed) == caller
            }
            End::Either => {
                self.producer.load(Ordering::Relaxed) == caller
                    || self.consumer.load(Ordering::Relaxed) == caller
                    || self.admits_unbound(caller)
            }
        }
    }

    /// Whether `caller`, bound to neither end, acts from either all the
    /// same: the kernel, or the relay.
    #[cold]
    #[inline(never)]
    fn admits_unbound(&self, caller: ModuleId) -> bool {
        caller == NO_MODULE || self.relay.load(Ordering::Relaxed) == caller
    }

    #[inline]
    fn buf(&self) -> i32 {
        i32::from(self.buffer_slot.load(Ordering::Acquire))
    }

    fn get_buffer_ptr(&self) -> *mut u8 {
        let slot = self.buffer_slot.load(Ordering::Acquire);
        if slot < 0 {
            return core::ptr::null_mut();
        }
        buffer_pool::get_streaming_ptr(slot as i32)
    }
    fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut FifoState, Option<&mut [u8]>) -> R,
    {
        // Bounded spin with yield to prevent starvation under cross-core contention.
        // The critical section is short (ring buffer read/write), so contention is brief.
        let mut spins = 0u32;
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            spins += 1;
            if spins > 256 {
                // SAFETY: aarch64 `YIELD` is a hint, side-effect-free,
                // safe to issue from any privilege level.
                #[cfg(target_arch = "aarch64")]
                unsafe {
                    core::arch::asm!("yield", options(nomem, nostack));
                }
                spins = 0;
            }
            core::hint::spin_loop();
        }
        let buf_ptr = self.get_buffer_ptr();
        // SAFETY: the spin-lock above gives this thread exclusive access
        // to `self.fifo` for the duration of `f`.
        let fifo = unsafe { &mut *self.fifo.get() };
        let storage = if buf_ptr.is_null() {
            None
        } else {
            // SAFETY: `buf_ptr` was obtained from `buffer_pool::get_streaming_ptr`
            // for the slot pinned in `self.buffer_slot`; `reset` detaches the
            // buffer under this lock, so it cannot be released while this
            // slice is live.
            Some(unsafe { core::slice::from_raw_parts_mut(buf_ptr, fifo.capacity()) })
        };
        let result = f(fifo, storage);
        self.lock.store(false, Ordering::Release);
        result
    }
}

/// The channel slot table: reserved at boot to the plan's `channels` ceiling
/// and committed as channels open (`size`) on Linux, bcm2712 and RP, the
/// profile's static array on wasm.
static CHANNELS: crate::kernel::mem::table::Table<ChannelSlot, MAX_CHANNELS> = crate::boot_table!(
    MAX_CHANNELS,
    ChannelSlot::new(),
    crate::abi::contracts::resource::POOL_CHANNELS
);

/// The channel contract's id: the contract field of every channel handle.
const CHANNEL: u16 = crate::abi::registry::channel::ID;

/// The open channel `handle` names: its slot index and slot. `None` for a
/// handle of another contract, a slot past the table, a slot not open, or
/// one opened again since the handle was minted (its generation moved on).
#[inline]
fn resolve(handle: i32) -> Option<(usize, &'static ChannelSlot)> {
    let (c, generation, idx) = crate::abi::kernel_abi::handle::decode(handle)?;
    let idx = idx as usize;
    let slot = CHANNELS.get(idx)?;
    (c == CHANNEL
        && slot.generation.load(Ordering::Acquire) == generation
        && slot.state.load(Ordering::Acquire) == ChannelState::Open as u8)
        .then_some((idx, slot))
}

/// The open channel `handle` names, when `caller` acts from `end` of it:
/// `EBADF` otherwise.
#[inline]
fn resolve_as(handle: i32, caller: ModuleId, end: End) -> Result<&'static ChannelSlot, i32> {
    match resolve(handle) {
        Some((_, slot)) if slot.admits(caller, end) => Ok(slot),
        _ => Err(errno::EBADF),
    }
}

/// The handle naming slot `idx` at its current generation.
fn handle_of(idx: usize, slot: &ChannelSlot) -> i32 {
    crate::abi::kernel_abi::handle::encode(
        CHANNEL,
        slot.generation.load(Ordering::Acquire),
        idx as u32,
    )
}

/// The slot index `handle` names, while the channel is open: the key the
/// buffer registry and the scheduler's per-edge tables share.
pub fn slot_index(handle: i32) -> Option<usize> {
    resolve(handle).map(|(i, _)| i)
}

/// Reserve the channel table for `ceiling` slots and commit `live` of them.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size(
    ceiling: usize,
    live: usize,
) -> Result<(), crate::kernel::mem::table::TableError> {
    CHANNELS.reserve(ceiling)?;
    CHANNELS.grow(live)?;
    crate::kernel::ipc::buffer_pool::size_registry(ceiling, live)
}

/// Channel slots live now.
pub fn slots() -> usize {
    CHANNELS.len()
}

/// Slots not in `Free` state — resource-ledger sample for `POOL_CHANNELS`.
pub fn in_use_count() -> usize {
    CHANNELS
        .iter()
        .filter(|c| c.state.load(Ordering::Relaxed) != ChannelState::Free as u8)
        .count()
}

// ============================================================================
// Open, bind, close
// ============================================================================

/// The ring capacity an OPEN's argument asks for: empty → the default
/// (`BUFFER_SIZE`); four bytes → a little-endian `u32`, a power of two within
/// `[MIN_RING_BYTES, MAX_RING_BYTES]` (`ring_size`, the bounds the scheduler
/// and the composer size rings by). Every other shape is a wiring bug.
fn ring_capacity(config: &[u8]) -> Option<usize> {
    match *config {
        [] => Some(BUFFER_SIZE),
        [a, b, c, d] => {
            let size = u32::from_le_bytes([a, b, c, d]);
            (super::ring_size::MIN_RING_BYTES..=super::ring_size::MAX_RING_BYTES)
                .contains(&size)
                .then_some(size as usize)
                .filter(|s| s.is_power_of_two())
        }
        _ => None,
    }
}

/// Open a channel the kernel's own code holds: both ends `NO_MODULE` until
/// [`channel_bind_edge`] names them.
pub fn channel_open(config: &[u8]) -> i32 {
    channel_open_for_module(config, NO_MODULE)
}

/// Open a channel whose producer and consumer are both `opener` (a module's
/// own `channel::OPEN`).
pub fn channel_open_for_module(config: &[u8], opener: ModuleId) -> i32 {
    // ISR-tier (Tier 1b / Tier 2) modules must not open channels — their I/O
    // rides bridge channels registered ahead of time. The build-time
    // validator already rejects this shape; the runtime check is defense in
    // depth for hand-rolled binaries.
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("channel_open") {
        return crate::kernel::sys::errno::EACCES;
    }
    let Some(buf_capacity) = ring_capacity(config) else {
        return CHAN_EINVAL;
    };
    if !crate::kernel::sys::resource_ledger::enforced_allows(
        crate::abi::contracts::resource::POOL_CHANNELS,
        in_use_count() as u32 + 1,
    ) {
        crate::kernel::sys::resource_ledger::deny(crate::abi::contracts::resource::POOL_CHANNELS);
        return crate::kernel::sys::errno::ENOSPC;
    }
    let mut from = 0;
    loop {
        let live = CHANNELS.len();
        for (idx, slot) in CHANNELS.iter().enumerate().skip(from) {
            match slot.try_claim(idx, buf_capacity, opener) {
                SlotClaim::Claimed => {
                    debug!("channel_open: channel {idx} buf_size={buf_capacity}");
                    return handle_of(idx, slot);
                }
                SlotClaim::Taken => {}
                // The arena is short, not the slot table: say so once rather
                // than retrying the same allocation against every free slot.
                SlotClaim::NoBuffer => return errno::ENOMEM,
            }
        }
        // Every live slot is taken: commit the next segment of the table,
        // within the plan's ceiling, and try the new slots.
        if CHANNELS.grow(live + 1).is_err()
            || crate::kernel::ipc::buffer_pool::grow_registry(CHANNELS.len()).is_err()
        {
            break;
        }
        from = live;
    }
    // Slot table at its ceiling — an accounted capacity denial, not a busy
    // peer.
    log::warn!(
        "[channel] open refused: pool 'channels' at its ceiling of {} slots",
        CHANNELS.len()
    );
    crate::kernel::sys::resource_ledger::deny(crate::abi::contracts::resource::POOL_CHANNELS);
    crate::kernel::sys::errno::ENOSPC
}

/// Bind the ends of one graph edge carried by `handle`: `producer` writes
/// it, `consumer` reads it (`NO_MODULE` leaves that end the kernel's). An
/// alias chain carries several edges on one channel: an edge that leaves the
/// bound consumer, or arrives at the bound producer, makes that module the
/// chain's in-place relay and moves the end past it.
pub fn channel_bind_edge(handle: i32, producer: ModuleId, consumer: ModuleId) {
    let Some((_, slot)) = resolve(handle) else {
        return;
    };
    let p = slot.producer.load(Ordering::Acquire);
    let c = slot.consumer.load(Ordering::Acquire);
    if p == NO_MODULE && c == NO_MODULE {
        slot.producer.store(producer, Ordering::Release);
        slot.consumer.store(consumer, Ordering::Release);
    } else if producer != NO_MODULE && producer == c {
        slot.relay.store(producer, Ordering::Release);
        slot.consumer.store(consumer, Ordering::Release);
    } else if consumer != NO_MODULE && consumer == p {
        slot.relay.store(consumer, Ordering::Release);
        slot.producer.store(producer, Ordering::Release);
    } else {
        if p == NO_MODULE {
            slot.producer.store(producer, Ordering::Release);
        }
        if c == NO_MODULE {
            slot.consumer.store(consumer, Ordering::Release);
        }
    }
}

/// Name `module` the end `end` of `handle` when that end is the kernel's
/// alone: a port handed to a module outside a graph edge (a merge's output,
/// a kernel-fed control input). An end already bound stays as it is.
pub fn channel_bind_end(handle: i32, end: End, module: ModuleId) {
    let Some((_, slot)) = resolve(handle) else {
        return;
    };
    let field = match end {
        End::Producer => &slot.producer,
        End::Consumer => &slot.consumer,
        End::Either => return,
    };
    let _ = field.compare_exchange(NO_MODULE, module, Ordering::AcqRel, Ordering::Acquire);
}

/// Name `handle`'s producer (`NO_MODULE`: none but the kernel) — a spare
/// lane taking or losing its producer.
pub fn channel_set_producer(handle: i32, producer: ModuleId) {
    if let Some((_, slot)) = resolve(handle) {
        slot.producer.store(producer, Ordering::Release);
    }
}

/// Close `handle` (the kernel's call).
pub fn channel_close(handle: i32) {
    if let Some((_, slot)) = resolve(handle) {
        slot.reset();
    }
}

/// Close `handle` as `caller`: either end.
pub fn close_as(handle: i32, caller: ModuleId) -> i32 {
    match resolve_as(handle, caller, End::Either) {
        Ok(slot) => {
            slot.reset();
            CHAN_OK
        }
        Err(e) => e,
    }
}

/// Snapshot of channel slot table usage. Used by diagnostics and
/// harness tests that need to assert slot-table state without
/// reaching into the private `CHANNELS` static.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelStats {
    /// Slots available for `channel_open`: committed slots in
    /// `ChannelState::Free`, and the slots below the table's ceiling not yet
    /// committed (an open commits them as it needs them).
    pub free: usize,
    /// Slots open.
    pub open: usize,
    /// The channel table's ceiling: the slots this graph's plan sized it for.
    pub capacity: usize,
}

/// Return current occupancy of the channel slot table. Snapshots are
/// non-atomic — under concurrent load `free + open` equals `capacity` only
/// at quiescent moments. Intended for diagnostics, not for steady-state
/// correctness reasoning.
pub fn stats() -> ChannelStats {
    let mut free = 0usize;
    let mut open = 0usize;
    for slot in CHANNELS.iter() {
        if slot.state.load(Ordering::Acquire) == ChannelState::Free as u8 {
            free += 1;
        } else {
            open += 1;
        }
    }
    let capacity = CHANNELS.ceiling();
    ChannelStats {
        free: free + capacity.saturating_sub(CHANNELS.len()),
        open,
        capacity,
    }
}

/// Close every channel slot. Used at graph-reconfigure boundaries so a
/// previous graph's slot claims don't accumulate across calls to
/// `scheduler::prepare_graph`.
///
/// **DMA-owned edge contract**: callers must ensure any device with
/// outstanding DMA against a buffer attached to a channel has been quiesced
/// (descriptors retired, device idle) before invoking `reset_all` (or
/// closing that one channel). The kernel does not issue `DMA_INVALIDATE` on
/// the buffer memory here — the buffer arena hands the memory to the next
/// channel opened, and a still-active device would corrupt the new occupant.
/// Platforms whose drivers hold DMA descriptors (NIC RX rings, NVMe
/// submission queues, PIO DMA streams) are responsible for tearing the
/// device down via their module's `module_drain` / `module_state_export`
/// exports before the kernel reaches this point.
pub fn reset_all() {
    for slot in CHANNELS.iter() {
        slot.reset();
    }
}

// ============================================================================
// The commit path
// ============================================================================

/// Every successful write ends here, ring or mailbox, copied or lent, its
/// reader gone or not: the channel has carried bytes (WROTE), the tap gets
/// its copy, `visible` makes the write readable (a mailbox's publish; the
/// ring's bytes already landed), and the consumer is woken.
#[inline]
fn committed(slot: &ChannelSlot, bytes: &[u8], visible: impl FnOnce()) {
    slot.ever_written.store(true, Ordering::Release);
    mirror_write(slot, bytes);
    visible();
    wake_consumer_if_flagged(slot);
}

/// The only exit from WRITING: `caller`'s lend of the mailbox record ends
/// with `len` bytes published. `EBUSY` unless `caller` holds the record for
/// writing; `len == 0` cancels it (WRITING → IDLE) and returns 0; a length
/// past the buffer's capacity is `EINVAL`, the lend kept. With the reader
/// gone the record is committed and dropped (→ IDLE).
fn publish(slot: &ChannelSlot, len: u32, caller: ModuleId) -> i32 {
    let buf_slot = slot.buf();
    let (ptr, cap) = match buffer_pool::writing(buf_slot, caller) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if len == 0 {
        buffer_pool::finish_write(buf_slot, 0, true);
        return 0;
    }
    if len > cap {
        return CHAN_EINVAL;
    }
    // SAFETY: the record is WRITING and held by `caller` (just checked): no
    // one else writes `[ptr, ptr + len)`, which is inside the buffer.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
    let gone = slot.reader_gone.load(Ordering::Acquire);
    committed(slot, bytes, || {
        buffer_pool::finish_write(buf_slot, len, gone)
    });
    len as i32
}

// ============================================================================
// Reads and writes
// ============================================================================

/// Read up to `len` bytes into `buf` as `caller` (the consumer).
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes (or null, which is
/// rejected).
pub unsafe fn read_as(handle: i32, caller: ModuleId, buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() {
        return CHAN_EINVAL;
    }
    let slot = match resolve_as(handle, caller, End::Consumer) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if len == 0 {
        return CHAN_EAGAIN;
    }
    if slot.mailbox.load(Ordering::Acquire) {
        let buf_slot = slot.buf();
        let Some((rec, rec_len)) = buffer_pool::acquire_read(buf_slot, caller) else {
            return CHAN_EAGAIN;
        };
        if (len as u32) < rec_len {
            // Too small for the whole record: put it back untouched.
            buffer_pool::cancel_read(buf_slot, caller);
            return CHAN_EINVAL;
        }
        core::ptr::copy_nonoverlapping(rec, buf, rec_len as usize);
        buffer_pool::release_read(buf_slot, caller);
        return rec_len as i32;
    }
    let out = core::slice::from_raw_parts_mut(buf, len);
    let read = slot.with_lock(|fifo, storage| {
        let Some(storage) = storage else { return -1i32 };
        fifo.read(storage, out) as i32
    });
    match read {
        r if r < 0 => CHAN_EINVAL,
        0 => CHAN_EAGAIN,
        r => r,
    }
}

/// The kernel's read of `handle`. See [`read_as`].
///
/// # Safety
/// As [`read_as`].
pub unsafe fn channel_read(handle: i32, buf: *mut u8, len: usize) -> i32 {
    read_as(handle, NO_MODULE, buf, len)
}

/// Copy up to `len` bytes from the head of the channel into `buf` without
/// consuming them, as `caller` (the consumer): from a ring, the head of its
/// stream; from a mailbox, the head of its READY record, which is lent for
/// the copy and returned untouched (`processed` too), so an in-place writer
/// on another core never races the copy. Returns the bytes copied (0 when
/// nothing is buffered).
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes (or null, which is
/// rejected with `CHAN_EINVAL`).
pub unsafe fn peek_as(handle: i32, caller: ModuleId, buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() {
        return CHAN_EINVAL;
    }
    let slot = match resolve_as(handle, caller, End::Consumer) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if slot.mailbox.load(Ordering::Acquire) {
        let buf_slot = slot.buf();
        let Some((rec, rec_len)) = buffer_pool::acquire_read(buf_slot, caller) else {
            return 0;
        };
        let n = len.min(rec_len as usize);
        core::ptr::copy_nonoverlapping(rec, buf, n);
        buffer_pool::cancel_read(buf_slot, caller);
        return n as i32;
    }
    let out = core::slice::from_raw_parts_mut(buf, len);
    let n = slot.with_lock(|fifo, storage| {
        let Some(storage) = storage else { return -1i32 };
        fifo.peek(storage, out) as i32
    });
    if n < 0 {
        CHAN_EINVAL
    } else {
        n
    }
}

/// The kernel's peek of `handle`. See [`peek_as`].
///
/// # Safety
/// As [`peek_as`].
pub unsafe fn channel_peek(handle: i32, buf: *mut u8, len: usize) -> i32 {
    peek_as(handle, NO_MODULE, buf, len)
}

/// Drop the next `len` bytes of a channel's stream without copying them, as
/// `caller` (the consumer).
///
/// On a ring, what is buffered now goes at once, and the rest is dropped
/// from the front of each later write as it arrives, before it lands.
/// Returns `len`, or `CHAN_EINVAL` for a `len` past `i32::MAX` or the owed
/// count's width.
///
/// On a mailbox the unit is the record, and no part of one is ever left:
/// `len` at least the READY record's releases it whole and returns its
/// length; `0 < len < record` is `EINVAL`, the record left in place;
/// `CHAN_EAGAIN` when none is READY. `len == 0` returns 0 either way.
pub fn discard_as(handle: i32, caller: ModuleId, len: usize) -> i32 {
    let slot = match resolve_as(handle, caller, End::Consumer) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if len > i32::MAX as usize {
        return CHAN_EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if slot.mailbox.load(Ordering::Acquire) {
        let buf_slot = slot.buf();
        let Some((_, rec_len)) = buffer_pool::acquire_read(buf_slot, caller) else {
            return CHAN_EAGAIN;
        };
        if len < rec_len as usize {
            buffer_pool::cancel_read(buf_slot, caller);
            return CHAN_EINVAL;
        }
        buffer_pool::release_read(buf_slot, caller);
        return rec_len as i32;
    }
    let ok = slot.with_lock(|fifo, storage| {
        let Some(storage) = storage else {
            return false;
        };
        let now = len.min(fifo.len());
        let owed = slot.discard_owed.load(Ordering::Relaxed) as usize;
        let Some(total_owed) = owed.checked_add(len - now) else {
            return false;
        };
        let Ok(total_owed) = u32::try_from(total_owed) else {
            return false;
        };
        fifo.skip(storage, now);
        slot.discard_owed.store(total_owed, Ordering::Relaxed);
        true
    });
    if ok {
        len as i32
    } else {
        CHAN_EINVAL
    }
}

/// The kernel's discard on `handle`. See [`discard_as`].
pub fn channel_discard(handle: i32, len: usize) -> i32 {
    discard_as(handle, NO_MODULE, len)
}

/// Write `len` bytes from `data` as one record, as `caller` (the producer):
/// whole or not at all. Returns `len`, `CHAN_EAGAIN` when it does not fit
/// now, or 0 for `len == 0`, which publishes nothing. With the reader gone a
/// write is committed and kept nowhere.
///
/// # Safety
/// `data` must be valid for reads of `len` bytes (or null, which is
/// rejected).
pub unsafe fn write_as(handle: i32, caller: ModuleId, data: *const u8, len: usize) -> i32 {
    if data.is_null() {
        return CHAN_EINVAL;
    }
    let slot = match resolve_as(handle, caller, End::Producer) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if len == 0 {
        return 0;
    }
    let input = core::slice::from_raw_parts(data, len);
    if slot.mailbox.load(Ordering::Acquire) {
        let buf_slot = slot.buf();
        let Some((rec, cap)) = buffer_pool::acquire_write(buf_slot, caller) else {
            return CHAN_EAGAIN;
        };
        if len > cap as usize {
            // Larger than the record can be: give the lend back unused.
            buffer_pool::cancel_write(buf_slot, caller);
            return CHAN_EINVAL;
        }
        core::ptr::copy_nonoverlapping(data, rec, len);
        trace!("chan_write h={handle} mailbox len={len}");
        return publish(slot, len as u32, caller);
    }
    if slot.reader_gone.load(Ordering::Acquire) {
        committed(slot, input, || {});
        return len as i32;
    }
    let took = slot.with_lock(|fifo, storage| match storage {
        Some(storage) => land(slot, fifo, storage, input) as i32,
        None => -1,
    });
    match took {
        // The tap observes the producer: it is handed the whole write,
        // whatever the consumer had asked to have dropped of it.
        1 => {
            committed(slot, input, || {});
            len as i32
        }
        0 => CHAN_EAGAIN,
        _ => CHAN_EINVAL,
    }
}

/// The kernel's write to `handle`. See [`write_as`].
///
/// # Safety
/// As [`write_as`].
pub unsafe fn channel_write(handle: i32, data: *const u8, len: usize) -> i32 {
    write_as(handle, NO_MODULE, data, len)
}

/// Take `bytes` into `slot`'s ring, after the bytes a `channel_discard` owes
/// the stream: the owed bytes are dropped from the front of `bytes`, and the
/// rest lands as one record, whole or not at all. `true` when every byte was
/// taken, dropped or landed; `false`, with nothing changed, when what remains
/// does not fit. Every writer of a ring goes through here, so a consumer that
/// dropped a frame ahead never sees its tail. Called under the ring lock.
fn land(slot: &ChannelSlot, fifo: &mut FifoState, storage: &mut [u8], bytes: &[u8]) -> bool {
    let owed = slot.discard_owed.load(Ordering::Relaxed) as usize;
    if owed >= bytes.len() {
        slot.discard_owed
            .store((owed - bytes.len()) as u32, Ordering::Relaxed);
        return true;
    }
    let rest = &bytes[owed..];
    if fifo.write(storage, rest) == 0 {
        return false;
    }
    slot.discard_owed.store(0, Ordering::Relaxed);
    true
}

/// Copy what was just written to `slot` into its tap, if it has one: whole or
/// not at all. A partial copy would split the producer's write — a line, a
/// record — into bytes the observer cannot parse, so a copy that does not fit
/// is dropped; the observer sees a gap, never a torn unit, and the producer
/// never waits on it.
fn mirror_write(slot: &ChannelSlot, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let Some((_, tap)) = resolve(slot.mirror.load(Ordering::Acquire)) else {
        return;
    };
    if tap.mailbox.load(Ordering::Acquire) {
        return;
    }
    let copied = tap.with_lock(|fifo, storage| match storage {
        Some(storage) => land(tap, fifo, storage, bytes),
        None => false,
    });
    if copied {
        tap.ever_written.store(true, Ordering::Release);
        wake_consumer_if_flagged(tap);
    }
}

/// Make `tap` receive a copy of every write to `source` (`tap < 0` clears).
/// Refuses a second tap on one channel, and a tap that names no channel.
pub fn channel_set_mirror(source: i32, tap: i32) -> bool {
    let Some((_, slot)) = resolve(source) else {
        return false;
    };
    if tap < 0 {
        slot.mirror.store(-1, Ordering::Release);
        return true;
    }
    if resolve(tap).is_none() {
        return false;
    }
    slot.mirror
        .compare_exchange(-1, tap, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Bind a consumer module to be event-woken by successful writes on this
/// channel. `module_idx < 0` clears the binding.
pub fn channel_set_wake_module(handle: i32, module_idx: i32) {
    let Some((_, slot)) = resolve(handle) else {
        return;
    };
    let clamped = if module_idx < 0
        || module_idx as usize >= crate::kernel::exec::scheduler::module_slots()
    {
        -1
    } else {
        module_idx as i16
    };
    slot.wake_module.store(clamped, Ordering::Release);
}

/// Wake-on-write: after a successful write on a `wake: true` edge,
/// latch the consumer's event-wake bit and ring the scheduler doorbell.
/// No-op for the unflagged default, so unconfigured graphs pay one relaxed
/// atomic load per write.
#[inline]
fn wake_consumer_if_flagged(slot: &ChannelSlot) {
    let m = slot.wake_module.load(Ordering::Relaxed);
    if m >= 0 {
        // `latch_module_wake` returns false when the consumer's owner is
        // paused: the wake is deferred (re-latched on `owner_resume`) and
        // the doorbell is suppressed, so a write into a paused owner never
        // leaks a cross-domain wake.
        if crate::kernel::ipc::event::latch_module_wake(m as usize) {
            crate::kernel::sys::hal::wake_scheduler();
        }
    }
}

// ============================================================================
// Readiness, records and stream state
// ============================================================================

/// The `events` that hold on `handle`, as `caller` (either end): IN when a
/// record (or a ring byte) is buffered, OUT when a write fits (or the reader
/// is gone, when every write does), HUP when the producer ended the stream
/// or is gone, ERR when it failed, WROTE when anything was written since the
/// last flush.
pub fn poll_as(handle: i32, caller: ModuleId, events: u32) -> i32 {
    let slot = match resolve_as(handle, caller, End::Either) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut ready = 0u32;
    let gone = slot.reader_gone.load(Ordering::Acquire);
    if slot.mailbox.load(Ordering::Acquire) {
        let buf_slot = slot.buf();
        if events & POLL_IN != 0 && buffer_pool::mailbox_has_data(buf_slot) {
            ready |= POLL_IN;
        }
        if events & POLL_OUT != 0 && (gone || buffer_pool::mailbox_can_write(buf_slot)) {
            ready |= POLL_OUT;
        }
    } else if events & (POLL_IN | POLL_OUT) != 0 {
        let (readable, writable) =
            slot.with_lock(|fifo, _storage| (fifo.is_readable(), fifo.is_writable()));
        if events & POLL_IN != 0 && readable {
            ready |= POLL_IN;
        }
        if events & POLL_OUT != 0 && (gone || writable) {
            ready |= POLL_OUT;
        }
    }
    let ev = slot.events.load(Ordering::Acquire);
    if events & POLL_HUP != 0 && (ev & EV_HUP != 0 || slot.producer_gone.load(Ordering::Acquire)) {
        ready |= POLL_HUP;
    }
    if events & POLL_ERR != 0 && ev & EV_ERR != 0 {
        ready |= POLL_ERR;
    }
    // HUP with WROTE is a stream that ended, HUP without it one that never
    // started.
    if events & POLL_WROTE != 0 && slot.ever_written.load(Ordering::Acquire) {
        ready |= POLL_WROTE;
    }
    trace!("chan_poll h={handle} events=0x{events:02x} ready=0x{ready:02x}");
    ready as i32
}

/// The kernel's poll of `handle`. See [`poll_as`].
pub fn channel_poll(handle: i32, events: u32) -> i32 {
    poll_as(handle, NO_MODULE, events)
}

/// The unread bytes of the record at the head of `handle`, as `caller` (the
/// consumer): a ring's head record (what a read has left of it), a mailbox's
/// READY record. `CHAN_EAGAIN` when nothing is buffered.
pub fn record_len_as(handle: i32, caller: ModuleId) -> i32 {
    let slot = match resolve_as(handle, caller, End::Consumer) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if slot.mailbox.load(Ordering::Acquire) {
        return match buffer_pool::mailbox_ready_len(slot.buf()) {
            Some(n) => n as i32,
            None => CHAN_EAGAIN,
        };
    }
    let n = slot.with_lock(|fifo, storage| storage.map_or(0, |s| fifo.record_len(s)));
    if n == 0 {
        CHAN_EAGAIN
    } else {
        n as i32
    }
}

/// The kernel's `RECORD_LEN` on `handle`. See [`record_len_as`].
pub fn channel_record_len(handle: i32) -> i32 {
    record_len_as(handle, NO_MODULE)
}

/// Start the stream over, as `caller` (either end): drop the ring's bytes or
/// the mailbox's READY record (`EBUSY` while the record is lent, and nothing
/// changes), the owed discard and WROTE, and the stated HUP — which the
/// producer's retirement still answers. ERR stays.
pub fn flush_as(handle: i32, caller: ModuleId) -> i32 {
    let slot = match resolve_as(handle, caller, End::Either) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if slot.mailbox.load(Ordering::Acquire) {
        let rc = buffer_pool::flush(slot.buf());
        if rc != 0 {
            return rc;
        }
    } else {
        slot.with_lock(|fifo, _storage| {
            fifo.clear();
            slot.discard_owed.store(0, Ordering::Relaxed);
        });
    }
    slot.events.fetch_and(!EV_HUP, Ordering::AcqRel);
    slot.ever_written.store(false, Ordering::Release);
    debug!("chan h={handle} FLUSH");
    CHAN_OK
}

/// The kernel's flush of `handle`. See [`flush_as`].
pub fn channel_flush(handle: i32) -> i32 {
    flush_as(handle, NO_MODULE)
}

/// End the stream, as `caller` (the producer): HUP, seen by the channel's
/// tap too, so a pipeline observing a finite stream completes by EOF.
pub fn set_hup_as(handle: i32, caller: ModuleId) -> i32 {
    let slot = match resolve_as(handle, caller, End::Producer) {
        Ok(s) => s,
        Err(e) => return e,
    };
    slot.events.fetch_or(EV_HUP, Ordering::AcqRel);
    if let Some((_, tap)) = resolve(slot.mirror.load(Ordering::Acquire)) {
        tap.events.fetch_or(EV_HUP, Ordering::AcqRel);
    }
    CHAN_OK
}

/// The kernel's end of `handle`'s stream. See [`set_hup_as`].
pub fn channel_set_hup(handle: i32) -> i32 {
    set_hup_as(handle, NO_MODULE)
}

/// The largest write `handle` takes now, as `caller` (the producer): a
/// ring's free space less its record prefixes, 0 for a full ring and for a
/// mailbox. A channel whose reader is gone keeps nothing and never runs out
/// of room; it answers the ring's capacity, so every caller that sizes a
/// write by this answer stays inside the bounds it was written for.
pub fn writable_as(handle: i32, caller: ModuleId) -> Result<usize, i32> {
    let slot = resolve_as(handle, caller, End::Producer)?;
    if slot.reader_gone.load(Ordering::Acquire) {
        return Ok(slot.with_lock(|fifo, _| fifo.capacity()));
    }
    if slot.mailbox.load(Ordering::Acquire) {
        return Ok(0);
    }
    Ok(slot.with_lock(|fifo, _| fifo.writable()))
}

/// The kernel's [`writable_as`]: 0 for a handle that names no channel.
pub fn channel_writable_bytes(handle: i32) -> usize {
    writable_as(handle, NO_MODULE).unwrap_or(0)
}

/// Enable mailbox mode on a channel (`buffer_group != 0`, the scheduler's
/// aliasing): the lend ops act on it from here on.
pub fn channel_set_mailbox(handle: i32) {
    let Some((_, slot)) = resolve(handle) else {
        return;
    };
    slot.mailbox.store(true, Ordering::Release);
    debug!("channel_set_mailbox: ch {handle} enabled");
}

/// Does the channel hold undelivered data — covering BOTH transport modes:
/// ring bytes AND a READY mailbox record. This is the drain-quiescence
/// emptiness check. Invalid/closed handles are empty.
pub fn channel_has_pending(handle: i32) -> bool {
    let Some((_, slot)) = resolve(handle) else {
        return false;
    };
    if slot.mailbox.load(Ordering::Acquire) {
        return buffer_pool::mailbox_has_data(slot.buf());
    }
    slot.with_lock(|fifo, _| fifo.is_readable())
}

/// Return readable payload bytes in channel's ring (0 for invalid/mailbox/empty).
pub fn channel_readable_bytes(handle: i32) -> usize {
    let Some((_, slot)) = resolve(handle) else {
        return 0;
    };
    if slot.mailbox.load(Ordering::Acquire) {
        return 0;
    }
    slot.with_lock(|fifo, _| fifo.len())
}

/// Return true if channel is in mailbox mode.
pub fn channel_is_mailbox(handle: i32) -> bool {
    resolve(handle).is_some_and(|(_, slot)| slot.mailbox.load(Ordering::Acquire))
}

/// The producer of `handle` is gone (retired, or the tapped module of a tap
/// removed): HUP from here on, whatever a flush does, and ERR too when it
/// failed.
pub fn channel_producer_gone(handle: i32, errored: bool) {
    let Some((_, slot)) = resolve(handle) else {
        return;
    };
    if errored {
        slot.events.fetch_or(EV_ERR, Ordering::AcqRel);
    }
    slot.producer_gone.store(true, Ordering::Release);
}

/// Mark a channel as one whose consumer has finished.
///
/// From here on it commits every write and keeps none: see `reader_gone`.
/// A mailbox record already published is dropped with it, since no one will
/// release it. The scheduler calls this for every input channel of a module
/// it retires.
pub fn channel_set_reader_gone(handle: i32) {
    if let Some((_, slot)) = resolve(handle) {
        slot.reader_gone.store(true, Ordering::Release);
        if slot.mailbox.load(Ordering::Acquire) {
            buffer_pool::flush(slot.buf());
        }
    }
}

// ============================================================================
// Syscall Entry Points — a module's calls, as the module stepping
// ============================================================================

/// The module whose call this is, or `EACCES` for an ISR-tier module: its
/// I/O rides bridge rings, never a channel.
#[inline]
fn caller(op: &'static str) -> Result<ModuleId, i32> {
    crate::kernel::exec::scheduler::channel_caller(op)
}

#[unsafe(no_mangle)]
pub extern "C" fn syscall_channel_close(handle: i32) {
    if let Ok(me) = caller("channel_close") {
        close_as(handle, me);
    }
}

/// # Safety
/// `buf` must be valid for writes of `len` bytes (or null, which is
/// rejected). See [`read_as`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_channel_read(handle: i32, buf: *mut u8, len: usize) -> i32 {
    match caller("channel_read") {
        Ok(me) => read_as(handle, me, buf, len),
        Err(e) => e,
    }
}

/// # Safety
/// `buf` must be valid for writes of `len` bytes (or null, which is
/// rejected). See [`peek_as`].
pub unsafe extern "C" fn syscall_channel_peek(handle: i32, buf: *mut u8, len: usize) -> i32 {
    match caller("channel_peek") {
        Ok(me) => peek_as(handle, me, buf, len),
        Err(e) => e,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn syscall_channel_discard(handle: i32, len: usize) -> i32 {
    match caller("channel_discard") {
        Ok(me) => discard_as(handle, me, len),
        Err(e) => e,
    }
}

/// # Safety
/// `data` must be valid for reads of `len` bytes (or null, which is
/// rejected). See [`write_as`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_channel_write(handle: i32, data: *const u8, len: usize) -> i32 {
    match caller("channel_write") {
        Ok(me) => write_as(handle, me, data, len),
        Err(e) => e,
    }
}

/// Poll from an ISR module would let it busy-wait on a channel.
#[unsafe(no_mangle)]
pub extern "C" fn syscall_channel_poll(handle: i32, events: u32) -> i32 {
    match caller("channel_poll") {
        Ok(me) => poll_as(handle, me, events),
        Err(e) => e,
    }
}

// ============================================================================
// Lends — the mailbox record, as a module's channel ops
// ============================================================================

/// What a mailbox acquire hands back: a status, the buffer's address, and a
/// length. The address travels beside the status and never inside it — a
/// pointer does not fit an `i32` result on a 64-bit target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acquired {
    /// `0` when the record was lent; otherwise a negative errno: `EAGAIN`
    /// for a mailbox whose record is not available now (write: not IDLE;
    /// read and in-place: none READY, or in-place: already processed),
    /// `ENOTSUP` for a channel that is not a mailbox, `EBADF` for a channel
    /// that does not exist or whose end the caller is not.
    pub status: i32,
    /// The buffer, or null unless `status` is `0`.
    pub ptr: *mut u8,
    /// Write: the buffer's capacity, also reported for a busy mailbox so a
    /// producer can tell "busy" from "not a mailbox". Read and in-place: the
    /// record's length. `0` otherwise.
    pub len: u32,
}

impl Acquired {
    const fn refused(status: i32, len: u32) -> Self {
        Self {
            status,
            ptr: core::ptr::null_mut(),
            len,
        }
    }
}

/// The mailbox channel `chan` names from `caller`'s `end`, with its buffer
/// slot, or the refusal that explains why there is none. Only a channel the
/// scheduler marked as a mailbox is lent this way: a ring's reader looks at
/// the ring's head and tail, not at the record's state.
fn mailbox_of(
    chan: i32,
    caller: ModuleId,
    end: End,
) -> Result<(&'static ChannelSlot, i32), Acquired> {
    let slot = resolve_as(chan, caller, end).map_err(|e| Acquired::refused(e, 0))?;
    if !slot.mailbox.load(Ordering::Acquire) {
        return Err(Acquired::refused(errno::ENOTSUP, 0));
    }
    Ok((slot, slot.buf()))
}

/// `ACQUIRE_WRITE`: lend the record to `caller` (the producer) for writing
/// (IDLE → WRITING). The record is the caller's until it publishes or
/// cancels it (`RELEASE_WRITE`).
pub fn buffer_acquire_write(chan: i32, caller: ModuleId) -> Acquired {
    let (_, buf_slot) = match mailbox_of(chan, caller, End::Producer) {
        Ok(v) => v,
        Err(refused) => return refused,
    };
    match buffer_pool::acquire_write(buf_slot, caller) {
        Some((ptr, cap)) => Acquired {
            status: 0,
            ptr,
            len: cap,
        },
        // Busy, not absent: the capacity tells the producer it must not fall
        // back to a ring write, which would corrupt the pending record.
        None => Acquired::refused(errno::EAGAIN, buffer_pool::get_capacity(buf_slot)),
    }
}

/// `RELEASE_WRITE`: [`publish`] `len` bytes of the record `caller` holds
/// (0 cancels the lend). Either end may hold a write lend — the producer's
/// write, the relay's in-place rewrite — and only its holder ends it.
pub fn buffer_release_write(chan: i32, caller: ModuleId, len: u32) -> i32 {
    match mailbox_of(chan, caller, End::Either) {
        Ok((slot, _)) => publish(slot, len, caller),
        Err(refused) => refused.status,
    }
}

/// `ACQUIRE_READ`: lend the READY record to `caller` (the consumer) for
/// reading (READY → READING).
pub fn buffer_acquire_read(chan: i32, caller: ModuleId) -> Acquired {
    let (_, buf_slot) = match mailbox_of(chan, caller, End::Consumer) {
        Ok(v) => v,
        Err(refused) => return refused,
    };
    match buffer_pool::acquire_read(buf_slot, caller) {
        Some((ptr, len)) => Acquired {
            status: 0,
            ptr: ptr as *mut u8,
            len,
        },
        None => Acquired::refused(errno::EAGAIN, 0),
    }
}

/// `RELEASE_READ`: end `caller`'s read lend, consuming the record (READING →
/// IDLE).
pub fn buffer_release_read(chan: i32, caller: ModuleId) -> i32 {
    match mailbox_of(chan, caller, End::Consumer) {
        Ok((_, buf_slot)) => buffer_pool::release_read(buf_slot, caller),
        Err(refused) => refused.status,
    }
}

/// `ACQUIRE_INPLACE`: lend the READY record to `caller` (the consumer, or an
/// alias chain's relay) for rewriting in place (READY → WRITING), when no
/// in-place writer has processed it. Its `RELEASE_WRITE` publishes the
/// record processed, for the next module in the chain.
pub fn buffer_acquire_inplace(chan: i32, caller: ModuleId) -> Acquired {
    let (_, buf_slot) = match mailbox_of(chan, caller, End::Consumer) {
        Ok(v) => v,
        Err(refused) => return refused,
    };
    match buffer_pool::acquire_inplace(buf_slot, caller) {
        Some((ptr, len)) => Acquired {
            status: 0,
            ptr,
            len,
        },
        None => Acquired::refused(errno::EAGAIN, 0),
    }
}

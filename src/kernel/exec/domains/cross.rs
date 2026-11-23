//! Edges between execution domains on different cores: each is split at the
//! boundary into a producer-side and a consumer-side channel joined by a
//! lock-free SPSC ring, and each side's domain pumps its half on its own core.
//! An edge between two domains of one core stays a plain channel: one loop
//! steps both ends.
//!
//! ## SPSC ring
//!
//! Each [`CrossDomainChannel`] is a single-producer, single-consumer ring of
//! [`RING_SLOTS`] slots, each sized to hold one full mailbox payload
//! ([`SLOT_DATA_SIZE`] = `abi::CHANNEL_BUFFER_SIZE`), so any frame a
//! producer-side mailbox can hold also fits a slot. The head index is the
//! producer's, the tail the consumer's, each on its own cache line.
//!
//! ## Signalling
//!
//! The producer writes the slot, publishes the head with Release, then
//! signals the other cores (the platform's `signal`: a barrier and `sev`),
//! which ends a wait for an event. A consumer domain waiting for its tick
//! interrupt takes the frame on its next pass, so its tick bounds the
//! delivery latency.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::kernel::boot::config::EdgeClass;
use crate::kernel::exec::scheduler::{self, MAX_DOMAINS};

/// The cross-domain channel index RANGE, not a table size: a
/// `CrossDomainEdge` names its ring in a `u8`. The ring and edge tables are
/// sized from the graph when it is bridged ([`size_cross`]), one per edge
/// that crosses domains.
pub const MAX_CROSS_CHANNELS: usize = 256;

/// Number of slots in each ring buffer. Must be a power of 2. A ring's slots
/// come out of the kernel's static pool on a microcontroller, where two hold
/// a frame in flight and the next behind it.
#[cfg(not(feature = "rp"))]
pub const RING_SLOTS: usize = 8;
#[cfg(feature = "rp")]
pub const RING_SLOTS: usize = 2;

/// Mask for wrapping ring indices (RING_SLOTS - 1).
const RING_MASK: u32 = (RING_SLOTS - 1) as u32;

/// Size of each slot's data payload in bytes. Sized to match
/// `abi::CHANNEL_BUFFER_SIZE` so any payload the producer-side mailbox
/// can hold also fits in a cross-domain SPSC slot — undersizing this
/// stalls the producer mailbox at READY (the pump's `channel_read`
/// returns EINVAL, the frame is never consumed).
pub const SLOT_DATA_SIZE: usize = crate::abi::CHANNEL_BUFFER_SIZE;

// ── Cross-domain telemetry ────────────────────────────────────────────────
//
// Two aggregate counters show a bridge refusing or holding back data, so an
// overloaded destination can be diagnosed on a running node:
//
// * `CROSS_DOMAIN_DROPS` — the ring refused the producer pump: a ring
//   claimed by another producing core, never a full ring (the pump checks
//   for room first). The record stays in the producer's channel.
// * `CROSS_DOMAIN_BACKPRESSURE` — a pump pass that stopped with frames left
//   where they were: the ring full on the producer side, or the consumer's
//   channel without room for the next frame. Nothing is lost, but a sustained
//   rate means the destination is under-served.
//
// `cross_domain_stats()` reads both and `cross_domain_stats_reset()` zeroes
// them.

use portable_atomic::AtomicU64;

pub static CROSS_DOMAIN_DROPS: AtomicU64 = AtomicU64::new(0);
pub static CROSS_DOMAIN_BACKPRESSURE: AtomicU64 = AtomicU64::new(0);

/// Snapshot the cross-domain counters: `(drops, backpressure)`.
pub fn cross_domain_stats() -> (u64, u64) {
    use portable_atomic::Ordering;
    (
        CROSS_DOMAIN_DROPS.load(Ordering::Relaxed),
        CROSS_DOMAIN_BACKPRESSURE.load(Ordering::Relaxed),
    )
}

/// Zero the cross-domain counters, for a diagnostic window.
pub fn cross_domain_stats_reset() {
    use portable_atomic::Ordering;
    CROSS_DOMAIN_DROPS.store(0, Ordering::Relaxed);
    CROSS_DOMAIN_BACKPRESSURE.store(0, Ordering::Relaxed);
}

/// Per-domain queue depth, indexed by destination `domain_id`. The
/// aggregate counters in `cross_domain_stats()` give totals but not
/// "which domain is starved"; this snapshot answers that. Walks every
/// registered `CrossDomainEdge` and adds the source ring's
/// pending-message count to its destination domain's slot. Cheap:
/// O(cross_edge_count) atomic loads, no locks; safe to call from
/// diagnostics on any core.
///
/// Reading uses `count()` which is the SPSC `head - tail` (relaxed
/// for head, acquire for tail) — for diagnostics, not strict
/// correctness. The returned array is the snapshot at this call's
/// last load and may be stale by the time it returns.
pub fn cross_domain_queue_depths() -> [u32; MAX_DOMAINS] {
    let mut out = [0u32; MAX_DOMAINS];
    let n = cross_edge_count();
    let mut i = 0usize;
    while i < n {
        if let Some(edge) = get_cross_edge(i) {
            let dst = edge.to_domain as usize;
            if dst < MAX_DOMAINS {
                if let Some(ch) = get_cross_channel(edge.channel_idx as usize) {
                    out[dst] = out[dst].saturating_add(ch.count());
                }
            }
        }
        i += 1;
    }
    out
}

// ============================================================================
// CrossDomainChannel — lock-free SPSC ring buffer
// ============================================================================

/// A single slot in the ring buffer: 4-byte length + `SLOT_DATA_SIZE`
/// bytes of payload. `SLOT_DATA_SIZE` mirrors `abi::CHANNEL_BUFFER_SIZE`
/// so a producer-side mailbox payload always fits in a slot.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct RingSlot {
    /// Length of valid data (0..SLOT_DATA_SIZE).
    len: u32,
    /// Data payload.
    data: [u8; SLOT_DATA_SIZE],
}

impl RingSlot {
    const fn new() -> Self {
        Self {
            len: 0,
            data: [0u8; SLOT_DATA_SIZE],
        }
    }
}

/// No producer has claimed this channel yet.
const PRODUCER_NONE: u32 = 0xFFFF_FFFF;

/// Lock-free SPSC ring buffer for cross-core communication.
///
/// The ring has `RING_SLOTS` slots, each sized to hold one full mailbox
/// payload (`SLOT_DATA_SIZE` bytes). Head and tail indices are on
/// separate cache lines to avoid false sharing.
///
/// The `producer_core` field enforces SPSC: the first core to call `send()`
/// claims the channel, and a send from any other core is refused.
///
/// Protocol:
/// - Producer: write slot at `head & MASK`, advance head (Release), SEV
/// - Consumer: if `head != tail`, read slot at `tail & MASK`, advance tail (Release)
/// - Full: `head - tail >= RING_SLOTS` — `send` refuses the frame
#[repr(C)]
pub struct CrossDomainChannel {
    /// Producer's write index (cache-line aligned).
    head: CacheAlignedU32,
    /// Consumer's read index (cache-line aligned, separate cache line from head).
    tail: CacheAlignedU32,
    /// Core ID of the producer (set on first send, checked thereafter).
    /// PRODUCER_NONE means unclaimed.
    producer_core: AtomicU32,
    /// Ring buffer slots.
    slots: [RingSlot; RING_SLOTS],
}

/// Cache-line-aligned atomic u32 to prevent false sharing.
#[repr(C, align(64))]
struct CacheAlignedU32 {
    val: AtomicU32,
}

impl CacheAlignedU32 {
    const fn new(v: u32) -> Self {
        Self {
            val: AtomicU32::new(v),
        }
    }
}

impl Default for CrossDomainChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossDomainChannel {
    /// Create a new empty channel.
    pub const fn new() -> Self {
        Self {
            head: CacheAlignedU32::new(0),
            tail: CacheAlignedU32::new(0),
            producer_core: AtomicU32::new(PRODUCER_NONE),
            slots: [const { RingSlot::new() }; RING_SLOTS],
        }
    }

    /// Send data through the channel (producer side).
    ///
    /// Returns `true` if the data was enqueued, `false` if the ring is full,
    /// a different core is trying to produce, or the frame exceeds
    /// `SLOT_DATA_SIZE` (slots are fixed-size and a frame is never
    /// truncated; every producer-side mailbox is `CHANNEL_BUFFER_SIZE`, so
    /// an oversized frame is a wiring fault).
    pub fn send(&self, src: &[u8]) -> bool {
        if src.len() > SLOT_DATA_SIZE {
            return false;
        }
        let len = src.len();

        if !self.claim_producer() {
            return false;
        }

        let head = self.head.val.load(Ordering::Relaxed);
        let tail = self.tail.val.load(Ordering::Acquire);

        // Check if ring is full
        if head.wrapping_sub(tail) >= RING_SLOTS as u32 {
            return false; // Drop on full
        }

        // Write slot data
        let slot_idx = (head & RING_MASK) as usize;
        // SAFETY: SPSC ring — single producer writes the slot before
        // publishing the new head with Release ordering. `slot_idx <
        // RING_SLOTS` because `head` wraps mod `RING_SLOTS`.
        unsafe {
            let slot_ptr = &self.slots[slot_idx] as *const RingSlot as *mut RingSlot;
            let data_dst = core::ptr::addr_of_mut!((*slot_ptr).data) as *mut u8;
            core::ptr::copy_nonoverlapping(src.as_ptr(), data_dst, len);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot_ptr).len), len as u32);
        }

        // Publish the new head (Release ensures slot writes are visible first)
        self.head.val.store(head.wrapping_add(1), Ordering::Release);

        // Ends a consumer's wait for an event; one waiting for its tick
        // takes the frame on its next pass.
        super::signal();

        true
    }

    /// SPSC enforcement: the first core to produce claims the ring, and a
    /// send from any other core is refused.
    fn claim_producer(&self) -> bool {
        let my_core = super::core_id() as u32;
        match self.producer_core.compare_exchange(
            PRODUCER_NONE,
            my_core,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => true,
            Err(owner) => owner == my_core,
        }
    }

    /// Enqueue one frame the caller writes in place (producer side): `fill`
    /// is handed the next free slot's payload and returns the bytes it wrote,
    /// or `None` to enqueue nothing. Returns the frame's length, `None` when
    /// the ring is full, another core owns the producer side, or `fill`
    /// declined.
    pub fn send_with(
        &self,
        fill: impl FnOnce(&mut [u8; SLOT_DATA_SIZE]) -> Option<usize>,
    ) -> Option<usize> {
        if !self.claim_producer() {
            return None;
        }
        let head = self.head.val.load(Ordering::Relaxed);
        let tail = self.tail.val.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= RING_SLOTS as u32 {
            return None;
        }
        let slot_idx = (head & RING_MASK) as usize;
        // SAFETY: SPSC ring: the single producer owns the slot at `head`
        // until it publishes the new head; `slot_idx < RING_SLOTS`.
        let len = unsafe {
            let slot_ptr = &self.slots[slot_idx] as *const RingSlot as *mut RingSlot;
            let len = fill(&mut *core::ptr::addr_of_mut!((*slot_ptr).data))?.min(SLOT_DATA_SIZE);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot_ptr).len), len as u32);
            len
        };
        self.head.val.store(head.wrapping_add(1), Ordering::Release);
        super::signal();
        Some(len)
    }

    /// Dequeue the oldest frame, read in place (consumer side): `take` is
    /// handed the frame and the frame leaves the ring when it returns.
    /// `None` when the ring is empty.
    pub fn recv_with<R>(&self, take: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let tail = self.tail.val.load(Ordering::Relaxed);
        let head = self.head.val.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let slot_idx = (tail & RING_MASK) as usize;
        // SAFETY: SPSC consumer: the slot at `tail` was published by the
        // producer with Release and is not rewritten until the tail moves.
        let r = unsafe {
            let slot_ptr = &self.slots[slot_idx] as *const RingSlot;
            let len = (core::ptr::read_volatile(core::ptr::addr_of!((*slot_ptr).len)) as usize)
                .min(SLOT_DATA_SIZE);
            take(&(&*core::ptr::addr_of!((*slot_ptr).data))[..len])
        };
        self.tail.val.store(tail.wrapping_add(1), Ordering::Release);
        Some(r)
    }

    /// The length of the oldest frame, without consuming it; `None` when the
    /// ring is empty. The consumer pump delivers a frame only when the
    /// consumer's channel has room for all of it.
    pub fn try_peek_len(&self) -> Option<usize> {
        let tail = self.tail.val.load(Ordering::Relaxed);
        let head = self.head.val.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let slot_idx = (tail & RING_MASK) as usize;
        // SAFETY: head>tail invariant means the slot at `tail` was just
        // published by the producer with Release ordering.
        let len = unsafe {
            let slot_ptr = &self.slots[slot_idx] as *const RingSlot;
            core::ptr::read_volatile(core::ptr::addr_of!((*slot_ptr).len)) as usize
        };
        Some(len)
    }

    /// Try to receive data from the channel (consumer side).
    ///
    /// Returns `Some(len)` with data copied into `dst`, or `None` if empty.
    pub fn try_recv(&self, dst: &mut [u8]) -> Option<usize> {
        let tail = self.tail.val.load(Ordering::Relaxed);
        let head = self.head.val.load(Ordering::Acquire);

        if tail == head {
            return None; // Ring is empty
        }

        let slot_idx = (tail & RING_MASK) as usize;
        let (len, copy_len);
        // SAFETY: SPSC consumer — slot was published by producer with
        // Release; `copy_len` bounded by `dst.len()` and `SLOT_DATA_SIZE`.
        unsafe {
            let slot_ptr = &self.slots[slot_idx] as *const RingSlot;
            len = core::ptr::read_volatile(core::ptr::addr_of!((*slot_ptr).len)) as usize;
            copy_len = len.min(dst.len()).min(SLOT_DATA_SIZE);
            let data_src = core::ptr::addr_of!((*slot_ptr).data) as *const u8;
            core::ptr::copy_nonoverlapping(data_src, dst.as_mut_ptr(), copy_len);
        }

        // Advance tail (Release so producer sees the freed slot)
        self.tail.val.store(tail.wrapping_add(1), Ordering::Release);

        Some(copy_len)
    }

    /// Whether the ring has no free slot.
    pub fn is_full(&self) -> bool {
        let head = self.head.val.load(Ordering::Relaxed);
        let tail = self.tail.val.load(Ordering::Acquire);
        head.wrapping_sub(tail) >= RING_SLOTS as u32
    }

    /// Number of messages currently in the ring.
    pub fn count(&self) -> u32 {
        let head = self.head.val.load(Ordering::Relaxed);
        let tail = self.tail.val.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    /// Reset the channel to empty, unclaimed state.
    pub fn reset(&self) {
        self.head.val.store(0, Ordering::Relaxed);
        self.tail.val.store(0, Ordering::Relaxed);
        self.producer_core.store(PRODUCER_NONE, Ordering::Release);
    }
}

// Channel pool: one SPSC ring per cross-domain edge of the graph, carved when
// the graph is bridged ([`size_cross`]).
static CROSS_CHANNELS: crate::kernel::mem::table::Table<CrossDomainChannel, 0> =
    crate::boot_table!(0, CrossDomainChannel::new());

/// Number of allocated cross-domain channels.
static CROSS_CHANNEL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Allocate a cross-domain channel, returning its index.
/// Returns `None` if all channels are in use.
pub fn alloc_cross_channel() -> Option<usize> {
    let idx = CROSS_CHANNEL_COUNT.fetch_add(1, Ordering::Relaxed) as usize;
    if idx >= CROSS_CHANNELS.len() {
        CROSS_CHANNEL_COUNT.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    CROSS_CHANNELS[idx].reset();
    Some(idx)
}

/// Get a reference to a cross-domain channel by index.
pub fn get_cross_channel(idx: usize) -> Option<&'static CrossDomainChannel> {
    CROSS_CHANNELS.get(idx)
}

/// Size the ring and edge tables for `n` cross-domain edges: the graph's
/// count, at boot or a rebuild, before any is registered. A table already
/// larger keeps its slots. `Err(Ceiling)` past the ring-index range.
///
/// # Safety
/// Graph preparation (boot) or a rebuild under full quiesce: no pump walks
/// the tables and nothing holds a reference into them.
pub unsafe fn size_cross(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    if n > MAX_CROSS_CHANNELS {
        return Err(crate::kernel::mem::table::TableError::Ceiling);
    }
    CROSS_CHANNELS.reserve(n)?;
    CROSS_CHANNELS.grow(n)?;
    let edges = &*core::ptr::addr_of!(CROSS_EDGES);
    edges.reserve(n)?;
    edges.grow(n)
}

// What an edge between cores takes of the RP kernel's pool is a figure the
// graph builder charges a graph's state arena: the two are one constant.
#[cfg(all(feature = "rp", target_pointer_width = "32"))]
const _: () = assert!(
    core::mem::size_of::<CrossDomainChannel>() + core::mem::size_of::<CrossDomainEdge>()
        == fluxor_contracts::core_map::RP_CROSSING_BYTES
);

// ============================================================================
// Cross-domain edge tracking
// ============================================================================

/// A cross-domain edge connects a module output in one domain to a module
/// input in another domain via a CrossDomainChannel.
pub struct CrossDomainEdge {
    /// Source domain.
    pub from_domain: u8,
    /// Source module index.
    pub from_module: crate::kernel::exec::scheduler::ModuleId,
    /// Source output port index.
    pub from_port: u8,
    /// Destination domain.
    pub to_domain: u8,
    /// Destination module index.
    pub to_module: crate::kernel::exec::scheduler::ModuleId,
    /// Which input of the destination the edge feeds: 1 its control input,
    /// 0 its data input.
    pub to_port: u8,
    /// Index into CROSS_CHANNELS.
    pub channel_idx: u8,
    /// Local channel handle on the producer side (module writes to this).
    pub local_out_handle: i32,
    /// Local channel handle on the consumer side (module reads from this).
    pub local_in_handle: i32,
}

impl CrossDomainEdge {
    pub const fn empty() -> Self {
        Self {
            from_domain: 0,
            from_module: 0,
            from_port: 0,
            to_domain: 0,
            to_module: 0,
            to_port: 0,
            channel_idx: 0,
            local_out_handle: -1,
            local_in_handle: -1,
        }
    }
}

/// Global cross-domain edge table, sized with the rings ([`size_cross`]).
static mut CROSS_EDGES: crate::kernel::mem::table::Table<CrossDomainEdge, 0> =
    crate::boot_table!(0, CrossDomainEdge::empty());
static CROSS_EDGE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Register a cross-domain edge. Returns the edge index, or None if full.
///
/// # Safety
/// Graph preparation (boot) or a rebuild with every other domain parked.
pub unsafe fn register_cross_edge(edge: CrossDomainEdge) -> Option<usize> {
    let idx = CROSS_EDGE_COUNT.load(Ordering::Relaxed) as usize;
    let edges = &mut *core::ptr::addr_of_mut!(CROSS_EDGES);
    let slot = edges.get_mut(idx)?;
    *slot = edge;
    CROSS_EDGE_COUNT.store((idx + 1) as u32, Ordering::Relaxed);
    Some(idx)
}

/// Get the number of registered cross-domain edges.
pub fn cross_edge_count() -> usize {
    CROSS_EDGE_COUNT.load(Ordering::Relaxed) as usize
}

/// Reset all cross-domain bridge state — edge table and SPSC ring pool — so a
/// live graph rebuild can re-establish bridges for the new graph exactly the
/// way boot did.
///
/// # Safety
/// Every non-primary domain must be parked (`request_quiesce` + `wait_parked`)
/// before calling: parked pumps neither walk the edge table nor touch the
/// rings, so zeroing the counts and resetting each ring is race-free. Entries
/// past the reset counts are never read; new registrations overwrite in place.
pub unsafe fn reset_cross_state() {
    CROSS_EDGE_COUNT.store(0, Ordering::Release);
    let n = CROSS_CHANNEL_COUNT.swap(0, Ordering::AcqRel) as usize;
    let mut i = 0usize;
    while i < n.min(CROSS_CHANNELS.len()) {
        CROSS_CHANNELS[i].reset();
        i += 1;
    }
}

/// Get a reference to a cross-domain edge.
pub fn get_cross_edge(idx: usize) -> Option<&'static CrossDomainEdge> {
    if idx < cross_edge_count() {
        // SAFETY: `idx < cross_edge_count()`, within the table; the edge was
        // registered before the domains were released or resumed.
        unsafe { (&*core::ptr::addr_of!(CROSS_EDGES)).get(idx) }
    } else {
        None
    }
}

/// Bridge every cross-domain edge of the freshly compiled graph: split each
/// edge whose endpoints live in different domains into producer-side /
/// consumer-side channels joined by a `CrossDomainChannel` SPSC
/// pump. Shared by first boot and live rebuild — a rebuild first calls
/// `reset_cross_state()` under quiesce so this re-registers from a
/// clean table, exactly like boot.
///
/// The walk reads `sched.edges` (not `cfg.graph_edges`) so an edge that is
/// part of both a fan group and a cross-domain hop is seen through its
/// rewritten endpoints. For each cross edge: open a fresh consumer-side
/// channel `W2`, register the SPSC bridge `edge.channel → W2`, and set
/// `edge.consumer_channel = W2` (`collect_input_channels` honours it, so
/// `populate_ports` lifts `W2` into the consumer's in_chans).
///
/// Returns the number of bridges established, or a diagnostic on reservation
/// shortfall. On `Err` no partial rewiring is left visible to consumers: the
/// failing edge's `consumer_channel` is untouched, and the caller decides the
/// posture (boot halts; rebuild leaves the graph idle / fail-safe).
pub fn bridge_edges() -> Result<usize, &'static str> {
    use crate::kernel::ipc::channel;

    // SAFETY: scheduler-thread access during graph prep (boot) or under
    // full quiesce (rebuild) — sole mutator of scheduler state either way.
    let sched = unsafe { scheduler::sched_mut() };
    let n_compiled_edges = sched.edge_count;
    // Size the ring and edge tables for this graph's cross-domain edges
    // before any is registered.
    let crosses = |edge: &scheduler::Edge| {
        edge.edge_class == EdgeClass::CrossCore
            || super::crosses_cores(
                scheduler::module_domain_id(edge.from_module) as usize,
                scheduler::module_domain_id(edge.to_module) as usize,
            )
    };
    let crossing = (0..n_compiled_edges)
        .filter(|&e| sched.edges[e].channel >= 0 && crosses(&sched.edges[e]))
        .count();
    // SAFETY: graph prep (boot) or full quiesce (rebuild): no pump walks the
    // tables.
    if unsafe { size_cross(crossing) }.is_err() {
        return Err("cross-domain ring tables could not be sized for this graph");
    }
    let mut bridged = 0usize;
    let mut e = 0usize;
    while e < n_compiled_edges {
        let edge_snapshot = sched.edges[e];
        if edge_snapshot.channel < 0 {
            e += 1;
            continue;
        }

        let from = edge_snapshot.from_module;
        let to = edge_snapshot.to_module;
        let from_domain = scheduler::module_domain_id(from);
        let to_domain = scheduler::module_domain_id(to);
        if !crosses(&edge_snapshot) {
            e += 1;
            continue;
        }

        // Reserve the SPSC ring, the consumer-side channel, and the
        // edge-table slot before touching `consumer_channel`, so a failure
        // never leaves a consumer rebound to a handle no pump fills.
        let cross_ch_idx = match alloc_cross_channel() {
            Some(i) => i,
            None => return Err("cross-domain SPSC rings exhausted; cannot bridge edge"),
        };

        let in_ch = channel::channel_open(&[]);
        if in_ch < 0 {
            return Err("consumer-side channel alloc failed for cross-domain edge");
        }

        // Mirror the producer-side channel's mailbox flag onto the
        // consumer-side bridge channel. Without this, typed-envelope
        // edges (WsFrame, FmpMessage, etc.) shred their framing at
        // this seam: the pump writes back-to-back atomic frames into
        // a FIFO ring, the consumer's next `channel_read` returns
        // multiple envelopes coalesced, and only the first parses
        // cleanly. POLL_IN also stays latched on the leftover bytes,
        // driving the consumer module to spin on phantom reads.
        if channel::channel_is_mailbox(edge_snapshot.channel) {
            channel::channel_set_mailbox(in_ch);
        }

        let to_port_marker: u8 = if edge_snapshot.is_ctrl() { 1 } else { 0 };
        // SAFETY: graph preparation (boot) or a rebuild with every other
        // domain parked.
        let registered = unsafe {
            register_cross_edge(CrossDomainEdge {
                from_domain,
                from_module: from as crate::kernel::exec::scheduler::ModuleId,
                from_port: edge_snapshot.from_port_index,
                to_domain,
                to_module: to as crate::kernel::exec::scheduler::ModuleId,
                to_port: to_port_marker,
                channel_idx: cross_ch_idx as u8,
                local_out_handle: edge_snapshot.channel,
                local_in_handle: in_ch,
            })
        };
        if registered.is_none() {
            return Err("cross-domain edge table full; cannot bridge edge");
        }

        // The pump writes the consumer's channel; the consumer reads it.
        channel::channel_bind_edge(
            in_ch,
            crate::kernel::exec::scheduler::NO_MODULE,
            to as crate::kernel::exec::scheduler::ModuleId,
        );
        sched.edges[e].consumer_channel = in_ch;
        // Delivery-side wake: for a `wake: true` cross-domain edge, bind
        // the CONSUMER-local channel — the consumer-side pump delivers
        // into it via `channel_write`, so the existing wake hook fires at
        // the first moment the consumer could actually read the bytes.
        // The producer-side channel is left unbound (a write-time wake is
        // guaranteed-spurious: the consumer's domain steps before it
        // pumps inbound). The consumer domain's tick bounds how long the wake
        // waits, since no interrupt ends its WFI.
        if edge_snapshot.wake_on_write {
            crate::kernel::ipc::channel::channel_set_wake_module(
                in_ch,
                edge_snapshot.to_module as i32,
            );
            log::info!(
                "[wake] cross-domain edge {}→{} consumer chan={} delivery-wake bound",
                edge_snapshot.from_module,
                edge_snapshot.to_module,
                in_ch
            );
        }
        bridged += 1;
        e += 1;
    }
    Ok(bridged)
}

/// Max frames a single [`pump`] pass moves per edge per direction: a whole
/// ring, so a burst (a TLS flight of many records) crosses in one pass rather
/// than one frame per tick.
const CROSS_PUMP_BURST: u32 = RING_SLOTS as u32;

// Per-domain-pair flow, indexed by `flow_index(from, to)`. PROD counts frames
// the producer arm pushed into the SPSC ring; CONS counts frames the consumer
// arm delivered into the local consumer channel. A pair where PROD>0 but
// CONS≈0 localises where cross-core delivery stalls.
static XPUMP_PROD: [AtomicU32; MAX_DOMAINS * MAX_DOMAINS] =
    [const { AtomicU32::new(0) }; MAX_DOMAINS * MAX_DOMAINS];
static XPUMP_CONS: [AtomicU32; MAX_DOMAINS * MAX_DOMAINS] =
    [const { AtomicU32::new(0) }; MAX_DOMAINS * MAX_DOMAINS];

fn flow_index(from: usize, to: usize) -> usize {
    (from.min(MAX_DOMAINS - 1)) * MAX_DOMAINS + to.min(MAX_DOMAINS - 1)
}

/// Frames moved from domain `from` toward domain `to`: `(pushed into the
/// ring, delivered to the consumer)`.
pub fn flow(from: usize, to: usize) -> (u32, u32) {
    let i = flow_index(from, to);
    (
        XPUMP_PROD[i].load(Ordering::Relaxed),
        XPUMP_CONS[i].load(Ordering::Relaxed),
    )
}

/// Move up to [`CROSS_PUMP_BURST`] frames per edge in each direction between
/// local pipe channels and their cross-domain SPSC ring. Called from the
/// domain run loop every pass; producer and consumer sides of each edge each
/// fire on the pass of their owning domain.
///
/// On the consumer side, a frame leaves the ring only when the consumer's
/// channel has room for all of it (`channel_writable_bytes`):
/// `channel_write` writes what fits, so a frame written into too little room
/// would lose its tail.
///
/// A frame is one record of the producer's channel: the producer side reads
/// record by record (`channel_record_len`), so the consumer's channel gets
/// the producer's writes with their boundaries.
pub fn pump(domain_id: usize) {
    let n_cross = cross_edge_count();
    let mut ei = 0;
    while ei < n_cross {
        let Some(edge) = get_cross_edge(ei) else {
            ei += 1;
            continue;
        };
        let Some(ch) = get_cross_channel(edge.channel_idx as usize) else {
            ei += 1;
            continue;
        };

        // Producer side. Check remote SPSC space first — `channel_read`
        // consumes the producer's record, so consuming the producer's
        // frame before knowing the SPSC ring has room would be a real
        // drop. If the ring is full we leave the frame in the producer
        // mailbox; the producer module sees back-pressure on its output
        // and the pump retries next tick.
        if edge.from_domain == domain_id as u8 && edge.local_out_handle >= 0 {
            // Drain up to a ring's worth of frames from the producer mailbox,
            // stopping when the ring is full (back-pressure) or the mailbox is
            // empty.
            let mut moved = 0u32;
            while moved < CROSS_PUMP_BURST {
                if ch.is_full() {
                    CROSS_DOMAIN_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                let rec = crate::kernel::ipc::channel::channel_record_len(edge.local_out_handle);
                if rec <= 0 {
                    break; // nothing buffered
                }
                // The record is read straight into the ring's next slot. The
                // ring had room, so a refusal is a ring another core claimed
                // the producer side of: the record stays in the producer's
                // channel and the refusal is counted.
                let mut read = 0i32;
                let sent = ch.send_with(|slot| {
                    let want = (rec as usize).min(slot.len());
                    // SAFETY: `slot` is `SLOT_DATA_SIZE` writable bytes;
                    // channel_read writes at most `want` of them.
                    read = unsafe {
                        crate::kernel::ipc::channel::channel_read(
                            edge.local_out_handle,
                            slot.as_mut_ptr(),
                            want,
                        )
                    };
                    usize::try_from(read).ok().filter(|&n| n > 0)
                });
                if sent.is_none() {
                    if read == 0 {
                        // The slot was never offered: the ring refused this
                        // core as its producer.
                        CROSS_DOMAIN_DROPS.fetch_add(1, Ordering::Relaxed);
                    }
                    break;
                }
                let mi = flow_index(edge.from_domain as usize, edge.to_domain as usize);
                XPUMP_PROD[mi].fetch_add(1, Ordering::Relaxed);
                moved += 1;
            }
        }

        // Consumer side.
        if edge.to_domain == domain_id as u8 && edge.local_in_handle >= 0 {
            // Drain up to a full ring's worth of frames from the SPSC ring
            // into the local consumer channel this pass, re-checking POLL_OUT
            // each iteration (the FIFO can fill mid-drain). Matches the
            // multi-frame producer drain above so a burst clears in one pump.
            let mut moved = 0u32;
            while moved < CROSS_PUMP_BURST {
                // A frame is delivered whole or not at all. The consumer's
                // channel is a FIFO whose `channel_write` writes what fits, so
                // a frame written into too little room loses its tail and
                // desyncs a framed stream (`[type][len][payload]` read with a
                // bogus length). Peek the frame's length and take it from the
                // ring only when the channel has room for all of it;
                // otherwise leave it queued and back-pressure.
                let Some(slot_len) = ch.try_peek_len() else {
                    break; // ring empty
                };
                let room = if crate::kernel::ipc::channel::channel_is_mailbox(edge.local_in_handle)
                {
                    // A mailbox takes the next record once its last is read.
                    crate::kernel::ipc::channel::channel_poll(
                        edge.local_in_handle,
                        crate::kernel::ipc::channel::POLL_OUT,
                    ) > 0
                } else {
                    crate::kernel::ipc::channel::channel_writable_bytes(edge.local_in_handle)
                        >= slot_len
                };
                if !room {
                    CROSS_DOMAIN_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                // The frame is written straight from its slot; the channel
                // was just confirmed to have room for all of it, so the
                // write is complete.
                let delivered = ch.recv_with(|frame| {
                    // SAFETY: `frame` is the slot's valid bytes.
                    unsafe {
                        crate::kernel::ipc::channel::channel_write(
                            edge.local_in_handle,
                            frame.as_ptr(),
                            frame.len(),
                        );
                    }
                });
                if delivered.is_none() {
                    break; // ring drained between peek and recv
                }
                let mi = flow_index(edge.from_domain as usize, edge.to_domain as usize);
                XPUMP_CONS[mi].fetch_add(1, Ordering::Relaxed);
                moved += 1;
            }
        }
        ei += 1;
    }
}

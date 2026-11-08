//! Edges between execution domains: each is split at the domain boundary into
//! a producer-side and a consumer-side channel joined by a lock-free SPSC ring,
//! and each side's domain pumps its half on its own core.
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
//! The producer writes the slot, publishes the head with Release, then issues
//! `dmb ish` + `sev`, which ends a wait in WFE. A consumer domain idling in WFI
//! takes the frame on its next pass, so its tick bounds the delivery latency.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::kernel::boot::config::EdgeClass;
use crate::kernel::exec::scheduler::{self, MAX_DOMAINS};

/// The cross-domain channel index DOMAIN, not a table size: a
/// `CrossDomainEdge` names its ring in a `u8`. The ring and edge tables are
/// sized from the graph when it is bridged ([`size_cross`]), one per edge
/// that crosses domains.
pub const MAX_CROSS_CHANNELS: usize = 256;

/// Number of slots in each ring buffer. Must be a power of 2.
pub const RING_SLOTS: usize = 8;

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
// Three aggregate counters show a bridge losing or holding back data, so an
// overloaded destination can be diagnosed on a running node:
//
// * `CROSS_DOMAIN_DROPS` — the ring refused a frame the producer pump had
//   already read out of the producer's mailbox: a frame lost. The pump checks
//   for room first, so this is a frame the ring cannot carry (one claimed by
//   another producing core), never a full ring.
// * `CROSS_DOMAIN_BACKPRESSURE` — a pump pass that stopped with frames left
//   where they were: the ring full on the producer side, or the consumer's
//   channel without room for the next frame. Nothing is lost, but a sustained
//   rate means the destination is under-served.
// * `SIDEBAND_AUX_OVERWRITES` — a consumer's `IOCTL_NOTIFY` value replaced by
//   a newer one before the producer pump forwarded it. The sideband is one
//   slot and coalescing by design (a seek to position N: the later wins).
//
// `cross_domain_stats()` reads all three and `cross_domain_stats_reset()`
// zeroes them.

use portable_atomic::AtomicU64;

pub static CROSS_DOMAIN_DROPS: AtomicU64 = AtomicU64::new(0);
pub static CROSS_DOMAIN_BACKPRESSURE: AtomicU64 = AtomicU64::new(0);
pub static SIDEBAND_AUX_OVERWRITES: AtomicU64 = AtomicU64::new(0);

/// Snapshot the three cross-domain counters.
/// Returns `(drops, backpressure, sideband_overwrites)`.
pub fn cross_domain_stats() -> (u64, u64, u64) {
    use portable_atomic::Ordering;
    (
        CROSS_DOMAIN_DROPS.load(Ordering::Relaxed),
        CROSS_DOMAIN_BACKPRESSURE.load(Ordering::Relaxed),
        SIDEBAND_AUX_OVERWRITES.load(Ordering::Relaxed),
    )
}

/// Zero the three cross-domain counters, for a diagnostic window.
pub fn cross_domain_stats_reset() {
    use portable_atomic::Ordering;
    CROSS_DOMAIN_DROPS.store(0, Ordering::Relaxed);
    CROSS_DOMAIN_BACKPRESSURE.store(0, Ordering::Relaxed);
    SIDEBAND_AUX_OVERWRITES.store(0, Ordering::Relaxed);
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

        // SPSC enforcement: claim or verify producer core
        #[cfg(target_arch = "aarch64")]
        {
            let my_core = current_core_id_inline();
            let prev = self.producer_core.compare_exchange(
                PRODUCER_NONE,
                my_core,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            match prev {
                Ok(_) => {}                          // We claimed it
                Err(owner) if owner == my_core => {} // Already ours
                Err(_) => return false,              // Different core owns this channel
            }
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

        // Ends a consumer's wait in WFE; one idling in WFI takes the frame on
        // its next pass.
        // SAFETY: DMB + SEV are architectural hints; no memory effects.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("dmb ish", "sev", options(nomem, nostack));
        }

        true
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

/// The running core's number, for SPSC enforcement.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn current_core_id_inline() -> u32 {
    crate::arch::aarch64::cpu::current_core_id() as u32
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
/// larger keeps its slots. `Err(Ceiling)` past the ring-index domain.
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
    /// Aux-u32 value posted by the consumer via `IOCTL_NOTIFY` on its
    /// local input handle, forwarded by the producer-side pump via
    /// `IOCTL_NOTIFY` on the producer's local output handle. Bridges
    /// seek-style sideband signals across domain boundaries.
    /// `u32::MAX` = no aux pending.
    pub pending_aux: core::sync::atomic::AtomicU32,
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
            pending_aux: core::sync::atomic::AtomicU32::new(u32::MAX),
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
    let crossing = (0..n_compiled_edges)
        .filter(|&e| {
            let edge = sched.edges[e];
            edge.channel >= 0
                && (scheduler::module_domain_id(edge.from_module)
                    != scheduler::module_domain_id(edge.to_module)
                    || edge.edge_class == EdgeClass::CrossCore)
        })
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
        let is_cross = from_domain != to_domain || edge_snapshot.edge_class == EdgeClass::CrossCore;
        if !is_cross {
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

        let in_ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
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
                pending_aux: core::sync::atomic::AtomicU32::new(u32::MAX),
            })
        };
        if registered.is_none() {
            return Err("cross-domain edge table full; cannot bridge edge");
        }

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
/// `IOCTL_NOTIFY` sideband (seek requests and the like) is bridged via
/// `edge.pending_aux`: the consumer-side pump drains the consumer's
/// local input aux and stores it there; the producer-side pump drains
/// it and replays it onto the producer's local output aux.
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
        // commits the local mailbox frame, so consuming the producer's
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
                let mut buf = [0u8; SLOT_DATA_SIZE];
                // SAFETY: `buf` is `SLOT_DATA_SIZE` bytes on the stack;
                // channel_read writes ≤ `buf.len()` bytes.
                let n = unsafe {
                    crate::kernel::ipc::channel::channel_read(
                        edge.local_out_handle,
                        buf.as_mut_ptr(),
                        buf.len(),
                    )
                };
                if n <= 0 {
                    break; // producer mailbox empty
                }
                // The ring had room, so a refusal is a frame it cannot carry
                // (another core claimed the producer side): counted as lost.
                if !ch.send(&buf[..n as usize]) {
                    CROSS_DOMAIN_DROPS.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                let mi = flow_index(edge.from_domain as usize, edge.to_domain as usize);
                XPUMP_PROD[mi].fetch_add(1, Ordering::Relaxed);
                moved += 1;
            }
            let aux = edge.pending_aux.swap(u32::MAX, Ordering::AcqRel);
            if aux != u32::MAX {
                let mut val = aux;
                let _ = crate::kernel::ipc::channel::channel_ioctl(
                    edge.local_out_handle,
                    crate::kernel::ipc::channel::IOCTL_NOTIFY,
                    &mut val as *mut u32 as *mut u8,
                );
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
                if crate::kernel::ipc::channel::channel_writable_bytes(edge.local_in_handle)
                    < slot_len
                {
                    CROSS_DOMAIN_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                let mut buf = [0u8; SLOT_DATA_SIZE];
                let Some(len) = ch.try_recv(&mut buf) else {
                    break; // ring drained between peek and recv
                };
                // SAFETY: `len == slot_len <= SLOT_DATA_SIZE = buf.len()`, and
                // the FIFO was just confirmed to have room for the whole slot,
                // so this write is complete (no truncation).
                unsafe {
                    crate::kernel::ipc::channel::channel_write(
                        edge.local_in_handle,
                        buf.as_ptr(),
                        len,
                    );
                }
                let mi = flow_index(edge.from_domain as usize, edge.to_domain as usize);
                XPUMP_CONS[mi].fetch_add(1, Ordering::Relaxed);
                moved += 1;
            }
            let mut val: u32 = 0;
            let rc = crate::kernel::ipc::channel::channel_ioctl(
                edge.local_in_handle,
                crate::kernel::ipc::channel::IOCTL_POLL_NOTIFY,
                &mut val as *mut u32 as *mut u8,
            );
            if rc == crate::kernel::ipc::channel::CHAN_OK && val != u32::MAX {
                // `pending_aux` is one slot: a newer notification replaces
                // one the producer pump has not yet forwarded (the later
                // wins), and the overwrite is counted.
                let prev = edge.pending_aux.swap(val, Ordering::AcqRel);
                if prev != u32::MAX {
                    SIDEBAND_AUX_OVERWRITES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        ei += 1;
    }
}

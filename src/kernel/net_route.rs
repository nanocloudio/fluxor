//! net.route (0x20) — the node's segment, peer-route and held-address tables,
//! shared by every provider.
//!
//! A provider is this store plus a realization. A platform that realizes the
//! tables itself (Linux) supplies a [`Realizer`]: it is handed each table as
//! it is replaced, before the store keeps it, and answers each entry's state
//! when `READ` asks. A node whose realization is a module (the bare-metal
//! network stack) registers no realizer: that module reads the tables with
//! `TAKE` and states each entry with `REPORT`, both admitted only from the
//! registered net-identity provider.
//!
//! **Gate.** Every op needs the node's authority (`caller_authority`); the
//! contract grant and `platform_raw` are checked in the syscall layer before
//! dispatch reaches here (`REPORT` and `TAKE` excepted from `platform_raw`,
//! admitted here by the caller's identity instead).
//!
//! **One writer per table.** A table binds its writer — `(module slot, slot
//! generation)` — on its first successful replace; another module gets
//! `EBUSY`. A binding whose slot generation has moved on is stale, and the
//! next caller takes it over. Bindings are released when their module's
//! providers are ([`release_module`]) and cleared when a graph is rebuilt
//! ([`reset_bindings`]); the tables themselves persist across both, and
//! only the platform's boot reclaim clears what they realized.
//!
//! **Concurrency.** The tables are read from every core. A replace holds its
//! table's apply flag from the writer check to the binding, so admission,
//! realization and the store are one step and two writers never interleave
//! (the second is `EBUSY`); readers never wait for it, though a realizer may
//! take milliseconds. Each region — the three request tables and the entry
//! states — is a sequence lock: a writer moves its count to odd (a
//! compare-and-swap, so a second writer is turned away rather than
//! interleaved), writes, and moves it to even; a reader copies and retries a
//! bounded number of times, then answers `EAGAIN` and the caller keeps its
//! previous copy.
//!
//! **Reports follow a take.** `REPORT` states entries by their index in the
//! tables the reporter last took. A replace between the two renumbers them,
//! so a report made against tables that have since moved is refused
//! (`EAGAIN`): the reporter takes again and reports what it realized from
//! those — a stale report can never mark a new entry realized or fenced.
//!
//! **Capacity.** Each table is sized from its pool's plan (`net_route_*`), and
//! across a rebuild keeps `max(previous, planned)`: storage is never shrunk
//! under entries it holds. Bounded and allocation-free on the dispatch path.

use crate::abi::contracts::net::route as wire;
use crate::abi::contracts::resource as res;
use crate::kernel::mem::table::Table as BootTable;
use crate::kernel::sys::errno;
use portable_atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Segments held at once: the profile's static count, or on Linux the plan's
/// `net_route_segments` pool (by default 16 — one per node is the common
/// shape). A SEGMENTS replace past it is `ENOSPC`, counted.
pub const MAX_SEGMENTS: usize = crate::kernel::config::static_slots(res::POOL_NET_ROUTE_SEGMENTS);
/// Peer routes held at once: the static count, or the plan's
/// `net_route_peers` (by default 256 — one per other node). A ROUTES replace
/// past it is `ENOSPC`, counted.
pub const MAX_PEERS: usize = crate::kernel::config::static_slots(res::POOL_NET_ROUTE_PEERS);
/// Held addresses at once: the static count, or the plan's `net_route_held`
/// (by default 256 — service addresses the node answers for). A HOLD
/// replace past it is `ENOSPC`, counted.
pub const MAX_HELD: usize = crate::kernel::config::static_slots(res::POOL_NET_ROUTE_HELD);

/// Times a reader retries a region a writer is changing before it gives up
/// and keeps its previous copy (`EAGAIN`).
const READ_RETRIES: usize = 8;
/// Times a replace waits for the entry-state region before it gives up. The
/// region is held across a copy of the states and, on a platform that
/// realizes the tables itself, across asking it for each entry's state —
/// which can wait on a realization in flight, so a hosted build yields
/// between tries rather than spinning.
const STATE_SPINS: u32 = 1 << 16;

static mut SEGS: BootTable<wire::Segment, MAX_SEGMENTS> =
    crate::boot_table!(MAX_SEGMENTS, wire::Segment::EMPTY);
static mut ROUTES: BootTable<wire::Route, MAX_PEERS> =
    crate::boot_table!(MAX_PEERS, wire::Route::EMPTY);
static mut HELD: BootTable<wire::Held, MAX_HELD> = crate::boot_table!(MAX_HELD, wire::Held::EMPTY);
static mut SEG_STATE: BootTable<wire::EntryState, MAX_SEGMENTS> =
    crate::boot_table!(MAX_SEGMENTS, wire::EntryState::EMPTY);
static mut ROUTE_STATE: BootTable<wire::EntryState, MAX_PEERS> =
    crate::boot_table!(MAX_PEERS, wire::EntryState::EMPTY);
static mut HELD_STATE: BootTable<wire::EntryState, MAX_HELD> =
    crate::boot_table!(MAX_HELD, wire::EntryState::EMPTY);

/// The three request tables, in the order READ and TAKE walk them.
const T_SEG: usize = 0;
const T_ROUTE: usize = 1;
const T_HELD: usize = 2;

/// Entries in each table.
static COUNT: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
/// Entries each table may hold: `max(previous, planned)`.
static CAPACITY: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
/// One sequence lock per request table.
static TABLE_SEQ: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
/// The entry-state region's sequence lock. Its counts are copies of
/// [`COUNT`] taken when the region was last reset, so a reader of states
/// never needs the request tables.
static STATE_SEQ: AtomicU32 = AtomicU32::new(0);
static STATE_COUNT: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
/// Advances on every table replace: what TAKE answers.
static TABLE_GEN: AtomicU64 = AtomicU64::new(0);
/// The table generation the realizing module last took (whole, or past its
/// buffer): the tables its REPORT indexes. [`UNTAKEN`] before any TAKE.
static TAKEN_GEN: AtomicU64 = AtomicU64::new(UNTAKEN);
const UNTAKEN: u64 = u64::MAX;
/// Held by the one replace of each table between its writer check and its
/// binding.
static APPLYING: [AtomicBool; 3] = [const { AtomicBool::new(false) }; 3];
/// Advances on every table replace and every entry-state change: what READ
/// answers.
static STATE_GEN: AtomicU64 = AtomicU64::new(0);

/// No writer bound.
const UNBOUND: u64 = u64::MAX;
/// Each table's writer: `slot | generation << 32`, or [`UNBOUND`].
static WRITER: [AtomicU64; 3] = [const { AtomicU64::new(UNBOUND) }; 3];

/// A platform's realization of the tables.
pub struct Realizer {
    /// What the platform realizes now (`wire::caps`).
    pub caps: fn() -> u32,
    /// Realize the whole segment table. `Err(errno)` refuses the replace
    /// and the stored table is left as it was; an entry the host defeats is
    /// not an error — its state says so.
    pub segments: fn(&[wire::Segment]) -> Result<(), i32>,
    /// Realize the whole peer-route table.
    pub routes: fn(&[wire::Route]) -> Result<(), i32>,
    /// Realize the whole held-address table.
    pub held: fn(&[wire::Held]) -> Result<(), i32>,
    /// Whether a workload is attached to segment `id` now.
    pub segment_in_use: fn(u16) -> bool,
    /// `(state, reason)` of entry `index` of table `kind`
    /// (`wire::entry::KIND_*`).
    pub state: fn(u8, usize) -> (u8, u8),
    /// Held address `index`'s fence evidence, `(install_gen, cutoff,
    /// cutoff_kind)`: the install that realized it, and for a fenced one
    /// the cutoff the platform proved (`net::identity::cutoff`). Zeros where
    /// the platform has none to give.
    pub held_evidence: fn(usize) -> (u32, u64, u8),
}

// ---- sizing ---------------------------------------------------------------

/// Size the tables to `segments`, `peers` and `held` entries. A table keeps
/// the entries it holds and never shrinks: its capacity is the larger of
/// what it had and what is asked.
///
/// # Safety
/// Boot or graph-preparation context: no reference into a table is live.
pub unsafe fn size(
    segments: usize,
    peers: usize,
    held: usize,
) -> Result<(), crate::kernel::mem::table::TableError> {
    let s = &*core::ptr::addr_of!(SEGS);
    let ss = &*core::ptr::addr_of!(SEG_STATE);
    let r = &*core::ptr::addr_of!(ROUTES);
    let rs = &*core::ptr::addr_of!(ROUTE_STATE);
    let h = &*core::ptr::addr_of!(HELD);
    let hs = &*core::ptr::addr_of!(HELD_STATE);
    let n = [
        segments.max(CAPACITY[T_SEG].load(Ordering::Relaxed)),
        peers.max(CAPACITY[T_ROUTE].load(Ordering::Relaxed)),
        held.max(CAPACITY[T_HELD].load(Ordering::Relaxed)),
    ];
    s.reserve(n[T_SEG])?;
    s.grow(n[T_SEG])?;
    ss.reserve(n[T_SEG])?;
    ss.grow(n[T_SEG])?;
    r.reserve(n[T_ROUTE])?;
    r.grow(n[T_ROUTE])?;
    rs.reserve(n[T_ROUTE])?;
    rs.grow(n[T_ROUTE])?;
    h.reserve(n[T_HELD])?;
    h.grow(n[T_HELD])?;
    hs.reserve(n[T_HELD])?;
    hs.grow(n[T_HELD])?;
    for (c, v) in CAPACITY.iter().zip(n) {
        c.store(v, Ordering::Relaxed);
    }
    Ok(())
}

/// Size the tables from the plan's defaults when no plan has.
unsafe fn ensure_sized() {
    if CAPACITY.iter().all(|c| c.load(Ordering::Relaxed) == 0) {
        let c = crate::kernel::sys::resource_ledger::ceiling;
        let _ = size(
            c(res::POOL_NET_ROUTE_SEGMENTS) as usize,
            c(res::POOL_NET_ROUTE_PEERS) as usize,
            c(res::POOL_NET_ROUTE_HELD) as usize,
        );
    }
}

/// Entries a pool's table holds now — the ledger's `cur`.
pub fn in_use(pool: u16) -> usize {
    match pool {
        res::POOL_NET_ROUTE_SEGMENTS => COUNT[T_SEG].load(Ordering::Relaxed),
        res::POOL_NET_ROUTE_PEERS => COUNT[T_ROUTE].load(Ordering::Relaxed),
        res::POOL_NET_ROUTE_HELD => COUNT[T_HELD].load(Ordering::Relaxed),
        _ => 0,
    }
}

const POOLS: [u16; 3] = [
    res::POOL_NET_ROUTE_SEGMENTS,
    res::POOL_NET_ROUTE_PEERS,
    res::POOL_NET_ROUTE_HELD,
];

// ---- sequence locks -------------------------------------------------------

/// Enter a region's write side; `false` while another writer is in it.
fn write_begin(seq: &AtomicU32) -> bool {
    let s = seq.load(Ordering::Relaxed);
    if s & 1 == 1 {
        return false;
    }
    if seq
        .compare_exchange(s, s.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    core::sync::atomic::fence(Ordering::Release);
    true
}

fn write_end(seq: &AtomicU32) {
    seq.fetch_add(1, Ordering::Release);
}

/// One wait for a region another writer holds.
#[inline]
fn relax() {
    #[cfg(feature = "host-linux")]
    std::thread::yield_now();
    #[cfg(not(feature = "host-linux"))]
    core::hint::spin_loop();
}

/// Run `f` until it reads the region with no writer in it; `None` after
/// [`READ_RETRIES`] tries.
fn read_consistent<R>(seq: &AtomicU32, mut f: impl FnMut() -> R) -> Option<R> {
    for _ in 0..READ_RETRIES {
        let before = seq.load(Ordering::Acquire);
        if before & 1 == 1 {
            core::hint::spin_loop();
            continue;
        }
        let r = f();
        core::sync::atomic::fence(Ordering::Acquire);
        if seq.load(Ordering::Relaxed) == before {
            return Some(r);
        }
    }
    None
}

// ---- writer bindings ------------------------------------------------------

fn pack(slot: usize, gen: u32) -> u64 {
    (slot as u32 as u64) | ((gen as u64) << 32)
}

/// The calling module, as `(slot, generation)`.
fn caller() -> (usize, u32) {
    let idx = crate::kernel::exec::scheduler::current_module_index();
    (
        idx,
        crate::kernel::exec::scheduler::module_slot_generation(idx),
    )
}

/// Whether the caller may write table `t`: no writer bound, the caller is
/// the writer, or the bound writer's slot has moved on (stale).
fn may_write(t: usize, slot: usize, gen: u32) -> bool {
    let b = WRITER[t].load(Ordering::Acquire);
    if b == UNBOUND || b == pack(slot, gen) {
        return true;
    }
    let (bslot, bgen) = ((b & 0xFFFF_FFFF) as usize, (b >> 32) as u32);
    crate::kernel::exec::scheduler::module_slot_generation(bslot) != bgen
}

/// Clear every writer binding: a rebuilt graph's modules start unbound
/// (the previous graph's slots no longer name them).
pub fn reset_bindings() {
    for w in &WRITER {
        w.store(UNBOUND, Ordering::Release);
    }
}

/// Release the bindings module `idx` holds (it finished, faulted, was
/// quarantined, removed or reconfigured). Its tables stay.
pub fn release_module(idx: usize) {
    for w in &WRITER {
        let b = w.load(Ordering::Acquire);
        if b != UNBOUND && (b & 0xFFFF_FFFF) as usize == idx {
            let _ = w.compare_exchange(b, UNBOUND, Ordering::AcqRel, Ordering::Relaxed);
        }
    }
}

/// What a node whose realization is a module (the bare-metal network stack)
/// realizes: segments (a workload created on one holds its address in that
/// module, which sources its cluster traffic from it), peer routes reached
/// directly, and held addresses in `deliver` mode — and only while that
/// module is registered, since without it nothing realizes anything.
/// Forwarding between segments, translated egress and `announce` are not
/// realized there.
fn module_caps() -> u32 {
    #[cfg(feature = "multitenant")]
    {
        if crate::kernel::workload::workload_graph::net_identity_provider_present() {
            return wire::caps::SEGMENTS | wire::caps::PEER_ROUTES | wire::caps::HOLD_DELIVER;
        }
    }
    0
}

/// Whether the caller is the node's registered net-identity provider.
fn caller_is_net_identity_provider() -> bool {
    #[cfg(feature = "multitenant")]
    {
        let (slot, gen) = caller();
        crate::kernel::workload::workload_graph::is_net_identity_provider(slot, gen)
    }
    #[cfg(not(feature = "multitenant"))]
    {
        false
    }
}

// ---- reads for the platform -----------------------------------------------

/// A copy of segment `id`, if the table holds it. `Err(EAGAIN)` when a
/// writer kept it from being read consistently.
pub fn segment(id: u16) -> Result<Option<wire::Segment>, i32> {
    // SAFETY: a shared read of a table only `apply` writes, bracketed by the
    // table's sequence lock.
    unsafe { ensure_sized() };
    read_consistent(&TABLE_SEQ[T_SEG], || {
        // SAFETY: as above.
        let segs = unsafe { &*core::ptr::addr_of!(SEGS) };
        let n = COUNT[T_SEG].load(Ordering::Acquire).min(segs.len());
        segs.iter().take(n).find(|s| s.id == id).copied()
    })
    .ok_or(errno::EAGAIN)
}

/// A copy of the segment whose prefix holds `addr` (of `family`), if any —
/// the most specific when several do. `Err(EAGAIN)` as [`segment`].
pub fn segment_for(family: u8, addr: &[u8; wire::ADDR_LEN]) -> Result<Option<wire::Segment>, i32> {
    // SAFETY: as `segment`.
    unsafe { ensure_sized() };
    read_consistent(&TABLE_SEQ[T_SEG], || {
        // SAFETY: as above.
        let segs = unsafe { &*core::ptr::addr_of!(SEGS) };
        let n = COUNT[T_SEG].load(Ordering::Acquire).min(segs.len());
        segs.iter()
            .take(n)
            .filter(|s| s.prefix.contains(family, addr))
            .max_by_key(|s| s.prefix.len)
            .copied()
    })
    .ok_or(errno::EAGAIN)
}

/// What a CREATE naming `segment` (≥ 1) must satisfy before a backend
/// realizes it: the segment exists (`ENOENT`), the address is the segment's
/// family, inside its prefix and not its gateway (`EINVAL`), and the backend
/// attaches workloads to segments (`ENOSYS`). The segment the workload
/// joins on success.
pub fn validate_attach(
    family: u8,
    addr: &[u8; wire::ADDR_LEN],
    segment_id: u16,
    backend_attaches: bool,
) -> Result<wire::Segment, i32> {
    let Some(s) = segment(segment_id)? else {
        return Err(errno::ENOENT);
    };
    if !s.prefix.contains(family, addr) || s.gateway == *addr {
        return Err(errno::EINVAL);
    }
    if !backend_attaches {
        return Err(errno::ENOSYS);
    }
    Ok(s)
}

// ---- dispatch -------------------------------------------------------------

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Reset the state region for table `t` to `n` pending entries, and
/// advance both generations. Called inside the table's write side.
fn reset_states(t: usize, n: usize, states: &mut [wire::EntryState]) {
    let kind = match t {
        T_SEG => wire::entry::KIND_SEGMENT,
        T_ROUTE => wire::entry::KIND_ROUTE,
        _ => wire::entry::KIND_HELD,
    };
    for (i, e) in states.iter_mut().take(n).enumerate() {
        *e = wire::EntryState {
            kind,
            index: i as u16,
            ..wire::EntryState::EMPTY
        };
    }
    STATE_COUNT[t].store(n, Ordering::Release);
}

/// The state table of request table `t`.
///
/// # Safety
/// The caller is inside the state region's write side, or reads under its
/// sequence lock.
unsafe fn state_table(t: usize) -> &'static mut [wire::EntryState] {
    match t {
        T_SEG => &mut *core::ptr::addr_of_mut!(SEG_STATE),
        T_ROUTE => &mut *core::ptr::addr_of_mut!(ROUTE_STATE),
        _ => &mut *core::ptr::addr_of_mut!(HELD_STATE),
    }
}

/// Store `items` as table `t`, under the table's and the state region's
/// write sides. Called with the table's apply flag held, so the table's own
/// write side is free; the state region is held only across copies, so it
/// is waited for. `EAGAIN` only when it stayed busy past [`STATE_SPINS`].
fn store<T: Copy>(t: usize, items: &[T], table: &mut [T]) -> Result<(), i32> {
    if !write_begin(&TABLE_SEQ[t]) {
        return Err(errno::EAGAIN);
    }
    let mut spins = 0;
    while !write_begin(&STATE_SEQ) {
        spins += 1;
        if spins >= STATE_SPINS {
            write_end(&TABLE_SEQ[t]);
            return Err(errno::EAGAIN);
        }
        relax();
    }
    for (d, s) in table.iter_mut().zip(items) {
        *d = *s;
    }
    COUNT[t].store(items.len(), Ordering::Release);
    // SAFETY: inside the state region's write side.
    reset_states(t, items.len(), unsafe { state_table(t) });
    TABLE_GEN.fetch_add(1, Ordering::AcqRel);
    STATE_GEN.fetch_add(1, Ordering::AcqRel);
    write_end(&STATE_SEQ);
    write_end(&TABLE_SEQ[t]);
    Ok(())
}

/// Run `f` as the one replace of table `t`: `EBUSY` while another is in
/// flight (a module single-steps, so that one is another module's).
fn exclusive(t: usize, f: impl FnOnce() -> i32) -> i32 {
    if APPLYING[t]
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return errno::EBUSY;
    }
    let rc = f();
    APPLYING[t].store(false, Ordering::Release);
    rc
}

/// Admit a replace of table `t` holding `n` entries from the caller: its
/// capacity (`ENOSPC`, counted) and its writer (`EBUSY`). Under the table's
/// apply flag.
fn admit_replace(t: usize, n: usize) -> Result<(usize, u32), i32> {
    if n > CAPACITY[t].load(Ordering::Relaxed) {
        crate::kernel::sys::resource_ledger::deny(POOLS[t]);
        return Err(errno::ENOSPC);
    }
    let (slot, gen) = caller();
    if !may_write(t, slot, gen) {
        return Err(errno::EBUSY);
    }
    Ok((slot, gen))
}

fn bind(t: usize, slot: usize, gen: u32) {
    WRITER[t].store(pack(slot, gen), Ordering::Release);
}

/// A realizer's hook for one table.
type RealizeFn<T> = fn(&[T]) -> Result<(), i32>;

/// Realize `new` and store it as table `t`, then bind its writer. A store
/// that cannot complete realizes `old` again, so the host never holds a
/// table the store does not.
fn realize_and_store<T: Copy>(
    t: usize,
    new: &[T],
    old: &[T],
    table: &mut [T],
    realize: Option<RealizeFn<T>>,
    writer: (usize, u32),
) -> i32 {
    if let Some(f) = realize {
        if let Err(e) = f(new) {
            return e;
        }
    }
    if let Err(e) = store(t, new, table) {
        if let Some(f) = realize {
            if f(old).is_err() {
                log::error!("[net_route] table {t} stored as before, realized as refused");
            }
        }
        return e;
    }
    bind(t, writer.0, writer.1);
    0
}

/// Decode a SEGMENTS argument into `out`; the count, or `EINVAL`.
fn parse_segments(a: &[u8], out: &mut [wire::Segment]) -> Result<usize, i32> {
    let n = *a.first().ok_or(errno::EINVAL)? as usize;
    if n > out.len() {
        return Err(errno::ENOSPC);
    }
    let mut at = 1;
    for i in 0..n {
        let (s, next) = wire::segment_at(a, at).ok_or(errno::EINVAL)?;
        // Ids and gateways name one segment each.
        if out
            .iter()
            .take(i)
            .any(|o| o.id == s.id || (o.prefix.family == s.prefix.family && o.gateway == s.gateway))
        {
            return Err(errno::EINVAL);
        }
        out[i] = s;
        at = next;
    }
    if at != a.len() {
        return Err(errno::EINVAL);
    }
    Ok(n)
}

/// Whether a workload is attached to segment `id`: the platform's
/// realization says, or, where a module realizes the tables, the kernel's
/// own record of the workloads it admitted onto one.
fn segment_in_use(id: u16, realizer: Option<&Realizer>) -> bool {
    match realizer {
        Some(r) => (r.segment_in_use)(id),
        None => {
            #[cfg(feature = "multitenant")]
            {
                crate::kernel::workload::workload_graph::segment_attached(id)
            }
            #[cfg(not(feature = "multitenant"))]
            {
                let _ = id;
                false
            }
        }
    }
}

/// Whether the replace would detach a segment a workload is on: it goes,
/// or its family, prefix or gateway changes.
fn removes_attached(
    new: &[wire::Segment],
    old: &[wire::Segment],
    realizer: Option<&Realizer>,
) -> bool {
    old.iter().any(|o| {
        let kept = new
            .iter()
            .any(|s| s.id == o.id && s.prefix == o.prefix && s.gateway == o.gateway);
        !kept && segment_in_use(o.id, realizer)
    })
}

/// SEGMENTS, ROUTES and HOLD share one shape under the table's apply flag:
/// capacity and writer, decode, the table-specific checks, realize, store,
/// bind.
unsafe fn replace_segments(a: &[u8], realizer: Option<&Realizer>) -> i32 {
    let Some(&n) = a.first() else {
        return errno::EINVAL;
    };
    exclusive(T_SEG, || {
        // SAFETY: the table's apply flag is held: no other replace touches it.
        unsafe { replace_segments_locked(a, n as usize, realizer) }
    })
}

unsafe fn replace_segments_locked(a: &[u8], n: usize, realizer: Option<&Realizer>) -> i32 {
    let writer = match admit_replace(T_SEG, n) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut buf = crate::scratch![wire::Segment::EMPTY; MAX_SEGMENTS, n];
    if let Err(e) = parse_segments(a, &mut buf) {
        return e;
    }
    let table = &mut *core::ptr::addr_of_mut!(SEGS);
    let had = COUNT[T_SEG].load(Ordering::Acquire).min(table.len());
    let mut old = crate::scratch![wire::Segment::EMPTY; MAX_SEGMENTS, had];
    for (d, s) in old.iter_mut().zip(table.iter()) {
        *d = *s;
    }
    let (new, old) = (&buf[..n], &old[..had]);
    if removes_attached(new, old, realizer) {
        return errno::EBUSY;
    }
    realize_and_store(T_SEG, new, old, table, realizer.map(|r| r.segments), writer)
}

unsafe fn replace_routes(a: &[u8], realizer: Option<&Realizer>) -> i32 {
    let Some(n) = u16_at(a, 0).map(usize::from) else {
        return errno::EINVAL;
    };
    exclusive(T_ROUTE, || {
        // SAFETY: as `replace_segments`.
        unsafe { replace_routes_locked(a, n, realizer) }
    })
}

unsafe fn replace_routes_locked(a: &[u8], n: usize, realizer: Option<&Realizer>) -> i32 {
    let writer = match admit_replace(T_ROUTE, n) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if a.len() != 2 + n * wire::peer::SIZE {
        return errno::EINVAL;
    }
    let mut buf = crate::scratch![wire::Route::EMPTY; MAX_PEERS, n];
    for (i, slot) in buf.iter_mut().take(n).enumerate() {
        match wire::route_at(a, 2 + i * wire::peer::SIZE) {
            Some(r) => *slot = r,
            None => return errno::EINVAL,
        }
    }
    let table = &mut *core::ptr::addr_of_mut!(ROUTES);
    let had = COUNT[T_ROUTE].load(Ordering::Acquire).min(table.len());
    let mut old = crate::scratch![wire::Route::EMPTY; MAX_PEERS, had];
    for (d, s) in old.iter_mut().zip(table.iter()) {
        *d = *s;
    }
    realize_and_store(
        T_ROUTE,
        &buf[..n],
        &old[..had],
        table,
        realizer.map(|r| r.routes),
        writer,
    )
}

unsafe fn replace_held(a: &[u8], realizer: Option<&Realizer>) -> i32 {
    let Some(n) = u16_at(a, 0).map(usize::from) else {
        return errno::EINVAL;
    };
    exclusive(T_HELD, || {
        // SAFETY: as `replace_segments`.
        unsafe { replace_held_locked(a, n, realizer) }
    })
}

unsafe fn replace_held_locked(a: &[u8], n: usize, realizer: Option<&Realizer>) -> i32 {
    let writer = match admit_replace(T_HELD, n) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if a.len() != 2 + n * wire::held::SIZE {
        return errno::EINVAL;
    }
    let mut buf = crate::scratch![wire::Held::EMPTY; MAX_HELD, n];
    for i in 0..n {
        match wire::held_at(a, 2 + i * wire::held::SIZE) {
            Some(h)
                if !buf[..i]
                    .iter()
                    .any(|o| o.family == h.family && o.addr == h.addr) =>
            {
                buf[i] = h
            }
            _ => return errno::EINVAL,
        }
    }
    let table = &mut *core::ptr::addr_of_mut!(HELD);
    let had = COUNT[T_HELD].load(Ordering::Acquire).min(table.len());
    let mut old = crate::scratch![wire::Held::EMPTY; MAX_HELD, had];
    for (d, s) in old.iter_mut().zip(table.iter()) {
        *d = *s;
    }
    realize_and_store(
        T_HELD,
        &buf[..n],
        &old[..had],
        table,
        realizer.map(|r| r.held),
        writer,
    )
}

/// Ask the realizer for every entry's state and record what changed. A
/// writer already in the state region (a concurrent READ) leaves it to
/// that one.
fn refresh_states(r: &Realizer) {
    if !write_begin(&STATE_SEQ) {
        return;
    }
    let mut changed = false;
    for t in [T_SEG, T_ROUTE, T_HELD] {
        let n = STATE_COUNT[t].load(Ordering::Acquire);
        // SAFETY: inside the state region's write side.
        let states = unsafe { state_table(t) };
        for (i, e) in states.iter_mut().take(n).enumerate() {
            let (s, why) = (r.state)(e.kind, i);
            let (ig, cut, kind) = if t == T_HELD {
                (r.held_evidence)(i)
            } else {
                (0, 0, 0)
            };
            if e.state != s
                || e.reason != why
                || e.install_gen != ig
                || e.cutoff != cut
                || e.cutoff_kind != kind
            {
                e.state = s;
                e.reason = why;
                e.install_gen = ig;
                e.cutoff = cut;
                e.cutoff_kind = kind;
                changed = true;
            }
        }
    }
    if changed {
        STATE_GEN.fetch_add(1, Ordering::AcqRel);
    }
    write_end(&STATE_SEQ);
}

unsafe fn read(out: &mut [u8], realizer: Option<&Realizer>) -> i32 {
    if out.len() < 8 {
        return errno::EINVAL;
    }
    if let Some(r) = realizer {
        refresh_states(r);
    }
    let rc = read_consistent(&STATE_SEQ, || {
        let gen = STATE_GEN.load(Ordering::Acquire);
        let counts = [
            STATE_COUNT[T_SEG].load(Ordering::Acquire),
            STATE_COUNT[T_ROUTE].load(Ordering::Acquire),
            STATE_COUNT[T_HELD].load(Ordering::Acquire),
        ];
        let need = 8 + counts.iter().sum::<usize>() * wire::entry::SIZE;
        for (d, s) in out.iter_mut().zip(gen.to_le_bytes()) {
            *d = s;
        }
        if need > out.len() {
            return errno::ERANGE;
        }
        let mut at = 8;
        for (t, &n) in counts.iter().enumerate() {
            // SAFETY: read under the state region's sequence lock.
            let states = unsafe { state_table(t) };
            for e in states.iter().take(n) {
                at += wire::write_entry(out, at, e).unwrap_or(0);
            }
        }
        at as i32
    });
    rc.unwrap_or(errno::EAGAIN)
}

unsafe fn report(a: &[u8]) -> i32 {
    if !caller_is_net_identity_provider() {
        return errno::EACCES;
    }
    if !a.len().is_multiple_of(wire::entry::SIZE) {
        return errno::EINVAL;
    }
    if !write_begin(&STATE_SEQ) {
        return errno::EAGAIN;
    }
    // Inside the state region a replace cannot move the tables, so this is
    // the table generation the entries' indices are checked against.
    let rc = if TAKEN_GEN.load(Ordering::Acquire) != TABLE_GEN.load(Ordering::Acquire) {
        errno::EAGAIN
    } else {
        apply_report(a)
    };
    write_end(&STATE_SEQ);
    rc
}

/// Check every entry of a REPORT, then record them: a malformed report
/// changes nothing. Inside the state region's write side.
unsafe fn apply_report(a: &[u8]) -> i32 {
    for at in (0..a.len()).step_by(wire::entry::SIZE) {
        let Some(e) = wire::entry_at(a, at) else {
            return errno::EINVAL;
        };
        let t = (e.kind - 1) as usize;
        let n = STATE_COUNT[t]
            .load(Ordering::Acquire)
            .min(state_table(t).len());
        if e.index as usize >= n {
            return errno::EINVAL;
        }
    }
    let mut changed = false;
    for at in (0..a.len()).step_by(wire::entry::SIZE) {
        let Some(e) = wire::entry_at(a, at) else {
            continue;
        };
        if let Some(slot) = state_table((e.kind - 1) as usize).get_mut(e.index as usize) {
            if *slot != e {
                *slot = e;
                changed = true;
            }
        }
    }
    if changed {
        STATE_GEN.fetch_add(1, Ordering::AcqRel);
    }
    0
}

unsafe fn take(out: &mut [u8]) -> i32 {
    if !caller_is_net_identity_provider() {
        return errno::EACCES;
    }
    if out.len() < 8 {
        return errno::EINVAL;
    }
    for _ in 0..READ_RETRIES {
        let gen = TABLE_GEN.load(Ordering::Acquire);
        let segs = &*core::ptr::addr_of!(SEGS);
        let routes = &*core::ptr::addr_of!(ROUTES);
        let held = &*core::ptr::addr_of!(HELD);
        let r = read_consistent(&TABLE_SEQ[T_SEG], || {
            let n = COUNT[T_SEG].load(Ordering::Acquire).min(segs.len());
            segs.iter().take(n).map(|s| s.wire_len()).sum::<usize>()
        });
        let Some(seg_bytes) = r else { continue };
        let nr = COUNT[T_ROUTE].load(Ordering::Acquire).min(routes.len());
        let nh = COUNT[T_HELD].load(Ordering::Acquire).min(held.len());
        let ns = COUNT[T_SEG].load(Ordering::Acquire).min(segs.len());
        // The header — generation and counts — goes out whether or not the
        // records fit, so a reader past its buffer knows what it is missing.
        let mut head = [0u8; wire::TAKE_HEAD];
        head[..8].copy_from_slice(&gen.to_le_bytes());
        head[8] = ns as u8;
        head[10..12].copy_from_slice(&(nr as u16).to_le_bytes());
        head[12..14].copy_from_slice(&(nh as u16).to_le_bytes());
        for (d, s) in out.iter_mut().zip(head) {
            *d = s;
        }
        let at = wire::TAKE_HEAD;
        let need = at + seg_bytes + nr * wire::peer::SIZE + nh * wire::held::SIZE;
        if need > out.len() {
            if TABLE_GEN.load(Ordering::Acquire) != gen {
                continue;
            }
            TAKEN_GEN.store(gen, Ordering::Release);
            return errno::ERANGE;
        }
        let ok = read_consistent(&TABLE_SEQ[T_SEG], || {
            let mut p = at;
            for s in segs.iter().take(ns) {
                p += wire::write_segment(out, p, s).unwrap_or(0);
            }
            p
        })
        .and_then(|p| {
            read_consistent(&TABLE_SEQ[T_ROUTE], || {
                let mut q = p;
                for r in routes.iter().take(nr) {
                    q += wire::write_route(out, q, r).unwrap_or(0);
                }
                q
            })
        })
        .and_then(|q| {
            read_consistent(&TABLE_SEQ[T_HELD], || {
                let mut z = q;
                for h in held.iter().take(nh) {
                    z += wire::write_held(out, z, h).unwrap_or(0);
                }
                z
            })
        });
        match ok {
            Some(end) if TABLE_GEN.load(Ordering::Acquire) == gen => {
                TAKEN_GEN.store(gen, Ordering::Release);
                return end as i32;
            }
            _ => continue,
        }
    }
    errno::EAGAIN
}

/// The contract's dispatch, for a provider realized by `realizer` (`None`
/// where a module realizes the tables through `TAKE`/`REPORT`).
///
/// # Safety
/// `arg` points to `arg_len` caller-owned bytes for the call (the provider
/// contract).
pub unsafe fn dispatch(
    realizer: Option<&Realizer>,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if handle >= 0 {
        return errno::EINVAL;
    }
    // The node's routing is the node's: only a module acting with its
    // authority reaches it, whatever else it holds.
    if !crate::kernel::exec::scheduler::caller_authority().is_system() {
        return errno::EACCES;
    }
    ensure_sized();
    let a: &mut [u8] = if arg.is_null() || arg_len == 0 {
        &mut []
    } else {
        core::slice::from_raw_parts_mut(arg, arg_len)
    };
    match opcode {
        wire::PROBE => 0,
        wire::CAPS => {
            let caps = match realizer {
                Some(r) => (r.caps)(),
                None => module_caps(),
            };
            if a.len() < 4 {
                return errno::EINVAL;
            }
            for (d, s) in a.iter_mut().zip(caps.to_le_bytes()) {
                *d = s;
            }
            0
        }
        wire::SEGMENTS => replace_segments(a, realizer),
        wire::ROUTES => replace_routes(a, realizer),
        wire::HOLD => {
            // A held address a module realizes goes through that module's
            // own table; with a coordinator writing its `addr_ctl` there
            // would be two writers of the node's addresses.
            #[cfg(feature = "multitenant")]
            if realizer.is_none()
                && crate::kernel::workload::workload_graph::direct_addr_ctl_wired()
            {
                return errno::EBUSY;
            }
            replace_held(a, realizer)
        }
        wire::READ => read(a, realizer),
        wire::REPORT => report(a),
        wire::TAKE => take(a),
        _ => errno::ENOSYS,
    }
}

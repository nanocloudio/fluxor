//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
use super::*;

// ===========================================================================
// Multi-graph runtime (resident graphs in the domain loop)
// ===========================================================================
//
// The graph-local pacer surface above is keyed by `(graph_slot, generation,
// domain)`. This section is the runtime that admits and concurrently runs MORE
// THAN ONE resident graph, so that pacer surface is live: each resident graph is
// an `owner::OwnerHandle{slot, generation}` (the node graph is `OWNER_NODE`,
// slot 0; workload graphs are admitted as owners 1..N via the splice (`splice::admit`)). On
// a shared domain loop the pass steps each owner's modules
// independently, skips an idle owner, and arms the physical sleep as the
// deadline-merge minimum.
//
// The resident-graph index is a table built at admission/finalize time, NOT
// scanned per pass. The graph→domain→pacer keys are resolved into
// `RESIDENT_GRAPHS` once; a live pass only reads it. It is a per-owner table,
// sized at boot with the owner table to a `(graph, domain)` entry per owner
// slot and domain (`size_resident_graphs`), so every resident graph the owner
// table seats is indexed.

/// One resident `(graph, domain)` the domain loop multiplexes. `mask` is the cached
/// set of module slots this graph owns *in this domain* (built at finalize so
/// `take_wake_in_mask` is an `EVENT_WAKE ∩ mask` intersection, never a scan).
/// `primed` forces the first pass after (re)build to step the graph at least
/// once so the steady-state runnable predicate has prior-pass signals to read.
#[derive(Clone, Copy)]
pub(crate) struct ResidentGraph {
    pub(crate) slot: u16,
    pub(crate) generation: u32,
    pub(crate) domain: u8,
    pub(crate) mask: ModuleMask,
    pub(crate) primed: bool,
    /// The graph's `MON_GRAPH_PACER` line: its last idle/busy state and the
    /// rate limit on reporting it.
    pacer_line: PacerLine,
    /// Modules with `step_period > 1`, each on its own wall-clock schedule
    /// (`SchedulerState::module_next_due_us`): a due one makes the graph
    /// runnable, and the soonest bounds the domain's sleep.
    pub(crate) periodic_mask: ModuleMask,
    /// True iff EVERY owned module is idle-safe attested — the precondition for
    /// fully parking the graph when idle. When false the graph is
    /// fail-closed: never parked, only relaxed to the `tick_max` backstop.
    pub(crate) idle_safe: bool,
    /// Absolute wall-clock deadline (µs) for the next backstop liveness step of a
    /// NON-idle-safe graph (advanced by `tick_max` each backstop step). Unused
    /// when `idle_safe` (the graph may park outright).
    pub(crate) backstop_next_due_us: u64,
}

impl ResidentGraph {
    const EMPTY: ResidentGraph = ResidentGraph {
        slot: 0,
        generation: 0,
        domain: 0,
        mask: ModuleMask::EMPTY,
        primed: false,
        pacer_line: PacerLine::NEW,
        periodic_mask: ModuleMask::EMPTY,
        idle_safe: false,
        backstop_next_due_us: 0,
    };
}

/// The resident `(graph, domain)` entries, `RESIDENT_GRAPH_COUNT` of them
/// live, at most one per owner slot and domain.
static mut RESIDENT_GRAPHS: crate::kernel::mem::table::Table<
    ResidentGraph,
    { crate::kernel::workload::owner::OWNER_TABLE_SLOTS * MAX_DOMAINS },
> = crate::boot_table!(
    crate::kernel::workload::owner::OWNER_TABLE_SLOTS * MAX_DOMAINS,
    ResidentGraph::EMPTY,
    crate::abi::contracts::resource::POOL_OWNERS,
    MAX_DOMAINS
);
static mut RESIDENT_GRAPH_COUNT: usize = 0;

/// Size the resident-graph index for an owner table of `owners` slots: an
/// entry per slot and domain, the most distinct `(graph, domain)` pairs the
/// modules of those owners can form. Committed as the index fills.
///
/// # Safety
/// As `Table::reserve`: graph preparation, with no entry borrowed.
pub(crate) unsafe fn size_resident_graphs(
    owners: usize,
) -> Result<(), crate::kernel::mem::table::TableError> {
    let n = owners
        .checked_mul(MAX_DOMAINS)
        .ok_or(crate::kernel::mem::table::TableError::Ceiling)?;
    // SAFETY: the caller's contract; the count is reset with the graph.
    unsafe {
        RESIDENT_GRAPH_COUNT = 0;
        (*core::ptr::addr_of!(RESIDENT_GRAPHS)).reserve(n)
    }
}

/// Whether slot `idx` belongs to a resident graph: an occupied slot.
pub(crate) fn slot_resident(sched: &SchedulerState, idx: usize) -> bool {
    !matches!(sched.modules[idx], ModuleSlot::Empty)
}

/// Rebuild the resident-graph index from the resident module set. Runs when
/// a graph is prepared, admitted or freed (a reused slot is a new
/// generation, so its pacer starts fresh and its `primed` flag re-arms);
/// with every other domain parked on a multicore target. One bounded pass
/// over module slots, never on the hot path.
pub fn rebuild_resident_graph_index() {
    // SAFETY: scheduler-thread-exclusive; never concurrent with a pass.
    let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
    // SAFETY: same single-mutator context as `sched` above.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(RESIDENT_GRAPHS) };
    let mut count = 0usize;
    for entry in table.iter_mut() {
        *entry = ResidentGraph::EMPTY;
    }
    for idx in 0..module_slots() {
        if !slot_resident(sched, idx) {
            continue;
        }
        let owner = sched.module_owner[idx];
        let domain = (sched.domain_id[idx] as usize).min(MAX_DOMAINS - 1) as u8;
        let found = table.iter().take(count).position(|e| {
            e.slot == owner.slot && e.generation == owner.generation && e.domain == domain
        });
        let i = match found {
            Some(i) => i,
            None => {
                // The index commits entries as it fills; its ceiling is an
                // entry per owner slot and domain, which no set of live
                // owners exceeds. Fail closed if it ever does.
                if count >= table.len() && table.grow(count + 1).is_err() {
                    log::error!(
                        "[multigraph] resident-graph index full ({}); module {idx} owner \
                         slot={} not indexed",
                        table.len(),
                        owner.slot
                    );
                    continue;
                }
                let i = count;
                table[i] = ResidentGraph {
                    slot: owner.slot,
                    generation: owner.generation,
                    domain,
                    // Idle-safe until a module without the attestation joins.
                    idle_safe: true,
                    ..ResidentGraph::EMPTY
                };
                count += 1;
                i
            }
        };
        table[i].mask.set(idx);
        if sched.step_period[idx] > 1 {
            table[i].periodic_mask.set(idx);
        }
        if !sched.module_idle_safe[idx] {
            table[i].idle_safe = false;
        }
    }
    // A pacer whose key no longer appears belongs to a freed or rebuilt
    // graph; release it so a reused slot starts fresh.
    graph_pacer_retain(|slot, generation, domain| {
        table
            .iter()
            .take(count)
            .any(|e| e.slot == slot && e.generation == generation && e.domain == domain)
    });
    // SAFETY: scheduler-thread-exclusive write.
    unsafe {
        RESIDENT_GRAPH_COUNT = count;
    }
}

/// A copy of resident-graph entry `gi`.
pub(crate) fn resident_graph(gi: usize) -> Option<ResidentGraph> {
    // SAFETY: an entry's identity changes only at a rebuild (other domains
    // parked); its pass state only by its own domain's loop, the caller.
    let table = unsafe { &*core::ptr::addr_of!(RESIDENT_GRAPHS) };
    // SAFETY: as above.
    if gi >= unsafe { RESIDENT_GRAPH_COUNT } {
        return None;
    }
    table.get(gi).copied()
}

/// Record that the pass stepped graph `gi`: it is primed, and its next
/// backstop liveness step is due at `backstop_us`.
pub(crate) fn mark_graph_stepped(gi: usize, backstop_us: u64) {
    // SAFETY: this domain's loop writes its own entry.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(RESIDENT_GRAPHS) };
    if let Some(e) = table.get_mut(gi) {
        e.primed = true;
        e.backstop_next_due_us = backstop_us;
    }
}

/// Boot path: admit every resident workload the config declares (its `WKLD`
/// section: the `combine <two-graph.yaml>` / `workloads:` mechanism) as a
/// workload owner via the splice. Call ONCE after the node's graph is
/// published and BEFORE the per-domain run loops start. No-op when the
/// config declares no workloads.
pub fn admit_resident_workloads_from_config() {
    // SAFETY: boot context — single-threaded, sole reader of STATIC_CONFIG.
    let cfg = unsafe { static_config() };
    // The config parser admitted the blob whole: the section is checksummed
    // and every record bounded by the codec.
    let Some(workloads) = cfg.workloads() else {
        return;
    };
    // Each workload's blob is applied where it lies in the config image:
    // the add borrows the blob's params in place, as the node graph's
    // modules borrow theirs, and the image stays mapped for the kernel's
    // life. Nothing is copied, so no blob is too large for a buffer.
    //
    // Atomic admission: a partial admit (some workloads live, others
    // rejected) would contradict the "all workloads" contract and leave the
    // runtime half-built. Each admitted owner's slot is recorded; if ANY
    // workload fails, every owner admitted in this pass is rolled back via
    // `free_owner` and ZERO are admitted — the runtime stays single-graph
    // rather than partially multiplexed.
    const SLOT_WORDS: usize = crate::kernel::workload::owner::MAX_OWNERS.div_ceil(64);
    let mut admitted_slots = [0u64; SLOT_WORDS];
    let mut admitted = 0usize;
    let mut failed = false;
    for workload in workloads.iter() {
        if workload.blob.is_empty() {
            log::error!("[multigraph] resident workload with an empty blob; rolling back");
            failed = true;
            break;
        }
        // SAFETY: `workload.blob` lies in the config image, which stays
        // mapped and unchanged for the kernel's life; the splice validates
        // the composed graph before anything is allocated.
        match unsafe { super::splice::apply_borrowed(workload.blob) } {
            Ok(handle) => {
                let slot = handle.slot as usize;
                admitted_slots[slot / 64] |= 1 << (slot % 64);
                admitted += 1;
                // The endpoints the graph's author granted it: what its
                // lanes may listen on, and all they may.
                if let Err(rc) = crate::kernel::workload::endpoints::admit(
                    handle,
                    crate::kernel::workload::endpoints::listed(workload.endpoints),
                ) {
                    log::error!(
                        "[multigraph] resident workload endpoints refused rc={rc}; rolling back"
                    );
                    failed = true;
                    break;
                }
                // The workload's idle-safe attestation goes on its
                // modules; the index is rebuilt from them below. Unattested
                // workloads stay fail-closed (backstop cadence).
                set_owner_idle_safe(handle, workload.idle_safe);
            }
            Err(rc) => {
                log::error!("[multigraph] resident workload admit failed rc={rc}; rolling back");
                failed = true;
                break;
            }
        }
    }
    if failed {
        for slot in 1..crate::kernel::workload::owner::MAX_OWNERS {
            if admitted_slots[slot / 64] & (1 << (slot % 64)) == 0 {
                continue;
            }
            if let Some(e) = super::owners().entry_at(slot) {
                let _ = live::free_owner(crate::kernel::workload::owner::OwnerHandle {
                    slot: slot as u16,
                    generation: e.generation,
                });
            }
        }
        log::error!(
            "[multigraph] resident workload admission aborted; rolled back {admitted} workload(s) — \
             none active (single-graph boot)"
        );
        return;
    }
    if admitted > 0 {
        log::info!("[multigraph] admitted {admitted} resident workload(s) from config");
        rebuild_resident_graph_index();
    }
}

/// Number of distinct resident `(graph, domain)` instances the domain loop is
/// multiplexing. `<= 1` selects the single-graph fast path.
pub fn resident_graph_count() -> usize {
    // SAFETY: scheduler-thread read of a bounded counter.
    unsafe { RESIDENT_GRAPH_COUNT }
}

/// Pause predicate for a resident graph: true iff the owning slot is
/// `Paused` at this generation. Callers MUST short-circuit behind
/// `event::paused_owners_present()` so the unused path stays a single
/// relaxed load (default-off discipline).
#[inline]
pub(crate) fn owner_graph_paused(sched: &SchedulerState, slot: u16, generation: u32) -> bool {
    slot != 0
        && sched.owners.entry_at(slot as usize).is_some_and(|e| {
            e.generation == generation
                && matches!(e.state, crate::kernel::workload::owner::OwnerState::Paused)
        })
}

/// Readable-channel term: does any edge whose CONSUMER belongs to
/// this graph — and whose PRODUCER does not — hold readable bytes? Without
/// this term, data written into a skipped graph's inbound channel (a
/// cross-owner the splice edge, or a node graph producer) waits for the
/// graph's backstop cadence: under demand-driven idle that is
/// `tick_max_us` per hop — the multi-workload latency term this domain loop
/// exists to remove. The check adds a wake REASON evaluated at the
/// domain loop's existing cadence — not a wake source — so there is no storm
/// surface and no ordering change.
///
/// Cost: O(edges) per otherwise-idle graph per pass, one lock-guarded
/// `channel_poll` per cross-graph edge (POLL_IN covers both FIFO fill and
/// mailbox READY). Callers short-circuit it behind every cheaper runnable
/// term. If graph counts ever make the scan measurable, the refinement is
/// a per-graph dirty bit set inside `channel_write` — decide
/// from density-scenario profiling, not up front.
///
/// Intra-graph edges are deliberately excluded: data on them can only have
/// been produced by this graph's own modules, whose step already reported
/// work/burst to the pacer — including them would keep a graph busy on
/// bytes it is itself draining at its own pace.
///
/// Fills `out` with the CONSUMER modules that have readable inbound data;
/// the domain loop adds them to the woken set so they step with
/// `event_wake = true` (bypassing step-period gating) — cross-graph
/// channel data thereby carries exactly the semantics of a targeted
/// `event_signal`, which is what mechanism (a) means by a "channel
/// write" wake. Returns `true` if any were found.
pub(crate) fn graph_inbound_readable(
    sched: &SchedulerState,
    mask: &ModuleMask,
    out: &mut ModuleMask,
) -> bool {
    let mut any = false;
    for e in sched.edges.iter().take(sched.edge_count) {
        if !mask.test(e.to_module) || mask.test(e.from_module) {
            continue;
        }
        // Consumer-side handle: the bridged override when present (the
        // consumer can only read what the pump already delivered), else
        // the shared channel.
        let ch = if e.consumer_channel >= 0 {
            e.consumer_channel
        } else {
            e.channel
        };
        if ch < 0 {
            continue;
        }
        let ready =
            crate::kernel::ipc::channel::channel_poll(ch, crate::kernel::ipc::channel::POLL_IN);
        if ready > 0 && (ready as u32 & crate::kernel::ipc::channel::POLL_IN) != 0 {
            out.set(e.to_module);
            any = true;
        }
    }
    any
}

/// The least time between two `MON_GRAPH_PACER` lines of one graph (µs).
pub const PACER_LOG_INTERVAL_US: u64 = 1_000_000;

/// The rate limit on one resident graph's `MON_GRAPH_PACER` line.
///
/// Each pass reports the graph's idle/busy state with [`PacerLine::observe`].
/// A change of state is a transition; transitions are reported on a line
/// carrying how many there were, at most one line per
/// [`PACER_LOG_INTERVAL_US`]. The first transition is reported at once; one
/// that falls inside the interval is held and reported, with any that follow
/// it, on the first pass after the interval ends, so the last line always
/// names the state the graph settled in. A graph that flips state every few
/// ticks costs one line a second, not one a flip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacerLine {
    busy: bool,
    pending: u32,
    logged_at_us: Option<u64>,
}

impl PacerLine {
    /// A graph not yet observed: taken as busy, as its first pass steps it,
    /// with nothing reported.
    pub const NEW: PacerLine = PacerLine {
        busy: true,
        pending: 0,
        logged_at_us: None,
    };

    /// Record the graph's state at `now_us` (a monotonic clock). Returns the
    /// transitions a line logged now reports, or `None` when no line is due:
    /// nothing has changed since the last line, or the last line is under
    /// [`PACER_LOG_INTERVAL_US`] old. The count saturates at `u32::MAX`.
    pub fn observe(&mut self, busy: bool, now_us: u64) -> Option<u32> {
        if busy != self.busy {
            self.busy = busy;
            self.pending = self.pending.saturating_add(1);
        }
        if self.pending == 0 {
            return None;
        }
        if let Some(at) = self.logged_at_us {
            if now_us.saturating_sub(at) < PACER_LOG_INTERVAL_US {
                return None;
            }
        }
        let n = self.pending;
        self.pending = 0;
        self.logged_at_us = Some(now_us);
        Some(n)
    }
}

/// Feed resident-graph entry `gi`'s state at `now` to its [`PacerLine`] and
/// log the `MON_GRAPH_PACER` line when one is due. `stepped` is whether this
/// pass stepped the graph.
pub(crate) fn log_pacer_line(
    gi: usize,
    now: u64,
    busy: bool,
    stepped: bool,
    slot: u16,
    generation: u32,
    domain: usize,
) {
    // SAFETY: scheduler-thread-exclusive write of this domain's own entry.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(RESIDENT_GRAPHS) };
    let Some(transitions) = table[gi].pacer_line.observe(busy, now) else {
        return;
    };
    let tick = pass_count(domain);
    log::info!(
        "MON_GRAPH_PACER slot={slot} gen={generation} domain={domain} state={} stepped={} \
         tick={tick} transitions={transitions}",
        if busy { "busy" } else { "idle" },
        stepped as u8,
    );
}

/// A domain's execution mode, as `prepare_graph` read it from the
/// boot-config domain record; `Tick` past the last domain.
pub fn domain_exec_mode(domain_id: usize) -> ExecMode {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        unsafe { SCHED.domains[domain_id].exec_mode }
    } else {
        ExecMode::Tick
    }
}

/// `true` if `module_idx`'s assigned domain runs an interrupt mode
/// (`timer` or `irq`). A pass skips stepping such modules because they
/// run from a timer or IRQ handler.
#[inline]
pub fn module_is_interrupt_mode(module_idx: usize) -> bool {
    if module_idx >= module_slots() {
        return false;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded.
    let d = unsafe { SCHED.domain_id[module_idx] } as usize;
    if d >= MAX_DOMAINS {
        return false;
    }
    // SAFETY: as above; d bounded by the check just above.
    let m = unsafe { SCHED.domains[d].exec_mode };
    m.is_interrupt()
}

/// Reject syscall `op` when the calling module sits in an interrupt-mode
/// (`timer` or `irq`) domain. Emits a single `MON_PERM_DENIED` log line per
/// rejection and returns `true` so the caller can bail with the standard
/// `errno::EACCES`. Cooperative callers (`tick`, `poll`, pre-pass) and
/// out-of-bounds `module_idx` return `false`.
///
/// The runtime gate is defense in depth — the build-time validator
/// (`tools/src/config.rs::validate_interrupt_admission`) already
/// rejects malformed graphs; this catches hand-rolled binaries that
/// bypass the tools pipeline.
#[inline]
pub fn deny_interrupt_mode_syscall(op: &'static str) -> bool {
    let module_idx = current_module_index();
    if module_idx >= module_slots() {
        return false;
    }
    if !module_is_interrupt_mode(module_idx) {
        return false;
    }
    // SAFETY: scheduler-thread read; module_idx already bounded.
    let domain = unsafe { SCHED.domain_id[module_idx] };
    log::warn!(
        "MON_PERM_DENIED domain={domain} mod={module_idx} op={op} tick={tick}",
        tick = pass_count(domain as usize),
    );
    true
}

/// The module making a channel call: its id (`NO_MODULE` in kernel context),
/// or `EACCES` for an interrupt-mode module, which reads and writes bridge rings
/// and never a channel (`op` names the call for the log). One lookup of the
/// stepping module serves both questions on the channel's hot path.
#[inline(never)]
pub fn channel_caller(op: &'static str) -> Result<ModuleId, i32> {
    let module_idx = current_module_index();
    if module_idx >= module_slots() {
        return Ok(NO_MODULE);
    }
    if deny_interrupt_mode_syscall(op) {
        return Err(crate::kernel::sys::errno::EACCES);
    }
    Ok(module_idx as ModuleId)
}

/// Test-facing setter — assigns `domain` to module `module_idx`.
/// Production paths route the assignment through `prepare_graph`,
/// which reads it off the config blob; this helper exists so
/// scheduler-conformance tests can plant a module's domain without
/// going through a full graph build.
pub fn set_module_domain(module_idx: usize, domain: u8) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread mutation; module_idx bounded.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    let from = (sched.domain_id[module_idx] as usize).min(MAX_DOMAINS - 1);
    let mut gone = ModuleMask::new();
    gone.set(module_idx);
    unsplice_from_orders(&gone, 1u32 << from);
    sched.domain_id[module_idx] = domain;
    let to = splice_into_order(module_idx);
    refresh_domains((1u32 << from) | to);
    rebuild_resident_graph_index();
}

/// Test-facing setter — assigns `exec_mode` to `domain_id`. Used by
/// conformance tests that exercise the cooperative-skip behaviour
/// without going through a full `prepare_graph` cycle. Production
/// callers should source `exec_mode` from `prepare_graph` reading
/// the config blob.
pub fn set_domain_exec_mode(domain_id: usize, exec_mode: ExecMode) {
    if domain_id >= MAX_DOMAINS {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; domain_id bounded.
    unsafe {
        SCHED.domains[domain_id].exec_mode = exec_mode;
    }
}

/// Return the number of configured domains.
pub fn domain_count() -> usize {
    // SAFETY: scheduler-thread-only read.
    let c = unsafe { SCHED.domain_count } as usize;
    if c == 0 {
        1
    } else {
        c
    }
}

/// Return the module count for a specific domain.
pub fn domain_module_count(domain_id: usize) -> usize {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        unsafe { SCHED.domains[domain_id].module_count as usize }
    } else {
        0
    }
}

/// Return the global module index at position `i` in `domain_id`'s
/// topologically-sorted execution order, or `None` if out of range.
/// Per-core pump loops walk this to drive every module — user modules
/// and any `_tee` / `_merge` — that lives in their domain.
pub fn domain_exec_order_at(domain_id: usize, i: usize) -> Option<usize> {
    if domain_id >= MAX_DOMAINS {
        return None;
    }
    // SAFETY: domain_id bounded above.
    let count = unsafe { SCHED.domains[domain_id].module_count as usize };
    if i >= count {
        return None;
    }
    // SAFETY: `i < count <= module_slots()`; domain_id bounded.
    Some(unsafe { SCHED.domain_exec_order[domain_id][i] as usize })
}

/// Return the domain id assigned to a module, or `0` (the default
/// domain) for out-of-range indices.
pub fn module_domain_id(module_idx: usize) -> u8 {
    if module_idx >= module_slots() {
        return 0;
    }
    // SAFETY: module_idx bounded above.
    unsafe { SCHED.domain_id[module_idx] }
}

/// Report a module's processing latency in frames.
/// Called by modules during init via the REPORT_LATENCY kernel primitive.
pub fn report_module_latency(module_idx: usize, frames: u32) {
    if module_idx < module_slots() {
        // SAFETY: scheduler-thread-only mutation; idx bounded.
        unsafe {
            SCHED.module_latency[module_idx] = frames;
        }
    }
}

/// Get the downstream latency for a module (computed after all modules init).
pub fn downstream_latency(module_idx: usize) -> u32 {
    if module_idx < module_slots() {
        // SAFETY: module_idx bounded above.
        unsafe { SCHED.downstream_latency[module_idx] }
    } else {
        0
    }
}

/// Bucket index for a step elapsed time in microseconds.
/// 0: <2, 1: <4, 2: <8, 3: <16, 4: <32, 5: <64, 6: <256, 7: >=256
///
/// The ladder is deliberately weighted BELOW the tick budget. Edges that
/// start at `<64` and double to `>=4096` put every step of a healthy
/// `tick_us: 100` graph into `b0` — a histogram that cannot separate a 1 µs
/// module from a 50 µs one, and from which no per-module share of the tick
/// budget can be computed at all.
///
/// The tail such edges would resolve is already reported exactly, and per
/// module, by `MON_HEAVY_STEP` (`elapsed_us` verbatim) and in aggregate by
/// `MON_BUDGET_OVERRUN` (`consumed_us` vs `limit_us`). Spending resolution
/// there costs the only range where attribution is still possible. `b6`/`b7`
/// keep enough of the top end to spot a heavy module without reading the
/// fault stream.
#[inline]
fn step_bucket(elapsed_us: u32) -> usize {
    if elapsed_us < 2 {
        0
    } else if elapsed_us < 4 {
        1
    } else if elapsed_us < 8 {
        2
    } else if elapsed_us < 16 {
        3
    } else if elapsed_us < 32 {
        4
    } else if elapsed_us < 64 {
        5
    } else if elapsed_us < 256 {
        6
    } else {
        7
    }
}

/// Record a step's elapsed time into per-module and global histograms.
pub fn record_step_time(module_idx: usize, elapsed_us: u32) {
    if module_idx >= module_slots() {
        return;
    }
    let b = step_bucket(elapsed_us);
    // SAFETY: scheduler-thread-only mutation; module_idx bounded above.
    unsafe {
        SCHED.step_hist[module_idx][b] = SCHED.step_hist[module_idx][b].saturating_add(1);
        SCHED.step_hist_global[b] = SCHED.step_hist_global[b].saturating_add(1);
    }
}

/// Query step histogram. `module_idx == usize::MAX` returns the global
/// histogram; otherwise a per-module histogram. Writes 8 u32 LE to
/// `out[..32]`; `EINVAL` when `out` is shorter.
pub fn query_step_histogram(module_idx: usize, out: &mut [u8]) -> i32 {
    let Some(out) = out.get_mut(..32) else {
        return crate::kernel::sys::errno::EINVAL;
    };
    // SAFETY: scheduler-thread-only read of the histogram tables.
    let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
    let hist = if module_idx == usize::MAX {
        &sched.step_hist_global
    } else if module_idx < module_slots() {
        &sched.step_hist[module_idx]
    } else {
        return crate::kernel::sys::errno::EINVAL;
    };
    for (chunk, v) in out.chunks_exact_mut(4).zip(hist.iter()) {
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    0
}

/// Serialise a module's scheduler-visible state for
/// `monitor::MODULE_STATE_QUERY`.
///
/// Every field here is one `module_state_snapshot` already tracks. What
/// this opcode adds is reach: without it a diagnostic can only infer a
/// module's state from its absence in the step histogram, which answers
/// a different question — whether it is being stepped, not why it is
/// not running.
///
/// Writes the record into `out`, which holds at least
/// `monitor::MODULE_STATE_LEN` bytes.
pub fn query_module_state(module_idx: usize, out: &mut [u8]) -> i32 {
    let out_cap = out.len();
    use crate::abi::internal::monitor::{
        module_state_flags as f, MODULE_STATE_LEN, MODULE_STATE_MAX, MODULE_STATE_NAME_MAX,
    };

    if module_idx >= module_slots() || out_cap < MODULE_STATE_LEN {
        return crate::kernel::sys::errno::EINVAL;
    }
    let s = module_state_snapshot(module_idx);

    let mut buf = [0u8; MODULE_STATE_MAX];
    use crate::abi::internal::monitor::module_state_off as o;
    buf[o::IDX..o::IDX + 2].copy_from_slice(&s.idx.to_le_bytes());
    buf[o::FLAGS] = (if s.present { f::PRESENT } else { 0 })
        | (if s.ready { f::READY } else { 0 })
        | (if s.finished { f::FINISHED } else { 0 });
    buf[o::FAULT_STATE] = s.fault_state as u8;
    buf[o::STEP_PERIOD] = s.step_period;
    buf[o::GRANTS..o::GRANTS + 8].copy_from_slice(&s.grants[0].to_le_bytes());
    buf[o::GRANTS + 8..o::GRANTS + 16].copy_from_slice(&s.grants[1].to_le_bytes());
    buf[o::DOMAIN_ID] = s.domain_id;
    // SAFETY: scheduler-thread-only read; module_idx bounded above.
    buf[o::PROTECTION] = unsafe {
        let p = &raw const SCHED;
        (&(*p).protection)[module_idx] as u8
    };
    buf[o::RESTART_COUNT..o::RESTART_COUNT + 2].copy_from_slice(&s.restart_count.to_le_bytes());
    buf[o::INACTIVE_FOR_TICKS..o::INACTIVE_FOR_TICKS + 4]
        .copy_from_slice(&s.inactive_for_ticks.to_le_bytes());
    buf[o::SLOT_GENERATION..o::SLOT_GENERATION + 4]
        .copy_from_slice(&s.slot_generation.to_le_bytes());

    // The name goes in only if the caller left room for it; a caller
    // that asked for the header alone gets `name_len = 0` rather than a
    // truncated name it would have no way to recognise as truncated.
    let mut written = MODULE_STATE_LEN;
    if s.present && out_cap > MODULE_STATE_LEN {
        // SAFETY: scheduler-thread-only read; module_idx bounded above.
        let sched = unsafe {
            let p = &raw const SCHED;
            &*p
        };
        let name = sched.modules[module_idx].type_name().as_bytes();
        let room = core::cmp::min(out_cap - MODULE_STATE_LEN, MODULE_STATE_NAME_MAX);
        let n = core::cmp::min(name.len(), room);
        buf[MODULE_STATE_LEN..MODULE_STATE_LEN + n].copy_from_slice(&name[..n]);
        buf[o::NAME_LEN] = n as u8;
        written += n;
    }

    out[..written].copy_from_slice(&buf[..written]);
    written as i32
}

/// Get fault statistics for a module (for `monitor::FAULT_STATS_QUERY`).
pub fn get_fault_stats(module_idx: usize) -> FaultStats {
    if module_idx >= module_slots() {
        return FaultStats::default();
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded above.
    unsafe {
        let pass = pass_count(SCHED.domain_id[module_idx] as usize);
        SCHED.fault_info[module_idx].to_stats(pass)
    }
}

/// A copy of a module's fault record: its policy, deadlines and fault
/// state as the step guard reads them. `None` past `MAX_MODULES`.
pub fn module_fault_info(module_idx: usize) -> Option<ModuleFaultInfo> {
    if module_idx >= module_slots() {
        return None;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded above.
    unsafe { Some(SCHED.fault_info[module_idx]) }
}

/// Get mutable fault info for a module (for config-time setup).
pub fn set_module_fault_policy(
    module_idx: usize,
    policy: FaultPolicy,
    max_restarts: u16,
    backoff_ms: u16,
) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        let fi = &mut SCHED.fault_info[module_idx];
        fi.policy = policy;
        fi.max_restarts = max_restarts;
        fi.restart_backoff_ms = backoff_ms;
    }
}

/// Set per-module step deadline (from config).
pub fn set_module_step_deadline(module_idx: usize, deadline_us: u32) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.fault_info[module_idx].step_deadline_us = deadline_us;
    }
}

/// Set the per-module burst-deadline override in microseconds.
/// `0` disables the override and falls back to the implicit
/// `step_deadline_us * BURST_MULTIPLIER` ceiling used by
/// `step_one_module`. Sourced from the module manifest's
/// `step_deadline_burst_us` setting.
pub fn set_module_step_deadline_burst(module_idx: usize, deadline_us: u32) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.fault_info[module_idx].step_deadline_burst_us = deadline_us;
    }
}

/// Declare a quarantine partner for `module_idx`. When this module
/// faults AND the partner has faulted within `QUARANTINE_WINDOW_MS`,
/// both transition to `Terminated`. Pass `NO_MODULE` to clear the pairing.
/// Sourced from the module manifest's `quarantine_partner` setting;
/// the kernel does not infer pairings from channel wiring.
pub fn set_module_quarantine_partner(module_idx: usize, partner: ModuleId) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.fault_info[module_idx].quarantine_partner = partner;
    }
}

/// Set the module's phase within its period: its first due falls
/// `period - phase - 1` nominal ticks after its first pass, so modules of one
/// period can be staggered (what `instantiate_one_module` does from the
/// manifest's `ModuleHeader::step_phase`).
pub fn set_module_step_phase(module_idx: usize, phase: u8) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        let period = SCHED.step_period[module_idx];
        SCHED.step_phase[module_idx] = if period > 0 { phase % period } else { 0 };
        SCHED.module_next_due_us[module_idx] = 0;
    }
}

/// Set a module's step period in nominal ticks of its domain (`0` or `1` =
/// every pass); its schedule re-anchors on its next pass.
pub fn set_module_step_period(module_idx: usize, period: u8) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.step_period[module_idx] = period;
        SCHED.step_phase[module_idx] = 0;
        SCHED.module_next_due_us[module_idx] = 0;
    }
    rebuild_resident_graph_index();
}

/// Read the current fault state of a module. Test-facing query so
/// scheduler conformance tests can assert fault transitions without
/// reaching into `SCHED` directly.
pub fn module_fault_state(module_idx: usize) -> FaultState {
    if module_idx >= module_slots() {
        return FaultState::Running;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded.
    unsafe { SCHED.fault_info[module_idx].state }
}

/// Read `finished[module_idx]`. Test-facing query for terminate /
/// done assertions.
pub fn module_finished(module_idx: usize) -> bool {
    if module_idx >= module_slots() {
        return false;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded.
    unsafe { SCHED.finished[module_idx] }
}

/// Mark a module as "deferred-ready". Deferred-ready modules step
/// freely even when their upstream peers haven't signaled `Ready` yet
/// — they need to run to reach Ready themselves (typical for
/// infrastructure like `linux_net` that sets `Ready` only after the
/// network is up).
pub fn set_module_deferred_ready(module_idx: usize, deferred: bool) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.deferred_ready[module_idx] = deferred;
    }
}

/// Set the upstream-readiness mask for a module. Each bit i in `mask`
/// means "this module depends on module i being Ready before it can
/// step". Used by loader manifest plumbing and by conformance tests
/// that exercise ready-signal gating without a real graph.
pub fn set_module_upstream_mask(module_idx: usize, mask: u64) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    // Loader manifest plumbing and conformance tests pass a u64 (≤64 modules);
    // the full-width path is built by `compute_upstream_mask`.
    unsafe {
        SCHED.upstream_mask[module_idx] = ModuleMask::from_u64(mask);
    }
}

/// Full-width variant of [`set_module_upstream_mask`]: set individual
/// upstream bits, including indices ≥ 64. Test-facing (like
/// `clear_module_ready`) — production masks come from
/// `compute_upstream_mask`.
pub fn set_module_upstream_bits(module_idx: usize, bits: &[usize]) {
    if module_idx >= module_slots() {
        return;
    }
    let mut mask = ModuleMask::new();
    for &b in bits {
        if b < module_slots() {
            mask.set(b);
        }
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.upstream_mask[module_idx] = mask;
    }
}

/// Clear the per-module ready bit. Test-facing helper so a fresh
/// graph can be wired into a state where downstream modules are
/// gated waiting on a not-yet-Ready upstream.
pub fn clear_module_ready(module_idx: usize) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.ready[module_idx] = false;
    }
}

/// Read the per-module ready bit.
pub fn module_is_ready(module_idx: usize) -> bool {
    if module_idx >= module_slots() {
        return false;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded.
    unsafe { SCHED.ready[module_idx] }
}

/// Snapshot of a single module's scheduler-visible state. Used by
/// diagnostics
/// and by operator-facing introspection.
#[derive(Debug, Clone, Copy)]
pub struct ModuleStateSnapshot {
    /// Module slot index in the scheduler's `modules` array.
    pub idx: ModuleId,
    /// `true` if the module's slot is non-empty in the scheduler.
    pub present: bool,
    /// Whether the module has signaled `StepOutcome::Ready`.
    pub ready: bool,
    /// Whether the module has finalised (`Done` / terminated).
    pub finished: bool,
    /// The module's grants: contracts, then op-level grants.
    pub grants: [u64; 2],
    /// Per-module fault state machine state.
    pub fault_state: FaultState,
    /// Step-period gate in scheduler ticks (0 = every tick, N = every
    /// N ticks). Wall-clock period is `step_period * domain_tick_us`.
    pub step_period: u8,
    /// Restart count to date.
    pub restart_count: u16,
    /// Domain the module is assigned to (0 = default).
    pub domain_id: u8,
    /// Consecutive ticks the readiness gate has been blocking this
    /// module from stepping. `0` after every successful step; non-zero
    /// indicates a dead upstream edge.
    pub inactive_for_ticks: u32,
    /// Whether the readiness gate has held this module for a whole report
    /// window and the kernel has logged it (`[ready] ... not stepped`).
    /// Clears when the hold ends.
    pub readiness_starved: bool,
    /// Per-slot generation. Bumped on graph reset, restart, and
    /// module replacement. Async consumers that snapshot telemetry
    /// must pair this with a later read of the same module — a
    /// mismatch means the slot was reused and the prior snapshot is
    /// stale.
    pub slot_generation: u32,
}

/// Build a `ModuleStateSnapshot` for `module_idx`. Returns a
/// `present: false` placeholder if the slot is empty or out of range
/// so callers can iterate `0..module_slots()` uniformly.
pub fn module_state_snapshot(module_idx: usize) -> ModuleStateSnapshot {
    if module_idx >= module_slots() {
        return ModuleStateSnapshot {
            idx: 0,
            present: false,
            ready: false,
            finished: false,
            grants: [0; 2],
            fault_state: FaultState::Running,
            step_period: 0,
            restart_count: 0,
            domain_id: 0,
            inactive_for_ticks: 0,
            readiness_starved: false,
            slot_generation: 0,
        };
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded above.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let present = !matches!(sched.modules[module_idx], ModuleSlot::Empty);
    ModuleStateSnapshot {
        idx: module_idx as ModuleId,
        present,
        ready: sched.ready[module_idx],
        finished: sched.finished[module_idx],
        grants: sched.grants[module_idx],
        fault_state: sched.fault_info[module_idx].state,
        step_period: sched.step_period[module_idx],
        restart_count: sched.fault_info[module_idx].restart_count,
        domain_id: sched.domain_id[module_idx],
        inactive_for_ticks: sched.inactive_for_ticks[module_idx],
        readiness_starved: sched.starvation_reported.test(module_idx),
        slot_generation: sched.slot_generation[module_idx],
    }
}

/// Lookup a channel port for the currently-executing module.
/// Called from the channel_port syscall implementation.
pub fn channel_port_lookup(port_type: u8, index: u8) -> i32 {
    let idx = index as usize;
    let cm = current_module_index();
    // Guard the "no module" sentinel (== MAX_MODULES): a live-added module can reach
    // a port lookup before CURRENT_MODULE_PER_CORE is set to its slot. Return -1
    // (port not resolvable yet) rather than index a fixed [_; MAX_MODULES] array OOB.
    if cm >= module_slots() {
        return -1;
    }
    // SAFETY: cm bounded above; scheduler-thread-only read.
    let ports = unsafe { &SCHED.ports[cm] };
    match port_type {
        0 => {
            if idx < ports.in_count as usize {
                ports.in_chans[idx]
            } else {
                -1
            }
        }
        1 => {
            if idx < ports.out_count as usize {
                ports.out_chans[idx]
            } else {
                -1
            }
        }
        2 => {
            if idx < ports.ctrl_count as usize {
                ports.ctrl_chans[idx]
            } else {
                -1
            }
        }
        _ => -1,
    }
}

/// The calling module's arena: its base and size, or `(null, 0)` when it
/// has none. The base stays the module's for as long as it is loaded.
pub fn arena_get() -> (*mut u8, u32) {
    let cm = current_module_index();
    // SAFETY: scheduler-thread read of the arena table.
    let Some(arena) = (unsafe { &*core::ptr::addr_of!(SCHED) })
        .arenas
        .get(cm)
        .copied()
    else {
        return (core::ptr::null_mut(), 0);
    };
    // An elastic heap's arena is its whole cap, committed at instantiation
    // for a module that declares raw arena use (`params_raw_arena`). One that
    // did not declare it gets none: committing here would zero memory on
    // whatever step asked.
    let (ptr, size) = if arena.ptr.is_null() && arena.size > 0 {
        match crate::kernel::mem::heap::committed_whole(cm) {
            Some((p, n)) => (p, n as u32),
            None => {
                log::warn!(
                    "[heap] module {cm}: ARENA_GET on a heap that declared no raw arena use \
                     (`heap.raw_arena` / `[capacities] raw_arena`); no arena"
                );
                (core::ptr::null_mut(), 0)
            }
        }
    } else {
        (arena.ptr, arena.size)
    };
    (ptr, size)
}

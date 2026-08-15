//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

// ============================================================================
// Module Instantiation
// ============================================================================

/// Internal module hashes (fnv1a32)
pub const INTERNAL_TEE_HASH: u32 = 0x607f045c; // "_tee"
pub const INTERNAL_MERGE_HASH: u32 = 0x8a6bcd3e; // "_merge"

/// Consumers registered here drain EVERY inbound edge to a data port as
/// its own channel (priority lanes: lane index = the edge's position in
/// the graph wiring), so `insert_fan_in` must NOT collapse their fan
/// groups into a single merged FIFO. A merge would serialise latency-
/// critical producers behind bulk ones in one queue — a web-stream
/// flood stalling Raft peer heartbeats past their election timeout.
/// Platforms register their multi-inbound built-ins before
/// `prepare_graph` (e.g. linux_net).
static mut MULTI_INBOUND_HASHES: [u32; 8] = [0; 8];

/// Register a module name-hash whose data inputs support one channel
/// per edge (see [`MULTI_INBOUND_HASHES`]). Call before `prepare_graph`.
pub fn register_multi_inbound(name_hash: u32) {
    // SAFETY: called single-threaded during platform bring-up, before
    // the scheduler starts stepping.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(MULTI_INBOUND_HASHES) };
    for slot in table.iter_mut() {
        if *slot == name_hash {
            return;
        }
        if *slot == 0 {
            *slot = name_hash;
            return;
        }
    }
    log::error!("[graph] multi-inbound table full; {name_hash:#x} not registered");
}

pub(crate) fn is_multi_inbound(name_hash: u32) -> bool {
    // SAFETY: read-only after bring-up registration.
    let table = unsafe { &*core::ptr::addr_of!(MULTI_INBOUND_HASHES) };
    table.iter().any(|&h| h != 0 && h == name_hash)
}

/// Build the dense module list from the validated config.
///
/// Fail-closed on every malformation:
///   * Modules with `id >= MAX_MODULES` → `Err(EINVAL)`.
///   * Duplicate ids → `Err(EINVAL)`.
///   * Modules exceeding the per-graph `MAX_MODULES` ceiling →
///     `Err(EINVAL)`.
///
/// The error code is the bare `i32` negative-errno that
/// `prepare_graph` already propagates.
type ModuleList = ([Option<ModuleEntry>; MAX_MODULES], usize, [i8; MAX_MODULES]);

pub(crate) fn build_module_list(config: &Config) -> Result<ModuleList, i32> {
    let mut module_list: [Option<ModuleEntry>; MAX_MODULES] = [None; MAX_MODULES];
    let mut id_to_slot: [i8; MAX_MODULES] = [-1; MAX_MODULES];
    let mut count = 0;

    for entry in config.modules.iter().flatten() {
        if count >= MAX_MODULES {
            log::error!("[graph] module count exceeds MAX_MODULES={MAX_MODULES} — graph rejected");
            return Err(crate::kernel::sys::errno::EINVAL);
        }

        let id = entry.id as usize;
        if id >= MAX_MODULES {
            log::error!(
                "[graph] module id={} out of range (MAX_MODULES={}) — graph rejected",
                entry.id,
                MAX_MODULES
            );
            return Err(crate::kernel::sys::errno::EINVAL);
        }

        if id_to_slot[id] >= 0 {
            log::error!("[graph] duplicate module id={} — graph rejected", entry.id);
            return Err(crate::kernel::sys::errno::EINVAL);
        }

        id_to_slot[id] = count as i8;
        module_list[count] = Some(*entry);
        count += 1;
    }

    Ok((module_list, count, id_to_slot))
}

/// Query channel hints for all modules in the list.
///
/// For each module, looks up its `module_channel_hints` export and
/// stores the hints in MODULE_HINTS. Modules without the export
/// get empty hints (all ports use default buffer sizes).
/// Pre-pass: set `SCHED.isolated[i]` for every module whose config params
/// request `protection: isolated` (TLV tag 0xF5 >= 2), BEFORE channels are
/// opened. This lets `open_channels`/`alloc_streaming_for_module` page-align an
/// isolated producer's channel buffers and the channel-region pass round its
/// region to whole pages. The full protection TLV (fault policy, deadlines, …)
/// is still parsed at instantiation via `parse_protection_config`; this only
/// peeks the isolation bit. No-op off BCM2712 (EL0 isolation is BCM2712-only,
/// but the flag itself is platform-agnostic — `module_is_isolated` callers gate
/// on the chip feature).
pub(crate) fn mark_isolated_from_params(
    module_list: &[Option<ModuleEntry>; MAX_MODULES],
    module_count: usize,
) {
    for (module_idx, slot) in module_list.iter().enumerate().take(module_count) {
        let entry = match slot {
            Some(e) => e,
            None => continue,
        };
        if is_internal_module(entry) {
            continue;
        }
        if !params_request_isolation(entry.params()) {
            continue;
        }
        // SAFETY: prepare_graph context — single mutator of SCHED.
        unsafe {
            let p = &raw mut SCHED;
            (*p).isolated[module_idx] = true;
        }
        crate::kernel::sys::hal::protection_set_enabled(true);
    }
}

pub(crate) fn collect_module_hints(
    loader: &ModuleLoader,
    module_list: &[Option<ModuleEntry>; MAX_MODULES],
    module_count: usize,
) {
    // SAFETY: prepare_graph context — single mutator of SCHED.
    let module_hints = unsafe {
        let p = &raw mut SCHED;
        &mut (*p).hints
    };

    for module_idx in 0..module_count {
        let entry = match &module_list[module_idx] {
            Some(e) => e,
            None => continue,
        };

        // Skip internal modules (tee, merge) — they have no hints export
        if is_internal_module(entry) {
            continue;
        }

        // Find the module in flash
        let loaded = match loader.find_by_name_hash(entry.name_hash) {
            Ok(m) => m,
            Err(_) => continue, // Will be caught during instantiation
        };

        // Validate integrity/signature BEFORE invoking any of the module's own
        // code. `query_channel_hints` below calls the module's
        // `module_channel_hints` export; without this gate unverified native
        // code runs before admission, because the signature/integrity check in
        // `start_new` only happens later, at instantiation. A module that fails
        // here is skipped now (its code never runs) and is hard-rejected when
        // instantiation re-validates it.
        if crate::kernel::module::loader::validate_module(&loaded, "hints").is_err() {
            continue;
        }

        // Extract mailbox_safe / in_place_writer flags early so open_channels
        // can use them for buffer-group aliasing decisions.
        let flags_byte = loaded.header.reserved[0];
        // SAFETY: prepare_graph context — single mutator.
        unsafe {
            let p = &raw mut SCHED;
            let sched = &mut *p;
            sched.mailbox_safe[module_idx] = (flags_byte & 0x01) != 0;
            sched.in_place_writer[module_idx] = (flags_byte & 0x02) != 0;
        }

        // Static manifest capacities (flag-bit-5 section): no module
        // code executes, and wasm payloads (whose packed export
        // tables are empty) are covered.
        let (hints, count) = loaded.manifest_port_capacities();
        if count > 0 {
            module_hints[module_idx].hints = hints;
            module_hints[module_idx].count = count;
        }
    }
}

pub(crate) fn push_internal_module(
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
    name_hash: u32,
    domain_id: u8,
    frame_kind: u8,
) -> Option<usize> {
    if *module_count >= MAX_MODULES
        || !crate::kernel::sys::resource_ledger::enforced_allows(
            crate::abi::contracts::resource::POOL_MODULE_SLOTS,
            *module_count as u32 + 1,
        )
    {
        log::error!("No room for internal module");
        crate::kernel::sys::resource_ledger::deny(
            crate::abi::contracts::resource::POOL_MODULE_SLOTS,
        );
        return None;
    }

    let idx = *module_count;
    module_list[idx] = Some(ModuleEntry {
        name_hash,
        id: idx as u8,
        domain_id,
        pre_tick_drain: false,
        frame_kind,
        params_ptr: core::ptr::null(),
        params_len: 0,
    });
    // Mirror the domain assignment into SCHED so the per-domain
    // exec-order partitioner sees the inserted slot.
    if idx < MAX_MODULES {
        // SAFETY: prepare_graph context — single mutator; idx bounded.
        let sched = unsafe {
            let p = &raw mut SCHED;
            &mut *p
        };
        sched.domain_id[idx] = domain_id;
    }
    *module_count += 1;
    Some(idx)
}

pub(crate) fn is_internal_module(entry: &ModuleEntry) -> bool {
    entry.name_hash == INTERNAL_TEE_HASH || entry.name_hash == INTERNAL_MERGE_HASH
}

/// Direction for fan-in/fan-out insertion
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FanDirection {
    Out,
    In,
}

/// Finalize a module after it reports done or error.
///
/// Sets POLL_HUP (done) or POLL_ERR (error) on all output channels,
/// releases owned handles, and marks the module finished.
/// `error_code`: None = module done normally, Some(rc) = error with return code.
pub(crate) fn finalize_module(
    module_idx: usize,
    error_code: Option<i32>,
    type_name: &str,
    context: &str,
) {
    // SAFETY: scheduler-thread context (called from step_modules teardown).
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    let flag = if error_code.is_some() {
        POLL_ERR as u8
    } else {
        POLL_HUP as u8
    }; // u8: sticky_events is AtomicU8
    if let Some(rc) = error_code {
        log::warn!("[sched] module {module_idx} ({type_name}) error rc={rc}{context}");
    } else {
        log::info!("[sched] module {module_idx} ({type_name}) done{context}");
    }

    let ports = &sched.ports[module_idx];
    let mut p = 0;
    while p < ports.out_count as usize {
        if ports.out_chans[p] >= 0 {
            channel_set_flags(ports.out_chans[p], flag);
        }
        p += 1;
    }
    syscalls::release_module_handles(module_idx as u8);
    sched.finished[module_idx] = true;
}

#[no_mangle]
pub static mut DBG_TICK: u32 = 0;

/// Rate-limit for the per-step budget monitors (`MON_HEAVY_STEP`,
/// `MON_BUDGET_OVERRUN`, `MON_BURST_BUDGET_ABORT`). On a coarse-timer host
/// these are meaningless per-step: the browser's `now_micros` floor is
/// ~1–2 ms, far above the 50 µs heavy threshold and the ~1 ms domain
/// budget, so every step trips all three and drowns the log (tens of
/// thousands of lines/sec). Emit at most one line per monitor per
/// `MON_LOG_THROTTLE_TICKS`, carrying the number suppressed since the last
/// line — a genuine (rare) native overrun is still surfaced, while the
/// wasm flood collapses to a periodic summary. Monitoring/counters are
/// unaffected; only the log emission is throttled.
const MON_LOG_THROTTLE_TICKS: u32 = 2000;
pub(crate) static mut MON_HEAVY_LAST: u32 = 0;
pub(crate) static mut MON_HEAVY_SUP: u32 = 0;
pub(crate) static mut MON_OVERRUN_LAST: u32 = 0;
pub(crate) static mut MON_OVERRUN_SUP: u32 = 0;
pub(crate) static mut MON_BURST_LAST: u32 = 0;
pub(crate) static mut MON_BURST_SUP: u32 = 0;
pub(crate) static mut MON_WAKE_DEFER_LAST: u32 = 0;
pub(crate) static mut MON_WAKE_DEFER_SUP: u32 = 0;
pub(crate) static mut MON_HOTSTART_LAST: u32 = 0;
pub(crate) static mut MON_HOTSTART_SUP: u32 = 0;

/// Returns `Some(suppressed_since_last)` when the throttle window has
/// elapsed (and opens a new window); else `None`, bumping the suppressed
/// counter. Raw pointers (not `&mut` to statics) keep clear of the
/// `static_mut_refs` lint; scheduler-thread only, so no races.
#[inline]
pub(crate) unsafe fn mon_throttle(last: *mut u32, sup: *mut u32) -> Option<u32> {
    let now = DBG_TICK;
    if now.wrapping_sub(*last) >= MON_LOG_THROTTLE_TICKS {
        let n = *sup;
        *sup = 0;
        *last = now;
        Some(n)
    } else {
        *sup = (*sup).wrapping_add(1);
        None
    }
}

/// Current tick count (milliseconds since boot). Used by timer FDs on aarch64.
pub fn tick_count() -> u32 {
    // SAFETY: DBG_TICK is a u32 static; aligned read.
    unsafe { DBG_TICK }
}

/// Wallclock-paced scheduler heartbeat. Platforms call this once per
/// tick from their outer loop; this is the single canonical emit
/// point for `[sched] alive` across linux / wasm / rp / bcm — the
/// per-platform and step_modules-internal copies that used to live
/// here have all been collapsed into this function.
///
/// Cadence: every 30 wallclock seconds at the active `tick_us` for
/// the given domain (or the global `tick_us` for the default domain
/// / single-domain platforms). `hal::now_millis()` provides the
/// `elapsed_ms` suffix — every supported platform's HAL implements
/// it.
///
/// `domain_id == None` is the flat / single-domain case (linux,
/// wasm, rp, qemu): no `domain=` field is emitted. `Some(d)` is the
/// multi-domain case (bcm2712): the field is appended so per-core
/// logs are distinguishable.
pub fn maybe_emit_alive(tick: u64, domain_id: Option<usize>) {
    if tick == 0 {
        return;
    }
    let di = domain_id.unwrap_or(0).min(MAX_DOMAINS - 1);
    // Flow-stall sampling piggybacks on the same canonical per-tick
    // entry point (default domain only — one sampler pass per tick).
    if di == 0 {
        sample_flow_stalls();
        sample_pstatus();
    }
    let ms = crate::kernel::sys::hal::now_millis();
    // Wall-clock cadence (~30 s), driven by `now_millis()` rather than a
    // `30_000_000 / tick_us` tick-count threshold. The tick-count form silently
    // mis-scales the moment mechanism (b) varies the period away from 1 ms, and
    // stalls entirely when mechanism (a) idle-sleep stops advancing the tick —
    // so the heartbeat would no longer be ~30 s. Diagnostic-cadence class:
    // best-effort, no correctness impact (RFC adaptive_tick §7.6).
    // `LAST_ALIVE_MS` is 0 at boot, so the first heartbeat lands ~30 s in,
    // matching the previous tick-count behaviour.
    let last = LAST_ALIVE_MS[di].load(Ordering::Relaxed);
    if ms.wrapping_sub(last) < ALIVE_INTERVAL_MS {
        return;
    }
    LAST_ALIVE_MS[di].store(ms, Ordering::Relaxed);
    match domain_id {
        Some(d) => log::info!("[sched] alive t={tick} elapsed_ms={ms} domain={d}"),
        None => log::info!("[sched] alive t={tick} elapsed_ms={ms}"),
    }
}

/// Flow-stall detector. Samples every classed (audio+) edge's ring
/// fill on a ~2 s wall-clock cadence from the scheduler loop; a ring
/// holding the SAME non-zero fill across consecutive samples is a
/// frozen hop. Emits `MON_FLOW_STALL` at the threshold and every 32
/// samples while stalled; clearing logs `MON_FLOW_RESUME` once so
/// log readers see the episode close.
pub fn sample_flow_stalls() {
    const FLOW_SAMPLE_INTERVAL_MS: u64 = 2_000;
    /// Consecutive unchanged samples before the first log (~8 s).
    const STALL_THRESHOLD: u8 = 4;
    let ms = crate::kernel::sys::hal::now_millis();
    let last = LAST_FLOW_SAMPLE_MS.load(Ordering::Relaxed);
    if ms.wrapping_sub(last) < FLOW_SAMPLE_INTERVAL_MS {
        return;
    }
    LAST_FLOW_SAMPLE_MS.store(ms, Ordering::Relaxed);
    // SAFETY: called from the scheduler loop — single mutator of SCHED.
    unsafe {
        let p = &raw mut SCHED;
        let sched = &mut *p;
        for i in 0..sched.edge_count.min(MAX_CHANNELS) {
            let e = &sched.edges[i];
            if e.rate_class == 0 || e.channel < 0 {
                continue;
            }
            let fill = crate::kernel::ipc::channel::channel_readable_bytes(e.channel) as u32;
            if fill > 0 && fill == sched.flow_last_fill[i] {
                let stalls = sched.flow_stalls[i].saturating_add(1);
                sched.flow_stalls[i] = stalls;
                if stalls == STALL_THRESHOLD
                    || (stalls > STALL_THRESHOLD && stalls.is_multiple_of(32))
                {
                    log::warn!(
                        "MON_FLOW_STALL edge={} from={} port={} class={} fill={} stalled_s={}",
                        i,
                        e.from_module,
                        e.from_port_index,
                        e.rate_class,
                        fill,
                        (stalls as u64) * FLOW_SAMPLE_INTERVAL_MS / 1000,
                    );
                }
            } else {
                if sched.flow_stalls[i] >= STALL_THRESHOLD {
                    log::info!(
                        "MON_FLOW_RESUME edge={} from={} after_s={}",
                        i,
                        e.from_module,
                        (sched.flow_stalls[i] as u64) * FLOW_SAMPLE_INTERVAL_MS / 1000,
                    );
                }
                sched.flow_stalls[i] = 0;
            }
            sched.flow_last_fill[i] = fill;
        }
    }
}

static LAST_FLOW_SAMPLE_MS: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);

/// Wall-clock timestamp (ms) of the last PSTATUS cadence round.
static LAST_PSTATUS_MS: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);
/// PSTATUS cadence interval (ms); a subscriber declares its own via the
/// `TLM_SUBSCRIBE` interval field (§5.3). Default matches the observe/monitor
/// console cadence.
static PSTATUS_INTERVAL_MS: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(5_000);

/// Set the PSTATUS cadence interval, as declared by a `TLM_SUBSCRIBE` caller
/// (§5.3). `0` leaves the default in place.
pub fn set_pstatus_interval_ms(ms: u64) {
    if ms != 0 {
        PSTATUS_INTERVAL_MS.store(ms, Ordering::Relaxed);
    }
}

/// Push one round of kernel-produced PSTATUS records to the telemetry ring: a
/// `STEP` (step count + step-time histogram — the `MON_HIST` source) and a `RES`
/// (arena + fault state) per active module, kernel-stamped with that module's
/// identity (`rfc_observability_surface.md` §5.3). No-op unless a ring consumer
/// is subscribed (`is_enabled()` — one relaxed load), so the default path is
/// free. Called once per tick on the default domain from `maybe_emit_alive`;
/// its own wall-clock cadence gates the actual emit.
pub fn sample_pstatus() {
    use crate::abi::contracts::telemetry as tlm;
    // Cheap gate: nothing subscribed → build/emit nothing.
    if !crate::kernel::sys::telemetry_ring::is_enabled() {
        return;
    }
    let ms = crate::kernel::sys::hal::now_millis();
    let last = LAST_PSTATUS_MS.load(Ordering::Relaxed);
    if ms.wrapping_sub(last) < PSTATUS_INTERVAL_MS.load(Ordering::Relaxed) {
        return;
    }
    LAST_PSTATUS_MS.store(ms, Ordering::Relaxed);
    let t = crate::kernel::sys::hal::now_micros();

    // SAFETY: called from the scheduler loop — single reader of SCHED here.
    unsafe {
        let p = &raw const SCHED;
        let sched = &*p;
        for i in 0..MAX_MODULES {
            if matches!(sched.modules[i], ModuleSlot::Empty) {
                continue;
            }
            let buckets = sched.step_hist[i];
            let mut step_count: u64 = 0;
            for b in &buckets {
                step_count = step_count.wrapping_add(*b as u64);
            }
            let mut step = [0u8; tlm::PSTATUS_STEP_SIZE];
            if let Some(n) = tlm::write_pstatus_step(&mut step, i as u16, t, step_count, &buckets) {
                crate::kernel::sys::telemetry_ring::emit(i as u16, &step[..n]);
            }

            let hs = crate::kernel::mem::heap::heap_stats(i);
            let fs = get_fault_stats(i);
            let mut res = [0u8; tlm::PSTATUS_RES_SIZE];
            if let Some(n) = tlm::write_pstatus_res(
                &mut res,
                i as u16,
                t,
                hs.allocated,
                hs.arena_size,
                fs.fault_count as u32,
                fs.current_state as u32,
            ) {
                crate::kernel::sys::telemetry_ring::emit(i as u16, &res[..n]);
            }
        }
    }

    // One `POOL` record per kernel resource pool, kernel-stamped — the
    // ledger's cadence surface (`rfc_resource_model.md` §6.1).
    crate::kernel::sys::resource_ledger::emit_all(t);
}

/// Per-domain wall-clock timestamp (ms) of the last `[sched] alive` heartbeat,
/// so the cadence is driven by `now_millis()` instead of a tick count that
/// mis-scales under variable/idle pacing (RFC adaptive_tick §7.6).
static LAST_ALIVE_MS: [portable_atomic::AtomicU64; MAX_DOMAINS] =
    [const { portable_atomic::AtomicU64::new(0) }; MAX_DOMAINS];
/// Wall-clock heartbeat interval for `maybe_emit_alive` (~30 s).
const ALIVE_INTERVAL_MS: u64 = 30_000;
/// Last module index attempted before a crash — readable by HardFault handler
#[no_mangle]
pub static mut DBG_STEP_MODULE: u8 = 0xFF;

/// Crash data buffer in .uninit section — NOT zeroed by cortex-m-rt startup,
/// survives SYSRESETREQ software resets. Written by HardFault handler, read at tick 500.
/// Layout: [0]=magic, [1]=PC, [2]=LR, [3]=module, [4]=tick, [5]=R0
#[link_section = ".uninit.CRASH_DATA"]
#[no_mangle]
pub static mut CRASH_DATA: core::mem::MaybeUninit<[u32; 8]> = core::mem::MaybeUninit::uninit();

/// Magic marker for valid crash data
pub const CRASH_MAGIC: u32 = 0xDEAD_BEEF;

/// One-shot latch for the post-boot crash-info read (`step_modules`). Set once
/// per boot so the prior-run `.uninit CRASH_DATA` is read exactly once, gated on
/// a wall-clock delay rather than a `30_000_000 / tick_us` tick threshold that
/// mis-scales / can be skipped under variable or idle pacing (RFC adaptive_tick
/// §7.6, one-shot-correctness class).
pub(crate) static CRASH_CHECKED: AtomicBool = AtomicBool::new(false);
/// Wall-clock delay after boot before the crash-info read (USB serial up).
pub(crate) const CRASH_CHECK_DELAY_MS: u64 = 30_000;

/// Whether module `idx` requested `protection: isolated` (TLV 0xF5 == 2).
/// Read by the graph-prepare pass to decide which modules get an EL0
/// page table, and by the loader to flag the `DynamicModule` so its
/// step routes through `mmu::protected_step`. Non-isolated modules keep
/// the direct EL1 call path unchanged.
pub fn module_is_isolated(idx: usize) -> bool {
    if idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: scheduler-thread-only read of a bool array; `idx` bounded.
    unsafe { SCHED.isolated[idx] }
}

/// Peek a module's params TLV for a `protection: isolated` request (tag
/// 0xF5, value >= 2) WITHOUT mutating any scheduler state. The loader calls
/// this before allocating state so it can route an isolated module's state and
/// heap into the dedicated page-aligned ISO arena (the EL0 mapping rounds to
/// pages, so isolated allocations must own their pages — see
/// `loader::alloc_isolated`). Mirrors the tag walk in `parse_protection_config`.
pub fn params_request_isolation(params: &[u8]) -> bool {
    if params.len() < 4 {
        return false;
    }
    let mut pos = if params[0] == 0xFE { 4 } else { 0 };
    while pos + 2 <= params.len() {
        let tag = params[pos];
        let len = params[pos + 1] as usize;
        pos += 2;
        if tag == 0xFF {
            break;
        }
        if pos + len > params.len() {
            break;
        }
        if tag == 0xF5 && len == 1 && params[pos] >= 2 {
            return true;
        }
        pos += len;
    }
    false
}

/// Parse protection configuration from module params TLV.
///
/// Recognised tags in the schema-packed params blob:
/// - 0xF0: step_deadline_us (u32 LE)
/// - 0xF1: fault_policy (u8: 0=skip, 1=restart, 2=restart_graph)
/// - 0xF2: max_restarts (u16 LE)
/// - 0xF3: restart_backoff_ms (u16 LE)
/// - 0xF4: trust_tier (u8)
/// - 0xF5: protection (u8)
/// - 0xF6: step_deadline_burst_us (u32 LE)
/// - 0xF7: quarantine_partner (u8 module index, 0xFF = none)
/// - 0xF8: heap_zero_on_free (u8 bool)
/// - 0xF9: heap_fault_on_alloc_failure (u8 bool)
/// - 0xFA: heap_canary_enabled (u8 bool)
pub fn parse_protection_config(module_idx: usize, params: &[u8]) {
    if params.len() < 4 {
        return;
    }

    // TLV format: [0xFE, ver, len_lo, len_hi, ...entries..., 0xFF, 0x00].
    // Each entry: tag(1), len(1), value(len). The header layout (magic,
    // version, u16 len) is stable across versions; only the version
    // byte's meaning is informational, so any version is accepted here.
    let mut pos = 0;
    if params.len() >= 4 && params[0] == 0xFE {
        pos = 4; // Skip header (magic, version, length)
    }

    // SAFETY: parse_protection_config runs during instantiation —
    // scheduler-thread, no concurrent reader on this module's slot.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    let fi = &mut sched.fault_info[module_idx];

    while pos + 2 <= params.len() {
        let tag = params[pos];
        let len = params[pos + 1] as usize;
        pos += 2;

        if tag == 0xFF {
            break; // End-of-params marker
        }

        if pos + len > params.len() {
            break;
        }

        match tag {
            0xF0 if len == 4 => {
                // step_deadline_us (u32 LE)
                let val = u32::from_le_bytes([
                    params[pos],
                    params[pos + 1],
                    params[pos + 2],
                    params[pos + 3],
                ]);
                fi.step_deadline_us = val;
            }
            0xF1 if len >= 1 => {
                // fault_policy
                fi.policy = match params[pos] {
                    0 => FaultPolicy::Skip,
                    1 => FaultPolicy::Restart,
                    2 => FaultPolicy::RestartGraph,
                    _ => FaultPolicy::Skip,
                };
            }
            0xF2 if len == 2 => {
                // max_restarts (u16 LE)
                fi.max_restarts = u16::from_le_bytes([params[pos], params[pos + 1]]);
            }
            0xF3 if len == 2 => {
                // restart_backoff_ms (u16 LE)
                fi.restart_backoff_ms = u16::from_le_bytes([params[pos], params[pos + 1]]);
            }
            0xF4 if len == 1 => {
                // trust_tier: 0=platform, 1=verified, 2=community, 3=unsigned.
                // Signature verification happens in the loader; this tag only
                // surfaces the outcome for telemetry.
                if params[pos] == 3 {
                    log::warn!("[trust] module {module_idx} is unsigned");
                }
            }
            0xF5 if len == 1 => {
                // protection: 0=none, 1=guarded, 2=isolated.
                // An isolated module opts the whole graph into MPU/MMU
                // isolation; per-module regions are registered during
                // instantiation and the page table is built before the
                // first step (see `build_isolated_tables`).
                if params[pos] >= 2 {
                    crate::kernel::sys::hal::protection_set_enabled(true);
                    sched.isolated[module_idx] = true;
                    // On Pi 5 (BCM2712), enable the EL0 MMU-isolation regime so
                    // `mmu::protected_step` drops the module to EL0. No-op on
                    // other platforms (the Cortex-M MPU path above stands in).
                }
            }
            0xF6 if len == 4 => {
                // step_deadline_burst_us (u32 LE)
                let val = u32::from_le_bytes([
                    params[pos],
                    params[pos + 1],
                    params[pos + 2],
                    params[pos + 3],
                ]);
                fi.step_deadline_burst_us = val;
            }
            0xF7 if len == 1 => {
                // quarantine_partner (u8 module index, 0xFF = none)
                fi.quarantine_partner = params[pos];
            }
            0xF8 if len == 1 => {
                // heap.zero_on_free (u8 bool). Heap setter touches
                // MODULE_HEAPS, not SCHED.fault_info, so no borrow
                // conflict with `fi`.
                crate::kernel::mem::heap::set_zero_on_free(module_idx, params[pos] != 0);
            }
            0xF9 if len == 1 => {
                // heap.alloc_failure_policy (u8 bool: false=null, true=fault)
                crate::kernel::mem::heap::set_fault_on_alloc_failure(module_idx, params[pos] != 0);
            }
            0xFA if len == 1 => {
                // heap.canary_enabled (u8 bool)
                crate::kernel::mem::heap::set_canary_enabled(module_idx, params[pos] != 0);
            }
            0xFB if len == 4 => {
                // isr_budget_cycles (u32 LE). Per-module Tier 1b/2
                // cycle budget; `0` falls back to
                // `DEFAULT_ISR_BUDGET_CYCLES`. Set BEFORE the
                // post-instantiation `register_isr_tier_modules_from_graph`
                // helper reads it (parse_protection_config runs
                // per-module right after `module_new`).
                let val = u32::from_le_bytes([
                    params[pos],
                    params[pos + 1],
                    params[pos + 2],
                    params[pos + 3],
                ]);
                set_module_isr_budget_cycles(module_idx, val);
            }
            0xFC if len == 2 => {
                // irq (u16 LE). Per-module hardware IRQ for Tier 2
                // admission. The admission helper later passes this
                // to `register_tier2_module`.
                let val = u16::from_le_bytes([params[pos], params[pos + 1]]);
                set_module_irq(module_idx, val);
            }
            _ => {}
        }

        pos += len;
    }
}

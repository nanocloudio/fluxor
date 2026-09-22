//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`). The step loop and per-module fault handling (quarantine/restart).
use super::*;

/// Drain-timeout enforcement, shared by `step_modules` and
/// `step_domain_modules`. Returns `true` if the timeout fired and the
/// caller should bail out of its iteration with `StepResult::Done`.
///
/// Walks every active module through `finalize_module` so the
/// downstream POLL_ERR/POLL_HUP signalling, the
/// `release_module_handles` syscall path, and the
/// `mark_module_finished` invariant all fire. Setting
/// `fault_info[i].state = Terminated` and `finished[i] = true`
/// directly is not equivalent: it leaves consumers blocked on closed
/// channels and leaks owned handles.
pub(crate) fn enforce_drain_timeout(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    count: usize,
) -> bool {
    if sched.reconfigure_phase != ReconfigurePhase::Draining {
        return false;
    }
    let start = sched.drain_started_ms;
    // Wall-clock ceiling: a tick-counted `MAX_DRAIN_TICKS` would no
    // longer mean 30 s once mechanism (b) varies the period, and a hung
    // module under mechanism (a) freezes the tick so the ceiling could
    // never fire.
    let now_ms = crate::kernel::sys::hal::now_millis();
    if start == u64::MAX || now_ms.wrapping_sub(start) <= MAX_DRAIN_MS {
        return false;
    }
    let surviving = (0..count).filter(|i| !sched.finished[*i]).count();
    log::warn!(
        "MON_DRAIN_FORCED ms_elapsed={} ceiling_ms={} — force-terminating \
         {} still-running modules",
        now_ms.wrapping_sub(start),
        MAX_DRAIN_MS,
        surviving,
    );
    // Indexed loop — body touches `sched.finished[i]`, `sched.fault_info[i]`,
    // and `modules[i]` together; an iterator over one array can't reach
    // the parallel state on the others.
    #[expect(
        clippy::needless_range_loop,
        reason = "iteration over indices avoids borrow conflicts on the collection"
    )]
    for i in 0..count {
        if !sched.finished[i] {
            sched.fault_info[i].state = FaultState::Terminated;
            let name = modules[i].type_name();
            finalize_module(i, Some(-110), name, " (drain timeout)");
        }
    }
    sched.reconfigure_phase = ReconfigurePhase::Running;
    sched.drain_started_ms = u64::MAX;
    true
}

/// Cascade-origin lookup. Walk the faulted module's
/// `upstream_mask` and find the most-recent upstream that itself
/// faulted within `CASCADE_WINDOW_TICKS` of the current tick. Returns
/// `0xFF` if no cascade detected — the fault was independent (or its
/// upstream was healthy). A "cascade" is loosely defined: 4 ticks is
/// tight enough to ignore unrelated faults, wide enough that an
/// upstream→downstream pipeline (rarely more than 1-2 ticks apart)
/// is captured.
const CASCADE_WINDOW_TICKS: u32 = 4;

pub(crate) fn detect_caused_by(sched: &SchedulerState, module_idx: usize, tick: u32) -> u8 {
    let mask = sched.upstream_mask[module_idx];
    if mask.is_empty() {
        return 0xFF;
    }
    let mut best: u8 = 0xFF;
    let mut best_elapsed: u32 = CASCADE_WINDOW_TICKS + 1;
    for i in mask.iter_set() {
        let fi = &sched.fault_info[i];
        if fi.fault_count == 0 {
            continue;
        }
        let elapsed = tick.wrapping_sub(fi.last_fault_tick);
        if elapsed <= CASCADE_WINDOW_TICKS && elapsed < best_elapsed {
            best = i as u8;
            best_elapsed = elapsed;
        }
    }
    best
}

/// content_type of the module's last consumed input. Currently
/// returns `0` (unknown) for every module — implementation deferred
/// pending a per-channel content_type cache (`channel_content_type:
/// [u8; MAX_CHANNELS]`) populated at edge-wire time and read on each
/// `channel::channel_read`.
///
/// The wire byte at `FaultRecord.byte 3` is reserved so the
/// FaultRecord layout doesn't change when the cache lands. See the
/// doc comment on `FaultRecord` for the consumer-side contract.
pub(crate) fn last_input_content_type(_module_idx: usize) -> u8 {
    // TODO: wire to `SCHED.last_input_ct[module_idx]` once the
    // per-channel content_type cache is in place. The cache is
    // populated during prepare_graph (after the destination port
    // → content_type lookup is resolved from each module's
    // manifest) and read by `channel::channel_read` to update
    // `SCHED.last_input_ct[current_module] = channel_content_type[handle]`.
    0
}

/// Check whether a freshly-faulted module declares a paired partner
/// that ALSO faulted within `QUARANTINE_WINDOW_MS`. If so,
/// terminate both — the pair is bound by a shared invariant (TLS
/// handshake pair, codec pair-stream) that's broken once half goes
/// down. Skip if either side has already been finalised; idempotent.
///
/// Called from each `handle_step_*` fault handler AFTER it has set
/// the faulted-module's `state` and `last_fault_tick`. Pair-terminate
/// transitions the partner to `Terminated` regardless of its own
/// `FaultPolicy::Restart` — quarantine is a graph-level decision that
/// outranks individual-module recovery.
pub(crate) fn apply_quarantine(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
    active_count: &mut usize,
) {
    // Wall-clock window decision: a tick-counted window
    // re-scales under variable pacing and stalls under idle-sleep, so
    // the co-incidence test reads `last_fault_ms` against `now_millis()`.
    let now_ms = crate::kernel::sys::hal::now_millis();
    // Collect every module to quarantine — both the freshly-faulted
    // module's declared partner AND any already-faulted module that
    // named THIS module as its partner. The reverse-scan catches
    // unreciprocated declarations (A → B without B → A) when A
    // faulted first and B faulted later.
    let mut targets: [bool; MAX_MODULES] = [false; MAX_MODULES];

    // Forward: this module's declared partner (if any, and that
    // partner itself has a recent fault).
    let forward = sched.fault_info[module_idx].quarantine_partner as usize;
    if forward < MAX_MODULES
        && forward != module_idx
        && !sched.finished[forward]
        && sched.fault_info[forward].fault_count > 0
        && now_ms.wrapping_sub(sched.fault_info[forward].last_fault_ms) <= QUARANTINE_WINDOW_MS
    {
        targets[forward] = true;
    }

    // Reverse: any module that declared THIS module as its
    // partner AND has itself faulted within the window. Walks
    // every fault_info slot once — MAX_MODULES is small (64), so
    // the per-fault cost is bounded. Indexed loop because the body
    // reads from `sched.finished` and `sched.fault_info` and writes
    // to `targets` — three parallel arrays keyed by module index.
    #[expect(
        clippy::needless_range_loop,
        reason = "iteration over indices avoids borrow conflicts on the collection"
    )]
    for i in 0..MAX_MODULES {
        if i == module_idx || sched.finished[i] {
            continue;
        }
        if sched.fault_info[i].quarantine_partner as usize != module_idx {
            continue;
        }
        if sched.fault_info[i].fault_count == 0 {
            continue;
        }
        if now_ms.wrapping_sub(sched.fault_info[i].last_fault_ms) <= QUARANTINE_WINDOW_MS {
            targets[i] = true;
        }
    }

    // Nothing to quarantine? Exit silently. Quarantine fires only
    // when at least one partnered module is co-faulted.
    if !targets.iter().any(|t| *t) {
        return;
    }

    // Always include the self module in the termination set so
    // operators see the pair (or set) terminated together. If
    // self is already finished (Skip already finalised it), the
    // loop below silently skips.
    // Count targets for the log line — no Vec to avoid pulling in
    // `alloc` from kernel-side code (which is no_std).
    let target_count = targets.iter().filter(|t| **t).count();
    log::warn!(
        "MON_QUARANTINE module={module_idx} partner_count={target_count} now_ms={now_ms} window_ms={QUARANTINE_WINDOW_MS}",
    );

    // Terminate self first, then every named target. Use a tiny
    // closure to avoid duplicating the body.
    let mut term = |idx: usize| {
        if idx < MAX_MODULES && !sched.finished[idx] {
            sched.fault_info[idx].state = FaultState::Terminated;
            finalize_module(idx, Some(-111), modules[idx].type_name(), " (quarantined)");
            *active_count -= 1;
        }
    };
    term(module_idx);
    #[expect(
        clippy::needless_range_loop,
        reason = "iteration over indices avoids borrow conflicts on the collection"
    )]
    for i in 0..MAX_MODULES {
        if targets[i] {
            term(i);
        }
    }
}

/// Handle a step timeout: record fault, transition to Faulted or Terminated.
pub(crate) fn handle_step_timeout(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
    active_count: &mut usize,
) {
    // SAFETY: DBG_TICK is a u32 static; aligned read.
    let tick = unsafe { DBG_TICK };
    // Capture cascade + last-input bytes BEFORE taking the mutable
    // borrow on fault_info — both helpers read sched immutably and
    // would conflict with the `&mut fi` borrow below.
    let caused_by = detect_caused_by(sched, module_idx, tick);
    let last_input_ct = last_input_content_type(module_idx);
    let fi = &mut sched.fault_info[module_idx];
    fi.record_fault(fault_type::TIMEOUT, tick);
    log::warn!(
        "[guard] module {} ({}) step timeout (fault #{})",
        module_idx,
        modules[module_idx].type_name(),
        fi.fault_count
    );
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as u8,
        fault_kind: fault_type::TIMEOUT,
        caused_by,
        last_input_ct,
        tick,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });

    if fi.policy == FaultPolicy::Tolerate {
        // Recorded above (fault counter, [guard] warn, fault ring) —
        // and that is ALL. The module keeps running: a storage step
        // stalled behind a device cache flush is late work, not a
        // runaway, and faulting it would take the graph down for
        // latency the module does not control. Quarantine pairing is
        // skipped too — a tolerated overrun must not execute a
        // partner either.
        return;
    }
    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.backoff_remaining = fi.effective_backoff_ticks();
    } else {
        fi.state = FaultState::Terminated;
        finalize_module(
            module_idx,
            Some(-110),
            modules[module_idx].type_name(),
            " (timeout terminated)",
        );
        *active_count -= 1;
    }
    // Check quarantine pair-terminate.
    apply_quarantine(sched, modules, module_idx, active_count);
}

/// Handle a step error: record fault, transition to Faulted or finalize.
pub(crate) fn handle_step_error(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
    rc: i32,
    active_count: &mut usize,
    context: &str,
) {
    // SAFETY: DBG_TICK aligned u32 static read.
    let tick = unsafe { DBG_TICK };
    let caused_by = detect_caused_by(sched, module_idx, tick);
    let last_input_ct = last_input_content_type(module_idx);
    let fi = &mut sched.fault_info[module_idx];
    fi.record_fault(fault_type::STEP_ERROR, tick);
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as u8,
        fault_kind: fault_type::STEP_ERROR,
        caused_by,
        last_input_ct,
        tick,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });

    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.backoff_remaining = fi.effective_backoff_ticks();
        log::warn!(
            "[guard] module {} ({}) error rc={} — will restart (fault #{})",
            module_idx,
            modules[module_idx].type_name(),
            rc,
            fi.fault_count
        );
    } else {
        fi.state = FaultState::Terminated;
        finalize_module(
            module_idx,
            Some(rc),
            modules[module_idx].type_name(),
            context,
        );
        *active_count -= 1;
    }
    // Check quarantine pair-terminate.
    apply_quarantine(sched, modules, module_idx, active_count);
}

/// Handle an MPU/MMU protection fault: record, emit event, transition state.
pub(crate) fn handle_mpu_fault(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
    active_count: &mut usize,
) {
    // SAFETY: DBG_TICK aligned u32 static read.
    let tick = unsafe { DBG_TICK };
    let caused_by = detect_caused_by(sched, module_idx, tick);
    let last_input_ct = last_input_content_type(module_idx);
    let fi = &mut sched.fault_info[module_idx];
    fi.record_fault(fault_type::MPU_FAULT, tick);
    log::warn!(
        "[mpu] module {} ({}) protection fault (fault #{})",
        module_idx,
        modules[module_idx].type_name(),
        fi.fault_count
    );
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as u8,
        fault_kind: fault_type::MPU_FAULT,
        caused_by,
        last_input_ct,
        tick,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });

    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.backoff_remaining = fi.effective_backoff_ticks();
    } else {
        fi.state = FaultState::Terminated;
        finalize_module(
            module_idx,
            Some(-14),
            modules[module_idx].type_name(),
            " (mpu terminated)",
        );
        *active_count -= 1;
    }
    // Check quarantine pair-terminate.
    apply_quarantine(sched, modules, module_idx, active_count);
}

/// Attempt to restart a faulted module.
///
/// **v1 partial-restart contract**:
///
/// 1. `syscalls::release_module_handles` releases events, timers, DMA, and
///    tracked provider handles owned by the module.
/// 2. Every connected channel (in / out / ctrl) is `IOCTL_FLUSH`'d.
/// 3. If the module was `deferred_ready`, its ready bit is reset.
/// 4. Fault state moves back to `Running`; `finished[idx]` is cleared.
///
/// What is **not** done in v1, and would be needed for a full restart:
///   - State memory is **not** zeroed — the module observes whatever state
///     it had when it faulted. Safe for stateless / idempotent modules.
///   - `module_new()` is **not** re-called. Stored params + loader state to
///     drive a fresh init aren't plumbed through the restart path yet.
///   - Channel ioctl handlers registered by the module are **not** cleared.
///     Today this matches behaviour (no `module_new` re-call means no
///     re-register), but a full restart implementation must clear them
///     before re-init to avoid stale handler pointers.
///
/// Modules whose invariants do not survive "saw faulted state and got
/// re-stepped" should use `FaultPolicy::Skip` and rely on the operator to
/// drain+reload via the reconfigure module.
pub(crate) fn handle_module_restart(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
) {
    sched.fault_info[module_idx].state = FaultState::Recovering;
    sched.fault_info[module_idx].restart_count += 1;
    log::info!(
        "[guard] restarting module {} ({}) (restart #{})",
        module_idx,
        modules[module_idx].type_name(),
        sched.fault_info[module_idx].restart_count
    );

    // Release owned handles (events, timers, DMA, providers, etc.)
    syscalls::release_module_handles(module_idx as u8);

    // Drain/flush all connected channels (both in and out)
    let ports = &sched.ports[module_idx];
    for i in 0..ports.in_count as usize {
        if ports.in_chans[i] >= 0 {
            channel::channel_ioctl(
                ports.in_chans[i],
                channel::IOCTL_FLUSH,
                core::ptr::null_mut(),
            );
        }
    }
    for i in 0..ports.out_count as usize {
        if ports.out_chans[i] >= 0 {
            channel::channel_ioctl(
                ports.out_chans[i],
                channel::IOCTL_FLUSH,
                core::ptr::null_mut(),
            );
        }
    }
    for i in 0..ports.ctrl_count as usize {
        if ports.ctrl_chans[i] >= 0 {
            channel::channel_ioctl(
                ports.ctrl_chans[i],
                channel::IOCTL_FLUSH,
                core::ptr::null_mut(),
            );
        }
    }

    // **v1 partial-restart**: state is intentionally NOT zeroed — the
    // `DynamicModule` doesn't carry its `state_size`, and zeroing a
    // conservative range could overrun adjacent module state in the
    // shared arena. The module will see whatever state it had at fault
    // time; this matches the docstring above. Full restart (state zero
    // + `module_new` re-call) needs stored params and loader state
    // plumbed through this path. Modules that can't safely
    // resume from faulted state must opt out of `Restart` (use `Skip`).
    let _ = &modules[module_idx];

    // Reset ready signal if module was deferred_ready
    if sched.deferred_ready[module_idx] {
        sched.ready[module_idx] = false;
    }

    // Bump the slot generation — outstanding telemetry snapshots
    // taken before the restart now refer to pre-restart state and
    // must not be trusted by async consumers.
    sched.slot_generation[module_idx] = sched.slot_generation[module_idx].wrapping_add(1);

    // Mark as running again
    sched.fault_info[module_idx].state = FaultState::Running;
    sched.finished[module_idx] = false;
}

pub fn step_modules(modules: &mut [ModuleSlot; MAX_MODULES], count: usize) -> StepResult {
    // SAFETY: scheduler thread is the sole stepper; `modules` is passed
    // through by the caller (per-platform main loop) which owns it.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    // Transaction marker: if `prepare_graph` is mid-build or bailed
    // mid-build, the module slots may not be wired. Treat the graph
    // as cleanly idle (Done) so callers neither dereference
    // half-initialised state nor mistake it for runnable work.
    if sched.prepare_in_progress {
        return StepResult::Done;
    }
    // SAFETY: scheduler-thread sole writer.
    unsafe {
        DBG_TICK += 1;
    }

    // Drain timeout ceiling: see `enforce_drain_timeout`.
    if enforce_drain_timeout(sched, modules, count) {
        return StepResult::Done;
    }

    // Crash-info one-shot: ~CRASH_CHECK_DELAY_MS after boot (by when USB
    // serial is reliably connected), check the .uninit CRASH_DATA RAM that a
    // HardFault handler may have left behind from the previous run, and clear
    // the marker so it doesn't repeat. Gated on wall-clock + a one-shot latch
    // rather than a `30_000_000 / tick_us` tick threshold: the tick form
    // mis-scales when mechanism (b) varies the period, and under mechanism (a)
    // idle-sleep the threshold tick may never be reached (DBG_TICK stalls) — a
    // missed one-shot-correctness read. The latch guarantees it fires exactly
    // once per boot regardless of pass count. The `[sched] alive` log itself
    // is emitted by the platform's outer loop via `maybe_emit_alive`.
    if !CRASH_CHECKED.load(Ordering::Relaxed)
        && crate::kernel::sys::hal::now_millis() >= CRASH_CHECK_DELAY_MS
    {
        CRASH_CHECKED.store(true, Ordering::Relaxed);
        // SAFETY: CRASH_DATA is in `.uninit` and survives soft reset; we
        // read 8 u32 words (32 bytes) which match the section size, and
        // re-clear `magic` afterwards so the path runs once per boot.
        unsafe {
            let crash = (&raw const CRASH_DATA) as *const u32;
            let magic = core::ptr::read_volatile(crash);
            if magic == CRASH_MAGIC {
                let pc = core::ptr::read_volatile(crash.add(1));
                let lr = core::ptr::read_volatile(crash.add(2));
                let module = core::ptr::read_volatile(crash.add(3));
                let prev_tick = core::ptr::read_volatile(crash.add(4));
                let r0 = core::ptr::read_volatile(crash.add(5));
                let cfsr = core::ptr::read_volatile(crash.add(6));
                let bfar = core::ptr::read_volatile(crash.add(7));
                log::error!(
                    "[crash] pc={pc:08x} lr={lr:08x} r0={r0:08x} mod={module} t={prev_tick}"
                );
                log::error!("[crash] cfsr={cfsr:08x} bfar={bfar:08x}");
                core::ptr::write_volatile((&raw mut CRASH_DATA) as *mut u32, 0);
            }
        }
    }
    // Count active (non-finished) modules upfront so step-period gating
    // doesn't falsely produce active_count==0 → StepResult::Done.
    let mut active_count: usize = 0;
    for i in 0..count {
        if !sched.finished[i] {
            active_count += 1;
        }
    }

    // Compute not-ready bitmask for upstream gating
    let mut not_ready = ModuleMask::new();
    for i in 0..count {
        if !sched.ready[i] {
            not_ready.set(i);
        }
    }

    // Reset the per-pass budget accumulator for **every** domain
    // before this pass starts. `step_one_module` charges elapsed
    // time to the module's *actual* `domain_id`, so multi-domain
    // configs on a flat target (rare but architecturally legal)
    // need every bucket cleared — resetting only domain 0 would
    // leak time into the wrong accumulator when a non-default-domain
    // module is stepped.
    sched.pass_module_us = [0; MAX_MODULES];
    sched.pass_module_steps = [0; MAX_MODULES];
    for d in 0..MAX_DOMAINS {
        sched.domain_budget_us_consumed[d] = 0;
        // Decay the adaptive-tick floor's worst-step peak-hold once per pass so
        // a stale spike ages out. step_one_module re-raises it to the live worst.
        // The decrement is `max(v >> shift, 1)` for any non-zero value: a pure
        // `v >> 8` stalls at 0 once v < 256, so a stale sub-256 µs spike would
        // never fully age out and would hold the floor (and tick_min) up.
        let w = sched.domain_worst_step_us[d];
        if w > 0 {
            sched.domain_worst_step_us[d] = w - (w >> WORST_STEP_DECAY_SHIFT).max(1);
        }
    }
    // Track which domains already logged a soft-overrun this pass,
    // so we don't emit a MON_BUDGET_OVERRUN line per remaining module.
    let mut overrun_logged: [bool; MAX_DOMAINS] = [false; MAX_DOMAINS];

    // Tier 1c pre-pass drain — run each domain's `pre_tick_drain`
    // modules before the global exec_order rotation. Single-core
    // targets only populate domain 0; the loop is bounded so the
    // overhead is constant when no domain has pre-tick modules.
    for d in 0..MAX_DOMAINS {
        if sched.domain_pre_tick_count[d] > 0 {
            step_domain_pre_tick(modules, sched, d, &not_ready, &mut active_count);
        }
    }

    // Step modules in topological order so producers run before
    // consumers. The per-module step body is in `step_one_module`
    // so the domain-scoped `step_domain_modules` can reuse the same
    // semantics.
    //
    // When a previous pass tripped a budget overrun, the start of
    // `exec_order` is rotated by `exec_order_offset`. Without the
    // rotation, modules after the overrunning module in topological
    // order never get their tick — the burster monopolises until
    // its own domain budget is exhausted, then the pass breaks.
    // Rotating the start point gives every position equal exposure
    // across many passes (deterministic cycle, no random).
    // Topological correctness is preserved because channel rings
    // already buffer one tick of upstream output — a consumer that
    // runs before its producer on tick T reads tick T-1's buffered
    // bytes.
    let exec_count = sched.exec_order_count;
    let n = if exec_count > 0 { exec_count } else { count };
    let offset = if exec_count > 0 {
        (sched.exec_order_offset as usize) % exec_count
    } else {
        0
    };
    // Bounded multi-pass within the tick (see `MAX_PIPELINE_PASSES`). One pass
    // moves data one hop along `exec_order`, so a request's return path
    // (consumer-before-producer for the reverse direction) waits a full tick
    // per hop. Re-running the pass while any module still reports `Burst` lets
    // the full round-trip complete in one tick — the dominant per-request
    // latency. Idle ticks burst nothing → one pass (low-load cost unchanged);
    // the per-domain budget bounds the busy case.
    //
    // Reset the pacer's per-tick busy accumulator once for the whole outer tick
    // (all domains — the flat path steps every domain). Set on any burst, read
    // by the pacer; `BURST_SEEN_THIS_PASS` is reset per sub-pass and can't serve
    // it. See `PACER_BURST_TICK`.
    for b in PACER_BURST_TICK.iter() {
        b.store(false, Ordering::Relaxed);
    }
    // Useful-work signal: reset on the same per-tick cadence as the burst
    // accumulator.
    for b in PACER_WORK_TICK.iter() {
        b.store(false, Ordering::Relaxed);
    }
    let mut tick_pass = 0u32;
    let mut hard_break = false;
    loop {
        // Single-domain path (rp2350/linux/wasm): not run concurrently, but it
        // steps every module regardless of `domain_id`, so clear/check across
        // all domain slots rather than assuming domain 0.
        for b in BURST_SEEN_THIS_PASS.iter() {
            b.store(false, Ordering::Relaxed);
        }
        let pass_start_us = sched.domain_budget_us_consumed;
        for order_pos in 0..n {
            let rotated_pos = if exec_count > 0 {
                (order_pos + offset) % exec_count
            } else {
                order_pos
            };
            let module_idx = if exec_count > 0 {
                sched.exec_order[rotated_pos] as usize
            } else {
                order_pos
            };
            if module_idx >= count {
                continue;
            }
            // Skip Tier 1c (pre-tick) modules from the regular exec_order
            // pass — they already ran via `step_domain_pre_tick` at the
            // top of this function.
            if sched.pre_tick_drain[module_idx] {
                continue;
            }
            step_one_module(
                modules,
                sched,
                module_idx,
                &not_ready,
                &mut active_count,
                false,
            );

            // Soft overrun: log + advance the cyclic shift but keep
            // running downstream modules (the NIC drain in particular).
            // Hard overrun (`break`) reserved for runaway-loop protection.
            let stepped_domain = sched.domain_id[module_idx] as usize;
            if stepped_domain < MAX_DOMAINS {
                let soft = domain_budget_exhausted(sched, stepped_domain);
                let hard = soft && domain_budget_hard_overrun(sched, stepped_domain);
                if soft && !overrun_logged[stepped_domain] {
                    record_domain_budget_overrun(sched, stepped_domain, module_idx);
                    sched.exec_order_offset = sched.exec_order_offset.wrapping_add(1);
                    overrun_logged[stepped_domain] = true;
                }
                if hard {
                    hard_break = true;
                    break;
                }
            }
        }
        tick_pass += 1;
        if hard_break || tick_pass >= MAX_PIPELINE_PASSES {
            break;
        }
        // A domain that cannot afford another pass ends the tick's passes
        // for every domain: the flat path steps them all together.
        if (0..MAX_DOMAINS).any(|d| !domain_budget_admits_repass(sched, d, pass_start_us[d])) {
            break;
        }
        let mut refilled = false;
        for d in 0..MAX_DOMAINS {
            if sched.domain_pre_tick_count[d] > 0 {
                refilled |= step_domain_pipeline_refill(modules, sched, d, &mut active_count);
            }
        }
        // Pipeline drained (no module backlog and no newly-admitted device
        // input) → nothing to re-pass.
        if !BURST_SEEN_THIS_PASS
            .iter()
            .any(|b| b.load(Ordering::Relaxed))
            && !refilled
        {
            break;
        }
    }

    // Output-only post-pass hook. Unlike re-running Tier 1c module_step, this
    // cannot drain RX or repeat other input side effects: modules must opt in
    // with a dedicated module_post_tick_flush export.
    for d in 0..MAX_DOMAINS {
        if sched.domain_pre_tick_count[d] > 0 {
            step_domain_post_tick_flush(modules, sched, d, &mut active_count);
        }
    }

    // Drain any cooperative⇄ISR-tier bridge edges so messages
    // pending in either direction flow before the next tick. Runs
    // last (after all cooperative modules have a chance to produce)
    // so a producer's tick-T output reaches the ISR side as soon as
    // tick T finishes.
    pump_isr_bridges();

    if active_count == 0 {
        StepResult::Done
    } else {
        StepResult::Continue
    }
}

/// Step every module assigned to `domain_id` in the per-domain
/// topological order. Multi-domain counterpart to [`step_modules`];
/// both share the same per-module body (`step_one_module`) so semantics
/// match exactly — step-period gating, ready-signal gating, fault
/// transitions, `StepOutcome::{Continue, Ready, Done, Burst}`,
/// step-guard arm/disarm, step-time recording.
///
/// Returns `StepResult::Done` when every active module across the
/// whole graph is finalised (the active_count is global). Sibling
/// domains can keep
/// stepping independently; callers should decide global shutdown
/// based on every domain returning `Done`.
///
/// `domain_id` >= `MAX_DOMAINS` returns `StepResult::Done` immediately
/// (no-op, no error). The caller should guarantee this never happens —
/// `multicore::MAX_DOMAINS` already caps assignment.
///
/// Set inside `step_one_module` whenever a module returns `Burst` from
/// `m.step()`, and read by the Tier 3 poll-mode wrapper
/// (`step_domain_modules_poll`) to decide whether the domain has more
/// work pending or can WFE. Each `step_domain_modules_poll` call
/// clears the flag before the pass.
/// PER-DOMAIN, indexed by `domain_id`. On BCM2712 each core runs its own
/// domain's `step_domain_modules` concurrently; a single shared flag would let
/// one core clear or observe another core's burst marker mid-pass, making the
/// multi-pass re-run nondeterministic and risking a poll-mode domain WFE-ing
/// while it still has local pending work. A slot per domain keeps each core's
/// burst signal isolated to its own pass.
/// Minimum exec-order passes per tick, regardless of `Burst`.
///
/// Default 1 is the baseline: idle ticks run one pass, and only a module
/// returning `StepOutcome::Burst` earns a re-pass. Raising it forces the
/// first K passes unconditionally, so a request's reply path — which flows
/// AGAINST exec order and otherwise pays one tick per hop — can complete
/// within the tick without any module opting in via Burst.
///
/// Scheduler-side rather than module-side, deliberately. Letting modules
/// ask for the extra pass by returning Burst on productive work starves the
/// CM5 write path: a module that always has work monopolises the re-passes.
/// Forcing them here is fairness-neutral — every module steps the same K
/// times — and the per-domain budget still bounds the busy case, so the
/// guards that make one pass safe make K passes safe.
pub(crate) static FORCED_PIPELINE_PASSES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

/// Should the exec-order loop take another pass purely because the forced
/// count has not been reached yet? Both the single-graph loop
/// (`domain_budget`) and the multi-graph runner (`multigraph`) gate their
/// idle exit on this, so the knob cannot come to mean two different things
/// depending on which scheduler path a graph took.
#[inline]
pub(crate) fn forced_pass_pending(tick_pass: u32) -> bool {
    tick_pass < FORCED_PIPELINE_PASSES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Set the forced pass count, clamped to `[1, MAX_PIPELINE_PASSES]`.
pub fn set_forced_pipeline_passes(n: u32) {
    let clamped = n.clamp(
        1,
        crate::kernel::exec::scheduler::domain_budget::MAX_PIPELINE_PASSES,
    );
    FORCED_PIPELINE_PASSES.store(clamped, core::sync::atomic::Ordering::Relaxed);
}

pub(crate) static BURST_SEEN_THIS_PASS: [AtomicBool; MAX_DOMAINS] =
    [const { AtomicBool::new(false) }; MAX_DOMAINS];

/// Per-domain "any Burst across the whole outer tick" — the adaptive-tick
/// pacer's busy signal. Distinct from `BURST_SEEN_THIS_PASS`, which is reset at
/// the start of EVERY pipeline sub-pass for drain-detection and is therefore
/// `false` after a tick that bursts early then drains clean. The pacer must see
/// "was this *tick* busy", so this slot is reset once per outer tick (top of
/// `step_modules` / `step_domain_modules`) and only ever SET on a burst, never
/// mid-tick. Read by `pacer_next_deadline_us`.
pub(crate) static PACER_BURST_TICK: [AtomicBool; MAX_DOMAINS] =
    [const { AtomicBool::new(false) }; MAX_DOMAINS];

/// Per-domain "a module reported useful work this outer tick" — the pacer's
/// work signal. Set by the `REPORT_STEP_EFFECT` syscall when a module reports
/// `WorkDone`/`RunnableBacklog`/`Burst`; reset once per outer tick alongside
/// `PACER_BURST_TICK`. Read by `pacer_next_deadline_us` so a graph that does
/// useful work WITHOUT returning `StepOutcome::Burst` (e.g. the IP forwarding
/// path, which avoids Burst to not starve the NIC ring) still keeps the pacer
/// hot. This heats the pacer ONLY — it never authorises the immediate
/// same-module re-step, which remains driven by the `Burst` return.
pub(crate) static PACER_WORK_TICK: [AtomicBool; MAX_DOMAINS] =
    [const { AtomicBool::new(false) }; MAX_DOMAINS];

/// `StepEffect` codes reported via `REPORT_STEP_EFFECT`. Values are
/// wire-stable (module SDK ↔ kernel).
pub mod step_effect {
    /// No useful work; no known runnable backlog.
    pub const IDLE: u8 = 0;
    /// Blocked on external/device/peer progress — does NOT heat the pacer.
    pub const WAITING: u8 = 1;
    /// Useful work happened; no immediate same-module re-step.
    pub const WORK_DONE: u8 = 2;
    /// More local work can progress, but fairness says yield — heats the pacer,
    /// no immediate re-step.
    pub const RUNNABLE_BACKLOG: u8 = 3;
    /// Useful work and immediate re-step is productive (mirror of the `Burst`
    /// return; reporting it here also heats the pacer).
    pub const BURST: u8 = 4;
}

/// Record a module's `StepEffect` for the current outer tick.
/// `WorkDone`/`RunnableBacklog`/`Burst` mark the module's domain busy for the
/// pacer; `Idle`/`Waiting` do nothing (a blocked module must not pin the
/// pacer hot). Called from the `REPORT_STEP_EFFECT` syscall handler with the
/// calling module's index.
pub fn report_step_effect(module_idx: usize, effect: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    if effect >= step_effect::WORK_DONE {
        // SAFETY: scheduler-thread read of the per-module domain id.
        let domain = unsafe { SCHED.domain_id[module_idx] as usize };
        if domain < MAX_DOMAINS {
            PACER_WORK_TICK[domain].store(true, Ordering::Relaxed);
        }
    }
}

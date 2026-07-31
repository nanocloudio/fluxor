//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

// ============================================================================
// Live Reconfigure — Kernel Primitives
// ============================================================================
//
// Raw primitives exposed to the `modules/reconfigure` PIC module via the
// `dev_system` reconfigure opcodes (0x0C67–0x0C6F).

/// Return the current reconfigure phase.
pub fn reconfigure_phase() -> ReconfigurePhase {
    // SAFETY: scheduler-thread read.
    unsafe { SCHED.reconfigure_phase }
}

/// Diagnostic accessor: `true` while `prepare_graph` is mid-build or
/// has bailed mid-build. Exposed so tests and platform diagnostics can
/// confirm the transaction-marker contract. When `true`, the
/// scheduler step paths short-circuit to `StepResult::Done` (or no-op
/// for event wakes) — the graph is not safe to step.
pub fn prepare_in_progress() -> bool {
    // SAFETY: scheduler-thread read of the transaction marker.
    unsafe { SCHED.prepare_in_progress }
}

/// Set the current reconfigure phase.
///
/// Capturing the entry tick for `Draining` arms the kernel-side
/// drain-timeout ceiling. Transitioning *out* of `Draining` clears
/// the marker so a subsequent `Running → Migrating` transition (the
/// normal happy path) doesn't false-trip the timeout.
pub fn set_reconfigure_phase(phase: ReconfigurePhase) {
    // SAFETY: reconfigure orchestrator runs on the scheduler thread.
    unsafe {
        let was_draining = SCHED.reconfigure_phase == ReconfigurePhase::Draining;
        SCHED.reconfigure_phase = phase;
        match phase {
            ReconfigurePhase::Draining => {
                if !was_draining {
                    SCHED.drain_started_ms = crate::kernel::sys::hal::now_millis();
                }
            }
            _ => {
                SCHED.drain_started_ms = u64::MAX;
            }
        }
    }
}

/// Return the number of active modules in the current graph.
pub fn active_module_count() -> usize {
    // SAFETY: scheduler-thread read.
    unsafe { SCHED.active_module_count }
}

/// Return the number of modules currently in `exec_order` (the
/// topologically-sorted list `step_modules` iterates). Exposed so tests
/// and diagnostics can confirm `prepare_graph` populated it. Equals
/// `active_module_count` after a clean graph prepare; >0 once any module
/// has been ordered.
pub fn exec_order_count() -> usize {
    // SAFETY: scheduler-thread read.
    unsafe { SCHED.exec_order_count }
}

/// Return the module slot scheduled at position `pos` in `exec_order`, or
/// `None` if `pos` is past `exec_order_count`. Lets tests confirm a live
/// mutation left existing modules at their original schedule positions.
pub fn exec_order_slot(pos: usize) -> Option<u8> {
    // SAFETY: scheduler-thread read.
    unsafe {
        if pos < SCHED.exec_order_count {
            Some(SCHED.exec_order[pos])
        } else {
            None
        }
    }
}

/// Platform hook: set the active module count. Called by platforms whose
/// graph-setup path doesn't go through `prepare_graph` (e.g. the bcm2712
/// domain-based instantiator) but which still want queries like
/// `RECONFIGURE_MODULE_COUNT` to report the right value.
pub fn set_active_module_count(n: usize) {
    // SAFETY: scheduler-thread mutation.
    unsafe {
        SCHED.active_module_count = n;
    }
}

/// Invoke `module_drain()` on module N. Returns the module's return code,
/// or -1 if the module is not drain-capable or the index is invalid.
pub fn call_module_drain(module_idx: usize) -> i32 {
    if module_idx >= MAX_MODULES {
        return -1;
    }
    // SAFETY: scheduler-thread read.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    if let ModuleSlot::Dynamic(ref m) = sched.modules[module_idx] {
        set_current_module(module_idx);
        // SAFETY: `m` is the dynamic-module slot's owned handle; `call_drain`
        // is its ABI surface invoked from a safe scheduler context.
        let rc = unsafe { m.call_drain() };
        // Drop module context (see step_one_module) so post-drain
        // platform logs attribute to the system owner.
        set_current_module(MAX_MODULES);
        rc
    } else {
        -1
    }
}

/// Mark a module as finished so the scheduler skips it in future ticks.
pub fn mark_module_finished(module_idx: usize) {
    if module_idx < MAX_MODULES {
        // SAFETY: scheduler-thread mutation; module_idx bounded.
        unsafe {
            let p = &raw mut SCHED;
            (*p).finished[module_idx] = true;
        }
    }
}

/// Raise a fault against module `idx` with the given `fault_kind`
/// (see `step_guard::fault_type`). Updates the module's fault
/// bookkeeping, **marks the module Faulted (or leaves it alone if
/// already Faulted/Terminated)**, and pushes a record to the global
/// fault ring so subscribers (monitor CLI, metrics sinks) observe it
/// uniformly with step-guard / MPU faults.
///
/// Used by non-step-context faulting paths — currently `heap_alloc`
/// when the module's `fault_on_alloc_failure` flag is set. The
/// caller's `m.step()` frame is typically still on the stack at
/// invocation, which means we **must not** finalize / release
/// handles inline (that would tear down the module while its step
/// body is still mid-execution). Instead, we just flip the
/// fault-state machine and let the *next* `step_one_module` tick run
/// the declared `FaultPolicy` through its normal recovery path:
///
///   * `FaultPolicy::Restart` + `can_restart()` → backoff arms, restart
///     fires at the next eligible tick.
///   * Otherwise → next `step_one_module` observes `Faulted` +
///     `!can_restart()` and routes through the `Terminated` branch,
///     which calls `finalize_module` from a safe context.
///
/// This matches the contract documented at the heap-side caller
/// (`heap.alloc_failure_policy = "fault"` → "policy runs next tick").
pub fn raise_module_fault(module_idx: usize, fault_kind: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: heap-side caller runs on the scheduler thread (per the
    // contract documented above: "policy runs next tick"); we only
    // flip the fault-state machine here, finalisation happens later.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    // SAFETY: DBG_TICK aligned u32 read.
    let tick = unsafe { DBG_TICK };
    let caused_by = detect_caused_by(sched, module_idx, tick);
    let last_input_ct = last_input_content_type(module_idx);
    sched.fault_info[module_idx].record_fault(fault_kind, tick);
    let fi = &mut sched.fault_info[module_idx];
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as u8,
        fault_kind,
        caused_by,
        last_input_ct,
        tick,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });
    // Mark Faulted only if not already in a terminal / recovering
    // state. Critically, do NOT call `finalize_module` here — that
    // releases handles while the caller's `m.step()` frame may
    // still be on the stack.
    //
    // Backoff is only armed for `FaultPolicy::Restart` (and only
    // when the module is actually restartable). Skip / RestartGraph
    // / exhausted-restart modules don't restart — leaving
    // `backoff_remaining` at zero means the next `step_one_module`
    // observes `Faulted + !can_restart()` and finalises immediately,
    // instead of waiting through `restart_backoff_ms` ticks while
    // channels and handles stay live.
    if fi.state == FaultState::Running {
        fi.state = FaultState::Faulted;
        if fi.can_restart() {
            fi.backoff_remaining = fi.effective_backoff_ticks();
        } else {
            fi.backoff_remaining = 0;
        }
    }
}

/// Module capability flag bitmask:
///   bit 0: drain_capable (module exports module_drain)
///   bit 1: deferred_ready
///   bit 2: mailbox_safe
///   bit 3: in_place_writer
pub fn module_info_flags(module_idx: usize) -> u32 {
    if module_idx >= MAX_MODULES {
        return 0;
    }
    // SAFETY: scheduler-thread read.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let mut flags: u32 = 0;
    if let ModuleSlot::Dynamic(ref m) = sched.modules[module_idx] {
        if m.has_drain() {
            flags |= 0x01;
        }
    }
    if sched.deferred_ready[module_idx] {
        flags |= 0x02;
    }
    if sched.mailbox_safe[module_idx] {
        flags |= 0x04;
    }
    if sched.in_place_writer[module_idx] {
        flags |= 0x08;
    }
    flags
}

/// Upstream-module bitmask for module N.
pub fn module_upstream_mask(module_idx: usize) -> u64 {
    if module_idx >= MAX_MODULES {
        return 0;
    }
    // SAFETY: scheduler-thread read; module_idx bounded.
    // The reconfigure syscall ABI surfaces a u64; it observes the low-64
    // upstream bits. Widening that opcode is tracked with the reconfigure ABI.
    unsafe { SCHED.upstream_mask[module_idx].as_u64() }
}

/// Whether every producer that can still feed `module_idx` — over any edge,
/// including a feedback-cycle back-edge — has finished. A sink (`cli_out`) uses
/// this instead of the forward-only `upstream_mask`: with the forward mask a sink
/// placed downstream of the `tcp_client`/`linux_net` cycle sees an EMPTY upstream
/// set (its only feeder arrives via a back-edge) and would declare itself done
/// before the async reply is produced. `true` when no live producer remains
/// (also `true` for a genuine source with no predecessors at all).
pub fn module_completion_predecessors_finished(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return true;
    }
    // SAFETY: scheduler-thread read; module_idx bounded.
    let mask = unsafe { &SCHED.completion_mask[module_idx] };
    for producer in mask.iter_set() {
        if !module_is_finished(producer) {
            return false;
        }
    }
    true
}

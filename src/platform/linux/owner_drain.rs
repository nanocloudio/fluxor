// Owner drain driver (rfc_owner_drain_and_logs.md §3.4) — the platform half of
// bounded owner drain on Linux.
//
// A removal generation with a grace window reaches this file through the
// pure-drain delta path (`owner_plan::try_apply_drain_delta`, no rebuild): each
// newly revoked owner is flipped to `Draining` in the kernel (admission closes,
// readiness withdraws via the status writer) and an entry lands here carrying
// the plan-stamped `deadline_unix`. Ticked on the same ~100 ms window as the
// status writer, each entry is freed (`scheduler::free_owner` — drain hooks,
// stop, unsplice, close edges, reclaim, revoke) at the earlier of:
//
//   * quiescence — every module the owner stamps ran to Done/terminal
//     (`scheduler::owner_modules_quiescent`, the v1 predicate), or
//   * the deadline — wall clock passing the stamped `deadline_unix`.
//
// The terminal outcome is recorded here (Completed vs drain-timeout, plus a
// by-restart flag for drains forfeited by a process restart) and served into
// `owner_status.json` beside the live pods until the revocation's retention
// window lapses. All single-threaded on the scheduler/main thread.

/// One armed drain.
struct DrainEntry {
    pod_uid: [u8; 16],
    slot: u16,
    generation: u32,
    deadline_unix: u64,
}

/// One drained owner's terminal outcome, retained until `retain_until_unix`.
struct DrainTerminal {
    pod_uid: [u8; 16],
    slot: u16,
    generation: u32,
    /// Deadline passed before quiescence (forced revoke).
    timed_out: bool,
    /// Forfeited by a runtime restart mid-drain (§3.6).
    by_restart: bool,
    finished_unix: u64,
    retain_until_unix: u64,
}

/// Armed drains + terminal records. Main-thread only.
struct DrainDriver {
    entries: Vec<DrainEntry>,
    terminals: Vec<DrainTerminal>,
}

static mut DRAIN_DRIVER: Option<DrainDriver> = None;

fn drain_driver() -> &'static mut DrainDriver {
    // SAFETY: main-thread-only access (the platform loop and boot path).
    unsafe {
        let p = &raw mut DRAIN_DRIVER;
        (*p).get_or_insert_with(|| DrainDriver {
            entries: Vec::new(),
            terminals: Vec::new(),
        })
    }
}

/// Retention window for a terminal record past its deadline — mirrors the
/// agent-side `REVOCATION_SETTLE_SECS` plus slack so `agent status` polling at
/// the expiry boundary still observes the outcome.
const TERMINAL_RETAIN_SECS: u64 = 30;

/// Arm the drains a delta apply produced. Re-arming an already-armed
/// `(slot, generation)` keeps the ORIGINAL deadline: a replayed revocation
/// record never resets the clock (§3.4).
fn arm_drains(delta: &fluxor::kernel::owner_plan::DrainDelta) {
    let d = drain_driver();
    for arm in &delta.arms[..delta.count] {
        let already = d
            .entries
            .iter()
            .any(|e| e.slot == arm.slot && e.generation == arm.generation);
        if already {
            continue;
        }
        log::info!(
            "[drain] owner slot {} gen {} draining until unix {}",
            arm.slot,
            arm.generation,
            arm.deadline_unix
        );
        d.entries.push(DrainEntry {
            pod_uid: arm.pod_uid,
            slot: arm.slot,
            generation: arm.generation,
            deadline_unix: arm.deadline_unix,
        });
    }
}

/// Drive every armed drain: free the owner at quiescence or deadline and record
/// the terminal outcome. Called on the ~100 ms platform tick.
fn drain_tick(now_unix: u64) {
    let d = drain_driver();
    if d.entries.is_empty() && d.terminals.is_empty() {
        return;
    }
    let mut i = 0;
    while i < d.entries.len() {
        let e = &d.entries[i];
        let handle = fluxor::kernel::owner::OwnerHandle {
            slot: e.slot,
            generation: e.generation,
        };
        // An owner that vanished under us (a structural rebuild mid-drain
        // reset the table — v1 forfeits the remainder) gets its terminal
        // record now; nothing is left to free.
        let gone = fluxor::kernel::scheduler::owners_mut().lookup(handle).is_none();
        let quiescent =
            !gone && fluxor::kernel::scheduler::owner_modules_quiescent(handle);
        let expired = now_unix >= e.deadline_unix;
        if !gone && !quiescent && !expired {
            i += 1;
            continue;
        }
        let timed_out = expired && !quiescent && !gone;
        if !gone {
            match fluxor::kernel::scheduler::free_owner(handle) {
                Ok(()) => {}
                Err(err) => log::warn!(
                    "[drain] free_owner slot {} gen {}: {err:?}",
                    e.slot,
                    e.generation
                ),
            }
        }
        log::info!(
            "[drain] owner slot {} gen {} revoked ({})",
            e.slot,
            e.generation,
            if timed_out {
                "deadline exceeded"
            } else if gone {
                "forfeited by rebuild"
            } else {
                "quiesced"
            }
        );
        let e = d.entries.swap_remove(i);
        d.terminals.push(DrainTerminal {
            pod_uid: e.pod_uid,
            slot: e.slot,
            generation: e.generation,
            timed_out,
            by_restart: false,
            finished_unix: now_unix,
            retain_until_unix: e.deadline_unix.saturating_add(TERMINAL_RETAIN_SECS),
        });
    }
    d.terminals
        .retain(|t| now_unix <= t.retain_until_unix.max(t.finished_unix));
}

/// At boot: any revocation the (just-applied) retained plan still lists, whose
/// owner is NOT installed, was mid-drain when the previous process died. The
/// drain is forfeited (§3.6) and the terminal record says so.
fn synthesize_restart_terminals(now_unix: u64) {
    let mut revs = [fluxor::kernel::owner_plan::PlanRevocation::EMPTY;
        fluxor::kernel::owner_plan::MAX_PLAN_ASSIGNMENTS];
    let n = fluxor::kernel::owner_plan::retained_revocations(&mut revs);
    let d = drain_driver();
    for rev in &revs[..n] {
        let handle = fluxor::kernel::owner::OwnerHandle {
            slot: rev.assignment.slot,
            generation: rev.assignment.generation,
        };
        if fluxor::kernel::scheduler::owners_mut().lookup(handle).is_some() {
            continue; // installed → a live drain, not a forfeit
        }
        let already = d
            .terminals
            .iter()
            .any(|t| t.slot == rev.assignment.slot && t.generation == rev.assignment.generation);
        if already {
            continue;
        }
        d.terminals.push(DrainTerminal {
            pod_uid: rev.assignment.pod_uid,
            slot: rev.assignment.slot,
            generation: rev.assignment.generation,
            timed_out: true,
            by_restart: true,
            finished_unix: now_unix,
            retain_until_unix: rev.deadline_unix.saturating_add(TERMINAL_RETAIN_SECS),
        });
    }
}

/// Overlay live drain deadlines onto the kernel status snapshot (the kernel
/// carries `owner_state`; the deadline lives here). Called by the status
/// writer's tick before deriving the pods JSON.
fn drain_overlay_for_status(
    recs: &mut [fluxor::kernel::scheduler::OwnerLiveStatus],
    now_unix: u64,
) {
    let d = drain_driver();
    if d.entries.is_empty() {
        return;
    }
    for rec in recs.iter_mut() {
        if let Some(e) = d
            .entries
            .iter()
            .find(|e| e.slot == rec.slot && e.generation == rec.generation)
        {
            rec.drain_deadline_unix = e.deadline_unix;
            rec.drain_remaining_secs = e.deadline_unix.saturating_sub(now_unix) as u32;
        }
    }
}

/// Render the retained terminal records as status-file pod entries (same shape
/// as the live pods array; §7.2 vocabulary + the additive `drain{}` detail).
/// Returns entries WITHOUT leading separators; empty when nothing is retained.
fn drain_terminal_pods_json() -> Vec<String> {
    use std::fmt::Write as _;
    let d = drain_driver();
    let mut out = Vec::with_capacity(d.terminals.len());
    for t in &d.terminals {
        let uid_hex: String = t.pod_uid.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let (reason, exit_code) = if t.timed_out {
            (
                "GraphNodeFault",
                fluxor::kernel::step_guard::fault_type::DRAIN_TIMEOUT as i32,
            )
        } else {
            ("Completed", 0)
        };
        let mut e = String::new();
        let _ = write!(
            e,
            "{{\"pod_uid_hex\":\"{uid_hex}\",\"slot\":{},\"owner_generation\":{},\
             \"runtime\":{{\"phase\":\"Terminated\",\"ready\":false,\"started\":false,\
             \"restart_count\":0,\"terminated\":{{\"reason\":\"{reason}\",\
             \"exit_code\":{exit_code},\"signal\":null,\"finished_at\":\"{}\"}},\
             \"drain\":{{\"timed_out\":{},\"by_restart\":{}}}}}}}",
            t.slot,
            t.generation,
            rfc3339_utc(t.finished_unix),
            t.timed_out,
            t.by_restart,
        );
        out.push(e);
    }
    out
}

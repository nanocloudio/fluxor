//! Primary-core ops called from another core.
//!
//! Some kernel work runs on the primary core alone: the ops that change the
//! graph, check a signature or use the key vault, which assume one provider
//! call at a time and run the kernel's deepest frames, and (on RP) taking
//! execute-in-place flash away. A module stepped on another core still
//! calls them; its core hands the call to the primary and waits for the
//! answer. The call stays synchronous: the caller's arguments and lends stay
//! where they are (the caller's frame is live for the whole wait), and the
//! caller cannot tell where it ran.
//!
//! One slot per core. A secondary fills its slot, posts it, signals the
//! primary and waits; the primary, at its service points (between module
//! steps, at its pass boundary, and inside its own waits for the other cores
//! to park), serves each posted slot as the caller (its module context,
//! grants and realm) and marks it done. A caller whose module slot was freed
//! or reused while it waited is answered `ESRCH` without running.
//!
//! While its call is served the caller counts as parked for a structural
//! quiesce: a served op that changes the graph (an add, a removal) parks
//! the other cores, and the caller is suspended inside the call exactly as
//! the primary's own pass is suspended under an op one of its own modules
//! made. A posted call not yet served does not count: the primary serves it
//! before it takes a structural change, so the caller is never left inside a
//! step while the graph changes under it.
//!
//! Pure atomics and a cell per slot, with the platform's waits and the
//! scheduler's context passed in, so a host test runs both sides on threads.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use super::quiesce::MAX_CORES;

use crate::kernel::sys::errno::ESRCH;

const FREE: u32 = 0;
const POSTED: u32 = 1;
const SERVING: u32 = 2;
const DONE: u32 = 3;

/// Who made a call: the module the caller's core was stepping, that slot's
/// generation when it called, and the module that asked for the provider
/// frame the call was made in (the stepping module itself when none was).
/// A module index past the table is the kernel's own context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    pub module: usize,
    pub generation: u32,
    pub requester: usize,
}

/// One core's call. The cell is written only by its core while the state
/// is `FREE`, and read only by the primary while it is `SERVING`.
struct Slot {
    state: AtomicU32,
    rc: AtomicI32,
    call: UnsafeCell<Option<Posted>>,
}

/// What a posted slot holds: the work, as a pointer to the caller's
/// closure, and the caller.
#[derive(Clone, Copy)]
struct Posted {
    run: *mut (dyn FnMut() -> i32 + 'static),
    caller: Caller,
}

/// The primary-core calls of every core.
pub struct PrimaryCalls {
    slots: [Slot; MAX_CORES],
    /// A bit per core with a slot posted: the primary's one load at a
    /// service point.
    posted: AtomicU32,
    /// Set while the primary serves a slot, so a wait inside the served op
    /// serves no other slot underneath it.
    serving: AtomicU32,
}

// SAFETY: each slot's cell is handed between its core and the primary by
// the state word (Release on post, Acquire on serve and on completion), so
// no two cores touch a cell at once; the closure a cell points at lives in
// the frame of a caller that waits until the primary has let go of it.
unsafe impl Sync for PrimaryCalls {}
// SAFETY: as `Sync`: the table holds no pointer outside a posted call.
unsafe impl Send for PrimaryCalls {}

impl Default for PrimaryCalls {
    fn default() -> Self {
        Self::new()
    }
}

impl PrimaryCalls {
    pub const fn new() -> Self {
        Self {
            slots: [const {
                Slot {
                    state: AtomicU32::new(FREE),
                    rc: AtomicI32::new(0),
                    call: UnsafeCell::new(None),
                }
            }; MAX_CORES],
            posted: AtomicU32::new(0),
            serving: AtomicU32::new(0),
        }
    }

    /// On core `core` (not 0): run `run` on the primary as `caller` and
    /// return its answer. Posts the call, calls `signal` once, then calls
    /// `wait_turn` until the primary has answered: the platform's wait for
    /// an event, which also honours a step quiesce (the call may take XIP
    /// away) but never a structural one.
    pub fn delegate(
        &self,
        core: usize,
        caller: Caller,
        run: &mut dyn FnMut() -> i32,
        signal: impl FnOnce(),
        mut wait_turn: impl FnMut(),
    ) -> i32 {
        let Some(slot) = self.slots.get(core).filter(|_| core != 0) else {
            return run();
        };
        // SAFETY: only the lifetime is erased. The closure outlives every
        // use: this frame waits for `DONE`, after which the primary no
        // longer holds the pointer.
        let run: *mut (dyn FnMut() -> i32 + 'static) = unsafe { core::mem::transmute(run) };
        // SAFETY: the slot is FREE, so only this core touches the cell.
        unsafe { *slot.call.get() = Some(Posted { run, caller }) };
        slot.state.store(POSTED, Ordering::Release);
        self.posted.fetch_or(1 << core, Ordering::AcqRel);
        signal();
        while slot.state.load(Ordering::Acquire) != DONE {
            wait_turn();
        }
        let rc = slot.rc.load(Ordering::Relaxed);
        // SAFETY: DONE: the primary has let go of the cell.
        unsafe { *slot.call.get() = None };
        slot.state.store(FREE, Ordering::Release);
        rc
    }

    /// Whether core `core` has a call posted or being served: it is waiting
    /// on the primary.
    pub fn waiting(&self, core: usize) -> bool {
        self.slots
            .get(core)
            .is_some_and(|s| matches!(s.state.load(Ordering::Acquire), POSTED | SERVING))
    }

    /// Whether any core has a call posted.
    #[inline]
    pub fn any_posted(&self) -> bool {
        self.posted.load(Ordering::Acquire) != 0
    }

    /// On the primary: serve every posted call. `live` says whether the
    /// caller's module still holds the slot it called from; `as_caller`
    /// runs the work in the caller's context; `away` marks the caller
    /// parked for a structural quiesce while its call runs. `signal` wakes
    /// the callers. A call made while another is served (from a wait inside
    /// the served op) is left for the next service point. Returns the calls
    /// served.
    pub fn serve(
        &self,
        live: impl Fn(Caller) -> bool,
        mut as_caller: impl FnMut(Caller, &mut dyn FnMut() -> i32) -> i32,
        away: impl Fn(usize, bool),
        signal: impl Fn(),
    ) -> u32 {
        if !self.any_posted() || self.serving.swap(1, Ordering::AcqRel) != 0 {
            return 0;
        }
        let mut served = 0;
        for core in 1..MAX_CORES {
            let slot = &self.slots[core];
            if slot
                .state
                .compare_exchange(POSTED, SERVING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            self.posted.fetch_and(!(1 << core), Ordering::AcqRel);
            // SAFETY: SERVING: the caller waits and does not touch the cell.
            let posted = unsafe { (*slot.call.get()).take() };
            let rc = match posted {
                Some(p) if live(p.caller) => {
                    away(core, true);
                    // SAFETY: the caller's closure, live while it waits.
                    let rc = as_caller(p.caller, unsafe { &mut *p.run });
                    away(core, false);
                    rc
                }
                _ => ESRCH,
            };
            slot.rc.store(rc, Ordering::Relaxed);
            slot.state.store(DONE, Ordering::Release);
            served += 1;
        }
        self.serving.store(0, Ordering::Release);
        if served != 0 {
            signal();
        }
        served
    }
}

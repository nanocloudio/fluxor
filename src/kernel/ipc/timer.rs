//! Timers: a timer is a handle its creator owns. `SET` arms it, it polls
//! `POLL_IN` once it has fired, and the kernel steps the owner when it fires
//! (`timer_pump`).

use portable_atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};

use crate::kernel::ipc::event;
use crate::kernel::sys::errno;
use crate::kernel::sys::hal;

/// The timer contract's id: the contract field of every timer handle.
const TIMER: u16 = crate::abi::registry::timer::ID;

/// Timers held at once: the profile's static table, or where the plan sizes
/// it (Linux, bcm2712, RP) the plan's `timers` pool (`size_timers`), its
/// envelope entry or default.
pub const MAX_TIMERS: usize =
    crate::kernel::config::static_slots(crate::abi::contracts::resource::POOL_TIMERS);

struct TimerSlot {
    allocated: AtomicBool,
    active: AtomicBool,
    owner: AtomicU16,
    /// The generation a handle to this slot carries; moved on every create.
    generation: AtomicU16,
    /// Deadline in milliseconds (from Instant epoch), wrapping-safe comparison
    deadline_ms: AtomicU32,
    /// The owner has been woken for THIS arming. A timer is an fd: the
    /// kernel steps its owner once when it fires (`timer_pump`), and the
    /// owner reads `POLL_IN` and re-arms or cancels. Without the latch an
    /// expired-but-unconsumed timer would wake its owner every pass — a
    /// level, where a fire is an edge. Cleared by SET / CANCEL / DESTROY.
    woken: AtomicBool,
}

impl TimerSlot {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            active: AtomicBool::new(false),
            owner: AtomicU16::new(NO_MODULE),
            generation: AtomicU16::new(0),
            deadline_ms: AtomicU32::new(0),
            woken: AtomicBool::new(false),
        }
    }
}

impl crate::kernel::ipc::handle::Native for TimerSlot {
    fn live(&self) -> bool {
        self.allocated.load(Ordering::Acquire)
    }
    fn generation(&self) -> u16 {
        self.generation.load(Ordering::Acquire)
    }
    fn owner(&self) -> ModuleId {
        self.owner.load(Ordering::Acquire)
    }
}

static TIMER_SLOTS: crate::kernel::mem::table::Table<TimerSlot, MAX_TIMERS> = crate::boot_table!(
    MAX_TIMERS,
    TimerSlot::new(),
    crate::abi::contracts::resource::POOL_TIMERS
);

/// Size the timer table to `n` slots, all live.
///
/// # Safety
/// Boot or graph-preparation context: no reference into the table is live.
pub unsafe fn size_timers(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    TIMER_SLOTS.reserve(n)?;
    TIMER_SLOTS.grow(n)
}

/// The timer table, sized from the plan's defaults when no plan has sized it.
fn timers() -> &'static [TimerSlot] {
    TIMER_SLOTS.size_unplanned(|| {
        crate::kernel::sys::resource_ledger::ceiling(crate::abi::contracts::resource::POOL_TIMERS)
            as usize
    });
    &TIMER_SLOTS
}

fn now_ms() -> u32 {
    hal::now_millis() as u32
}

/// Create a new timer owned by the current module: its handle, or a negative
/// errno.
pub fn timer_create() -> i32 {
    use crate::abi::contracts::resource::POOL_TIMERS;
    use crate::kernel::sys::resource_ledger as ledger;
    if !ledger::enforced_allows(POOL_TIMERS, timer_in_use_count() as u32 + 1) {
        ledger::deny(POOL_TIMERS);
        return errno::ENOSPC;
    }
    let owner = crate::kernel::exec::scheduler::current_module_id();
    for (i, timer) in timers().iter().enumerate() {
        if timer
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            timer.active.store(false, Ordering::Release);
            timer.owner.store(owner, Ordering::Release);
            timer.deadline_ms.store(0, Ordering::Release);
            timer.woken.store(false, Ordering::Release);
            let generation = timer.generation.load(Ordering::Relaxed).wrapping_add(1)
                & crate::abi::kernel_abi::handle::GEN_MASK;
            timer.generation.store(generation, Ordering::Release);
            return crate::abi::kernel_abi::handle::encode(TIMER, generation, i as u32);
        }
    }
    crate::kernel::sys::resource_ledger::deny(crate::abi::contracts::resource::POOL_TIMERS);
    errno::ENOSPC
}

/// Allocated timer slots — resource-ledger sample for `POOL_TIMERS`.
pub fn timer_in_use_count() -> usize {
    timers()
        .iter()
        .filter(|t| t.allocated.load(Ordering::Relaxed))
        .count()
}

/// The timer `fd` names, when it is live and the calling module's; `EBADF`
/// otherwise.
fn owned_timer(fd: i32) -> Result<&'static TimerSlot, i32> {
    crate::kernel::ipc::handle::resolve_owned(
        timers(),
        TIMER,
        fd,
        crate::kernel::exec::scheduler::current_module_id(),
    )
    .map(|(_, t)| t)
}

/// Start (or restart) a timer with a delay in milliseconds.
pub fn timer_set(fd: i32, delay_ms: u32) -> i32 {
    let timer = match owned_timer(fd) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let deadline = now_ms().wrapping_add(delay_ms);
    timer.deadline_ms.store(deadline, Ordering::Release);
    timer.woken.store(false, Ordering::Release);
    timer.active.store(true, Ordering::Release);
    0
}

/// Cancel an active timer (stop it without destroying).
pub fn timer_cancel(fd: i32) -> i32 {
    let timer = match owned_timer(fd) {
        Ok(t) => t,
        Err(e) => return e,
    };
    timer.active.store(false, Ordering::Release);
    timer.woken.store(false, Ordering::Release);
    0
}

/// Destroy a timer and free its slot.
pub fn timer_destroy(fd: i32) -> i32 {
    let timer = match owned_timer(fd) {
        Ok(t) => t,
        Err(e) => return e,
    };
    timer.active.store(false, Ordering::Release);
    timer.woken.store(false, Ordering::Release);
    timer.owner.store(NO_MODULE, Ordering::Release);
    timer.allocated.store(false, Ordering::Release);
    0
}

/// The kernel's side of "a timer is an fd": service every armed timer once
/// per pacing pass. An expired timer whose owner has not yet been woken for
/// this arming latches the owner's wake bit — exactly what `event_signal`
/// does for an event — so a wake pass runs it and it finds
/// `POLL_IN`. Bounded scan of `MAX_TIMERS` slots; the woken latch makes a
/// fire an edge, not a level.
///
/// Returns the milliseconds until the earliest armed timer OWNED BY
/// `domain_id` that has not yet fired, so that domain's pacer can bound its
/// sleep to it — a timer is serviced when it fires, not at the adaptive
/// backstop. `None` when the domain has no pending armed timer, meaning
/// nothing bounds its sleep. Firing is domain-blind and the deadline is not:
/// whichever domain pumps first latches the owner's wake bit, but only the
/// owner's own domain shortens its sleep for it, so a sibling domain's
/// 5 ms timer cannot drag this one off its backstop.
pub fn timer_pump(domain_id: u8) -> Option<u32> {
    let now = now_ms();
    let mut earliest: Option<u32> = None;
    for timer in timers().iter() {
        if !timer.allocated.load(Ordering::Acquire) || !timer.active.load(Ordering::Acquire) {
            continue;
        }
        let owner = timer.owner.load(Ordering::Acquire) as usize;
        if owner == usize::from(NO_MODULE) {
            continue;
        }
        let deadline = timer.deadline_ms.load(Ordering::Acquire);
        let delta = deadline.wrapping_sub(now) as i32;
        if delta <= 0 {
            if !timer.woken.swap(true, Ordering::AcqRel) {
                let _ = event::latch_module_wake(owner);
            }
            continue;
        }
        if crate::kernel::exec::scheduler::module_domain_id(owner) != domain_id {
            continue;
        }
        let remaining = delta as u32;
        earliest = Some(earliest.map_or(remaining, |e| e.min(remaining)));
    }
    earliest
}

/// Non-destructive readiness of a timer the calling module owns: the timer
/// contract's `HANDLE_POLL`.
pub fn timer_poll(fd: i32, events: u32) -> i32 {
    match owned_timer(fd) {
        Ok(t) if events & crate::abi::kernel_abi::poll::IN != 0 && timer_is_expired(t) => {
            crate::abi::kernel_abi::poll::IN as i32
        }
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// Non-destructive check: has this timer expired?
fn timer_is_expired(timer: &TimerSlot) -> bool {
    if !timer.active.load(Ordering::Acquire) {
        return false;
    }
    let deadline = timer.deadline_ms.load(Ordering::Acquire);
    let now = now_ms();
    // Wrapping-safe: (now - deadline) as signed >= 0 means expired
    (now.wrapping_sub(deadline) as i32) >= 0
}

/// Release all timer slots owned by a specific module. Called on module finish.
pub fn release_timers_owned_by(module_idx: ModuleId) {
    for timer in timers().iter() {
        if !timer.allocated.load(Ordering::Acquire) {
            continue;
        }
        if timer.owner.load(Ordering::Acquire) != module_idx {
            continue;
        }
        timer.active.store(false, Ordering::Release);
        timer.woken.store(false, Ordering::Release);
        timer.owner.store(NO_MODULE, Ordering::Release);
        timer.allocated.store(false, Ordering::Release);
    }
}

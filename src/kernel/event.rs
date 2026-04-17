//! Kernel event subsystem — signalable/pollable notification objects.
//!
//! Events are the universal wake mechanism for modules. An event is a
//! single-bit flag that can be signaled (from any context, including ISR)
//! and polled (non-blocking, clears on read).
//!
//! Device-specific bindings (e.g. GPIO edge -> event) are handled by the
//! respective device providers, not here. Providers call `event_signal()`
//! when their hardware condition fires.
//!
//! The scheduler checks `EVENT_WAKE_PENDING` and steps only the affected
//! modules via `step_woken_modules()`, providing intra-tick wake response.

use portable_atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::kernel::errno;
use crate::kernel::hal;

/// Maximum concurrent events across all modules.
pub const MAX_EVENTS: usize = 32;

// ============================================================================
// Event slot
// ============================================================================

struct EventSlot {
    /// Whether this slot is allocated.
    allocated: AtomicBool,
    /// The signaled flag — set by signal(), cleared by poll().
    signaled: AtomicBool,
    /// Owning module index (0..MAX_MODULES-1), or 0xFF if unowned.
    owner: AtomicU8,
}

impl EventSlot {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            signaled: AtomicBool::new(false),
            owner: AtomicU8::new(0xFF),
        }
    }
}

// ============================================================================
// Static state
// ============================================================================

static EVENT_SLOTS: [EventSlot; MAX_EVENTS] = [const { EventSlot::new() }; MAX_EVENTS];

/// One bit per module (MAX_MODULES=64 fits in u64).
/// Set when any owned event is signaled.
/// Scheduler reads + clears atomically via swap(0).
static EVENT_WAKE_PENDING: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Ownership validation
// ============================================================================

/// Check that the event handle is valid, allocated, and owned by the calling module.
/// Returns Ok(&EventSlot) on success, Err(errno) on failure.
fn check_event_access(handle: i32) -> Result<&'static EventSlot, i32> {
    if handle < 0 || handle as usize >= MAX_EVENTS {
        return Err(errno::EINVAL);
    }
    let slot = &EVENT_SLOTS[handle as usize];
    if !slot.allocated.load(Ordering::Acquire) {
        return Err(errno::EINVAL);
    }
    let owner = slot.owner.load(Ordering::Acquire);
    let caller = crate::kernel::scheduler::current_module_index() as u8;
    if owner != 0xFF && owner != caller {
        return Err(errno::EINVAL);
    }
    Ok(slot)
}

// ============================================================================
// Core event operations
// ============================================================================

/// Create a new event owned by the currently executing module.
/// Returns event handle (slot index, >=0) or negative errno.
pub fn event_create() -> i32 {
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    for i in 0..MAX_EVENTS {
        if EVENT_SLOTS[i]
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            EVENT_SLOTS[i].signaled.store(false, Ordering::Release);
            EVENT_SLOTS[i].owner.store(owner, Ordering::Release);
            return i as i32;
        }
    }
    errno::ENOMEM
}

/// Signal an event. Safe to call from any context (module step, poll, ISR).
///
/// Sets the signaled flag, marks the owning module for wake, and pokes
/// the scheduler signal so it can break out of its timer sleep.
pub fn event_signal(handle: i32) -> i32 {
    if handle < 0 || handle as usize >= MAX_EVENTS {
        return errno::EINVAL;
    }
    let slot = &EVENT_SLOTS[handle as usize];
    if !slot.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    slot.signaled.store(true, Ordering::Release);
    let owner = slot.owner.load(Ordering::Relaxed);
    if (owner as usize) < crate::kernel::config::MAX_MODULES {
        EVENT_WAKE_PENDING.fetch_or(1u64 << owner as u64, Ordering::Release);
    }
    hal::wake_scheduler();
    0
}

/// Minimal ISR-safe signal path. No validation beyond bounds check.
/// Called at most once per ISR entry (coalesced), not per-pin.
///
/// # Safety
/// Caller must ensure handle is a valid, allocated event slot.
pub fn event_signal_from_isr(handle: i32) {
    if handle < 0 || handle as usize >= MAX_EVENTS {
        return;
    }
    let slot = &EVENT_SLOTS[handle as usize];
    slot.signaled.store(true, Ordering::Release);
    let owner = slot.owner.load(Ordering::Relaxed);
    if (owner as usize) < crate::kernel::config::MAX_MODULES {
        EVENT_WAKE_PENDING.fetch_or(1u64 << owner as u64, Ordering::Release);
    }
    hal::wake_scheduler();
}

/// Poll an event (non-blocking). Clears the signaled flag atomically.
/// Returns: 1 if was signaled (now cleared), 0 if not signaled, <0 on error.
/// Only the owning module may poll its events.
pub fn event_poll(handle: i32) -> i32 {
    let slot = match check_event_access(handle) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if slot.signaled.swap(false, Ordering::AcqRel) {
        1
    } else {
        0
    }
}

/// Non-destructive peek: check if an event is signaled without clearing it.
/// Used by `fd_poll` for unified readiness checks.
pub fn event_is_signaled(handle: i32) -> bool {
    if handle < 0 || handle as usize >= MAX_EVENTS {
        return false;
    }
    let slot = &EVENT_SLOTS[handle as usize];
    if !slot.allocated.load(Ordering::Acquire) {
        return false;
    }
    slot.signaled.load(Ordering::Acquire)
}

/// Destroy an event and free its slot.
/// Only the owning module may destroy its events.
/// Note: Device-specific cleanup (e.g. GPIO edge unbinding) is the
/// responsibility of the device provider, not the event subsystem.
pub fn event_destroy(handle: i32) -> i32 {
    let slot = match check_event_access(handle) {
        Ok(s) => s,
        Err(e) => return e,
    };
    slot.signaled.store(false, Ordering::Release);
    slot.owner.store(0xFF, Ordering::Release);
    slot.allocated.store(false, Ordering::Release);
    0
}

// ============================================================================
// Scheduler interface
// ============================================================================

/// Atomically read and clear the wake-pending bitmask.
/// Returns a u64 where bit N is set if module N has pending events.
pub fn take_wake_pending() -> u64 {
    EVENT_WAKE_PENDING.swap(0, Ordering::AcqRel)
}

/// Release all events owned by a specific module. Called on module finish.
/// Note: Device providers (GPIO etc.) clean up their own bindings via
/// their own release_owned_by — this only frees event slots.
pub fn release_owned_by(module_idx: u8) {
    for i in 0..MAX_EVENTS {
        let slot = &EVENT_SLOTS[i];
        if !slot.allocated.load(Ordering::Acquire) {
            continue;
        }
        if slot.owner.load(Ordering::Acquire) != module_idx {
            continue;
        }
        slot.signaled.store(false, Ordering::Release);
        slot.owner.store(0xFF, Ordering::Release);
        slot.allocated.store(false, Ordering::Release);
    }
}

/// Clear all event slots. Called on graph teardown / reload.
/// Device providers must clear their own bindings before calling this.
pub fn reset_all() {
    for i in 0..MAX_EVENTS {
        let slot = &EVENT_SLOTS[i];
        if slot.allocated.load(Ordering::Acquire) {
            slot.signaled.store(false, Ordering::Release);
            slot.owner.store(0xFF, Ordering::Release);
            slot.allocated.store(false, Ordering::Release);
        }
    }
    EVENT_WAKE_PENDING.store(0, Ordering::Release);
}

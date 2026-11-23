//! Critical-section implementation for the Cortex-M targets.
//!
//! `portable_atomic::AtomicU64` has no native instruction on ARMv6-M or on
//! ARMv8-M without the 64-bit atomics extension, so it falls back to a
//! critical section — and something has to provide one.
//!
//! Declared here rather than taken from whichever dependency happens to
//! supply one, so the 64-bit atomics have a named owner. A missing
//! implementation surfaces as a compile error about `AtomicU64` not
//! existing, several layers from the cause.
//!
//! A section masks the local core's interrupts (the PRIMASK save/restore
//! `arch::cortex_m` already has) and then takes one lock between the cores
//! ([`super::core_lock`]), so a section on one core excludes both that
//! core's handlers and the other core. Restoring the previous mask rather
//! than unconditionally enabling is what makes it safe to nest: an inner
//! section inside an outer one must leave the mask set on the way out, and
//! it takes the lock no second time: the outermost section holds it.
//!
//! The lock word is a static, in main SRAM, where the two cores' exclusive
//! accesses are arbitrated.

use critical_section::RawRestoreState;

struct CortexMCriticalSection;
critical_section::set_impl!(CortexMCriticalSection);

/// The lock every critical section on either core holds.
static LOCK: super::core_lock::CoreLock = super::core_lock::CoreLock::new();

/// Restore-state bit: interrupts were already masked when the section was
/// entered.
const WAS_MASKED: RawRestoreState = 1 << 0;
/// Restore-state bit: this section took the lock, and releases it.
const TOOK_LOCK: RawRestoreState = 1 << 1;

/// Critical sections entered at the outermost level since boot, on either
/// core: the times the lock between the cores was taken.
pub fn outermost_sections() -> u32 {
    LOCK.taken()
}

/// Give up the lock between the cores on behalf of `core`, which has stopped
/// for good (it faulted, or the other core reset it) and may have stopped
/// inside a section. What that section was updating is left as it was; the
/// caller is on its way to a report or a reset and needs the other core's
/// sections to end.
pub fn abandon(core: u32) {
    LOCK.abandon(core);
}

// SAFETY: `acquire` masks this core's interrupts, then takes the lock unless
// this core already holds it, and reports both facts; `release` gives the
// lock back if this section took it and restores exactly the mask it found.
// The pair is balanced by the `critical_section` API's own contract, and
// both restores are conditional so nesting cannot open an outer section
// early. The lock is only ever held with interrupts masked, so a handler on
// the holding core never finds it taken by the code it interrupted.
unsafe impl critical_section::Impl for CortexMCriticalSection {
    unsafe fn acquire() -> RawRestoreState {
        let was_masked = super::cortex_m::primask_is_active();
        // SAFETY: the matching `release` restores this.
        unsafe { super::cortex_m::disable_interrupts() };
        let took = LOCK.acquire(crate::platform::chip::core_id() as u32);
        // The restore state is a u8 rather than a bool: Cargo unifies
        // features across the build, and every crate in it
        // selects that width. Only one implementation is ever linked, but
        // both must name the same type.
        (if was_masked { WAS_MASKED } else { 0 }) | (if took { TOOK_LOCK } else { 0 })
    }

    unsafe fn release(state: RawRestoreState) {
        if state & TOOK_LOCK != 0 {
            LOCK.release();
        }
        if state & WAS_MASKED == 0 {
            // SAFETY: interrupts were enabled when this section was entered,
            // so re-enabling them is exactly the caller's prior state.
            unsafe { super::cortex_m::enable_interrupts() };
        }
    }
}

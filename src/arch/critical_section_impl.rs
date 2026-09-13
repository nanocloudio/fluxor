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
//! The implementation is the PRIMASK save/restore `arch::cortex_m` already
//! has. Restoring the previous mask rather than unconditionally enabling is
//! what makes it safe to nest — an inner section inside an outer one must
//! leave the mask set on the way out.

use critical_section::RawRestoreState;

struct CortexMCriticalSection;
critical_section::set_impl!(CortexMCriticalSection);

// SAFETY: `acquire` masks interrupts and reports whether they were already
// masked; `release` restores exactly that state. The pair is balanced by the
// `critical_section` API's own contract, and the restore is conditional so
// nesting cannot open an outer section early.
unsafe impl critical_section::Impl for CortexMCriticalSection {
    unsafe fn acquire() -> RawRestoreState {
        let was_masked = super::cortex_m::primask_is_active();
        // SAFETY: the matching `release` restores this.
        unsafe { super::cortex_m::disable_interrupts() };
        // The restore state is a u8 rather than a bool: Cargo unifies
        // features across the build, and every crate in it
        // selects that width. Only one implementation is ever linked, but
        // both must name the same type.
        u8::from(was_masked)
    }

    unsafe fn release(was_masked: RawRestoreState) {
        if was_masked == 0 {
            // SAFETY: interrupts were enabled when this section was entered,
            // so re-enabling them is exactly the caller's prior state.
            unsafe { super::cortex_m::enable_interrupts() };
        }
    }
}

//! KernelGuard — cross-platform critical section abstraction.
//!
//! Provides a drop-based RAII guard that disables interrupts on entry and
//! restores them on drop. On single-core targets (RP2040, RP2350) this is
//! a simple interrupt disable/enable. On aarch64 (BCM2712) it masks IRQs
//! via DAIF.
//!
//! Usage:
//! ```ignore
//! let _guard = KernelGuard::acquire();
//! // critical section — interrupts disabled
//! // automatically restored when _guard drops
//! ```

/// RAII guard that holds a critical section.
///
/// Interrupts are disabled when the guard is created and restored to their
/// prior state when the guard is dropped. Nesting is safe — the innermost
/// drop restores the state saved by the outermost acquire.
pub struct KernelGuard {
    /// Saved interrupt state (PRIMASK on Cortex-M, DAIF on aarch64).
    _saved: u32,
}

impl KernelGuard {
    /// Enter a critical section by disabling interrupts.
    ///
    /// Returns a guard whose Drop impl restores the prior interrupt state.
    #[inline(always)]
    pub fn acquire() -> Self {
        let saved = disable_interrupts();
        Self { _saved: saved }
    }
}

impl Drop for KernelGuard {
    #[inline(always)]
    fn drop(&mut self) {
        restore_interrupts(self._saved);
    }
}

// ============================================================================
// Platform-specific interrupt control
// ============================================================================

/// Disable interrupts and return the prior state.
#[cfg(feature = "rp")]
#[inline(always)]
fn disable_interrupts() -> u32 {
    let primask: u32;
    unsafe {
        core::arch::asm!(
            "mrs {}, PRIMASK",
            "cpsid i",
            out(reg) primask,
            options(nomem, nostack, preserves_flags),
        );
    }
    primask
}

/// Restore interrupt state saved by disable_interrupts.
#[cfg(feature = "rp")]
#[inline(always)]
fn restore_interrupts(saved: u32) {
    unsafe {
        core::arch::asm!(
            "msr PRIMASK, {}",
            in(reg) saved,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Disable IRQs and return the prior DAIF state.
#[cfg(feature = "chip-bcm2712")]
#[inline(always)]
fn disable_interrupts() -> u32 {
    let daif: u32;
    unsafe {
        core::arch::asm!(
            "mrs {0:x}, daif",
            "msr daifset, #2",
            out(reg) daif,
            options(nomem, nostack, preserves_flags),
        );
    }
    daif
}

/// Restore DAIF state saved by disable_interrupts.
#[cfg(feature = "chip-bcm2712")]
#[inline(always)]
fn restore_interrupts(saved: u32) {
    unsafe {
        core::arch::asm!(
            "msr daif, {0:x}",
            in(reg) saved,
            options(nomem, nostack, preserves_flags),
        );
    }
}

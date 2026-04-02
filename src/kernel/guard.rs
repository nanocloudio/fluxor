//! KernelGuard — cross-platform critical section abstraction.
//!
//! Provides a drop-based RAII guard that disables interrupts on entry and
//! restores them on drop. Platform-specific interrupt control is delegated
//! to the HAL function pointer table — no cfg blocks here.
//!
//! Usage:
//! ```ignore
//! let _guard = KernelGuard::acquire();
//! // critical section — interrupts disabled
//! // automatically restored when _guard drops
//! ```

use crate::kernel::hal;

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
        let saved = hal::disable_interrupts();
        Self { _saved: saved }
    }
}

impl Drop for KernelGuard {
    #[inline(always)]
    fn drop(&mut self) {
        hal::restore_interrupts(self._saved);
    }
}

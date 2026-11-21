//! Chip abstraction layer — WASM target.
//!
//! No real silicon; the kernel runs as a wasm32 module instantiated
//! by a host (browser, wasmtime, edge runtime). Kernel capacity is
//! stated per kernel platform in `kernel::config` (`profile_wasm`).
//!
//! See `docs/architecture/wasm_platform.md` for the platform model
//! and the per-host docs (`wasm_browser_host.md`,
//! `wasm_wasmtime_host.md`) for the surrounding shim layout.

/// Default step deadline: 2 ms.
pub const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// Default budget of one interrupt-mode step, in this target's cycle
/// counter (`hal::read_cycle_count`).
pub const DEFAULT_ISR_BUDGET_CYCLES: u32 = 2000;

/// Size the kernel's tables from the boot plan (`size`): this platform keeps
/// no tables of its own and plans no memory around them.
///
/// # Safety
/// Graph preparation: no module runs and nothing holds a reference into
/// any of the tables.
pub unsafe fn plan_tables(
    size: impl FnOnce() -> Result<(), crate::kernel::sys::resource_ledger::Refused>,
) -> Result<(), crate::kernel::sys::resource_ledger::Refused> {
    size()
}

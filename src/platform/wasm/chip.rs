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

//! Chip abstraction layer — WASM target.
//!
//! No real silicon; the kernel runs as a wasm32 module instantiated by
//! a host (browser, wasmtime, edge runtime). Arena sizes mirror the
//! Linux host since both target user-space-class memory budgets.
//!
//! See `docs/architecture/wasm_platform.md` for the platform model and
//! the per-host docs (`wasm_browser_host.md`, `wasm_wasmtime_host.md`)
//! for the surrounding shim layout.

pub const STATE_ARENA_SIZE: usize = 4 * 1024 * 1024;
pub const BUFFER_ARENA_SIZE: usize = 1024 * 1024;
pub const MAX_MODULE_CONFIG_SIZE: usize = 32 * 1024;
pub const CONFIG_ARENA_SIZE: usize = 64 * 1024;

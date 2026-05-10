//! Chip abstraction layer — WASM target.
//!
//! No real silicon; the kernel runs as a wasm32 module instantiated
//! by a host (browser, wasmtime, edge runtime). Capacity tunables
//! are centralised in `abi::config::kernel` (the `profile_wasm`
//! module); this file is a thin re-export shim.
//!
//! See `docs/architecture/wasm_platform.md` for the platform model
//! and the per-host docs (`wasm_browser_host.md`,
//! `wasm_wasmtime_host.md`) for the surrounding shim layout.

pub use crate::abi::config::kernel::{
    BUFFER_ARENA_SIZE, CONFIG_ARENA_SIZE, MAX_MODULE_CONFIG_SIZE, STATE_ARENA_SIZE,
};

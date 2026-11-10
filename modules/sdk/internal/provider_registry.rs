// Internal: provider registration (kernel-private, unstable).
//
// Layer: internal.
//
// HAL-contract providers (PWM, SPI, I2C, PIO, UART, ADC) are registered
// by the loader, driven by two well-known module exports:
//   - `module_provides_contract() -> u32`   — contract id
//   - `module_provider_dispatch(state, handle, op, arg, len) -> i32`
//     — dispatch entry point
// The loader resolves both after `module_new()` returns Ready and
// calls `provider::register_module_provider()` directly — no runtime
// syscall is involved. Modules that aren't providers simply omit
// `module_provides_contract`.
//
// One service registration uses a runtime enable opcode below. It binds
// a kernel-internal dispatcher whose per-module state is pinned into a
// kernel-held pointer (not the common provider-chain mechanism): the
// flash parameter store.

/// Register flash store dispatch function. Called by flash module on init.
/// handle=-1, arg=[export_hash:u32 LE] (4 bytes). Kernel resolves the
/// hash against the module's export table to get the dispatch address.
/// Returns 0 or negative errno.
pub use super::super::registry::provider_registry::FLASH_STORE_ENABLE;

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
// Two service registrations still use runtime enable opcodes below.
// They bind kernel-internal dispatchers whose per-module state needs
// to be pinned into a kernel-held pointer (not the common
// provider-chain mechanism): the flash parameter store, and the
// demand-paged-arena backing provider.

/// Register flash store dispatch function. Called by flash module on init.
/// handle=-1, arg=[export_hash:u32 LE] (4 bytes). Kernel resolves the
/// hash against the module's export table to get the dispatch address.
/// Returns 0 or negative errno.
pub const FLASH_STORE_ENABLE: u32 = 0x0C37;

/// Register a driver module as the paged-arena backing-store provider.
/// handle=-1, arg=[fn_addr:u32 LE] — FNV-1a hash of the exported
/// dispatch symbol (or raw function address, resolved module-local).
/// The kernel stores `(dispatch, state)` and routes pager read/write
/// for arenas registered with `BackingType::External`. See
/// `src/kernel/internal/backing_provider.rs` for the dispatch contract
/// (op constants + arg layout). Returns 0 or negative errno.
pub const BACKING_PROVIDER_ENABLE: u32 = 0x0CED;

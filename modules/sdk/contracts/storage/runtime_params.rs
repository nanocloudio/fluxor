// Contract: runtime_params — persistent module parameter overrides.
//
// Layer: contracts/storage (public, stable).
//
// This file defines only the PARAM_STORE / PARAM_DELETE / PARAM_CLEAR_ALL
// syscall opcodes — the storage-medium-neutral surface for module
// parameter persistence. Flash layout (offset, sector size, on-flash
// magic/version) is platform-specific and lives in
// `platform/<chip>/flash_layout.rs`. For RP: see
// `platform::rp::flash_layout::PARAM_STORE_*`.
//
// Log-structured append with TLV entries scoped per (module_id, tag).
// At boot, the platform layer merges matching overrides into compiled
// params before each module's `module_new()`. Overrides persist across
// reboots.

/// Store a runtime parameter override (persists across reboots).
/// handle=-1, arg=[tag:u8, value_bytes...], arg_len=1+value_len.
/// Scoped to current module instance. Returns 0 or negative errno.
pub const STORE: u32 = 0x0C34;
/// Delete a runtime parameter override (reverts to compiled default).
/// handle=-1, arg=[tag:u8], arg_len=1.
/// Scoped to current module instance. Returns 0 or negative errno.
pub const DELETE: u32 = 0x0C35;
/// Clear all runtime overrides for current module (arg_len=0) or
/// global factory reset (arg[0]=0xFF). handle=-1.
pub const CLEAR_ALL: u32 = 0x0C36;

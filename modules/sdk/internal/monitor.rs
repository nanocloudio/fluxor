// Internal: fault / diagnostics / scheduler monitoring.
//
// Layer: internal (unstable, kernel-private).
//
// Consumed only by the monitor / debug PIC modules. Not part of the
// public ABI — the opcode numbers may change.

/// Subscribe to fault events. handle=event_handle (or -1 to unsubscribe).
/// Kernel signals the event whenever any module faults. Only one subscriber.
pub const FAULT_MONITOR_SUBSCRIBE: u32 = 0x0C52;
/// Pop the next fault record from the fault ring.
/// handle=-1, arg=12-byte output buffer (FaultRecord layout).
/// Returns 1 if a record was copied, 0 if empty, negative on error.
pub const FAULT_MONITOR_POP: u32 = 0x0C53;
/// Query per-module fault stats. handle=module_idx, arg=12-byte output
/// buffer (FaultStats layout). Returns 0 or negative errno.
pub const FAULT_STATS_QUERY: u32 = 0x0C54;
/// Query step timing histogram. handle=module_idx (or -1 for global),
/// arg=output buffer of 8*u32 (bucket counts). Returns 0 or errno.
pub const STEP_HISTOGRAM_QUERY: u32 = 0x0C55;
/// Raise a fault against a module. handle=-1,
/// arg=[module_idx:u8, fault_kind:u8]. Fault kinds mirror
/// `step_guard::fault_type::*` (TIMEOUT=1, STEP_ERROR=2, HARD_FAULT=3,
/// MPU_FAULT=4, DRAIN_TIMEOUT=5). Returns 0 or -errno.
pub const FAULT_RAISE: u32 = 0x0C56;

/// Query arena memory usage. handle=-1.
/// Returns (used_bytes: u16, total_bytes: u16) packed as u32:
/// (used << 16) | total.
pub const ARENA_USAGE: u32 = 0x0C32;

/// Get paged arena statistics. handle=-1, arg=24-byte output buffer.
/// Returns PagedArenaStats struct.
pub const PAGED_ARENA_STATS: u32 = 0x0CF9;

/// Query ISR module metrics. handle=-1, arg=[tier:u8, slot:u8] (2 bytes input).
/// On success, writes IsrMetrics (24 bytes) to arg buffer.
/// tier: 1=Tier 1b, 2=Tier 2. slot: slot index within tier.
pub const ISR_METRICS: u32 = 0x0CE8;

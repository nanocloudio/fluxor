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
/// Query a module's scheduler-visible state. handle=module_idx,
/// arg=20-byte output buffer. Returns 0 or negative errno.
///
/// This is what settles "why is this module not being stepped?" without
/// inference. The scheduler already tracks every field; until this
/// opcode existed none of them were reachable from a module, so the
/// only evidence available was absence from the step histogram — which
/// is a different question and was being read as this one.
///
/// Output layout (all little-endian):
///
/// ```text
///   [0]      idx: u8
///   [1]      flags: u8    — bit0 present, bit1 ready, bit2 finished
///   [2]      fault_state: u8  — 0 Running, 1 Faulted, 2 Recovering,
///                               3 Terminated
///   [3]      cap_class: u8
///   [4..6]   permissions: u16
///   [6]      step_period: u8  — ticks between steps, 0 = every tick
///   [7]      domain_id: u8
///   [8..10]  restart_count: u16
///   [10..14] inactive_for_ticks: u32 — consecutive ticks the readiness
///                               gate has blocked this module
///   [14..18] slot_generation: u32
///   [18]     name_len: u8 — 0 when the buffer had no room for a name
///   [19]     reserved
///   [20..]   name: name_len bytes — the module's type name
/// ```
///
/// Returns the number of bytes written, so a caller learns the width it
/// actually got rather than assuming the one it asked for. A buffer of
/// exactly `MODULE_STATE_LEN` is valid and yields `name_len = 0`.
///
/// Protection level and trust tier are deliberately absent: the
/// scheduler does not track either per module, and a field invented at
/// the emitter would be a reading nobody could trust.
pub const MODULE_STATE_QUERY: u32 = 0x0C57;

/// The fixed header `MODULE_STATE_QUERY` always writes. A variable
/// name may follow it when the caller's buffer is larger.
pub const MODULE_STATE_LEN: usize = 20;

/// Longest module name the query will copy.
pub const MODULE_STATE_NAME_MAX: usize = 32;

/// Buffer size that always receives the header and a full name.
pub const MODULE_STATE_MAX: usize = MODULE_STATE_LEN + MODULE_STATE_NAME_MAX;

/// `MODULE_STATE_QUERY` flag bits in output byte 1.
pub mod module_state_flags {
    /// The scheduler slot is non-empty.
    pub const PRESENT: u8 = 1 << 0;
    /// The module has signalled `StepOutcome::Ready`.
    pub const READY: u8 = 1 << 1;
    /// The module has finalised (`Done` or terminated).
    pub const FINISHED: u8 = 1 << 2;
}

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

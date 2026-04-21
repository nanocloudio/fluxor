// Internal: live graph reconfigure.
//
// Layer: internal (unstable, kernel-private).
//
// Raw primitives consumed by `modules/foundation/reconfigure`; the
// drain / transition-plan / timeout logic lives in that module. Not
// part of the public ABI.

/// Return the caller's own module index. handle=-1, arg=NULL.
/// Returns the index, or negative errno if the calling context is unknown.
pub const SELF_INDEX: u32 = 0x0C67;
/// Set the current reconfigure phase.
/// handle=-1, arg=[phase:u8]. 0=Running, 1=Draining, 2=Migrating.
pub const SET_PHASE: u32 = 0x0C68;
/// Invoke module_drain() on module N.
/// handle=-1, arg=[module_idx:u8]. Returns module's drain return code, or -1.
pub const CALL_DRAIN: u32 = 0x0C69;
/// Mark module N as finished so the scheduler skips it.
/// handle=-1, arg=[module_idx:u8]. Returns 0.
pub const MARK_FINISHED: u32 = 0x0C6A;
/// Query active module count.
/// handle=-1, arg=NULL. Returns module count (>=0) or negative errno.
pub const MODULE_COUNT: u32 = 0x0C6B;
/// Query module capability flags.
/// handle=-1, arg=[module_idx:u8]. Returns flags bitmask:
///   bit 0 = drain_capable, bit 1 = deferred_ready,
///   bit 2 = mailbox_safe,  bit 3 = in_place_writer.
pub const MODULE_INFO: u32 = 0x0C6C;
/// Request a graph rebuild. The main loop consumes this after the
/// current step_modules returns.
/// handle=-1, arg=[config_ptr:usize, config_len:usize] (platform pointer size).
/// Returns 0.
pub const TRIGGER_REBUILD: u32 = 0x0C6D;
/// Query the upstream-module bitmask for module N (for topological drain ordering).
/// handle=-1, arg=[module_idx:u8]. Returns upstream mask as i32 (cast from u32).
pub const MODULE_UPSTREAM: u32 = 0x0C6E;
/// Query whether module N has returned StepOutcome::Done (finished).
/// handle=-1, arg=[module_idx:u8]. Returns 1 if finished, 0 otherwise.
pub const MODULE_DONE: u32 = 0x0C6F;

// Contract: paged_arena — demand-paged memory arenas.
//
// Layer: contracts/storage (public, stable).
//
// The core paged-arena query/prefault primitives live in `kernel_abi`
// (`PAGED_ARENA_GET`, `PAGED_ARENA_PREFAULT`). This file carries the
// generic backing-arena registration/read/write contract. Backing
// storage comes from one of: zero-fill (`None`), a built-in RAM page
// array (`RamDisk`), or a driver module that has registered via
// `BACKING_PROVIDER_ENABLE` (`External`) — the kernel does not name
// specific devices. The driver (NVMe, SD card, eMMC, raw flash, …)
// interprets an abstract page-granular base index in its own
// addressing space. See `internal/provider_registry.rs` for the
// registration hook.

/// Register a backing-store arena for the calling module. Module
/// index is taken from the scheduler's `current_module_index`; an
/// arena id is returned. Used by test modules to exercise the
/// generic backing-provider chain without needing the full paged-arena
/// config pipeline.
/// handle=-1, arg=[virtual_pages:u32 LE, resident_max:u32 LE,
///                 backing_type:u8 (0=None,1=RamDisk,2=External),
///                 writeback:u8 (0=Deferred,1=WriteThrough)] (10 bytes).
/// Returns arena_id (>=0) or negative errno.
pub const ARENA_REGISTER: u32 = 0x0CEE;
/// Read one 4 KB page from a registered arena into `buf`.
/// handle=-1, arg=[arena_id:u8, _pad:u8, vpage_idx:u32 LE,
///                 buf_ptr:u64 LE] (14 bytes). Returns 0 or errno.
pub const ARENA_READ: u32 = 0x0CEF;
/// Write one 4 KB page from `buf` to a registered arena.
/// Same arg shape as ARENA_READ.
pub const ARENA_WRITE: u32 = 0x0CFE;
/// Flush any pending writes for a registered arena.
/// handle=-1, arg=[arena_id:u8] (1 byte). Returns 0 or errno.
pub const ARENA_FLUSH: u32 = 0x0CFF;

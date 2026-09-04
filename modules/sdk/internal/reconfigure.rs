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
/// Query the upstream-module bitmask for module N (for topological drain
/// ordering). handle=-1, arg layout: in `[module_idx:u8]`, out
/// `[mask word u64 LE × W]` (low word first). The kernel writes
/// `W = min(MODULE_MASK_WORDS, (arg_len - 1) / 8)` words and returns the
/// kernel's full word count (positive), so a caller can detect a buffer
/// narrower than the mask. Pass `arg_len >= 1 + 8 × 4` to cover the whole
/// u8 module-index domain (256 modules = 4 words) on every profile.
/// Returns -EINVAL if the arg is null or shorter than one word. Bit `i`
/// of the flattened words means "module `i` is upstream of `module_idx`".
pub const MODULE_UPSTREAM: u32 = 0x0C6E;
/// Query whether module N has returned StepOutcome::Done (finished).
/// handle=-1, arg=[module_idx:u8]. Returns 1 if finished, 0 otherwise.
pub const MODULE_DONE: u32 = 0x0C6F;

// ── Live graph mutation (add owner / free owner) ────────────────────────────
// Splice a self-contained subgraph into a running graph, and tear it down,
// without a destructive rebuild. Add and teardown only: partial
// replacement and migration are not part of this surface.
//
// Wire numbers live in the free 0x0C47..=0x0C4A gap between the kernel core
// primitives (0x0C40..=0x0C46) and the monitor range (0x0C52..=0x0C5F) — a
// dedicated live-mutation block that is deliberately OUTSIDE both the
// peripheral register-bridge range (0x0C70..=0x0CCF: I2C/SPI/ADC/UART/PIO)
// and the monitor-gated 0x0C5x range. They classify as PLATFORM_RAW via the
// permission classifier's catch-all in src/kernel/syscalls.rs.

/// Add a new owner's subgraph to the running graph.
/// handle=-1, arg = bounded binary `AddSubgraph` (magic `FLXA`, version, body,
/// trailing sha256 — same discipline as the composed plan codec). On success
/// the kernel writes the 6-byte `OwnerHandle` (`slot:u16 LE, generation:u32 LE`)
/// into the first 6 bytes of `arg`. Returns 0 on success, negative `AddError`
/// otherwise. NOTE: the on-wire form carries PIC modules (by `name_hash` +
/// params); a target whose PIC load is asynchronous returns `-WouldBlock` until
/// the async-load follow-up lands. In-process callers use `scheduler::apply_add`
/// directly (built-in or already-resident modules).
pub const APPLY_ADD: u32 = 0x0C47;
/// Free an owner: stop its modules, close its edges, reclaim its state, and
/// revoke the handle (the generation guard rejects it thereafter).
/// handle=-1, arg = `[slot:u16 LE, generation:u32 LE]`. Returns 0 on success,
/// negative `FreeError` otherwise.
pub const FREE_OWNER: u32 = 0x0C48;

// ── Owner pause/resume: metal PAUSE as a reversible quiesce verb ─────────────
// The OWNER-level kernel mechanism a 0x1A workload backend or orchestrator
// maps PAUSE/RESUME onto: the admission close and wake masking that drain
// uses, plus the resume re-latch path. In the 0x0C47..=0x0C4A
// live-mutation block
// beside APPLY_ADD/FREE_OWNER — NOT in monitor-gated 0x0C5x, and NOT in the
// peripheral register-bridge range (0x0C70..=0x0CCF).

/// Pause an owner (reversible quiesce): close admission for its subgraph,
/// let in-flight steps complete (no preemption), and mask its wake sources
/// (event signals, wake-on-write latches, cross-domain doorbells) so its
/// graphs stop being stepped. Idempotent; the system owner is refused.
/// handle=-1, arg = `[slot:u16 LE, generation:u32 LE]`. Returns 0 on success,
/// negative `PauseError` otherwise.
pub const OWNER_PAUSE: u32 = 0x0C49;
/// Resume a paused owner: reopen admission and re-latch every wake that
/// arrived while paused (each masked-arrival produces a wake now, exactly
/// once). Idempotent on an Active owner.
/// handle=-1, arg = `[slot:u16 LE, generation:u32 LE]`. Returns 0 on success,
/// negative `PauseError` otherwise.
pub const OWNER_RESUME: u32 = 0x0C4A;

// ── OTA RAM staging (Pi 5 / hosted Linux) ────────────────────────────────────
// The RAM-staged counterpart of the RP flash graph-slot pair: a module
// streams a GRAPH IMAGE (`fluxor build --emit=image`) into the kernel's
// inactive staging buffer, then commits it. Commit validates header,
// payload SHA-256, ABI-surface pin, and epoch monotonicity, then swaps
// loader+config to the staged blobs and fires the rebuild bridge.
// Gated platform_raw via the dev_system catch-all; ENOSYS on targets
// without a RAM staging surface.

/// Stream graph-image bytes into the staging buffer.
/// handle=-1, arg = `[offset: u32 LE][payload bytes]`. `offset == 0`
/// begins a fresh stage; writes advance monotonically — an offset
/// below the staged length is -EINVAL, a forward gap is zero-filled
/// (layered-pull alignment padding). Returns 0 / -EINVAL / -ENOSPC
/// (over capacity) / -ENOSYS (no staging surface).
pub const OTA_STAGE_WRITE: u32 = 0x0C20;
/// Control the staged image. handle=-1, arg = `[cmd: u8]`:
/// 0 COMMIT (validate + activate; 0 / -EINVAL bad header, sha, or
/// populate failure / -EACCES ABI-pin mismatch / -EBUSY epoch not
/// newer than live / -ERROR protect failure), 1 ABORT (discard staged
/// bytes), 2 EPOCH (returns the live epoch, saturated to i32).
pub const OTA_STAGE_CTRL: u32 = 0x0C21;

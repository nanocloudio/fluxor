// Internal: live graph reconfigure.
//
// Layer: internal (unstable, kernel-private).
//
// Raw primitives consumed by `modules/foundation/reconfigure`; the
// drain / transition-plan / timeout logic lives in that module. Not
// part of the public ABI.

/// Invoke module_drain() on module N.
/// handle=-1, arg=[module_idx:u16 LE]. Returns module's drain return code, or -1.
pub use super::super::registry::reconfigure::CALL_DRAIN;
/// Mark module N as finished so the scheduler skips it.
/// handle=-1, arg=[module_idx:u16 LE]. Returns 0.
pub use super::super::registry::reconfigure::MARK_FINISHED;
/// Query active module count.
/// handle=-1, arg=NULL. Returns module count (>=0) or negative errno.
pub use super::super::registry::reconfigure::MODULE_COUNT;
/// Query whether module N has returned StepOutcome::Done (finished).
/// handle=-1, arg=[module_idx:u16 LE]. Returns 1 if finished, 0 otherwise.
pub use super::super::registry::reconfigure::MODULE_DONE;
/// Query module capability flags.
/// handle=-1, arg=[module_idx:u16 LE]. Returns flags bitmask:
///   bit 0 = drain_capable, bit 1 = deferred_ready,
///   bit 2 = mailbox_safe,  bit 3 = in_place_writer.
pub use super::super::registry::reconfigure::MODULE_INFO;
/// Query a window of the upstream-module bitmask for module N (for
/// topological drain ordering). handle=-1, arg layout: in
/// `[module_idx:u16 LE][first_word:u16 LE]`, out `[mask word u64 LE × W]`
/// from offset 4, starting at mask word `first_word` (bit `i` of word `w`
/// means "module `64·w + i` is upstream of `module_idx`"). The kernel writes
/// `W = min(total - first_word, (arg_len - 4) / 8)` words and returns its
/// full word count `total` (positive), so a caller reads the mask in windows
/// of any width and knows where it ends; a `first_word` at or past `total`
/// writes nothing. Returns -EINVAL if the arg is null or shorter than one
/// word.
pub use super::super::registry::reconfigure::MODULE_UPSTREAM;
/// Set the current reconfigure phase.
/// handle=-1, arg=[phase:u8]. 0=Running, 1=Draining, 2=Migrating.
pub use super::super::registry::reconfigure::SET_PHASE;
/// Query the kernel's module-slot capacity: one past the highest module
/// index this kernel can hold. handle=-1, arg=NULL. Returns the count
/// (positive).
///
/// Kernel capacity is not ABI: the figure is per kernel platform and may be
/// raised without moving the ABI surface, so a module that keeps per-slot
/// state sizes it from this answer at runtime and never from a compiled
/// constant. Gated by the `reconfigure` permission.
pub use super::super::registry::reconfigure::SLOT_CAPACITY;
/// Request a graph rebuild. The main loop consumes this after the
/// current step_modules returns.
/// handle=-1, arg=[config_ptr:usize, config_len:usize] (platform pointer size).
/// Returns 0.
pub use super::super::registry::reconfigure::TRIGGER_REBUILD;

// ── Live graph mutation (add owner / free owner) ────────────────────────────
// Splice a self-contained subgraph into a running graph, and tear it down,
// without a destructive rebuild. Add and teardown only: partial
// replacement and migration are not part of this surface.
//
// They require `platform_raw` (the registry's permission for them).

/// Add a new owner's subgraph to the running graph.
/// handle=-1, arg = bounded binary `AddSubgraph` (magic `FLXA`, version,
/// flags, body; validated for structure and bounds — the channel, not the
/// blob, is authenticated). On success the kernel writes the 6-byte
/// `OwnerHandle` (`slot:u16 LE, generation:u32 LE`) into the first 6 bytes of
/// `arg`. Returns 0 on success, a negative errno otherwise. The on-wire form
/// carries PIC modules (by `name_hash` + params), each loaded within the
/// call: a module whose load cannot complete synchronously refuses the add
/// `EAGAIN`. In-process callers use `scheduler::apply_add` directly (built-in
/// or already-resident modules).
pub use super::super::registry::reconfigure::APPLY_ADD;
/// `AddSubgraph` header flag: the new owner acts with its creator's
/// authority. Honoured only from the module syscall, and only when the
/// calling module acts with the node's authority: the owner then reaches the
/// node's provider layers and the platform's storage as the node does, while
/// it is still freed, paused, charged and released as an owner of its own.
/// A workload caller is refused `EACCES`; any other path that decodes an
/// `AddSubgraph` (a workload `CREATE`, a boot graph) refuses the flag
/// `EINVAL`, as it refuses every undefined flag bit.
pub const ADD_FLAG_CREATOR_AUTHORITY: u16 = 0x0001;
/// Free an owner: stop its modules, close its edges, reclaim its state, and
/// revoke the handle (the generation guard rejects it thereafter).
/// handle=-1, arg = `[slot:u16 LE, generation:u32 LE]`. Returns 0 on success,
/// -1 for the system owner, -2 for a handle that no longer resolves, and -3
/// for an owner still being added (its add publishes or rolls it back).
pub use super::super::registry::reconfigure::FREE_OWNER;

// ── Owner pause/resume: metal PAUSE as a reversible quiesce verb ─────────────
// The OWNER-level kernel mechanism a workload backend or orchestrator maps
// PAUSE/RESUME onto: the admission close and wake masking that drain uses,
// plus the resume re-latch path.

/// Pause an owner (reversible quiesce): close admission for its subgraph,
/// let in-flight steps complete (no preemption), and mask its wake sources
/// (event signals, wake-on-write latches, cross-domain doorbells) so its
/// graphs stop being stepped. Idempotent; the system owner is refused.
/// handle=-1, arg = `[slot:u16 LE, generation:u32 LE]`. Returns 0 on success,
/// negative `PauseError` otherwise.
pub use super::super::registry::reconfigure::OWNER_PAUSE;
/// Resume a paused owner: reopen admission and re-latch every wake that
/// arrived while paused (each masked-arrival produces a wake now, exactly
/// once). Idempotent on an Active owner.
/// handle=-1, arg = `[slot:u16 LE, generation:u32 LE]`. Returns 0 on success,
/// negative `PauseError` otherwise.
pub use super::super::registry::reconfigure::OWNER_RESUME;

// ── Owner release: the kernel's notification TO a provider ──────────────────
// Every other opcode in this file travels module → kernel. This one travels
// the other way: the kernel invokes a provider module's
// `module_provider_dispatch` with `OWNER_RELEASED` just before it tears an
// owner down, so the provider can reclaim what it holds on that owner's
// behalf while the owner handle is still valid and the provider is still live.
//
// It is delivered only to providers that opted in by exporting
// `module_observes_owner_release`; a provider that has not is never called
// with this opcode. The kernel ignores the return value — a provider that
// answers `-ENOSYS` is simply one with nothing to release.

/// Notify a provider that `owner` is about to be freed. Delivered before any
/// teardown: the owner's slot/generation still resolve, the provider module's
/// state is still live, and syscalls made from the handler behave normally.
///
/// `handle = -1`; `arg` is the SAME 8-byte owner record that
/// `query_key::CALLER_OWNER` hands back, so a provider that stamped its
/// resources with the caller's owner compares the two without reformatting:
///
/// ```text
///   [slot: u16 LE][reserved: u16 (0)][generation: u32 LE]
/// ```
///
/// Return value is ignored. The handler MUST be bounded: it runs inline on
/// the scheduler thread inside the teardown path, so it releases bookkeeping
/// and hands long work to the provider's own steps.
pub use super::super::registry::reconfigure::OWNER_RELEASED;

/// Byte length of the `OWNER_RELEASED` argument record.
pub const OWNER_RELEASED_ARG_LEN: usize = 8;

// ── OTA RAM staging (Pi 5 / hosted Linux) ────────────────────────────────────
// The RAM-staged counterpart of the RP flash graph-slot pair: a module
// streams a GRAPH IMAGE (`fluxor build --emit=image`) into the kernel's
// inactive staging buffer, then commits it. Commit validates header,
// payload SHA-256, ABI-surface pin, and epoch monotonicity, then swaps
// loader+config to the staged blobs and fires the rebuild bridge.
// Gated platform_raw via the dev_system catch-all; ENOSYS on targets
// without a RAM staging surface.

/// Control the staged image. handle=-1, arg = `[cmd: u8]`:
/// 0 COMMIT (validate + activate; 0 / -EINVAL bad header, sha, or
/// populate failure / -EACCES ABI-pin mismatch / -EBUSY epoch not
/// newer than live / -ERROR protect failure), 1 ABORT (discard staged
/// bytes), 2 EPOCH (returns the live epoch, saturated to i32).
pub use super::super::registry::reconfigure::OTA_STAGE_CTRL;
/// Stream graph-image bytes into the staging buffer.
/// handle=-1, arg = `[offset: u32 LE][payload bytes]`. `offset == 0`
/// begins a fresh stage; writes advance monotonically — an offset
/// below the staged length is -EINVAL, a forward gap is zero-filled
/// (layered-pull alignment padding). Returns 0 / -EINVAL / -ENOSPC
/// (over capacity) / -ENOSYS (no staging surface).
pub use super::super::registry::reconfigure::OTA_STAGE_WRITE;

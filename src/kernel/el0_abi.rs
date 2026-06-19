//! EL0 syscall-gateway ABI — shared, platform-independent definitions for
//! the minimal `SVC #1` channel-mediation surface used by isolated modules.
//!
//! An isolated module runs at EL0 and cannot call the `SyscallTable`
//! function pointers (they are EL1 kernel addresses, unmapped at EL0). The
//! walking-skeleton mediation slice gives it exactly three channel ops via
//! `SVC #1`, each of which the kernel services at EL1 and then `ERET`s back
//! to EL0:
//!
//! Calling convention (module side, `SVC #1`):
//!   x0 = op (`SYS_CHANNEL_*`), x1 = channel handle (i32),
//!   x2 = buffer pointer, x3 = length.  Returns the kernel result in x0.
//!
//! `channel_read` / `channel_write` / `channel_poll` and the per-module heap
//! ops `heap_alloc` / `heap_free` are exposed. Providers, timers and events
//! are deliberately out of this slice (see the architecture doc) — channel
//! I/O plus per-module heap is the highest-value surface with the smallest
//! privilege footprint.
//!
//! Before the kernel dereferences any EL0 pointer, it validates that the
//! whole `[ptr, ptr+len)` range lies inside the calling module's own mapped
//! read/write regions (state / heap / channel buffers / EL0 stack). The
//! range check itself is the pure, host-tested [`buf_within_regions`]; the
//! BCM2712 gateway (`kernel::mmu`'s `el0` submodule) builds the region list
//! from the module's registered regions and calls it.
//!
//! ## Argument / return conventions per op
//!
//! All ops share the register layout `x0 = op`, and the gateway returns a
//! **signed 64-bit** value in `x0`. Channel ops keep their pre-existing
//! signed `i32` errno/byte-count semantics (sign-extended into the 64-bit
//! return). Heap ops use the same register file but a pointer-sized return:
//!
//! | op                | x1     | x2          | x3     | returns (`x0`, `i64`)                       |
//! |-------------------|--------|-------------|--------|---------------------------------------------|
//! | `channel_read`    | handle | buf ptr     | len    | bytes read (≥0) or `-errno`                 |
//! | `channel_write`   | handle | buf ptr     | len    | bytes written (≥0) or `-errno`              |
//! | `channel_poll`    | handle | —           | —      | readable bytes (≥0)                         |
//! | `heap_alloc`      | —      | —           | size   | allocation pointer, or `0` (null) on failure |
//! | `heap_free`       | —      | ptr         | —      | `0` on success/no-op, or `-errno` on reject |
//!
//! The return is `i64` so a heap pointer fits in `x0` without truncation;
//! channel errnos are negative `i32` values sign-extended into it.

/// `SVC #1` op selectors.
pub const SYS_CHANNEL_READ: u64 = 0;
pub const SYS_CHANNEL_WRITE: u64 = 1;
pub const SYS_CHANNEL_POLL: u64 = 2;
/// Allocate from the calling module's own per-module heap. The requested
/// size travels in `x3` (the `len` slot); the allocation pointer is returned
/// in `x0`, or `0` (null) when the heap is exhausted, the module has no heap,
/// or the allocator returned memory outside the module's EL0 heap mapping.
pub const SYS_HEAP_ALLOC: u64 = 3;
/// Free a pointer previously returned by [`SYS_HEAP_ALLOC`]. The pointer
/// travels in `x2` (the `ptr` slot). Returns `0` on success (and for a null
/// pointer, defined as a no-op), or `-EFAULT` if the pointer lies outside the
/// caller's heap mapping. Interior/stale/double-free/malformed pointers that
/// fall *inside* the heap are forwarded to the allocator, which detects and
/// logs them without corrupting kernel state.
pub const SYS_HEAP_FREE: u64 = 4;

/// The `SVC` immediate that selects the syscall gateway (vs `SVC #0`, the
/// module-step return).
pub const SVC_SYSCALL_IMM: u64 = 1;

/// Shared errno-style return values for the gateway, as `i64` so they sit
/// alongside the pointer-sized heap results in `x0` (negative = error).
pub const EL0_EPERM: i64 = -1;
pub const EL0_EFAULT: i64 = -14;
pub const EL0_EINVAL: i64 = -22;

/// Returns `true` iff the entire range `[ptr, ptr+len)` lies within one of
/// the `(base, size)` regions. `len == 0` is always accepted (a degenerate
/// read/write touches nothing). Overflow in `ptr + len` rejects the range.
///
/// This is the load-bearing safety check for the EL0 syscall gateway:
/// validating an untrusted EL0 pointer against the module's *own* mapped
/// regions before the kernel dereferences it, so a compromised or buggy
/// isolated module cannot turn a channel syscall into an arbitrary kernel
/// read/write. Each region must be entirely contained — a range that
/// straddles two adjacent regions is rejected (kept strict on purpose).
pub fn buf_within_regions(ptr: u64, len: usize, regions: &[(u64, u64)]) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = ptr.checked_add(len as u64) else {
        return false; // address-space wraparound
    };
    for &(base, size) in regions {
        if size == 0 {
            continue;
        }
        let Some(region_end) = base.checked_add(size) else {
            continue;
        };
        if ptr >= base && end <= region_end {
            return true;
        }
    }
    false
}

/// The action the `heap_free` gateway path must take for an untrusted EL0
/// pointer, decided *before* the kernel allocator ever touches it. This is
/// the load-bearing safety classification for `SYS_HEAP_FREE`: it confines a
/// hostile pointer to one of three well-defined outcomes so it can never
/// drive an arbitrary kernel read/write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapFreeAction {
    /// Null pointer — defined as a no-op success (mirrors C `free(NULL)`),
    /// returns `0` to EL0. Explicitly *not* an error.
    Noop,
    /// Pointer lies within the caller's own heap mapping `[base, base+size)`.
    /// Safe to forward to the per-module allocator, which performs the
    /// remaining interior / stale / double-free / malformed-header checks
    /// against its block metadata (all confined to this arena) and logs —
    /// never corrupts — on a bad pointer.
    Forward,
    /// Pointer is null-free but outside the caller's heap region (a foreign
    /// module's heap, a stack/code/state address, or arbitrary memory). The
    /// gateway returns `-EFAULT` and the kernel allocator is never invoked,
    /// so the pointer is never dereferenced.
    Reject,
}

/// Classify an EL0 `heap_free` pointer against the caller's own heap mapping
/// `[heap_base, heap_base + heap_size)`. Pure, host-tested; the BCM2712
/// gateway sources `heap_base`/`heap_size` from the calling module's
/// registered EL0 heap region (keyed by the explicit `module_idx` in the EL0
/// control block — never ambient scheduler state).
///
/// A null pointer is a defined no-op ([`HeapFreeAction::Noop`]). A module
/// with no heap (`heap_size == 0`) rejects every non-null pointer. A pointer
/// inside the half-open heap range is forwarded ([`HeapFreeAction::Forward`]);
/// anything else is rejected ([`HeapFreeAction::Reject`]). The upper-bound
/// arithmetic is overflow-checked so a colossal `heap_size` cannot wrap the
/// range open.
pub fn classify_heap_free(ptr: u64, heap_base: u64, heap_size: u64) -> HeapFreeAction {
    if ptr == 0 {
        return HeapFreeAction::Noop;
    }
    if heap_size == 0 {
        return HeapFreeAction::Reject; // module declared no heap arena
    }
    let Some(end) = heap_base.checked_add(heap_size) else {
        return HeapFreeAction::Reject; // malformed region; fail closed
    };
    if ptr >= heap_base && ptr < end {
        HeapFreeAction::Forward
    } else {
        HeapFreeAction::Reject
    }
}

// Unit tests for `buf_within_regions` live in `tests/harness/tests/el0_abi.rs`
// (project policy: production `src/` carries no inline unit tests).

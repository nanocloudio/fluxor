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
//! Only `channel_read` / `channel_write` / `channel_poll` are exposed.
//! Heap, providers, timers and events are deliberately out of this slice
//! (see docs/architecture/cm5_el0_isolation.md) — channel I/O is the
//! highest-value surface with the smallest privilege footprint.
//!
//! Before the kernel dereferences any EL0 pointer, it validates that the
//! whole `[ptr, ptr+len)` range lies inside the calling module's own mapped
//! read/write regions (state / heap / channel buffers / EL0 stack). The
//! range check itself is the pure, host-tested [`buf_within_regions`]; the
//! BCM2712 gateway (`kernel::mmu`'s `el0` submodule) builds the region list
//! from the module's registered regions and calls it.

/// `SVC #1` op selectors.
pub const SYS_CHANNEL_READ: u64 = 0;
pub const SYS_CHANNEL_WRITE: u64 = 1;
pub const SYS_CHANNEL_POLL: u64 = 2;

/// The `SVC` immediate that selects the syscall gateway (vs `SVC #0`, the
/// module-step return).
pub const SVC_SYSCALL_IMM: u64 = 1;

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

// Unit tests for `buf_within_regions` live in `tests/harness/tests/el0_abi.rs`
// (project policy: production `src/` carries no inline unit tests).

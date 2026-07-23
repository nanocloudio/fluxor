//! EL0 isolated transform module — proves the `SVC #1` channel-syscall
//! gateway end to end: a useful module that runs entirely at EL0 under its
//! own page table, reads from its input channel, transforms the bytes, and
//! writes to its output channel — all via mediated syscalls, with zero
//! access to kernel memory or the `SyscallTable` function pointers.
//!
//! Wire it between two ordinary (non-isolated) modules with
//! `protection: isolated`; see `examples/iso_transform/cm5.yaml`.
//!
//! Transform: byte-wise XOR with `0xFF` (involutive, so a second instance
//! restores the original — handy for a loopback sanity check).
//!
//! ## Why this is "useful" isolation (vs the iso_probe diagnostic)
//!
//! `module_step` performs real I/O through the kernel without holding any
//! kernel pointer: `channel_poll` / `channel_read` / `channel_write` are
//! issued as `SVC #1`, the kernel validates the EL0 buffer against this
//! module's own mapped regions, services the channel op at EL1, and `ERET`s
//! back to EL0. Heap, providers, timers and events are NOT available in
//! this slice (a later gateway extension) — channel I/O is the highest-value
//! surface with the smallest privilege footprint.
//!
//! **Requires `protection: isolated`.** Run non-isolated it would execute at
//! EL1, where `svc #1` traps to the current-EL vector (no syscall path) —
//! so this module is only meaningful under EL0 isolation.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset."
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ---- EL0 syscall gateway (SVC #1) ------------------------------------------
//
// Calling convention mirrors `kernel::el0_abi`:
//   x0 = op, x1 = channel handle, x2 = buffer ptr, x3 = len -> x0 = result.
const SYS_CHANNEL_READ: u64 = 0;
const SYS_CHANNEL_WRITE: u64 = 1;
const SYS_CHANNEL_POLL: u64 = 2;

/// Issue one channel syscall via `SVC #1`. Only valid at EL0 (isolated).
///
/// # Safety
/// `ptr`/`len` must describe a buffer inside this module's own mapped EL0
/// regions (the kernel re-validates and returns EFAULT otherwise). For
/// poll, pass a null ptr and 0 len.
#[inline(always)]
unsafe fn svc1(op: u64, chan: i32, ptr: *mut u8, len: usize) -> i32 {
    let ret: u64;
    core::arch::asm!(
        "svc #1",
        in("x0") op,
        in("x1") chan as i64,
        in("x2") ptr as u64,
        in("x3") len as u64,
        lateout("x0") ret,
        clobber_abi("C"),
    );
    ret as i32
}

// ============================================================================
// Module State
// ============================================================================

const BUF_LEN: usize = 256;

#[repr(C)]
struct IsoTransformState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    /// XOR key applied to every byte (default 0xFF).
    key: u8,
    /// Fixed output-staging buffer holding transformed bytes that have not
    /// yet been accepted by the downstream channel. No heap, no_std: this is
    /// the only place a partial write's tail can live across ticks.
    out_buf: [u8; BUF_LEN],
    /// Index of the first byte in `out_buf` not yet written downstream. When
    /// `out_head == out_len` the staging buffer is empty (fully flushed).
    out_head: usize,
    /// Count of valid bytes in `out_buf` (transformed, awaiting write). The
    /// pending region is `out_buf[out_head..out_len]`.
    out_len: usize,
}

// ============================================================================
// Exported functions
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<IsoTransformState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // Runs at EL1 during instantiation — `dev_log` is allowed here.
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<IsoTransformState>() {
            return -3;
        }
        let s = &mut *(state as *mut IsoTransformState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.key = 0xFF;
        s.out_buf = [0u8; BUF_LEN];
        s.out_head = 0;
        s.out_len = 0;
        dev_log(&*s.syscalls, 3, b"[iso_transform] init\0".as_ptr(), 20);
        0 // Ready
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // Runs at EL0 under the module's page table. SYSCALL-MEDIATED: all
    // channel I/O goes through `svc1` (SVC #1); no kernel pointer is touched.
    unsafe {
        let s = &mut *(state as *mut IsoTransformState);
        if s.in_chan < 0 || s.out_chan < 0 {
            return -1;
        }

        // --- Phase 1: flush any pending transformed output FIRST. ----------
        //
        // A previous tick's write may have been short (downstream backpressure
        // returns fewer bytes than offered, possibly 0). The unwritten tail
        // lives in `out_buf[out_head..out_len]`; drain it before touching the
        // input so no transformed byte is ever dropped. The SVC gateway's
        // write returns bytes actually written (>=0) or a negative errno.
        if s.out_head < s.out_len {
            let pending = s.out_len - s.out_head;
            let w = svc1(
                SYS_CHANNEL_WRITE,
                s.out_chan,
                s.out_buf.as_mut_ptr().add(s.out_head),
                pending,
            );
            if w == E_AGAIN {
                // Downstream FIFO full — backpressure, not an error. Hold the
                // pending tail staged and retry next tick (consume no input).
                return 0;
            }
            if w < 0 {
                return w; // Real error — fault.
            }
            s.out_head += w as usize;
            if s.out_head < s.out_len {
                // Still backpressured. Hold the remainder and retry next tick;
                // do NOT read new input (would overwrite the staging buffer).
                return 0;
            }
            // Fully flushed — reset the staging buffer to empty.
            s.out_head = 0;
            s.out_len = 0;
        }

        // --- Phase 2: read new input only once output is fully drained. -----

        // How many bytes are waiting on the input channel? The SVC gateway's
        // poll returns the readable byte count (not the SDK readiness bitmask)
        // — see note in the gateway dispatch. Distinguish "nothing available"
        // from a real gateway error: 0 (and EAGAIN) = idle → Continue; any other
        // negative (EPERM/EFAULT/EINVAL — a denied handle, bad pointer, or bad
        // op) is a genuine fault and MUST propagate, not be silently swallowed.
        let avail = svc1(SYS_CHANNEL_POLL, s.in_chan, core::ptr::null_mut(), 0);
        if avail == 0 || avail == E_AGAIN {
            return 0; // Continue — nothing to read this tick
        }
        if avail < 0 {
            return avail; // gateway error → fault per policy
        }

        // Read only as much as we can buffer (BUF_LEN), so the staging buffer
        // can hold the entire transformed result and we never have to consume
        // input we cannot stage. The read happens into the staging buffer
        // directly (mapped in this module's EL0 region, so the kernel's
        // pointer check accepts it).
        let want = if (avail as usize) < BUF_LEN {
            avail as usize
        } else {
            BUF_LEN
        };
        let n = svc1(SYS_CHANNEL_READ, s.in_chan, s.out_buf.as_mut_ptr(), want);
        if n == 0 || n == E_AGAIN {
            return 0; // nothing to read right now → Continue
        }
        if n < 0 {
            return n; // gateway error (EPERM/EFAULT/EINVAL) → fault, don't hide it
        }
        let n = n as usize;

        // Transform in place inside the staging buffer.
        for b in s.out_buf.iter_mut().take(n) {
            *b ^= s.key;
        }
        s.out_head = 0;
        s.out_len = n;

        // Attempt the first write now; whatever the downstream cannot accept
        // stays staged and is retried in Phase 1 on subsequent ticks. The
        // write returns bytes written (0 under full backpressure) or <0 errno.
        let w = svc1(SYS_CHANNEL_WRITE, s.out_chan, s.out_buf.as_mut_ptr(), s.out_len);
        if w == E_AGAIN {
            // Downstream FIFO full — keep the freshly-staged result
            // (out_head=0, out_len=n) and retry in Phase 1 next tick.
            return 0;
        }
        if w < 0 {
            return w;
        }
        s.out_head = w as usize;
        if s.out_head >= s.out_len {
            // Wrote it all this tick — staging buffer is empty again.
            s.out_head = 0;
            s.out_len = 0;
        }
        0 // Continue
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");

//! Isolated transform module — a useful module that runs gated, reads its
//! input channel, transforms the bytes and writes its output channel, all
//! through the gateway: its `SyscallTable` is the gateway's, so every channel
//! call is a veneer that traps, and the kernel copies between the channel and
//! this module's own buffer after checking both the handle and the buffer.
//!
//! Wire it between two ordinary modules with `protection: isolated`; see
//! `examples/iso_transform/pi5.yaml`.
//!
//! Transform: byte-wise XOR with `0xFF` (involutive, so a second instance
//! restores the original — handy for a loopback sanity check).

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

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

declare_module_state_bytes!(IsoTransformState);

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
    // Runs gated like `module_step`: `dev_log` below is a gateway call.
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
    unsafe {
        let s = &mut *(state as *mut IsoTransformState);
        let sys = &*s.syscalls;
        if s.in_chan < 0 || s.out_chan < 0 {
            return -1;
        }

        // --- Phase 1: flush any pending transformed output FIRST. ----------
        //
        // A previous tick's write may have been short (downstream backpressure
        // returns fewer bytes than offered, possibly 0). The unwritten tail
        // lives in `out_buf[out_head..out_len]`; drain it before touching the
        // input so no transformed byte is ever dropped. A write returns the
        // bytes actually written (>=0) or a negative errno.
        if s.out_head < s.out_len {
            let pending = s.out_len - s.out_head;
            let w = (sys.channel_write)(s.out_chan, s.out_buf.as_ptr().add(s.out_head), pending);
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

        // Read at most what the staging buffer holds, so every byte read can
        // be transformed and staged. 0 (and EAGAIN) = nothing this tick; any
        // other negative — a refused handle or buffer — is a genuine fault
        // and propagates.
        let n = (sys.channel_read)(s.in_chan, s.out_buf.as_mut_ptr(), BUF_LEN);
        if n == 0 || n == E_AGAIN {
            return 0; // nothing to read right now → Continue
        }
        if n < 0 {
            return n;
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
        let w = (sys.channel_write)(s.out_chan, s.out_buf.as_ptr(), s.out_len);
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
include!("../../sdk/runtime/wasm_entry.rs");

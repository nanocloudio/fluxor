//! Owner-pause probe — resident-pod half of the metal PAUSE silicon AC.
//!
//! A self-driven counter that runs inside a resident pod (workload owner).
//! Every `log_every` steps it logs `[pprobe] c=<count> ms=<dev_millis>`
//! (the liveness observable), and whenever the wall-clock gap between two
//! consecutive steps exceeds `gap_min_ms` it logs
//! `[pprobe] gap_ms=<gap>` — the pod's OWN proof that it was not stepped
//! for that window. Paired with `pause_driver`, which pauses/resumes the
//! pod's owner from the base graph: the gap line can only appear if the
//! pause actually froze the pod, and its magnitude must match the
//! driver's pause→resume window.

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
include!("../../sdk/runtime/params.rs");

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    count: u32,
    /// Steps between `[pprobe] c=` liveness lines. Default 250.
    log_every: u32,
    /// Minimum inter-step wall-clock gap (ms) that logs a `gap_ms` line.
    /// Default 1500 — far above any scheduling jitter, far below the
    /// driver's pause window.
    gap_min_ms: u32,
    last_step_ms: u64,
}

mod params_def {
    use super::p_u32;
    use super::State;
    use super::SCHEMA_MAX;

    define_params! {
        State;

        1, log_every, u32, 250
            => |s, d, len| { let v = p_u32(d, len, 0, 250); s.log_every = if v == 0 { 250 } else { v }; };

        2, gap_min_ms, u32, 1500
            => |s, d, len| { let v = p_u32(d, len, 0, 1500); s.gap_min_ms = if v == 0 { 1500 } else { v }; };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.count = 0;
        s.log_every = 250;
        s.gap_min_ms = 1500;
        s.last_step_ms = 0;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
    }
    0
}

/// Append `v` as decimal digits at `msg[len..]`; returns the new length.
fn put_dec(msg: &mut [u8], mut len: usize, v: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut d = 0usize;
    let mut x = v;
    loop {
        digits[d] = b'0' + (x % 10) as u8;
        d += 1;
        x /= 10;
        if x == 0 || d >= digits.len() {
            break;
        }
    }
    while d > 0 && len < msg.len() {
        d -= 1;
        msg[len] = digits[d];
        len += 1;
    }
    len
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return 0;
        }
        let sys = &*s.syscalls;
        s.count = s.count.wrapping_add(1);
        let now = dev_millis(sys);
        if now == 0 {
            dev_log(sys, 1, b"[pprobe] clock_dead".as_ptr(), 19);
            return 0;
        }
        // Freeze detector: a pause spans many nominal ticks, so the first
        // step after resume sees a wall-clock gap ≈ the pause window.
        if s.last_step_ms != 0 {
            let gap = now.saturating_sub(s.last_step_ms);
            if gap >= s.gap_min_ms as u64 {
                let mut msg = [0u8; 40];
                let prefix = b"[pprobe] gap_ms=";
                msg[..prefix.len()].copy_from_slice(prefix);
                let len = put_dec(&mut msg, prefix.len(), gap);
                dev_log(sys, 3, msg.as_ptr(), len);
            }
        }
        s.last_step_ms = now;
        // checked_rem: no panic path in PIC .text (log_every is nonzero by
        // construction, but the compiler can't prove it).
        if s.count.checked_rem(s.log_every) == Some(0) {
            let mut msg = [0u8; 56];
            let prefix = b"[pprobe] c=";
            msg[..prefix.len()].copy_from_slice(prefix);
            let mut len = put_dec(&mut msg, prefix.len(), s.count as u64);
            let mid = b" ms=";
            if len + mid.len() <= msg.len() {
                msg[len..len + mid.len()].copy_from_slice(mid);
                len += mid.len();
            }
            let len = put_dec(&mut msg, len, now);
            dev_log(sys, 3, msg.as_ptr(), len);
        }
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");

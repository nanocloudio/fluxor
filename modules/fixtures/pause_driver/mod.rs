//! Owner-pause driver — base-graph half of the metal PAUSE silicon AC
//! (rfc_workload_lifecycle.md §3.2, P4).
//!
//! Runs in the SYSTEM graph and drives one pause→resume cycle against a
//! resident pod's owner via the OWNER_PAUSE / OWNER_RESUME live-mutation
//! ops (0x0C49/0x0C4A, beside APPLY_ADD/FREE_OWNER):
//!
//!   at `pause_at_ms`  → OWNER_PAUSE  `[slot:u16 LE][generation:u32 LE]`
//!   at `resume_at_ms` → OWNER_RESUME (same handle record)
//!
//! Logs `[pdrv] pause ms=<t> rc=<rc>` / `[pdrv] resume ms=<t> rc=<rc>`
//! and a periodic `[pdrv] hb ms=<t>` heartbeat proving the SYSTEM graph
//! keeps stepping throughout the pod's pause window. The paired
//! `pause_probe` inside the pod logs the freeze (`[pprobe] gap_ms=…`).
//!
//! The boot-admitted first pod deterministically owns slot 1 at
//! generation 1 (lowest-free-slot + fresh monotonic generation), which
//! the defaults encode; override via params for other topologies.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts the complete SDK; this driver uses a small subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::internal::reconfigure::{OWNER_PAUSE, OWNER_RESUME};
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    /// Target owner handle (defaults: first boot-admitted pod).
    slot: u32,
    generation: u32,
    /// Wall-clock schedule (ms since boot).
    pause_at_ms: u32,
    resume_at_ms: u32,
    /// Heartbeat period (ms).
    hb_every_ms: u32,
    paused: bool,
    resumed: bool,
    _pad: [u8; 2],
    last_hb_ms: u64,
}

mod params_def {
    use super::State;
    use super::SCHEMA_MAX;
    use super::p_u32;

    define_params! {
        State;

        1, slot, u32, 1
            => |s, d, len| { s.slot = p_u32(d, len, 0, 1); };

        2, generation, u32, 1
            => |s, d, len| { s.generation = p_u32(d, len, 0, 1); };

        3, pause_at_ms, u32, 10_000
            => |s, d, len| { s.pause_at_ms = p_u32(d, len, 0, 10_000); };

        4, resume_at_ms, u32, 17_000
            => |s, d, len| { s.resume_at_ms = p_u32(d, len, 0, 17_000); };

        5, hb_every_ms, u32, 2_000
            => |s, d, len| { let v = p_u32(d, len, 0, 2_000); s.hb_every_ms = if v == 0 { 2_000 } else { v }; };
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
        s.slot = 1;
        s.generation = 1;
        s.pause_at_ms = 10_000;
        s.resume_at_ms = 17_000;
        s.hb_every_ms = 2_000;
        s.paused = false;
        s.resumed = false;
        s.last_hb_ms = 0;
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
/// Negative values get a leading '-'.
fn put_dec_i(msg: &mut [u8], mut len: usize, v: i64) -> usize {
    let mut x = if v < 0 {
        if len < msg.len() {
            msg[len] = b'-';
            len += 1;
        }
        (-(v as i128)) as u64
    } else {
        v as u64
    };
    let mut digits = [0u8; 20];
    let mut d = 0usize;
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

unsafe fn emit(sys: &SyscallTable, verb: &[u8], now: u64, rc: i32) {
    let mut msg = [0u8; 56];
    let prefix = b"[pdrv] ";
    msg[..prefix.len()].copy_from_slice(prefix);
    let mut len = prefix.len();
    msg[len..len + verb.len()].copy_from_slice(verb);
    len += verb.len();
    let mid = b" ms=";
    msg[len..len + mid.len()].copy_from_slice(mid);
    len += mid.len();
    let mut len = put_dec_i(&mut msg, len, now as i64);
    let tail = b" rc=";
    if len + tail.len() <= msg.len() {
        msg[len..len + tail.len()].copy_from_slice(tail);
        len += tail.len();
    }
    let len = put_dec_i(&mut msg, len, rc as i64);
    dev_log(sys, 3, msg.as_ptr(), len);
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
        let now = dev_millis(sys);
        if now == 0 {
            dev_log(sys, 1, b"[pdrv] clock_dead".as_ptr(), 17);
            return 0;
        }
        // System-graph liveness heartbeat — must keep appearing while the
        // pod is paused (co-resident isolation).
        if now.saturating_sub(s.last_hb_ms) >= s.hb_every_ms as u64 {
            s.last_hb_ms = now;
            emit(sys, b"hb", now, 0);
        }
        // `[slot:u16 LE][generation:u32 LE]` — the FREE_OWNER handle record.
        let mut arg = [0u8; 6];
        arg[0..2].copy_from_slice(&(s.slot as u16).to_le_bytes());
        arg[2..6].copy_from_slice(&s.generation.to_le_bytes());
        if !s.paused && now >= s.pause_at_ms as u64 {
            s.paused = true;
            let rc = (sys.provider_call)(-1, OWNER_PAUSE, arg.as_mut_ptr(), arg.len());
            emit(sys, b"pause", now, rc);
        }
        if s.paused && !s.resumed && now >= s.resume_at_ms as u64 {
            s.resumed = true;
            let rc = (sys.provider_call)(-1, OWNER_RESUME, arg.as_mut_ptr(), arg.len());
            emit(sys, b"resume", now, rc);
        }
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");

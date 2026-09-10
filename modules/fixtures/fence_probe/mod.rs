//! fence_probe — installs a secondary address on the ip module, then
//! fences it after a delay, logging each step so a packet capture can be
//! aligned against the fence.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::net::identity as netid;

const PHASE_WAIT_NET: u8 = 0;
const PHASE_INSTALLED: u8 = 1;
const PHASE_FENCE_SENT: u8 = 2;
const PHASE_DONE: u8 = 3;

#[repr(C)]
pub struct ProbeState {
    syscalls: *const SyscallTable,
    addr_ctl: i32,
    addr_evt: i32,
    vip: u32,
    prefix_len: u8,
    phase: u8,
    _pad: [u8; 2],
    install_after_s: u32,
    fence_after_s: u32,
    boot_ms: u32,
    installed_ms: u32,
    token: [u8; 16],
    pub generation: u32,
    pub cutoff_kind: u8,
    _pad2: [u8; 3],
    pub cutoff_index: u64,
    buf: [u8; 64],
}

mod params_def {
    use super::*;
    define_params! {
        ProbeState;
        1, vip, u32, 0 => |s, d, len| { s.vip = p_u32(d, len, 0, 0); };
        2, prefix_len, u8, 24 => |s, d, len| { s.prefix_len = p_u8(d, len, 0, 24); };
        3, install_after_s, u32, 20 => |s, d, len| { s.install_after_s = p_u32(d, len, 0, 20); };
        4, fence_after_s, u32, 20 => |s, d, len| { s.fence_after_s = p_u32(d, len, 0, 20); };
    }
}

fn fmt_u32(mut v: u32, out: &mut [u8; 12]) -> &[u8] {
    let mut i = 12;
    if v == 0 {
        i -= 1;
        out[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &out[i..]
}

unsafe fn log_line(s: &ProbeState, parts: &[&[u8]]) {
    let sys = &*s.syscalls;
    let mut line = [0u8; 96];
    let mut p = 0usize;
    for part in parts {
        let n = part.len().min(96 - p);
        line[p..p + n].copy_from_slice(&part[..n]);
        p += n;
    }
    dev_log(sys, 3, line.as_ptr(), p);
}

/// The 16-byte address field the identity contract carries: the IPv4
/// address big-endian in the first four bytes, the rest zero.
fn addr16(v4: u32) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&v4.to_be_bytes());
    a
}

unsafe fn send_install(s: &mut ProbeState) {
    let sys = &*s.syscalls;
    let mut payload = [0u8; netid::ADDR_ADD_PAYLOAD_LEN + 1];
    payload[..16].copy_from_slice(&addr16(s.vip));
    payload[netid::ADD_PREFIX_LEN_OFF] = s.prefix_len;
    payload[netid::ADD_OWNER_TAG_OFF] = 0;
    payload[netid::ADD_OWNER_TAG_OFF + 1] = 0;
    payload[netid::ADD_FLAGS_OFF] = 0;
    net_write_frame(sys, s.addr_ctl, netid::ADDR_ADD, payload.as_ptr(), payload.len(), s.buf.as_mut_ptr(), 64);
}

unsafe fn send_fence(s: &mut ProbeState) {
    let sys = &*s.syscalls;
    let mut payload = [0u8; netid::ADDR_TOKEN_PAYLOAD_LEN];
    payload[..16].copy_from_slice(&addr16(s.vip));
    payload[netid::TOKEN_OFF..netid::TOKEN_OFF + 16].copy_from_slice(&s.token);
    net_write_frame(sys, s.addr_ctl, netid::ADDR_FENCE, payload.as_ptr(), payload.len(), s.buf.as_mut_ptr(), 64);
}

unsafe fn service_events(s: &mut ProbeState) {
    let sys = &*s.syscalls;
    let mut n = 0;
    while n < 8 {
        let (msg, plen) = net_read_frame(sys, s.addr_evt, s.buf.as_mut_ptr(), 64);
        if msg == 0 {
            break;
        }
        let plen = plen as usize;
        let p = s.buf.as_ptr().add(3);
        let ours = plen >= 16 && core::slice::from_raw_parts(p, 16) == addr16(s.vip);
        match msg {
            netid::MSG_ADDR_ADDED if ours && plen >= 36 => {
                core::ptr::copy_nonoverlapping(p.add(16), s.token.as_mut_ptr(), 16);
                s.generation = u32::from_le_bytes([*p.add(32), *p.add(33), *p.add(34), *p.add(35)]);
                s.installed_ms = dev_millis(sys) as u32;
                s.phase = PHASE_INSTALLED;
                let mut t = [0u8; 12];
                let v = s.vip;
                log_line(
                    s,
                    &[
                        b"[fence_probe] installed ",
                        fmt_u32(v >> 24, &mut t),
                        b".",
                        fmt_u32((v >> 16) & 0xFF, &mut [0u8; 12]),
                        b".",
                        fmt_u32((v >> 8) & 0xFF, &mut [0u8; 12]),
                        b".",
                        fmt_u32(v & 0xFF, &mut [0u8; 12]),
                    ],
                );
            }
            netid::MSG_ADDR_FENCED if ours && plen >= 30 => {
                s.cutoff_index = u64::from_le_bytes([
                    *p.add(20), *p.add(21), *p.add(22), *p.add(23),
                    *p.add(24), *p.add(25), *p.add(26), *p.add(27),
                ]);
                s.cutoff_kind = *p.add(28);
                s.phase = PHASE_DONE;
                let kind: &[u8] = if s.cutoff_kind == netid::cutoff::WIRE { b"wire" } else { b"ring_handoff" };
                let mut t = [0u8; 12];
                let idx = s.cutoff_index as u32;
                log_line(s, &[b"[fence_probe] fenced cutoff=", kind, b" index=", fmt_u32(idx, &mut t)]);
            }
            netid::MSG_ADDR_REFUSED if ours && plen >= 18 => {
                let mut t = [0u8; 12];
                let reason = u32::from(*p.add(17));
                log_line(s, &[b"[fence_probe] refused reason=", fmt_u32(reason, &mut t)]);
            }
            _ => {}
        }
        n += 1;
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ProbeState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return -22;
    }
    if state_size < core::mem::size_of::<ProbeState>() {
        return -6;
    }
    let s = &mut *(state as *mut ProbeState);
    s.syscalls = syscalls as *const SyscallTable;
    s.addr_evt = in_chan;
    s.addr_ctl = out_chan;
    s.phase = PHASE_WAIT_NET;
    s.boot_ms = dev_millis(&*s.syscalls) as u32;
    s.installed_ms = 0;
    s.token = [0; 16];
    s.generation = 0;
    s.cutoff_kind = 0;
    s.cutoff_index = 0;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    if s.vip == 0 {
        let m = b"[fence_probe] refusing to construct: vip is required";
        dev_log(&*s.syscalls, 1, m.as_ptr(), m.len());
        return -22;
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut ProbeState);
    let now = dev_millis(&*s.syscalls) as u32;
    service_events(s);
    match s.phase {
        PHASE_WAIT_NET => {
            // Install once the stack has had time to bind its primary; the
            // install is retried on the same period until it is answered.
            if now.wrapping_sub(s.boot_ms) >= s.install_after_s * 1000 && (now / 1000) % 2 == 0 {
                if s.token == [0; 16] {
                    send_install(s);
                    // One request per two-second window.
                    s.boot_ms = now.wrapping_sub(s.install_after_s * 1000).wrapping_add(1000);
                }
            }
        }
        PHASE_INSTALLED => {
            if now.wrapping_sub(s.installed_ms) >= s.fence_after_s * 1000 {
                log_line(s, &[b"[fence_probe] fence requested"]);
                send_fence(s);
                s.phase = PHASE_FENCE_SENT;
            }
        }
        _ => {}
    }
    0
}

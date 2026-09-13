//! directory_stand_in — the session-directory role at fixture scale: a
//! single-writer binding table keyed by session id, epoch-fenced, with an
//! egress-counter reservation grant per attached session.

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

use abi::contracts::net::session_ctrl as sc;

/// Sessions the table holds.
const MAX_BINDINGS: usize = 64;
/// Egress-counter values in one reservation grant.
const GRANT_LEN: u64 = 1 << 20;
/// This directory's identity on HELLO_ACK.
const DIRECTORY_ID: [u8; 8] = *b"stand-in";

#[repr(C)]
#[derive(Clone, Copy)]
struct Binding {
    session_id: [u8; sc::SESSION_ID_BYTES],
    worker_id: [u8; sc::WORKER_ID_BYTES],
    epoch: u32,
    in_use: u8,
    _pad: [u8; 3],
}

const NO_BINDING: Binding = Binding {
    session_id: [0; sc::SESSION_ID_BYTES],
    worker_id: [0; sc::WORKER_ID_BYTES],
    epoch: 0,
    in_use: 0,
    _pad: [0; 3],
};

#[repr(C)]
pub struct DirState {
    syscalls: *const SyscallTable,
    ctrl_in: i32,
    ctrl_out: i32,
    bindings: [Binding; MAX_BINDINGS],
    /// First counter value no grant has covered yet.
    pub next_grant_start: u64,
    /// Bindings held right now.
    pub bound: u32,
    buf: [u8; 128],
    out: [u8; 128],
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

unsafe fn log_line(s: &DirState, parts: &[&[u8]]) {
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

unsafe fn reply(s: &mut DirState, msg: u8, payload: &[u8]) {
    let sys = &*s.syscalls;
    net_write_frame(
        sys,
        s.ctrl_out,
        msg,
        payload.as_ptr(),
        payload.len(),
        s.out.as_mut_ptr(),
        128,
    );
}

fn find(s: &DirState, session_id: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < MAX_BINDINGS {
        if s.bindings[i].in_use != 0 && s.bindings[i].session_id == session_id {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn free_slot(s: &DirState) -> Option<usize> {
    let mut i = 0;
    while i < MAX_BINDINGS {
        if s.bindings[i].in_use == 0 {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// `[session_id:16][epoch:4][status:1]`.
unsafe fn reply_status(s: &mut DirState, msg: u8, session_id: &[u8], epoch: u32, status: u8) {
    let mut p = [0u8; sc::SESSION_HEADER + 1];
    p[..sc::SESSION_ID_BYTES].copy_from_slice(session_id);
    p[sc::SESSION_ID_BYTES..sc::SESSION_HEADER].copy_from_slice(&epoch.to_le_bytes());
    p[sc::SESSION_HEADER] = status;
    reply(s, msg, &p);
}

unsafe fn log_stale(s: &DirState, epoch: u32, held: u32) {
    let mut a = [0u8; 12];
    let mut b = [0u8; 12];
    let e = fmt_u32(epoch, &mut a);
    let h = fmt_u32(held, &mut b);
    log_line(s, &[b"[directory] stale epoch=", e, b" held=", h]);
}

unsafe fn log_bound(s: &DirState, epoch: u32) {
    let mut a = [0u8; 12];
    let mut b = [0u8; 12];
    let n = fmt_u32(s.bound, &mut a);
    let e = fmt_u32(epoch, &mut b);
    log_line(s, &[b"[directory] bound ", n, b" epoch=", e]);
}

/// Grant the session a block of egress-counter values past every block
/// granted before, under the epoch the binding now holds.
unsafe fn grant(s: &mut DirState, session_id: &[u8], epoch: u32) {
    let start = s.next_grant_start;
    s.next_grant_start = start.wrapping_add(GRANT_LEN);
    let mut p = [0u8; sc::FLOW_ID_BYTES + sc::GRANT_LEN];
    p[..sc::FLOW_ID_BYTES].copy_from_slice(session_id);
    let g = &mut p[sc::FLOW_ID_BYTES..];
    g[0] = sc::GRANT_OP_RESERVE;
    g[1] = sc::GRANT_STATUS_OK;
    g[2..18].copy_from_slice(session_id);
    g[18..22].copy_from_slice(&epoch.to_le_bytes());
    g[22..30].copy_from_slice(&start.to_le_bytes());
    g[30..38].copy_from_slice(&GRANT_LEN.to_le_bytes());
    reply(s, sc::CMD_SC_RESERVATION_GRANT, &p);
    let mut a = [0u8; 12];
    let mut b = [0u8; 12];
    let st = fmt_u32(start as u32, &mut a);
    let ln = fmt_u32(GRANT_LEN as u32, &mut b);
    log_line(s, &[b"[directory] granted start=", st, b" len=", ln]);
}

unsafe fn on_attach(s: &mut DirState, p: &[u8]) {
    if p.len() < sc::ATTACH_PAYLOAD_LEN {
        return;
    }
    let mut session_id = [0u8; sc::SESSION_ID_BYTES];
    session_id.copy_from_slice(sc::session_id(p));
    let epoch = sc::attach_epoch(p);
    let at = sc::SESSION_ID_BYTES + sc::ANCHOR_ID_BYTES + sc::EPOCH_BYTES + 1;
    let mut worker_id = [0u8; sc::WORKER_ID_BYTES];
    worker_id.copy_from_slice(&p[at..at + sc::WORKER_ID_BYTES]);
    let idx = match find(s, &session_id) {
        Some(i) => {
            // A rebind is authoritative only at a higher generation.
            if epoch <= s.bindings[i].epoch {
                log_stale(s, epoch, s.bindings[i].epoch);
                reply_status(
                    s,
                    sc::MSG_SC_ATTACHED,
                    &session_id,
                    epoch,
                    sc::STATUS_STALE_EPOCH,
                );
                return;
            }
            i
        }
        None => match free_slot(s) {
            Some(i) => {
                s.bound += 1;
                i
            }
            None => {
                reply_status(
                    s,
                    sc::MSG_SC_ATTACHED,
                    &session_id,
                    epoch,
                    sc::STATUS_NO_CAPACITY,
                );
                return;
            }
        },
    };
    s.bindings[idx] = Binding {
        session_id,
        worker_id,
        epoch,
        in_use: 1,
        _pad: [0; 3],
    };
    reply_status(s, sc::MSG_SC_ATTACHED, &session_id, epoch, sc::STATUS_OK);
    log_bound(s, epoch);
    grant(s, &session_id, epoch);
}

unsafe fn on_detach(s: &mut DirState, p: &[u8]) {
    if p.len() < sc::DETACH_PAYLOAD_LEN {
        return;
    }
    let mut session_id = [0u8; sc::SESSION_ID_BYTES];
    session_id.copy_from_slice(sc::session_id(p));
    let epoch = sc::epoch(p);
    let Some(i) = find(s, &session_id) else {
        reply_status(
            s,
            sc::MSG_SC_ERROR,
            &session_id,
            epoch,
            sc::STATUS_UNKNOWN_SESSION,
        );
        return;
    };
    if epoch < s.bindings[i].epoch {
        log_stale(s, epoch, s.bindings[i].epoch);
        reply_status(
            s,
            sc::MSG_SC_ERROR,
            &session_id,
            epoch,
            sc::STATUS_STALE_EPOCH,
        );
        return;
    }
    s.bindings[i] = NO_BINDING;
    s.bound -= 1;
    let mut q = [0u8; sc::SESSION_HEADER];
    sc::put_session_header(&mut q, &session_id, epoch);
    reply(s, sc::MSG_SC_DETACHED, &q);
}

/// `[session_id:16][old_epoch:4][new_epoch:4]`: advance the generation.
unsafe fn on_epoch_bump(s: &mut DirState, p: &[u8]) {
    if p.len() < sc::EPOCH_BUMP_PAYLOAD_LEN {
        return;
    }
    let mut session_id = [0u8; sc::SESSION_ID_BYTES];
    session_id.copy_from_slice(sc::session_id(p));
    let old = sc::epoch(p);
    let new = sc::u32_after_header(p);
    let Some(i) = find(s, &session_id) else {
        reply_status(
            s,
            sc::MSG_SC_ERROR,
            &session_id,
            old,
            sc::STATUS_UNKNOWN_SESSION,
        );
        return;
    };
    if old != s.bindings[i].epoch || new <= old {
        log_stale(s, old, s.bindings[i].epoch);
        reply_status(
            s,
            sc::MSG_SC_ERROR,
            &session_id,
            old,
            sc::STATUS_STALE_EPOCH,
        );
        return;
    }
    s.bindings[i].epoch = new;
    let mut q = [0u8; sc::SESSION_HEADER];
    sc::put_session_header(&mut q, &session_id, new);
    reply(s, sc::MSG_SC_EPOCH_CONFIRMED, &q);
    log_bound(s, new);
    grant(s, &session_id, new);
}

/// `[session_id:16][epoch:4][new_worker:8]`: move the binding at the
/// current epoch.
unsafe fn on_relocate(s: &mut DirState, p: &[u8]) {
    if p.len() < sc::RELOCATE_PAYLOAD_LEN {
        return;
    }
    let mut session_id = [0u8; sc::SESSION_ID_BYTES];
    session_id.copy_from_slice(sc::session_id(p));
    let epoch = sc::epoch(p);
    let Some(i) = find(s, &session_id) else {
        reply_status(
            s,
            sc::MSG_SC_RELOCATED,
            &session_id,
            epoch,
            sc::STATUS_UNKNOWN_SESSION,
        );
        return;
    };
    if epoch != s.bindings[i].epoch {
        log_stale(s, epoch, s.bindings[i].epoch);
        reply_status(
            s,
            sc::MSG_SC_RELOCATED,
            &session_id,
            epoch,
            sc::STATUS_STALE_EPOCH,
        );
        return;
    }
    let at = sc::SESSION_HEADER;
    s.bindings[i]
        .worker_id
        .copy_from_slice(&p[at..at + sc::WORKER_ID_BYTES]);
    reply_status(s, sc::MSG_SC_RELOCATED, &session_id, epoch, sc::STATUS_OK);
}

unsafe fn on_hello(s: &mut DirState, p: &[u8]) {
    let role = if p.is_empty() { 0 } else { p[0] };
    let mut q = [0u8; 1 + sc::ANCHOR_ID_BYTES];
    q[0] = sc::ROLE_DIRECTORY;
    q[1..].copy_from_slice(&DIRECTORY_ID);
    reply(s, sc::MSG_SC_HELLO_ACK, &q);
    let mut a = [0u8; 12];
    let r = fmt_u32(u32::from(role), &mut a);
    log_line(s, &[b"[directory] hello role=", r]);
}

unsafe fn service(s: &mut DirState) {
    let sys = &*s.syscalls;
    let mut n = 0;
    while n < 16 {
        // Frame-aligned: a payload too large for `buf` is dropped whole
        // rather than left to desync the control channel for good. Every
        // message this role answers is far smaller than the buffer, so a
        // short read is a malformed writer, not a message to act on.
        let (msg, copied, payload_len) =
            net_read_frame_aligned(sys, s.ctrl_in, s.buf.as_mut_ptr(), 128);
        if msg == 0 {
            break;
        }
        n += 1;
        if copied != payload_len {
            continue;
        }
        let mut p = [0u8; 128];
        p[..copied].copy_from_slice(&s.buf[sc::FRAME_HDR..sc::FRAME_HDR + copied]);
        let p = &p[..copied];
        match msg {
            sc::CMD_SC_HELLO => on_hello(s, p),
            sc::CMD_SC_ATTACH => on_attach(s, p),
            sc::CMD_SC_DETACH => on_detach(s, p),
            sc::CMD_SC_EPOCH_BUMP => on_epoch_bump(s, p),
            sc::CMD_SC_RELOCATE => on_relocate(s, p),
            _ => {}
        }
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DirState>() as u32
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
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return -22;
    }
    if state_size < core::mem::size_of::<DirState>() {
        return -6;
    }
    let s = &mut *(state as *mut DirState);
    s.syscalls = syscalls as *const SyscallTable;
    s.ctrl_in = in_chan;
    s.ctrl_out = out_chan;
    s.bindings = [NO_BINDING; MAX_BINDINGS];
    s.next_grant_start = 0;
    s.bound = 0;
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut DirState);
    service(s);
    0
}

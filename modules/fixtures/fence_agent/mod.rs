//! fence_agent — the reference out-of-band `fence.enforceable` provider:
//! answers the net-identity address-control verbs for the host it holds in
//! custody, and cuts that host by running a command through the `proc`
//! executor, confirming the fence only once the command has succeeded and
//! the host's hold-up time has passed.

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

/// Host process-executor opcodes (class `host_process::PROC_CLASS`).
/// `PROC_STATUS` answers `1` while the command runs and `0` once it is
/// done, writing its exit code into the caller's buffer.
const PROC_SPAWN: u32 = 0x1600;
const PROC_READ: u32 = 0x1601;
const PROC_STATUS: u32 = 0x1602;
const PROC_CLOSE: u32 = 0x1603;

/// Longest actuator command line.
const CMD_MAX: usize = 96;
/// The default cut and restore: the rig's power backend.
const DEFAULT_FENCE_CMD: &[u8] = b"fluxor rig power off";
const DEFAULT_RESTORE_CMD: &[u8] = b"fluxor rig power on";
/// How long the fenced host may go on emitting after its actuator reports
/// the cut — its supply's hold-up — before the fence is confirmed.
const DEFAULT_QUIET_AFTER_MS: u32 = 2000;

/// Nothing is being actuated.
const PHASE_IDLE: u8 = 0;
/// The actuator command is running.
const PHASE_RUNNING: u8 = 1;
/// The cut succeeded; the host's hold-up is being waited out.
const PHASE_HOLDING: u8 = 2;

/// One actuation, and the custody it was requested under. The identity is
/// captured here at dispatch rather than read back from the custody at
/// completion: releasing custody while a cut is in flight must not change
/// which host and generation the answer names.
#[repr(C)]
#[derive(Clone, Copy)]
struct Actuation {
    addr: [u8; 16],
    generation: u32,
    /// `PHASE_*`.
    phase: u8,
    /// The verb being served: `ADDR_FENCE` or `ADDR_ARM`.
    op: u8,
    _pad: [u8; 2],
    /// `dev_millis` at which a confirmed cut's hold-up ends.
    quiet_until_ms: u32,
}

const NO_ACTUATION: Actuation = Actuation {
    addr: [0; 16],
    generation: 0,
    phase: PHASE_IDLE,
    op: 0,
    _pad: [0; 2],
    quiet_until_ms: 0,
};

/// The agent holds one host: its actuator command names that host, so a
/// second host is a second instance of this module with its own command.
#[repr(C)]
pub struct AgentState {
    syscalls: *const SyscallTable,
    addr_ctl: i32,
    addr_evt: i32,
    /// The host in custody: its address, the token that authorises
    /// fencing it, and the custody generation.
    addr: [u8; 16],
    token: [u8; 16],
    generation: u32,
    /// Whether a host is held at all.
    held: u8,
    fence_cmd_len: u8,
    restore_cmd_len: u8,
    _pad: u8,
    /// Custody generations minted over this agent's life.
    generation_next: u32,
    /// Fences confirmed over this agent's life: the `cutoff` index.
    pub fence_count: u64,
    /// The running actuator's handle, or -1.
    proc_slot: i32,
    /// Hold-up allowance applied to a confirmed cut.
    quiet_after_ms: u32,
    pending: Actuation,
    fence_cmd: [u8; CMD_MAX],
    restore_cmd: [u8; CMD_MAX],
    /// Frames read from `addr_ctl`.
    buf: [u8; 64],
    /// Frames written to `addr_evt`, kept apart from `buf` so emitting
    /// never overwrites the frame being served.
    out: [u8; 64],
    /// Actuator output, read and discarded: its exit code is the signal.
    drain: [u8; 256],
}

mod params_def {
    use super::*;
    define_params! {
        AgentState;
        // A variable-length parameter carries no default the schema can
        // hold, so `set_defaults` applies it as a zero-length value. Zero
        // length therefore means "the graph named none", and the built-in
        // binding below stands.
        1, fence_cmd, str, 0 => |s, d, len| {
            let n = if len > CMD_MAX { CMD_MAX } else { len };
            if n > 0 {
                s.fence_cmd_len = n as u8;
                core::ptr::copy_nonoverlapping(d, s.fence_cmd.as_mut_ptr(), n);
            }
        };
        2, restore_cmd, str, 0 => |s, d, len| {
            let n = if len > CMD_MAX { CMD_MAX } else { len };
            if n > 0 {
                s.restore_cmd_len = n as u8;
                core::ptr::copy_nonoverlapping(d, s.restore_cmd.as_mut_ptr(), n);
            }
        };
        3, quiet_after_ms, u32, DEFAULT_QUIET_AFTER_MS => |s, d, len| {
            s.quiet_after_ms = p_u32(d, len, 0, DEFAULT_QUIET_AFTER_MS);
        };
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

/// Dotted-quad of the IPv4 address in an identity address slot.
fn fmt_ip(addr: &[u8; 16], out: &mut [u8; 16]) -> usize {
    let mut p = 0;
    let mut i = 0;
    while i < 4 {
        let mut t = [0u8; 12];
        let d = fmt_u32(u32::from(addr[i]), &mut t);
        out[p..p + d.len()].copy_from_slice(d);
        p += d.len();
        if i < 3 {
            out[p] = b'.';
            p += 1;
        }
        i += 1;
    }
    p
}

unsafe fn log_line(s: &AgentState, parts: &[&[u8]]) {
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

/// A log line naming the host: `<head><ip><tail…>`.
unsafe fn log_addr(s: &AgentState, head: &[u8], addr: &[u8; 16], tail: &[&[u8]]) {
    let mut ip = [0u8; 16];
    let n = fmt_ip(addr, &mut ip);
    let mut parts: [&[u8]; 8] = [&[]; 8];
    parts[0] = head;
    parts[1] = &ip[..n];
    let mut i = 0;
    while i < tail.len() && i + 2 < 8 {
        parts[i + 2] = tail[i];
        i += 1;
    }
    log_line(s, &parts[..2 + i]);
}

/// Mint a custody token: CSPRNG bytes mixed with the boot incarnation, so
/// a token from a previous custody or a previous life of the agent cannot
/// match. `None` fails closed.
unsafe fn mint_token(s: &AgentState) -> Option<[u8; 16]> {
    let sys = &*s.syscalls;
    let mut t = [0u8; 16];
    if dev_csprng_fill(sys, t.as_mut_ptr(), 16) < 0 {
        return None;
    }
    let inc = dev_boot_incarnation(sys)?;
    let mut i = 0;
    while i < 16 {
        t[i] ^= inc[i];
        i += 1;
    }
    if t == [0u8; 16] {
        None
    } else {
        Some(t)
    }
}

unsafe fn emit(s: &mut AgentState, msg: u8, payload: &[u8]) {
    let sys = &*s.syscalls;
    net_write_frame(
        sys,
        s.addr_evt,
        msg,
        payload.as_ptr(),
        payload.len(),
        s.out.as_mut_ptr(),
        64,
    );
}

unsafe fn refuse(s: &mut AgentState, addr: &[u8; 16], op: u8, reason: u8) {
    let mut p = [0u8; 18];
    p[..16].copy_from_slice(addr);
    p[16] = op;
    p[17] = reason;
    emit(s, netid::MSG_ADDR_REFUSED, &p);
    let mut a = [0u8; 12];
    let mut b = [0u8; 12];
    let op_s = fmt_u32(u32::from(op), &mut a);
    let r_s = fmt_u32(u32::from(reason), &mut b);
    log_addr(
        s,
        b"[fence_agent] refused ",
        addr,
        &[b" op=", op_s, b" reason=", r_s],
    );
}

/// Whether `addr` is the host this agent holds.
fn holds(s: &AgentState, addr: &[u8; 16]) -> bool {
    s.held != 0 && s.addr == *addr
}

/// `ADDR_ADD`: take custody of the host owning `addr`. Re-taking custody
/// of the held host mints a fresh token and generation, so a coordinator
/// that has taken over cannot be fenced by its predecessor's token.
unsafe fn take_custody(s: &mut AgentState, addr: &[u8; 16]) {
    if s.held != 0 && s.addr != *addr {
        // One host per instance: the actuator command names it.
        refuse(s, addr, netid::ADDR_ADD, netid::refusal::TABLE_FULL);
        return;
    }
    let Some(token) = mint_token(s) else {
        refuse(s, addr, netid::ADDR_ADD, netid::refusal::NO_ENTROPY);
        return;
    };
    s.generation_next = s.generation_next.wrapping_add(1);
    s.addr = *addr;
    s.token = token;
    s.generation = s.generation_next;
    s.held = 1;
    let mut p = [0u8; 36];
    p[..16].copy_from_slice(addr);
    p[16..32].copy_from_slice(&token);
    p[32..36].copy_from_slice(&s.generation.to_le_bytes());
    emit(s, netid::MSG_ADDR_ADDED, &p);
    let mut t = [0u8; 12];
    let g = fmt_u32(s.generation, &mut t);
    log_addr(s, b"[fence_agent] custody ", addr, &[b" gen=", g]);
}

/// `ADDR_FENCE` / `ADDR_ARM`: check the token against the custody and
/// start the actuator.
unsafe fn actuate(s: &mut AgentState, op: u8, addr: &[u8; 16], token: &[u8; 16]) {
    if !holds(s, addr) {
        refuse(s, addr, op, netid::refusal::NOT_FOUND);
        return;
    }
    if s.token != *token {
        refuse(s, addr, op, netid::refusal::TOKEN_MISMATCH);
        return;
    }
    if s.pending.phase != PHASE_IDLE {
        // One actuation at a time, its hold-up included. A second is
        // refused rather than queued, so a coordinator learns the host's
        // state is not yet settled instead of waiting on an answer that
        // would describe the wrong actuation.
        refuse(s, addr, op, netid::refusal::ACTUATOR);
        return;
    }
    let sys = &*s.syscalls;
    let (cmd, len) = if op == netid::ADDR_FENCE {
        (s.fence_cmd.as_mut_ptr(), s.fence_cmd_len as usize)
    } else {
        (s.restore_cmd.as_mut_ptr(), s.restore_cmd_len as usize)
    };
    let verb: &[u8] = if op == netid::ADDR_FENCE {
        b"[fence_agent] cutting "
    } else {
        b"[fence_agent] restoring "
    };
    log_addr(s, verb, addr, &[]);
    let rc = (sys.provider_call)(-1, PROC_SPAWN, cmd, len);
    if rc < 0 {
        // No executor on this node, or a command it will not run: the
        // host was not touched and the caller is told so.
        let mut t = [0u8; 12];
        let e = fmt_u32(rc.unsigned_abs(), &mut t);
        log_line(s, &[b"[fence_agent] actuator not spawned rc=-", e]);
        refuse(s, addr, op, netid::refusal::ACTUATOR);
        return;
    }
    s.proc_slot = rc;
    s.pending = Actuation {
        addr: *addr,
        generation: s.generation,
        phase: PHASE_RUNNING,
        op,
        _pad: [0; 2],
        quiet_until_ms: 0,
    };
}

/// Answer a confirmed cut: `MSG_ADDR_FENCED` at the wire, carrying this
/// agent's fence count as the cutoff index and the custody generation a
/// coordinator presents as `fence_gen`.
unsafe fn emit_fenced(s: &mut AgentState) {
    let addr = s.pending.addr;
    let generation = s.pending.generation;
    s.fence_count = s.fence_count.wrapping_add(1);
    let mut p = [0u8; 30];
    p[..16].copy_from_slice(&addr);
    p[16..20].copy_from_slice(&generation.to_le_bytes());
    p[20..28].copy_from_slice(&s.fence_count.to_le_bytes());
    p[28] = netid::cutoff::WIRE;
    p[29] = 0;
    emit(s, netid::MSG_ADDR_FENCED, &p);
    let mut a = [0u8; 12];
    let mut b = [0u8; 12];
    let g = fmt_u32(generation, &mut a);
    let c = fmt_u32(s.fence_count as u32, &mut b);
    log_addr(
        s,
        b"[fence_agent] fenced ",
        &addr,
        &[b" gen=", g, b" count=", c],
    );
}

/// Poll a running actuator. Its exit code is the answer: zero starts the
/// hold-up on a cut and completes a restore, anything else refuses.
unsafe fn poll_actuator(s: &mut AgentState) {
    if s.pending.phase != PHASE_RUNNING || s.proc_slot < 0 {
        return;
    }
    let sys = &*s.syscalls;
    // The command's output is not the signal, but it must be drained: the
    // executor reports a command done only once its output has been read.
    let mut n = 0;
    while n < 8 {
        let r = (sys.provider_call)(s.proc_slot, PROC_READ, s.drain.as_mut_ptr(), 256);
        if r <= 0 {
            break;
        }
        n += 1;
    }
    let mut st = [0u8; 4];
    let status = (sys.provider_call)(s.proc_slot, PROC_STATUS, st.as_mut_ptr(), 4);
    if status > 0 {
        return;
    }
    // `status == 0` is done, with the exit code in `st`; a negative status
    // is the executor refusing the query, which is no better than a failed
    // command.
    let code = if status == 0 {
        i32::from_le_bytes(st)
    } else {
        status
    };
    let _ = (sys.provider_call)(s.proc_slot, PROC_CLOSE, core::ptr::null_mut(), 0);
    s.proc_slot = -1;
    let addr = s.pending.addr;
    let op = s.pending.op;
    if code != 0 {
        s.pending = NO_ACTUATION;
        refuse(s, &addr, op, netid::refusal::ACTUATOR);
        return;
    }
    if op == netid::ADDR_FENCE {
        // The actuator has cut the host; the host may still be emitting on
        // what its supply holds. The fence is confirmed once that has
        // passed (`confirm_quiet`).
        let now = dev_millis(sys) as u32;
        s.pending.phase = PHASE_HOLDING;
        s.pending.quiet_until_ms = now.wrapping_add(s.quiet_after_ms);
        let mut t = [0u8; 12];
        let h = fmt_u32(s.quiet_after_ms, &mut t);
        log_addr(s, b"[fence_agent] cut ", &addr, &[b" holding ", h, b"ms"]);
        // A zero allowance is confirmed on this step rather than the next.
        confirm_quiet(s);
    } else {
        let generation = s.pending.generation;
        s.pending = NO_ACTUATION;
        let mut p = [0u8; 20];
        p[..16].copy_from_slice(&addr);
        p[16..20].copy_from_slice(&generation.to_le_bytes());
        emit(s, netid::MSG_ADDR_ARMED, &p);
        log_addr(s, b"[fence_agent] restored ", &addr, &[]);
    }
}

/// Confirm a cut once the fenced host's hold-up has passed.
unsafe fn confirm_quiet(s: &mut AgentState) {
    if s.pending.phase != PHASE_HOLDING {
        return;
    }
    let now = dev_millis(&*s.syscalls) as u32;
    // Wrap-safe "now is at or past the deadline".
    if now.wrapping_sub(s.pending.quiet_until_ms) > u32::MAX / 2 {
        return;
    }
    emit_fenced(s);
    s.pending = NO_ACTUATION;
}

unsafe fn service_ctl(s: &mut AgentState) {
    let sys = &*s.syscalls;
    let mut n = 0;
    while n < 8 {
        // Frame-aligned: a payload too large for `buf` is dropped whole
        // rather than left to desync the control channel for good.
        let (msg, copied, payload_len) =
            net_read_frame_aligned(sys, s.addr_ctl, s.buf.as_mut_ptr(), 64);
        if msg == 0 {
            break;
        }
        n += 1;
        if copied != payload_len || copied < 16 {
            continue;
        }
        let p = s.buf.as_ptr().add(netid::FRAME_HDR);
        let mut addr = [0u8; 16];
        core::ptr::copy_nonoverlapping(p, addr.as_mut_ptr(), 16);
        match msg {
            netid::ADDR_ADD => take_custody(s, &addr),
            netid::ADDR_DEL => {
                if holds(s, &addr) {
                    // An actuation in flight keeps its own copy of what it
                    // is fencing, so it still answers for the custody it
                    // was asked under.
                    s.held = 0;
                    s.token = [0; 16];
                }
            }
            netid::ADDR_FENCE | netid::ADDR_ARM
                if copied >= netid::ADDR_TOKEN_PAYLOAD_LEN =>
            {
                let mut token = [0u8; 16];
                core::ptr::copy_nonoverlapping(p.add(netid::TOKEN_OFF), token.as_mut_ptr(), 16);
                actuate(s, msg, &addr, &token);
            }
            _ => {}
        }
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<AgentState>() as u32
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
    if state_size < core::mem::size_of::<AgentState>() {
        return -6;
    }
    let s = &mut *(state as *mut AgentState);
    s.syscalls = syscalls as *const SyscallTable;
    s.addr_ctl = in_chan;
    s.addr_evt = out_chan;
    s.addr = [0; 16];
    s.token = [0; 16];
    s.generation = 0;
    s.held = 0;
    s.generation_next = 0;
    s.fence_count = 0;
    s.proc_slot = -1;
    s.pending = NO_ACTUATION;
    s.quiet_after_ms = DEFAULT_QUIET_AFTER_MS;
    s.fence_cmd_len = DEFAULT_FENCE_CMD.len() as u8;
    s.fence_cmd[..DEFAULT_FENCE_CMD.len()].copy_from_slice(DEFAULT_FENCE_CMD);
    s.restore_cmd_len = DEFAULT_RESTORE_CMD.len() as u8;
    s.restore_cmd[..DEFAULT_RESTORE_CMD.len()].copy_from_slice(DEFAULT_RESTORE_CMD);
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut AgentState);
    poll_actuator(s);
    confirm_quiet(s);
    service_ctl(s);
    0
}

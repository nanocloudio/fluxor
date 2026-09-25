//! Stateless Packet Filter PIC Module
//!
//! Reads parsed packet metadata (from eth_parser), evaluates match rules
//! from config params, and forwards or drops packets.
//!
//! # Channels
//!
//! - `in[0]`: Parsed packets (20-byte metadata + payload from eth_parser)
//! - `out[0]`: Accepted packets (same format, passed through)
//!
//! # Config Params
//!
//! Rules are configured via params:
//! - tag 1: rule_count (u8, max 8)
//! - tags 10-17: rule_N (8 bytes each):
//!   ```text
//!   [0]     action: 0=drop, 1=accept
//!   [1]     proto_match: 0=any, 6=TCP, 17=UDP, 1=ICMP
//!   [2..3]  dst_port_lo (u16 LE, 0=any)
//!   [4..5]  dst_port_hi (u16 LE, 0=same as lo)
//!   [6..7]  reserved
//!   ```
//!
//! Default policy: accept all (no rules = pass-through).
//!
//! # net.policy mode
//!
//! With `table` (tag 3, a name) the module enforces that net.policy table
//! instead of the static rules — the bare-metal realization of the contract.
//! It ATTACHes once (so the provider's CAPS report ENFORCED), polls the table's
//! generation every [`POLICY_POLL_STEPS`] steps and re-reads it on change.
//! Evaluation, per packet: the table's ALLOW/DROP rules in order (ingress =
//! the destination is the subject, egress = the source is), first match
//! decides; otherwise a packet whose destination is ingress-isolated, or whose
//! source is egress-isolated, is dropped — unless it is a TCP segment carrying
//! ACK without SYN, i.e. part of a flow already admitted. That is the
//! stateless approximation of a stateful filter; UDP replies to an isolated
//! workload's own requests are NOT distinguished and are dropped.

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
// Constants
// ============================================================================

const MAX_FRAME: usize = 1514;
const META_SIZE: usize = 20;
const MAX_RULES: usize = 8;
/// net.policy mode: filter rules and isolations held from the table.
const MAX_POLICY_RULES: usize = 64;
const MAX_ISOLATES: usize = 32;
/// Steps between generation polls: a table change takes effect within this.
const POLICY_POLL_STEPS: u32 = 1024;
const POLICY_BUF: usize = 4096;
const NP_READ: u32 = 0x1E04;
const NP_ATTACH: u32 = 0x1E05;
const RULE_ALLOW: u8 = 1;
const RULE_DROP: u8 = 2;
const RULE_ISOLATE: u8 = 3;

const ACTION_DROP: u8 = 0;
const ACTION_ACCEPT: u8 = 1;

// ============================================================================
// Rule
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct FilterRule {
    action: u8,
    proto_match: u8,
    dst_port_lo: u16,
    dst_port_hi: u16,
    _reserved: u16,
}

impl FilterRule {
    const fn empty() -> Self {
        Self {
            action: ACTION_ACCEPT,
            proto_match: 0,
            dst_port_lo: 0,
            dst_port_hi: 0,
            _reserved: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct FilterState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    rule_count: u8,
    default_action: u8,
    _pad: [u8; 2],
    rules: [FilterRule; MAX_RULES],
    accepted: u32,
    dropped: u32,
    // ---- net.policy mode ----
    table: [u8; 32],
    table_len: u8,
    attached: u8,
    poll: u32,
    generation: u64,
    policy_count: u16,
    isolate_count: u16,
    policy: [PolicyRule; MAX_POLICY_RULES],
    isolates: [Isolate; MAX_ISOLATES],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PolicyRule {
    allow: u8,
    dir: u8,
    proto: u8,
    subject_prefix: u8,
    peer_prefix: u8,
    subject: u32,
    peer: u32,
    port_lo: u16,
    port_hi: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Isolate {
    dir: u8,
    prefix: u8,
    subject: u32,
}

const POLICY_EMPTY: PolicyRule = PolicyRule {
    allow: 0,
    dir: 0,
    proto: 0,
    subject_prefix: 0,
    peer_prefix: 0,
    subject: 0,
    peer: 0,
    port_lo: 0,
    port_hi: 0,
};

fn in_net(addr: u32, net: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        !(u32::MAX >> prefix)
    };
    (addr & mask) == (net & mask)
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Load a table's records into the rule arrays. Unknown kinds (DNAT, which
/// this platform's provider refuses anyway, or advisory ones) are skipped.
unsafe fn load_policy(s: &mut FilterState, rules: &[u8]) {
    s.policy_count = 0;
    s.isolate_count = 0;
    let mut at = 0usize;
    while at + 2 <= rules.len() {
        let kind = rules[at];
        let len = rules[at + 1] as usize;
        let body_at = at + 2;
        if body_at + len > rules.len() {
            break;
        }
        let b = &rules[body_at..body_at + len];
        if (kind == RULE_ALLOW || kind == RULE_DROP)
            && len == 16
            && (s.policy_count as usize) < MAX_POLICY_RULES
        {
            let r = &mut s.policy[s.policy_count as usize];
            r.allow = (kind == RULE_ALLOW) as u8;
            r.dir = b[0];
            r.proto = b[1];
            r.subject = be32(b, 2);
            r.subject_prefix = b[6];
            r.peer = be32(b, 7);
            r.peer_prefix = b[11];
            r.port_lo = u16::from_be_bytes([b[12], b[13]]);
            r.port_hi = u16::from_be_bytes([b[14], b[15]]);
            if r.port_hi == 0 {
                r.port_hi = r.port_lo;
            }
            s.policy_count += 1;
        } else if kind == RULE_ISOLATE && len == 6 && (s.isolate_count as usize) < MAX_ISOLATES {
            let i = &mut s.isolates[s.isolate_count as usize];
            i.dir = b[0];
            i.subject = be32(b, 1);
            i.prefix = b[5];
            s.isolate_count += 1;
        }
        at = body_at + len;
    }
}

/// Poll the table's generation; re-read it when it moved.
unsafe fn refresh_policy(s: &mut FilterState, sys: &SyscallTable) {
    let mut buf = [0u8; POLICY_BUF];
    let mut gen: u64 = 0;
    let mut arg = [0u8; 1 + 32 + 8 + 4 + 8];
    let nl = s.table_len as usize;
    arg[0] = nl as u8;
    arg[1..1 + nl].copy_from_slice(&s.table[..nl]);
    let p = 1 + nl;
    arg[p..p + 8].copy_from_slice(&(buf.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 8..p + 12].copy_from_slice(&(POLICY_BUF as u32).to_le_bytes());
    arg[p + 12..p + 20].copy_from_slice(&(&mut gen as *mut u64 as u64).to_le_bytes());
    let n = (sys.provider_call)(-1, NP_READ, arg.as_mut_ptr(), p + 20);
    if n < 0 {
        // No such table yet (ENOENT), or no provider: nothing to enforce, so
        // nothing is isolated — the default is to pass.
        if s.generation != 0 {
            s.policy_count = 0;
            s.isolate_count = 0;
            s.generation = 0;
        }
        return;
    }
    if gen != s.generation {
        load_policy(s, &buf[..n as usize]);
        s.generation = gen;
    }
    if s.attached == 0 {
        (sys.provider_call)(-1, NP_ATTACH, core::ptr::null_mut(), 0);
        s.attached = 1;
    }
}

/// Is this TCP segment part of an established flow (ACK set, SYN clear)? The
/// payload after the metadata is the frame from L3 onward.
fn tcp_established(buf: &[u8], n: usize) -> bool {
    let l3 = META_SIZE;
    if n < l3 + 20 || buf[10] != 6 {
        return false;
    }
    let ihl = ((buf[l3] & 0x0F) as usize) * 4;
    let flags_at = l3 + ihl + 13;
    if flags_at >= n {
        return false;
    }
    let f = buf[flags_at];
    (f & 0x10) != 0 && (f & 0x02) == 0
}

unsafe fn evaluate_policy(s: &FilterState, buf: &[u8], n: usize) -> bool {
    let src = be32(buf, 2);
    let dst = be32(buf, 6);
    let proto = buf[10];
    let dport = u16::from_be_bytes([buf[13], buf[14]]);
    for r in &s.policy[..s.policy_count as usize] {
        let (subject, peer) = if r.dir == 0 { (dst, src) } else { (src, dst) };
        if !in_net(subject, r.subject, r.subject_prefix) || !in_net(peer, r.peer, r.peer_prefix) {
            continue;
        }
        if r.proto != 0 && r.proto != proto {
            continue;
        }
        if r.port_lo != 0 && (dport < r.port_lo || dport > r.port_hi) {
            continue;
        }
        return r.allow == 1;
    }
    for i in &s.isolates[..s.isolate_count as usize] {
        let who = if i.dir == 0 { dst } else { src };
        if in_net(who, i.subject, i.prefix) {
            return tcp_established(buf, n);
        }
    }
    true
}

// ============================================================================
// Param parsing
// ============================================================================

unsafe fn parse_params(s: &mut FilterState, params: *const u8, params_len: usize) {
    if params.is_null() || params_len == 0 {
        return;
    }

    let mut off = 0usize;
    while off + 2 <= params_len {
        let tag = *params.add(off);
        let len = *params.add(off + 1) as usize;
        off += 2;
        if off + len > params_len {
            break;
        }
        let val = params.add(off);

        match tag {
            1 => {
                // rule_count
                if len >= 1 {
                    s.rule_count = (*val).min(MAX_RULES as u8);
                }
            }
            2 => {
                // default_action
                if len >= 1 {
                    s.default_action = *val;
                }
            }
            3 => {
                // table — net.policy mode
                let n = len.min(32);
                let mut i = 0;
                while i < n {
                    s.table[i] = *val.add(i);
                    i += 1;
                }
                s.table_len = n as u8;
            }
            10..=17 => {
                // rule N
                let idx = (tag - 10) as usize;
                if idx < MAX_RULES && len >= 6 {
                    let rp = s.rules.as_mut_ptr().add(idx);
                    (*rp).action = *val;
                    (*rp).proto_match = *val.add(1);
                    (*rp).dst_port_lo = u16::from_le_bytes([*val.add(2), *val.add(3)]);
                    (*rp).dst_port_hi = u16::from_le_bytes([*val.add(4), *val.add(5)]);
                    (*rp)._reserved = 0;
                    if (*rp).dst_port_hi == 0 {
                        (*rp).dst_port_hi = (*rp).dst_port_lo;
                    }
                }
            }
            _ => {}
        }
        off += len;
    }
}

// ============================================================================
// Filter logic
// ============================================================================

unsafe fn evaluate(s: &FilterState, meta: &[u8; META_SIZE]) -> bool {
    if s.rule_count == 0 {
        return s.default_action != ACTION_DROP;
    }

    let mp = meta.as_ptr();
    let ip_proto = *mp.add(10);
    let dst_port = ((*mp.add(13) as u16) << 8) | *mp.add(14) as u16; // big-endian in meta

    let mut i = 0usize;
    while i < s.rule_count as usize {
        let rule = &*s.rules.as_ptr().add(i);

        // Protocol match
        let proto_ok = rule.proto_match == 0 || rule.proto_match == ip_proto;

        // Port match
        let port_ok =
            rule.dst_port_lo == 0 || (dst_port >= rule.dst_port_lo && dst_port <= rule.dst_port_hi);

        if proto_ok && port_ok {
            return rule.action == ACTION_ACCEPT;
        }
        i += 1;
    }

    // No rule matched: use default
    s.default_action != ACTION_DROP
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<FilterState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    syscalls: *const SyscallTable,
) -> i32 {
    let s = unsafe { &mut *(state as *mut FilterState) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s._ctrl_chan = ctrl_chan;
    s.rule_count = 0;
    s.default_action = ACTION_ACCEPT;
    s.accepted = 0;
    s.dropped = 0;
    s.table_len = 0;
    s.attached = 0;
    s.poll = 0;
    s.generation = 0;
    s.policy_count = 0;
    s.isolate_count = 0;
    s.policy = [POLICY_EMPTY; MAX_POLICY_RULES];
    s.isolates = [Isolate {
        dir: 0,
        prefix: 0,
        subject: 0,
    }; MAX_ISOLATES];

    // Init rules to empty
    let mut i = 0;
    while i < MAX_RULES {
        let rp = unsafe { s.rules.as_mut_ptr().add(i) };
        unsafe {
            *rp = FilterRule::empty();
        }
        i += 1;
    }

    unsafe {
        parse_params(s, params, params_len);
    }
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut FilterState);
    let sys = &*s.syscalls;

    if s.table_len > 0 {
        if s.poll == 0 {
            refresh_policy(s, sys);
            s.poll = POLICY_POLL_STEPS;
        }
        s.poll -= 1;
    }

    // Read parsed packet (metadata + payload)
    let mut buf = [0u8; META_SIZE + MAX_FRAME];
    let n = (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), buf.len());
    if n < META_SIZE as i32 {
        return 0; // Nothing to process
    }

    // Extract metadata
    let mut meta = [0u8; META_SIZE];
    let mp = meta.as_mut_ptr();
    let bp = buf.as_ptr();
    let mut i = 0;
    while i < META_SIZE {
        core::ptr::write_volatile(mp.add(i), core::ptr::read_volatile(bp.add(i)));
        i += 1;
    }

    let pass = if s.table_len > 0 {
        evaluate_policy(s, &buf, n as usize)
    } else {
        evaluate(s, &meta)
    };
    if pass {
        // Forward entire message (metadata + payload)
        (sys.channel_write)(s.out_chan, buf.as_ptr(), n as usize);
        s.accepted = s.accepted.wrapping_add(1);
    } else {
        s.dropped = s.dropped.wrapping_add(1);
    }

    2 // Burst (may have more)
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");

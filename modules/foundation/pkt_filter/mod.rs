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
//! Every [`POLICY_POLL_STEPS`] steps it polls the store-wide generation (a
//! zero-length READ) and, when it moved, re-reads the table. It ATTACHes
//! naming the table, which binds it as the table's one enforcer, and
//! re-issues ATTACH with the generation it applied in full — so the table's
//! READ state reports ENFORCED only while what this module holds is what the
//! store holds. A read lands whole in a spare buffer and is swapped in only
//! then, so a read the store moved under never tears what is in force. A
//! table past [`POLICY_BUF`] bytes is reported as not applied, and the
//! previous copy stays in force.
//! Evaluation, per packet, is the shared one (`net::policy::evaluate`, the
//! same rules as the Linux rendering): ALLOW/DROP in order, first match;
//! then ISOLATE; then services with no backends. A table that isolates
//! anything first passes a TCP segment carrying ACK without SYN — part of a
//! flow already admitted — as the rendering passes `ct state established`:
//! the stateless approximation of a stateful filter. UDP replies to an
//! isolated workload's own requests are NOT distinguished and are judged
//! as new.

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
/// Steps between generation polls: a table change takes effect within this.
const POLICY_POLL_STEPS: u32 = 1024;
const POLICY_BUF: usize = 4096;
const NP_READ: u32 = 0x1E04;
const NP_ATTACH: u32 = 0x1E05;
/// READ's state record: `[generation:u64][applied:u64][flags:u32][rsv:u32]`.
const NP_STATE: usize = 24;
const ERANGE: i32 = -34;
const ENOENT: i32 = -2;
use abi::contracts::net::policy as np;

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
    /// The store-wide generation last seen; the table is re-read only when
    /// it moves.
    store_gen: u64,
    /// The generation last reported to ATTACH as applied.
    reported: u64,
    /// The table as held: two buffers, `live` the one in force, `len` its
    /// bytes. A read goes to the other.
    live: u8,
    isolating: bool,
    len: u16,
    bufs: [[u8; POLICY_BUF]; 2],
}

/// The table in force.
fn held(s: &FilterState) -> &[u8] {
    s.bufs[(s.live & 1) as usize]
        .get(..s.len as usize)
        .unwrap_or(&[])
}

/// Write `v` little-endian at `arg[at..]`, panic-free.
fn put_le(arg: &mut [u8], at: usize, v: u64, n: usize) {
    let b = v.to_le_bytes();
    let mut i = 0;
    while i < n && i < 8 {
        if let Some(d) = arg.get_mut(at + i) {
            *d = b[i];
        }
        i += 1;
    }
}

fn get_u64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        v[i] = b.get(at + i).copied().unwrap_or(0);
        i += 1;
    }
    u64::from_le_bytes(v)
}

/// READ `name_len` bytes of `s.table` (0: the store) into `out`; the state
/// record lands in `state`.
unsafe fn np_read(
    s: &FilterState,
    sys: &SyscallTable,
    name_len: usize,
    out: &mut [u8],
    state: &mut [u8; NP_STATE],
) -> i32 {
    let mut arg = [0u8; 1 + 32 + 8 + 4 + 8];
    arg[0] = name_len as u8;
    let mut i = 0;
    while i < name_len && i < 32 {
        arg[1 + i] = s.table[i];
        i += 1;
    }
    let p = 1 + name_len;
    put_le(&mut arg, p, out.as_mut_ptr() as u64, 8);
    put_le(&mut arg, p + 8, out.len() as u64, 4);
    put_le(&mut arg, p + 12, state.as_mut_ptr() as u64, 8);
    (sys.provider_call)(-1, NP_READ, arg.as_mut_ptr(), p + 20)
}

/// ATTACH naming the table, reporting `applied`.
unsafe fn np_attach(s: &FilterState, sys: &SyscallTable, applied: u64) -> i32 {
    let mut arg = [0u8; 1 + 32 + 8];
    let nl = s.table_len as usize;
    arg[0] = nl as u8;
    let mut i = 0;
    while i < nl && i < 32 {
        arg[1 + i] = s.table[i];
        i += 1;
    }
    put_le(&mut arg, 1 + nl, applied, 8);
    (sys.provider_call)(-1, NP_ATTACH, arg.as_mut_ptr(), 1 + nl + 8)
}

/// Poll the store-wide generation; re-read the table when it moved, and
/// report what was applied.
unsafe fn refresh_policy(s: &mut FilterState, sys: &SyscallTable) {
    let mut state = [0u8; NP_STATE];
    let mut none = [0u8; 0];
    if np_read(s, sys, 0, &mut none, &mut state) == 0 {
        let g = get_u64(&state, 0);
        if g == s.store_gen && s.attached != 0 {
            return;
        }
        s.store_gen = g;
    }
    let spare = ((s.live ^ 1) & 1) as usize;
    let mut buf = s.bufs[spare];
    let n = np_read(s, sys, s.table_len as usize, &mut buf, &mut state);
    let gen = get_u64(&state, 0);
    let applied = if n >= 0 {
        if gen != s.generation {
            // The whole table landed in the spare buffer: swap it in.
            s.bufs[spare] = buf;
            s.live = spare as u8;
            s.len = n as u16;
            s.isolating = isolates_any(held(s));
            s.generation = gen;
            gen
        } else {
            s.reported
        }
    } else if n == ENOENT {
        // No such table: nothing to enforce, so nothing is isolated — the
        // default is to pass.
        s.len = 0;
        s.isolating = false;
        s.generation = 0;
        0
    } else if n == ERANGE {
        // Too big to hold: the previous copy stays, and is not this
        // generation.
        0
    } else {
        // A busy store (EAGAIN) or no provider: keep what is held, and read
        // the table again at the next poll whatever the store-wide
        // generation says (it has already moved past this one).
        s.store_gen = u64::MAX;
        s.reported
    };
    if s.attached == 0 || applied != s.reported {
        // EBUSY (another enforcer holds the table) leaves us unbound: our
        // filtering still runs, but vouches for nothing.
        if np_attach(s, sys, applied) == 0 {
            s.attached = 1;
            s.reported = applied;
        }
    }
}

/// Is this TCP segment part of an established flow (ACK set, SYN clear)? The
/// payload after the metadata is the frame from L3 onward.
fn tcp_established(buf: &[u8], n: usize) -> bool {
    let l3 = META_SIZE;
    let b = |i: usize| buf.get(i).copied().unwrap_or(0);
    if n < l3 + 20 || b(10) != 6 {
        return false;
    }
    let ihl = ((b(l3) & 0x0F) as usize) * 4;
    let flags_at = l3 + ihl + 13;
    if flags_at >= n {
        return false;
    }
    let f = b(flags_at);
    (f & 0x10) != 0 && (f & 0x02) == 0
}

/// Whether the table isolates anything (its rendering then passes
/// established flows first).
fn isolates_any(rules: &[u8]) -> bool {
    let mut at = 0;
    while let Some((kind, _, next)) = np::next_rule(rules, at) {
        if kind == np::rule::ISOLATE {
            return true;
        }
        at = next;
    }
    false
}

/// The table's verdict on the packet in `buf` (metadata, then L3 onward).
unsafe fn evaluate_policy(s: &FilterState, buf: &[u8], n: usize) -> bool {
    if s.isolating && tcp_established(buf, n) {
        return true;
    }
    let b = |i: usize| buf.get(i).copied().unwrap_or(0);
    let p = np::Packet {
        src: u32::from_be_bytes([b(2), b(3), b(4), b(5)]),
        dst: u32::from_be_bytes([b(6), b(7), b(8), b(9)]),
        proto: b(10),
        dport: u16::from_be_bytes([b(13), b(14)]),
    };
    np::evaluate(held(s), &p) == np::Verdict::Accept
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

declare_module_state_bytes!(FilterState);

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<FilterState>()
}

/// # Safety
/// Kernel module-ABI entry point: `syscalls` is the kernel's syscall table,
/// valid for the module's lifetime.
#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
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
    s.store_gen = 0;
    s.reported = 0;
    s.live = 0;
    s.len = 0;
    s.isolating = false;

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

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
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

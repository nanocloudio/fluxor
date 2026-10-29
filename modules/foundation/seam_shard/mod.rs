//! seam_shard — software receive-side scaling for the decision seam.
//!
//! One `ip`'s pre-transport seam, up to four director shards: every
//! `MSG_PKT_DECIDE` / `MSG_PKT_DECIDE6` goes to the shard a symmetric hash of
//! its canonical tuple names, so both directions of a flow (and every packet
//! of it) reach the same shard and each shard owns its flows' state alone:
//! the software equivalent of a NIC's symmetric receive-side hash, the shard
//! index written into the record's `rx_queue` byte as an RSS queue's would
//! be. What `ip` says later about a packet (`MSG_PKT_CLONED`,
//! `MSG_PKT_EXPIRED`, `MSG_PKT_MIRROR_LOST`) goes to the shard that was given
//! it — also after that shard has disposed of it, since `ip` answers a clone
//! request and reports a lost mirror copy after the disposition that
//! follows or carries it. A clone `ip` reports is the same shard's packet.
//!
//! The shards' dispositions and clone requests merge back onto `ip`'s
//! `packet_in`, whole records only, the shards served in turn. A shard may
//! only act on a packet it was given and has not yet disposed of (nor seen
//! expire): any other record — another shard's packet, one no shard holds,
//! a second disposition — is dropped and counted (`foreign`), so a stale or
//! misbehaving shard cannot settle a flow it does not own.
//!
//! One shard with no room for its next record holds the decision stream
//! behind it: records leave in the order `ip` wrote them, and the back
//! pressure reaches `ip`'s hold, whose deadline bounds it. A record longer
//! than any this seam carries (`REC_MAX`) is skipped whole and counted
//! (`oversize`).
//!
//! Ports: in[0] `decide_in` (from `ip.packet_out`), in[1..=4] `disp_k` (from
//! shard k); out[0] `disp_out` (to `ip.packet_in`), out[1..=4] `decide_k`
//! (to shard k). The shard count is the number of `decide_k` outputs wired
//! (at least one).

#![cfg_attr(not(feature = "host-test"), no_std)]
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

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

pub const SHARDS: usize = 4;
const HDR: usize = 3;
/// The longest record either way (a decision record, a disposition with a
/// copy block).
pub const REC_MAX: usize = 128;
const RECS_PER_STEP: usize = 64;
const LOG_PERIOD: u32 = 512;

use abi::contracts::net::packet as pkt;

const MSG_PKT_DECIDE: u8 = pkt::MSG_PKT_DECIDE;
const MSG_PKT_CLONED: u8 = pkt::MSG_PKT_CLONED;
const MSG_PKT_EXPIRED: u8 = pkt::MSG_PKT_EXPIRED;
const MSG_PKT_MIRROR_LOST: u8 = pkt::MSG_PKT_MIRROR_LOST;
const MSG_PKT_DECIDE6: u8 = pkt::MSG_PKT_DECIDE6;
const CMD_PKT_DISPOSE: u8 = pkt::CMD_PKT_DISPOSE;
const CMD_PKT_CLONE: u8 = pkt::CMD_PKT_CLONE;
const DECIDE_LEN: usize = pkt::DECIDE_LEN;
const DECIDE6_LEN: usize = pkt::DECIDE6_LEN;
/// `rx_queue`'s offset in each decision record.
const RXQ_V4: usize = 19;
const RXQ_V6: usize = 43;
/// The seam's hold slots: a packet id's slot bits.
const SLOTS: usize = 1 << pkt::PKT_SLOT_BITS;
const NO_SHARD: u8 = 0xFF;
const PKT_ID_NONE: u32 = pkt::PKT_ID_NONE;

#[repr(C)]
pub struct ShardState {
    syscalls: *const SyscallTable,
    decide_in: i32,
    disp_out: i32,
    disp_in: [i32; SHARDS],
    decide_out: [i32; SHARDS],
    shards: u8,
    /// The packet each hold slot was last given out as, and to which shard.
    owner_id: [u32; SLOTS],
    owner: [u8; SLOTS],
    /// Whether that packet still awaits its shard's disposition.
    open: [bool; SLOTS],
    /// Per input (`decide_in`, then `disp_k`), bytes of an oversize record
    /// still to skip.
    skip: [u32; 1 + SHARDS],
    next_merge: u8,
    step_count: u32,
    pub routed: [u32; SHARDS],
    pub merged: u32,
    pub foreign: u32,
    pub unknown: u32,
    pub oversize: u32,
    logged: [u32; 5],
    buf: [u8; REC_MAX],
}

fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

/// The symmetric hash of a flow: the same whichever endpoint is the source.
/// `a`/`b` are the endpoints' addresses (4 or 16 bytes), `pa`/`pb` their
/// ports, `proto` the transport.
pub fn flow_hash(a: &[u8], pa: u16, b: &[u8], pb: u16, proto: u8) -> u64 {
    let end = |addr: &[u8], port: u16| -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for &x in addr {
            h = (h ^ u64::from(x)).wrapping_mul(0x0100_0000_01b3);
        }
        mix64(h ^ (u64::from(port) << 48))
    };
    let (x, y) = (end(a, pa), end(b, pb));
    // Commutative: sum and xor of the two ends.
    mix64(x.wrapping_add(y) ^ (x ^ y).rotate_left(17) ^ u64::from(proto))
}

/// The shard of `hash` among `n` (multiply-shift: no division).
pub fn shard_of(hash: u64, n: u8) -> u8 {
    (((hash >> 32) * u64::from(n)) >> 32) as u8
}

/// The shard a decision record goes to, `None` if it is not one.
pub fn record_shard(kind: u8, p: &[u8], n: u8) -> Option<u8> {
    let (alen, ports) = match kind {
        MSG_PKT_DECIDE if p.len() == DECIDE_LEN => (4, 14),
        MSG_PKT_DECIDE6 if p.len() == DECIDE6_LEN => (16, 38),
        _ => return None,
    };
    let src = &p[6..6 + alen];
    let dst = &p[6 + alen..6 + 2 * alen];
    let sp = u16::from_le_bytes([p[ports], p[ports + 1]]);
    let dp = u16::from_le_bytes([p[ports + 2], p[ports + 3]]);
    Some(shard_of(flow_hash(src, sp, dst, dp, p[5]), n))
}

unsafe fn write_whole(sys: &SyscallTable, ch: i32, b: &[u8]) -> bool {
    ch >= 0 && (sys.channel_write)(ch, b.as_ptr(), b.len()) == b.len() as i32
}

/// Peek the next whole record on input `at` (0 `decide_in`, 1 + k
/// `disp_k`), channel `ch`, into `buf`: its kind and total length, or `None`
/// while it is incomplete. An oversize record is skipped whole — across
/// steps if it arrives over several — and counted.
unsafe fn peek_rec(s: &mut ShardState, at: usize, ch: i32) -> Option<(u8, usize)> {
    let sys = &*s.syscalls;
    if ch < 0 {
        return None;
    }
    loop {
        let mut scratch = [0u8; 64];
        while s.skip[at] > 0 {
            let n = (sys.channel_read)(ch, scratch.as_mut_ptr(), (s.skip[at] as usize).min(64));
            if n <= 0 {
                return None;
            }
            s.skip[at] -= n as u32;
        }
        if (sys.channel_peek)(ch, s.buf.as_mut_ptr(), HDR) < HDR as i32 {
            return None;
        }
        let total = HDR + u16::from_le_bytes([s.buf[1], s.buf[2]]) as usize;
        if total <= REC_MAX {
            if (sys.channel_peek)(ch, s.buf.as_mut_ptr(), total) < total as i32 {
                return None;
            }
            return Some((s.buf[0], total));
        }
        s.oversize = s.oversize.wrapping_add(1);
        s.skip[at] = total as u32;
    }
}

/// `ip` → shards.
unsafe fn route(s: &mut ShardState) {
    for _ in 0..RECS_PER_STEP {
        let Some((kind, total)) = peek_rec(s, 0, s.decide_in) else {
            return;
        };
        let sys = &*s.syscalls;
        let id = if total >= HDR + 4 {
            u32::from_le_bytes([s.buf[3], s.buf[4], s.buf[5], s.buf[6]])
        } else {
            u32::MAX
        };
        let slot = pkt::pkt_slot(id);
        let target = match record_shard(kind, &s.buf[HDR..total], s.shards) {
            Some(k) => {
                let at = HDR
                    + if kind == MSG_PKT_DECIDE {
                        RXQ_V4
                    } else {
                        RXQ_V6
                    };
                s.buf[at] = k;
                Some(k)
            }
            None => match kind {
                MSG_PKT_CLONED | MSG_PKT_EXPIRED | MSG_PKT_MIRROR_LOST
                    if s.owner[slot] != NO_SHARD && s.owner_id[slot] == id =>
                {
                    Some(s.owner[slot])
                }
                _ => None,
            },
        };
        match target {
            Some(k) => {
                let rec = &s.buf[..total];
                if !write_whole(sys, s.decide_out[k as usize], rec) {
                    // The shard has no room: the record, and the stream
                    // behind it, wait (back pressure reaches ip's hold).
                    return;
                }
                match kind {
                    MSG_PKT_DECIDE | MSG_PKT_DECIDE6 => {
                        s.owner[slot] = k;
                        s.owner_id[slot] = id;
                        s.open[slot] = true;
                    }
                    MSG_PKT_EXPIRED => s.open[slot] = false,
                    MSG_PKT_CLONED if total >= HDR + 8 => {
                        // The clone is a packet of the same shard's.
                        let cid = u32::from_le_bytes([s.buf[7], s.buf[8], s.buf[9], s.buf[10]]);
                        if cid != PKT_ID_NONE {
                            let cs = pkt::pkt_slot(cid);
                            s.owner[cs] = k;
                            s.owner_id[cs] = cid;
                            s.open[cs] = true;
                        }
                    }
                    _ => {}
                }
                s.routed[k as usize] = s.routed[k as usize].wrapping_add(1);
            }
            None => s.unknown = s.unknown.wrapping_add(1),
        }
        (sys.channel_discard)(s.decide_in, total);
    }
}

/// Shards → `ip`: whole records, one per shard in turn, each checked
/// against the packets that shard was given and has yet to dispose of.
unsafe fn merge(s: &mut ShardState) {
    let n = s.shards as usize;
    for _ in 0..RECS_PER_STEP {
        let mut moved = false;
        let start = s.next_merge as usize;
        for j in 0..n {
            let k = (start + j) % n;
            let ch = s.disp_in[k];
            let Some((kind, total)) = peek_rec(s, 1 + k, ch) else {
                continue;
            };
            let sys = &*s.syscalls;
            let id = if total >= HDR + 4 {
                u32::from_le_bytes([s.buf[3], s.buf[4], s.buf[5], s.buf[6]])
            } else {
                u32::MAX
            };
            let slot = pkt::pkt_slot(id);
            let own = matches!(kind, CMD_PKT_DISPOSE | CMD_PKT_CLONE)
                && s.owner[slot] == k as u8
                && s.owner_id[slot] == id
                && s.open[slot];
            if own {
                let rec = &s.buf[..total];
                if !write_whole(sys, s.disp_out, rec) {
                    return;
                }
                s.merged = s.merged.wrapping_add(1);
                if kind == CMD_PKT_DISPOSE {
                    s.open[slot] = false;
                }
            } else {
                s.foreign = s.foreign.wrapping_add(1);
            }
            (sys.channel_discard)(ch, total);
            s.next_merge = ((k + 1) % n) as u8;
            moved = true;
        }
        if !moved {
            return;
        }
    }
}

unsafe fn heartbeat(s: &mut ShardState) {
    let now = [
        s.routed.iter().fold(0u32, |a, b| a.wrapping_add(*b)),
        s.merged,
        s.foreign,
        s.unknown,
        s.oversize,
    ];
    if now == s.logged {
        return;
    }
    s.logged = now;
    let mut line = [0u8; 192];
    let mut at = 0;
    let mut num = [0u8; 10];
    for (label, v) in [
        (&b"[seam_shard] routed="[..], now[0]),
        (&b" merged="[..], now[1]),
        (&b" foreign="[..], now[2]),
        (&b" unknown="[..], now[3]),
        (&b" oversize="[..], now[4]),
        (&b" shard1="[..], s.routed[0]),
        (&b" shard2="[..], s.routed[1]),
        (&b" shard3="[..], s.routed[2]),
        (&b" shard4="[..], s.routed[3]),
    ] {
        line[at..at + label.len()].copy_from_slice(label);
        at += label.len();
        let k = fmt_u32_raw(num.as_mut_ptr(), v);
        line[at..at + k].copy_from_slice(&num[..k]);
        at += k;
    }
    dev_log(&*s.syscalls, 3, line.as_ptr(), at);
}

declare_module_state_bytes!(ShardState);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ShardState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table.
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
    if state_size < core::mem::size_of::<ShardState>() {
        return -6;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<ShardState>());
    let s = &mut *(state as *mut ShardState);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.decide_in = in_chan;
    s.disp_out = out_chan;
    s.owner = [NO_SHARD; SLOTS];
    let mut n = 0u8;
    for k in 0..SHARDS {
        s.disp_in[k] = dev_channel_port(sys, 0, (k + 1) as u8);
        s.decide_out[k] = dev_channel_port(sys, 1, (k + 1) as u8);
        if s.decide_out[k] >= 0 {
            // Shards are the wired outputs, from the first: a gap ends them.
            if n as usize == k {
                n += 1;
            }
        }
    }
    if n == 0 {
        let m = b"[seam_shard] refusing to construct: no shard output wired (decide_1)";
        dev_log(sys, 1, m.as_ptr(), m.len());
        return -22;
    }
    s.shards = n;
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut ShardState);
    s.step_count = s.step_count.wrapping_add(1);
    route(s);
    merge(s);
    if s.step_count.is_multiple_of(LOG_PERIOD) {
        heartbeat(s);
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_arena_size() -> u32 {
    0
}

//! The flow table: the contract's flow model (`net::policy::flow`) as this
//! module records it.
//!
//! **Storage.** `max_flows` records, their free stack and a hash index in
//! the module heap, sized at construction; nothing grows on a step. The
//! index holds two keys per flow — the tuple as its first packet carried it
//! (original) and the reverse (reply) — and is at least four times the
//! table, so its clusters stay short; it is never rehashed.
//!
//! **Full.** A new flow is recorded only into a free record. When none is
//! free, expired records are reclaimed first (a whole-table sweep); when
//! none of those is left either, the new flow is refused — its packet is
//! dropped and counted (`flows_refused`) — and no recorded flow is ever
//! evicted to make room.
//!
//! **Expiry.** A flow lives its state's timeout past its last packet:
//! checked on lookup, and by a sweep of [`SWEEP_SLICE`] records per step.

use super::*;
use abi::contracts::net::policy::flow as fm;

/// Flows held when the graph declares none (`max_flows`).
#[cfg(target_arch = "aarch64")]
pub(crate) const FLOWS_DEFAULT: u16 = 4096;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const FLOWS_DEFAULT: u16 = 64;
/// Records one step's expiry sweep visits.
const SWEEP_SLICE: usize = 32;

/// `Flow::flags`.
const F_LIVE: u8 = 0x01;
/// A packet has travelled the reply direction.
const F_REPLIED: u8 = 0x02;

/// A flow's key, as one packet carries it: addresses host order.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tuple {
    pub proto: u8,
    pub src: u32,
    pub dst: u32,
    pub sport: u16,
    pub dport: u16,
}

/// One recorded flow: the tuple of its first packet, and its state.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Flow {
    proto: u8,
    /// TCP state (`flow::SYN_SENT` …); 0 for other protocols.
    state: u8,
    flags: u8,
    /// TCP FIN bits (`flow::FIN_ORIG`, `flow::FIN_REPLY`).
    fins: u8,
    a_ip: u32,
    b_ip: u32,
    a_port: u16,
    b_port: u16,
    last_ms: u32,
}

impl Flow {
    const EMPTY: Flow = Flow {
        proto: 0,
        state: 0,
        flags: 0,
        fins: 0,
        a_ip: 0,
        b_ip: 0,
        a_port: 0,
        b_port: 0,
        last_ms: 0,
    };
}

/// Bytes the table of `n` flows takes in the heap: the records, the free
/// stack and the index.
pub(crate) const fn heap_bytes(n: usize) -> usize {
    n * core::mem::size_of::<Flow>() + n * 2 + index_len(n) * 4
}

/// Entries of the index for `n` flows: the power of two at least `4 n`.
const fn index_len(n: usize) -> usize {
    let mut i = 1usize;
    while i < n * 4 {
        i <<= 1;
    }
    i
}

/// Size the table into the heap. `false` when the heap cannot hold it.
pub(crate) unsafe fn size(s: &mut FilterState) -> bool {
    let n = s.max_flows as usize;
    if n == 0 {
        return true;
    }
    let sys = &*s.syscalls;
    let idx = index_len(n);
    let flows = heap_alloc(sys, (n * core::mem::size_of::<Flow>()) as u32) as *mut Flow;
    let free = heap_alloc(sys, (n * 2) as u32) as *mut u16;
    let index = heap_alloc(sys, (idx * 4) as u32) as *mut u32;
    if flows.is_null() || free.is_null() || index.is_null() {
        return false;
    }
    let mut i = 0;
    while i < n {
        flows.add(i).write(Flow::EMPTY);
        // Pushed high to low so the lowest record is taken first.
        free.add(i).write((n - 1 - i) as u16);
        i += 1;
    }
    let mut i = 0;
    while i < idx {
        index.add(i).write(index::EMPTY);
        i += 1;
    }
    s.flows = flows;
    s.flow_free = free;
    s.flow_index = index;
    s.flow_index_len = idx as u32;
    s.flow_free_top = n as u32;
    true
}

#[inline(always)]
unsafe fn flow<'a>(s: &FilterState, i: usize) -> &'a mut Flow {
    &mut *s.flows.add(i)
}

#[inline(always)]
unsafe fn index_of<'a>(s: &FilterState) -> &'a mut [u32] {
    if s.flow_index.is_null() {
        return &mut [];
    }
    core::slice::from_raw_parts_mut(s.flow_index, s.flow_index_len as usize)
}

#[inline(always)]
fn key_hash(seed: u32, proto: u8, src: u32, sport: u16, dst: u32, dport: u16) -> u32 {
    let a = index::mix32(src ^ seed);
    let b = index::mix32(dst.rotate_left(7) ^ u32::from(proto).wrapping_mul(0x9e37_79b9));
    index::mix32(a ^ b ^ (u32::from(sport) | (u32::from(dport) << 16)))
}

/// The hash index entry `slot` (flow `slot / 2`, key `slot % 2`) was
/// inserted under.
#[inline(always)]
unsafe fn home(s: &FilterState, slot: usize) -> u32 {
    let f = flow(s, slot / 2);
    if slot.is_multiple_of(2) {
        key_hash(s.seed, f.proto, f.a_ip, f.a_port, f.b_ip, f.b_port)
    } else {
        key_hash(s.seed, f.proto, f.b_ip, f.b_port, f.a_ip, f.a_port)
    }
}

/// Seconds flow `f` lives idle.
#[inline(always)]
fn timeout_s(f: &Flow) -> u32 {
    match f.proto {
        6 => fm::tcp_timeout_s(f.state),
        1 => fm::ICMP_S,
        _ if f.flags & F_REPLIED != 0 => fm::DATAGRAM_REPLIED_S,
        _ => fm::DATAGRAM_UNREPLIED_S,
    }
}

#[inline(always)]
fn expired(f: &Flow, now: u32) -> bool {
    now.wrapping_sub(f.last_ms) >= timeout_s(f).saturating_mul(1000)
}

/// The live flow `t` belongs to: `(flow, reply)`, `reply` when `t` travels
/// the reply direction. An expired flow found here is released.
pub(crate) unsafe fn find(s: &mut FilterState, t: &Tuple, now: u32) -> Option<(usize, bool)> {
    if s.flows.is_null() {
        return None;
    }
    let h = key_hash(s.seed, t.proto, t.src, t.sport, t.dst, t.dport);
    let found = index::lookup(index_of(s), h, |slot| {
        let f = flow(s, slot / 2);
        if f.flags & F_LIVE == 0 || f.proto != t.proto {
            return false;
        }
        if slot.is_multiple_of(2) {
            f.a_ip == t.src && f.a_port == t.sport && f.b_ip == t.dst && f.b_port == t.dport
        } else {
            f.b_ip == t.src && f.b_port == t.sport && f.a_ip == t.dst && f.a_port == t.dport
        }
    })?;
    let i = found / 2;
    if expired(flow(s, i), now) {
        release(s, i);
        s.flows_expired = s.flows_expired.wrapping_add(1);
        return None;
    }
    Some((i, !found.is_multiple_of(2)))
}

/// A packet of flow `i` (in the reply direction when `reply`) passed with
/// TCP `flags`: its state and clock move on. `false` when the segment
/// begins a new connection on the flow's ports — the flow is released, and
/// the packet is judged as new.
pub(crate) unsafe fn note(s: &mut FilterState, i: usize, reply: bool, flags: u8, now: u32) -> bool {
    let f = flow(s, i);
    if f.proto == 6 {
        if fm::tcp_reopens(f.state, flags) {
            release(s, i);
            return false;
        }
        let (st, fins) = fm::tcp_next(f.state, f.fins, reply, flags);
        f.state = st;
        f.fins = fins;
    }
    if reply {
        f.flags |= F_REPLIED;
    }
    f.last_ms = now;
    true
}

/// Record a flow for `t`, its first packet just passed (TCP `state` as
/// `flow::tcp_opens` gave it, else 0). `false` when no record is free even
/// after expired ones are reclaimed: the flow is refused.
pub(crate) unsafe fn make(s: &mut FilterState, t: &Tuple, state: u8, now: u32) -> bool {
    if s.flows.is_null() {
        s.flows_refused = s.flows_refused.wrapping_add(1);
        return false;
    }
    if s.flow_free_top == 0 {
        sweep(s, s.max_flows as usize, now);
        if s.flow_free_top == 0 {
            s.flows_refused = s.flows_refused.wrapping_add(1);
            return false;
        }
    }
    s.flow_free_top -= 1;
    let i = *s.flow_free.add(s.flow_free_top as usize) as usize;
    *flow(s, i) = Flow {
        proto: t.proto,
        state,
        flags: F_LIVE,
        fins: 0,
        a_ip: t.src,
        b_ip: t.dst,
        a_port: t.sport,
        b_port: t.dport,
        last_ms: now,
    };
    let seed = s.seed;
    let _ = index::insert(
        index_of(s),
        key_hash(seed, t.proto, t.src, t.sport, t.dst, t.dport),
        i * 2,
    );
    let _ = index::insert(
        index_of(s),
        key_hash(seed, t.proto, t.dst, t.dport, t.src, t.sport),
        i * 2 + 1,
    );
    s.flows_live = s.flows_live.saturating_add(1);
    true
}

/// Release flow `i`.
unsafe fn release(s: &mut FilterState, i: usize) {
    if flow(s, i).flags & F_LIVE == 0 {
        return;
    }
    let _ = index::remove(index_of(s), home(s, i * 2), i * 2, |slot| home(s, slot));
    let _ = index::remove(index_of(s), home(s, i * 2 + 1), i * 2 + 1, |slot| {
        home(s, slot)
    });
    flow(s, i).flags = 0;
    s.flows_live = s.flows_live.saturating_sub(1);
    if (s.flow_free_top as usize) < s.max_flows as usize {
        *s.flow_free.add(s.flow_free_top as usize) = i as u16;
        s.flow_free_top += 1;
    }
}

/// One slice of the expiry sweep: up to `budget` records.
pub(crate) unsafe fn sweep(s: &mut FilterState, budget: usize, now: u32) {
    let n = s.max_flows as usize;
    if n == 0 || s.flows.is_null() {
        return;
    }
    let mut k = 0;
    while k < budget.min(n) {
        let i = (s.flow_sweep as usize).checked_rem(n).unwrap_or(0);
        s.flow_sweep = (i + 1).checked_rem(n).unwrap_or(0) as u32;
        let f = flow(s, i);
        if f.flags & F_LIVE != 0 && expired(f, now) {
            release(s, i);
            s.flows_expired = s.flows_expired.wrapping_add(1);
        }
        k += 1;
    }
}

/// The step's sweep slice.
pub(crate) unsafe fn step(s: &mut FilterState, now: u32) {
    sweep(s, SWEEP_SLICE, now);
}

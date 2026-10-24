//! The datagram flow table.
//!
//! A workload's datagram endpoint is reached on its own address; what it
//! sends outside the cluster prefixes leaves from the node's address, from
//! an egress port the endpoint holds (`egress_port`). A reply to that port
//! is delivered only for a live flow — `(endpoint, peer)`, made by the
//! endpoint's own send — so a workload endpoint is never exposed on the
//! node's address to whoever sends there. A flow also carries what was
//! decided when it began: its packet-policy verdict (kept for the flow's
//! lifetime, as connection tracking keeps it) and, for a send to a service
//! address, the backend it was pinned to.
//!
//! **Storage.** The table and its index live in the module heap, sized at
//! construction from `max_dg_flows`; nothing grows on a step. Each lane
//! (the node's included) is guaranteed `dg_flow_floor` entries, and
//! construction requires `max_dg_flows ≥ (lanes + 1) × floor`, so a lane
//! under its floor always finds room; past it a lane draws on the shared
//! part, and when that is spent the send is refused `ENOBUFS`. An
//! inbound-only flow nobody answered is given up first; an egress flow is
//! never evicted while it is live.
//!
//! **Index.** One open-addressed hash (`index.rs`) over two keys per flow:
//! the address the endpoint sent to (the service address, for a translated
//! send) and the address replies come from (the backend). An untranslated
//! flow's two keys are one. The index is four times the table and never
//! rehashed.
//!
//! **Expiry.** The contract's flow model (`net::policy::flow`), as the host's
//! connection tracking keeps a datagram flow: a flow nobody has answered is
//! live until `dg_flow_idle_s` passes without traffic (by default the
//! model's `DATAGRAM_UNREPLIED_S`), an answered one until the longer of that
//! and `DATAGRAM_REPLIED_S`. Checked lazily on lookup, and by a sweep sliced
//! across steps.

use super::*;
use abi::contracts::net::policy as np;

/// Flows held when the graph declares none (`max_dg_flows`), and each
/// lane's floor (`dg_flow_floor`), and the idle timeout (`dg_flow_idle_s`).
#[cfg(target_arch = "aarch64")]
pub(crate) const FLOWS_DEFAULT: u16 = 1024;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const FLOWS_DEFAULT: u16 = 4;
#[cfg(target_arch = "aarch64")]
pub(crate) const FLOOR_DEFAULT: u8 = 16;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const FLOOR_DEFAULT: u8 = 1;
pub(crate) const IDLE_DEFAULT_S: u16 = np::flow::DATAGRAM_UNREPLIED_S as u16;
/// Entries one step's expiry sweep visits.
const SWEEP_SLICE: usize = 64;

/// `DgFlow::flags`.
pub(crate) const F_LIVE: u8 = 0x01;
/// Made by the endpoint's own send: never evicted while live.
pub(crate) const F_EGRESS: u8 = 0x02;
/// The peer has answered (or the endpoint has, to an inbound flow).
pub(crate) const F_REPLIED: u8 = 0x04;
/// The packet-policy verdict, decided when the flow began.
pub(crate) const F_ALLOW: u8 = 0x08;
/// The flow leaves from the node's address and the endpoint's egress port.
pub(crate) const F_VIA_EGRESS: u8 = 0x10;

/// One flow.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct DgFlow {
    pub ep: u8,
    pub lane: u8,
    pub flags: u8,
    pub _pad: u8,
    /// Where the endpoint sends: the service address for a translated
    /// flow, else the peer (host order).
    pub dst_ip: u32,
    pub dst_port: u16,
    /// Where replies come from: the pinned backend, else the peer.
    pub peer_port: u16,
    pub peer_ip: u32,
    /// The service generation the backend was pinned under.
    pub pin_gen: u32,
    /// The filter generation the verdict was made under.
    pub verdict_gen: u32,
    pub last_ms: u32,
}

impl DgFlow {
    pub(crate) const EMPTY: DgFlow = DgFlow {
        ep: 0,
        lane: 0,
        flags: 0,
        _pad: 0,
        dst_ip: 0,
        dst_port: 0,
        peer_port: 0,
        peer_ip: 0,
        pin_gen: 0,
        verdict_gen: 0,
        last_ms: 0,
    };
}

/// Size the table, its free stack and its index into the heap. `false`
/// (logged) when the declaration is inconsistent or does not fit.
pub(crate) unsafe fn size(s: &mut IpState) -> bool {
    let n = s.max_dg_flows as usize;
    let owners = s.lane_cap as usize + 1;
    if n < owners * s.dg_flow_floor as usize {
        let msg = b"[ip] refusing to construct: max_dg_flows is below (lanes + 1) x dg_flow_floor";
        dev_log(&*s.syscalls, 1, msg.as_ptr(), msg.len());
        return false;
    }
    if n == 0 {
        return true;
    }
    s.flows = heap_table(s, n, DgFlow::EMPTY);
    s.flow_free = heap_table(s, n, 0u16);
    let mut idx = 1usize;
    while idx < n * 4 {
        idx <<= 1;
    }
    s.flow_index = heap_table(s, idx, index::EMPTY);
    if s.flows.is_null() || s.flow_free.is_null() || s.flow_index.is_null() {
        refuse_capacity(s, b"the datagram flow table (max_dg_flows)");
        return false;
    }
    s.flow_index_len = idx as u32;
    let mut i = 0;
    while i < n {
        // Pushed high to low so the lowest entry is taken first.
        *s.flow_free.add(i) = (n - 1 - i) as u16;
        i += 1;
    }
    s.flow_free_top = n as u32;
    true
}

#[inline(always)]
unsafe fn flow<'a>(s: &IpState, i: usize) -> &'a mut DgFlow {
    &mut *s.flows.add(i)
}

#[inline(always)]
unsafe fn index_of<'a>(s: &IpState) -> &'a mut [u32] {
    if s.flow_index.is_null() {
        return &mut [];
    }
    core::slice::from_raw_parts_mut(s.flow_index, s.flow_index_len as usize)
}

#[inline(always)]
fn key_hash(seed: u32, ep: u8, ip: u32, port: u16) -> u32 {
    index::mix32(ip ^ seed ^ index::mix32(u32::from(port) | (u32::from(ep) << 16)))
}

/// The hash index entry `slot` (flow `slot / 2`, key `slot % 2`) was
/// inserted under.
#[inline(always)]
unsafe fn home(s: &IpState, slot: usize) -> u32 {
    let f = flow(s, slot / 2);
    if slot.is_multiple_of(2) {
        key_hash(s.index_seed, f.ep, f.dst_ip, f.dst_port)
    } else {
        key_hash(s.index_seed, f.ep, f.peer_ip, f.peer_port)
    }
}

#[inline(always)]
fn idle_ms(s: &IpState) -> u32 {
    u32::from(s.dg_flow_idle_s).saturating_mul(1000)
}

#[inline(always)]
fn expired(s: &IpState, f: &DgFlow, now: u32) -> bool {
    let idle = if f.flags & F_REPLIED != 0 {
        idle_ms(s).max(np::flow::DATAGRAM_REPLIED_S * 1000)
    } else {
        idle_ms(s)
    };
    now.wrapping_sub(f.last_ms) >= idle
}

/// The live flow endpoint `ep` sends to `(ip, port)` by (its send key), or
/// the one whose replies come from it (`reply`).
pub(crate) unsafe fn find(
    s: &mut IpState,
    ep: u8,
    ip: u32,
    port: u16,
    reply: bool,
) -> Option<usize> {
    if s.flows.is_null() {
        return None;
    }
    let now = dev_millis(&*s.syscalls) as u32;
    let h = key_hash(s.index_seed, ep, ip, port);
    let found = index::lookup(index_of(s), h, |slot| {
        let f = flow(s, slot / 2);
        if f.flags & F_LIVE == 0 || f.ep != ep {
            return false;
        }
        let want_reply = !slot.is_multiple_of(2);
        if want_reply != reply {
            return false;
        }
        if reply {
            f.peer_ip == ip && f.peer_port == port
        } else {
            f.dst_ip == ip && f.dst_port == port
        }
    })?;
    let i = found / 2;
    if expired(s, flow(s, i), now) {
        release(s, i);
        return None;
    }
    Some(i)
}

/// Note traffic on flow `i`.
#[inline(always)]
pub(crate) unsafe fn touch(s: &mut IpState, i: usize, replied: bool) {
    let now = dev_millis(&*s.syscalls) as u32;
    let f = flow(s, i);
    f.last_ms = now;
    if replied {
        f.flags |= F_REPLIED;
    }
}

/// Flow `i`, for reading and updating its decisions.
#[inline(always)]
pub(crate) unsafe fn get<'a>(s: &IpState, i: usize) -> &'a mut DgFlow {
    flow(s, i)
}

/// Whether lane `lane` may take one more flow: under its floor always;
/// past it while the shared part has room.
unsafe fn may_take(s: &IpState, lane: u8) -> bool {
    let floor = s.dg_flow_floor as u16;
    if lane_state(s, lane).flows < floor {
        return true;
    }
    let shared = (s.max_dg_flows as u32)
        .saturating_sub((s.lane_cap as u32 + 1) * u32::from(s.dg_flow_floor));
    s.flows_over_floor < shared
}

/// Give up one of `lane`'s inbound-only flows nobody answered, to make room.
unsafe fn evict_inbound(s: &mut IpState, lane: u8) -> bool {
    let mut i = 0;
    while i < s.max_dg_flows as usize {
        let f = flow(s, i);
        if f.flags & F_LIVE != 0 && f.lane == lane && f.flags & (F_EGRESS | F_REPLIED) == 0 {
            release(s, i);
            s.flow_evicted = s.flow_evicted.wrapping_add(1);
            return true;
        }
        i += 1;
    }
    false
}

/// Make a flow for endpoint `ep` of `lane`: `Err(ENOBUFS)` when the lane
/// is at its floor and the shared part is spent.
pub(crate) unsafe fn make(s: &mut IpState, mut f: DgFlow) -> Result<usize, i8> {
    if s.flows.is_null() {
        return Err(-105);
    }
    if !may_take(s, f.lane) && !evict_inbound(s, f.lane) {
        s.flow_refused = s.flow_refused.wrapping_add(1);
        return Err(-105); // ENOBUFS
    }
    if s.flow_free_top == 0 {
        // Only expired entries are left: reclaim one, as the sweep would.
        sweep(s, s.max_dg_flows as usize);
        if s.flow_free_top == 0 {
            s.flow_refused = s.flow_refused.wrapping_add(1);
            return Err(-105);
        }
    }
    s.flow_free_top -= 1;
    let i = *s.flow_free.add(s.flow_free_top as usize) as usize;
    f.flags |= F_LIVE;
    f.last_ms = dev_millis(&*s.syscalls) as u32;
    *flow(s, i) = f;
    let seed = s.index_seed;
    let _ = index::insert(
        index_of(s),
        key_hash(seed, f.ep, f.dst_ip, f.dst_port),
        i * 2,
    );
    let _ = index::insert(
        index_of(s),
        key_hash(seed, f.ep, f.peer_ip, f.peer_port),
        i * 2 + 1,
    );
    let st = lane_state(s, f.lane);
    st.flows += 1;
    if st.flows > s.dg_flow_floor as u16 {
        s.flows_over_floor += 1;
    }
    Ok(i)
}

/// Re-key flow `i`'s reply side (a re-picked backend).
pub(crate) unsafe fn repin(s: &mut IpState, i: usize, peer_ip: u32, peer_port: u16, gen: u32) {
    let seed = s.index_seed;
    let old = home(s, i * 2 + 1);
    let _ = index::remove(index_of(s), old, i * 2 + 1, |slot| home(s, slot));
    let f = flow(s, i);
    f.peer_ip = peer_ip;
    f.peer_port = peer_port;
    f.pin_gen = gen;
    let _ = index::insert(
        index_of(s),
        key_hash(seed, f.ep, peer_ip, peer_port),
        i * 2 + 1,
    );
}

/// Release flow `i`.
pub(crate) unsafe fn release(s: &mut IpState, i: usize) {
    let f = *flow(s, i);
    if f.flags & F_LIVE == 0 {
        return;
    }
    let _ = index::remove(index_of(s), home(s, i * 2), i * 2, |slot| home(s, slot));
    let _ = index::remove(index_of(s), home(s, i * 2 + 1), i * 2 + 1, |slot| {
        home(s, slot)
    });
    flow(s, i).flags = 0;
    let st = lane_state(s, f.lane);
    if st.flows > s.dg_flow_floor as u16 {
        s.flows_over_floor = s.flows_over_floor.saturating_sub(1);
    }
    st.flows = st.flows.saturating_sub(1);
    if (s.flow_free_top as usize) < s.max_dg_flows as usize {
        *s.flow_free.add(s.flow_free_top as usize) = i as u16;
        s.flow_free_top += 1;
    }
}

/// Release every flow endpoint `ep` holds (it closed).
pub(crate) unsafe fn release_endpoint(s: &mut IpState, ep: u8) {
    let mut i = 0;
    while i < s.max_dg_flows as usize && !s.flows.is_null() {
        let f = flow(s, i);
        if f.flags & F_LIVE != 0 && f.ep == ep {
            release(s, i);
        }
        i += 1;
    }
}

/// One slice of the expiry sweep: up to `budget` entries.
pub(crate) unsafe fn sweep(s: &mut IpState, budget: usize) {
    let n = s.max_dg_flows as usize;
    if n == 0 || s.flows.is_null() {
        return;
    }
    let now = dev_millis(&*s.syscalls) as u32;
    let mut k = 0;
    while k < budget.min(n) {
        let i = (s.flow_sweep as usize).checked_rem(n).unwrap_or(0);
        s.flow_sweep = (i + 1).checked_rem(n).unwrap_or(0) as u32;
        let f = flow(s, i);
        if f.flags & F_LIVE != 0 && expired(s, f, now) {
            release(s, i);
            s.flow_expired = s.flow_expired.wrapping_add(1);
        }
        k += 1;
    }
}

/// The step's sweep slice.
pub(crate) unsafe fn step(s: &mut IpState) {
    sweep(s, SWEEP_SLICE);
}

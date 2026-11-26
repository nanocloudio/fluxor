//! The node's segments, peer routes and held addresses, as this module
//! stores and realizes them (`net.route`).
//!
//! This module is the node's `net.route` provider on bare metal: the node
//! agent's SEGMENTS / ROUTES / HOLD / READ reach it through
//! `provider.rs`, which keeps the tables here with the shared core
//! (`fluxor_sdk::cores::net_tables`). A replace lands between steps; the next
//! step sees the table generation moved and realizes the tables, stating
//! each entry's state in the store, where READ finds it.
//!
//! - **Segments** give each workload address its cluster prefixes: a
//!   destination inside them is reached from the workload's own address,
//!   anything else from the node's.
//! - **Peer routes** are `prefix → peer node`, looked up before the single
//!   default gateway; a connection caches its next hop under the route
//!   epoch, so a stream pays the lookup once per table change. A route
//!   whose prefix overlaps the primary's link (its connected prefix) is
//!   never used and is stated `refused(conflict)`: the node's own link and
//!   its neighbours on it are reached directly whatever the table says.
//!   Checked again whenever the primary's address or netmask changes.
//! - **Held addresses** (`deliver` mode) are realized as node addresses
//!   (`held.rs`).
//!
//! The tables live in the module heap, sized from declared inputs
//! (`max_segments`, `max_peers`, `max_held`); a replace past them is refused
//! `ENOSPC` by the store.

use super::*;
use abi::contracts::net::route as nr;
use fluxor_sdk::cores::net_tables::RouteTables;

/// Segments held when the graph declares none (`max_segments`): a node's
/// own, with room for a few more — none on an MCU-class target, which hosts
/// no workloads.
#[cfg(target_arch = "aarch64")]
pub(crate) const SEGMENTS_DEFAULT: u8 = 4;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const SEGMENTS_DEFAULT: u8 = 0;

/// Size the route tables into the heap: each table, its spare and its
/// entry states. `false` when the heap cannot hold them.
pub(crate) unsafe fn size_tables(s: &mut IpState) -> bool {
    let segs = s.max_segments as usize;
    let peers = s.max_peers as usize;
    let held = s.max_held as usize;
    s.rt_meta = fluxor_sdk::cores::net_tables::RouteMeta::default();
    if segs > 0 {
        s.rt_segs = heap_table(s, segs, nr::Segment::EMPTY);
        s.rt_spare_segs = heap_table(s, segs, nr::Segment::EMPTY);
        s.rt_seg_state = heap_table(s, segs, nr::EntryState::EMPTY);
        if s.rt_segs.is_null() || s.rt_spare_segs.is_null() || s.rt_seg_state.is_null() {
            return false;
        }
    }
    if peers > 0 {
        s.rt_routes = heap_table(s, peers, nr::Route::EMPTY);
        s.rt_spare_routes = heap_table(s, peers, nr::Route::EMPTY);
        s.rt_route_state = heap_table(s, peers, nr::EntryState::EMPTY);
        if s.rt_routes.is_null() || s.rt_spare_routes.is_null() || s.rt_route_state.is_null() {
            return false;
        }
    }
    if held > 0 {
        s.rt_held = heap_table(s, held, nr::Held::EMPTY);
        s.rt_spare_held = heap_table(s, held, nr::Held::EMPTY);
        s.rt_held_state = heap_table(s, held, nr::EntryState::EMPTY);
        if s.rt_held.is_null() || s.rt_spare_held.is_null() || s.rt_held_state.is_null() {
            return false;
        }
    }
    s.route_epoch = 1;
    true
}

/// A slice over `n` entries at `p` (empty when there is no table).
#[inline(always)]
unsafe fn table<'a, T>(p: *mut T, n: usize) -> &'a mut [T] {
    if p.is_null() || n == 0 {
        return &mut [];
    }
    core::slice::from_raw_parts_mut(p, n)
}

/// The store over this instance's tables.
pub(crate) unsafe fn store<'a>(s: &'a mut IpState) -> RouteTables<'a> {
    let (segs, peers, held) = (
        s.max_segments as usize,
        s.max_peers as usize,
        s.max_held as usize,
    );
    RouteTables {
        segs: table(s.rt_segs, segs),
        routes: table(s.rt_routes, peers),
        held: table(s.rt_held, held),
        spare_segs: table(s.rt_spare_segs, segs),
        spare_routes: table(s.rt_spare_routes, peers),
        spare_held: table(s.rt_spare_held, held),
        seg_state: table(s.rt_seg_state, segs),
        route_state: table(s.rt_route_state, peers),
        held_state: table(s.rt_held_state, held),
        meta: &mut s.rt_meta,
    }
}

#[inline(always)]
unsafe fn segs<'a>(s: &IpState) -> &'a [nr::Segment] {
    if s.rt_segs.is_null() {
        return &[];
    }
    core::slice::from_raw_parts(s.rt_segs, s.rt_nsegs as usize)
}

#[inline(always)]
pub(crate) unsafe fn routes<'a>(s: &IpState) -> &'a [nr::Route] {
    if s.rt_routes.is_null() {
        return &[];
    }
    core::slice::from_raw_parts(s.rt_routes, s.rt_nroutes as usize)
}

#[inline(always)]
pub(crate) unsafe fn held<'a>(s: &IpState) -> &'a [nr::Held] {
    if s.rt_held.is_null() {
        return &[];
    }
    core::slice::from_raw_parts(s.rt_held, s.rt_nheld as usize)
}

/// A host-order IPv4 address as the tables carry it.
#[inline(always)]
pub(crate) fn addr16(ip: u32) -> [u8; 16] {
    let b = ip.to_be_bytes();
    let mut a = [0u8; 16];
    a[0] = b[0];
    a[1] = b[1];
    a[2] = b[2];
    a[3] = b[3];
    a
}

/// The host-order IPv4 address of a table address.
#[inline(always)]
pub(crate) fn ip_of(a: &[u8; 16]) -> u32 {
    u32::from_be_bytes([a[0], a[1], a[2], a[3]])
}

/// Whether `dst` is on the primary's link.
#[inline(always)]
pub(crate) fn on_link(s: &IpState, dst: u32) -> bool {
    s.netmask == 0 || (dst & s.netmask) == (s.local_ip & s.netmask)
}

/// The length of a contiguous netmask (host order).
#[inline(always)]
fn mask_len(mask: u32) -> u8 {
    let mut n = 0u8;
    while n < 32 && mask & 0x8000_0000u32.checked_shr(u32::from(n)).unwrap_or(0) != 0 {
        n += 1;
    }
    n
}

/// Whether peer route `r` overlaps the primary's link — the connected prefix
/// of the node's own address. Such a route is never used.
#[inline(always)]
pub(crate) fn takes_uplink(s: &IpState, r: &nr::Route) -> bool {
    if s.local_ip == 0 || r.prefix.family != nr::FAM_IPV4 {
        return false;
    }
    let up = nr::Prefix {
        family: nr::FAM_IPV4,
        len: mask_len(s.netmask),
        addr: addr16(s.local_ip & s.netmask),
    };
    r.prefix.overlaps(&up)
}

/// The peer node a route sends `dst` to: the longest matching peer route
/// whose peer is on the link, if any.
pub(crate) unsafe fn route_peer(s: &IpState, dst: u32) -> Option<u32> {
    let d = addr16(dst);
    let mut best: Option<(u8, u32)> = None;
    for r in routes(s) {
        if r.prefix.family != nr::FAM_IPV4
            || !r.prefix.contains(nr::FAM_IPV4, &d)
            || takes_uplink(s, r)
        {
            continue;
        }
        let peer = ip_of(&r.peer);
        if !on_link(s, peer) {
            continue;
        }
        if best.is_none_or(|(len, _)| r.prefix.len > len) {
            best = Some((r.prefix.len, peer));
        }
    }
    best.map(|(_, p)| p)
}

/// Whether `dst` lies inside the segment that holds `src` (a workload's own
/// address) or one of its cluster prefixes: such a destination is reached
/// from the workload's address; anything else leaves from the node's — as
/// a Linux node translates a segment's egress outside those same prefixes.
pub(crate) unsafe fn in_cluster(s: &IpState, src: u32, dst: u32) -> bool {
    let a = addr16(src);
    let d = addr16(dst);
    for seg in segs(s) {
        if !seg.prefix.contains(nr::FAM_IPV4, &a) {
            continue;
        }
        if seg.prefix.contains(nr::FAM_IPV4, &d) {
            return true;
        }
        for c in seg.cluster() {
            if c.contains(nr::FAM_IPV4, &d) {
                return true;
            }
        }
    }
    false
}

/// Realize the tables when a replace moved them, or the node's own address
/// moved under them; then state every entry.
pub(crate) unsafe fn step(s: &mut IpState) {
    let gen = s.rt_meta.table_gen;
    if gen == s.rt_gen && s.rt_realized_ip == s.local_ip && s.rt_realized_mask == s.netmask {
        return;
    }
    s.rt_gen = gen;
    s.rt_realized_ip = s.local_ip;
    s.rt_realized_mask = s.netmask;
    let [segs, routes, held] = s.rt_meta.count;
    s.rt_nsegs = segs.min(u16::from(s.max_segments)) as u8;
    s.rt_nroutes = routes.min(s.max_peers);
    s.rt_nheld = held.min(s.max_held);
    // Every cached next hop and source choice is looked up afresh.
    s.route_epoch = s.route_epoch.wrapping_add(1).max(1);
    super::held::realize(s);
    report(s);
}

/// One entry's state.
fn entry(kind: u8, index: usize, state: u8, reason: u8) -> nr::EntryState {
    nr::EntryState {
        kind,
        state,
        reason,
        cutoff_kind: 0,
        index: index as u16,
        install_gen: 0,
        cutoff: 0,
    }
}

/// State what took effect: every segment held (its addresses are this
/// module's to hold), every route whose peer is on the link (one that is
/// not cannot be reached directly, the only carriage there is) and that does
/// not overlap the primary's link (`refused(conflict)`), and every held
/// address as `held.rs` holds it.
pub(crate) unsafe fn report(s: &mut IpState) {
    let mut i = 0;
    while i < s.rt_nsegs as usize {
        let e = entry(nr::entry::KIND_SEGMENT, i, nr::state::REALIZED, 0);
        store(s).set_state(e);
        i += 1;
    }
    let mut i = 0;
    while i < s.rt_nroutes as usize {
        let r = *s.rt_routes.add(i);
        let e = if takes_uplink(s, &r) {
            entry(
                nr::entry::KIND_ROUTE,
                i,
                nr::state::REFUSED,
                nr::reason::CONFLICT,
            )
        } else if on_link(s, ip_of(&r.peer)) {
            entry(nr::entry::KIND_ROUTE, i, nr::state::REALIZED, 0)
        } else {
            entry(
                nr::entry::KIND_ROUTE,
                i,
                nr::state::REFUSED,
                nr::reason::UNSUPPORTED,
            )
        };
        store(s).set_state(e);
        i += 1;
    }
    let mut i = 0;
    while i < s.rt_nheld as usize {
        let e = super::held::entry_state(s, i);
        store(s).set_state(e);
        i += 1;
    }
}

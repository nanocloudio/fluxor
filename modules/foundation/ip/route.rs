//! The node's segments, peer routes and held addresses, as this module
//! realizes them (`net.route`).
//!
//! The node agent writes the tables to the kernel; this module reads them
//! with `TAKE` — a provider-only op admitted from the registered
//! net-identity provider, no `platform_raw` — polling the table generation
//! (a `TAKE` into an 8-byte buffer answers `ERANGE` and still writes it) and
//! re-reading only when it moved. Each entry's state goes back with `REPORT`.
//!
//! - **Segments** give each workload address its cluster prefixes: a
//!   destination inside them is reached from the workload's own address,
//!   anything else from the node's.
//! - **Peer routes** are `prefix → peer node`, looked up before the single
//!   default gateway; a connection caches its next hop under the route
//!   epoch, so a stream pays the lookup once per table change.
//! - **Held addresses** (`deliver` mode) are realized as node addresses
//!   (`held.rs`).
//!
//! The tables live in the module heap, sized from declared inputs
//! (`max_segments`, `max_peers`, `max_held`). Entries past what this module
//! declared are not held and are reported refused (`table_full`), so the
//! writer sees the gap; tables that do not fit `TAKE`'s buffer at all leave
//! the previous copy in force, and every entry is reported `table_full`.
//!
//! A `REPORT` indexes the tables of the last `TAKE`; when they have moved
//! since, the kernel refuses it (`EAGAIN`) and the tables are taken again at
//! the next poll.

use super::*;
use abi::contracts::net::route as nr;

/// How often the table generation is polled, wall clock.
pub(crate) const ROUTE_POLL_MS: u32 = 200;
/// How often a node with no `net.route` provider is asked again.
const ROUTE_ABSENT_POLL_MS: u32 = 5000;
/// Segments held when the graph declares none (`max_segments`): a node's
/// own, with room for a few more — none on an MCU-class target, which hosts
/// no workloads.
#[cfg(target_arch = "aarch64")]
pub(crate) const SEGMENTS_DEFAULT: u8 = 4;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const SEGMENTS_DEFAULT: u8 = 0;

const ERANGE: i32 = -34;
const EAGAIN: i32 = -11;

/// Bytes `TAKE` needs for the declared tables, at most.
pub(crate) fn take_bytes(max_segments: u8, max_peers: u16, max_held: u16) -> usize {
    nr::TAKE_HEAD
        + max_segments as usize
            * (nr::segment::HEAD + nr::MAX_CLUSTER_PREFIXES * nr::segment::CLUSTER)
        + max_peers as usize * nr::peer::SIZE
        + max_held as usize * nr::held::SIZE
}

/// Size the route tables into the heap. `false` when the heap cannot hold
/// them.
pub(crate) unsafe fn size_tables(s: &mut IpState) -> bool {
    let segs = s.max_segments as usize;
    let peers = s.max_peers as usize;
    let held = s.max_held as usize;
    let buf = take_bytes(s.max_segments, s.max_peers, s.max_held);
    s.rt_buf = heap_table(s, buf, 0u8);
    s.rt_buf_len = buf as u32;
    if s.rt_buf.is_null() {
        return false;
    }
    if segs > 0 {
        s.rt_segs = heap_table(s, segs, nr::Segment::EMPTY);
        if s.rt_segs.is_null() {
            return false;
        }
    }
    if peers > 0 {
        s.rt_routes = heap_table(s, peers, nr::Route::EMPTY);
        if s.rt_routes.is_null() {
            return false;
        }
    }
    if held > 0 {
        s.rt_held = heap_table(s, held, nr::Held::EMPTY);
        if s.rt_held.is_null() {
            return false;
        }
    }
    s.route_epoch = 1;
    true
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

/// The peer node a route sends `dst` to: the longest matching peer route
/// whose peer is on the link, if any.
pub(crate) unsafe fn route_peer(s: &IpState, dst: u32) -> Option<u32> {
    let d = addr16(dst);
    let mut best: Option<(u8, u32)> = None;
    for r in routes(s) {
        if r.prefix.family != nr::FAM_IPV4 || !r.prefix.contains(nr::FAM_IPV4, &d) {
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

/// Poll the table generation; re-read and re-report when it moved.
pub(crate) unsafe fn step(s: &mut IpState) {
    let now = dev_millis(&*s.syscalls) as u32;
    let every = if s.rt_absent {
        ROUTE_ABSENT_POLL_MS
    } else {
        ROUTE_POLL_MS
    };
    if s.rt_polled_ms != 0 && now.wrapping_sub(s.rt_polled_ms) < every {
        return;
    }
    s.rt_polled_ms = if now == 0 { 1 } else { now };
    let sys = &*s.syscalls;
    let mut head = [0u8; 8];
    let rc = (sys.provider_call)(-1, nr::TAKE, head.as_mut_ptr(), head.len());
    if rc != ERANGE && rc < 0 {
        // No provider, or not the registered net-identity provider: no
        // tables to realize.
        s.rt_absent = true;
        return;
    }
    s.rt_absent = false;
    let gen = u64::from_le_bytes(head);
    if gen == s.rt_gen && s.rt_have {
        // The tables are as they were; the node's own address may not be
        // (a held address is realized only on the primary's link).
        if s.rt_realized_ip != s.local_ip {
            s.rt_realized_ip = s.local_ip;
            super::held::realize(s);
            report(s);
        }
        return;
    }
    s.rt_realized_ip = s.local_ip;
    take(s, gen);
}

/// The table counts a TAKE header states: `(segments, routes, held)`.
fn take_counts(buf: &[u8]) -> Option<(u8, u16, u16)> {
    let (Some(&ns), Some(&r0), Some(&r1), Some(&h0), Some(&h1)) = (
        buf.get(8),
        buf.get(10),
        buf.get(11),
        buf.get(12),
        buf.get(13),
    ) else {
        return None;
    };
    Some((
        ns,
        u16::from_le_bytes([r0, r1]),
        u16::from_le_bytes([h0, h1]),
    ))
}

/// Read the whole tables and adopt them.
///
/// Entries past what this module declared are not held, and are reported
/// `refused(table_full)`, so the writer sees the gap. Tables whose records
/// do not fit TAKE's buffer at all (`ERANGE`) are not adopted: the previous
/// copy stays in force, and every entry of the new tables is reported
/// `table_full` against the counts the header still carries.
unsafe fn take(s: &mut IpState, gen: u64) {
    let sys = &*s.syscalls;
    let rc = (sys.provider_call)(-1, nr::TAKE, s.rt_buf, s.rt_buf_len as usize);
    let buf = core::slice::from_raw_parts(s.rt_buf, s.rt_buf_len as usize);
    if rc == ERANGE {
        s.rt_overflow = s.rt_overflow.wrapping_add(1);
        s.rt_gen = nr::generation(buf).unwrap_or(gen);
        s.rt_have = true;
        if let Some((ns, nroutes, nheld)) = take_counts(buf) {
            report_overflow(s, ns, nroutes, nheld);
        }
        return;
    }
    if rc < nr::TAKE_HEAD as i32 {
        return;
    }
    let buf = buf.get(..rc as usize).unwrap_or(&[]);
    let Some((ns, nroutes, nheld)) = take_counts(buf) else {
        return;
    };
    // Decode the whole of it before adopting any: the kernel validated every
    // record, so a malformed one means the copy is not the tables, and the
    // previous copy stays.
    let mut at = nr::TAKE_HEAD;
    let mut i = 0;
    while i < ns as usize {
        let Some((_, next)) = nr::segment_at(buf, at) else {
            return;
        };
        at = next;
        i += 1;
    }
    let routes_at = at;
    let held_at = routes_at + nroutes as usize * nr::peer::SIZE;
    if held_at + nheld as usize * nr::held::SIZE != buf.len() {
        return;
    }
    let mut i = 0;
    while i < nroutes as usize {
        if nr::route_at(buf, routes_at + i * nr::peer::SIZE).is_none() {
            return;
        }
        i += 1;
    }
    let mut i = 0;
    while i < nheld as usize {
        if nr::held_at(buf, held_at + i * nr::held::SIZE).is_none() {
            return;
        }
        i += 1;
    }
    // Adopt each table's leading entries, as many as this module holds.
    let mut at = nr::TAKE_HEAD;
    let mut i = 0;
    while i < ns as usize {
        if let Some((seg, next)) = nr::segment_at(buf, at) {
            if i < s.max_segments as usize {
                *s.rt_segs.add(i) = seg;
            }
            at = next;
        }
        i += 1;
    }
    s.rt_nsegs = ns.min(s.max_segments);
    let kept = nroutes.min(s.max_peers);
    let mut i = 0;
    while i < kept as usize {
        if let Some(r) = nr::route_at(buf, routes_at + i * nr::peer::SIZE) {
            *s.rt_routes.add(i) = r;
        }
        i += 1;
    }
    s.rt_nroutes = kept;
    let kept = nheld.min(s.max_held);
    let mut i = 0;
    while i < kept as usize {
        if let Some(h) = nr::held_at(buf, held_at + i * nr::held::SIZE) {
            *s.rt_held.add(i) = h;
        }
        i += 1;
    }
    s.rt_nheld = kept;
    s.rt_tsegs = ns;
    s.rt_troutes = nroutes;
    s.rt_theld = nheld;
    s.rt_gen = nr::generation(buf).unwrap_or(gen);
    s.rt_have = true;
    // Every cached next hop and source choice is looked up afresh.
    s.route_epoch = s.route_epoch.wrapping_add(1).max(1);
    super::held::realize(s);
    report(s);
}

/// One entry's state, as REPORT carries it.
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

/// Report what took effect: every segment held (its addresses are this
/// module's to hold), every route held whose peer is on the link (one that
/// is not cannot be reached directly, the only carriage there is), every
/// held address held (`held.rs`), and each table's entries past what this
/// module holds as `table_full`.
pub(crate) unsafe fn report(s: &mut IpState) {
    let mut n = 0usize;
    let mut i = 0;
    while i < s.rt_tsegs as usize {
        let e = if i < s.rt_nsegs as usize {
            entry(nr::entry::KIND_SEGMENT, i, nr::state::REALIZED, 0)
        } else {
            full(nr::entry::KIND_SEGMENT, i)
        };
        report_one(s, &mut n, e);
        i += 1;
    }
    let mut i = 0;
    while i < s.rt_troutes as usize {
        let e = if i >= s.rt_nroutes as usize {
            full(nr::entry::KIND_ROUTE, i)
        } else if on_link(s, ip_of(&(*s.rt_routes.add(i)).peer)) {
            entry(nr::entry::KIND_ROUTE, i, nr::state::REALIZED, 0)
        } else {
            entry(
                nr::entry::KIND_ROUTE,
                i,
                nr::state::REFUSED,
                nr::reason::UNSUPPORTED,
            )
        };
        report_one(s, &mut n, e);
        i += 1;
    }
    let mut i = 0;
    while i < s.rt_theld as usize {
        let e = if i < s.rt_nheld as usize {
            super::held::entry_state(s, i)
        } else {
            full(nr::entry::KIND_HELD, i)
        };
        report_one(s, &mut n, e);
        i += 1;
    }
    report_flush(s, &mut n);
}

/// An entry past what this module holds.
fn full(kind: u8, index: usize) -> nr::EntryState {
    entry(kind, index, nr::state::REFUSED, nr::reason::TABLE_FULL)
}

/// Tables whose records did not fit: none of their entries is in effect as
/// written. The copy in force is the previous one.
unsafe fn report_overflow(s: &mut IpState, ns: u8, nroutes: u16, nheld: u16) {
    let mut n = 0usize;
    let mut i = 0;
    while i < ns as usize {
        report_one(s, &mut n, full(nr::entry::KIND_SEGMENT, i));
        i += 1;
    }
    let mut i = 0;
    while i < nroutes as usize {
        report_one(s, &mut n, full(nr::entry::KIND_ROUTE, i));
        i += 1;
    }
    let mut i = 0;
    while i < nheld as usize {
        report_one(s, &mut n, full(nr::entry::KIND_HELD, i));
        i += 1;
    }
    report_flush(s, &mut n);
}

/// Entries REPORT carries per call.
const REPORT_BATCH: usize = 16;

unsafe fn report_one(s: &mut IpState, n: &mut usize, e: nr::EntryState) {
    let at = *n * nr::entry::SIZE;
    let _ = nr::write_entry(&mut s.rt_report, at, &e);
    *n += 1;
    if *n == REPORT_BATCH {
        report_flush(s, n);
    }
}

unsafe fn report_flush(s: &mut IpState, n: &mut usize) {
    if *n == 0 {
        return;
    }
    let len = *n * nr::entry::SIZE;
    let sys = &*s.syscalls;
    let rc = (sys.provider_call)(-1, nr::REPORT, s.rt_report.as_mut_ptr(), len);
    *n = 0;
    if rc == EAGAIN {
        // The tables moved since they were taken: take them again at the
        // next poll, and report against those.
        s.rt_have = false;
    }
}

/// Bytes of one REPORT batch.
pub(crate) const REPORT_BYTES: usize = REPORT_BATCH * nr::entry::SIZE;

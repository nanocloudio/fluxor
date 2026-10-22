//! Service translation for traffic this node originates (`net.policy` DNAT
//! with `scope = local`).
//!
//! A dial or datagram from this node — a workload's or the node's own — to a
//! service address is sent to one of its backends instead: at `connect_v4`
//! (literal and resolved-name dials alike), at a datagram `SEND_TO`, and at
//! the resolver's own sends, before the same-node check, so a backend on
//! this node is reached directly.
//!
//! **Index.** The DNAT records of every table this instance holds, merged
//! per `(proto, vip, vport)` — the writer emits one record per backend — into
//! a hashed index of services, each with its backend list. Only `scope =
//! local` records are realized here (the provider refuses the rest). The
//! index is double-buffered: a table change rebuilds the spare copy a
//! [`SLICE`] of records per step and swaps it in whole, so the copy in use
//! serves until the swap and no step pays for the whole table. Each swap
//! advances the service generation a datagram flow's pin is stamped with.
//!
//! **Choice.** A stream picks a backend once and keeps it for its lifetime
//! (an established stream to a removed backend continues). A datagram flow
//! is pinned to one, and re-picks on its next send when its backend has
//! left the set. A service with no backends refuses: `ECONNREFUSED` for a
//! stream, `MSG_DG_ERROR` for a datagram.

use super::*;
use abi::contracts::net::policy as np;

/// Records one step's rebuild slice handles, and index entries one step
/// clears.
const SLICE: usize = 64;
const CLEAR_SLICE: usize = 1024;
/// No backend.
const NONE: u16 = u16::MAX;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Svc {
    pub proto: u8,
    pub flags: u8,
    pub vport: u16,
    pub vip: u32,
    pub n: u16,
    pub head: u16,
    pub tail: u16,
    pub _pad: u16,
}

impl Svc {
    const EMPTY: Svc = Svc {
        proto: 0,
        flags: 0,
        vport: 0,
        vip: 0,
        n: 0,
        head: NONE,
        tail: NONE,
        _pad: 0,
    };
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Backend {
    pub addr: u32,
    pub port: u16,
    pub next: u16,
}

impl Backend {
    const EMPTY: Backend = Backend {
        addr: 0,
        port: 0,
        next: NONE,
    };
}

/// One copy of the index.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SvcCopy {
    pub svcs: *mut Svc,
    pub backends: *mut Backend,
    pub index: *mut u32,
    pub n_svc: u16,
    pub n_be: u16,
}

impl SvcCopy {
    pub(crate) const EMPTY: SvcCopy = SvcCopy {
        svcs: core::ptr::null_mut(),
        backends: core::ptr::null_mut(),
        index: core::ptr::null_mut(),
        n_svc: 0,
        n_be: 0,
    };
}

/// Size both copies from the tables this instance holds.
pub(crate) unsafe fn size(s: &mut IpState) -> bool {
    let bytes = s.pol_n as usize * s.policy_bytes as usize;
    if bytes == 0 {
        return true;
    }
    let svc_cap = (bytes / (2 + np::rule::DNAT_HEAD)).min(u16::MAX as usize - 1);
    let be_cap = (bytes / np::rule::DNAT_BACKEND).min(u16::MAX as usize - 1);
    let mut idx = 1usize;
    while idx < svc_cap * 2 {
        idx <<= 1;
    }
    s.svc_cap = svc_cap as u16;
    s.svc_be_cap = be_cap as u16;
    s.svc_index_len = idx as u32;
    let mut c = 0;
    while c < 2 {
        let copy = SvcCopy {
            svcs: heap_table(s, svc_cap, Svc::EMPTY),
            backends: heap_table(s, be_cap, Backend::EMPTY),
            index: heap_table(s, idx, index::EMPTY),
            n_svc: 0,
            n_be: 0,
        };
        if copy.svcs.is_null() || copy.backends.is_null() || copy.index.is_null() {
            refuse_capacity(s, b"the service index (policy_tables, policy_bytes)");
            return false;
        }
        s.svc[c] = copy;
        c += 1;
    }
    true
}

#[inline(always)]
fn key_hash(seed: u32, proto: u8, vip: u32, vport: u16) -> u32 {
    index::mix32(vip ^ seed ^ index::mix32(u32::from(vport) | (u32::from(proto) << 16)))
}

#[inline(always)]
unsafe fn index_of<'a>(s: &IpState, c: usize) -> &'a mut [u32] {
    let copy = &s.svc[c & 1];
    if copy.index.is_null() {
        return &mut [];
    }
    core::slice::from_raw_parts_mut(copy.index, s.svc_index_len as usize)
}

#[inline(always)]
unsafe fn svc_at<'a>(s: &IpState, c: usize, i: usize) -> &'a mut Svc {
    &mut *s.svc[c & 1].svcs.add(i)
}

#[inline(always)]
unsafe fn be_at<'a>(s: &IpState, c: usize, i: usize) -> &'a mut Backend {
    &mut *s.svc[c & 1].backends.add(i)
}

/// Begin rebuilding the spare copy from the tables as they are now.
pub(crate) unsafe fn rebuild(s: &mut IpState) {
    if s.svc_cap == 0 {
        return;
    }
    s.svc_build = 1;
    s.svc_build_t = 0;
    s.svc_build_at = 0;
    let spare = (s.svc_live ^ 1) as usize;
    s.svc[spare].n_svc = 0;
    s.svc[spare].n_be = 0;
}

/// One slice of the rebuild in flight.
pub(crate) unsafe fn step(s: &mut IpState) {
    if s.svc_build == 0 {
        return;
    }
    let spare = (s.svc_live ^ 1) as usize;
    if s.svc_build == 1 {
        // Phase 1: clear the spare index, a slice at a time.
        let idx = index_of(s, spare);
        let mut k = 0;
        while k < CLEAR_SLICE && (s.svc_build_at as usize) < idx.len() {
            if let Some(e) = idx.get_mut(s.svc_build_at as usize) {
                *e = index::EMPTY;
            }
            s.svc_build_at += 1;
            k += 1;
        }
        if (s.svc_build_at as usize) >= idx.len() {
            s.svc_build = 2;
            s.svc_build_at = 0;
        }
        return;
    }
    // Phase 2: the tables' DNAT records, a slice at a time.
    let mut k = 0;
    while k < SLICE {
        if s.svc_build_t as usize >= s.pol_n as usize {
            // Done: swap the copy in whole.
            s.svc_live ^= 1;
            s.svc_gen = s.svc_gen.wrapping_add(1).max(1);
            s.svc_build = 0;
            return;
        }
        let rules = super::policy::table_rules(s, s.svc_build_t as usize);
        match np::next_rule(rules, s.svc_build_at as usize) {
            Some((kind, body, next)) => {
                s.svc_build_at = next as u32;
                if kind == np::rule::DNAT {
                    if let Some(d) = np::dnat(body) {
                        if d.local() {
                            add(s, spare, &d, body);
                        }
                    }
                }
            }
            None => {
                s.svc_build_t += 1;
                s.svc_build_at = 0;
            }
        }
        k += 1;
    }
}

/// The service `(proto, vip, vport)` of copy `c`, if indexed.
unsafe fn find_in(s: &IpState, c: usize, proto: u8, vip: u32, vport: u16) -> Option<usize> {
    let n = s.svc[c & 1].n_svc as usize;
    index::lookup(
        index_of(s, c),
        key_hash(s.index_seed, proto, vip, vport),
        |i| {
            i < n && {
                let v = svc_at(s, c, i);
                v.proto == proto && v.vip == vip && v.vport == vport
            }
        },
    )
}

/// Merge one DNAT record into copy `c`.
unsafe fn add(s: &mut IpState, c: usize, d: &np::Dnat, body: &[u8]) {
    let i = match find_in(s, c, d.proto, d.vip, d.vport) {
        Some(i) => i,
        None => {
            let n = s.svc[c].n_svc as usize;
            if n >= s.svc_cap as usize {
                s.svc_overflow = s.svc_overflow.wrapping_add(1);
                return;
            }
            *svc_at(s, c, n) = Svc {
                proto: d.proto,
                flags: d.flags,
                vport: d.vport,
                vip: d.vip,
                ..Svc::EMPTY
            };
            let seed = s.index_seed;
            let _ = index::insert(index_of(s, c), key_hash(seed, d.proto, d.vip, d.vport), n);
            s.svc[c].n_svc += 1;
            n
        }
    };
    let mut b = 0;
    while b < d.backends as usize {
        let Some((addr, port)) = np::dnat_backend(body, b) else {
            break;
        };
        let nb = s.svc[c].n_be as usize;
        if nb >= s.svc_be_cap as usize {
            s.svc_overflow = s.svc_overflow.wrapping_add(1);
            return;
        }
        *be_at(s, c, nb) = Backend {
            addr,
            port,
            next: NONE,
        };
        s.svc[c].n_be += 1;
        let v = svc_at(s, c, i);
        if v.tail == NONE {
            v.head = nb as u16;
        } else {
            be_at(s, c, v.tail as usize).next = nb as u16;
        }
        v.tail = nb as u16;
        v.n += 1;
        b += 1;
    }
}

/// The service a packet to `(vip, vport)` over `proto` is for, in the copy
/// in use: an exact record first, then one for any protocol.
pub(crate) unsafe fn lookup(s: &IpState, proto: u8, vip: u32, vport: u16) -> Option<usize> {
    if s.svc_cap == 0 || s.svc_gen == 0 {
        return None;
    }
    let c = s.svc_live as usize;
    find_in(s, c, proto, vip, vport).or_else(|| find_in(s, c, np::rule::PROTO_ANY, vip, vport))
}

/// Backend `k` (mod the set) of service `i`: `None` for a service with no
/// backends.
pub(crate) unsafe fn pick(s: &IpState, i: usize, salt: u32) -> Option<(u32, u16)> {
    let c = s.svc_live as usize;
    let v = *svc_at(s, c, i);
    if v.n == 0 {
        return None;
    }
    let mut k = (salt as usize).checked_rem(v.n as usize).unwrap_or(0);
    let mut at = v.head;
    while k > 0 && at != NONE {
        at = be_at(s, c, at as usize).next;
        k -= 1;
    }
    if at == NONE {
        return None;
    }
    let b = *be_at(s, c, at as usize);
    Some((b.addr, if b.port == 0 { v.vport } else { b.port }))
}

/// Whether service `i` still has backend `(addr, port)`.
pub(crate) unsafe fn has(s: &IpState, i: usize, addr: u32, port: u16) -> bool {
    let c = s.svc_live as usize;
    let v = *svc_at(s, c, i);
    let mut at = v.head;
    let mut walked = 0;
    while at != NONE && walked <= v.n {
        let b = *be_at(s, c, at as usize);
        let bp = if b.port == 0 { v.vport } else { b.port };
        if b.addr == addr && bp == port {
            return true;
        }
        at = b.next;
        walked += 1;
    }
    false
}

/// A spread for a backend choice: the CSPRNG when it answers.
pub(crate) unsafe fn salt(s: &IpState) -> u32 {
    let mut r = [0u8; 4];
    if dev_csprng_fill(&*s.syscalls, r.as_mut_ptr(), 4) < 0 {
        return s.step_count;
    }
    u32::from_le_bytes(r)
}

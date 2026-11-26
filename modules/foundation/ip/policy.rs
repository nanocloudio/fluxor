//! Packet policy, enforced in `ip`: the bare-metal store and enforcer of
//! the `net.policy` tables.
//!
//! **Store.** This module is the node's `net.policy` provider on bare metal:
//! a controller's REPLACE / CLEAR / READ, and an in-graph enforcer's ATTACH
//! (`pkt_filter`), reach it through `provider.rs`, which keeps the tables
//! here with the shared core (`fluxor_sdk::cores::net_tables`):
//! `policy_store` tables of `policy_bytes` rule bytes each.
//!
//! **Tables.** The graph names the tables this instance applies itself
//! (`policy_tables`, comma-separated). A change lands between steps; the
//! next step sees the store's generation moved, takes each named table as
//! stored, and marks it applied, so its READ state says ENFORCED. A named
//! table the store does not hold judges nothing.
//!
//! **Evaluation** is the shared one (`net::policy::evaluate`), the same
//! rules as the Linux rendering, so a policy means the same on every node.
//!
//! **Where it judges** — the traffic Linux's forward hook sees, and nothing
//! the node itself originates (its lanes are exempt):
//! - a stream from a workload at its connect, and a stream to a workload
//!   address at its inbound SYN and again when a SYN cookie installs it;
//!   established segments never reach the evaluator;
//! - a workload's datagram when its flow begins (the verdict lasts the
//!   flow's lifetime, as connection tracking keeps it), and a datagram from
//!   another node to a workload endpoint with no flow of its own, per
//!   packet;
//! - an ICMP echo to a workload address.
//!
//! **IPv6.** The tables name IPv4 addresses only; an IPv6 flow they would
//! judge (one to or from a workload's IPv6 address, seen here under its
//! `v6t.rs` stand-ins) is dropped while any table judges packets, and
//! passes as an IPv4 one does when none does.

use super::*;
use abi::contracts::net::policy as np;
use fluxor_sdk::cores::net_tables::{PolicyBinding, PolicyStore, PolicyTable};

/// Rule bytes per table when the graph declares none (`policy_bytes`).
#[cfg(target_arch = "aarch64")]
pub(crate) const BYTES_DEFAULT: u16 = 8192;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const BYTES_DEFAULT: u16 = 1024;

/// Tables the store holds when the graph declares none (`policy_store`):
/// one per controller on a node that hosts workloads; none on an MCU-class
/// target, which enforces only the tables it names.
#[cfg(target_arch = "aarch64")]
pub(crate) const STORE_DEFAULT: u8 = 8;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const STORE_DEFAULT: u8 = 0;

/// One table this instance applies.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PolTable {
    pub name: [u8; np::MAX_TABLE_NAME],
    pub name_len: u8,
    /// It holds filter records (judges packets at all).
    pub filters: bool,
    /// The store slot holding it, while it is stored.
    pub slot: u8,
    pub stored: bool,
    /// Bytes of rules held.
    pub len: u32,
    /// The table generation applied (0: none).
    pub gen: u64,
}

impl PolTable {
    const EMPTY: PolTable = PolTable {
        name: [0; np::MAX_TABLE_NAME],
        name_len: 0,
        filters: false,
        slot: 0,
        stored: false,
        len: 0,
        gen: 0,
    };
}

/// Size the store, and split the `policy_tables` param into the tables
/// this instance applies.
pub(crate) unsafe fn size(s: &mut IpState) -> bool {
    s.pol_meta = fluxor_sdk::cores::net_tables::PolicyMeta::default();
    let n_store = s.pol_store_n as usize;
    if n_store > 0 {
        s.pol_tables = heap_table(s, n_store, PolicyTable::EMPTY);
        s.pol_bindings = heap_table(s, n_store, PolicyBinding::EMPTY);
        s.pol_rules = heap_table(s, n_store * s.policy_bytes as usize, 0u8);
        if s.pol_tables.is_null() || s.pol_bindings.is_null() || s.pol_rules.is_null() {
            refuse_capacity(s, b"the policy store (policy_store, policy_bytes)");
            return false;
        }
    }
    // Count the names first.
    let raw = s.pol_names;
    let raw = raw.get(..s.pol_names_len as usize).unwrap_or(&[]);
    let at = |i: usize| match raw.get(i) {
        Some(c) => *c,
        None => b',',
    };
    let mut n = 0usize;
    let mut i = 0;
    let mut in_name = false;
    while i < raw.len() {
        let c = at(i);
        if c == b',' || c == b' ' {
            in_name = false;
        } else if !in_name {
            in_name = true;
            n += 1;
        }
        i += 1;
    }
    if n == 0 {
        return true;
    }
    s.pol = heap_table(s, n, PolTable::EMPTY);
    if s.pol.is_null() {
        refuse_capacity(s, b"the policy tables (policy_tables)");
        return false;
    }
    let mut t = 0usize;
    let mut i = 0;
    while i < raw.len() && t < n {
        while i < raw.len() && (at(i) == b',' || at(i) == b' ') {
            i += 1;
        }
        let e = &mut *s.pol.add(t);
        let mut k = 0usize;
        while i < raw.len() && at(i) != b',' && at(i) != b' ' {
            if let Some(d) = e.name.get_mut(k) {
                *d = at(i);
                k += 1;
            }
            i += 1;
        }
        e.name_len = k as u8;
        t += 1;
    }
    s.pol_n = n as u8;
    true
}

/// The store over this instance's tables.
pub(crate) unsafe fn store<'a>(s: &'a mut IpState) -> PolicyStore<'a> {
    let n = s.pol_store_n as usize;
    let (tables, bindings, rules): (&mut [PolicyTable], &mut [PolicyBinding], &mut [u8]) =
        if n == 0 || s.pol_tables.is_null() || s.pol_bindings.is_null() || s.pol_rules.is_null() {
            (&mut [], &mut [], &mut [])
        } else {
            (
                core::slice::from_raw_parts_mut(s.pol_tables, n),
                core::slice::from_raw_parts_mut(s.pol_bindings, n),
                core::slice::from_raw_parts_mut(s.pol_rules, n * s.policy_bytes as usize),
            )
        };
    PolicyStore {
        meta: &mut s.pol_meta,
        tables,
        bindings,
        rules,
    }
}

#[inline(always)]
unsafe fn table<'a>(s: &IpState, t: usize) -> &'a mut PolTable {
    &mut *s.pol.add(t)
}

/// Table `t`'s rule bytes as applied: the store's own copy.
#[inline(always)]
unsafe fn rules<'a>(s: &IpState, t: usize) -> &'a [u8] {
    let e = table(s, t);
    if !e.stored || s.pol_rules.is_null() {
        return &[];
    }
    let b = s.policy_bytes as usize;
    core::slice::from_raw_parts(
        s.pol_rules.add(e.slot as usize * b),
        (e.len as usize).min(b),
    )
}

/// Apply the store when it moved since the last step: take each named
/// table as stored and mark it applied.
pub(crate) unsafe fn step(s: &mut IpState) {
    if s.pol_n == 0 {
        return;
    }
    let g = s.pol_meta.next_generation;
    if g == s.pol_store_gen {
        return;
    }
    s.pol_store_gen = g;
    let mut filter_moved = false;
    let mut t = 0;
    while t < s.pol_n as usize {
        let e = *table(s, t);
        let name = e.name;
        let name = name.get(..e.name_len as usize).unwrap_or(&[]);
        let found = {
            let st = store(s);
            st.tables
                .iter()
                .position(|x| x.live && x.name() == name)
                .and_then(|i| st.tables.get(i).map(|x| (i, x.len, x.generation)))
        };
        let entry = table(s, t);
        match found {
            Some((slot, len, gen)) => {
                let had = entry.filters;
                entry.stored = true;
                entry.slot = slot as u8;
                entry.len = len;
                entry.gen = gen;
                let f = np::filters(rules(s, t));
                let entry = table(s, t);
                entry.filters = f;
                filter_moved |= had || f;
                store(s).mark_applied(name, gen);
            }
            None => {
                if entry.stored || entry.filters {
                    filter_moved = true;
                }
                *entry = PolTable {
                    name: e.name,
                    name_len: e.name_len,
                    ..PolTable::EMPTY
                };
            }
        }
        t += 1;
    }
    if filter_moved {
        s.filter_epoch = s.filter_epoch.wrapping_add(1).max(1);
    }
    super::service::rebuild(s);
}

/// Whether every table passes `p`.
pub(crate) unsafe fn allows(s: &mut IpState, p: &np::Packet) -> bool {
    // The tables name IPv4 addresses. An IPv6 flow reaches here under its
    // stand-ins (`v6t.rs`), which no rule names: judging those would pass
    // what an ISOLATE or DROP meant to stop, so while any table judges
    // packets such a flow is dropped instead.
    if (v6t::is_reserved(p.src) || v6t::is_reserved(p.dst)) && active(s) {
        s.drops.policy_denied = s.drops.policy_denied.wrapping_add(1);
        return false;
    }
    let mut t = 0;
    while t < s.pol_n as usize {
        let e = table(s, t);
        if e.filters && np::evaluate(rules(s, t), p) != np::Verdict::Accept {
            s.drops.policy_denied = s.drops.policy_denied.wrapping_add(1);
            return false;
        }
        t += 1;
    }
    true
}

/// Whether any table judges packets at all.
#[inline(always)]
pub(crate) unsafe fn active(s: &IpState) -> bool {
    let mut t = 0;
    while t < s.pol_n as usize {
        if table(s, t).filters {
            return true;
        }
        t += 1;
    }
    false
}

/// The rules of every table this instance holds, for the service index.
pub(crate) unsafe fn table_rules<'a>(s: &IpState, t: usize) -> &'a [u8] {
    if t >= s.pol_n as usize {
        return &[];
    }
    rules(s, t)
}

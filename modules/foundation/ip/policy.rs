//! Packet policy, enforced in `ip`: the bare-metal enforcer of the
//! `net.policy` tables.
//!
//! **Tables.** The graph names the tables this instance applies
//! (`policy_tables`, comma-separated). Every [`POLL_MS`] the store-wide
//! generation is polled (a zero-length `READ`; a `CLEAR` consumes one too,
//! so a deleted policy is noticed like a changed one) and only when it moved
//! is each table read again, whole, into this module's heap (`policy_bytes`
//! per table). `ATTACH` binds this module as each table's one enforcer,
//! declares `policy_bytes` as the most of it this module holds (so the store
//! refuses a larger REPLACE, `E2BIG`), and reports the generation it applied
//! in full: a table it could not hold, a read the store kept moving under (a
//! stale copy), or a table that is gone reports 0 — so the table's
//! `ENFORCED` is clear whenever what is in force here is not what the store
//! holds, and a faulted module's binding ends with its slot.
//!
//! **Fail closed.** A table this module cannot hold (one stored before it
//! bound, larger than `policy_bytes`) is not enforced by its previous copy:
//! it is enforced closed — every packet it judges is dropped, and its
//! services are withdrawn — until a read of it fits.
//!
//! **Evaluation** is the shared one (`net::policy::evaluate`), the same
//! rules as the Linux rendering, so a policy means the same on every node.
//!
//! **Where it judges** — the traffic Linux's forward hook sees, and nothing
//! the node itself originates (lane 0 is exempt):
//! - a stream from a workload at its connect, and a stream to a workload
//!   address at its inbound SYN and again when a SYN cookie installs it;
//!   established segments never reach the evaluator;
//! - a workload's datagram when its flow begins (the verdict lasts the
//!   flow's lifetime, as connection tracking keeps it), and a datagram from
//!   another node to a workload endpoint with no flow of its own, per
//!   packet;
//! - an ICMP echo to a workload address.

use super::*;
use abi::contracts::net::policy as np;

/// How often the store-wide generation is polled.
pub(crate) const POLL_MS: u32 = 100;
/// Bytes held per table when the graph declares none (`policy_bytes`).
#[cfg(target_arch = "aarch64")]
pub(crate) const BYTES_DEFAULT: u16 = 8192;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const BYTES_DEFAULT: u16 = 1024;

const ENOENT: i32 = -2;
const ENOSYS: i32 = -38;
const ERANGE: i32 = -34;

/// One table this instance applies.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PolTable {
    pub name: [u8; np::MAX_TABLE_NAME],
    pub name_len: u8,
    /// It holds filter records (judges packets at all).
    pub filters: bool,
    /// Which half of the table's double buffer is in force: a read lands in
    /// the other and is swapped in only whole, so a read the store moved
    /// under never tears what is in force.
    pub live: u8,
    /// The store holds more of it than this module can: enforced closed.
    pub closed: bool,
    /// Bytes of rules held, in this table's part of the heap buffer.
    pub len: u32,
    /// The table generation held, and the one reported applied (0: none).
    pub gen: u64,
    pub applied: u64,
}

impl PolTable {
    const EMPTY: PolTable = PolTable {
        name: [0; np::MAX_TABLE_NAME],
        name_len: 0,
        filters: false,
        live: 0,
        closed: false,
        len: 0,
        gen: 0,
        applied: 0,
    };
}

/// Split the `policy_tables` param into tables and size them into the heap.
pub(crate) unsafe fn size(s: &mut IpState) -> bool {
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
    s.pol_buf = heap_table(s, n * 2 * s.policy_bytes as usize, 0u8);
    if s.pol.is_null() || s.pol_buf.is_null() {
        refuse_capacity(s, b"the policy tables (policy_tables, policy_bytes)");
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

#[inline(always)]
unsafe fn table<'a>(s: &IpState, t: usize) -> &'a mut PolTable {
    &mut *s.pol.add(t)
}

/// Where half `half` of table `t`'s double buffer starts.
#[inline(always)]
unsafe fn half_ptr(s: &IpState, t: usize, half: u8) -> *mut u8 {
    s.pol_buf
        .add((t * 2 + (half & 1) as usize) * s.policy_bytes as usize)
}

/// Table `t`'s rule bytes as in force.
#[inline(always)]
unsafe fn rules<'a>(s: &IpState, t: usize) -> &'a [u8] {
    let e = table(s, t);
    core::slice::from_raw_parts(
        half_ptr(s, t, e.live),
        (e.len as usize).min(s.policy_bytes as usize),
    )
}

/// READ table `name` (empty: the store) into `out`; the state lands in
/// `state`.
unsafe fn read(
    s: &IpState,
    name: &[u8],
    out: *mut u8,
    cap: usize,
    state: &mut [u8; np::state::BYTES],
) -> i32 {
    let mut arg = [0u8; 1 + np::MAX_TABLE_NAME + 8 + 4 + 8];
    let nl = name.len().min(np::MAX_TABLE_NAME);
    arg[0] = nl as u8;
    let mut i = 0;
    while i < nl {
        if let Some(d) = arg.get_mut(1 + i) {
            *d = match name.get(i) {
                Some(b) => *b,
                None => 0,
            };
        }
        i += 1;
    }
    let p = 1 + nl;
    let w = |arg: &mut [u8], at: usize, v: u64, n: usize| {
        let b = v.to_le_bytes();
        let mut k = 0;
        while k < n && k < 8 {
            if let Some(d) = arg.get_mut(at + k) {
                *d = b[k];
            }
            k += 1;
        }
    };
    w(&mut arg, p, out as u64, 8);
    w(&mut arg, p + 8, cap as u64, 4);
    w(&mut arg, p + 12, state.as_mut_ptr() as u64, 8);
    ((*s.syscalls).provider_call)(-1, np::READ, arg.as_mut_ptr(), p + 20)
}

#[inline(always)]
fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        v[i] = match b.get(at + i) {
            Some(x) => *x,
            None => 0,
        };
        i += 1;
    }
    u64::from_le_bytes(v)
}

/// Poll the store; re-read and re-report when it moved.
pub(crate) unsafe fn step(s: &mut IpState) {
    if s.pol_n == 0 || s.pol_absent {
        return;
    }
    let now = dev_millis(&*s.syscalls) as u32;
    if s.pol_polled_ms != 0 && now.wrapping_sub(s.pol_polled_ms) < POLL_MS {
        return;
    }
    s.pol_polled_ms = if now == 0 { 1 } else { now };
    let mut state = [0u8; np::state::BYTES];
    let rc = read(s, &[], core::ptr::null_mut(), 0, &mut state);
    if rc == ENOSYS {
        s.pol_absent = true;
        return;
    }
    if rc == 0 {
        let g = u64_at(&state, np::state::GENERATION);
        if g == s.pol_store_gen && s.pol_attached {
            return;
        }
        s.pol_store_gen = g;
    }
    refresh(s);
}

/// Re-read every table and report what is applied.
unsafe fn refresh(s: &mut IpState) {
    let mut filter_moved = false;
    let mut retry = false;
    let mut t = 0;
    while t < s.pol_n as usize {
        let e = *table(s, t);
        let name = e.name;
        let name = name.get(..e.name_len as usize).unwrap_or(&[]);
        let mut state = [0u8; np::state::BYTES];
        let spare = table(s, t).live ^ 1;
        let rc = read(
            s,
            name,
            half_ptr(s, t, spare),
            s.policy_bytes as usize,
            &mut state,
        );
        let gen = u64_at(&state, np::state::GENERATION);
        let entry = table(s, t);
        if rc >= 0 {
            if gen != entry.gen || entry.applied != gen || entry.closed {
                // The whole table landed in the spare half: swap it in.
                let was_closed = entry.closed;
                entry.live = spare;
                entry.len = rc as u32;
                entry.gen = gen;
                entry.applied = gen;
                entry.closed = false;
                let had = entry.filters;
                entry.filters = np::filters(rules(s, t));
                filter_moved |= had || was_closed || table(s, t).filters;
            }
        } else if rc == ENOENT {
            // The table is gone: nothing of it is in force any more.
            if entry.len != 0 || entry.filters || entry.closed {
                filter_moved = true;
            }
            entry.len = 0;
            entry.filters = false;
            entry.closed = false;
            entry.gen = 0;
            entry.applied = 0;
        } else if rc == ERANGE {
            // Too big to hold: enforced closed, not by the copy held before
            // — that copy is a policy the store no longer has, and keeping it
            // in force would pass what the stored table may drop. Every
            // packet it judges is dropped and its services withdrawn until a
            // read fits; nothing is reported applied, so ENFORCED is clear.
            s.pol_oversized = s.pol_oversized.wrapping_add(1);
            if !entry.closed || entry.len != 0 {
                filter_moved = true;
            }
            entry.closed = true;
            entry.len = 0;
            entry.filters = false;
            entry.gen = gen;
            entry.applied = 0;
        } else {
            // The store kept moving (EAGAIN): the previous copy stays in
            // force — the read went to the spare half — and is not this
            // generation, so it is not reported applied: it keeps reporting
            // the generation it does hold, which the store no longer has,
            // and ENFORCED is clear. Read again at the next poll, whatever
            // the store says.
            retry = true;
        }
        t += 1;
    }
    if retry {
        s.pol_store_gen = 0;
    }
    if filter_moved {
        s.filter_epoch = s.filter_epoch.wrapping_add(1).max(1);
    }
    super::service::rebuild(s);
    attach(s);
}

/// ATTACH naming every table, with the generation applied and the most of
/// it this module holds (`policy_bytes`).
unsafe fn attach(s: &mut IpState) {
    let mut arg = [0u8; 1 + np::MAX_TABLE_NAME + np::ATTACH_TAIL + np::ATTACH_CAPACITY_TAIL];
    // One table per call: each binding stands or falls on its own (another
    // enforcer holding one table leaves this one bound for the rest).
    let mut all = true;
    let mut t = 0;
    while t < s.pol_n as usize {
        let e = *table(s, t);
        let nl = (e.name_len as usize).min(np::MAX_TABLE_NAME);
        arg[0] = nl as u8 | np::ATTACH_CAPACITY;
        let mut i = 0;
        while i < nl {
            if let (Some(d), Some(c)) = (arg.get_mut(1 + i), e.name.get(i)) {
                *d = *c;
            }
            i += 1;
        }
        let g = e.applied.to_le_bytes();
        let mut k = 0;
        while k < 8 {
            if let Some(d) = arg.get_mut(1 + nl + k) {
                *d = g[k];
            }
            k += 1;
        }
        let cap = u32::from(s.policy_bytes).to_le_bytes();
        let mut k = 0;
        while k < np::ATTACH_CAPACITY_TAIL {
            if let (Some(d), Some(c)) = (arg.get_mut(1 + nl + 8 + k), cap.get(k)) {
                *d = *c;
            }
            k += 1;
        }
        let len = 1 + nl + np::ATTACH_TAIL + np::ATTACH_CAPACITY_TAIL;
        let rc = ((*s.syscalls).provider_call)(-1, np::ATTACH, arg.as_mut_ptr(), len);
        if rc != 0 {
            all = false;
        }
        t += 1;
    }
    s.pol_attached = all;
}

/// Whether every table passes `p`: a table enforced closed passes nothing.
pub(crate) unsafe fn allows(s: &mut IpState, p: &np::Packet) -> bool {
    let mut t = 0;
    while t < s.pol_n as usize {
        let e = table(s, t);
        if e.closed || (e.filters && np::evaluate(rules(s, t), p) != np::Verdict::Accept) {
            s.drops.policy_denied = s.drops.policy_denied.wrapping_add(1);
            return false;
        }
        t += 1;
    }
    true
}

/// Whether any table judges packets at all (one enforced closed does).
#[inline(always)]
pub(crate) unsafe fn active(s: &IpState) -> bool {
    let mut t = 0;
    while t < s.pol_n as usize {
        if table(s, t).filters || table(s, t).closed {
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

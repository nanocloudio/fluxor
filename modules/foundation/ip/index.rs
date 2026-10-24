//! Bounded lookup structures over the connection and address tables.
//!
//! The tables themselves are flat arrays sized per profile
//! (`abi::config::ip`). At the host ceilings — 65,536 connections, 4,096
//! addresses — a per-packet scan is a per-packet cost the size of the
//! table, so every hot-path lookup goes through one of these instead:
//!
//! - an open-addressed hash index from a connection's 4-tuple (plus the
//!   local-address slot) to its slot;
//! - the same shape from a local IPv4 address to its address slot;
//! - a short list of listening slots, since a SYN is matched against
//!   listeners rather than connections;
//! - a per-port reference count, so "is this port bound?" is a load;
//! - a small per-source table of half-open counts, so the SYN-flood
//!   gauges need no sweep.
//!
//! Each is explicit about what it holds and is maintained at the exact
//! points a connection is keyed or released (`conn_index_insert` /
//! `conn_reset` in `mod.rs`), so nothing here is ever rebuilt on the hot
//! path. Entries are `slot + 1` and 0 is empty — there is no third state.
//! A removal pulls the rest of its chain back over the hole rather than
//! marking it, so every entry is either live or free and a lookup always
//! meets an empty entry at the end of its cluster. Marking instead would
//! be cheaper per removal and unsound over time: a mark is only skipped,
//! never reclaimed, so under sustained churn the empties disappear and
//! every MISS walks the whole table — the one case an index exists to make
//! cheap, turned into the most expensive thing the module does.
//!
//! The index is twice the table, so clusters stay short, and the hash is
//! seeded per module instance so the tuples that land in one cluster
//! cannot be chosen from outside.

include!("../../sdk/runtime/hash_index.rs");

/// A keyed connection: what distinguishes one from another at the
/// transport, including which local address it is reached at.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConnKey {
    pub remote_ip: u32,
    pub remote_port: u16,
    pub local_port: u16,
    pub local_slot: u16,
}

impl ConnKey {
    #[inline]
    /// The bucket this key is at home in, under `seed`.
    ///
    /// `seed` is the module instance's, drawn once and never changed. The
    /// tuple is otherwise the caller's to choose — a remote picks its own
    /// address and port — so without it an attacker computes offline which
    /// tuples share a cluster and sends exactly those, turning the index
    /// back into a list.
    #[must_use]
    pub fn hash(&self, seed: u32) -> u32 {
        let a = mix32(self.remote_ip ^ seed);
        let b = mix32(u32::from(self.remote_port) | (u32::from(self.local_port) << 16));
        mix32(a ^ b.rotate_left(13) ^ u32::from(self.local_slot).wrapping_mul(0x9e37_79b9))
    }
}

/// One entry of the per-source half-open table.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SourceCount {
    pub ip: u32,
    pub count: u32,
}

impl SourceCount {
    pub const fn empty() -> Self {
        Self { ip: 0, count: 0 }
    }
}

/// Add one half-open connection from `ip`. Returns the source's count
/// after the add, or `None` when the table is full and the source is
/// untracked — the caller counts those so the gauge's blind spot is
/// visible.
///
/// # Safety
/// `table` must be a power-of-two length.
#[inline]
pub unsafe fn source_enter(table: &mut [SourceCount], ip: u32) -> Option<u32> {
    let mask = table.len() - 1;
    let mut i = mix32(ip) as usize & mask;
    let mut probes = 0;
    while probes < table.len() {
        let e = &mut *table.as_mut_ptr().add(i);
        if e.count == 0 {
            e.ip = ip;
            e.count = 1;
            return Some(1);
        }
        if e.ip == ip {
            e.count = e.count.saturating_add(1);
            return Some(e.count);
        }
        i = (i + 1) & mask;
        probes += 1;
    }
    None
}

/// Remove one half-open connection from `ip`, if it is tracked. A source
/// whose count reaches zero frees its entry by backward-shift deletion:
/// later entries on the same probe chain are pulled back over the hole, so
/// the chain never holds a gap a lookup would stop at. No tombstones, so
/// the table never fills with them under churn.
///
/// # Safety
/// `table` must be a power-of-two length.
#[inline]
pub unsafe fn source_leave(table: &mut [SourceCount], ip: u32) {
    let mask = table.len() - 1;
    let mut i = mix32(ip) as usize & mask;
    let mut probes = 0;
    while probes < table.len() {
        let e = &mut *table.as_mut_ptr().add(i);
        if e.count == 0 {
            return;
        }
        if e.ip == ip {
            e.count -= 1;
            if e.count == 0 {
                // Keep later entries on this chain reachable: pull the
                // chain back over the hole (backward-shift deletion).
                let mut j = (i + 1) & mask;
                let mut shifted = 0;
                while shifted < table.len() {
                    shifted += 1;
                    let f = *table.as_ptr().add(j);
                    if f.count == 0 {
                        break;
                    }
                    let home = mix32(f.ip) as usize & mask;
                    // `f` may move into `i` only if `i` lies between its
                    // home and `j` on the cyclic probe path.
                    let between = if i <= j {
                        home <= i || home > j
                    } else {
                        home <= i && home > j
                    };
                    if between {
                        *table.as_mut_ptr().add(i) = f;
                        *table.as_mut_ptr().add(j) = SourceCount::empty();
                        i = j;
                    }
                    j = (j + 1) & mask;
                }
            }
            return;
        }
        i = (i + 1) & mask;
        probes += 1;
    }
}

/// As [`lookup`], also reporting how many entries were probed — so a
/// harness can hold the cost of a lookup against the table's size rather
/// than take it on trust.
///
/// # Safety
/// `index` must be a power-of-two length.
pub unsafe fn lookup_counted<F: FnMut(usize) -> bool>(
    index: &[u32],
    hash: u32,
    mut matches: F,
) -> (Option<usize>, usize) {
    let mask = index.len() - 1;
    let mut i = hash as usize & mask;
    let mut probes = 0;
    while probes < index.len() {
        probes += 1;
        let e = *index.as_ptr().add(i);
        if e == EMPTY {
            return (None, probes);
        }
        let slot = (e - 1) as usize;
        if matches(slot) {
            return (Some(slot), probes);
        }
        i = (i + 1) & mask;
    }
    (None, probes)
}

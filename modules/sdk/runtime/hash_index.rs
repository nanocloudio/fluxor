// Open-addressed hash index over a caller's table: the bounded lookup
// structure every keyed table in a module goes through instead of a scan.
//
// Mounted with `include!` into the module that keys a table (`ip`'s
// connection and flow indices, `pkt_filter`'s flow table), so it is one
// implementation wherever a module hashes its records.
//
// Entries are `slot + 1` and 0 is empty — there is no third state. A
// removal pulls the rest of its chain back over the hole rather than
// marking it, so every entry is either live or free and a lookup always
// meets an empty entry at the end of its cluster. Marking instead would be
// cheaper per removal and unsound over time: a mark is only skipped, never
// reclaimed, so under sustained churn the empties disappear and every MISS
// walks the whole table — the one case an index exists to make cheap,
// turned into the most expensive thing the module does.
//
// The index is sized larger than its table (a power of two), so clusters
// stay short, and the caller's hash is seeded per module instance so the
// keys that land in one cluster cannot be chosen from outside.

/// Empty index entry.
pub const EMPTY: u32 = 0;

/// Avalanche mix of one word — the finaliser a hash needs so nearby keys
/// (consecutive ports, adjacent addresses) land far apart.
#[inline]
pub fn mix32(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    x
}

/// Insert `slot` under `hash`, at the first empty entry on its probe path.
/// `false` only when every entry is live, which cannot happen while the
/// index is larger than the table it indexes.
///
/// # Safety
/// `index` must be a power-of-two length.
#[inline]
pub unsafe fn insert(index: &mut [u32], hash: u32, slot: usize) -> bool {
    let mask = index.len() - 1;
    let mut i = hash as usize & mask;
    let mut probes = 0;
    while probes < index.len() {
        let e = *index.as_ptr().add(i);
        if e == EMPTY {
            *index.as_mut_ptr().add(i) = slot as u32 + 1;
            return true;
        }
        i = (i + 1) & mask;
        probes += 1;
    }
    false
}

/// Remove the entry for `slot` under `hash`, closing the hole behind it.
/// `false` when no such entry was on the probe path.
///
/// `home_of` gives the hash an occupied entry was inserted under, so the
/// chain can be pulled back over the hole. It is asked only about entries
/// this index holds, and it MUST answer what that slot was inserted with:
/// the caller's key fields are immutable for as long as the slot is
/// indexed, and a `home_of` that disagrees moves a live entry off its own
/// chain, where nothing will find it again.
///
/// # Safety
/// `index` must be a power-of-two length.
#[inline]
pub unsafe fn remove(
    index: &mut [u32],
    hash: u32,
    slot: usize,
    home_of: impl Fn(usize) -> u32,
) -> bool {
    let mask = index.len() - 1;
    let mut i = hash as usize & mask;
    let mut probes = 0;
    let want = slot as u32 + 1;
    while probes < index.len() {
        let e = *index.as_ptr().add(i);
        if e == EMPTY {
            return false;
        }
        if e == want {
            *index.as_mut_ptr().add(i) = EMPTY;
            // Pull the rest of the cluster back over the hole, so the
            // entries past it stay reachable from their own home
            // (backward-shift deletion). Bounded like every other walk
            // here: a degenerate cluster must cost a bounded step, not an
            // open-ended one.
            let mut j = (i + 1) & mask;
            let mut shifted = 0;
            while shifted < index.len() {
                let f = *index.as_ptr().add(j);
                if f == EMPTY {
                    break;
                }
                let home = home_of((f - 1) as usize) as usize & mask;
                // `f` may fill the hole only when the hole lies between
                // its home and where it currently sits, on the cyclic
                // probe path.
                let between = if i <= j {
                    home <= i || home > j
                } else {
                    home <= i && home > j
                };
                if between {
                    *index.as_mut_ptr().add(i) = f;
                    *index.as_mut_ptr().add(j) = EMPTY;
                    i = j;
                }
                j = (j + 1) & mask;
                shifted += 1;
            }
            return true;
        }
        i = (i + 1) & mask;
        probes += 1;
    }
    false
}

/// The first slot on `hash`'s probe path for which `matches` holds.
/// Entries are validated by the caller's predicate rather than trusted:
/// two keys may share a hash, and a slot may have been reused since it
/// was indexed under a key that has not yet been removed.
///
/// # Safety
/// `index` must be a power-of-two length.
#[inline]
pub unsafe fn lookup<F: FnMut(usize) -> bool>(
    index: &[u32],
    hash: u32,
    mut matches: F,
) -> Option<usize> {
    let mask = index.len() - 1;
    let mut i = hash as usize & mask;
    let mut probes = 0;
    while probes < index.len() {
        let e = *index.as_ptr().add(i);
        if e == EMPTY {
            return None;
        }
        let slot = (e - 1) as usize;
        if matches(slot) {
            return Some(slot);
        }
        i = (i + 1) & mask;
        probes += 1;
    }
    None
}

/// Forget everything.
#[inline]
pub fn clear(index: &mut [u32]) {
    let mut i = 0;
    while i < index.len() {
        index[i] = EMPTY;
        i += 1;
    }
}

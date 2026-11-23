//! Which core runs each execution domain.
//!
//! A target maps every domain index to a core (`[smp] domain_cores` in its
//! TOML). One domain loop runs per core that has a domain, passing over that
//! core's domains in index order. The rules a map obeys, and the questions
//! asked of one, are here as plain functions of the map: the kernel, its
//! build script and the graph builder share this one copy.

/// Domains a map covers: the scheduler's `MAX_DOMAINS`.
pub const DOMAINS: usize = 4;

/// Why a map is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The map does not name a core for exactly [`DOMAINS`] domains.
    Length,
    /// The target runs no core at all.
    NoCores,
    /// Domain 0 is not on core 0, the core that boots and owns the graph.
    PrimaryNotOnBootCore,
    /// `domain` names a core the target does not run.
    CoreOutOfRange { domain: usize },
    /// `core`, a core other than 0, is given more than one domain. A
    /// secondary core's loop runs in its one domain's execution mode.
    SecondaryShared { core: u8 },
}

/// Check `map` against a target that runs `cores` cores.
pub const fn validate(map: &[u8], cores: u8) -> Result<(), MapError> {
    if map.len() != DOMAINS {
        return Err(MapError::Length);
    }
    if cores == 0 {
        return Err(MapError::NoCores);
    }
    if map[0] != 0 {
        return Err(MapError::PrimaryNotOnBootCore);
    }
    let mut d = 0;
    while d < DOMAINS {
        if map[d] >= cores {
            return Err(MapError::CoreOutOfRange { domain: d });
        }
        if map[d] != 0 {
            let mut other = 0;
            while other < d {
                if map[other] == map[d] {
                    return Err(MapError::SecondaryShared { core: map[d] });
                }
                other += 1;
            }
        }
        d += 1;
    }
    Ok(())
}

/// The core `map` runs `domain` on; core 0 for a domain past the map.
pub const fn core_of(map: &[u8; DOMAINS], domain: usize) -> usize {
    if domain < DOMAINS {
        map[domain] as usize
    } else {
        0
    }
}

/// The domains `core`'s loop passes over, in index order, as a bit per
/// domain.
pub const fn domains_of(map: &[u8; DOMAINS], core: usize) -> u8 {
    let mut mask = 0u8;
    let mut d = 0;
    while d < DOMAINS {
        if map[d] as usize == core {
            mask |= 1 << d;
        }
        d += 1;
    }
    mask
}

/// The one domain a core other than 0 runs, if `map` gives it one.
pub const fn secondary_domain(map: &[u8; DOMAINS], core: usize) -> Option<usize> {
    if core == 0 {
        return None;
    }
    let mut d = 1;
    while d < DOMAINS {
        if map[d] as usize == core {
            return Some(d);
        }
        d += 1;
    }
    None
}

/// Whether `map` runs any domain off core 0.
pub const fn has_secondary(map: &[u8; DOMAINS]) -> bool {
    let mut d = 0;
    while d < DOMAINS {
        if map[d] != 0 {
            return true;
        }
        d += 1;
    }
    false
}

/// Whether an edge between `from` and `to` crosses cores under `map`: its
/// two ends are stepped by different loops, so it is bridged by a ring.
pub const fn crosses_cores(map: &[u8; DOMAINS], from: usize, to: usize) -> bool {
    core_of(map, from) != core_of(map, to)
}

/// What one edge between cores takes of an RP kernel's static pool, in
/// bytes: its bridge ring (two slots of one 8 KiB channel buffer each, with
/// the ring's indices) and its edge record. The pool is the one the state
/// arena is carved from, so the graph builder charges a graph this much of
/// that arena for each such edge; the RP kernel asserts the figure against
/// the types it describes.
pub const RP_CROSSING_BYTES: usize = 16_704 + 20;

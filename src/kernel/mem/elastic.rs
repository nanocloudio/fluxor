//! Tier B elastic region — kernel-owned chunk grants for runtime pool
//! growth ( `resource::ELASTIC_ALLOC`).
//!
//! Module state and heap arenas are committed whole at load, so a pool
//! that grows *while the node runs* (TLS sessions, conns) takes chunks
//! from this region instead. Design points, per the RFC:
//!
//! - **Chunk-granular free lists, no general allocator.** Grants are
//!   rounded up to `ELASTIC_QUANTUM`; a freed chunk is reused exact-fit
//!   or the bump mark advances. Fragmentation-proof by construction.
//! - **Monotonic-to-teardown.** No individual free; [`reclaim_module`]
//!   releases every chunk a module holds when its owner is torn down.
//! - **Deliberately oversubscribable.** Σ of pool maxima MAY exceed the
//!   region; contention is a counted `POOL_ELASTIC_REGION` denial.
//! - **MCU degeneration.** `ELASTIC_REGION_SIZE == 0` on embedded
//!   profiles: the static costs nothing and every request denies.
//!
//! Grants happen at module control-plane moments (a pool's grow step),
//! never on the packet path; a grant zeroes at most one chunk.

use crate::kernel::config::{ELASTIC_QUANTUM, ELASTIC_REGION_SIZE};
use crate::kernel::sys::guard::KernelGuard;

/// Chunk bookkeeping entries. Chunks are quantum-multiples, so a full
/// table implies ≥ 128 live grants — far beyond any real graph; a full
/// table is a counted denial, not a panic.
const MAX_CHUNKS: usize = 128;

#[derive(Clone, Copy)]
struct Chunk {
    offset: u32,
    len: u32,
    /// Owning module index; `u8::MAX` = free (reusable exact-fit).
    owner: u8,
}

const FREE: u8 = u8::MAX;

struct ElasticState {
    chunks: [Chunk; MAX_CHUNKS],
    count: usize,
    bump: usize,
}

#[repr(C, align(4096))]
struct AlignedRegion([u8; ELASTIC_REGION_SIZE]);

static mut REGION: AlignedRegion = AlignedRegion([0; ELASTIC_REGION_SIZE]);
static mut STATE: ElasticState = ElasticState {
    chunks: [Chunk {
        offset: 0,
        len: 0,
        owner: FREE,
    }; MAX_CHUNKS],
    count: 0,
    bump: 0,
};

/// Grant a chunk of at least `bytes` to `module_idx`. Returns the chunk
/// `(ptr, len)` — `len` is `bytes` rounded up to [`ELASTIC_QUANTUM`] —
/// or `None` (the caller counts the denial and returns `ENOSPC`).
pub fn alloc(module_idx: u8, bytes: usize) -> Option<(*mut u8, usize)> {
    if ELASTIC_REGION_SIZE == 0 || bytes == 0 || module_idx == FREE {
        return None;
    }
    let len = bytes.div_ceil(ELASTIC_QUANTUM) * ELASTIC_QUANTUM;
    let _g = KernelGuard::acquire();
    // SAFETY: STATE/REGION are guarded by the interrupt guard (single-core
    // control-plane callers; grants never happen on the packet path).
    unsafe {
        let st = &mut *core::ptr::addr_of_mut!(STATE);
        // Exact-fit reuse of a reclaimed chunk first.
        for c in st.chunks.iter_mut().take(st.count) {
            if c.owner == FREE && c.len as usize == len {
                c.owner = module_idx;
                let ptr = core::ptr::addr_of_mut!(REGION.0)
                    .cast::<u8>()
                    .add(c.offset as usize);
                core::ptr::write_bytes(ptr, 0, len);
                return Some((ptr, len));
            }
        }
        // Bump a fresh chunk.
        if st.count >= MAX_CHUNKS || st.bump + len > ELASTIC_REGION_SIZE {
            return None;
        }
        let offset = st.bump;
        st.chunks[st.count] = Chunk {
            offset: offset as u32,
            len: len as u32,
            owner: module_idx,
        };
        st.count += 1;
        st.bump = offset + len;
        let ptr = core::ptr::addr_of_mut!(REGION.0).cast::<u8>().add(offset);
        core::ptr::write_bytes(ptr, 0, len);
        Some((ptr, len))
    }
}

/// Release every chunk `module_idx` holds — the owner-teardown reclaim
/// (§3.6: teardown is the reclaim path; there is no individual free).
pub fn reclaim_module(module_idx: u8) {
    if ELASTIC_REGION_SIZE == 0 {
        return;
    }
    let _g = KernelGuard::acquire();
    // SAFETY: guarded as in `alloc`.
    unsafe {
        let st = &mut *core::ptr::addr_of_mut!(STATE);
        for c in st.chunks.iter_mut().take(st.count) {
            if c.owner == module_idx {
                c.owner = FREE;
            }
        }
    }
}

/// `(used_bytes, region_bytes)` — resource-ledger sample for
/// `POOL_ELASTIC_REGION`. Used = live (non-free) chunk bytes.
pub fn region_usage() -> (usize, usize) {
    if ELASTIC_REGION_SIZE == 0 {
        return (0, 0);
    }
    let _g = KernelGuard::acquire();
    // SAFETY: guarded as in `alloc`.
    unsafe {
        let st = &*core::ptr::addr_of!(STATE);
        let used: usize = st
            .chunks
            .iter()
            .take(st.count)
            .filter(|c| c.owner != FREE)
            .map(|c| c.len as usize)
            .sum();
        (used, ELASTIC_REGION_SIZE)
    }
}

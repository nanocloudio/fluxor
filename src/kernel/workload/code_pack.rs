//! Per-owner code: the module packs a workload brings with it.
//!
//! A workload CREATE'd from `SOURCE_FMOD_PACK` carries its own modules — a
//! module table (FXMT) of `.fmod`s the node's boot image does not hold —
//! beside the subgraph that wires them. Modules execute in place and the
//! loader applies no relocations (`docs/architecture/module_architecture.md`),
//! so a pack is copied whole into a page-aligned region of [`POOL`], its
//! table is validated exactly as the boot table is
//! (`ModuleLoader::init_from_blob_with_len`), and the region is made
//! executable (`hal::ota_stage_protect`: D-/I-cache maintenance on bare
//! metal, an RW → RX `mprotect` on a hosted kernel) before anything in it is
//! instantiated. The region is the owner's for as long as the owner lives:
//! freed when the owner is, when the add that staged it rolls back, and on
//! a rebuild.
//!
//! Every pack module is admitted only if it is the module the orchestrator
//! asked for: its full bytes match one of the SHA-256 pins CREATE carries
//! (an OCI layer digest is exactly that hash), or it carries a signature
//! the kernel verifies against its signing root. A pack that names no pin
//! and is unsigned runs nothing.
//!
//! Scheduler-thread state, like the scheduler's own: CREATE and owner
//! teardown both run there.

use crate::kernel::module::loader::{self, ModuleLoader};
use crate::kernel::sys::errno;
use crate::kernel::sys::hal;

/// Page granularity of a region: the largest page an aarch64 Linux kernel
/// uses (64 KiB), so protecting one region never changes a neighbour's on any
/// host; bare metal needs only cache-line alignment.
pub const PAGE: usize = 64 * 1024;

/// The pool every pack is staged into. 16 MiB on a 64-bit node — several
/// workloads' worth of modules at the 1 MiB per-module code ceiling — and
/// none on a microcontroller, which runs only its boot image's modules.
#[cfg(target_pointer_width = "64")]
pub const POOL_SIZE: usize = 16 * 1024 * 1024;
#[cfg(not(target_pointer_width = "64"))]
pub const POOL_SIZE: usize = 0;

const PAGES: usize = POOL_SIZE / PAGE;

/// Regions at once: one per owner, and one being staged.
const REGIONS: usize = crate::kernel::workload::owner::MAX_OWNERS + 1;

#[repr(C, align(65536))]
struct Pool {
    bytes: [u8; POOL_SIZE],
}

static mut POOL: Pool = Pool {
    bytes: [0; POOL_SIZE],
};

/// No owner: a region being staged, not yet bound.
const UNBOUND: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Region {
    used: bool,
    owner: u16,
    first_page: u32,
    pages: u32,
}

impl Region {
    const EMPTY: Self = Self {
        used: false,
        owner: UNBOUND,
        first_page: 0,
        pages: 0,
    };
}

struct State {
    regions: [Region; REGIONS],
    loaders: [ModuleLoader; REGIONS],
}

static mut STATE: State = State {
    regions: [Region::EMPTY; REGIONS],
    loaders: [const { ModuleLoader::new() }; REGIONS],
};

fn state() -> &'static mut State {
    // SAFETY: scheduler-thread state (see the module doc).
    unsafe {
        let p = &raw mut STATE;
        &mut *p
    }
}

fn pool_base() -> *mut u8 {
    // SAFETY: the pool's address; access is scheduler-thread only.
    unsafe {
        let p = &raw mut POOL;
        (*p).bytes.as_mut_ptr()
    }
}

/// Is page `p` inside any live region?
fn page_used(st: &State, p: u32) -> bool {
    st.regions
        .iter()
        .any(|r| r.used && p >= r.first_page && p < r.first_page + r.pages)
}

/// First run of `n` free pages: its first page.
fn find_pages(st: &State, n: u32) -> Option<u32> {
    let total = PAGES as u32;
    let mut start = 0u32;
    while start + n <= total {
        match (start..start + n).find(|&p| page_used(st, p)) {
            None => return Some(start),
            Some(busy) => start = busy + 1,
        }
    }
    None
}

/// A staged pack: its region and the loader over it.
#[derive(Clone, Copy)]
pub struct Staged(usize);

/// Copy `pack` (an FXMT module table) into a fresh region and validate its
/// table. Writable until [`seal`]. `ENOSYS` where there is no pool, `EINVAL`
/// for an empty pack, `E2BIG` past the pool, `ENOMEM` when no region or pages are free, `EFAULT` when the
/// region cannot be made writable, `EINVAL` for a table the loader refuses.
pub fn stage(pack: &[u8]) -> Result<Staged, i32> {
    if POOL_SIZE == 0 {
        return Err(errno::ENOSYS);
    }
    if pack.is_empty() {
        return Err(errno::EINVAL);
    }
    if pack.len() > POOL_SIZE {
        return Err(errno::E2BIG);
    }
    let st = state();
    let Some(id) = st.regions.iter().position(|r| !r.used) else {
        return Err(errno::ENOMEM);
    };
    let pages = pack.len().div_ceil(PAGE) as u32;
    let Some(first) = find_pages(st, pages) else {
        return Err(errno::ENOMEM);
    };
    let base = pool_base().wrapping_add(first as usize * PAGE);
    let len = pages as usize * PAGE;
    if !hal::ota_stage_protect(base, len, false) {
        return Err(errno::EFAULT);
    }
    // SAFETY: `base..base+len` lies inside the pool (find_pages bounds it)
    // and no live region overlaps it.
    unsafe {
        core::ptr::copy_nonoverlapping(pack.as_ptr(), base, pack.len());
        core::ptr::write_bytes(base.add(pack.len()), 0, len - pack.len());
    }
    let mut ldr = ModuleLoader::new();
    if ldr.init_from_blob_with_len(base, pack.len()).is_err() {
        return Err(errno::EINVAL);
    }
    st.loaders[id] = ldr;
    st.regions[id] = Region {
        used: true,
        owner: UNBOUND,
        first_page: first,
        pages,
    };
    Ok(Staged(id))
}

/// The loader over a staged pack.
pub fn loader(s: Staged) -> &'static ModuleLoader {
    &state().loaders[s.0]
}

/// The modules of a staged pack, each as `(name_hash, its full .fmod bytes)`
/// — the bytes a pin is the SHA-256 of. Calls `f` once per module.
pub fn for_each_module(s: Staged, f: impl FnMut(u32, &[u8])) {
    loader(s).for_each_entry(f);
}

/// Make a staged pack's region executable: from here its code may run.
pub fn seal(s: Staged) -> bool {
    let r = state().regions[s.0];
    let base = pool_base().wrapping_add(r.first_page as usize * PAGE);
    hal::ota_stage_protect(base, r.pages as usize * PAGE, true)
}

/// The staged pack is `owner_slot`'s now: freed with the owner.
pub fn bind(s: Staged, owner_slot: u16) {
    state().regions[s.0].owner = owner_slot;
}

/// Free a region: writable again, its loader forgotten.
fn free(id: usize) {
    let st = state();
    let r = st.regions[id];
    if !r.used {
        return;
    }
    let base = pool_base().wrapping_add(r.first_page as usize * PAGE);
    let _ = hal::ota_stage_protect(base, r.pages as usize * PAGE, false);
    st.loaders[id] = ModuleLoader::new();
    st.regions[id] = Region::EMPTY;
}

/// Release a pack that was staged but never bound (its add failed).
pub fn release(s: Staged) {
    if state().regions[s.0].owner == UNBOUND {
        free(s.0);
    }
}

/// Release `owner_slot`'s pack, when it has one. Call only once nothing of
/// the owner's runs: every module instantiated from it has been freed.
pub fn release_owner(owner_slot: u16) {
    if let Some(id) = state()
        .regions
        .iter()
        .position(|r| r.used && r.owner == owner_slot)
    {
        free(id);
    }
}

/// Forget every pack: a rebuild drops every workload, and with it the code
/// they ran. The node's own image may have changed with it (an OTA swaps the
/// table), so its digests are computed afresh.
pub fn reset() {
    for id in 0..REGIONS {
        free(id);
    }
    // SAFETY: scheduler-thread state.
    unsafe {
        STAGING = None;
        DIGESTS_READY = false;
    }
}

/// Most modules a module table holds: its count is one byte.
const TABLE_MODULES_MAX: usize = u8::MAX as usize;

/// The node's own modules' digests, computed once (hashing every module of
/// the image is milliseconds of work, not a per-call cost). Sized by what a
/// table can hold, not by what one graph instantiates: the image may carry
/// more modules than its graph runs, and every one of them is pinnable.
static mut DIGESTS: [(u32, [u8; 32]); TABLE_MODULES_MAX] = [(0, [0; 32]); TABLE_MODULES_MAX];
static mut DIGEST_COUNT: usize = 0;
static mut DIGESTS_READY: bool = false;

/// `MODULE_DIGESTS`: `[count:u16][0:u16]` then `[name_hash:u32][sha256:32]`
/// per module of the node's own image, as many as `out` holds; the count.
pub fn node_digests(node: &ModuleLoader, out: &mut [u8]) -> i32 {
    // SAFETY: scheduler-thread state.
    unsafe {
        if !DIGESTS_READY {
            let mut n = 0usize;
            node.for_each_entry(|hash, bytes| {
                let p = &raw mut DIGESTS;
                if n < (*p).len() {
                    let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
                    h.update(bytes);
                    (*p)[n] = (hash, h.finalize());
                    n += 1;
                }
            });
            DIGEST_COUNT = n;
            DIGESTS_READY = true;
        }
        if out.len() < 4 {
            return errno::EINVAL;
        }
        let count = DIGEST_COUNT;
        out[0..2].copy_from_slice(&(count as u16).to_le_bytes());
        out[2..4].copy_from_slice(&[0, 0]);
        let rec = crate::abi::contracts::workload::MODULE_DIGEST_RECORD;
        let d = &raw const DIGESTS;
        for i in 0..count {
            let at = 4 + i * rec;
            let Some(slot) = out.get_mut(at..at + rec) else {
                break;
            };
            let (hash, digest) = (*d)[i];
            slot[0..4].copy_from_slice(&hash.to_le_bytes());
            slot[4..36].copy_from_slice(&digest);
        }
        count as i32
    }
}

/// The pack an owner's modules resolve from, while its add is in progress:
/// set by CREATE around the add, consulted by the instantiation path before
/// the node's own loader. Scheduler-thread state.
static mut STAGING: Option<usize> = None;

/// Resolve names in `s` first, until [`end_staging`].
pub fn begin_staging(s: Staged) {
    // SAFETY: scheduler-thread state.
    unsafe {
        STAGING = Some(s.0);
    }
}

/// Resolve names in the node's own image only again.
pub fn end_staging() {
    // SAFETY: scheduler-thread state.
    unsafe {
        STAGING = None;
    }
}

/// The loader `name_hash` resolves from during an add: the staging pack's
/// when it holds the module, else `fallback` (the node's own).
pub fn resolve(name_hash: u32, fallback: &ModuleLoader) -> &ModuleLoader {
    // SAFETY: scheduler-thread state.
    let staging = unsafe { STAGING };
    if let Some(id) = staging {
        let l = &state().loaders[id];
        if l.find_by_name_hash(name_hash).is_ok() {
            return l;
        }
    }
    fallback
}

/// The kernel's verdict on one pack module: the module the orchestrator
/// asked for (`pinned` holds the SHA-256 of its full bytes), or one the
/// node's signing root signed.
pub fn admitted_with(
    bytes: &[u8],
    module: &loader::LoadedModule,
    pinned: impl Fn(&[u8; 32]) -> bool,
) -> bool {
    let digest = {
        let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
        h.update(bytes);
        h.finalize()
    };
    if pinned(&digest) {
        return true;
    }
    matches!(
        loader::validate_module(module, "pack"),
        Ok(loader::Signing::RootVerified)
    )
}

//! The bcm2712 memory map, from the device tree.
//!
//! The firmware describes the board's memory in the DTB it hands the kernel:
//! the `/memory` ranges, the `/reserved-memory` regions and the header's
//! reservation block, the initramfs it loaded, and the buses' DMA windows
//! (`kernel::boot::dtb::memory_facts`). [`build`] reads them before the MMU
//! is on and derives two things:
//!
//! - **what the boot page tables map as DRAM** — the gigabytes (and, in the
//!   Pi 5's first gigabyte, the 2 MB blocks) the tree states any memory in;
//!   a gigabyte or block with no memory behind it is mapped Device, never
//!   Normal, so a speculative fetch cannot reach it;
//! - **the zone**: the largest stretch of stated DRAM at or above
//!   [`ZONE_FLOOR`] (1 GB on the Pi 5, 2 GB on QEMU virt — above the boot
//!   image's RAM, which ends below `RAM_CEILING`, linker-asserted) that no
//!   reservation touches. The carve allocator takes the kernel's tables from its top
//!   (`kernel::mem::carve`) and the module state arena gets the rest
//!   (`kernel::module::loader::install_arena`). Nothing in it is zeroed here:
//!   each carve is zeroed as it is carved, and the arena zeroes what it hands
//!   out from a frontier advanced in the domains' slack.
//!
//! A tree that cannot be read (no blob, a malformed one, more ranges than the
//! reader keeps) leaves the kernel on a fixed map — the zone a 2 GB Pi 5 (or
//! QEMU at `-m 2G`) is known to have — and says so. A readable tree whose
//! memory leaves no zone gives the kernel none: every table carve is then
//! refused, and the boot fails naming the pool, never placing a table in
//! memory the tree did not offer.
//!
//! `.bss`, the stack and the payload window stay below `RAM_CEILING`
//! (`linker/memory-bcm2712.x`), which the zone's floor is never below.

use crate::kernel::boot::dtb::{self, MemoryFacts, Range};

/// Lowest address the zone may start at: the DRAM above 1 GB on the Pi 5
/// (clear of the firmware's top-of-first-GB reservation and of the DTB and
/// initramfs it places near 0x2E00_0000), QEMU virt's RAM above the kernel's
/// RAM region.
#[cfg(feature = "board-pi5")]
const ZONE_FLOOR: u64 = 0x4000_0000;
#[cfg(not(feature = "board-pi5"))]
const ZONE_FLOOR: u64 = 0x8000_0000;
/// One past the highest address the boot tables map as DRAM: the Pi 5's
/// first sixteen gigabytes, what its largest board holds (the SoC aperture
/// sits at 64 GB and the PCIe windows above it); QEMU virt's 39-bit address
/// space.
#[cfg(feature = "board-pi5")]
const DRAM_TOP: u64 = 0x4_0000_0000;
#[cfg(not(feature = "board-pi5"))]
const DRAM_TOP: u64 = 0x80_0000_0000;
/// The fixed map's zone, used when the tree cannot be read: what a 2 GB Pi 5
/// and QEMU virt at `-m 2G` hold above the floor.
#[cfg(feature = "board-pi5")]
const FIXED_ZONE: (u64, u64) = (0x4000_0000, 0x8000_0000);
#[cfg(not(feature = "board-pi5"))]
const FIXED_ZONE: (u64, u64) = (0x8000_0000, 0xC000_0000);
/// The fixed map's DRAM gigabytes (`[first, end)`).
#[cfg(feature = "board-pi5")]
const FIXED_DRAM_GBS: (usize, usize) = (1, 5);
#[cfg(not(feature = "board-pi5"))]
const FIXED_DRAM_GBS: (usize, usize) = (1, 3);
/// Zone alignment: the carve and arena granule.
const ZONE_ALIGN: u64 = 0x1_0000;
/// Candidate stretches a zone search keeps while splitting the memory ranges
/// around the reservations: one per memory range plus one per reservation
/// that lands inside one.
const MAX_SPANS: usize = dtb::MAX_MEMORY_RANGES + dtb::MAX_RESERVED_RANGES;
/// Where QEMU virt puts the DTB for a bare-metal (non-Linux) image: the base
/// of RAM, with no pointer in x0.
#[cfg(not(feature = "board-pi5"))]
const QEMU_DTB_ADDR: u64 = 0x4000_0000;

/// Where the map came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// Not built yet.
    None,
    /// The device tree.
    Dtb,
    /// The fixed map: no blob found.
    FixedNoBlob,
    /// The fixed map: the blob was malformed or overflowed the reader.
    FixedUnreadable,
    /// The fixed map: the tree states no memory.
    FixedNoMemory,
}

struct Map {
    source: Source,
    facts: MemoryFacts,
    blob: u64,
    zone: (u64, u64),
}

static mut MAP: Map = Map {
    source: Source::None,
    facts: MemoryFacts::empty(),
    blob: 0,
    zone: (0, 0),
};

fn map() -> &'static Map {
    // SAFETY: written once by `build`, at boot, before any reader.
    unsafe { &*core::ptr::addr_of!(MAP) }
}

/// The largest stretch of `memory` in `[ZONE_FLOOR, DRAM_TOP)` that no
/// `reserved` range touches, aligned. Uncapped: the state arena's offsets are
/// `usize`, so a board's DRAM above 4 GB is the arena's too.
fn find_zone(memory: &[Range], reserved: &[Range]) -> Option<(u64, u64)> {
    let mut spans = [(0u64, 0u64); MAX_SPANS];
    let mut n = 0usize;
    for r in memory {
        let lo = r.base.max(ZONE_FLOOR);
        let hi = r.end().min(DRAM_TOP);
        if lo < hi {
            if let Some(slot) = spans.get_mut(n) {
                *slot = (lo, hi);
                n += 1;
            }
        }
    }
    for rv in reserved {
        let (rlo, rhi) = (rv.base, rv.end());
        let mut i = 0;
        while i < n {
            let (lo, hi) = spans[i];
            if rhi <= lo || rlo >= hi {
                i += 1;
                continue;
            }
            // Cut the reservation out: keep the parts either side.
            let left = (lo, rlo.max(lo));
            let right = (rhi.min(hi), hi);
            spans[i] = left;
            if right.0 < right.1 {
                if let Some(slot) = spans.get_mut(n) {
                    *slot = right;
                    n += 1;
                }
            }
            i += 1;
        }
    }
    let mut best: Option<(u64, u64)> = None;
    for &(lo, hi) in spans.iter().take(n) {
        let lo = lo.next_multiple_of(ZONE_ALIGN);
        let hi = hi & !(ZONE_ALIGN - 1);
        if hi > lo && best.is_none_or(|(blo, bhi)| hi - lo > bhi - blo) {
            best = Some((lo, hi));
        }
    }
    best
}

/// Read the device tree at `dtb_phys` (the firmware's x0; QEMU leaves the
/// blob at the base of RAM instead) and build the map. Runs with the MMU off,
/// before the boot page tables are built from it, so it only reads the blob
/// and writes the map: with the MMU off every access is Device memory, where
/// an exclusive load/store never completes, and the carve allocator's lock
/// would spin forever. [`install`] hands the zone over once the MMU is on.
///
/// # Safety
/// Once, at boot, on the boot core, before anything allocates. `dtb_phys` is
/// what the firmware handed over.
pub unsafe fn build(dtb_phys: u64) {
    #[cfg(not(feature = "board-pi5"))]
    let dtb_phys = if dtb_phys == 0 {
        QEMU_DTB_ADDR
    } else {
        dtb_phys
    };
    // SAFETY: the firmware's pointer is into mapped DRAM (or null).
    let blob = unsafe { dtb::blob_at(dtb_phys as usize as *const u8) };
    let (source, facts, zone) = match blob.map(dtb::memory_facts) {
        None => (Source::FixedNoBlob, MemoryFacts::empty(), None),
        Some(None) => (Source::FixedUnreadable, MemoryFacts::empty(), None),
        Some(Some(f)) if f.truncated => (Source::FixedUnreadable, f, None),
        Some(Some(f)) if f.memory_count == 0 => (Source::FixedNoMemory, f, None),
        Some(Some(f)) => {
            let z = find_zone(f.memory(), f.reserved());
            (Source::Dtb, f, Some(z.unwrap_or((0, 0))))
        }
    };
    let zone = zone.unwrap_or(FIXED_ZONE);
    // SAFETY: the single boot-time writer.
    unsafe {
        let m = &mut *core::ptr::addr_of_mut!(MAP);
        m.source = source;
        m.facts = facts;
        m.blob = if blob.is_some() { dtb_phys } else { 0 };
        m.zone = zone;
    }
}

/// Give the carve allocator and the state arena the zone [`build`] found.
///
/// # Safety
/// Once, at boot, on the boot core, after [`build`] and after the MMU is on,
/// before anything allocates.
pub unsafe fn install() {
    let (lo, hi) = map().zone;
    let (lo, hi) = (lo as usize, hi as usize);
    crate::kernel::mem::carve::install(lo, hi);
    crate::kernel::module::loader::install_arena(lo, hi - lo);
}

/// Whether the map came from the device tree.
pub fn from_dtb() -> bool {
    map().source == Source::Dtb
}

/// Whether gigabyte `gb` of the physical address space holds DRAM the boot
/// tables map Normal.
pub fn dram_gb(gb: usize) -> bool {
    let m = map();
    if m.source != Source::Dtb {
        return (FIXED_DRAM_GBS.0..FIXED_DRAM_GBS.1).contains(&gb);
    }
    let (lo, hi) = ((gb as u64) << 30, ((gb as u64) + 1) << 30);
    hi <= DRAM_TOP && m.facts.memory().iter().any(|r| r.base < hi && r.end() > lo)
}

/// Whether 2 MB block `idx` of the first gigabyte holds DRAM: any of it
/// stated as memory. Without the tree, every block does (the fixed map).
pub fn dram_2mb(idx: usize) -> bool {
    let m = map();
    if m.source != Source::Dtb {
        return true;
    }
    let (lo, hi) = ((idx as u64) << 21, ((idx as u64) + 1) << 21);
    m.facts.memory().iter().any(|r| r.base < hi && r.end() > lo)
}

/// The zone `(lo, hi)` the carves and the state arena share.
pub fn zone() -> (u64, u64) {
    map().zone
}

/// Total DRAM the map states: the tree's `/memory`, or the fixed map's.
pub fn dram_bytes() -> u64 {
    let m = map();
    if m.source == Source::Dtb {
        m.facts.memory_bytes()
    } else {
        ((FIXED_DRAM_GBS.1 - FIXED_DRAM_GBS.0) as u64) << 30
    }
}

/// Log the map: where it came from, the memory, the reservations, the zone,
/// what the carves took and what the arena holds. Re-emitted on the heap
/// heartbeat, since a one-shot boot line can miss the rig's capture.
pub fn report() {
    let m = map();
    let (permanent, transient, leaked, refused) = crate::kernel::mem::carve::stats();
    log::info!(
        "[mem] src={:?} dram={:#x} ({} MiB) ranges={} reserved={} zone={:#x}-{:#x} carved={} \
         scratch={} reusable={} leaked={} refused={} arena={:#x} dma<={:#x} dtb={:#x}",
        m.source,
        dram_bytes(),
        dram_bytes() >> 20,
        m.facts.memory_count,
        m.facts.reserved_count,
        m.zone.0,
        m.zone.1,
        permanent,
        transient,
        crate::kernel::mem::carve::reusable(),
        leaked,
        refused,
        crate::kernel::module::loader::arena_cap(),
        m.facts.dma_ceiling.unwrap_or(u64::MAX),
        m.blob,
    );
    if m.facts.incomplete != 0 {
        for k in 0..8 {
            let bit = 1u8 << k;
            if m.facts.incomplete & bit == 0 {
                continue;
            }
            let why = match bit {
                dtb::INCOMPLETE_MEMORY_TABLE => "more /memory ranges than the reader keeps",
                dtb::INCOMPLETE_RESERVED_TABLE => "more reserved ranges than the reader keeps",
                dtb::INCOMPLETE_MEMORY_REG => "a /memory reg it cannot read",
                dtb::INCOMPLETE_RESERVED_REG => "a /reserved-memory reg it cannot read",
                dtb::INCOMPLETE_INITRD => "a /chosen initramfs range it cannot read",
                _ => "an unnamed reason",
            };
            log::warn!("[mem] device tree facts incomplete, fixed map used: {why}");
        }
    }
    for r in m.facts.memory() {
        log::info!("[mem] memory {:#x}-{:#x}", r.base, r.end());
    }
    for r in m.facts.reserved() {
        log::info!("[mem] reserved {:#x}-{:#x}", r.base, r.end());
    }
    if m.zone.1 <= m.zone.0 {
        log::error!(
            "[mem] no zone: the device tree states no DRAM at or above {ZONE_FLOOR:#x} clear of \
             its reservations, so no kernel table and no module state can be placed"
        );
    }
    // The DMA arenas the NIC and NVMe rings live in are kernel `.bss`; a bus
    // window that cannot reach them is a board this map does not fit.
    let top = crate::platform::nic_ring::pcie1_dma_arena_base()
        .saturating_add(crate::platform::nic_ring::pcie1_dma_arena_size())
        .max(
            crate::platform::nic_ring::dma_arena_base()
                .saturating_add(crate::platform::nic_ring::DMA_ARENA_SIZE),
        ) as u64;
    if m.facts.dma_ceiling.is_some_and(|c| top > c) {
        log::warn!(
            "[mem] DMA arenas end at {top:#x}, past the device tree's DMA window {:#x}",
            m.facts.dma_ceiling.unwrap_or(0)
        );
    }
}

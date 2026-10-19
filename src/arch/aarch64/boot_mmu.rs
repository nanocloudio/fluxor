//! Boot-time identity map: the page tables the core consults from the
//! moment the MMU comes on, and the switch that turns it on.
//!
//! Distinct from the per-module isolation tables (`isolation`), which
//! the kernel programmes at runtime. This is the one map the kernel itself
//! runs under: identity, 4 KB granule, EL1, 39-bit VA, 40-bit PA, 16-bit
//! ASIDs, built from 1 GB blocks with the first gigabyte split into 2 MB
//! blocks (and the blocks around kernel stack guard pages into 4 KB pages).
//!
//! What goes where is the machine's: a Pi 5 has DRAM below 4 GB and its
//! peripherals in two apertures far above, QEMU's `virt` machine has RAM
//! from 1 GB and devices below it, a UEFI machine says in its memory map.
//! So the platform describes its map in [`Kind`]s, gigabyte by gigabyte
//! ([`map_gb`]) and 2 MB block by block in the first gigabyte
//! ([`map_2mb`]), then calls [`enable`].
//!
//! MAIR indices: 0 Normal Write-Back Write-Allocate, 1 Device-nGnRE,
//! 2 Normal Non-cacheable (DMA arenas: hardware and CPU see the same
//! bytes with no cache maintenance on the fast path).

#![allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]

/// What a block of the identity map is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Normal cacheable memory: the kernel's, the modules', the arena's.
    Dram,
    /// Device-nGnRE, never executed: MMIO.
    Device,
    /// Normal non-cacheable memory: a DMA arena.
    Dma,
}

// Descriptor bits.
const VALID: u64 = 1;
const TABLE: u64 = 1 << 1;
const BLOCK: u64 = 0;
const ATTR_IDX_SHIFT: u64 = 2;
const AP_RW: u64 = 0 << 6; // AP[2:1] = 00: EL1 RW
const SH_INNER: u64 = 3 << 8;
const AF: u64 = 1 << 10;
/// nG (not-global): ASID-tag the entry. The kernel runs under ASID 0, but
/// EL0-isolated modules run under their own ASID with their own page
/// table. If the kernel identity map were GLOBAL, its cached 2 MB DRAM
/// block TLB entries would match ANY ASID and SHADOW an isolated module's
/// nG 4 KB EL0 carve in the same window (the EL0 stack, which co-locates
/// with the per-module page-table BSS) — a spurious EL0 permission fault
/// at level 2 even though the module's own tables are right. Tagged nG
/// (ASID 0), the kernel map never matches an isolated access.
const NG: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

/// MAIR_EL1. Attr1 is Device-nGnRE rather than nGnRnE: nGnRnE forces the
/// CPU to wait for each write to be observable before proceeding, which
/// stalls on PCIe posted writes that never return a completion (the RP1
/// datasheet §3.3.1.2 recommends nGnRE for exactly that reason).
pub const MAIR_VALUE: u64 = 0xFF              // index 0: Normal WB-WA
    | (0x04 << 8)    // index 1: Device-nGnRE
    | (0x44 << 16); // index 2: Normal Non-cacheable

/// TCR_EL1: 39-bit VA from L1 (T0SZ = 25), 4 KB granule (TG0 = 0, so the
/// field is omitted), inner+outer WB-WA, inner shareable, TTBR1 walks off,
/// 40-bit PA (1 TB: reaches a Pi 5's RP1 window at 0x1f_xxxx_xxxx), 16-bit
/// ASIDs (one per module index).
pub const TCR_VALUE: u64 =
    25 | (0b01 << 8) | (0b01 << 10) | (0b11 << 12) | (1 << 23) | (0b010u64 << 32) | (1u64 << 36);

const fn dram_block(addr: u64) -> u64 {
    addr | VALID | BLOCK | (0 << ATTR_IDX_SHIFT) | AP_RW | SH_INNER | AF | NG
}

const fn device_block(addr: u64) -> u64 {
    addr | VALID | BLOCK | (1 << ATTR_IDX_SHIFT) | AP_RW | AF | NG | PXN | UXN
}

const fn dma_block(addr: u64) -> u64 {
    addr | VALID | BLOCK | (2 << ATTR_IDX_SHIFT) | AP_RW | SH_INNER | AF | NG | UXN
}

const fn block(addr: u64, kind: Kind) -> u64 {
    match kind {
        Kind::Dram => dram_block(addr),
        Kind::Device => device_block(addr),
        Kind::Dma => dma_block(addr),
    }
}

const fn table_desc(next: u64) -> u64 {
    next | VALID | TABLE
}

/// One level of the map: 512 entries, 4 KB aligned.
#[repr(C, align(4096))]
pub struct PageTable([u64; 512]);

/// L1: 512 × 1 GB.
#[link_section = ".bss"]
pub static mut L1_TABLE: PageTable = PageTable([0; 512]);

/// L2 for the first gigabyte: 512 × 2 MB, so a DMA arena or a stack guard
/// in the kernel's own BSS can differ from the DRAM around it.
#[link_section = ".bss"]
static mut L2_TABLE_0: PageTable = PageTable([0; 512]);

/// L3 tables for the 2 MB blocks that hold a kernel stack guard page — one
/// per guard at most.
pub const MAX_GUARD_L3: usize = 4;

#[link_section = ".bss"]
static mut GUARD_L3: [PageTable; MAX_GUARD_L3] = [const { PageTable([0; 512]) }; MAX_GUARD_L3];

/// MAIR/TCR/TTBR0 as the boot core programmed them, published at the
/// point of coherency for a secondary core's trampoline, which installs
/// the same translation with the MMU still off so that its accesses join
/// inner-shareable coherency.
#[no_mangle]
pub static mut SECONDARY_MMU_MAIR: u64 = 0;
#[no_mangle]
pub static mut SECONDARY_MMU_TCR: u64 = 0;
#[no_mangle]
pub static mut SECONDARY_MMU_TTBR0: u64 = 0;

/// Map gigabyte `index` (address `index << 30`) as one block.
///
/// # Safety
/// Boot core, MMU off, before [`enable`].
pub unsafe fn map_gb(index: usize, kind: Kind) {
    let l1 = &raw mut L1_TABLE.0;
    (*l1)[index] = block((index as u64) << 30, kind);
}

/// Split the first gigabyte into 2 MB blocks, all `kind`, so that
/// [`map_2mb`] and [`unmap_stack_guards`] can refine it.
///
/// # Safety
/// As [`map_gb`].
pub unsafe fn split_first_gb(kind: Kind) {
    let l2 = &raw mut L2_TABLE_0.0;
    for (i, e) in (*l2).iter_mut().enumerate() {
        *e = block((i as u64) * 0x20_0000, kind);
    }
    let l1 = &raw mut L1_TABLE.0;
    (*l1)[0] = table_desc(&raw const L2_TABLE_0 as u64);
}

/// Map 2 MB block `index` of the first gigabyte (address `index << 21`)
/// as `kind`. Needs [`split_first_gb`] first.
///
/// # Safety
/// As [`map_gb`].
pub unsafe fn map_2mb(index: usize, kind: Kind) {
    let l2 = &raw mut L2_TABLE_0.0;
    (*l2)[index] = block((index as u64) * 0x20_0000, kind);
}

/// Leave each kernel stack's guard page (a 4 KB address in the first
/// gigabyte) unmapped, so an overflow faults at an address instead of
/// writing through the statics below the stack: the 2 MB block holding
/// the guard is split into 4 KB pages carrying the block's attributes,
/// with the guard page invalid. Two guards in one block share its table.
/// Needs [`split_first_gb`] first.
///
/// # Safety
/// As [`map_gb`].
pub unsafe fn unmap_stack_guards(guards: &[u64]) {
    const VALID_TYPE_MASK: u64 = 0b11;
    const PAGE_TYPE: u64 = 0b11;
    const BLOCK_ADDR: u64 = 0x0000_FFFF_FFE0_0000;
    let l2 = &mut *(&raw mut L2_TABLE_0).cast::<[u64; 512]>();
    let mut used = 0usize;
    for &guard in guards {
        let l2i = (guard >> 21) as usize;
        if l2i >= 512 {
            continue;
        }
        let entry = l2[l2i];
        let l3: *mut [u64; 512] = if entry & VALID_TYPE_MASK == VALID | TABLE {
            (entry & 0x0000_FFFF_FFFF_F000) as *mut [u64; 512]
        } else {
            if used == MAX_GUARD_L3 {
                continue;
            }
            let t = &raw mut GUARD_L3[used].0;
            used += 1;
            let base = entry & BLOCK_ADDR;
            let attrs = entry & !BLOCK_ADDR & !VALID_TYPE_MASK;
            for (j, e) in (*t).iter_mut().enumerate() {
                *e = (base + (j as u64) * 0x1000) | attrs | PAGE_TYPE;
            }
            l2[l2i] = table_desc(t as u64);
            t
        };
        (*l3)[((guard >> 12) & 0x1FF) as usize] = 0;
    }
}

/// Enable the MMU over the identity map, caches on, alignment checking
/// off (the firmware's value is not ours to assume, and modules are built
/// to emit unaligned accesses over Normal memory), and publish the
/// translation registers for the secondary cores.
///
/// # Safety
/// Boot core, once, after the map is built.
pub unsafe fn enable() {
    let ttbr = &raw const L1_TABLE as u64;
    core::arch::asm!(
        "tlbi vmalle1",
        "dsb ish",
        "msr mair_el1, {mair}",
        "msr tcr_el1, {tcr}",
        "msr ttbr0_el1, {ttbr}",
        "dsb ish",
        "isb",
        "mrs {tmp}, sctlr_el1",
        "bic {tmp}, {tmp}, #(1 << 1)",  // A: alignment checking off
        "orr {tmp}, {tmp}, #(1 << 0)",  // M
        "orr {tmp}, {tmp}, #(1 << 2)",  // C
        "orr {tmp}, {tmp}, #(1 << 12)", // I
        "msr sctlr_el1, {tmp}",
        "isb",
        mair = in(reg) MAIR_VALUE,
        tcr = in(reg) TCR_VALUE,
        ttbr = in(reg) ttbr,
        tmp = out(reg) _,
    );
    // The trampoline reads these with the MMU off, so they must be at the
    // point of coherency, not in this core's cache.
    let mair_p = &raw mut SECONDARY_MMU_MAIR;
    let tcr_p = &raw mut SECONDARY_MMU_TCR;
    let ttbr_p = &raw mut SECONDARY_MMU_TTBR0;
    core::ptr::write_volatile(mair_p, MAIR_VALUE);
    core::ptr::write_volatile(tcr_p, TCR_VALUE);
    core::ptr::write_volatile(ttbr_p, ttbr);
    core::arch::asm!(
        "dc cvac, {m}",
        "dc cvac, {t}",
        "dc cvac, {b}",
        "dsb sy",
        m = in(reg) mair_p,
        t = in(reg) tcr_p,
        b = in(reg) ttbr_p,
        options(nostack),
    );
}

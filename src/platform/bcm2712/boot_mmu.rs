//! Boot-time MMU page tables — Pi 5 only (cm5 board).
//!
//! Distinct from `fluxor::kernel::mmu`, which programmes per-module
//! page tables for EL0 hardware isolation at runtime. This module
//! builds the **identity-mapped** L1 + L2 tables consulted by the
//! Cortex-A76 immediately after `_start` and enables the MMU before
//! the kernel touches any cacheable memory.
//!
//! 4KB granule, EL1, 2-level (L1 + L2) identity map.
//! L1 covers 512 entries × 1GB each = 512 GB address space.
//! L2 covers 512 entries × 2MB each = 1 GB per L1 entry.
//!
//! MAIR indices:
//!   0 = Normal Cacheable (Write-Back, Write-Allocate, inner+outer)
//!   1 = Device-nGnRE     (strongly ordered device memory)
//!   2 = Normal Non-cacheable
//!
//! Memory map:
//!   0x0000_0000 .. 0x3FFF_FFFF  (1 GB)  — DRAM, Normal Cacheable
//!   0x4000_0000 .. 0x7FFF_FFFF  (1 GB)  — DRAM, Normal Cacheable
//!   0x8000_0000 .. 0xBFFF_FFFF  (1 GB)  — DRAM, Normal Cacheable
//!   0xC000_0000 .. 0xFFFF_FFFF  (1 GB)  — DRAM, Normal Cacheable
//!   0x1_0000_0000 .. onwards    — Device (PCIe, RP1, GIC, BCM2712 peripherals)
//!
//! On QEMU virt, the memory map is different but we use 1GB blocks which
//! is coarse enough to work. The key device regions (0x08000000 GIC,
//! 0x09000000 UART) fall in the first 1GB which we map as device memory.

#![allow(dead_code, reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it")]

#[cfg(feature = "board-cm5")]
mod cm5_impl {
    // Page table attributes for block descriptors (2MB or 1GB)
    const VALID: u64 = 1; // bit 0: valid
    const TABLE: u64 = 1 << 1; // bit 1: table descriptor (vs block for L1 1GB)
    const BLOCK: u64 = 0; // bit 1=0: block descriptor

    // Lower attributes (bits [11:2])
    const ATTR_IDX_SHIFT: u64 = 2;
    const NS: u64 = 1 << 5; // Non-secure
    const AP_RW: u64 = 0 << 6; // AP[2:1] = 00: EL1 RW
    const SH_INNER: u64 = 3 << 8; // Inner shareable
    const AF: u64 = 1 << 10; // Access flag (must set or we get fault)
    // nG (not-global): ASID-tag the entry. The kernel runs under ASID 0, but
    // EL0-isolated modules run under their own ASID (module_idx+1) with their
    // own page table (see bcm2712/mmu.rs). If the kernel identity map were
    // GLOBAL, its cached 2 MB DRAM block TLB entries would match ANY ASID and
    // SHADOW an isolated module's nG 4 KB EL0 carve in the same window (e.g.
    // the EL0 stack, which co-locates with the per-module page-table BSS) →
    // a spurious EL0 permission fault at level 2 even though the module's
    // L1/L2/L3 are correctly carved EL0-RW. Tagging the kernel map nG (ASID 0)
    // means it never matches an ASID-5 EL0 access, so the module's own carve is
    // always used. The kernel always runs ASID 0, so its own accesses still hit.
    const NG: u64 = 1 << 11;

    // Upper attributes
    const PXN: u64 = 1 << 53; // Privileged execute-never
    const UXN: u64 = 1 << 54; // Unprivileged execute-never

    // MAIR_EL1 encoding
    // Attr0: Normal, Write-Back Write-Allocate (inner+outer) = 0xFF
    // Attr1: Device-nGnRE = 0x04 (per RP1 datasheet §3.3.1.2: recommended
    //        AArch64 mapping for the RP1 PCIe peripheral region is nGnRE,
    //        not nGnRnE — nGnRnE forces the CPU to wait for writes to be
    //        "observable" before proceeding, which stalls on PCIe Posted
    //        writes that never return explicit completions)
    // Attr2: Normal Non-cacheable = 0x44
    pub const MAIR_VALUE: u64 = 0xFF              // index 0: Normal WB-WA
        | (0x04 << 8)    // index 1: Device-nGnRE
        | (0x44 << 16); // index 2: Normal Non-cacheable

    // TCR_EL1: 39-bit VA (T0SZ=25), 4KB granule, inner+outer WB-WA cacheable
    // T0SZ=25 → 39-bit VA (512 GB). Translation starts at L1 (no L0 needed).
    // Each L1 entry covers 1 GB. 512 entries covers the full 512 GB space.
    // TG0 = 0b00 (4KB) is encoded as zero — the bit field is intentionally
    // omitted from the OR chain so it stays zero without a no-effect shift.
    pub const TCR_VALUE: u64 = 25                 // T0SZ = 25 → 39-bit VA (512 GB)
        | (0b01 << 8)     // IRGN0: WB-WA
        | (0b01 << 10)    // ORGN0: WB-WA
        | (0b11 << 12)    // SH0: inner shareable
        | (1 << 23)       // EPD1: disable TTBR1_EL1 walks (kernel-only, no upper VA)
        | (0b010u64 << 32); // IPS = 0b010 → 40-bit PA (1TB, covers RP1 BAR at 0x1f_xxxx_xxxx)

    // Block descriptor for DRAM: Normal Cacheable, RW, Inner Shareable, nG.
    // nG so kernel (ASID 0) DRAM blocks never shadow an isolated module's
    // ASID-tagged EL0 carve in the same 2 MB window (see `NG`).
    const fn dram_block(addr: u64) -> u64 {
        addr | VALID | BLOCK | (0 << ATTR_IDX_SHIFT) | AP_RW | SH_INNER | AF | NG
    }

    // Block descriptor for Device memory: Device-nGnRnE, RW, no exec
    const fn device_block(addr: u64) -> u64 {
        addr | VALID | BLOCK | (1 << ATTR_IDX_SHIFT) | AP_RW | AF | PXN | UXN
    }

    // Block descriptor for DMA memory: Normal Non-Cacheable, RW, Inner Shareable
    // Used for NIC DMA arena so hardware DMA and CPU see coherent data without
    // explicit cache maintenance. MAIR index 2 = 0x44 (Normal Non-cacheable).
    const fn dma_block(addr: u64) -> u64 {
        addr | VALID | BLOCK | (2 << ATTR_IDX_SHIFT) | AP_RW | SH_INNER | AF | UXN
    }

    // Table descriptor: points L1 entry to an L2 table (for 2MB granularity)
    const fn table_desc(l2_addr: u64) -> u64 {
        l2_addr | VALID | TABLE
    }

    /// Static L1 page table (512 entries, 4KB aligned, in BSS).
    /// Each entry covers 1 GB.
    #[repr(C, align(4096))]
    pub struct PageTable([u64; 512]);

    #[link_section = ".bss"]
    pub static mut L1_TABLE: PageTable = PageTable([0; 512]);

    /// L2 page table for the first 1GB of DRAM (0x0 - 0x3FFFFFFF).
    /// This allows the NIC DMA arena (2MB-aligned in BSS) to be mapped
    /// as non-cacheable while the rest of DRAM stays cacheable.
    /// Each entry covers 2MB.
    #[repr(C, align(4096))]
    struct L2Table([u64; 512]);

    #[link_section = ".bss"]
    static mut L2_TABLE_0: L2Table = L2Table([0; 512]);

    /// Fill the L1 page table with identity mappings.
    /// Must be called before enabling the MMU.
    pub unsafe fn init_page_tables() {
        let l1_ptr = &raw mut L1_TABLE.0;
        let table = &mut *l1_ptr;

        // 0x0_0000_0000 .. 0x0_3FFF_FFFF (1 GB): DRAM with L2 table so
        // the 2 MB blocks enclosing the BSS-backed DMA arenas (NIC ring
        // and PCIe1) can be flipped to Normal Non-Cacheable while the
        // rest stays cacheable. Both arenas must live below 4 GB because
        // the PCIe1 inbound ATU only covers PCI bus 0..0xFFFFFFFF on
        // Pi 5 (see nvme_trace/baseline/README.md).
        {
            let l2_ptr = &raw mut L2_TABLE_0.0;
            let l2 = &mut *l2_ptr;
            // Fill all 512 L2 entries as cacheable DRAM (each 2MB)
            let mut i = 0usize;
            while i < 512 {
                l2[i] = dram_block((i as u64) * 0x20_0000);
                i += 1;
            }
            // Flip each BSS DMA arena's enclosing 2 MB to Normal
            // Non-Cacheable (MAIR index 2). Hardware DMA and CPU see
            // coherent memory by construction — no DC CVAC / IVAC on
            // the fast path.
            let dma_addr = fluxor::kernel::nic_ring::dma_arena_base();
            if dma_addr != 0 && dma_addr < 0x4000_0000 {
                let l2_idx = dma_addr >> 21;
                l2[l2_idx] = dma_block((l2_idx as u64) * 0x20_0000);
            }
            let pcie1_dma = fluxor::kernel::nic_ring::pcie1_dma_arena_base();
            if pcie1_dma != 0 && pcie1_dma < 0x4000_0000 {
                let l2_idx = pcie1_dma >> 21;
                l2[l2_idx] = dma_block((l2_idx as u64) * 0x20_0000);
            }
            // Point L1[0] to our L2 table
            table[0] = table_desc(&raw const L2_TABLE_0 as u64);
        }
        // 0x0_4000_0000 .. 0x0_7FFF_FFFF (1 GB): DRAM
        table[1] = dram_block(0x0_4000_0000);
        // 0x0_8000_0000 .. 0x0_BFFF_FFFF (1 GB): DRAM
        table[2] = dram_block(0x0_8000_0000);
        // 0x0_C000_0000 .. 0x0_FFFF_FFFF (1 GB): DRAM
        table[3] = dram_block(0x0_C000_0000);

        // 0x1_0000_0000 .. 0x1_3FFF_FFFF: real DRAM on 8/16 GB Pi 5
        // boards. No longer used as DMA target (see PCIE1_DMA_ARENA
        // comment in bcm2712/net.rs) — mapped as regular cacheable
        // DRAM in case a future consumer wants it.
        table[4] = dram_block(0x1_0000_0000);
        // 0x1_4000_0000 .. 0x1_7FFF_FFFF: more PCIe space (device)
        table[5] = device_block(0x1_4000_0000);
        // 0x1_8000_0000 .. 0x1_BFFF_FFFF: PCIe range (device)
        table[6] = device_block(0x1_8000_0000);
        // 0x1_C000_0000 .. 0x1_FFFF_FFFF: PCIe range (device)
        table[7] = device_block(0x1_C000_0000);

        // BCM2712 peripheral space at 0xFE000000-0xFFFFFFFF (GIC, UART, etc.)
        // falls in the 4th GB (0xC000_0000..0xFFFF_FFFF). Map as device memory.
        // This loses 1GB of DRAM addressability (3GB usable), which is fine for
        // a bare-metal kernel that uses < 1MB.
        table[3] = device_block(0x0_C000_0000);

        // BCM2712 SoC peripheral aperture at 0x10_0000_0000..0x10_8000_0000 (2 GB).
        // This covers the legacy peripherals block that device tree exposes under
        // `soc@107c000000 { ranges = <0x00 0x10 0x00 0x80000000>; }`, including
        // GIC-400 at 0x10_7fff_9000/a000 and the BCM7271 UART, pinctrl, etc.
        // L1 index = 0x10_0000_0000 / 0x4000_0000 = 64. Two 1GB blocks = 64, 65.
        table[64] = device_block(0x10_0000_0000);
        table[65] = device_block(0x10_4000_0000);

        // RP1 PCIe BAR region at 0x1c_0000_0000 (VPU firmware window).
        // L1 index = 0x1c_0000_0000 / 0x4000_0000 = 112.
        // Map 4 GB of device space covering the full RP1 BAR range.
        table[112] = device_block(0x1c_0000_0000);
        table[113] = device_block(0x1c_4000_0000);
        table[114] = device_block(0x1c_8000_0000);
        table[115] = device_block(0x1c_c000_0000);

        // PCIe1 (external x1 slot, NVMe HAT+) outbound MMIO window at
        // 0x18_0000_0000..0x1b_ffff_ffff (16 GB total) — verified
        // against the Pi 5 base-board 6.12 rpt kernel `dmesg` ranges
        // for the 1000110000.pcie controller (two ranges: mem1 at
        // 0x1800_0000_00 prefetchable, mem0 at 0x1b80_0000_00).
        // L1 indices 96..111, one 1 GB block each.
        let mut pcie1_idx = 96usize;
        while pcie1_idx < 112 {
            let addr = (pcie1_idx as u64) * 0x4000_0000;
            table[pcie1_idx] = device_block(addr);
            pcie1_idx += 1;
        }
    }

    /// Enable the MMU with the identity-mapped page tables.
    ///
    /// # Safety
    /// Must be called once, early in boot, before accessing any memory that
    /// requires cacheability attributes.
    pub unsafe fn enable() {
        let ttbr = &raw const L1_TABLE as u64;

        core::arch::asm!(
            // Set MAIR_EL1
            "msr mair_el1, {mair}",
            // Set TCR_EL1
            "msr tcr_el1, {tcr}",
            // Set TTBR0_EL1
            "msr ttbr0_el1, {ttbr}",
            // Barrier: ensure all table writes are visible
            "dsb ish",
            "isb",
            // Enable MMU (SCTLR_EL1: M=1, C=1, I=1)
            "mrs {tmp}, sctlr_el1",
            "orr {tmp}, {tmp}, #(1 << 0)",  // M: MMU enable
            "orr {tmp}, {tmp}, #(1 << 2)",  // C: Data cache enable
            "orr {tmp}, {tmp}, #(1 << 12)", // I: Instruction cache enable
            "msr sctlr_el1, {tmp}",
            "isb",
            mair = in(reg) MAIR_VALUE,
            tcr = in(reg) TCR_VALUE,
            ttbr = in(reg) ttbr,
            tmp = out(reg) _,
        );

        // Publish MAIR/TCR/TTBR0 for the secondary-core trampoline in
        // `bcm2712/multicore.rs`, which reads them with MMU off and
        // needs the values to already be at PoC.
        let mair_p = core::ptr::addr_of_mut!(fluxor::kernel::SECONDARY_MMU_MAIR);
        let tcr_p = core::ptr::addr_of_mut!(fluxor::kernel::SECONDARY_MMU_TCR);
        let ttbr_p = core::ptr::addr_of_mut!(fluxor::kernel::SECONDARY_MMU_TTBR0);
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
}

// Re-export the cm5 implementation as the module's public API.
#[cfg(feature = "board-cm5")]
pub use cm5_impl::{enable, init_page_tables};

// On QEMU virt, no MMU setup needed (identity mapped by QEMU firmware).
#[cfg(not(feature = "board-cm5"))]
pub unsafe fn init_page_tables() {}

#[cfg(not(feature = "board-cm5"))]
pub unsafe fn enable() {}

//! The boot-time memory maps — Pi 5 and QEMU virt — described to the
//! architecture's identity-map builder (`fluxor::arch::aarch64::boot_mmu`),
//! which owns the tables, the descriptors and the switch.
//!
//! Distinct from `fluxor::arch::aarch64::isolation`, which programmes
//! per-module page tables for EL0 hardware isolation at runtime.

#![allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]

use fluxor::arch::aarch64::boot_mmu::{self, Kind};

extern "C" {
    /// The image's first byte (`_start` is placed first, at RAM_ORIGIN).
    static _start: u8;
    /// The end of the RAM the image, its BSS and the boot stack occupy.
    static __end_block_addr: u8;
    /// The packed-payload header `_start` relocates from (magic, _, dest,
    /// size as u32s).
    static __package_header_start: u32;
}

/// The packed-payload header's magic, as `_start` checks it.
const PACKAGE_MAGIC: u32 = 0x4B50_5846;

/// Turn the MMU on. Everything since entry ran with the MMU off, so the
/// image's data, BSS (the page tables), the stack — all of
/// `_start..__end_block_addr` — and the payload `_start` relocated were
/// written straight to memory; `boot_mmu::enable` invalidates those
/// ranges before caching starts.
///
/// # Safety
/// As [`boot_mmu::enable`].
pub unsafe fn enable() {
    let image = (
        &raw const _start as usize,
        &raw const __end_block_addr as usize,
    );
    let hdr = &raw const __package_header_start;
    let payload = if core::ptr::read_volatile(hdr) == PACKAGE_MAGIC {
        let dest = core::ptr::read_volatile(hdr.add(2)) as usize;
        let size = core::ptr::read_volatile(hdr.add(3)) as usize;
        (dest, dest + size)
    } else {
        (0, 0)
    };
    boot_mmu::enable(&[image, payload]);
}

/// The Pi 5's map.
///
///   0x0000_0000 .. 0xFFFF_FFFF     DRAM (the first gigabyte in 2 MB blocks;
///                                  the firmware keeps 0x3FC0_0000..0x4000_0000)
///   0x1_0000_0000 .. 0x1_3FFF_FFFF DRAM (8 and 16 GB boards; not a DMA target)
///   0x1_4000_0000 .. 0x1_FFFF_FFFF Device: DRAM on 8 and 16 GB boards that
///                                  the kernel does not use
///   0x10_0000_0000 .. 0x10_7FFF_FFFF  SoC peripheral aperture (GIC-400, …)
///   0x18_0000_0000 .. 0x1B_FFFF_FFFF  PCIe1 (external connector) outbound windows
///   0x1C_0000_0000 .. 0x1C_FFFF_FFFF  RP1 BAR, where the firmware leaves PCIe2's
///                                     outbound window (RP1's UART, Ethernet, …)
///
/// The DRAM gigabytes above the first are mapped Normal whether or not a
/// smaller board populates them. Both BSS-backed DMA arenas must live
/// below 4 GB because the PCIe1 inbound ATU only covers PCI bus
/// 0..0xFFFFFFFF.
///
/// # Safety
/// Called once, early in boot, with the MMU off.
#[cfg(feature = "board-pi5")]
pub unsafe fn init_page_tables() {
    boot_mmu::split_first_gb(Kind::Dram);
    // Each BSS DMA arena's enclosing 2 MB blocks become Normal
    // Non-Cacheable: hardware DMA and CPU see coherent memory by
    // construction, with no DC CVAC / IVAC on the fast path.
    let dma_addr = fluxor::platform::nic_ring::dma_arena_base();
    if dma_addr != 0 && dma_addr < 0x4000_0000 {
        boot_mmu::map_2mb(dma_addr >> 21, Kind::Dma);
    }
    // The PCIe1 arena's size is a tunable in net.rs and may span more than
    // one block, so flip EVERY block it covers — one left cacheable would
    // silently corrupt DMA.
    let pcie1_dma = fluxor::platform::nic_ring::pcie1_dma_arena_base();
    let pcie1_size = fluxor::platform::nic_ring::pcie1_dma_arena_size();
    if pcie1_dma != 0 && pcie1_dma < 0x4000_0000 {
        let first = pcie1_dma >> 21;
        let last = (pcie1_dma + pcie1_size - 1) >> 21;
        let mut idx = first;
        while idx <= last && idx < 512 {
            boot_mmu::map_2mb(idx, Kind::Dma);
            idx += 1;
        }
    }
    boot_mmu::unmap_stack_guards(&fluxor::platform::multicore::kernel_stack_guards());

    for gb in 1..5 {
        boot_mmu::map_gb(gb, Kind::Dram);
    }
    for gb in 5..8 {
        boot_mmu::map_gb(gb, Kind::Device);
    }
    // The SoC aperture at 0x10_0000_0000 (2 GB): L1 indices 64, 65.
    boot_mmu::map_gb(64, Kind::Device);
    boot_mmu::map_gb(65, Kind::Device);
    // PCIe1 outbound windows at 0x18_0000_0000..0x1B_FFFF_FFFF (16 GB, the
    // `ranges` of the devicetree's pcie@1000110000): indices 96..111.
    for gb in 96..112 {
        boot_mmu::map_gb(gb, Kind::Device);
    }
    // The RP1 BAR at 0x1C_0000_0000: 4 GB, indices 112..115.
    for gb in 112..116 {
        boot_mmu::map_gb(gb, Kind::Device);
    }
}

/// QEMU virt: RAM starts at 1 GB and `fluxor run` gives the machine 2 GB of
/// it (`-m 2G`, `targets/boards/qemu-virt.toml`), which holds the kernel's
/// 1 GiB state arena. Only that is mapped Normal: address space with no
/// memory behind it is never mapped as memory, where a speculative fetch
/// could reach it. Every other gigabyte below 512 GB is Device — the first
/// holds the flash, GIC, UART, virtio-mmio and low PCIe windows, the one at
/// 256 GB the PCIe ECAM. The 64-bit PCIe window, at 512 GB, is outside a
/// 39-bit address space and is not mapped; nothing here places a BAR
/// there. Without the map the MMU stays off, every access is
/// Device-nGnRnE, and module code — built for a part that runs with the
/// MMU on, so free to emit unaligned loads and stores — would
/// alignment-fault on its first unaligned access.
///
/// # Safety
/// Called once, early in boot, with the MMU off.
#[cfg(not(feature = "board-pi5"))]
pub unsafe fn init_page_tables() {
    const RAM_FIRST_GB: usize = 1;
    const RAM_GBS: usize = 2;
    for gb in 0..512 {
        let kind = if (RAM_FIRST_GB..RAM_FIRST_GB + RAM_GBS).contains(&gb) {
            Kind::Dram
        } else {
            Kind::Device
        };
        boot_mmu::map_gb(gb, kind);
    }
    core::arch::asm!("dsb ish", "isb", options(nostack));
}

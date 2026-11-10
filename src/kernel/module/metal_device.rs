//! The `metal_device` contract: device registers, DMA memory and cache
//! maintenance for driver modules on a bare-metal aarch64 machine.
//!
//! The kernel decodes every request, checks it and keeps the caches, so each
//! op means one thing on every machine; a platform supplies only a
//! [`MetalDeviceOps`] table (`hal::metal_device`). Errors: a malformed
//! request is `EINVAL`, an address outside what the op may reach is
//! `EFAULT`, an exhausted DMA arena is `ENOMEM`, and an op the machine has
//! no hardware for is `ENOSYS` (the semantics text is
//! `modules/sdk/contracts/hal/metal_device.rs`).

use crate::abi::contracts::hal::metal_device as op;
use crate::kernel::sys::errno::{EFAULT, EINVAL, ENOMEM, ENOSYS};
use crate::kernel::sys::hal;

/// Which DMA memory an allocation draws from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DmaKind {
    /// Memory a device reaches coherently with no cache maintenance.
    Coherent,
    /// Cacheable memory the caller keeps coherent.
    Streaming,
}

/// The table-index PCI operations a machine with a scan-before-bind bus
/// serves (the Pi 5's brcmstb root complexes).
pub struct PciOps {
    /// Re-run enumeration; the device count found.
    pub rescan: fn() -> i32,
    /// Read a config word: arg=[dev_idx:u8, _pad:u8, offset:u16 LE], value
    /// written to arg[4..8].
    pub cfg_read32: unsafe fn(*mut u8, usize) -> i32,
    /// Write a config word: arg=[dev_idx:u8, _pad:u8, offset:u16 LE, value:u32 LE].
    pub cfg_write32: unsafe fn(*mut u8, usize) -> i32,
}

/// What a platform supplies for `metal_device`.
pub struct MetalDeviceOps {
    /// Whether `addr` is a device register a module may reach.
    pub mmio_ok: fn(u64) -> bool,
    /// Carve `size` bytes aligned to `align` (a power of two, at least 64)
    /// from the arena for `kind`; `None` when it is exhausted.
    pub dma_alloc: fn(DmaKind, usize, usize) -> Option<u64>,
    /// Whether `[addr, addr+size)` lies inside DMA memory this machine
    /// hands out.
    pub dma_range_ok: fn(u64, u32) -> bool,
    /// The scan-before-bind PCI operations, where the machine has them.
    pub pci: Option<&'static PciOps>,
}

/// The alignment the contract requires of an invalidate (no supported
/// machine has a data-cache line longer than this).
const LINE: u64 = 64;

/// Read `n` little-endian bytes at `at`.
///
/// # Safety
/// `arg` holds at least `at + n` readable bytes.
unsafe fn le(arg: *const u8, at: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..n {
        v |= u64::from(*arg.add(at + i)) << (8 * i);
    }
    v
}

/// Write `v` little-endian as `n` bytes at `at`.
///
/// # Safety
/// `arg` holds at least `at + n` writable bytes.
unsafe fn put(arg: *mut u8, at: usize, n: usize, v: u64) {
    for i in 0..n {
        *arg.add(at + i) = (v >> (8 * i)) as u8;
    }
}

#[derive(Clone, Copy)]
enum Maint {
    CleanInvalidate,
    Clean,
    Invalidate,
}

/// Run one maintenance instruction over every line of `[addr, addr+size)`.
fn maintain(addr: u64, size: u32, m: Maint) {
    #[cfg(target_arch = "aarch64")]
    {
        // Step by the smallest data-cache line the core reports, so no line
        // of the range is skipped.
        let ctr: u64;
        // SAFETY: reads an ID register.
        unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
        let step = 4u64 << ((ctr >> 16) & 0xF);
        let mut line = addr & !(step - 1);
        let end = addr + u64::from(size);
        while line < end {
            // SAFETY: the caller checked the range lies in DMA memory, which
            // is mapped; maintenance by VA neither reads nor writes it.
            unsafe {
                match m {
                    Maint::CleanInvalidate => {
                        core::arch::asm!("dc civac, {}", in(reg) line, options(nostack))
                    }
                    Maint::Clean => core::arch::asm!("dc cvac, {}", in(reg) line, options(nostack)),
                    Maint::Invalidate => {
                        core::arch::asm!("dc ivac, {}", in(reg) line, options(nostack))
                    }
                }
            }
            line += step;
        }
        // SAFETY: a barrier; completes the maintenance above.
        unsafe { core::arch::asm!("dsb sy", options(nostack)) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = (addr, size, m);
}

/// The `metal_device` provider.
///
/// # Safety
/// `arg` holds `arg_len` bytes owned by the caller for the call.
pub unsafe fn dispatch(_handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(ops) = hal::metal_device() else {
        return ENOSYS;
    };
    if arg.is_null() && !matches!(opcode, op::PCIE_RESCAN) {
        return EINVAL;
    }
    match opcode {
        op::MMIO_READ32 | op::MMIO_WRITE32 => {
            if arg_len < 12 {
                return EINVAL;
            }
            let addr = le(arg, 0, 8);
            if addr & 3 != 0 || !(ops.mmio_ok)(addr) {
                return EFAULT;
            }
            if opcode == op::MMIO_READ32 {
                put(
                    arg,
                    8,
                    4,
                    u64::from(core::ptr::read_volatile(addr as *const u32)),
                );
            } else {
                core::ptr::write_volatile(addr as *mut u32, le(arg, 8, 4) as u32);
            }
            0
        }
        op::DMA_ALLOC_CONTIG | op::DMA_ALLOC_STREAMING => {
            if arg_len < 16 {
                return EINVAL;
            }
            let (size, align) = (le(arg, 0, 4) as usize, le(arg, 4, 4) as usize);
            if size == 0 || !align.is_power_of_two() || (align as u64) < LINE {
                return EINVAL;
            }
            let kind = if opcode == op::DMA_ALLOC_CONTIG {
                DmaKind::Coherent
            } else {
                DmaKind::Streaming
            };
            match (ops.dma_alloc)(kind, size, align) {
                Some(addr) => {
                    put(arg, 8, 8, addr);
                    0
                }
                None => ENOMEM,
            }
        }
        op::CACHE_FLUSH_RANGE | op::DMA_FLUSH | op::DMA_INVALIDATE => {
            if arg_len < 12 {
                return EINVAL;
            }
            let (addr, size) = (le(arg, 0, 8), le(arg, 8, 4) as u32);
            if !(ops.dma_range_ok)(addr, size) {
                return EFAULT;
            }
            let m = match opcode {
                op::CACHE_FLUSH_RANGE => Maint::CleanInvalidate,
                op::DMA_FLUSH => Maint::Clean,
                _ => {
                    if addr % LINE != 0 || u64::from(size) % LINE != 0 {
                        return EINVAL;
                    }
                    Maint::Invalidate
                }
            };
            maintain(addr, size, m);
            0
        }
        op::PCIE_RESCAN => match ops.pci {
            Some(pci) => (pci.rescan)(),
            None => ENOSYS,
        },
        op::PCIE_CFG_READ32 | op::PCIE_CFG_WRITE32 => match ops.pci {
            Some(pci) if opcode == op::PCIE_CFG_READ32 => (pci.cfg_read32)(arg, arg_len),
            Some(pci) => (pci.cfg_write32)(arg, arg_len),
            None => ENOSYS,
        },
        _ => ENOSYS,
    }
}

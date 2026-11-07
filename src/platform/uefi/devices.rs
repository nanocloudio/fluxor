// What a driver module reaches through the system extension on this runtime:
// device registers, DMA memory, PCI by handle, MSI vectors and the paged arena.
//
// DMA memory is ordinary cacheable RAM carved from the zone, for both the
// contiguous and the streaming opcode. The machines this runtime targets (QEMU,
// Nitro) keep PCI I/O coherent with the CPU's caches and do not translate device
// addresses, so a buffer's CPU address is its device address. The cache
// maintenance opcodes do what they name all the same, for a driver that pairs
// them. They reach only the zone, where every address is mapped, and
// invalidation cleans as it invalidates (`DC CIVAC`), so no call can discard a
// dirty line.

use fluxor::abi::contracts::hal::pcie_device;
use fluxor::abi::contracts::storage::paged_arena;
use fluxor::abi::platform::bcm2712::mmio_dma;
use fluxor::arch::aarch64::{gic, mmio};
use fluxor::kernel::backing_store as backing;
use fluxor::kernel::sys::errno;

use super::{acpi, pci};

/// What the tables said that a driver's call depends on.
struct Facts {
    zone: (u64, u64),
    rid_maps: [(u32, u32, u32); acpi::MAX_RID_MAPS],
    rid_map_count: usize,
    v2m_base: u64,
    v2m_next_spi: u32,
    v2m_end_spi: u32,
}

static mut FACTS: Facts = Facts {
    zone: (0, 0),
    rid_maps: [(0, 0, 0); acpi::MAX_RID_MAPS],
    rid_map_count: 0,
    v2m_base: 0,
    v2m_next_spi: 0,
    v2m_end_spi: 0,
};

impl Facts {
    fn device_id(&self, rid: u32) -> u32 {
        acpi::device_id(&self.rid_maps[..self.rid_map_count], rid)
    }
}

fn facts() -> &'static mut Facts {
    // SAFETY: this runtime steps on one core; written once at boot before this.
    unsafe { &mut *core::ptr::addr_of_mut!(FACTS) }
}

pub fn configure(machine: &acpi::Machine, zone: (u64, u64)) {
    let f = facts();
    f.zone = zone;
    f.rid_maps = machine.rid_maps;
    f.rid_map_count = machine.rid_map_count;
    if machine.v2m_count != 0 {
        const V2M_TYPER: usize = 0x008;
        f.v2m_base = machine.v2m_base;
        // SAFETY: a frame the MADT described, mapped Device from boot.
        let typer = unsafe { mmio::read32(machine.v2m_base as usize + V2M_TYPER) };
        f.v2m_next_spi = (typer >> 16) & 0x3FF;
        f.v2m_end_spi = f.v2m_next_spi + (typer & 0x3FF);
    }
}

fn in_zone(addr: u64, size: u64) -> bool {
    let (lo, hi) = facts().zone;
    addr >= lo && addr.checked_add(size).is_some_and(|end| end <= hi)
}

/// A raw register access reaches devices only: a 4-byte-aligned word that
/// nothing in the firmware's memory map calls memory, and not the interrupt
/// controller's distributor window, which the kernel owns.
fn mmio_ok(addr: u64) -> bool {
    let gicd = gic::gicd_base() as u64;
    let in_gic = addr >= gicd && addr < gicd + 0x100_0000;
    addr & 3 == 0 && !super::is_ram(addr) && !in_gic
}

unsafe fn u32_at(arg: *const u8, at: usize) -> u32 {
    u32::from_le_bytes([
        *arg.add(at),
        *arg.add(at + 1),
        *arg.add(at + 2),
        *arg.add(at + 3),
    ])
}

unsafe fn u64_at(arg: *const u8, at: usize) -> u64 {
    u64::from(u32_at(arg, at)) | (u64::from(u32_at(arg, at + 4)) << 32)
}

unsafe fn dma_alloc(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 16 {
        return errno::EINVAL;
    }
    let (size, align) = (u32_at(arg, 0) as usize, u32_at(arg, 4).max(64) as usize);
    // An empty carve hands back no memory, only an address, which a device
    // must never be given.
    if size == 0 || !align.is_power_of_two() {
        return errno::EINVAL;
    }
    match fluxor::kernel::mem::carve::carve(size, align) {
        Some(ptr) => {
            let bytes = (ptr as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg.add(8), 8);
            0
        }
        None => errno::ENOMEM,
    }
}

/// Clean a DMA buffer to the point of coherency (`DC CVAC`), or clean and
/// invalidate it (`DC CIVAC`), by the smallest data-cache line `CTR_EL0`
/// reports.
unsafe fn dma_maintain(arg: *mut u8, arg_len: usize, invalidate: bool) -> i32 {
    if arg.is_null() || arg_len < 12 {
        return errno::EINVAL;
    }
    let (addr, size) = (u64_at(arg, 0), u32_at(arg, 8));
    if !in_zone(addr, u64::from(size)) {
        return errno::EFAULT;
    }
    let ctr: u64;
    core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack));
    let step = 4usize << ((ctr >> 16) & 0xF);
    let mut line = addr as usize & !(step - 1);
    let end = addr as usize + size as usize;
    while line < end {
        if invalidate {
            core::arch::asm!("dc civac, {}", in(reg) line, options(nostack));
        } else {
            core::arch::asm!("dc cvac, {}", in(reg) line, options(nostack));
        }
        line += step;
    }
    core::arch::asm!("dsb sy", options(nostack));
    0
}

/// The vector, the doorbell address and the payload, where `MSI_ALLOC` returns
/// them: `[vec u8, pad u8 x3, target u64, data u32]` at `arg[4..20]`.
unsafe fn write_msi(arg: *mut u8, vector: u32, target: u64, data: u32) {
    *arg.add(4) = (vector & 0xFF) as u8;
    *arg.add(5) = 0;
    *arg.add(6) = 0;
    *arg.add(7) = 0;
    core::ptr::copy_nonoverlapping(target.to_le_bytes().as_ptr(), arg.add(8), 8);
    core::ptr::copy_nonoverlapping(data.to_le_bytes().as_ptr(), arg.add(16), 4);
}

/// One MSI vector: a GICv2m frame turns a device's write into an SPI.
unsafe fn msi_alloc(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    const V2M_SETSPI: u64 = 0x040;
    if arg.is_null() || arg_len < 20 {
        return errno::EINVAL;
    }
    let event = u32_at(arg, 0) as i32;
    if let Some(rid) = pci::requester_id(handle) {
        let device_id = facts().device_id(rid);
        if let Some(result) = super::its::allocate(device_id, event) {
            return match result {
                Ok((target, data)) => {
                    write_msi(arg, data, target, data);
                    0
                }
                Err(why) => {
                    log::error!("[its] msi refused: {why}");
                    errno::ENOMEM
                }
            };
        }
    }
    let f = facts();
    if f.v2m_base == 0 {
        return errno::ENOSYS;
    }
    if f.v2m_next_spi >= f.v2m_end_spi {
        return errno::ENOMEM;
    }
    let spi = f.v2m_next_spi;
    // Edge first, then enabled: a v2m frame delivers each MSI as one pulse.
    gic::set_edge(spi);
    let rc = gic::irq_bind(spi, event, 0, 0);
    if rc != 0 {
        return rc;
    }
    f.v2m_next_spi += 1;
    write_msi(arg, spi, f.v2m_base + V2M_SETSPI, spi);
    0
}

unsafe fn arena(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    match opcode {
        paged_arena::ARENA_REGISTER if arg_len >= 10 => {
            let bt = match *arg.add(8) {
                0 => backing::BackingType::None,
                1 => backing::BackingType::RamDisk,
                2 => backing::BackingType::External,
                _ => return errno::EINVAL,
            };
            let wb = match *arg.add(9) {
                0 => backing::WritebackPolicy::Deferred,
                1 => backing::WritebackPolicy::WriteThrough,
                _ => return errno::EINVAL,
            };
            let module = fluxor::kernel::exec::scheduler::current_module_id();
            backing::backing_register(module, u32_at(arg, 0), u32_at(arg, 4), bt, wb)
        }
        paged_arena::ARENA_READ if arg_len >= 14 => {
            backing::backing_read(*arg as usize, u32_at(arg, 2), u64_at(arg, 6) as *mut u8)
        }
        paged_arena::ARENA_WRITE if arg_len >= 14 => {
            backing::backing_write(*arg as usize, u32_at(arg, 2), u64_at(arg, 6) as *const u8)
        }
        paged_arena::ARENA_FLUSH if arg_len >= 1 => backing::backing_flush(*arg as usize),
        paged_arena::ARENA_BULK if arg_len >= 18 => {
            let (id, vpage, count, buf) = (
                *arg as usize,
                u32_at(arg, 2),
                u32_at(arg, 6),
                u64_at(arg, 10),
            );
            match *arg.add(1) {
                paged_arena::ARENA_BULK_OP_WRITE => {
                    backing::backing_write_pages(id, vpage, count, buf as *const u8)
                }
                paged_arena::ARENA_BULK_OP_READ => {
                    backing::backing_read_pages(id, vpage, count, buf as *mut u8)
                }
                _ => errno::EINVAL,
            }
        }
        _ => errno::EINVAL,
    }
}

/// The system extension.
///
/// # Safety
/// The kernel's dispatch: `arg` holds `arg_len` bytes owned by the caller.
pub unsafe fn dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    match opcode {
        mmio_dma::MMIO_READ32 => {
            if arg.is_null() || arg_len < 12 {
                return errno::EINVAL;
            }
            if !mmio_ok(u64_at(arg, 0)) {
                return errno::EFAULT;
            }
            let value = mmio::read32(u64_at(arg, 0) as usize).to_le_bytes();
            core::ptr::copy_nonoverlapping(value.as_ptr(), arg.add(8), 4);
            0
        }
        mmio_dma::MMIO_WRITE32 => {
            if arg.is_null() || arg_len < 12 {
                return errno::EINVAL;
            }
            if !mmio_ok(u64_at(arg, 0)) {
                return errno::EFAULT;
            }
            mmio::write32(u64_at(arg, 0) as usize, u32_at(arg, 8));
            0
        }
        mmio_dma::DMA_ALLOC_CONTIG | mmio_dma::DMA_ALLOC_STREAMING => dma_alloc(arg, arg_len),
        mmio_dma::DMA_FLUSH => dma_maintain(arg, arg_len, false),
        mmio_dma::CACHE_FLUSH_RANGE | mmio_dma::DMA_INVALIDATE => dma_maintain(arg, arg_len, true),
        pcie_device::BIND => {
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            pci::bind(arg, arg_len)
        }
        pcie_device::CLOSE => pci::close(handle),
        pcie_device::CFG_READ32 => pci::cfg_read(handle, arg, arg_len),
        pcie_device::CFG_WRITE32 => pci::cfg_write(handle, arg, arg_len),
        pcie_device::BAR_MAP => pci::bar_map(handle, arg, arg_len),
        pcie_device::MSI_ALLOC => msi_alloc(handle, arg, arg_len),
        pcie_device::INFO => pci::info(handle, arg, arg_len),
        paged_arena::ARENA_REGISTER
        | paged_arena::ARENA_READ
        | paged_arena::ARENA_WRITE
        | paged_arena::ARENA_FLUSH
        | paged_arena::ARENA_BULK => {
            if arg.is_null() {
                return errno::EINVAL;
            }
            arena(opcode, arg, arg_len)
        }
        _ => errno::ENOSYS,
    }
}

// What a driver module reaches on this runtime: the `metal_device` table
// (device registers, DMA memory; the kernel decodes and keeps the caches),
// PCI by handle and MSI vectors.
//
// DMA memory is ordinary cacheable RAM carved from the zone, for both the
// coherent and the streaming kind. The machines this runtime targets (QEMU,
// Nitro) keep PCI I/O coherent with the CPU's caches and do not translate
// device addresses, so a buffer's CPU address is its device address.

use fluxor::abi::contracts::hal::pcie_device;
use fluxor::arch::aarch64::{gic, mmio};
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


/// The `metal_device` table: device registers outside RAM and the GIC, DMA
/// memory carved from the zone (one arena for both kinds: QEMU and Nitro keep
/// PCI I/O coherent with the caches), and no scan-before-bind PCI table.
pub static METAL_DEVICE: fluxor::kernel::module::metal_device::MetalDeviceOps =
    fluxor::kernel::module::metal_device::MetalDeviceOps {
        mmio_ok,
        dma_alloc,
        dma_range_ok: |addr, size| in_zone(addr, u64::from(size)),
        pci: None,
    };

fn dma_alloc(
    _kind: fluxor::kernel::module::metal_device::DmaKind,
    size: usize,
    align: usize,
) -> Option<u64> {
    fluxor::kernel::mem::carve::carve(size, align).map(|ptr| ptr as u64)
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

/// The system extension.
///
/// # Safety
/// The kernel's dispatch: `arg` holds `arg_len` bytes owned by the caller.
pub unsafe fn dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    match opcode {
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
        _ => errno::ENOSYS,
    }
}

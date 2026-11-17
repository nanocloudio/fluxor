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
    rid_maps: [(u32, u32, u32); acpi::MAX_RID_MAPS],
    rid_map_count: usize,
    v2m_base: u64,
    v2m_next_spi: u32,
    v2m_end_spi: u32,
}

static mut FACTS: Facts = Facts {
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

pub fn configure(machine: &acpi::Machine) {
    // QEMU virt's virtio-mmio transports: 32 from 0x0a00_0000, 0x200 apart,
    // transport `i` on SPI 16 + `i`.
    #[cfg(feature = "board-qemu-uefi")]
    gic::configure_virtio_mmio(gic::VirtioMmio {
        base: 0x0a00_0000,
        stride: 0x200,
        first_intid: 48,
        count: 32,
    });
    let f = facts();
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

/// The `metal_device` table: the devices' memory BARs as apertures, DMA
/// memory carved from the zone (one arena for both kinds: QEMU and Nitro keep
/// PCI I/O coherent with the caches), and no scan-before-bind PCI table.
pub static METAL_DEVICE: fluxor::kernel::module::metal_device::MetalDeviceOps =
    fluxor::kernel::module::metal_device::MetalDeviceOps {
        aperture: pci::aperture,
        dma_alloc,
        pci: None,
    };

fn dma_alloc(
    _kind: fluxor::kernel::module::metal_device::DmaKind,
    size: usize,
    align: usize,
) -> Option<u64> {
    fluxor::kernel::mem::carve::carve(size, align).map(|ptr| ptr as u64)
}

/// The index an MSI vector answers: [`VECTOR_BASE`] plus its slot in
/// [`VECTORS`], a band no device index shares.
const VECTOR_BASE: i32 = 0x1000;
/// MSI vectors held at once.
const MAX_VECTORS: usize = 16;

/// What an MSI vector raises: an LPI through the ITS, or a v2m frame's SPI.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Raises {
    Free,
    Lpi(u32),
    Spi(u32),
}

/// The vectors handed out, until the doorbell each rings is bound.
static mut VECTORS: [(Raises, bool); MAX_VECTORS] = [(Raises::Free, false); MAX_VECTORS];

fn vectors() -> &'static mut [(Raises, bool); MAX_VECTORS] {
    // SAFETY: this runtime steps on one core.
    unsafe { &mut *core::ptr::addr_of_mut!(VECTORS) }
}

/// Handles this runtime's platform tables hand out at once: bound devices and
/// MSI vectors.
pub fn handle_slots() -> usize {
    pci::HANDLE_SLOTS + MAX_VECTORS
}

/// The `MSI_ALLOC` answer (`pcie_device::msi`): the doorbell address and its
/// one-word window, the payload, the vector; and the vector's index.
fn answer_msi(arg: &mut [u8], raises: Raises, vector: u32, target: u64, data: u32) -> i32 {
    use pcie_device::msi;
    let Some(slot) = vectors().iter().position(|v| v.0 == Raises::Free) else {
        return errno::ENOMEM;
    };
    vectors()[slot] = (raises, false);
    let out = &mut arg[..msi::ARG_LEN];
    out.fill(0);
    out[msi::ADDR..msi::ADDR + 8].copy_from_slice(&target.to_le_bytes());
    out[msi::LEN..msi::LEN + 4].copy_from_slice(&4u32.to_le_bytes());
    out[msi::DATA..msi::DATA + 4].copy_from_slice(&data.to_le_bytes());
    out[msi::VEC] = (vector & 0xFF) as u8;
    VECTOR_BASE + slot as i32
}

/// One MSI vector: the ITS turns a device's write into an LPI, or a GICv2m
/// frame into an SPI. Its interrupt signals nothing until the kernel binds the
/// vector's doorbell ([`bind_doorbell`]).
fn msi_alloc(handle: i32, arg: &mut [u8]) -> i32 {
    const V2M_SETSPI: u64 = 0x040;
    if arg.len() < pcie_device::msi::ARG_LEN {
        return errno::EINVAL;
    }
    if let Some(rid) = pci::requester_id(handle) {
        let device_id = facts().device_id(rid);
        if let Some(result) = super::its::allocate(device_id) {
            return match result {
                Ok((target, data, lpi)) => answer_msi(arg, Raises::Lpi(lpi), data, target, data),
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
    let rc = answer_msi(arg, Raises::Spi(spi), spi, f.v2m_base + V2M_SETSPI, spi);
    if rc >= 0 {
        f.v2m_next_spi += 1;
    }
    rc
}

/// Bind the doorbell an MSI vector rings: its interrupt then signals it.
/// `EBADF` for an index that names no vector, or one already bound.
fn bind_doorbell(handle: i32, arg: &[u8]) -> i32 {
    let Some((doorbell, _)) = fluxor::abi::kernel_abi::doorbell::parse_bind(arg) else {
        return errno::EINVAL;
    };
    let Some(v) = handle
        .checked_sub(VECTOR_BASE)
        .and_then(|i| usize::try_from(i).ok())
        .and_then(|i| vectors().get_mut(i))
        .filter(|v| v.0 != Raises::Free && !v.1)
    else {
        return errno::EBADF;
    };
    let rc = match v.0 {
        Raises::Lpi(lpi) => gic::bind_lpi(lpi, doorbell as i32),
        Raises::Spi(spi) => {
            // Edge first, then enabled: a v2m frame delivers each MSI as one
            // pulse.
            // SAFETY: the GIC was configured at boot; `spi` is a v2m frame's
            // SPI, not yet bound.
            unsafe { gic::set_edge(spi) };
            gic::irq_bind(spi, doorbell as i32, fluxor::kernel::sys::hal::IrqAck::None, 0)
        }
        Raises::Free => errno::EBADF,
    };
    if rc == 0 {
        v.1 = true;
    }
    rc
}

/// The system extension.
pub fn dispatch(
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    _data: fluxor::kernel::module::user_span::UserSpan<'_>,
) -> i32 {
    match opcode {
        pcie_device::BIND => {
            if arg.is_empty() {
                return errno::EINVAL;
            }
            pci::bind(arg)
        }
        // A vector stays the device's: its interrupt is bound for good, and
        // a ring after its handle closed rings nothing.
        pcie_device::CLOSE if handle >= VECTOR_BASE => 0,
        pcie_device::CLOSE => pci::close(handle),
        pcie_device::CFG_READ32 => pci::cfg_read(handle, arg),
        pcie_device::CFG_WRITE32 => pci::cfg_write(handle, arg),
        pcie_device::BAR_MAP => pci::bar_map(handle, arg),
        pcie_device::MSI_ALLOC => msi_alloc(handle, arg),
        fluxor::abi::kernel_abi::doorbell::BIND_DOORBELL => bind_doorbell(handle, arg),
        pcie_device::INFO => pci::info(handle, arg),
        _ => errno::ENOSYS,
    }
}

//! The `metal_device` contract: device registers, DMA memory and cache
//! maintenance for driver modules on a bare-metal aarch64 machine.
//!
//! The kernel decodes every request, checks it and keeps the caches, so each
//! op means one thing on every machine; a platform supplies only a
//! [`MetalDeviceOps`] table (`hal::metal_device`). DMA memory is named by
//! the handle its allocation minted, device registers by an aperture handle
//! and an offset in it; the kernel keeps the allocations. A handle's index
//! (what this provider answers and is handed) is the allocation's slot, or
//! [`APERTURE_BASE`] plus the aperture's index.
//! Errors: a malformed request is `EINVAL`, a register or range outside what
//! the op may reach is `EFAULT`, a handle naming none of the caller's
//! allocations is `EBADF`, an exhausted DMA arena is `ENOMEM`, and an op the
//! machine has no hardware for is `ENOSYS` (the semantics text is
//! `crates/fluxor-abi/src/contracts/hal/metal_device.rs`).

use portable_atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use crate::abi::contracts::hal::metal_device as op;
use crate::kernel::exec::scheduler::{self, ModuleId};
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::sys::errno::{EBADF, EFAULT, EINVAL, ENOMEM, ENOSYS};
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
    pub cfg_read32: fn(&mut [u8]) -> i32,
    /// Write a config word: arg=[dev_idx:u8, _pad:u8, offset:u16 LE, value:u32 LE].
    pub cfg_write32: fn(&mut [u8]) -> i32,
}

/// What a platform supplies for `metal_device`.
pub struct MetalDeviceOps {
    /// The machine's device-register aperture `index`, `(base, len)`: the
    /// registers a module may reach (never DRAM, never the interrupt
    /// controller). `None` past the last.
    pub aperture: fn(u8) -> Option<(u64, u64)>,
    /// Carve `size` bytes aligned to `align` (a power of two, at least 64)
    /// from the arena for `kind`; `None` when it is exhausted.
    pub dma_alloc: fn(DmaKind, usize, usize) -> Option<u64>,
    /// The scan-before-bind PCI operations, where the machine has them.
    pub pci: Option<&'static PciOps>,
}

/// The index an aperture handle carries: [`APERTURE_BASE`] plus the
/// aperture's, above every allocation slot.
pub const APERTURE_BASE: i32 = 1 << 16;
const _: () = assert!(ALLOCS < APERTURE_BASE as usize);

/// The alignment the contract requires of an invalidate (no supported
/// machine has a data-cache line longer than this).
const LINE: u64 = 64;

/// Read `n` little-endian bytes at `at`; the caller checked `arg` holds them.
fn le(arg: &[u8], at: usize, n: usize) -> u64 {
    arg[at..at + n]
        .iter()
        .rev()
        .fold(0u64, |v, b| (v << 8) | u64::from(*b))
}

/// Write `v` little-endian as `n` bytes at `at`; the caller checked `arg`
/// holds them.
fn put(arg: &mut [u8], at: usize, n: usize, v: u64) {
    arg[at..at + n].copy_from_slice(&v.to_le_bytes()[..n]);
}

/// Most DMA allocations the machine's drivers hold at once: an NVMe
/// controller's queues and per-slot write pages, twice over, with room for a
/// NIC's rings. None on a machine without the contract.
const ALLOCS: usize = if cfg!(feature = "aarch64-metal") {
    512
} else {
    0
};

const FREE: u32 = 0;
const FILLING: u32 = 1;
const LIVE: u32 = 2;

/// One allocation a handle names. `state` publishes the rest: written while
/// `FILLING`, read only once `LIVE`, which it never leaves (the arenas are
/// carved, never returned).
struct Alloc {
    state: AtomicU32,
    addr: AtomicU64,
    len: AtomicU32,
    owner: AtomicU16,
}

static ALLOC: [Alloc; ALLOCS] = [const {
    Alloc {
        state: AtomicU32::new(FREE),
        addr: AtomicU64::new(0),
        len: AtomicU32::new(0),
        owner: AtomicU16::new(0),
    }
}; ALLOCS];

/// Carve an allocation for the calling module and record it: its handle, or
/// `ENOMEM` when the arena or the table is full. The slot is claimed first,
/// so a full table never strands arena memory.
fn allocate(
    ops: &MetalDeviceOps,
    kind: DmaKind,
    size: u32,
    align: usize,
) -> Result<(i32, u64), i32> {
    let slot = ALLOC
        .iter()
        .position(|a| {
            a.state
                .compare_exchange(FREE, FILLING, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        })
        .ok_or(ENOMEM)?;
    let a = &ALLOC[slot];
    let Some(addr) = (ops.dma_alloc)(kind, size as usize, align) else {
        a.state.store(FREE, Ordering::Release);
        return Err(ENOMEM);
    };
    a.addr.store(addr, Ordering::Relaxed);
    a.len.store(size, Ordering::Relaxed);
    a.owner
        .store(scheduler::current_module_id(), Ordering::Relaxed);
    a.state.store(LIVE, Ordering::Release);
    Ok((slot as i32, addr))
}

/// The address and length of the allocation `handle` names, when it names
/// one of the calling module's.
fn allocation(handle: i32) -> Option<(u64, u32)> {
    let a = ALLOC.get(usize::try_from(handle).ok()?)?;
    if a.state.load(Ordering::Acquire) != LIVE {
        return None;
    }
    let owner: ModuleId = a.owner.load(Ordering::Relaxed);
    (owner == scheduler::current_module_id()).then(|| {
        (
            a.addr.load(Ordering::Relaxed),
            a.len.load(Ordering::Relaxed),
        )
    })
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
            // SAFETY: the range lies inside one DMA allocation, which is
            // mapped; maintenance by VA neither reads nor writes it.
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
pub fn dispatch(handle: i32, opcode: u32, arg: &mut [u8], _data: UserSpan<'_>) -> i32 {
    let Some(ops) = hal::metal_device() else {
        return ENOSYS;
    };
    let arg_len = arg.len();
    match opcode {
        // In `[index u8]`, out `[base u64][len u32]`; the result is the
        // aperture's index, which the kernel wraps in a handle.
        op::MMIO_OPEN => {
            if arg_len < op::mmio::OPEN_LEN {
                return EINVAL;
            }
            let index = arg[0];
            let Some((base, len)) = (ops.aperture)(index) else {
                return crate::kernel::sys::errno::ENOENT;
            };
            let Ok(len) = u32::try_from(len) else {
                return crate::kernel::sys::errno::ERANGE;
            };
            put(arg, 0, 8, base);
            put(arg, 8, 4, u64::from(len));
            APERTURE_BASE + i32::from(index)
        }
        // `handle` = an aperture, arg `[offset u32][value u32]`.
        op::MMIO_READ32 | op::MMIO_WRITE32 => {
            if arg_len < op::mmio::ARG_LEN {
                return EINVAL;
            }
            let Some(index) = handle
                .checked_sub(APERTURE_BASE)
                .and_then(|i| u8::try_from(i).ok())
            else {
                return EBADF;
            };
            let Some((base, len)) = (ops.aperture)(index) else {
                return EBADF;
            };
            let offset = le(arg, 0, 4);
            if offset & 3 != 0 || offset + 4 > len {
                return EFAULT;
            }
            let addr = base + offset;
            if opcode == op::MMIO_READ32 {
                // SAFETY: an aligned word inside a device aperture the
                // platform vouched for and the kernel maps.
                let v = unsafe { core::ptr::read_volatile(addr as *const u32) };
                put(arg, 4, 4, u64::from(v));
            } else {
                // SAFETY: as the read.
                unsafe { core::ptr::write_volatile(addr as *mut u32, le(arg, 4, 4) as u32) };
            }
            0
        }
        // In `[size u32][align u32]`, out `[addr u64][len u32]`; the result
        // is the allocation's handle.
        op::DMA_ALLOC_CONTIG | op::DMA_ALLOC_STREAMING => {
            if arg_len < 12 {
                return EINVAL;
            }
            let (size, align) = (le(arg, 0, 4) as u32, le(arg, 4, 4) as usize);
            if size == 0 || !align.is_power_of_two() || (align as u64) < LINE {
                return EINVAL;
            }
            let kind = if opcode == op::DMA_ALLOC_CONTIG {
                DmaKind::Coherent
            } else {
                DmaKind::Streaming
            };
            match allocate(ops, kind, size, align) {
                Ok((h, addr)) => {
                    put(arg, 0, 8, addr);
                    put(arg, 8, 4, u64::from(size));
                    h
                }
                Err(e) => e,
            }
        }
        // `handle` = the allocation, arg `[offset u32][len u32]` within it.
        op::CACHE_FLUSH_RANGE | op::DMA_FLUSH | op::DMA_INVALIDATE => {
            if arg_len < 8 {
                return EINVAL;
            }
            let Some((base, total)) = allocation(handle) else {
                return EBADF;
            };
            let (offset, len) = (le(arg, 0, 4) as u32, le(arg, 4, 4) as u32);
            if offset.checked_add(len).is_none_or(|end| end > total) {
                return EFAULT;
            }
            let addr = base + u64::from(offset);
            let m = match opcode {
                op::CACHE_FLUSH_RANGE => Maint::CleanInvalidate,
                op::DMA_FLUSH => Maint::Clean,
                _ => {
                    if addr % LINE != 0 || u64::from(len) % LINE != 0 {
                        return EINVAL;
                    }
                    Maint::Invalidate
                }
            };
            maintain(addr, len, m);
            0
        }
        op::PCIE_RESCAN => match ops.pci {
            Some(pci) => (pci.rescan)(),
            None => ENOSYS,
        },
        op::PCIE_CFG_READ32 | op::PCIE_CFG_WRITE32 => match ops.pci {
            Some(pci) if opcode == op::PCIE_CFG_READ32 => (pci.cfg_read32)(arg),
            Some(pci) => (pci.cfg_write32)(arg),
            None => ENOSYS,
        },
        _ => ENOSYS,
    }
}

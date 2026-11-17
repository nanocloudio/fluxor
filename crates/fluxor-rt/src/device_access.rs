// ============================================================================
// Device access: DMA memory, cache maintenance and PCIe config/BAR helpers
// ============================================================================
//
// Thin SDK wrappers over the `metal_device` and `pcie_device` contracts.
// Consumed by storage/NIC drivers (NVMe, rp1_gem) via the flattened
// `runtime` namespace.
// Kept out of `telemetry.rs` — device access is not telemetry.

use crate::*;

/// One DMA allocation: the handle that names it to cache maintenance, and
/// where it lies (the CPU and the device see the same address).
#[derive(Clone, Copy)]
pub struct DmaRegion {
    pub handle: i32,
    pub addr: u64,
    pub len: u32,
}

/// Ask `metal_device` for an allocation: `op` is `DMA_ALLOC_CONTIG` or
/// `DMA_ALLOC_STREAMING`, answered `[addr u64][len u32]` and a handle.
#[inline(always)]
unsafe fn dma_alloc_op(sys: &SyscallTable, op: u32, size: u32, align: u32) -> Option<DmaRegion> {
    let mut arg = [0u8; 12];
    arg[0..4].copy_from_slice(&size.to_le_bytes());
    arg[4..8].copy_from_slice(&align.to_le_bytes());
    let handle = (sys.provider_call)(
        -1,
        op,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if handle < 0 {
        return None;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&arg[0..8]);
    let mut l = [0u8; 4];
    l.copy_from_slice(&arg[8..12]);
    Some(DmaRegion {
        handle,
        addr: u64::from_le_bytes(a),
        len: u32::from_le_bytes(l),
    })
}

/// Allocate `size` bytes of DMA memory a device reaches coherently, with
/// `align`-byte alignment (`metal_device::DMA_ALLOC_CONTIG`). `None` when the
/// arena is exhausted.
///
/// There is no matching free: the arena is bump-allocated.
#[inline(always)]
pub unsafe fn dev_dma_alloc(sys: &SyscallTable, size: u32, align: u32) -> Option<DmaRegion> {
    dma_alloc_op(
        sys,
        abi::registry::metal_device::DMA_ALLOC_CONTIG,
        size,
        align,
    )
}

/// Allocate `size` bytes of STREAMING (cacheable) DMA memory
/// (`metal_device::DMA_ALLOC_STREAMING`). `None` when the arena is
/// exhausted.
///
/// Streaming buffers must be paired with explicit cache maintenance at
/// handoff — see `dev_dma_flush` (before device-reads) and
/// `dev_dma_invalidate` (before CPU-reads of device-written regions).
#[inline(always)]
pub unsafe fn dev_dma_alloc_streaming(
    sys: &SyscallTable,
    size: u32,
    align: u32,
) -> Option<DmaRegion> {
    dma_alloc_op(
        sys,
        abi::registry::metal_device::DMA_ALLOC_STREAMING,
        size,
        align,
    )
}

/// Run one maintenance op over `[offset, offset + len)` of the allocation
/// `handle` names.
#[inline(always)]
unsafe fn dma_maint(sys: &SyscallTable, op: u32, handle: i32, offset: u32, len: u32) -> i32 {
    let mut arg = [0u8; 8];
    arg[0..4].copy_from_slice(&offset.to_le_bytes());
    arg[4..8].copy_from_slice(&len.to_le_bytes());
    (sys.provider_call)(
        handle,
        op,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    )
}

/// Clean `[offset, offset + len)` of a DMA allocation from the data cache
/// (`dc cvac` + `dsb sy`). Call after writing into a streaming DMA buffer
/// and before handing it to a device that will read it — ensures the device
/// sees the CPU's writes.
#[inline(always)]
pub unsafe fn dev_dma_flush(sys: &SyscallTable, handle: i32, offset: u32, len: u32) -> i32 {
    dma_maint(
        sys,
        abi::registry::metal_device::DMA_FLUSH,
        handle,
        offset,
        len,
    )
}

/// Invalidate `[offset, offset + len)` of a DMA allocation from the data
/// cache (`dc ivac` + `dsb sy`). Call before reading from a streaming DMA
/// buffer that a device has just written — drops any stale CPU cache lines
/// so the next load returns the device-written data. The range must be
/// 64-byte aligned.
#[inline(always)]
pub unsafe fn dev_dma_invalidate(sys: &SyscallTable, handle: i32, offset: u32, len: u32) -> i32 {
    dma_maint(
        sys,
        abi::registry::metal_device::DMA_INVALIDATE,
        handle,
        offset,
        len,
    )
}

/// PCIE_DEVICE contract: open a device by selector.
///
/// `selector` is a UTF-8 byte string — either a board-local alias
/// (e.g. `b"m2_primary"`) or a class match `b"@class=nvme"` that must
/// resolve to exactly one device. Returns the device handle on
/// success; on EAGAIN/ENODEV the caller should retry (the PCIe link
/// may still be training).
#[inline(always)]
pub unsafe fn dev_pcie_device_open(sys: &SyscallTable, selector: &[u8]) -> i32 {
    (sys.provider_open)(
        abi::registry::pcie_device::ID as u32,
        abi::contracts::hal::pcie_device::BIND,
        selector.as_ptr(),
        selector.len(),
    )
}

/// PCIE_DEVICE contract: read 32-bit config-space word for the bound
/// handle. Returns 0xFFFFFFFF on any failure (matches real-PCIe sentinel).
#[inline(always)]
pub unsafe fn dev_pcie_device_cfg_read32(sys: &SyscallTable, handle: i32, offset: u16) -> u32 {
    let mut buf = [0u8; 8];
    let bp = buf.as_mut_ptr();
    let ob = offset.to_le_bytes();
    *bp = ob[0];
    *bp.add(1) = ob[1];
    let rc = (sys.provider_call)(
        handle,
        abi::contracts::hal::pcie_device::CFG_READ32,
        bp,
        8,
        core::ptr::null_mut(),
        0,
    );
    if rc != 0 {
        return 0xFFFF_FFFF;
    }
    u32::from_le_bytes([*bp.add(4), *bp.add(5), *bp.add(6), *bp.add(7)])
}

/// PCIE_DEVICE contract: write 32-bit config-space word for the bound
/// handle. Returns 0 on success, negative errno otherwise.
#[inline(always)]
pub unsafe fn dev_pcie_device_cfg_write32(
    sys: &SyscallTable,
    handle: i32,
    offset: u16,
    val: u32,
) -> i32 {
    let mut buf = [0u8; 8];
    let bp = buf.as_mut_ptr();
    let ob = offset.to_le_bytes();
    *bp = ob[0];
    *bp.add(1) = ob[1];
    *bp.add(2) = 0;
    *bp.add(3) = 0;
    let vb = val.to_le_bytes();
    for (i, b) in vb.iter().enumerate() {
        *bp.add(4 + i) = *b;
    }
    (sys.provider_call)(
        handle,
        abi::contracts::hal::pcie_device::CFG_WRITE32,
        bp,
        8,
        core::ptr::null_mut(),
        0,
    )
}

/// PCIE_DEVICE contract: map BAR `bar_idx` for the bound handle: where it
/// lies and its length, or `None` on failure.
#[inline(always)]
pub unsafe fn dev_pcie_device_bar_map(
    sys: &SyscallTable,
    handle: i32,
    bar_idx: u8,
) -> Option<(u64, u32)> {
    let mut arg = [0u8; 12];
    arg[0] = bar_idx;
    let rc = (sys.provider_call)(
        handle,
        abi::contracts::hal::pcie_device::BAR_MAP,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return None;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&arg[0..8]);
    let mut l = [0u8; 4];
    l.copy_from_slice(&arg[8..12]);
    Some((u64::from_le_bytes(a), u32::from_le_bytes(l)))
}

/// PCIE_DEVICE contract: allocate an MSI-X vector on the bound device's
/// root complex. The kernel brings up the MSI controller lazily on first
/// call. Returns `Some((vector_handle, vector_idx, target_addr, data))`:
/// the handle polls `POLL_IN` once per interrupt (`dev_fd_poll`) and the
/// interrupt wakes the module.
#[inline(always)]
pub unsafe fn dev_pcie_device_msi_alloc(
    sys: &SyscallTable,
    handle: i32,
) -> Option<(i32, u8, u64, u32)> {
    use abi::contracts::hal::pcie_device::msi;
    let mut buf = [0u8; msi::ARG_LEN];
    let rc = (sys.provider_call)(
        handle,
        abi::contracts::hal::pcie_device::MSI_ALLOC,
        buf.as_mut_ptr(),
        buf.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return None;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[msi::ADDR..msi::ADDR + 8]);
    let mut d = [0u8; 4];
    d.copy_from_slice(&buf[msi::DATA..msi::DATA + 4]);
    Some((
        rc,
        buf[msi::VEC],
        u64::from_le_bytes(a),
        u32::from_le_bytes(d),
    ))
}

/// Read a 32-bit word from a discovered PCIe device's configuration
/// space via the global-op path. Used by `pcie_scan`'s diagnostic
/// enumerator; drivers that hold a PCIE_DEVICE handle should use
/// `dev_pcie_device_cfg_read32` instead.
///
/// `offset` is the byte offset within config space, 4-byte aligned
/// (low 2 bits ignored). Returns 0xFFFFFFFF when the device index
/// is out of range or the target function did not respond.
#[inline(always)]
pub unsafe fn dev_pcie_cfg_read32(sys: &SyscallTable, dev_idx: u8, offset: u16) -> u32 {
    let mut buf = [0u8; 8];
    let bp = buf.as_mut_ptr();
    *bp = dev_idx;
    *bp.add(1) = 0;
    let ob = offset.to_le_bytes();
    *bp.add(2) = ob[0];
    *bp.add(3) = ob[1];
    let rc = (sys.provider_call)(
        -1,
        abi::registry::metal_device::PCIE_CFG_READ32,
        bp,
        8,
        core::ptr::null_mut(),
        0,
    );
    if rc != 0 {
        return 0xFFFF_FFFF;
    }
    u32::from_le_bytes([*bp.add(4), *bp.add(5), *bp.add(6), *bp.add(7)])
}

/// Write a 32-bit value into a discovered device's PCI configuration
/// space. Returns 0 on success, negative errno on failure.
#[inline(always)]
pub unsafe fn dev_pcie_cfg_write32(sys: &SyscallTable, dev_idx: u8, offset: u16, val: u32) -> i32 {
    let mut buf = [0u8; 8];
    let bp = buf.as_mut_ptr();
    *bp = dev_idx;
    *bp.add(1) = 0;
    let ob = offset.to_le_bytes();
    *bp.add(2) = ob[0];
    *bp.add(3) = ob[1];
    let vb = val.to_le_bytes();
    *bp.add(4) = vb[0];
    *bp.add(5) = vb[1];
    *bp.add(6) = vb[2];
    *bp.add(7) = vb[3];
    (sys.provider_call)(
        -1,
        abi::registry::metal_device::PCIE_CFG_WRITE32,
        bp,
        8,
        core::ptr::null_mut(),
        0,
    )
}

/// The device window the graph granted this module (config tag 0xFD), as
/// `(base, size)`: the one peripheral block a gated driver may reach
/// directly. Read from the params blob `module_new` receives; `None` when
/// the graph granted none.
///
/// # Safety
/// `params` must be valid for reads of `len` bytes (or null).
#[inline(never)]
pub unsafe fn device_window(params: *const u8, len: usize) -> Option<(u64, u32)> {
    if params.is_null() || len < 4 || *params != 0xFE {
        return None;
    }
    let mut pos = 4;
    while pos + 2 <= len {
        let tag = *params.add(pos);
        let n = *params.add(pos + 1) as usize;
        pos += 2;
        if tag == 0xFF || pos + n > len {
            return None;
        }
        if tag == 0xFD && n == 12 {
            let mut base = 0u64;
            for i in (0..8).rev() {
                base = (base << 8) | *params.add(pos + i) as u64;
            }
            let mut size = 0u32;
            for i in (0..4).rev() {
                size = (size << 8) | *params.add(pos + 8 + i) as u32;
            }
            return Some((base, size));
        }
        pos += n;
    }
    None
}

/// Claim instance `instance` of a raw RP peripheral family
/// (`abi::platform::rp::raw_claim::family`) for this module: the handle every
/// raw op on that instance takes, or a negative errno (`EBUSY` when another
/// module holds it). Claiming an instance this module already holds returns
/// the same handle.
#[inline(always)]
pub unsafe fn dev_raw_claim(sys: &SyscallTable, family: u8, instance: u8) -> i32 {
    let mut arg = [family, instance];
    (sys.provider_call)(
        -1,
        abi::registry::rp_raw::CLAIM,
        arg.as_mut_ptr(),
        2,
        core::ptr::null_mut(),
        0,
    )
}

/// Where one part of a NIC ring lies (`platform_nic_ring::NIC_RING_INFO`,
/// an address answer): `(addr, len, count, size)` — the part's DMA address
/// and byte length, its entry count and entry size. `part` is one of
/// `abi::platform::bcm2712::nic_ring::info::{RX_DESC, TX_DESC, BUFFERS}`.
#[inline(always)]
pub unsafe fn dev_nic_ring_info(
    sys: &SyscallTable,
    ring: i32,
    part: u8,
) -> Option<(u64, u32, u16, u16)> {
    let mut arg = [0u8; abi::platform::bcm2712::nic_ring::info::LEN];
    arg[0] = part;
    let rc = (sys.provider_call)(
        ring,
        abi::registry::platform_nic_ring::NIC_RING_INFO,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return None;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&arg[0..8]);
    Some((
        u64::from_le_bytes(a),
        u32::from_le_bytes([arg[8], arg[9], arg[10], arg[11]]),
        u16::from_le_bytes([arg[12], arg[13]]),
        u16::from_le_bytes([arg[14], arg[15]]),
    ))
}

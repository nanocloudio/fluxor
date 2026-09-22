// ============================================================================
// Device access: DMA arena, PCIe config/BAR, and BCM2712 PCIe1 MSI helpers
// ============================================================================
//
// Thin SDK wrappers over the platform device-access opcodes (DMA arena,
// `pcie_device` contract, and the BCM2712 PCIe1 MSI controller). Consumed by
// storage/NIC drivers (NVMe, rp1_gem) via the flattened `runtime` namespace.
// Kept out of `telemetry.rs` — device access is not telemetry.

/// Allocate `size` bytes of DMA-coherent memory with `align`-byte alignment
/// from the kernel's non-cacheable DMA arena. Returns the physical address
/// (== virtual address under identity mapping) or 0 on failure.
///
/// Buffers returned here are Normal Non-cacheable memory — safe for device
/// DMA without explicit cache maintenance. See
/// `src/platform/bcm2712/net.rs` (the arena implementation) and
/// `src/platform/bcm2712.rs` `init_page_tables()` (MAIR attr2 = 0x44).
///
/// Bump-only for v1 — there is no matching `dev_dma_free`.
#[inline(always)]
unsafe fn dev_dma_alloc(sys: &SyscallTable, size: u32, align: u32) -> u64 {
    let mut buf = [0u8; 16];
    let bp = buf.as_mut_ptr();
    let sb = size.to_le_bytes();
    *bp = sb[0];
    *bp.add(1) = sb[1];
    *bp.add(2) = sb[2];
    *bp.add(3) = sb[3];
    let ab = align.to_le_bytes();
    *bp.add(4) = ab[0];
    *bp.add(5) = ab[1];
    *bp.add(6) = ab[2];
    *bp.add(7) = ab[3];
    let rc = (sys.provider_call)(-1, 0x0CE6, bp, 16);
    if rc != 0 {
        return 0;
    }
    u64::from_le_bytes([
        *bp.add(8),
        *bp.add(9),
        *bp.add(10),
        *bp.add(11),
        *bp.add(12),
        *bp.add(13),
        *bp.add(14),
        *bp.add(15),
    ])
}

/// Allocate `size` bytes of STREAMING (cacheable WB-WA) DMA memory from
/// the kernel's PCIe1 streaming arena. Returns the physical address (==
/// virtual under identity mapping) or 0 on failure.
///
/// Streaming buffers must be paired with explicit cache maintenance at
/// handoff — see `dev_dma_flush` (before device-reads) and
/// `dev_dma_invalidate` (before CPU-reads of device-written regions).
#[inline(always)]
unsafe fn dev_dma_alloc_streaming(sys: &SyscallTable, size: u32, align: u32) -> u64 {
    let mut buf = [0u8; 16];
    let bp = buf.as_mut_ptr();
    let sb = size.to_le_bytes();
    *bp = sb[0];
    *bp.add(1) = sb[1];
    *bp.add(2) = sb[2];
    *bp.add(3) = sb[3];
    let ab = align.to_le_bytes();
    *bp.add(4) = ab[0];
    *bp.add(5) = ab[1];
    *bp.add(6) = ab[2];
    *bp.add(7) = ab[3];
    let rc = (sys.provider_call)(-1, 0x0CEC, bp, 16);
    if rc != 0 {
        return 0;
    }
    u64::from_le_bytes([
        *bp.add(8),
        *bp.add(9),
        *bp.add(10),
        *bp.add(11),
        *bp.add(12),
        *bp.add(13),
        *bp.add(14),
        *bp.add(15),
    ])
}

/// Clean a VA range from the data cache (`dc cvac` + `dsb sy`). Call
/// after writing into a streaming DMA buffer and before handing it to
/// a device that will read it — ensures the device sees the CPU's writes.
#[inline(always)]
unsafe fn dev_dma_flush(sys: &SyscallTable, addr: u64, size: u32) -> i32 {
    let mut buf = [0u8; 12];
    let bp = buf.as_mut_ptr();
    let ab = addr.to_le_bytes();
    *bp = ab[0];
    *bp.add(1) = ab[1];
    *bp.add(2) = ab[2];
    *bp.add(3) = ab[3];
    *bp.add(4) = ab[4];
    *bp.add(5) = ab[5];
    *bp.add(6) = ab[6];
    *bp.add(7) = ab[7];
    let sb = size.to_le_bytes();
    *bp.add(8) = sb[0];
    *bp.add(9) = sb[1];
    *bp.add(10) = sb[2];
    *bp.add(11) = sb[3];
    (sys.provider_call)(-1, 0x0CEA, bp, 12)
}

/// Invalidate a VA range from the data cache (`dc ivac` + `dsb sy`).
/// Call before reading from a streaming DMA buffer that a device has
/// just written — drops any stale CPU cache lines so the next load
/// returns the device-written data.
#[inline(always)]
unsafe fn dev_dma_invalidate(sys: &SyscallTable, addr: u64, size: u32) -> i32 {
    let mut buf = [0u8; 12];
    let bp = buf.as_mut_ptr();
    let ab = addr.to_le_bytes();
    *bp = ab[0];
    *bp.add(1) = ab[1];
    *bp.add(2) = ab[2];
    *bp.add(3) = ab[3];
    *bp.add(4) = ab[4];
    *bp.add(5) = ab[5];
    *bp.add(6) = ab[6];
    *bp.add(7) = ab[7];
    let sb = size.to_le_bytes();
    *bp.add(8) = sb[0];
    *bp.add(9) = sb[1];
    *bp.add(10) = sb[2];
    *bp.add(11) = sb[3];
    (sys.provider_call)(-1, 0x0CEB, bp, 12)
}

/// PCIE_DEVICE contract: open a device by selector.
///
/// `selector` is a UTF-8 byte string — either a board-local alias
/// (e.g. `b"m2_primary"`) or a class match `b"@class=nvme"` that must
/// resolve to exactly one device. Returns the device handle on
/// success; on EAGAIN/ENODEV the caller should retry (the PCIe link
/// may still be training).
#[inline(always)]
unsafe fn dev_pcie_device_open(sys: &SyscallTable, selector: &[u8]) -> i32 {
    (sys.provider_open)(
        0x0012, // PCIE_DEVICE contract id
        abi::contracts::hal::pcie_device::BIND,
        selector.as_ptr(),
        selector.len(),
    )
}

/// PCIE_DEVICE contract: read 32-bit config-space word for the bound
/// handle. Returns 0xFFFFFFFF on any failure (matches real-PCIe sentinel).
#[inline(always)]
unsafe fn dev_pcie_device_cfg_read32(sys: &SyscallTable, handle: i32, offset: u16) -> u32 {
    let mut buf = [0u8; 8];
    let bp = buf.as_mut_ptr();
    let ob = offset.to_le_bytes();
    *bp = ob[0];
    *bp.add(1) = ob[1];
    let rc = (sys.provider_call)(handle, abi::contracts::hal::pcie_device::CFG_READ32, bp, 8);
    if rc != 0 {
        return 0xFFFF_FFFF;
    }
    u32::from_le_bytes([*bp.add(4), *bp.add(5), *bp.add(6), *bp.add(7)])
}

/// PCIE_DEVICE contract: write 32-bit config-space word for the bound
/// handle. Returns 0 on success, negative errno otherwise.
#[inline(always)]
unsafe fn dev_pcie_device_cfg_write32(
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
    (sys.provider_call)(handle, abi::contracts::hal::pcie_device::CFG_WRITE32, bp, 8)
}

/// PCIE_DEVICE contract: map BAR `bar_idx` for the bound handle,
/// returning the kernel-visible virt address (or 0 on failure).
#[inline(always)]
unsafe fn dev_pcie_device_bar_map(sys: &SyscallTable, handle: i32, bar_idx: u8) -> u64 {
    let mut buf = [0u8; 10];
    let bp = buf.as_mut_ptr();
    *bp = bar_idx;
    *bp.add(1) = 0;
    let rc = (sys.provider_call)(handle, abi::contracts::hal::pcie_device::BAR_MAP, bp, 10);
    if rc < 0 {
        return 0;
    }
    u64::from_le_bytes([
        *bp.add(2),
        *bp.add(3),
        *bp.add(4),
        *bp.add(5),
        *bp.add(6),
        *bp.add(7),
        *bp.add(8),
        *bp.add(9),
    ])
}

/// PCIE_DEVICE contract: allocate an MSI-X vector on the bound
/// device's root complex, routing fires to `event_handle`. The
/// kernel brings up the MSI controller lazily on first call.
/// Returns `Some((vector_idx, target_addr, data))` on success.
#[inline(always)]
unsafe fn dev_pcie_device_msi_alloc(
    sys: &SyscallTable,
    handle: i32,
    event_handle: i32,
) -> Option<(u8, u64, u32)> {
    let mut buf = [0u8; 20];
    let bp = buf.as_mut_ptr();
    let eb = event_handle.to_le_bytes();
    for (i, b) in eb.iter().enumerate() {
        *bp.add(i) = *b;
    }
    let rc = (sys.provider_call)(handle, abi::contracts::hal::pcie_device::MSI_ALLOC, bp, 20);
    if rc != 0 {
        return None;
    }
    let vec = *bp.add(4);
    let addr = u64::from_le_bytes([
        *bp.add(8),
        *bp.add(9),
        *bp.add(10),
        *bp.add(11),
        *bp.add(12),
        *bp.add(13),
        *bp.add(14),
        *bp.add(15),
    ]);
    let data = u32::from_le_bytes([*bp.add(16), *bp.add(17), *bp.add(18), *bp.add(19)]);
    Some((vec, addr, data))
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
unsafe fn dev_pcie_cfg_read32(sys: &SyscallTable, dev_idx: u8, offset: u16) -> u32 {
    let mut buf = [0u8; 8];
    let bp = buf.as_mut_ptr();
    *bp = dev_idx;
    *bp.add(1) = 0;
    let ob = offset.to_le_bytes();
    *bp.add(2) = ob[0];
    *bp.add(3) = ob[1];
    let rc = (sys.provider_call)(-1, 0x0CF6, bp, 8);
    if rc != 0 {
        return 0xFFFF_FFFF;
    }
    u32::from_le_bytes([*bp.add(4), *bp.add(5), *bp.add(6), *bp.add(7)])
}

/// Write a 32-bit value into a discovered device's PCI configuration
/// space. Returns 0 on success, negative errno on failure.
#[inline(always)]
unsafe fn dev_pcie_cfg_write32(sys: &SyscallTable, dev_idx: u8, offset: u16, val: u32) -> i32 {
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
    (sys.provider_call)(-1, 0x0CF7, bp, 8)
}

/// Initialise the brcmstb PCIe1 MSI controller behind GIC SPI
/// `spi_irq`. Idempotent. Returns 0 on success, negative errno otherwise.
#[inline(always)]
unsafe fn dev_pcie1_msi_init(sys: &SyscallTable, spi_irq: u32) -> i32 {
    let mut buf = spi_irq.to_le_bytes();
    (sys.provider_call)(
        -1,
        abi::platform::bcm2712::msi::PCIE1_MSI_INIT,
        buf.as_mut_ptr(),
        4,
    )
}

/// Allocate an MSI vector for `event_handle` and retrieve the
/// (target_addr, data) the caller writes into its MSI-X table entry.
/// Returns `Some((vector, target_addr, data))` on success.
#[inline(always)]
unsafe fn dev_pcie1_msi_alloc_vector(
    sys: &SyscallTable,
    event_handle: i32,
) -> Option<(u8, u64, u32)> {
    let mut buf = [0u8; 20];
    let bp = buf.as_mut_ptr();
    let eb = event_handle.to_le_bytes();
    *bp = eb[0];
    *bp.add(1) = eb[1];
    *bp.add(2) = eb[2];
    *bp.add(3) = eb[3];
    let rc = (sys.provider_call)(
        -1,
        abi::platform::bcm2712::msi::PCIE1_MSI_ALLOC_VECTOR,
        bp,
        20,
    );
    if rc != 0 {
        return None;
    }
    let vec = *bp.add(4);
    let addr = u64::from_le_bytes([
        *bp.add(8),
        *bp.add(9),
        *bp.add(10),
        *bp.add(11),
        *bp.add(12),
        *bp.add(13),
        *bp.add(14),
        *bp.add(15),
    ]);
    let data = u32::from_le_bytes([*bp.add(16), *bp.add(17), *bp.add(18), *bp.add(19)]);
    Some((vec, addr, data))
}

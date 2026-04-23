//! PCIe enumeration and BAR mapping for BCM2712 (CM5) — thin kernel bridge.
//!
//! The public enumeration path is the `pcie_scan` PIC module, which uses
//! MMIO_READ32/WRITE32 bridges. This file keeps a built-in fallback
//! implementation for boot-time flows that run before the module loads,
//! plus the syscall handler wrappers that delegate to whichever is
//! available.

#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

// ----------------------------------------------------------------------------
// PCIe controller addresses (BCM2712, Pi 5 / CM5)
// ----------------------------------------------------------------------------
//
// Source: mainline Linux `arch/arm64/boot/dts/broadcom/bcm2712.dtsi`
// (nodes `pcie1` at `pcie@114000` and `pcie2` at `pcie@120000`) plus the
// Pi 5 bare-metal notes in `docs/guides/pi5-bare-metal.md` (PCIe RC for
// RP1 at `0x10_0012_0000`).
//
// There are two usable PCIe controllers on BCM2712:
//   - PCIe2: the internal x4 link to RP1 (default in this codebase).
//   - PCIe1: the external x1 slot used by the CM5 NVMe HAT+ and friends.
//     Requires `pciex1` enabled in `config.txt` so VPU trains the link
//     and programs the outbound window before kernel handoff.
//
// The built-in fallback enumerator uses `ECAM_BASE = 0xFD50_0000` (a
// legacy routing the VPU still exposes). The PIC `pcie_scan` module
// uses the `BCM2712_PCIE2_*` values at `0x10_00**_0000`, which is
// where the Pi 5 SoC maps its PCIe controllers post-handoff.

/// BCM2712 PCIe2 (RP1) configuration-space base for the built-in
/// fallback enumerator.
#[cfg(feature = "board-cm5")]
const ECAM_BASE: usize = 0xFD50_0000;

#[cfg(not(feature = "board-cm5"))]
const ECAM_BASE: usize = 0;

/// BCM2712 PCIe2 (RP1) outbound MMIO window base.
#[cfg(feature = "board-cm5")]
const PCIE_MMIO_BASE: usize = 0x1F_0000_0000;

#[cfg(not(feature = "board-cm5"))]
const PCIE_MMIO_BASE: usize = 0x4000_0000;

/// BCM2712 PCIe2 (RP1, x4) controller base — matches mainline DTS node
/// `pcie@120000` under the soc `ranges = <0 0x10 0 0x80000000>` mapping,
/// and matches `PCIE_RC_BASE` in `bcm2712.rs`.
pub const BCM2712_PCIE2_RC_BASE: u64 = 0x10_0012_0000;

/// BCM2712 PCIe2 outbound MMIO window (RP1 BAR region after VPU
/// configuration; Linux remaps to `0x1f_0000_0000` post-handoff — the
/// bare-metal kernel inherits whichever mapping is live at entry).
pub const BCM2712_PCIE2_MMIO_BASE: u64 = 0x1C_0000_0000;

/// BCM2712 PCIe1 (external x1, NVMe HAT+) controller base — mainline DTS
/// node `pcie@114000`.
pub const BCM2712_PCIE1_RC_BASE: u64 = 0x10_0011_0000;

/// BCM2712 PCIe1 outbound MMIO window base. Verified on Pi 5 base
/// board (6.12 rpt kernel, 2026-04-16) via `dmesg | grep 1000110000`:
///   MEM 0x1b80000000..0x1bffffffff -> 0x0080000000   (mem0, ~2 GB)
///   MEM 0x1800000000..0x1b7fffffff -> 0x0400000000   (mem1, prefetch)
///
/// Effective range: `0x18_0000_0000..0x1B_FFFF_FFFF` (16 GB).
/// Must be covered by the MMU as device memory — see `bcm2712.rs`
/// `init_page_tables()` (L1 entries 96..111).
///
/// NOTE: this is NOT `0x1F`. `0x1F_0000_0000` is PCIe2/RP1's Linux
/// post-enumeration remapped window (see `docs/guides/pi5-bare-metal.md`
/// section on RP1 BAR remapping).
pub const BCM2712_PCIE1_MMIO_BASE: u64 = 0x18_0000_0000;

const MAX_SCAN_DEVS: usize = 32;
const MAX_BARS: usize = 6;
const MAX_BAR_MAPS: usize = 8;

// ============================================================================
// PCIe NIC type detection
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PcieNicType {
    Rp1Gem = 0,
    IntelE810 = 1,
    MellanoxCx5 = 2,
    Unknown = 0xFF,
}

// ============================================================================
// PcieDevice
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct PcieDevice {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u32,
    pub bars: [u64; MAX_BARS],
    pub bar_sizes: [u64; MAX_BARS],
    pub nic_type: PcieNicType,
}

impl PcieDevice {
    const fn empty() -> Self {
        Self {
            bus: 0,
            dev: 0,
            func: 0,
            vendor_id: 0,
            device_id: 0,
            class: 0,
            bars: [0; MAX_BARS],
            bar_sizes: [0; MAX_BARS],
            nic_type: PcieNicType::Unknown,
        }
    }

    fn identify_nic(&mut self) {
        self.nic_type = match (self.vendor_id, self.device_id) {
            (0x1de4, 0x0001) => PcieNicType::Rp1Gem,
            (0x8086, 0x1592) | (0x8086, 0x1593) => PcieNicType::IntelE810,
            (0x15B3, 0x1017) | (0x15B3, 0x1019) => PcieNicType::MellanoxCx5,
            _ => PcieNicType::Unknown,
        };
    }
}

// ============================================================================
// BAR map tracking
// ============================================================================

#[derive(Clone, Copy)]
struct BarMap {
    bdf: u16,
    bar_idx: u8,
    virt_addr: usize,
    size: usize,
    active: bool,
}

impl BarMap {
    const fn empty() -> Self {
        Self {
            bdf: 0,
            bar_idx: 0,
            virt_addr: 0,
            size: 0,
            active: false,
        }
    }
}

// ============================================================================
// Static state
// ============================================================================

static mut DEVICES: [PcieDevice; MAX_SCAN_DEVS] = [const { PcieDevice::empty() }; MAX_SCAN_DEVS];
static mut DEVICE_COUNT: usize = 0;
static mut BAR_MAPS: [BarMap; MAX_BAR_MAPS] = [const { BarMap::empty() }; MAX_BAR_MAPS];

// ============================================================================
// ECAM config space access
// ============================================================================

#[cfg(feature = "board-cm5")]
unsafe fn ecam_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let addr = ECAM_BASE
        + ((bus as usize) << 20)
        + ((dev as usize) << 15)
        + ((func as usize) << 12)
        + (offset as usize & 0xFFC);
    core::ptr::read_volatile(addr as *const u32)
}

#[cfg(feature = "board-cm5")]
unsafe fn ecam_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let addr = ECAM_BASE
        + ((bus as usize) << 20)
        + ((dev as usize) << 15)
        + ((func as usize) << 12)
        + (offset as usize & 0xFFC);
    core::ptr::write_volatile(addr as *mut u32, val);
}

// ============================================================================
// Enumerate
// ============================================================================

// ============================================================================
// Broadcom 2712 PCIe1 bring-up — indirect config access + outbound window
// ============================================================================
//
// BCM2712's PCIe root complex does NOT expose a flat ECAM. Config cycles for
// bus > 0 go through an INDEX/DATA pair in the RC register space (offsets
// 0x9000 / 0x8000, per Linux `drivers/pci/controller/pcie-brcmstb.c` and
// verified against the running rig under Linux, 2026-04-16).
//
// Bus 0 config (the RC root bridge itself) is accessible directly at the RC
// base. For bus 1+, write `(bus << 20) | (devfn << 12)` to EXT_CFG_INDEX,
// then read/write at EXT_CFG_DATA + (reg & 0xFFC).
//
// VPU (with `dtparam=pciex1` in config.txt) trains the link and sets
// MEM_WIN0_LO, but leaves the other outbound-window registers at 0. Our
// kernel finishes the job so CPU reads in the outbound range reach the
// downstream device BARs.

// ----------------------------------------------------------------------------
// BCM2712 reset-controller addresses (bare-metal CPU-visible).
// ----------------------------------------------------------------------------
// The PCIe1 RC registers decode only after the SATA/PCIe RESCAL block has been
// calibrated AND the bridge SW reset line (brcm,brcmstb-reset id=43) is
// deasserted. Linux's `brcm_pcie_probe` does both before the first RC read.
// Without this sequence on Pi 5 bare-metal, reads to 0x10_0011_0000 + offset
// trigger a bus error → CPU exception → reboot loop.
//
// Addresses derived from bcm2712.dtsi + ranges mapping (soc child base →
// CPU 0x10_0000_0000):
//   reset-controller@119500  → CPU 0x10_0011_9500  (brcm,bcm7216-rescal)
//   reset-controller@1504318 → CPU 0x10_0150_4318  (brcm,brcmstb-reset)
//
// For brcm,brcmstb-reset id=43: bank=id>>5=1, bit=id&0x1f=11. SW_INIT_SET
// at +0x18+0x00, SW_INIT_CLEAR at +0x18+0x04, STATUS at +0x18+0x08.

#[cfg(feature = "board-cm5")]
const RESCAL_BASE: u64 = 0x10_0011_9500;
#[cfg(feature = "board-cm5")]
const RESCAL_START: u64 = 0x00;
#[cfg(feature = "board-cm5")]
const RESCAL_STATUS: u64 = 0x08;

#[cfg(feature = "board-cm5")]
const BCM_RESET_BASE: u64 = 0x10_0150_4318;
#[cfg(feature = "board-cm5")]
const BCM_RESET_PCIE1_BANK_OFF: u64 = 0x18;
#[cfg(feature = "board-cm5")]
const BCM_RESET_PCIE1_BIT: u32 = 1 << 11;

#[cfg(feature = "board-cm5")]
mod brcm {
    pub const EXT_CFG_DATA: u64 = 0x8000;
    pub const EXT_CFG_INDEX: u64 = 0x9000;

    /// `PCIE_MISC_MISC_CTRL` — controller-wide behaviour bits. Linux's
    /// `brcm_pcie_setup` writes this early in probe; without SCB_ACCESS_EN
    /// the controller rejects configuration cycles from the CPU.
    pub const MISC_CTRL: u64 = 0x4008;
    pub const CTRL_SCB_ACCESS_EN: u32 = 1 << 12;
    pub const CTRL_CFG_READ_UR: u32 = 1 << 13;
    pub const CTRL_RCB_MPS_MODE: u32 = 1 << 10;
    pub const CTRL_RCB_64B_MODE: u32 = 1 << 7;
    /// MAX_BURST_SIZE field [21:20]: 0=128B, 1=256B, 2=512B.
    pub const CTRL_MAX_BURST_512: u32 = 0x2 << 20;
    pub const CTRL_MAX_BURST_MASK: u32 = 0x3 << 20;

    pub const MEM_WIN0_LO: u64 = 0x400c;
    pub const MEM_WIN0_HI: u64 = 0x4010;
    pub const MEM_WIN0_BASE_LIMIT: u64 = 0x4070;
    pub const MEM_WIN0_BASE_HI: u64 = 0x4080;
    pub const MEM_WIN0_LIMIT_HI: u64 = 0x4084;

    /// RC link-up status register. Bit 4 = PHYLINKUP, bit 5 = DL_ACTIVE.
    /// Both must be set for the link to be usable.
    pub const MISC_PCIE_STATUS: u64 = 0x4068;
    pub const STATUS_PHYLINKUP: u32 = 1 << 4;
    pub const STATUS_DL_ACTIVE: u32 = 1 << 5;

    /// Control register. Bit 2 = PCIE_PERSTB (active-high: 1 = PERST#
    /// deasserted / card out of reset). VPU on Pi 5 leaves this clear
    /// for non-Linux kernel handoff — matching brcm_pcie_perst_set_2712,
    /// we set it to release the downstream device.
    pub const MISC_PCIE_CTRL: u64 = 0x4064;
    pub const CTRL_PERSTB: u32 = 1 << 2;

    /// PCIe1 outbound window: CPU 0x1B_8000_0000..0x1B_FFFF_FFFF (2 GB)
    /// maps to PCI bus addresses 0x8000_0000..0xFFFF_FFFF. Matches what
    /// Linux's brcm-pcie driver programs when `dtparam=pciex1` is active.
    pub const PCIE1_OUTBOUND_CPU_BASE: u64 = 0x1B_8000_0000;
    pub const PCIE1_OUTBOUND_CPU_LIMIT: u64 = 0x1B_FFFF_FFFF;
    pub const PCIE1_OUTBOUND_PCI_BASE: u64 = 0x0000_0000_8000_0000;

    // Stage-4 (brcm_pcie_setup / post_setup / start_link) registers.
    pub const HARD_DEBUG: u64 = 0x4304;
    pub const HARD_DEBUG_SERDES_IDDQ: u32 = 1 << 21;
    pub const HARD_DEBUG_CLKREQ_MASK: u32 = (1 << 1) | (1 << 16) | (1 << 20) | (1 << 21);

    pub const RC_CFG_RETRY_TIMEOUT: u64 = 0x405c;
    pub const PL_PHY_CTL_15: u64 = 0x184c;
    pub const AXI_INTF_CTRL: u64 = 0x416c;
    pub const AXI_READ_ERR_DATA: u64 = 0x4170;
    pub const UBUS_CTRL: u64 = 0x40a4;
    pub const UBUS_TIMEOUT: u64 = 0x40a8;

    pub const RC_BAR1_CONFIG_LO: u64 = 0x402c;
    pub const RC_BAR1_CONFIG_HI: u64 = 0x4030;
    pub const RC_BAR2_CONFIG_LO: u64 = 0x4034;
    pub const RC_BAR2_CONFIG_HI: u64 = 0x4038;
    /// Per-BAR UBUS REMAP registers. REMAP_LO bit 0 = ACCESS_EN,
    /// bits[31:12] = cpu_addr[31:12] (fabric). REMAP_HI = cpu_addr high
    /// bits. When ACCESS_EN is set the REMAP value overrides the
    /// cpu_addr that RC_BAR(i)_CONFIG otherwise supplies. This is the
    /// actual DMA-target register on BCM7712 (see upstream
    /// `set_inbound_win_registers` + BCM7712 branch in pcie-brcmstb.c).
    pub const UBUS_BAR1_REMAP_LO: u64 = 0x40ac;
    pub const UBUS_BAR1_REMAP_HI: u64 = 0x40b0;
    pub const UBUS_BAR2_REMAP_LO: u64 = 0x40b4;
    pub const UBUS_BAR2_REMAP_HI: u64 = 0x40b8;
    pub const UBUS_REMAP_ACCESS_EN: u32 = 1 << 0;

    // MDIO indirect register-access protocol (brcm_pcie_mdio_write).
    pub const MDIO_ADDR: u64 = 0x1100;
    pub const MDIO_WR_DATA: u64 = 0x1104;
    pub const MDIO_DATA_DONE: u32 = 1 << 31;
    pub const MDIO_SET_ADDR_OFFSET: u8 = 0x1f;

    // --- brcmstb MSI controller (Linux pcie-brcmstb.c v6.12) ---
    //
    // RC-internal registers. A PCIe endpoint write posted to
    // `MSI_TARGET_ADDR` is intercepted by the RC MSI mux, decoded via
    // the match pattern in MSI_DATA_CONFIG, and raised as a single
    // GIC SPI. The low 5 bits of the incoming data select the vector.
    //
    // On BCM7712 (Pi 5) the MSI block lives at MSI_INTR2_BASE (0x4500)
    // with 32 vectors; the legacy INTR2_CPU path is for older silicon
    // and is not supported here.
    pub const MSI_BAR_CONFIG_LO: u64 = 0x4044;
    pub const MSI_BAR_CONFIG_HI: u64 = 0x4048;
    pub const MSI_DATA_CONFIG: u64 = 0x404c;
    /// Match-mask (top 16) | match-value (bottom 16).
    pub const MSI_DATA_CONFIG_VAL_32: u32 = 0xffe0_6540;
    /// Bit 0 of MSI_BAR_CONFIG_LO doubles as the MSI-Enable bit.
    pub const MSI_BAR_ENABLE: u32 = 0x1;
    /// RC-internal address the endpoint posts MSI writes to (the RC
    /// intercepts and never forwards to DRAM).
    pub const MSI_TARGET_ADDR: u64 = 0x0_FFFF_FFFC;

    /// Offsets inside the MSI intr block: STATUS, CLR, MASK_SET/CLR.
    pub const MSI_INTR2_BASE: u64 = 0x4500;
    pub const MSI_INT_STATUS: u64 = 0x0;
    pub const MSI_INT_CLR: u64 = 0x8;
    pub const MSI_INT_MASK_SET: u64 = 0x10;
    pub const MSI_INT_MASK_CLR: u64 = 0x14;

    pub const MSI_VECTOR_COUNT: u32 = 32;
    pub const MSI_MASK_ALL: u32 = 0xFFFF_FFFF;

    /// PCIe HW revision register; refuse MSI bring-up below rev 3.3.
    pub const MISC_REVISION: u64 = 0x406c;
    pub const HW_REV_33: u32 = 0x0303;
}

/// Post-probe target values captured on the rig under Linux
/// (nvme_trace/baseline/pcie1_rc_post_probe.txt). Stage-4 writes
/// these verbatim so the Fluxor state converges on `brcm_pcie_probe`.
#[cfg(feature = "board-cm5")]
mod post_probe {
    pub const MISC_CTRL: u32 = 0x00263480;
    pub const RC_CFG_RETRY: u32 = 0x0ABA0000;
    pub const PL_PHY_CTL_15: u32 = 0x4DBC0012;
    pub const AXI_INTF_CTRL: u32 = 0x0000004F;
    pub const AXI_READ_ERR_DATA: u32 = 0xFFFFFFFF;
    pub const UBUS_CTRL: u32 = 0x00082000;
    pub const UBUS_TIMEOUT: u32 = 0x0B2D0000;
    pub const RC_BAR1_LO: u32 = 0x00000015;
    pub const RC_BAR1_HI: u32 = 0x00000010;
    pub const RC_BAR2_LO: u32 = 0xFFFFF01C;
    pub const RC_BAR2_HI: u32 = 0x000000FF;
    pub const UBUS_BAR2_REMAP_LO: u32 = 0x00131001;
    pub const UBUS_BAR2_REMAP_HI: u32 = 0x00000010;
}

#[cfg(feature = "board-cm5")]
unsafe fn rc_r32(rc: u64, off: u64) -> u32 {
    core::ptr::read_volatile((rc + off) as *const u32)
}

#[cfg(feature = "board-cm5")]
unsafe fn rc_w32(rc: u64, off: u64, val: u32) {
    core::ptr::write_volatile((rc + off) as *mut u32, val);
}

/// Program the EXT_CFG_INDEX for the target BDF, then return the CPU
/// virtual address to access the requested `reg` via EXT_CFG_DATA.
/// Bus 0 is the RC root bridge, accessed directly.
#[cfg(feature = "board-cm5")]
unsafe fn cfg_r32(rc: u64, bus: u8, dev: u8, func: u8, reg: u16) -> u32 {
    if bus == 0 {
        return rc_r32(rc, (reg & 0xFFC) as u64);
    }
    let devfn = ((dev as u32) << 3) | (func as u32 & 0x7);
    let idx = ((bus as u32) << 20) | (devfn << 12);
    rc_w32(rc, brcm::EXT_CFG_INDEX, idx);
    core::arch::asm!("dsb sy", options(nostack));
    rc_r32(rc, brcm::EXT_CFG_DATA + (reg & 0xFFC) as u64)
}

#[cfg(feature = "board-cm5")]
unsafe fn cfg_w32(rc: u64, bus: u8, dev: u8, func: u8, reg: u16, val: u32) {
    if bus == 0 {
        rc_w32(rc, (reg & 0xFFC) as u64, val);
        return;
    }
    let devfn = ((dev as u32) << 3) | (func as u32 & 0x7);
    let idx = ((bus as u32) << 20) | (devfn << 12);
    rc_w32(rc, brcm::EXT_CFG_INDEX, idx);
    core::arch::asm!("dsb sy", options(nostack));
    rc_w32(rc, brcm::EXT_CFG_DATA + (reg & 0xFFC) as u64, val);
}

/// Finish the PCIe1 outbound window programming that VPU started. After
/// this runs, CPU reads in `PCIE1_OUTBOUND_CPU_BASE..PCIE1_OUTBOUND_CPU_LIMIT`
/// reach PCI bus addresses `PCIE1_OUTBOUND_PCI_BASE..`.
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_program_outbound() {
    let rc = BCM2712_PCIE1_RC_BASE;

    // MEM_WIN0_LO/HI: PCI-side base address (low/high 32).
    rc_w32(rc, brcm::MEM_WIN0_LO, brcm::PCIE1_OUTBOUND_PCI_BASE as u32);
    rc_w32(
        rc,
        brcm::MEM_WIN0_HI,
        (brcm::PCIE1_OUTBOUND_PCI_BASE >> 32) as u32,
    );

    // BASE_LIMIT: CPU-side base+limit in 1 MB units. Bits [15:4] = base_mb,
    // bits [31:20] = limit_mb (both mask to 12 bits — the high bits go into
    // BASE_HI / LIMIT_HI).
    let base_mb = (brcm::PCIE1_OUTBOUND_CPU_BASE >> 20) as u32;
    let limit_mb = (brcm::PCIE1_OUTBOUND_CPU_LIMIT >> 20) as u32;
    let base_limit = ((base_mb & 0xFFF) << 4) | ((limit_mb & 0xFFF) << 20);
    rc_w32(rc, brcm::MEM_WIN0_BASE_LIMIT, base_limit);
    rc_w32(rc, brcm::MEM_WIN0_BASE_HI, (base_mb >> 12) as u32);
    rc_w32(rc, brcm::MEM_WIN0_LIMIT_HI, (limit_mb >> 12) as u32);
}

/// Probe BAR0 size using the standard PCI write-ones / read-back
/// trick. Leaves the BAR contents restored on return.
///
/// Returns (is_mem, is_64bit, size_bytes). `size_bytes == 0` means
/// the BAR is unimplemented or wasn't probeable.
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_probe_bar0(rc: u64, bus: u8, dev: u8) -> (bool, bool, u64) {
    let original_lo = cfg_r32(rc, bus, dev, 0, 0x10);
    if original_lo == 0xFFFF_FFFF || original_lo == 0 {
        return (false, false, 0);
    }
    let is_mem = (original_lo & 1) == 0;
    if !is_mem {
        // I/O BARs: we don't use them on this platform.
        return (false, false, 0);
    }
    let is_64b = ((original_lo >> 1) & 3) == 2;

    // Write all-ones; for 64-bit BARs do both halves before reading
    // back so the probe doesn't race hardware aliasing.
    let original_hi = if is_64b {
        cfg_r32(rc, bus, dev, 0, 0x14)
    } else {
        0
    };
    cfg_w32(rc, bus, dev, 0, 0x10, 0xFFFF_FFFF);
    if is_64b {
        cfg_w32(rc, bus, dev, 0, 0x14, 0xFFFF_FFFF);
    }
    let probe_lo = cfg_r32(rc, bus, dev, 0, 0x10);
    let probe_hi = if is_64b {
        cfg_r32(rc, bus, dev, 0, 0x14)
    } else {
        0
    };

    // Restore original BAR contents so we leave the device in its
    // pre-probe state; the caller will rewrite with the chosen
    // outbound address.
    cfg_w32(rc, bus, dev, 0, 0x10, original_lo);
    if is_64b {
        cfg_w32(rc, bus, dev, 0, 0x14, original_hi);
    }

    // Size: mask off the low 4 flag bits, invert, +1.
    let size_mask_lo = (probe_lo & 0xFFFF_FFF0) as u64;
    let size_mask = if is_64b {
        size_mask_lo | ((probe_hi as u64) << 32)
    } else {
        size_mask_lo | 0xFFFF_FFFF_0000_0000u64
    };
    if size_mask == 0xFFFF_FFFF_FFFF_FFF0u64 {
        // No bits cleared → BAR not fully decoded by the device.
        return (true, is_64b, 0);
    }
    let size = (!size_mask).wrapping_add(1);
    (true, is_64b, size)
}

/// Scan bus 1 for downstream devices via indirect config access. For
/// each valid device, probe BAR0 to learn its size, assign a slot in
/// the outbound window (naturally-aligned to the BAR size), and
/// enable MEM + BusMaster.
///
/// Assignment strategy: cursor starts at
/// `PCIE1_OUTBOUND_PCI_BASE + 0x20000` (the slack Linux leaves between
/// the RC and downstream BARs), advancing by each BAR's size rounded
/// up to its natural alignment. Capped at
/// `PCIE1_OUTBOUND_PCI_LIMIT`; devices past that are logged but not
/// registered.
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_enumerate_bus1() {
    let rc = BCM2712_PCIE1_RC_BASE;

    // Outbound window is 2 GB wide on CM5 (CPU_LIMIT - CPU_BASE + 1).
    // Reserve a small slack at the start to match Linux's layout and
    // so the RC's own internal region isn't overlapped.
    let window_size = brcm::PCIE1_OUTBOUND_CPU_LIMIT - brcm::PCIE1_OUTBOUND_CPU_BASE + 1;
    let mut cursor = brcm::PCIE1_OUTBOUND_PCI_BASE + 0x20000;
    let limit = brcm::PCIE1_OUTBOUND_PCI_BASE + window_size;

    let mut dev_num = 0u8;
    while dev_num < 32 {
        let id = cfg_r32(rc, 1, dev_num, 0, 0x00);
        let vendor_id = (id & 0xFFFF) as u16;
        // 0xFFFF / 0x0000 both mean "no responder": Type-0 config reads
        // for a missing function return all-ones; the RC also maps
        // completion aborts to zero on some implementations.
        if vendor_id == 0xFFFF || vendor_id == 0 {
            dev_num += 1;
            continue;
        }

        let device_id = ((id >> 16) & 0xFFFF) as u16;
        let class_rev = cfg_r32(rc, 1, dev_num, 0, 0x08);
        let header_type = ((cfg_r32(rc, 1, dev_num, 0, 0x0C) >> 16) & 0x7F) as u8;

        let mut pdev = PcieDevice::empty();
        pdev.bus = 1;
        pdev.dev = dev_num;
        pdev.vendor_id = vendor_id;
        pdev.device_id = device_id;
        pdev.class = class_rev >> 8;

        // Disable MEM + BusMaster while we rewrite BAR0.
        let cmd_before = cfg_r32(rc, 1, dev_num, 0, 0x04);
        cfg_w32(rc, 1, dev_num, 0, 0x04, cmd_before & !0x0006);

        // Type-1 (PCI-to-PCI bridges) don't have device BARs we need
        // to program; skip the BAR assignment but still record the
        // device so downstream tools can see it.
        if header_type != 0 {
            log::info!(
                "[pcie1] bus1 dev{} vid={:04x} did={:04x} (bridge, htype={})",
                dev_num,
                vendor_id,
                device_id,
                header_type
            );
            cfg_w32(rc, 1, dev_num, 0, 0x04, cmd_before | 0x0006);
            pdev.identify_nic();
            record_device(pdev);
            dev_num += 1;
            continue;
        }

        let (is_mem, is_64b, size) = pcie1_probe_bar0(rc, 1, dev_num);

        if is_mem && size > 0 {
            // Align cursor up to a multiple of `size`. PCI BARs must
            // be naturally aligned; for power-of-two sizes that's
            // just `(cursor + size - 1) & !(size - 1)`.
            let aligned = (cursor + size - 1) & !(size - 1);
            if aligned + size > limit {
                log::warn!(
                    "[pcie1] bus1 dev{} BAR0 size={:#x} exceeds outbound window",
                    dev_num,
                    size
                );
            } else {
                let bar_lo_flags = cfg_r32(rc, 1, dev_num, 0, 0x10) & 0xF;
                let low = ((aligned & 0xFFFF_FFF0) as u32) | bar_lo_flags;
                cfg_w32(rc, 1, dev_num, 0, 0x10, low);
                if is_64b {
                    cfg_w32(rc, 1, dev_num, 0, 0x14, (aligned >> 32) as u32);
                }
                pdev.bars[0] =
                    brcm::PCIE1_OUTBOUND_CPU_BASE + (aligned - brcm::PCIE1_OUTBOUND_PCI_BASE);
                pdev.bar_sizes[0] = size;
                cursor = aligned + size;
            }
        }

        // Re-enable MEM + BusMaster.
        cfg_w32(rc, 1, dev_num, 0, 0x04, cmd_before | 0x0006);

        log::info!(
            "[pcie1] bus1 dev{} vid={:04x} did={:04x} bar0_cpu={:#x} size={:#x}",
            dev_num,
            vendor_id,
            device_id,
            pdev.bars[0],
            pdev.bar_sizes[0]
        );

        pdev.identify_nic();
        record_device(pdev);

        dev_num += 1;
    }
}

/// Append `pdev` to the global DEVICES table if there's room.
/// Uses raw pointer writes so each call site avoids tripping the
/// Rust 2024 static_mut_refs lint individually.
#[cfg(feature = "board-cm5")]
unsafe fn record_device(pdev: PcieDevice) {
    let count = *core::ptr::addr_of!(DEVICE_COUNT);
    if count >= MAX_SCAN_DEVS {
        return;
    }
    let slot = core::ptr::addr_of_mut!(DEVICES) as *mut PcieDevice;
    core::ptr::write(slot.add(count), pdev);
    core::ptr::write(core::ptr::addr_of_mut!(DEVICE_COUNT), count + 1);
}

/// Program the PCIe bridge secondary/subordinate bus numbers AND the
/// Type-1 MEM base/limit window in the RC's own config space. Without
/// the latter, the bridge silently drops memory cycles that came
/// through our outbound window — the downstream device is never hit
/// and the CPU reads back 0xFFFFFFFF.
///
/// PCI CFG offset 0x18: [31:24] SEC_LAT | [23:16] SUB | [15:8] SEC | [7:0] PRI.
/// PCI CFG offset 0x20 (MEM_BASE/LIMIT): [15:4] base[31:20], [31:20] limit[31:20].
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_program_bus_numbers() {
    let rc = BCM2712_PCIE1_RC_BASE;
    let cur = rc_r32(rc, 0x18);
    let new = (cur & 0xFF00_0000) | 0x0001_0100;
    rc_w32(rc, 0x18, new);

    // Forward memory cycles for PCI 0x80000000..0x800FFFFF (1 MB), which
    // covers our NVMe device's BAR0 at 0x80020000. Matches Linux
    // post-probe (0x80008000). Without this the bridge rejects all
    // downstream MEM cycles and CPU reads return 0xFFFFFFFF.
    rc_w32(rc, 0x20, 0x8000_8000);

    // Enable MEM + Bus Master in the bridge's own CMD register. Without
    // this the bridge's inbound cycles are allowed but outbound
    // forwarding stays disabled.
    let rc_cmd = rc_r32(rc, 0x04);
    rc_w32(rc, 0x04, rc_cmd | 0x0006);
}

/// Wait up to `max_ms` (polled against the ARM generic timer via the
/// cycle counter) for both PHYLINKUP and DL_ACTIVE to come up. VPU on
/// Pi 5 with `dtparam=pciex1` does *partial* link bring-up; Linux's
/// `brcm_pcie_start_link` waits ~100 ms for the link-up bits before
/// walking the bus. We do the same.
///
/// Returns the last observed status register value.
/// Busy-wait for the PCIe1 link to train. Uses the ARM generic timer
/// `CNTPCT_EL0` counter instead of `now_millis()` because this runs
/// before IRQs are enabled (the HAL `now_millis` is IRQ-driven).
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_wait_link_up(max_ms: u64) -> u32 {
    let rc = BCM2712_PCIE1_RC_BASE;
    let want = brcm::STATUS_PHYLINKUP | brcm::STATUS_DL_ACTIVE;

    let freq = timer_freq_hz();
    let start = read_cntpct();
    let budget = (max_ms * freq) / 1000;

    loop {
        let status = rc_r32(rc, brcm::MISC_PCIE_STATUS);
        if status & want == want {
            return status;
        }
        if read_cntpct().wrapping_sub(start) > budget {
            return status;
        }
    }
}

/// Busy-wait for `us` microseconds via the generic timer counter.
#[cfg(feature = "board-cm5")]
unsafe fn busy_wait_us(us: u64) {
    let freq = timer_freq_hz();
    let target_ticks = (us * freq) / 1_000_000;
    let start = read_cntpct();
    while read_cntpct().wrapping_sub(start) < target_ticks {}
}

#[cfg(feature = "board-cm5")]
unsafe fn read_cntpct() -> u64 {
    let v: u64;
    core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack));
    v
}

#[cfg(feature = "board-cm5")]
unsafe fn timer_freq_hz() -> u64 {
    let v: u64;
    core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack));
    v
}

/// MDIO write via the PCIe RC's indirect-access registers (brcm-pcie
/// `brcm_pcie_mdio_write`). `port=0` is the sole port on 2712.
/// Returns true on success; failure is logged by the caller.
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_mdio_write(port: u8, regad: u8, wrdata: u16) -> bool {
    let rc = BCM2712_PCIE1_RC_BASE;
    let pkt = (((port as u32 >> 4) & 1) << 21) | (((port as u32) & 0xf) << 16) | (regad as u32);
    rc_w32(rc, brcm::MDIO_ADDR, pkt);
    let _ = rc_r32(rc, brcm::MDIO_ADDR); // barrier read
    rc_w32(rc, brcm::MDIO_WR_DATA, brcm::MDIO_DATA_DONE | wrdata as u32);

    let freq = timer_freq_hz();
    let budget = (100u64 * freq) / 1_000_000; // 100 µs
    let t0 = read_cntpct();
    loop {
        let v = rc_r32(rc, brcm::MDIO_WR_DATA);
        if v & brcm::MDIO_DATA_DONE == 0 {
            return true;
        }
        if read_cntpct().wrapping_sub(t0) > budget {
            return false;
        }
    }
}

/// Deassert the PCIe1 bridge SW reset (brcm,brcmstb-reset id=43) and
/// trigger the shared SATA/PCIe RESCAL calibration block. After this
/// runs the PCIe1 RC registers at `0x10_0011_0000` are decodable.
///
/// Writing to SW_INIT_CLEAR is the `brcm,brcmstb-reset` deassert path
/// (idempotent: if already deasserted, the write is a no-op).
/// The RESCAL sequence matches `brcm_rescal_reset_set`: set start bit,
/// poll status bit (≤ 1 ms per driver), clear start bit.
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_pre_init() -> bool {
    // 1. Deassert the PCIe1 bridge SW reset.
    let clr = BCM_RESET_BASE + BCM_RESET_PCIE1_BANK_OFF + 0x04;
    core::ptr::write_volatile(clr as *mut u32, BCM_RESET_PCIE1_BIT);
    // brcm,brcmstb-reset driver sleeps 100-200 µs after the write.
    busy_wait_us(200);

    // 2. Trigger RESCAL calibration.
    let start = core::ptr::read_volatile(RESCAL_BASE as *const u32);
    core::ptr::write_volatile(RESCAL_BASE as *mut u32, start | 1);

    let freq = timer_freq_hz();
    let t0 = read_cntpct();
    let budget = (10u64 * freq) / 1000; // 10 ms
    let mut ok = false;
    loop {
        let sts = core::ptr::read_volatile((RESCAL_BASE + RESCAL_STATUS) as *const u32);
        if sts & 1 != 0 {
            ok = true;
            break;
        }
        if read_cntpct().wrapping_sub(t0) > budget {
            break;
        }
    }
    // Clear start bit regardless (matches driver behaviour).
    let s2 = core::ptr::read_volatile(RESCAL_BASE as *const u32);
    core::ptr::write_volatile(RESCAL_BASE as *mut u32, s2 & !1);
    ok
}

/// Track whether we've completed the one-shot bring-up (reset/RESCAL +
/// MISC_CTRL + MDIO + SerDes). Re-running those after the link is
/// already up would put the controller back into training.
#[cfg(feature = "board-cm5")]
static mut PCIE1_BRINGUP_DONE: bool = false;

/// Fast path: program outbound window + bridge bus numbers and
/// enumerate bus 1. Safe to call repeatedly — the register writes are
/// idempotent and `DEVICE_COUNT` is reset each call.
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_populate_devices() {
    DEVICE_COUNT = 0;
    pcie1_program_outbound();
    pcie1_program_bus_numbers();
    pcie1_enumerate_bus1();
}

#[cfg(feature = "board-cm5")]
pub fn enumerate() -> usize {
    unsafe {
        // On a rescan after link finally came up, skip the one-shot
        // bring-up and just re-enumerate. enumerate() is called at boot
        // and from the nvme module's fault-retry loop; re-running
        // reset/MDIO/PERST# after the link is live would put the
        // controller back into training.
        if PCIE1_BRINGUP_DONE {
            pcie1_populate_devices();
            return DEVICE_COUNT;
        }

        DEVICE_COUNT = 0;

        // Stage 1: clock + reset — makes PCIe1 RC registers safe to touch.
        let rescal_ok = pcie1_pre_init();
        if !rescal_ok {
            log::warn!("[pcie] RESCAL calibration timed out; aborting PCIe1");
            return 0;
        }

        // Stage 2a: MISC_CTRL first (enables SCB_ACCESS_EN required by
        // the UBUS path we program later). Linux does this right after
        // bridge reset + rescal.
        let rc = BCM2712_PCIE1_RC_BASE;
        rc_w32(rc, brcm::MISC_CTRL, post_probe::MISC_CTRL);
        // RC_CFG_RETRY_TIMEOUT: bounds the time the RC will wait for
        // PCIe config-cycle completions before failing. Without this,
        // downstream config writes that never complete (e.g. during
        // early link-up) can stall the UBUS indefinitely.
        rc_w32(rc, brcm::RC_CFG_RETRY_TIMEOUT, post_probe::RC_CFG_RETRY);

        // Inbound setup — match Linux brcm_pcie_setup ordering for
        // BCM2712, writing after MISC_CTRL and before MDIO / PERST#.
        // Values from nvme_trace/baseline/pcie1_rc_post_probe_v3.txt.
        //
        // Writing UBUS_CTRL / UBUS_TIMEOUT / AXI_INTF_CTRL /
        // AXI_READ_ERR_DATA after the link has trained (e.g. on a
        // rescan with live UBUS traffic) hangs the kernel, so these
        // must land during the one-shot bring-up window only. Without
        // them the inbound BAR2 write path doesn't open — device
        // master TLPs don't MA but don't reach DRAM either.
        rc_w32(rc, brcm::UBUS_CTRL, post_probe::UBUS_CTRL);
        rc_w32(rc, brcm::UBUS_TIMEOUT, post_probe::UBUS_TIMEOUT);
        rc_w32(rc, brcm::AXI_INTF_CTRL, post_probe::AXI_INTF_CTRL);
        rc_w32(rc, brcm::AXI_READ_ERR_DATA, post_probe::AXI_READ_ERR_DATA);

        // RC BAR1/2 config (PCI-side: pci_offset + size encoding).
        // Match Linux post-probe — the actual DMA target is set by
        // the UBUS REMAP registers below, not these.
        rc_w32(rc, brcm::RC_BAR1_CONFIG_LO, post_probe::RC_BAR1_LO);
        rc_w32(rc, brcm::RC_BAR1_CONFIG_HI, post_probe::RC_BAR1_HI);
        rc_w32(rc, brcm::RC_BAR2_CONFIG_LO, post_probe::RC_BAR2_LO);
        rc_w32(rc, brcm::RC_BAR2_CONFIG_HI, post_probe::RC_BAR2_HI);

        // UBUS REMAP: the real inbound-DMA-target registers on 7712.
        // REMAP_LO = (cpu_addr[31:12] << 12) | ACCESS_EN.
        // REMAP_HI = cpu_addr[63:32].
        //
        // BAR1 inbound window (per RC_BAR1_HI=0x10): PCI bus
        // 0x10_0000_0000..0x20_0000_0000. We remap that 64 GB slot so
        // device DMA to PCI 0x10_XXXXXXXX lands in CPU/fabric
        // 0x00_XXXXXXXX — i.e. ARM-visible low DRAM where our BSS
        // arena lives. (nvme PRP1/ASQ/ACQ must then be
        // buffer_arm_addr | 0x10_0000_0000.)
        rc_w32(rc, brcm::UBUS_BAR1_REMAP_LO, brcm::UBUS_REMAP_ACCESS_EN);
        rc_w32(rc, brcm::UBUS_BAR1_REMAP_HI, 0);

        // BAR2 REMAP: keep Linux post-probe values as-is (not on our
        // DMA path; BAR2 is a 4 KB placeholder in Linux's config).
        rc_w32(rc, brcm::UBUS_BAR2_REMAP_LO, post_probe::UBUS_BAR2_REMAP_LO);
        rc_w32(rc, brcm::UBUS_BAR2_REMAP_HI, post_probe::UBUS_BAR2_REMAP_HI);

        // Stage 2b: MDIO tuning (brcm_pcie_post_setup_bcm2712).
        // First set the MDIO base address to 0x1600, then write 7
        // registers. Each write is a short indirect bus op through
        // the RC's internal MDIO controller.
        let mdio_ok = pcie1_mdio_write(0, brcm::MDIO_SET_ADDR_OFFSET, 0x1600);
        let mdio_regs: [(u8, u16); 7] = [
            (0x16, 0x50b9),
            (0x17, 0xbda1),
            (0x18, 0x0094),
            (0x19, 0x97b4),
            (0x1b, 0x5030),
            (0x1c, 0x5030),
            (0x1e, 0x0007),
        ];
        let mut mdio_all_ok = mdio_ok;
        for &(r, d) in mdio_regs.iter() {
            mdio_all_ok &= pcie1_mdio_write(0, r, d);
        }
        if !mdio_all_ok {
            log::warn!("[pcie1] MDIO tuning failed");
        }
        busy_wait_us(200);

        // PM_CLK_PERIOD = 0x12 (18.52 ns for the 54 MHz refclk).
        let mut phy15 = rc_r32(rc, brcm::PL_PHY_CTL_15);
        phy15 = (phy15 & !0xFF) | 0x12;
        rc_w32(rc, brcm::PL_PHY_CTL_15, phy15);

        // Stage 2c: brcm_pcie_start_link — SerDes up, CLKREQ mask
        // clear, then PERST# deassert.
        let mut hd = rc_r32(rc, brcm::HARD_DEBUG);
        hd &= !brcm::HARD_DEBUG_SERDES_IDDQ;
        rc_w32(rc, brcm::HARD_DEBUG, hd);
        let mut hd2 = rc_r32(rc, brcm::HARD_DEBUG);
        hd2 &= !brcm::HARD_DEBUG_CLKREQ_MASK;
        rc_w32(rc, brcm::HARD_DEBUG, hd2);

        // Deassert PERST# to release the downstream card (if still asserted).
        let ctrl_now = rc_r32(rc, brcm::MISC_PCIE_CTRL);
        if ctrl_now & brcm::CTRL_PERSTB == 0 {
            rc_w32(rc, brcm::MISC_PCIE_CTRL, ctrl_now | brcm::CTRL_PERSTB);
        }

        // brcm driver waits 100 ms after PERST# deassert before polling.
        busy_wait_us(100_000);

        // Actual link-up can take longer than our 100 ms budget; the
        // nvme module retries `PCIE_RESCAN` on fault until the device
        // appears. We flag bring-up done so the rescan fast-path runs.
        PCIE1_BRINGUP_DONE = true;
        log::info!("[pcie1] bring-up done");
        0
    }
}

#[cfg(not(feature = "board-cm5"))]
pub fn enumerate() -> usize {
    unsafe {
        DEVICE_COUNT = 0;
        let mut rp1 = PcieDevice::empty();
        rp1.vendor_id = 0x1de4;
        rp1.device_id = 0x0001;
        rp1.class = 0x020000;
        rp1.bars[0] = PCIE_MMIO_BASE as u64;
        rp1.bar_sizes[0] = 0x0040_0000;
        rp1.nic_type = PcieNicType::Rp1Gem;
        DEVICES[0] = rp1;
        DEVICE_COUNT = 1;
        1
    }
}

// ============================================================================
// Device lookup
// ============================================================================

pub fn find_by_nic_type(nic_type: PcieNicType) -> Option<usize> {
    unsafe {
        for i in 0..DEVICE_COUNT {
            if DEVICES[i].nic_type == nic_type {
                return Some(i);
            }
        }
        None
    }
}

pub fn get_device(idx: usize) -> Option<&'static PcieDevice> {
    unsafe {
        if idx < DEVICE_COUNT {
            Some(&DEVICES[idx])
        } else {
            None
        }
    }
}

pub fn device_count() -> usize {
    unsafe { DEVICE_COUNT }
}

/// Read a 32-bit value from a discovered device's PCI configuration
/// space. `dev_idx` refers to the position in `DEVICES` populated by
/// the last `enumerate()` call; `offset` is the byte offset within
/// config space (must be 4-byte aligned; low 2 bits are ignored).
/// Returns 0xFFFFFFFF on out-of-range arguments (same sentinel a real
/// PCIe controller returns for a missing responder).
#[cfg(feature = "board-cm5")]
pub fn device_cfg_read32(dev_idx: usize, offset: u16) -> u32 {
    unsafe {
        let count = *core::ptr::addr_of!(DEVICE_COUNT);
        if dev_idx >= count {
            return 0xFFFF_FFFF;
        }
        let dev = &DEVICES[dev_idx];
        let rc = BCM2712_PCIE1_RC_BASE;
        cfg_r32(rc, dev.bus, dev.dev, dev.func, offset & 0xFFC)
    }
}

#[cfg(not(feature = "board-cm5"))]
pub fn device_cfg_read32(_dev_idx: usize, _offset: u16) -> u32 {
    0xFFFF_FFFF
}

/// Write a 32-bit value into a discovered device's PCI configuration
/// space. Returns 0 on success or `-EINVAL` for an out-of-range
/// `dev_idx`.
#[cfg(feature = "board-cm5")]
pub fn device_cfg_write32(dev_idx: usize, offset: u16, val: u32) -> i32 {
    unsafe {
        let count = *core::ptr::addr_of!(DEVICE_COUNT);
        if dev_idx >= count {
            return crate::kernel::errno::EINVAL;
        }
        let dev = &DEVICES[dev_idx];
        let rc = BCM2712_PCIE1_RC_BASE;
        cfg_w32(rc, dev.bus, dev.dev, dev.func, offset & 0xFFC, val);
        0
    }
}

#[cfg(not(feature = "board-cm5"))]
pub fn device_cfg_write32(_dev_idx: usize, _offset: u16, _val: u32) -> i32 {
    crate::kernel::errno::ENOSYS
}

/// Syscall handler for `PCIE_CFG_READ32`. Arg layout:
///   in:  `[dev_idx: u8][_pad: u8][offset: u16 LE]` (4 bytes)
///   out: `[value: u32 LE]` appended at offset 4 (caller must pass >= 8 B).
/// Returns 0 on success, -22 on malformed arg.
pub unsafe fn syscall_cfg_read32(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
        return -22;
    }
    let dev_idx = *arg as usize;
    let offset = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
    let val = device_cfg_read32(dev_idx, offset);
    let vb = val.to_le_bytes();
    *arg.add(4) = vb[0];
    *arg.add(5) = vb[1];
    *arg.add(6) = vb[2];
    *arg.add(7) = vb[3];
    0
}

/// Syscall handler for `PCIE_CFG_WRITE32`. Arg layout:
///   in:  `[dev_idx: u8][_pad: u8][offset: u16 LE][value: u32 LE]` (8 bytes).
/// Returns 0 on success, -22 on malformed arg.
pub unsafe fn syscall_cfg_write32(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
        return -22;
    }
    let dev_idx = *arg as usize;
    let offset = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
    let val = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
    device_cfg_write32(dev_idx, offset, val)
}

// ============================================================================
// BAR mapping
// ============================================================================

pub fn bar_map(dev_idx: usize, bar_idx: usize) -> usize {
    unsafe {
        // Use addr_of! so the log macro doesn't expand into an
        // &static-mut reference (Rust 2024 static_mut_refs).
        let count = *core::ptr::addr_of!(DEVICE_COUNT);
        if dev_idx >= count || bar_idx >= MAX_BARS {
            log::warn!(
                "[pcie] bar_map: dev_idx={} count={} bar_idx={} out of range",
                dev_idx,
                count,
                bar_idx
            );
            return 0;
        }
        let dev = &DEVICES[dev_idx];
        let phys = dev.bars[bar_idx];
        let size = dev.bar_sizes[bar_idx];
        if phys == 0 || size == 0 {
            log::warn!(
                "[pcie] bar_map: dev{} bar{} phys={:#x} size={:#x}",
                dev_idx,
                bar_idx,
                phys,
                size
            );
            return 0;
        }

        let virt = phys as usize;
        let bdf = ((dev.bus as u16) << 8) | ((dev.dev as u16) << 3) | (dev.func as u16);

        // Re-use an existing slot for the same BDF+bar_idx — callers can
        // and do invoke this repeatedly (e.g. nvme retry-on-fault) and
        // allocating a fresh slot each time would exhaust MAX_BAR_MAPS.
        for i in 0..MAX_BAR_MAPS {
            if BAR_MAPS[i].active && BAR_MAPS[i].bdf == bdf && BAR_MAPS[i].bar_idx == bar_idx as u8
            {
                return virt;
            }
        }

        let mut slot = MAX_BAR_MAPS;
        for i in 0..MAX_BAR_MAPS {
            if !BAR_MAPS[i].active {
                slot = i;
                break;
            }
        }
        if slot >= MAX_BAR_MAPS {
            return 0;
        }

        BAR_MAPS[slot] = BarMap {
            bdf,
            bar_idx: bar_idx as u8,
            virt_addr: virt,
            size: size as usize,
            active: true,
        };
        virt
    }
}

pub fn bar_unmap(virt_addr: usize) -> i32 {
    unsafe {
        for i in 0..MAX_BAR_MAPS {
            if BAR_MAPS[i].active && BAR_MAPS[i].virt_addr == virt_addr {
                BAR_MAPS[i].active = false;
                return 0;
            }
        }
        crate::kernel::errno::EINVAL
    }
}

// ============================================================================
// Syscall handlers
// ============================================================================

pub unsafe fn syscall_bar_map(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 2 {
        return crate::kernel::errno::EINVAL;
    }
    let dev_idx = *arg as usize;
    let bar_idx = *arg.add(1) as usize;
    let virt = bar_map(dev_idx, bar_idx);
    if virt == 0 {
        return crate::kernel::errno::ENOMEM;
    }
    if arg_len >= 10 {
        let addr_bytes = (virt as u64).to_le_bytes();
        core::ptr::copy_nonoverlapping(addr_bytes.as_ptr(), arg.add(2), 8);
    }
    // Return a small positive success code rather than the low 32 bits
    // of the virt address. A 64-bit BAR like `0x1B_8002_0000` on Pi 5
    // PCIe1 truncates to a *negative* i32 otherwise, tricking callers
    // that check `rc < 0` into thinking the map failed. The real
    // address is in arg[2..10].
    1
}

pub unsafe fn syscall_bar_unmap(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
        return crate::kernel::errno::EINVAL;
    }
    let mut addr_buf = [0u8; 8];
    core::ptr::copy_nonoverlapping(arg, addr_buf.as_mut_ptr(), 8);
    let virt = u64::from_le_bytes(addr_buf) as usize;
    bar_unmap(virt)
}

// ============================================================================
// brcmstb PCIe1 MSI controller
// ============================================================================
//
// Port of `brcm_msi_set_regs` + `brcm_pcie_msi_isr` from Linux
// drivers/pci/controller/pcie-brcmstb.c v6.12, narrowed to the Pi 5
// BCM7712 IP variant (rev 0x0500, 32 MSIs, MSI_INTR2_BASE at 0x4500).
//
//   `pcie1_msi_init` programs the RC MSI target/data registers and
//     unmasks all 32 vectors. Idempotent.
//   `pcie1_msi_alloc_vector` binds a free vector to a caller-owned
//     event fd and returns `(vector, target_addr, data)` for the
//     peripheral's MSI-X table entry.
//   `pcie1_msi_dispatch` reads MSI_INT_STATUS, signals each pending
//     vector's event, and acks via MSI_INT_CLR. Called from the GIC
//     SPI handler in `bcm2712.rs`.
//
// Nothing here runs unless a driver opts in via `PCIE1_MSI_INIT` +
// `PCIE1_MSI_ALLOC_VECTOR` syscalls (e.g. nvme with `irq_mode=1`).

#[cfg(feature = "board-cm5")]
pub const PCIE1_MSI_VECTORS: usize = 32;

#[cfg(feature = "board-cm5")]
#[derive(Clone, Copy)]
struct MsiVector {
    event_handle: i32,
    active: bool,
}

#[cfg(feature = "board-cm5")]
impl MsiVector {
    const fn empty() -> Self {
        Self {
            event_handle: -1,
            active: false,
        }
    }
}

#[cfg(feature = "board-cm5")]
static mut PCIE1_MSI_VECTORS_TAB: [MsiVector; PCIE1_MSI_VECTORS] =
    [const { MsiVector::empty() }; PCIE1_MSI_VECTORS];

#[cfg(feature = "board-cm5")]
static mut PCIE1_MSI_INITIALISED: bool = false;

/// Program the brcmstb PCIe1 MSI controller. Idempotent.
///
/// Must run after `enumerate()` — the RC registers don't decode until
/// PCIe1 reset is released and MISC_CTRL has been programmed. Returns
/// `false` if the RC is unreadable or reports a HW revision older
/// than 0x0303 (which would require the legacy MSI path — not
/// supported, BCM7712 is 0x0500).
#[cfg(feature = "board-cm5")]
pub unsafe fn pcie1_msi_init() -> bool {
    if PCIE1_MSI_INITIALISED {
        return true;
    }
    let rc = BCM2712_PCIE1_RC_BASE;

    let rev = rc_r32(rc, brcm::MISC_REVISION) & 0xFFFF;
    if rev == 0xFFFF || rev < brcm::HW_REV_33 {
        return false;
    }

    let target = brcm::MSI_TARGET_ADDR;
    let intr = rc + brcm::MSI_INTR2_BASE;

    // Mask everything, clear any stale pending bits.
    core::ptr::write_volatile(
        (intr + brcm::MSI_INT_MASK_SET) as *mut u32,
        brcm::MSI_MASK_ALL,
    );
    core::ptr::write_volatile((intr + brcm::MSI_INT_CLR) as *mut u32, brcm::MSI_MASK_ALL);

    // Program the RC's MSI target: low 32 bits have ENABLE bit set.
    rc_w32(
        rc,
        brcm::MSI_BAR_CONFIG_LO,
        (target as u32) | brcm::MSI_BAR_ENABLE,
    );
    rc_w32(rc, brcm::MSI_BAR_CONFIG_HI, (target >> 32) as u32);

    // DATA_CONFIG match pattern. Bits [31:16] = match-mask (0xffe0 =
    // bits [15:5]), bits [15:0] = match-value (0x6540). An incoming
    // MSI write with data `(0x6540 | vec)` where vec ∈ 0..31 is
    // recognised and posted on MSI_INT_STATUS bit `vec`.
    rc_w32(rc, brcm::MSI_DATA_CONFIG, brcm::MSI_DATA_CONFIG_VAL_32);

    // Unmask all 32 vectors. Per-vector masking at the MSI-X table
    // entry is what actually gates each peripheral's interrupts —
    // the RC-level mask is global.
    core::ptr::write_volatile(
        (intr + brcm::MSI_INT_MASK_CLR) as *mut u32,
        brcm::MSI_MASK_ALL,
    );

    core::arch::asm!("dsb sy");

    PCIE1_MSI_INITIALISED = true;
    true
}

/// Allocate a free MSI vector for `event_handle` and return
/// `(vector_index, target_addr, data_value)`. The caller writes
/// `address = target_addr`, `data = data_value` into the peripheral's
/// MSI-X table entry.
#[cfg(feature = "board-cm5")]
pub unsafe fn pcie1_msi_alloc_vector(event_handle: i32) -> Option<(u8, u64, u32)> {
    if !PCIE1_MSI_INITIALISED && !pcie1_msi_init() {
        return None;
    }
    for i in 0..PCIE1_MSI_VECTORS {
        let slot = &mut *core::ptr::addr_of_mut!(PCIE1_MSI_VECTORS_TAB[i]);
        if !slot.active {
            slot.active = true;
            slot.event_handle = event_handle;
            let data = (brcm::MSI_DATA_CONFIG_VAL_32 & 0xFFFF) | (i as u32);
            return Some((i as u8, brcm::MSI_TARGET_ADDR, data));
        }
    }
    None
}

/// Drain pending MSI vectors. Called from the GIC SPI handler when
/// the PCIe1 MSI SPI fires. Returns the number of events signalled.
#[cfg(feature = "board-cm5")]
pub unsafe fn pcie1_msi_dispatch() -> u32 {
    if !PCIE1_MSI_INITIALISED {
        return 0;
    }
    let intr = BCM2712_PCIE1_RC_BASE + brcm::MSI_INTR2_BASE;
    let status = core::ptr::read_volatile((intr + brcm::MSI_INT_STATUS) as *const u32);
    if status == 0 {
        return 0;
    }
    // Ack the snapshot before fanning out so MSIs that arrive during
    // dispatch accumulate on the next pass instead of being lost.
    core::ptr::write_volatile((intr + brcm::MSI_INT_CLR) as *mut u32, status);

    let mut signalled = 0u32;
    let mut bits = status;
    while bits != 0 {
        let v = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        if v >= PCIE1_MSI_VECTORS {
            continue;
        }
        let slot = &*core::ptr::addr_of!(PCIE1_MSI_VECTORS_TAB[v]);
        if slot.active && slot.event_handle >= 0 {
            crate::kernel::event::event_signal_from_isr(slot.event_handle);
            signalled += 1;
        }
    }
    signalled
}

#[cfg(not(feature = "board-cm5"))]
pub unsafe fn pcie1_msi_init() -> bool {
    false
}
#[cfg(not(feature = "board-cm5"))]
pub unsafe fn pcie1_msi_alloc_vector(_e: i32) -> Option<(u8, u64, u32)> {
    None
}
#[cfg(not(feature = "board-cm5"))]
pub unsafe fn pcie1_msi_dispatch() -> u32 {
    0
}

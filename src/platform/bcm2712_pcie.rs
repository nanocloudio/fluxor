//! PCIe enumeration and BAR mapping for BCM2712 (CM5) — thin kernel bridge.
//!
//! The full PCIe enumeration and BAR management logic has been extracted
//! into the `pcie_scan` PIC module, which uses MMIO_READ32/WRITE32 bridges.
//!
//! This file retains:
//! - Constants (ECAM base, MMIO base)
//! - Syscall handler wrappers that delegate to the PIC module when loaded,
//!   or fall back to the built-in implementation.
//! - The built-in implementation for backward compatibility.

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
// NOTE: `ECAM_BASE` below retains the historical `0xFD50_0000` value for
// backward compat with the pre-existing built-in enumerator. The PIC
// `pcie_scan` module uses the `BCM2712_PCIE2_*` values at `0x10_00**_0000`,
// which is what the Pi 5 SoC actually exposes.

/// BCM2712 PCIe2 (RP1) configuration-space base — historical value used by
/// the built-in fallback enumerator; kept for back-compat only.
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
pub const BCM2712_PCIE2_RC_BASE:   u64 = 0x10_0012_0000;

/// BCM2712 PCIe2 outbound MMIO window (RP1 BAR region after VPU
/// configuration; Linux remaps to `0x1f_0000_0000` post-handoff — the
/// bare-metal kernel inherits whichever mapping is live at entry).
pub const BCM2712_PCIE2_MMIO_BASE: u64 = 0x1C_0000_0000;

/// BCM2712 PCIe1 (external x1, NVMe HAT+) controller base — mainline DTS
/// node `pcie@114000`.
pub const BCM2712_PCIE1_RC_BASE:   u64 = 0x10_0011_0000;

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
            bus: 0, dev: 0, func: 0,
            vendor_id: 0, device_id: 0, class: 0,
            bars: [0; MAX_BARS], bar_sizes: [0; MAX_BARS],
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
        Self { bdf: 0, bar_idx: 0, virt_addr: 0, size: 0, active: false }
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
        + ((bus as usize) << 20) + ((dev as usize) << 15)
        + ((func as usize) << 12) + (offset as usize & 0xFFC);
    core::ptr::read_volatile(addr as *const u32)
}

#[cfg(feature = "board-cm5")]
unsafe fn ecam_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let addr = ECAM_BASE
        + ((bus as usize) << 20) + ((dev as usize) << 15)
        + ((func as usize) << 12) + (offset as usize & 0xFFC);
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
const RESCAL_BASE:       u64 = 0x10_0011_9500;
#[cfg(feature = "board-cm5")]
const RESCAL_START:      u64 = 0x00;
#[cfg(feature = "board-cm5")]
const RESCAL_STATUS:     u64 = 0x08;

#[cfg(feature = "board-cm5")]
const BCM_RESET_BASE:    u64 = 0x10_0150_4318;
#[cfg(feature = "board-cm5")]
const BCM_RESET_PCIE1_BANK_OFF: u64 = 0x18;
#[cfg(feature = "board-cm5")]
const BCM_RESET_PCIE1_BIT: u32 = 1 << 11;

#[cfg(feature = "board-cm5")]
mod brcm {
    pub const EXT_CFG_DATA:       u64 = 0x8000;
    pub const EXT_CFG_INDEX:      u64 = 0x9000;

    /// `PCIE_MISC_MISC_CTRL` — controller-wide behaviour bits. Linux's
    /// `brcm_pcie_setup` writes this early in probe; without SCB_ACCESS_EN
    /// the controller rejects configuration cycles from the CPU.
    pub const MISC_CTRL:            u64 = 0x4008;
    pub const CTRL_SCB_ACCESS_EN:   u32 = 1 << 12;
    pub const CTRL_CFG_READ_UR:     u32 = 1 << 13;
    pub const CTRL_RCB_MPS_MODE:    u32 = 1 << 10;
    pub const CTRL_RCB_64B_MODE:    u32 = 1 << 7;
    /// MAX_BURST_SIZE field [21:20]: 0=128B, 1=256B, 2=512B.
    pub const CTRL_MAX_BURST_512:   u32 = 0x2 << 20;
    pub const CTRL_MAX_BURST_MASK:  u32 = 0x3 << 20;

    pub const MEM_WIN0_LO:          u64 = 0x400c;
    pub const MEM_WIN0_HI:          u64 = 0x4010;
    pub const MEM_WIN0_BASE_LIMIT:  u64 = 0x4070;
    pub const MEM_WIN0_BASE_HI:     u64 = 0x4080;
    pub const MEM_WIN0_LIMIT_HI:    u64 = 0x4084;

    /// RC link-up status register. Bit 4 = PHYLINKUP, bit 5 = DL_ACTIVE.
    /// Both must be set for the link to be usable.
    pub const MISC_PCIE_STATUS:     u64 = 0x4068;
    pub const STATUS_PHYLINKUP:     u32 = 1 << 4;
    pub const STATUS_DL_ACTIVE:     u32 = 1 << 5;

    /// Control register. Bit 2 = PCIE_PERSTB (active-high: 1 = PERST#
    /// deasserted / card out of reset). VPU on Pi 5 leaves this clear
    /// for non-Linux kernel handoff — matching brcm_pcie_perst_set_2712,
    /// we set it to release the downstream device.
    pub const MISC_PCIE_CTRL:       u64 = 0x4064;
    pub const CTRL_PERSTB:          u32 = 1 << 2;

    /// PCIe1 outbound window: CPU 0x1B_8000_0000..0x1B_FFFF_FFFF (2 GB)
    /// maps to PCI bus addresses 0x8000_0000..0xFFFF_FFFF. Matches what
    /// Linux's brcm-pcie driver programs when `dtparam=pciex1` is active.
    pub const PCIE1_OUTBOUND_CPU_BASE:  u64 = 0x1B_8000_0000;
    pub const PCIE1_OUTBOUND_CPU_LIMIT: u64 = 0x1B_FFFF_FFFF;
    pub const PCIE1_OUTBOUND_PCI_BASE:  u64 = 0x0000_0000_8000_0000;

    // Stage-4 (brcm_pcie_setup / post_setup / start_link) registers.
    pub const HARD_DEBUG:             u64 = 0x4304;
    pub const HARD_DEBUG_SERDES_IDDQ: u32 = 1 << 21;
    pub const HARD_DEBUG_CLKREQ_MASK: u32 = (1 << 1) | (1 << 16) | (1 << 20) | (1 << 21);

    pub const RC_CFG_RETRY_TIMEOUT: u64 = 0x405c;
    pub const PL_PHY_CTL_15:        u64 = 0x184c;
    pub const AXI_INTF_CTRL:        u64 = 0x416c;
    pub const AXI_READ_ERR_DATA:    u64 = 0x4170;
    pub const UBUS_CTRL:            u64 = 0x40a4;
    pub const UBUS_TIMEOUT:         u64 = 0x40a8;

    pub const RC_BAR1_CONFIG_LO:    u64 = 0x402c;
    pub const RC_BAR1_CONFIG_HI:    u64 = 0x4030;
    pub const RC_BAR2_CONFIG_LO:    u64 = 0x4034;
    pub const RC_BAR2_CONFIG_HI:    u64 = 0x4038;
    /// Per-BAR UBUS REMAP registers. REMAP_LO bit 0 = ACCESS_EN,
    /// bits[31:12] = cpu_addr[31:12] (fabric). REMAP_HI = cpu_addr high
    /// bits. When ACCESS_EN is set the REMAP value overrides the
    /// cpu_addr that RC_BAR(i)_CONFIG otherwise supplies. This is the
    /// actual DMA-target register on BCM7712 (see upstream
    /// `set_inbound_win_registers` + BCM7712 branch in pcie-brcmstb.c).
    pub const UBUS_BAR1_REMAP_LO:   u64 = 0x40ac;
    pub const UBUS_BAR1_REMAP_HI:   u64 = 0x40b0;
    pub const UBUS_BAR2_REMAP_LO:   u64 = 0x40b4;
    pub const UBUS_BAR2_REMAP_HI:   u64 = 0x40b8;
    pub const UBUS_REMAP_ACCESS_EN: u32 = 1 << 0;

    // MDIO indirect register-access protocol (brcm_pcie_mdio_write).
    pub const MDIO_ADDR:            u64 = 0x1100;
    pub const MDIO_WR_DATA:         u64 = 0x1104;
    pub const MDIO_DATA_DONE:       u32 = 1 << 31;
    pub const MDIO_SET_ADDR_OFFSET: u8  = 0x1f;
}

/// Post-probe target values captured on the rig under Linux
/// (hw/nvme_trace/baseline/pcie1_rc_post_probe.txt). Stage-4 writes
/// these verbatim so the Fluxor state converges on `brcm_pcie_probe`.
#[cfg(feature = "board-cm5")]
mod post_probe {
    pub const MISC_CTRL:          u32 = 0x00263480;
    pub const RC_CFG_RETRY:       u32 = 0x0ABA0000;
    pub const PL_PHY_CTL_15:      u32 = 0x4DBC0012;
    pub const AXI_INTF_CTRL:      u32 = 0x0000004F;
    pub const AXI_READ_ERR_DATA:  u32 = 0xFFFFFFFF;
    pub const UBUS_CTRL:          u32 = 0x00082000;
    pub const UBUS_TIMEOUT:       u32 = 0x0B2D0000;
    pub const RC_BAR1_LO:           u32 = 0x00000015;
    pub const RC_BAR1_HI:           u32 = 0x00000010;
    pub const RC_BAR2_LO:           u32 = 0xFFFFF01C;
    pub const RC_BAR2_HI:           u32 = 0x000000FF;
    pub const UBUS_BAR2_REMAP_LO:   u32 = 0x00131001;
    pub const UBUS_BAR2_REMAP_HI:   u32 = 0x00000010;
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
    rc_w32(rc, brcm::MEM_WIN0_HI, (brcm::PCIE1_OUTBOUND_PCI_BASE >> 32) as u32);

    // BASE_LIMIT: CPU-side base+limit in 1 MB units. Bits [15:4] = base_mb,
    // bits [31:20] = limit_mb (both mask to 12 bits — the high bits go into
    // BASE_HI / LIMIT_HI).
    let base_mb  = (brcm::PCIE1_OUTBOUND_CPU_BASE  >> 20) as u32;
    let limit_mb = (brcm::PCIE1_OUTBOUND_CPU_LIMIT >> 20) as u32;
    let base_limit = ((base_mb  & 0xFFF) <<  4)
                   | ((limit_mb & 0xFFF) << 20);
    rc_w32(rc, brcm::MEM_WIN0_BASE_LIMIT, base_limit);
    rc_w32(rc, brcm::MEM_WIN0_BASE_HI,  (base_mb  >> 12) as u32);
    rc_w32(rc, brcm::MEM_WIN0_LIMIT_HI, (limit_mb >> 12) as u32);
}

/// Scan bus 1 for downstream devices (NVMe HAT+, etc.) via indirect
/// config access. Assigns BAR0 (and BAR1-hi for 64-bit BARs) into the
/// outbound window and enables MEM + BusMaster. v1 only supports the
/// single CM5 NVMe HAT+ slot (bus 1 dev 0) with a fixed 16 KB BAR0
/// assumption; add multi-device + BAR size probing in a follow-up.
#[cfg(feature = "board-cm5")]
unsafe fn pcie1_enumerate_bus1() {
    let rc = BCM2712_PCIE1_RC_BASE;
    let dev_num = 0u8;
    let id = cfg_r32(rc, 1, dev_num, 0, 0x00);
    let vendor_id = (id & 0xFFFF) as u16;
    let device_id = ((id >> 16) & 0xFFFF) as u16;
    if vendor_id == 0xFFFF || vendor_id == 0 { return; }

    let class_rev = cfg_r32(rc, 1, dev_num, 0, 0x08);
    let mut pdev = PcieDevice::empty();
    pdev.bus = 1;
    pdev.dev = dev_num;
    pdev.vendor_id = vendor_id;
    pdev.device_id = device_id;
    pdev.class = class_rev >> 8;

    // Disable MEM + BusMaster while we write BAR0 so in-flight cycles
    // don't race the reassignment.
    let cmd_before = cfg_r32(rc, 1, dev_num, 0, 0x04);
    cfg_w32(rc, 1, dev_num, 0, 0x04, cmd_before & !0x0006);

    let bar0_lo_raw = cfg_r32(rc, 1, dev_num, 0, 0x10);
    let is_mem = bar0_lo_raw & 1 == 0;
    let is_64b = is_mem && ((bar0_lo_raw >> 1) & 3) == 2;

    let assigned_pci: u64 = if is_mem {
        let base = brcm::PCIE1_OUTBOUND_PCI_BASE + 0x20000;
        let low  = (base & 0xFFFF_FFF0) as u32 | (bar0_lo_raw & 0xF);
        cfg_w32(rc, 1, dev_num, 0, 0x10, low);
        if is_64b {
            cfg_w32(rc, 1, dev_num, 0, 0x14, (base >> 32) as u32);
        }
        base
    } else { 0 };

    // Re-enable MEM + BusMaster.
    cfg_w32(rc, 1, dev_num, 0, 0x04, cmd_before | 0x0006);

    if is_mem && assigned_pci >= brcm::PCIE1_OUTBOUND_PCI_BASE {
        let offset = assigned_pci - brcm::PCIE1_OUTBOUND_PCI_BASE;
        pdev.bars[0] = brcm::PCIE1_OUTBOUND_CPU_BASE + offset;
        pdev.bar_sizes[0] = 0x4000;
    }
    log::info!(
        "[pcie1] bus1 dev{} vid={:04x} did={:04x} bar0_cpu={:#x}",
        dev_num, vendor_id, device_id, pdev.bars[0]
    );

    pdev.identify_nic();
    if DEVICE_COUNT < MAX_SCAN_DEVS {
        DEVICES[DEVICE_COUNT] = pdev;
        DEVICE_COUNT += 1;
    }
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
        if status & want == want { return status; }
        if read_cntpct().wrapping_sub(start) > budget { return status; }
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
    let pkt = (((port as u32 >> 4) & 1) << 21)
            | (((port as u32) & 0xf) << 16)
            | (regad as u32);
    rc_w32(rc, brcm::MDIO_ADDR, pkt);
    let _ = rc_r32(rc, brcm::MDIO_ADDR); // barrier read
    rc_w32(rc, brcm::MDIO_WR_DATA, brcm::MDIO_DATA_DONE | wrdata as u32);

    let freq = timer_freq_hz();
    let budget = (100u64 * freq) / 1_000_000; // 100 µs
    let t0 = read_cntpct();
    loop {
        let v = rc_r32(rc, brcm::MDIO_WR_DATA);
        if v & brcm::MDIO_DATA_DONE == 0 { return true; }
        if read_cntpct().wrapping_sub(t0) > budget { return false; }
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
        if sts & 1 != 0 { ok = true; break; }
        if read_cntpct().wrapping_sub(t0) > budget { break; }
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

        // Full inbound setup — match Linux brcm_pcie_setup ordering
        // for BCM2712, writing at boot (after MISC_CTRL, before MDIO /
        // PERST#). All values from
        // hw/nvme_trace/baseline/pcie1_rc_post_probe_v3.txt.
        //
        // Earlier sessions (see pi5_pcie1_bringup_blocker memory)
        // found that UBUS_CTRL / UBUS_TIMEOUT / AXI_INTF_CTRL /
        // AXI_READ_ERR_DATA hang the kernel when written at RESCAN
        // (after the link is trained and UBUS has live traffic).
        // Writing them here, before MDIO and PERST#, matches Linux
        // and has not been attempted until this session.
        //
        // Without UBUS_CTRL + AXI_INTF_CTRL the inbound BAR2 writes
        // land in the register but don't open the DMA path — the
        // device's master TLPs don't MA but also don't land in DRAM.
        rc_w32(rc, brcm::UBUS_CTRL,         post_probe::UBUS_CTRL);
        rc_w32(rc, brcm::UBUS_TIMEOUT,      post_probe::UBUS_TIMEOUT);
        rc_w32(rc, brcm::AXI_INTF_CTRL,     post_probe::AXI_INTF_CTRL);
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
            if DEVICES[i].nic_type == nic_type { return Some(i); }
        }
        None
    }
}

pub fn get_device(idx: usize) -> Option<&'static PcieDevice> {
    unsafe { if idx < DEVICE_COUNT { Some(&DEVICES[idx]) } else { None } }
}

pub fn device_count() -> usize { unsafe { DEVICE_COUNT } }

// ============================================================================
// BAR mapping
// ============================================================================

pub fn bar_map(dev_idx: usize, bar_idx: usize) -> usize {
    unsafe {
        if dev_idx >= DEVICE_COUNT || bar_idx >= MAX_BARS {
            log::warn!(
                "[pcie] bar_map: dev_idx={} count={} bar_idx={} out of range",
                dev_idx, DEVICE_COUNT, bar_idx
            );
            return 0;
        }
        let dev = &DEVICES[dev_idx];
        let phys = dev.bars[bar_idx];
        let size = dev.bar_sizes[bar_idx];
        if phys == 0 || size == 0 {
            log::warn!(
                "[pcie] bar_map: dev{} bar{} phys={:#x} size={:#x}",
                dev_idx, bar_idx, phys, size
            );
            return 0;
        }

        let virt = phys as usize;
        let bdf = ((dev.bus as u16) << 8) | ((dev.dev as u16) << 3) | (dev.func as u16);

        // Re-use an existing slot for the same BDF+bar_idx — callers can
        // and do invoke this repeatedly (e.g. nvme retry-on-fault) and
        // allocating a fresh slot each time would exhaust MAX_BAR_MAPS.
        for i in 0..MAX_BAR_MAPS {
            if BAR_MAPS[i].active
                && BAR_MAPS[i].bdf == bdf
                && BAR_MAPS[i].bar_idx == bar_idx as u8
            {
                return virt;
            }
        }

        let mut slot = MAX_BAR_MAPS;
        for i in 0..MAX_BAR_MAPS {
            if !BAR_MAPS[i].active { slot = i; break; }
        }
        if slot >= MAX_BAR_MAPS { return 0; }

        BAR_MAPS[slot] = BarMap { bdf, bar_idx: bar_idx as u8, virt_addr: virt, size: size as usize, active: true };
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
    if arg.is_null() || arg_len < 2 { return crate::kernel::errno::EINVAL; }
    let dev_idx = *arg as usize;
    let bar_idx = *arg.add(1) as usize;
    let virt = bar_map(dev_idx, bar_idx);
    if virt == 0 { return crate::kernel::errno::ENOMEM; }
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
    if arg.is_null() || arg_len < 8 { return crate::kernel::errno::EINVAL; }
    let mut addr_buf = [0u8; 8];
    core::ptr::copy_nonoverlapping(arg, addr_buf.as_mut_ptr(), 8);
    let virt = u64::from_le_bytes(addr_buf) as usize;
    bar_unmap(virt)
}

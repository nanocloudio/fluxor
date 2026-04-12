//! RP1 Cadence GEM NIC Driver PIC Module
//!
//! Kernel-bypass Ethernet driver for the Cadence GEM MAC on the RP1 chip
//! (Pi 5 / CM5). Uses known RP1 GEM register base, creates DMA rings via
//! NIC_RING_CREATE, and drives the MAC directly from poll-mode (Tier 3).
//!
//! # Channels
//!
//! - `in[0]`: TX packets from upstream (e.g. IP stack)
//! - `out[0]`: RX packets to downstream (e.g. IP stack)
//!
//! # Init Sequence
//!
//! 1. Use known RP1 GEM base address
//! 2. NIC_RING_CREATE for RX + TX descriptor rings
//! 3. NIC_RING_INFO to get descriptor/buffer addresses
//! 4. Program GEM registers (DMA config, MAC address, enable RX/TX)
//! 5. Return Ready when link is up
//!
//! Exports `module_deferred_ready` — gates downstream until link up.

#![no_std]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Cadence GEM Register Offsets
// ============================================================================

// Network control/config
const GEM_NWCTRL: usize = 0x000;        // Network control
const GEM_NWCFG: usize = 0x004;         // Network config
const GEM_NWSR: usize = 0x008;          // Network status
const GEM_DMACFG: usize = 0x010;        // DMA config
const GEM_TXSTATUS: usize = 0x014;      // TX status
const GEM_RXQBASE: usize = 0x018;       // RX queue base addr
const GEM_TXQBASE: usize = 0x01C;       // TX queue base addr
const GEM_RXSTATUS: usize = 0x020;      // RX status
const GEM_ISR: usize = 0x024;           // Interrupt status
const GEM_IDR: usize = 0x02C;           // Interrupt disable
const GEM_PHYMGMT: usize = 0x034;       // PHY management
const GEM_HASHBOT: usize = 0x080;       // Hash register bottom
const GEM_HASHTOP: usize = 0x084;       // Hash register top
const GEM_SA1B: usize = 0x088;          // Specific addr 1 bottom (MAC lo)
const GEM_SA1T: usize = 0x08C;          // Specific addr 1 top (MAC hi)
const GEM_USRIO: usize = 0x0C0;         // User IO (RGMII mode select)
const GEM_MID: usize = 0x0FC;           // Module ID (RO)
const GEM_DCFG1: usize = 0x280;         // Design config 1
const GEM_DCFG2: usize = 0x284;         // Design config 2

// Upper base address registers (64-bit DMA)
const GEM_RBQPH: usize = 0x04D4;        // RX queue base addr high
const GEM_TBQPH: usize = 0x04C8;        // TX queue base addr high

// Network control bits
const NWCTRL_RXEN: u32 = 1 << 2;
const NWCTRL_TXEN: u32 = 1 << 3;
const NWCTRL_MDIO_EN: u32 = 1 << 4;
const NWCTRL_CLRSTAT: u32 = 1 << 5;
const NWCTRL_STARTTX: u32 = 1 << 9;

// DMA config bits
const DMACFG_RXBUF_SIZE_SHIFT: u32 = 16;
const DMACFG_ADDR64: u32 = 1 << 30;     // 64-bit address bus

// NIC syscall opcodes
const NIC_RING_CREATE: u32 = 0x0CF2;
const NIC_RING_INFO: u32 = 0x0CF4;

// ============================================================================
// GEM RX descriptor (Cadence native, 64-bit addressing)
// ============================================================================
//
// Word 0: [31:2] buffer address low, [1] wrap, [0] ownership
//         ownership: 0 = owned by GEM (free), 1 = owned by SW (frame written)
// Word 1: [12:0] frame length (set by GEM), [31] global broadcast, etc.
// Word 2: [31:0] buffer address high
// Word 3: reserved
//
// Total: 16 bytes per descriptor, must be 16-byte aligned.

const RX_DESC_OWNERSHIP: u32 = 1 << 0;  // set by GEM when frame stored
const RX_DESC_WRAP: u32 = 1 << 1;       // last descriptor in ring
const RX_DESC_LEN_MASK: u32 = 0x1FFF;   // bits [12:0] of word 1

// ============================================================================
// GEM TX descriptor (Cadence native, 64-bit addressing)
// ============================================================================
//
// Word 0: [31:0] buffer address low
// Word 1: [13:0] length, [15] last buffer, [30] wrap, [31] used
//         used: 0 = owned by GEM (pending TX), 1 = owned by SW (GEM done)
// Word 2: [31:0] buffer address high
// Word 3: reserved

const TX_DESC_LEN_MASK: u32 = 0x3FFF;   // bits [13:0]
const TX_DESC_LAST: u32 = 1 << 15;      // last buffer of frame
const TX_DESC_WRAP: u32 = 1 << 30;      // last descriptor in ring
const TX_DESC_USED: u32 = 1 << 31;      // set by GEM when TX complete

// ============================================================================
// Constants
// ============================================================================

const RX_DESC_COUNT: u16 = 64;
const TX_DESC_COUNT: u16 = 64;
const BUF_SIZE: u16 = 2048;
const BUF_COUNT: u16 = 128; // 64 RX + 64 TX

/// Maximum Ethernet frame size (MTU 1500 + headers).
const MAX_FRAME: usize = 1514;

// Default MAC address (locally administered)
const DEFAULT_MAC: [u8; 6] = [0x02, 0xCA, 0xDE, 0x00, 0x00, 0x01];

// Expected GEM Module ID (verified via devmem on running Pi 5)
const EXPECTED_MID: u32 = 0x0007_0109;

/// PCIe inbound window identity-maps ARM physical addresses.
/// DMA addresses equal ARM physical addresses.
const DMA_OFFSET: u64 = 0;

// ============================================================================
// State
// ============================================================================

const STATE_SIZE: usize = 256;

#[repr(C)]
struct GemState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    gem_base: usize,
    ring_handle: i32,
    // Ring info (from NIC_RING_INFO)
    rx_desc_addr: u64,
    rx_desc_count: u16,
    tx_desc_addr: u64,
    tx_desc_count: u16,
    buf_pool_addr: u64,
    buf_size: u16,
    buf_count: u16,
    // Tracking
    rx_tail: u16,
    tx_head: u16,
    tx_tail: u16,
    mac: [u8; 6],
    phase: u8,        // 0=init, 1=wait_link, 2=running
    _pad: [u8; 3],
    step_count: u32,
    rx_packets: u32,
    tx_packets: u32,
    link_poll_counter: u32,
}

// ============================================================================
// MMIO helpers
// ============================================================================

#[inline(always)]
unsafe fn gem_read(base: usize, offset: usize) -> u32 {
    read_volatile((base + offset) as *const u32)
}

#[inline(always)]
unsafe fn gem_write(base: usize, offset: usize, val: u32) {
    write_volatile((base + offset) as *mut u32, val);
}

// ============================================================================
// Logging helper
// ============================================================================

unsafe fn log_msg(sys: &SyscallTable, msg: &[u8]) {
    dev_log(sys, 3, msg.as_ptr(), msg.len()); // level 3 = info
}

// ============================================================================
// MDIO (PHY management interface)
// ============================================================================

/// MDIO read: read PHY register via GEM's PHYMGMT register.
/// Returns register value (u16), or 0xFFFF on timeout.
unsafe fn mdio_read(base: usize, phy_addr: u8, reg: u8) -> u16 {
    // PHYMGMT register format (Cadence GEM / macb):
    // [31:30] = SOF = 0b01 (clause 22 start of frame)
    // [29:28] = RW  = 0b10 (read) or 0b01 (write)
    // [27:23] = PHY address
    // [22:18] = register address
    // [17:16] = 0b10 (clause 22 turnaround)
    // [15:0]  = data (write) / read back
    let val: u32 = (0b0110 << 28)        // SOF=01, RW=10 (read)
        | ((phy_addr as u32 & 0x1F) << 23)
        | ((reg as u32 & 0x1F) << 18)
        | (0b10 << 16);                   // turnaround
    gem_write(base, GEM_PHYMGMT, val);

    // Wait for MDIO idle (NWSR bit 2)
    let mut timeout = 10000u32;
    while timeout > 0 {
        let nwsr = gem_read(base, GEM_NWSR);
        if nwsr & (1 << 2) != 0 { break; }
        timeout -= 1;
    }
    if timeout == 0 { return 0xFFFF; }

    (gem_read(base, GEM_PHYMGMT) & 0xFFFF) as u16
}

/// MDIO write: write PHY register via GEM's PHYMGMT register.
unsafe fn mdio_write(base: usize, phy_addr: u8, reg: u8, data: u16) {
    let val: u32 = (0b0101 << 28)        // SOF=01, RW=01 (write)
        | ((phy_addr as u32 & 0x1F) << 23)
        | ((reg as u32 & 0x1F) << 18)
        | (0b10 << 16)                    // turnaround
        | (data as u32);
    gem_write(base, GEM_PHYMGMT, val);

    let mut timeout = 10000u32;
    while timeout > 0 {
        let nwsr = gem_read(base, GEM_NWSR);
        if nwsr & (1 << 2) != 0 { break; }
        timeout -= 1;
    }
}

// ============================================================================
// GEM init
// ============================================================================

unsafe fn init_gem(s: &mut GemState) -> bool {
    let sys = &*s.syscalls;

    // RP1 GEM base address — VPU firmware maps RP1 to 0x1c_0000_0000 via the
    // PCIe outbound window. GEM core is at offset 0x10_0000 within RP1.
    // Stored as u64 to compile on 32-bit targets (module only runs on aarch64).
    s.gem_base = 0x1c_0010_0000u64 as usize;

    // Read GEM Module ID to verify access
    let mid = gem_read(s.gem_base, GEM_MID);
    if mid == 0 || mid == 0xFFFF_FFFF {
        log_msg(sys, b"[rp1_gem] GEM not accessible (reads 0 or 0xFFFFFFFF)");
        return false;
    }

    // Create DMA ring
    let mut ring_arg = [0u8; 8];
    let p = ring_arg.as_mut_ptr();
    write_volatile(p as *mut u16, RX_DESC_COUNT.to_le());
    write_volatile(p.add(2) as *mut u16, TX_DESC_COUNT.to_le());
    write_volatile(p.add(4) as *mut u16, BUF_SIZE.to_le());
    write_volatile(p.add(6) as *mut u16, BUF_COUNT.to_le());
    let ring_handle = (sys.dev_call)(-1, NIC_RING_CREATE, ring_arg.as_mut_ptr(), 8);
    if ring_handle < 0 {
        log_msg(sys, b"[rp1_gem] RING_CREATE failed");
        return false;
    }
    s.ring_handle = ring_handle;

    // Get ring info
    let mut info = [0u8; 32];
    let info_rc = (sys.dev_call)(ring_handle, NIC_RING_INFO, info.as_mut_ptr(), 32);
    if info_rc < 0 {
        log_msg(sys, b"[rp1_gem] RING_INFO failed");
        return false;
    }
    let ip = info.as_ptr();
    s.rx_desc_addr = u64::from_le_bytes([
        read_volatile(ip), read_volatile(ip.add(1)),
        read_volatile(ip.add(2)), read_volatile(ip.add(3)),
        read_volatile(ip.add(4)), read_volatile(ip.add(5)),
        read_volatile(ip.add(6)), read_volatile(ip.add(7)),
    ]);
    s.rx_desc_count = u16::from_le_bytes([read_volatile(ip.add(8)), read_volatile(ip.add(9))]);
    s.tx_desc_addr = u64::from_le_bytes([
        read_volatile(ip.add(10)), read_volatile(ip.add(11)),
        read_volatile(ip.add(12)), read_volatile(ip.add(13)),
        read_volatile(ip.add(14)), read_volatile(ip.add(15)),
        read_volatile(ip.add(16)), read_volatile(ip.add(17)),
    ]);
    s.tx_desc_count = u16::from_le_bytes([read_volatile(ip.add(18)), read_volatile(ip.add(19))]);
    s.buf_pool_addr = u64::from_le_bytes([
        read_volatile(ip.add(20)), read_volatile(ip.add(21)),
        read_volatile(ip.add(22)), read_volatile(ip.add(23)),
        read_volatile(ip.add(24)), read_volatile(ip.add(25)),
        read_volatile(ip.add(26)), read_volatile(ip.add(27)),
    ]);
    s.buf_size = u16::from_le_bytes([read_volatile(ip.add(28)), read_volatile(ip.add(29))]);
    s.buf_count = u16::from_le_bytes([read_volatile(ip.add(30)), read_volatile(ip.add(31))]);

    // Reformat descriptors in Cadence GEM native layout
    init_rx_descriptors(s);
    init_tx_descriptors(s);

    // Program GEM registers
    let base = s.gem_base;

    // Disable RX/TX during configuration
    gem_write(base, GEM_NWCTRL, 0);

    // Clear stats
    gem_write(base, GEM_NWCTRL, NWCTRL_CLRSTAT);
    gem_write(base, GEM_NWCTRL, 0);

    // Clear any pending status
    gem_write(base, GEM_RXSTATUS, 0xF);
    gem_write(base, GEM_TXSTATUS, 0xFF);
    let _ = gem_read(base, GEM_ISR); // read-to-clear

    // Network config: GbE, full duplex, 128-bit data bus, MDC /224,
    // unicast hash enable. RX checksum offload disabled (software stack verifies).
    // 0x00d40502 = FD|UNI_HASH|GBE|MDC_DIV5|DBW128
    let nwcfg: u32 = 0x00d40502 & !(1 << 24);
    gem_write(base, GEM_NWCFG, nwcfg);

    // DMA config: RX buffer size in [23:16], plus fixed burst/RX buf/TX config, 64-bit bus.
    // 0x0F1F = FBLDO(0x1F)|RXBMS(3)|TX_PBUF|TX_CSUM
    let dmacfg = ((BUF_SIZE as u32 >> 6) << DMACFG_RXBUF_SIZE_SHIFT)
        | 0x0F1F
        | DMACFG_ADDR64;
    gem_write(base, GEM_DMACFG, dmacfg);

    // Set RX/TX queue base addresses (64-bit: write high first, then low)
    let rx_dma = s.rx_desc_addr + DMA_OFFSET;
    let tx_dma = s.tx_desc_addr + DMA_OFFSET;
    gem_write(base, GEM_RBQPH, (rx_dma >> 32) as u32);
    gem_write(base, GEM_RXQBASE, rx_dma as u32);

    gem_write(base, GEM_TBQPH, (tx_dma >> 32) as u32);
    gem_write(base, GEM_TXQBASE, tx_dma as u32);

    // Set MAC address
    s.mac = DEFAULT_MAC;
    let mac_lo = (s.mac[0] as u32) | ((s.mac[1] as u32) << 8)
        | ((s.mac[2] as u32) << 16) | ((s.mac[3] as u32) << 24);
    let mac_hi = (s.mac[4] as u32) | ((s.mac[5] as u32) << 8);
    gem_write(base, GEM_SA1B, mac_lo);
    gem_write(base, GEM_SA1T, mac_hi);

    // Clear hash filter
    gem_write(base, GEM_HASHBOT, 0);
    gem_write(base, GEM_HASHTOP, 0);

    // Select RGMII mode and enable TX clock via USRIO register
    // Bit 0 = GEM_RGMII (RGMII mode)
    // Bit 1 = GEM_CLKEN (clock enable — drives RGMII TX clock from core)
    gem_write(base, GEM_USRIO, 0x03);

    // Disable all interrupts (poll-mode driver)
    gem_write(base, GEM_IDR, 0xFFFF_FFFF);

    // Enable RX + TX + MDIO
    gem_write(base, GEM_NWCTRL, NWCTRL_RXEN | NWCTRL_TXEN | NWCTRL_MDIO_EN);

    // Configure RP1 eth_cfg wrapper for RGMII
    // ETH_CFG_BASE = GEM_BASE + 0x4000 (RP1 datasheet section 7.1)
    let cfg_base = base + 0x4000;

    // Enable the RGMII 125MHz clock in the RP1 clock controller.
    // CLK_ETH_CTRL at offset 0x64, bit 11 = ENABLE
    let clk_base = 0x1c_0001_8000u64 as usize;
    let clk_eth_ctrl = read_volatile((clk_base + 0x64) as *const u32);

    if clk_eth_ctrl & (1 << 11) == 0 {
        // Use atomic set alias (base + 0x2000) to set bit 11 without RMW
        let clk_eth_ctrl_set = clk_base + 0x2000 + 0x64;
        write_volatile(clk_eth_ctrl_set as *mut u32, 1 << 11);
    }

    // Also ensure CLK_ETH_TSU is enabled (offset 0x134, bit 11)
    let clk_tsu_ctrl = read_volatile((clk_base + 0x134) as *const u32);
    if clk_tsu_ctrl & (1 << 11) == 0 {
        let clk_tsu_ctrl_set = clk_base + 0x2000 + 0x134;
        write_volatile(clk_tsu_ctrl_set as *mut u32, 1 << 11);
    }

    // CLKGEN register (offset 0x14) — RP1 datasheet section 7.1 Table 139:
    //   bit 7: ENABLE, bit 3: SPEED_OVERRIDE_EN, bits 1:0: SPEED_OVERRIDE
    // PHY provides TX and RX delays (rgmii-id) — TXCLKDELEN=0.
    let cfg_clkgen_val: u32 =
          (1 << 7)   // ENABLE: start clock generator
        | (1 << 3)   // SPEED_OVERRIDE_EN: use our speed, not MAC auto
        | 2;          // SPEED_OVERRIDE = 1000M (GbE)
    write_volatile((cfg_base + 0x14) as *mut u32, cfg_clkgen_val);

    // CLK2FC register (offset 0x18) — SEL = rgmii_tx_clk
    write_volatile((cfg_base + 0x18) as *mut u32, 1);

    // Probe PHY via MDIO. BCM54213PE is typically at address 1 on Pi 5.
    let mut phy_addr = 0u8;
    let mut phy_found = false;
    while phy_addr < 4 {
        let id1 = mdio_read(base, phy_addr, 2);
        let id2 = mdio_read(base, phy_addr, 3);
        let _ = id2;
        if id1 != 0xFFFF && id1 != 0x0000 {
            phy_found = true;
            break;
        }
        phy_addr += 1;
    }

    if phy_found {
        // Restart auto-negotiation: set BMCR bit 9 (AN enable) + bit 12 (AN restart)
        let bmcr = mdio_read(base, phy_addr, 0);
        let new_bmcr = bmcr | (1 << 12) | (1 << 9);
        mdio_write(base, phy_addr, 0, new_bmcr);
    }

    // Clear OD (output disable) on RGMII pads if needed
    // Pad bits: [7]=OD, [6]=IE, [5:4]=DRIVE, [3]=PUE
    let pads_eth = 0x1c_000f_c000u64 as usize;
    let mut i = 1usize;
    while i < 15 {
        let val = read_volatile((pads_eth + i * 4) as *const u32);
        if val & 0x80 != 0 {
            let new_val = (val & !0x80) | 0x40;
            write_volatile((pads_eth + i * 4) as *mut u32, new_val);
        }
        i += 1;
    }

    s.phase = 1; // wait_link
    true
}

// ============================================================================
// Descriptor initialization (GEM native format)
// ============================================================================

/// Initialize RX descriptors in Cadence GEM 64-bit format.
/// Each descriptor: [addr_lo | flags, ctrl, addr_hi, reserved] = 16 bytes.
/// ownership bit 0 of word 0: 0 = owned by GEM (free buffer).
unsafe fn init_rx_descriptors(s: &GemState) {
    let mut i = 0u16;
    while i < s.rx_desc_count {
        let desc_base = s.rx_desc_addr as usize + (i as usize) * 16;
        // DMA address = ARM physical + DMA_OFFSET (for PCIe inbound translation)
        let buf_dma = s.buf_pool_addr + (i as u64) * (s.buf_size as u64) + DMA_OFFSET;

        // Word 0: buffer address low [31:2], wrap [1], ownership [0]=0 (GEM-owned)
        let mut word0 = (buf_dma as u32) & 0xFFFF_FFFC; // clear bits 0-1
        if i == s.rx_desc_count - 1 {
            word0 |= RX_DESC_WRAP; // bit 1 = wrap on last descriptor
        }
        write_volatile(desc_base as *mut u32, word0);

        // Word 1: cleared (GEM writes length/status here)
        write_volatile((desc_base + 4) as *mut u32, 0);

        // Word 2: buffer address high (DMA address)
        write_volatile((desc_base + 8) as *mut u32, (buf_dma >> 32) as u32);

        // Word 3: reserved
        write_volatile((desc_base + 12) as *mut u32, 0);

        i += 1;
    }
}

/// Initialize TX descriptors in Cadence GEM 64-bit format.
/// All TX descriptors start as "used" (owned by SW) until we submit frames.
unsafe fn init_tx_descriptors(s: &GemState) {
    let mut i = 0u16;
    while i < s.tx_desc_count {
        let desc_base = s.tx_desc_addr as usize + (i as usize) * 16;

        // Word 0: buffer address (will be set on submit)
        write_volatile(desc_base as *mut u32, 0);

        // Word 1: used=1 (SW-owned), wrap on last
        let mut word1 = TX_DESC_USED;
        if i == s.tx_desc_count - 1 {
            word1 |= TX_DESC_WRAP;
        }
        write_volatile((desc_base + 4) as *mut u32, word1);

        // Word 2: address high (set on submit)
        write_volatile((desc_base + 8) as *mut u32, 0);

        // Word 3: reserved
        write_volatile((desc_base + 12) as *mut u32, 0);

        i += 1;
    }
}

// ============================================================================
// RX/TX poll
// ============================================================================

unsafe fn poll_rx(s: &mut GemState) {
    if s.out_chan < 0 || s.rx_desc_count == 0 { return; }
    let sys = &*s.syscalls;

    let mut processed = 0u32;
    while processed < s.rx_desc_count as u32 {
        let idx = (s.rx_tail % s.rx_desc_count) as usize;
        let desc_base = s.rx_desc_addr as usize + idx * 16;

        // Word 0: bit 0 = ownership. 1 = GEM has written a frame (SW-owned).
        let word0 = read_volatile(desc_base as *const u32);
        if word0 & RX_DESC_OWNERSHIP == 0 {
            break; // Still owned by GEM — no frame yet
        }

        // Word 1: bits [12:0] = frame length
        let word1 = read_volatile((desc_base + 4) as *const u32);
        let len = (word1 & RX_DESC_LEN_MASK) as usize;

        if len > 0 && len <= MAX_FRAME {
            let buf_addr = s.buf_pool_addr as usize + idx * s.buf_size as usize;
            let buf_ptr = buf_addr as *const u8;

            (sys.channel_write)(s.out_chan, buf_ptr, len);
            s.rx_packets = s.rx_packets.wrapping_add(1);
        }

        // Return descriptor to GEM: clear ownership, set DMA buffer address, preserve wrap
        let buf_dma = s.buf_pool_addr + (idx as u64) * (s.buf_size as u64) + DMA_OFFSET;
        let mut new_word0 = (buf_dma as u32) & 0xFFFF_FFFC;
        if idx == (s.rx_desc_count - 1) as usize {
            new_word0 |= RX_DESC_WRAP;
        }
        // ownership bit 0 = 0 → owned by GEM again
        write_volatile(desc_base as *mut u32, new_word0);
        write_volatile((desc_base + 4) as *mut u32, 0); // clear status
        write_volatile((desc_base + 8) as *mut u32, (buf_dma >> 32) as u32); // addr high
        s.rx_tail = s.rx_tail.wrapping_add(1);
        processed += 1;
    }
}

unsafe fn poll_tx(s: &mut GemState) {
    if s.in_chan < 0 || s.tx_desc_count == 0 { return; }
    let sys = &*s.syscalls;

    // Reclaim completed TX descriptors
    while s.tx_tail != s.tx_head {
        let idx = (s.tx_tail % s.tx_desc_count) as usize;
        let desc_base = s.tx_desc_addr as usize + idx * 16;
        let word1 = read_volatile((desc_base + 4) as *const u32);
        // TX: used bit (31) set by GEM when transmission complete
        if word1 & TX_DESC_USED == 0 {
            break; // Not yet completed by GEM
        }
        s.tx_tail = s.tx_tail.wrapping_add(1);
    }

    // Submit new TX frames from input channel
    let used = s.tx_head.wrapping_sub(s.tx_tail);
    if used >= s.tx_desc_count {
        return; // Ring full
    }

    let idx = (s.tx_head % s.tx_desc_count) as usize;
    // TX buffers come from the second half of the buffer pool
    let buf_idx = s.rx_desc_count as usize + idx;
    if buf_idx >= s.buf_count as usize { return; }
    // CPU accesses buffer at ARM physical address; GEM uses DMA address
    let buf_arm = s.buf_pool_addr as usize + buf_idx * s.buf_size as usize;
    let buf_dma = buf_arm as u64 + DMA_OFFSET;
    let buf_ptr = buf_arm as *mut u8;

    let n = (sys.channel_read)(s.in_chan, buf_ptr, MAX_FRAME);
    if n <= 0 { return; }

    // Program TX descriptor in GEM format (use DMA addresses)
    let desc_base = s.tx_desc_addr as usize + idx * 16;

    // Word 0: buffer DMA address low
    write_volatile(desc_base as *mut u32, buf_dma as u32);

    // Word 2: buffer DMA address high (write before word 1 to avoid race)
    write_volatile((desc_base + 8) as *mut u32, (buf_dma >> 32) as u32);

    // Word 1: length [13:0], last [15], wrap [30], used=0 (GEM-owned)
    let mut word1 = (n as u32) & TX_DESC_LEN_MASK;
    word1 |= TX_DESC_LAST; // single-buffer frame
    if idx == (s.tx_desc_count - 1) as usize {
        word1 |= TX_DESC_WRAP;
    }
    // Note: used bit (31) is 0 → owned by GEM for transmission
    write_volatile((desc_base + 4) as *mut u32, word1);

    // Trigger TX start
    let base = s.gem_base;
    let ctrl = gem_read(base, GEM_NWCTRL);
    gem_write(base, GEM_NWCTRL, ctrl | NWCTRL_STARTTX);

    s.tx_head = s.tx_head.wrapping_add(1);
    s.tx_packets = s.tx_packets.wrapping_add(1);
}

/// Poll link status. Assumes link up after PHY auto-negotiation settle time.
unsafe fn check_link(s: &mut GemState) -> bool {
    s.link_poll_counter = s.link_poll_counter.wrapping_add(1);

    // Wait ~100 polls (at 1ms tick = 100ms) for link to settle
    s.link_poll_counter >= 100
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize { STATE_SIZE }

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    _state_size: usize,
    syscalls: *const SyscallTable,
) -> i32 {
    let s = unsafe { &mut *(state as *mut GemState) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.ctrl_chan = ctrl_chan;
    s.ring_handle = -1;
    s.gem_base = 0;
    s.rx_tail = 0;
    s.tx_head = 0;
    s.tx_tail = 0;
    s.phase = 0;
    s.step_count = 0;
    s.rx_packets = 0;
    s.tx_packets = 0;
    s.link_poll_counter = 0;
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut GemState);
    s.step_count = s.step_count.wrapping_add(1);

    match s.phase {
        0 => {
            // Phase 0: Initialize GEM
            if !init_gem(s) {
                return 0; // Continue, retry next step
            }
            // phase is now 1 (set by init_gem)
            0
        }
        1 => {
            // Phase 1: Wait for link
            if check_link(s) {
                // Send MAC announcement to downstream (ip module).
                // Frame format: dst=our_MAC, src=zeros, ethertype=0x0000.
                // The ip module's process_frame recognizes ethertype=0 as a
                // MAC announcement and extracts the destination MAC.
                if s.out_chan >= 0 {
                    let sys = &*s.syscalls;
                    let mut announce = [0u8; 14];
                    let ap = announce.as_mut_ptr();
                    // dst MAC = our MAC (bytes 0-5)
                    let mut m = 0usize;
                    while m < 6 {
                        write_volatile(ap.add(m), read_volatile(s.mac.as_ptr().add(m)));
                        m += 1;
                    }
                    // src MAC = zeros (bytes 6-11), ethertype = 0 (bytes 12-13)
                    // already zeroed
                    (sys.channel_write)(s.out_chan, ap, 14);
                }
                s.phase = 2;
                return 3; // StepOutcome::Ready
            }
            0
        }
        _ => {
            // Phase 2: Running — poll RX and TX
            poll_rx(s);
            poll_tx(s);

            // No diagnostic logging in the hot path — UART I/O blocks
            // the scheduler and causes frame loss from FIFO overruns.
            0
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

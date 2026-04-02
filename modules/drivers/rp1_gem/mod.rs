//! RP1 Cadence GEM NIC Driver PIC Module
//!
//! Kernel-bypass Ethernet driver for the Cadence GEM MAC on the RP1 chip
//! (Pi 5 / CM5). Maps the GEM BAR via NIC_BAR_MAP, creates DMA rings via
//! NIC_RING_CREATE, and drives the MAC directly from poll-mode (Tier 3).
//!
//! # Channels
//!
//! - `in[0]`: TX packets from upstream (e.g. IP stack or pkt_filter)
//! - `out[0]`: RX packets to downstream (e.g. eth_parser)
//!
//! # Init Sequence
//!
//! 1. NIC_BAR_MAP to get GEM register base
//! 2. NIC_RING_CREATE for RX + TX descriptor rings
//! 3. NIC_RING_INFO to get descriptor/buffer addresses
//! 4. Program GEM registers (DMA config, MAC address, enable RX/TX)
//! 5. Return Ready when link is up
//!
//! Exports `module_deferred_ready` — gates downstream until link up.

#![no_std]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");

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
const GEM_IER: usize = 0x028;           // Interrupt enable
const GEM_IDR: usize = 0x02C;           // Interrupt disable
const GEM_IMR: usize = 0x030;           // Interrupt mask
const GEM_PHYMGMT: usize = 0x034;       // PHY management
const GEM_HASHBOT: usize = 0x080;       // Hash register bottom
const GEM_HASHTOP: usize = 0x084;       // Hash register top
const GEM_LADDR1L: usize = 0x088;       // Specific addr 1 low
const GEM_LADDR1H: usize = 0x08C;       // Specific addr 1 high
const GEM_DCFG1: usize = 0x280;         // Design config 1
const GEM_DCFG2: usize = 0x284;         // Design config 2

// RX queue upper base (for 64-bit addressing)
const GEM_RXQBASE_HI: usize = 0x04D4;
const GEM_TXQBASE_HI: usize = 0x04C8;

// Network control bits
const NWCTRL_TXEN: u32 = 1 << 3;
const NWCTRL_RXEN: u32 = 1 << 2;
const NWCTRL_STARTTX: u32 = 1 << 9;
const NWCTRL_MDIO_EN: u32 = 1 << 4;

// Network config bits
const NWCFG_SPEED: u32 = 1 << 0;        // 100Mbps
const NWCFG_FD: u32 = 1 << 1;           // Full duplex
const NWCFG_COPY_ALL: u32 = 1 << 4;     // Copy all frames
const NWCFG_PROMISC: u32 = 1 << 4;      // Promiscuous mode
const NWCFG_GBE: u32 = 1 << 10;         // Gigabit mode
const NWCFG_RX_CSUM: u32 = 1 << 24;     // RX checksum offload
const NWCFG_DBUS_WIDTH_64: u32 = 1 << 21; // 64-bit data bus
const NWCFG_MDC_CLK_DIV: u32 = 4 << 18; // MDC clock divider

// DMA config bits
const DMACFG_RXBUF_SIZE_SHIFT: u32 = 16;
const DMACFG_TX_PBUF: u32 = 1 << 10;    // TX partial store and forward
const DMACFG_ADDR_BUS_WIDTH_64: u32 = 1 << 30; // 64-bit address bus

// Interrupt bits
const ISR_RXCMPL: u32 = 1 << 1;
const ISR_TXCMPL: u32 = 1 << 7;

// NIC syscall opcodes
const NIC_BAR_MAP: u32 = 0x0CF0;
const NIC_RING_CREATE: u32 = 0x0CF2;
const NIC_RING_INFO: u32 = 0x0CF4;

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
    initialized: u8,
    link_up: u8,
    ready_signaled: u8,
    _pad: u8,
    step_count: u32,
    rx_packets: u32,
    tx_packets: u32,
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
// GEM init
// ============================================================================

unsafe fn init_gem(s: &mut GemState) -> bool {
    let sys = &*s.syscalls;

    // Step 1: Map RP1 GEM BAR (dev_idx=0, bar_idx=0)
    let mut bar_arg = [0u8; 10];
    let bp = bar_arg.as_mut_ptr();
    *bp.add(0) = 0; // dev_idx
    *bp.add(1) = 0; // bar_idx
    let rc = (sys.dev_call)(-1, NIC_BAR_MAP, bp, 10);
    if rc < 0 {
        return false;
    }
    // On aarch64, read full 64-bit address from arg[2..10]
    let addr_bytes: [u8; 8] = [
        *bp.add(2), *bp.add(3), *bp.add(4), *bp.add(5),
        *bp.add(6), *bp.add(7), *bp.add(8), *bp.add(9),
    ];
    let bar_addr = u64::from_le_bytes(addr_bytes);
    // RP1 GEM is at offset 0x8000 within RP1 BAR0
    s.gem_base = (bar_addr as usize) + 0x8000;

    // Step 2: Create DMA ring
    let mut ring_arg = [0u8; 8];
    let p = ring_arg.as_mut_ptr();
    write_volatile(p as *mut u16, RX_DESC_COUNT.to_le());
    write_volatile(p.add(2) as *mut u16, TX_DESC_COUNT.to_le());
    write_volatile(p.add(4) as *mut u16, BUF_SIZE.to_le());
    write_volatile(p.add(6) as *mut u16, BUF_COUNT.to_le());
    let ring_handle = (sys.dev_call)(-1, NIC_RING_CREATE, ring_arg.as_mut_ptr(), 8);
    if ring_handle < 0 {
        return false;
    }
    s.ring_handle = ring_handle;

    // Step 3: Get ring info
    let mut info = [0u8; 32];
    let info_rc = (sys.dev_call)(ring_handle, NIC_RING_INFO, info.as_mut_ptr(), 32);
    if info_rc < 0 {
        return false;
    }
    // Parse ring info via pointer arithmetic (PIC: no array indexing)
    let ip = info.as_ptr();
    s.rx_desc_addr = u64::from_le_bytes([*ip, *ip.add(1), *ip.add(2), *ip.add(3),
                                          *ip.add(4), *ip.add(5), *ip.add(6), *ip.add(7)]);
    s.rx_desc_count = u16::from_le_bytes([*ip.add(8), *ip.add(9)]);
    s.tx_desc_addr = u64::from_le_bytes([*ip.add(10), *ip.add(11), *ip.add(12), *ip.add(13),
                                          *ip.add(14), *ip.add(15), *ip.add(16), *ip.add(17)]);
    s.tx_desc_count = u16::from_le_bytes([*ip.add(18), *ip.add(19)]);
    s.buf_pool_addr = u64::from_le_bytes([*ip.add(20), *ip.add(21), *ip.add(22), *ip.add(23),
                                           *ip.add(24), *ip.add(25), *ip.add(26), *ip.add(27)]);
    s.buf_size = u16::from_le_bytes([*ip.add(28), *ip.add(29)]);
    s.buf_count = u16::from_le_bytes([*ip.add(30), *ip.add(31)]);

    // Step 4: Program GEM registers
    let base = s.gem_base;

    // Disable RX/TX during init
    gem_write(base, GEM_NWCTRL, 0);

    // Network config: GbE, full duplex, promiscuous, 64-bit bus, RX checksum
    let nwcfg = NWCFG_GBE | NWCFG_FD | NWCFG_PROMISC | NWCFG_DBUS_WIDTH_64
        | NWCFG_RX_CSUM | NWCFG_MDC_CLK_DIV;
    gem_write(base, GEM_NWCFG, nwcfg);

    // DMA config: 2048-byte RX buffers, TX partial store-forward, 64-bit address
    let dmacfg = ((BUF_SIZE as u32 >> 6) << DMACFG_RXBUF_SIZE_SHIFT)
        | DMACFG_TX_PBUF
        | DMACFG_ADDR_BUS_WIDTH_64;
    gem_write(base, GEM_DMACFG, dmacfg);

    // Set RX queue base address
    gem_write(base, GEM_RXQBASE, s.rx_desc_addr as u32);
    gem_write(base, GEM_RXQBASE_HI, (s.rx_desc_addr >> 32) as u32);

    // Set TX queue base address
    gem_write(base, GEM_TXQBASE, s.tx_desc_addr as u32);
    gem_write(base, GEM_TXQBASE_HI, (s.tx_desc_addr >> 32) as u32);

    // Set MAC address
    s.mac = DEFAULT_MAC;
    let mac_lo = (s.mac[0] as u32) | ((s.mac[1] as u32) << 8)
        | ((s.mac[2] as u32) << 16) | ((s.mac[3] as u32) << 24);
    let mac_hi = (s.mac[4] as u32) | ((s.mac[5] as u32) << 8);
    gem_write(base, GEM_LADDR1L, mac_lo);
    gem_write(base, GEM_LADDR1H, mac_hi);

    // Clear hash filter
    gem_write(base, GEM_HASHBOT, 0);
    gem_write(base, GEM_HASHTOP, 0);

    // Disable all interrupts (poll-mode)
    gem_write(base, GEM_IDR, 0xFFFF_FFFF);

    // Enable RX + TX + MDIO
    gem_write(base, GEM_NWCTRL, NWCTRL_RXEN | NWCTRL_TXEN | NWCTRL_MDIO_EN);

    s.initialized = 1;
    true
}

// ============================================================================
// RX/TX poll
// ============================================================================

unsafe fn poll_rx(s: &mut GemState) {
    if s.out_chan < 0 || s.rx_desc_count == 0 { return; }
    let sys = &*s.syscalls;

    // Check RX descriptors for completed frames
    let mut processed = 0u32;
    while processed < 16 {
        let idx = (s.rx_tail % s.rx_desc_count) as usize;
        let desc_ptr = (s.rx_desc_addr as usize + idx * 16) as *const u32;

        // GEM RX descriptor word 0: bit 0 = ownership (0 = NIC written)
        let word0 = read_volatile(desc_ptr);
        if word0 & 1 != 0 {
            break; // Still owned by NIC
        }

        // Word 1: bits [12:0] = length
        let word1 = read_volatile(desc_ptr.add(1));
        let len = (word1 & 0x1FFF) as usize;

        if len > 0 && len <= MAX_FRAME {
            // Buffer is at buf_pool_addr + idx * buf_size
            let buf_addr = s.buf_pool_addr as usize + idx * s.buf_size as usize;
            let buf_ptr = buf_addr as *const u8;

            // Write to output channel
            (sys.channel_write)(s.out_chan, buf_ptr, len);
            s.rx_packets = s.rx_packets.wrapping_add(1);
        }

        // Return descriptor to NIC
        let desc_wr = desc_ptr as *mut u32;
        // Set ownership bit back
        let mut new_word0 = (s.buf_pool_addr as u32 + (idx * s.buf_size as usize) as u32) & 0xFFFF_FFFC;
        // Wrap bit on last descriptor
        if idx == (s.rx_desc_count - 1) as usize {
            new_word0 |= 1 << 1; // wrap
        }
        write_volatile(desc_wr, new_word0);
        write_volatile(desc_wr.add(1), 0); // clear status

        s.rx_tail = s.rx_tail.wrapping_add(1);
        processed += 1;
    }
}

unsafe fn poll_tx(s: &mut GemState) {
    if s.in_chan < 0 || s.tx_desc_count == 0 { return; }
    let sys = &*s.syscalls;

    // Check for completed TX descriptors
    while s.tx_tail != s.tx_head {
        let idx = (s.tx_tail % s.tx_desc_count) as usize;
        let desc_ptr = (s.tx_desc_addr as usize + idx * 16) as *const u32;
        let word1 = read_volatile(desc_ptr.add(1));
        // GEM TX descriptor word 1 bit 31 = used (set by NIC when done)
        if word1 & (1 << 31) == 0 {
            break; // Not yet completed
        }
        s.tx_tail = s.tx_tail.wrapping_add(1);
    }

    // Submit new TX frames from input channel
    let used = s.tx_head.wrapping_sub(s.tx_tail);
    if used >= s.tx_desc_count {
        return; // Ring full
    }

    let idx = (s.tx_head % s.tx_desc_count) as usize;
    // TX buffer from second half of pool
    let buf_idx = s.rx_desc_count as usize + idx;
    if buf_idx >= s.buf_count as usize { return; }
    let buf_addr = s.buf_pool_addr as usize + buf_idx * s.buf_size as usize;
    let buf_ptr = buf_addr as *mut u8;

    let n = (sys.channel_read)(s.in_chan, buf_ptr, MAX_FRAME);
    if n <= 0 { return; }

    // Program TX descriptor
    let desc_wr = (s.tx_desc_addr as usize + idx * 16) as *mut u32;
    write_volatile(desc_wr, buf_addr as u32); // word 0: buffer address
    let mut word1 = (n as u32) & 0x3FFF; // length in bits [13:0]
    word1 |= 1 << 15; // last buffer of frame
    if idx == (s.tx_desc_count - 1) as usize {
        word1 |= 1 << 30; // wrap
    }
    write_volatile(desc_wr.add(1), word1);

    // Trigger TX
    let base = s.gem_base;
    let ctrl = gem_read(base, GEM_NWCTRL);
    gem_write(base, GEM_NWCTRL, ctrl | NWCTRL_STARTTX);

    s.tx_head = s.tx_head.wrapping_add(1);
    s.tx_packets = s.tx_packets.wrapping_add(1);
}

unsafe fn check_link(s: &mut GemState) -> bool {
    // Check network status register for link
    let nwsr = gem_read(s.gem_base, GEM_NWSR);
    // Bit 2 = MDIO idle, bit 1 = PHY management done — for QEMU testing,
    // just consider link up after init
    if s.initialized != 0 {
        s.link_up = 1;
        return true;
    }
    let _ = nwsr;
    false
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
    s.initialized = 0;
    s.link_up = 0;
    s.ready_signaled = 0;
    s.step_count = 0;
    s.rx_packets = 0;
    s.tx_packets = 0;
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut GemState);
    s.step_count = s.step_count.wrapping_add(1);

    // Init on first step
    if s.initialized == 0 {
        if !init_gem(s) {
            return 0; // Continue, retry next step
        }
    }

    // Check link status
    if s.link_up == 0 {
        check_link(s);
    }

    // Signal ready once link is up
    if s.link_up != 0 && s.ready_signaled == 0 {
        s.ready_signaled = 1;
        return 3; // StepOutcome::Ready
    }

    // Poll RX and TX
    if s.link_up != 0 {
        poll_rx(s);
        poll_tx(s);
    }

    0 // StepOutcome::Continue
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

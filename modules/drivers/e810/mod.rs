//! Intel E810 100GbE NIC Driver PIC Module (skeleton)
//!
//! Kernel-bypass Ethernet driver for Intel E810-XXVDA2 / E810-CQDA2.
//! Maps BARs via NIC_BAR_MAP, creates DMA rings, drives the NIC in poll mode.
//!
//! # Status
//!
//! Skeleton — register constants and init sequence are defined.
//! RX/TX poll is stubbed pending hardware validation.
//!
//! # Channels
//!
//! - `in[0]`: TX packets from upstream
//! - `out[0]`: RX packets to downstream
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
// Intel E810 Register Offsets (BAR0)
// ============================================================================

// General registers
const E810_PFGEN_CTRL: usize = 0x0091_0000;    // PF General Control
const E810_PFGEN_STATUS: usize = 0x0091_0004;  // PF General Status
const E810_GLGEN_STAT: usize = 0x000B_612C;    // Global Status

// Admin queue
const E810_PF_ATQBAL: usize = 0x0008_0000;     // Admin TX Queue Base Low
const E810_PF_ATQBAH: usize = 0x0008_0100;     // Admin TX Queue Base High
const E810_PF_ATQLEN: usize = 0x0008_0200;     // Admin TX Queue Length
const E810_PF_ATQH: usize = 0x0008_0300;       // Admin TX Queue Head
const E810_PF_ATQT: usize = 0x0008_0400;       // Admin TX Queue Tail
const E810_PF_ARQBAL: usize = 0x0008_0080;     // Admin RX Queue Base Low
const E810_PF_ARQBAH: usize = 0x0008_0180;     // Admin RX Queue Base High
const E810_PF_ARQLEN: usize = 0x0008_0280;     // Admin RX Queue Length
const E810_PF_ARQH: usize = 0x0008_0380;       // Admin RX Queue Head
const E810_PF_ARQT: usize = 0x0008_0480;       // Admin RX Queue Tail

// TX/RX queue registers
const E810_QTX_COMM_DBELL: usize = 0x0010_0000; // TX doorbell (per-queue stride 4)
const E810_QRX_TAIL: usize = 0x0012_0000;       // RX tail (per-queue stride 4)

// LAN TX queue context
const E810_QINT_TQCTL: usize = 0x0014_0000;     // TX Queue Interrupt Cause Control
const E810_QINT_RQCTL: usize = 0x0015_0000;     // RX Queue Interrupt Cause Control

// Link status
const E810_PRTMAC_LINK: usize = 0x001E_2040;    // MAC link status (simplified)

// NIC syscall opcodes
const NIC_BAR_MAP: u32 = 0x0CF0;
const NIC_RING_CREATE: u32 = 0x0CF2;
const NIC_RING_INFO: u32 = 0x0CF4;

// ============================================================================
// Constants
// ============================================================================

const RX_DESC_COUNT: u16 = 128;
const TX_DESC_COUNT: u16 = 128;
const BUF_SIZE: u16 = 2048;
const BUF_COUNT: u16 = 256;

const MAX_FRAME: usize = 1514;
const STATE_SIZE: usize = 256;

const DEFAULT_MAC: [u8; 6] = [0x02, 0xE8, 0x10, 0x00, 0x00, 0x01];

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct E810State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    bar_base: usize,
    ring_handle: i32,
    rx_desc_addr: u64,
    rx_desc_count: u16,
    tx_desc_addr: u64,
    tx_desc_count: u16,
    buf_pool_addr: u64,
    buf_size: u16,
    buf_count: u16,
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
unsafe fn mmio_read(base: usize, offset: usize) -> u32 {
    read_volatile((base + offset) as *const u32)
}

#[inline(always)]
unsafe fn mmio_write(base: usize, offset: usize, val: u32) {
    write_volatile((base + offset) as *mut u32, val);
}

// ============================================================================
// E810 init (skeleton)
// ============================================================================

unsafe fn init_e810(s: &mut E810State) -> bool {
    let sys = &*s.syscalls;

    // Map BAR0 (dev_idx: scan for E810 at idx 0)
    let mut bar_arg = [0u8; 10];
    let bp = bar_arg.as_mut_ptr();
    *bp.add(0) = 0; // dev_idx
    *bp.add(1) = 0; // bar_idx
    let rc = (sys.dev_call)(-1, NIC_BAR_MAP, bp, 10);
    if rc < 0 {
        return false;
    }
    let addr_bytes: [u8; 8] = [
        *bp.add(2), *bp.add(3), *bp.add(4), *bp.add(5),
        *bp.add(6), *bp.add(7), *bp.add(8), *bp.add(9),
    ];
    s.bar_base = u64::from_le_bytes(addr_bytes) as usize;

    // Create DMA ring
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

    // Get ring info
    let mut info = [0u8; 32];
    let info_rc = (sys.dev_call)(ring_handle, NIC_RING_INFO, info.as_mut_ptr(), 32);
    if info_rc < 0 {
        return false;
    }
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

    // E810 init: PF reset + admin queue setup (skeleton)
    // In a full implementation this would:
    // 1. Assert PF reset via PFGEN_CTRL
    // 2. Wait for reset complete
    // 3. Setup admin TX/RX queues
    // 4. Issue admin queue commands for VSI, queue context, RSS
    // 5. Program LAN TX/RX queue context
    // 6. Enable queues

    // Disable all interrupts (poll mode)
    mmio_write(s.bar_base, E810_QINT_TQCTL, 0);
    mmio_write(s.bar_base, E810_QINT_RQCTL, 0);

    s.mac = DEFAULT_MAC;
    s.initialized = 1;
    true
}

// ============================================================================
// RX/TX poll (skeleton — returns immediately for now)
// ============================================================================

unsafe fn poll_rx(s: &mut E810State) {
    // E810 RX: check completion queue entries at rx_desc_addr
    // Each descriptor is 32 bytes (16B addr + 16B writeback)
    // For now this is a skeleton — real hardware would read
    // completed descriptors and forward to out_chan.
    let _ = s;
}

unsafe fn poll_tx(s: &mut E810State) {
    // E810 TX: read from in_chan, write to TX descriptor ring,
    // ring doorbell at QTX_COMM_DBELL
    let _ = s;
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
    let s = unsafe { &mut *(state as *mut E810State) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.ctrl_chan = ctrl_chan;
    s.ring_handle = -1;
    s.bar_base = 0;
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
    let s = &mut *(state as *mut E810State);
    s.step_count = s.step_count.wrapping_add(1);

    if s.initialized == 0 {
        if !init_e810(s) {
            return 0;
        }
    }

    // For skeleton: consider link up after init
    if s.link_up == 0 && s.initialized != 0 {
        s.link_up = 1;
    }

    if s.link_up != 0 && s.ready_signaled == 0 {
        s.ready_signaled = 1;
        return 3; // Ready
    }

    if s.link_up != 0 {
        poll_rx(s);
        poll_tx(s);
    }

    0 // Continue
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

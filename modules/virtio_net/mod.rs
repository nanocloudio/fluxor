//! Virtio-net PIC Module — QEMU virt aarch64 network driver
//!
//! Exchanges Ethernet frames with the QEMU virtual NIC via virtio-mmio.
//! Analogous to cyw43 on RP: a driver module that bridges raw frames
//! to/from the ip module via channels.
//!
//! # Channels
//!
//! - `in[0]`: Ethernet frames from ip module (for TX)
//! - `out[0]`: Ethernet frames to ip module (from RX)
//!
//! # Init Sequence
//!
//! 1. Scan MMIO slots (0x0a000000, stride 0x200) for device_id=1 (net)
//! 2. Virtio handshake: reset → ack → driver → features → driver_ok
//! 3. Setup RX + TX virtqueues (legacy v1)
//! 4. Pre-fill RX descriptors
//! 5. Send MAC announcement (ethertype 0x0000) on out_chan
//! 6. Poll: RX used ring → out_chan, in_chan → TX available ring

#![no_std]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const QUEUE_SIZE: usize = 16;
const NET_HDR_SIZE: usize = 10;
const MAX_FRAME_SIZE: usize = 1514;
const BUF_SIZE: usize = NET_HDR_SIZE + MAX_FRAME_SIZE;

// virtio-mmio register offsets
const MAGIC_VALUE: usize = 0x000;
const VERSION: usize = 0x004;
const DEVICE_ID: usize = 0x008;
const DEVICE_FEATURES: usize = 0x010;
const DEVICE_FEATURES_SEL: usize = 0x014;
const DRIVER_FEATURES: usize = 0x020;
const DRIVER_FEATURES_SEL: usize = 0x024;
const GUEST_PAGE_SIZE: usize = 0x028;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM_MAX: usize = 0x034;
const QUEUE_NUM: usize = 0x038;
const QUEUE_PFN: usize = 0x040;
const QUEUE_ALIGN_REG: usize = 0x03c;
const QUEUE_NOTIFY: usize = 0x050;
const INTERRUPT_STATUS: usize = 0x060;
const INTERRUPT_ACK: usize = 0x064;
const STATUS_REG: usize = 0x070;
const CONFIG_SPACE: usize = 0x100;

const STATUS_ACK: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VRING_DESC_F_WRITE: u16 = 2;

// Legacy virtqueue layout sizes (QUEUE_SIZE=16):
//   desc: 16 * 16 = 256 bytes
//   avail: 6 + 2*16 = 38 bytes
//   pad to 4096
//   used: 6 + 8*16 = 134 bytes
const VQ_DESC_SIZE: usize = QUEUE_SIZE * 16;  // 256
const VQ_AVAIL_SIZE: usize = 6 + 2 * QUEUE_SIZE;  // 38
const VQ_USED_SIZE: usize = 6 + 8 * QUEUE_SIZE;  // 134
// Total per virtqueue: 4096 (desc+avail+pad) + 134 (used) = 4230
// With 4096-alignment padding: up to 4096 extra
const VQ_TOTAL: usize = 4096 + VQ_USED_SIZE + 2; // +2 for last_used_idx

// State layout offsets (computed in module_new for alignment)
// Metadata (256 bytes) → RXQ (4096-aligned) → TXQ (4096-aligned) → RX_BUFS → TX_BUF
const META_SIZE: usize = 256;
const RX_BUFS_TOTAL: usize = QUEUE_SIZE * BUF_SIZE; // 16 * 1524 = 24384
const TX_BUF_TOTAL: usize = BUF_SIZE; // 1524

// Total state: metadata + alignment + 2 queues + buffers
const STATE_SIZE: usize = META_SIZE + 4096 + VQ_TOTAL + 4096 + VQ_TOTAL + RX_BUFS_TOTAL + TX_BUF_TOTAL;

// ============================================================================
// State (in metadata region)
// ============================================================================

#[repr(C)]
struct VirtioNetState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    device_base: usize,
    mac_addr: [u8; 6],
    initialized: u8,
    mac_announced: u8,
    // Computed pointers into state buffer
    rxq_ptr: usize,
    txq_ptr: usize,
    rx_bufs_ptr: usize,
    tx_buf_ptr: usize,
    // Queue tracking
    rx_last_used: u16,
    _pad0: u16,
    step_count: u32,
}

// ============================================================================
// MMIO helpers
// ============================================================================

unsafe fn mmio_read(base: usize, offset: usize) -> u32 {
    read_volatile((base + offset) as *const u32)
}

unsafe fn mmio_write(base: usize, offset: usize, val: u32) {
    write_volatile((base + offset) as *mut u32, val)
}

// ============================================================================
// Virtqueue helpers (operate on raw pointers)
// ============================================================================

// Descriptor: 16 bytes each at vq_base + i*16
// [addr: u64, len: u32, flags: u16, next: u16]
unsafe fn desc_set(vq: usize, i: usize, addr: u64, len: u32, flags: u16) {
    let p = vq + i * 16;
    write_volatile(p as *mut u64, addr);
    write_volatile((p + 8) as *mut u32, len);
    write_volatile((p + 12) as *mut u16, flags);
    write_volatile((p + 14) as *mut u16, 0); // next
}

// Avail ring: at vq_base + VQ_DESC_SIZE
// [flags: u16, idx: u16, ring[N]: u16]
unsafe fn avail_idx(vq: usize) -> u16 {
    read_volatile((vq + VQ_DESC_SIZE + 2) as *const u16)
}

unsafe fn avail_set_idx(vq: usize, idx: u16) {
    write_volatile((vq + VQ_DESC_SIZE + 2) as *mut u16, idx)
}

unsafe fn avail_ring_set(vq: usize, slot: usize, val: u16) {
    write_volatile((vq + VQ_DESC_SIZE + 4 + slot * 2) as *mut u16, val)
}

// Used ring: at vq_base + 4096
// [flags: u16, idx: u16, ring[N]: {id: u32, len: u32}]
unsafe fn used_idx(vq: usize) -> u16 {
    read_volatile((vq + 4096 + 2) as *const u16)
}

unsafe fn used_ring_id(vq: usize, slot: usize) -> u32 {
    read_volatile((vq + 4096 + 4 + slot * 8) as *const u32)
}

unsafe fn used_ring_len(vq: usize, slot: usize) -> u32 {
    read_volatile((vq + 4096 + 4 + slot * 8 + 4) as *const u32)
}

// last_used_idx stored after used ring
unsafe fn last_used(vq: usize) -> u16 {
    read_volatile((vq + 4096 + VQ_USED_SIZE) as *const u16)
}

unsafe fn set_last_used(vq: usize, val: u16) {
    write_volatile((vq + 4096 + VQ_USED_SIZE) as *mut u16, val)
}

// ============================================================================
// Device init
// ============================================================================

unsafe fn find_net_device() -> usize {
    let mut addr = 0x0a00_0000usize;
    let mut i = 0;
    while i < 32 {
        let magic = read_volatile(addr as *const u32);
        let device_id = read_volatile((addr + 0x008) as *const u32);
        if magic == 0x74726976 && device_id == 1 {
            return addr;
        }
        addr += 0x200;
        i += 1;
    }
    0
}

unsafe fn init_device(s: &mut VirtioNetState) -> bool {
    let base = find_net_device();
    if base == 0 { return false; }
    s.device_base = base;

    let ver = mmio_read(base, VERSION);
    if ver != 1 && ver != 2 { return false; }

    // Reset + handshake
    mmio_write(base, STATUS_REG, 0);
    mmio_write(base, STATUS_REG, STATUS_ACK);
    mmio_write(base, STATUS_REG, STATUS_ACK | STATUS_DRIVER);

    // Features
    mmio_write(base, DEVICE_FEATURES_SEL, 0);
    let features = mmio_read(base, DEVICE_FEATURES);
    mmio_write(base, DRIVER_FEATURES_SEL, 0);
    mmio_write(base, DRIVER_FEATURES, features & VIRTIO_NET_F_MAC);

    // Legacy: set guest page size
    if ver == 1 {
        mmio_write(base, GUEST_PAGE_SIZE, 4096);
    }

    // Setup RX queue
    mmio_write(base, QUEUE_SEL, 0);
    let max = mmio_read(base, QUEUE_NUM_MAX);
    if max == 0 || (max as usize) < QUEUE_SIZE { return false; }
    mmio_write(base, QUEUE_NUM, QUEUE_SIZE as u32);
    mmio_write(base, QUEUE_ALIGN_REG, 4096);
    mmio_write(base, QUEUE_PFN, (s.rxq_ptr as u64 / 4096) as u32);

    // Setup TX queue
    mmio_write(base, QUEUE_SEL, 1);
    let max = mmio_read(base, QUEUE_NUM_MAX);
    if max == 0 || (max as usize) < QUEUE_SIZE { return false; }
    mmio_write(base, QUEUE_NUM, QUEUE_SIZE as u32);
    mmio_write(base, QUEUE_ALIGN_REG, 4096);
    mmio_write(base, QUEUE_PFN, (s.txq_ptr as u64 / 4096) as u32);

    // Pre-fill RX descriptors
    let mut i = 0usize;
    while i < QUEUE_SIZE {
        let buf_addr = s.rx_bufs_ptr + i * BUF_SIZE;
        desc_set(s.rxq_ptr, i, buf_addr as u64, BUF_SIZE as u32, VRING_DESC_F_WRITE);
        avail_ring_set(s.rxq_ptr, i, i as u16);
        i += 1;
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    avail_set_idx(s.rxq_ptr, QUEUE_SIZE as u16);

    // Read MAC
    if features & VIRTIO_NET_F_MAC != 0 {
        let mp = s.mac_addr.as_mut_ptr();
        i = 0;
        while i < 6 {
            *mp.add(i) = read_volatile((base + CONFIG_SPACE + i) as *const u8);
            i += 1;
        }
    }

    // Driver OK
    mmio_write(base, STATUS_REG, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);

    // Notify RX queue
    mmio_write(base, QUEUE_NOTIFY, 0);

    s.initialized = 1;
    true
}

// ============================================================================
// RX/TX
// ============================================================================

unsafe fn poll_rx(s: &mut VirtioNetState) {
    if s.initialized == 0 || s.out_chan < 0 { return; }
    let sys = &*s.syscalls;

    let mut count = 0;
    while count < 4 {
        let ui = used_idx(s.rxq_ptr);
        let lu = last_used(s.rxq_ptr);
        if lu == ui { break; }

        let slot = (lu as usize) % QUEUE_SIZE;
        let desc_idx = used_ring_id(s.rxq_ptr, slot) as usize;
        let total_len = used_ring_len(s.rxq_ptr, slot) as usize;

        if total_len > NET_HDR_SIZE && desc_idx < QUEUE_SIZE {
            let frame_ptr = (s.rx_bufs_ptr + desc_idx * BUF_SIZE + NET_HDR_SIZE) as *const u8;
            let frame_len = total_len - NET_HDR_SIZE;
            let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
            if poll > 0 && (poll as u8 & POLL_OUT) != 0 {
                (sys.channel_write)(s.out_chan, frame_ptr, frame_len);
            }
        }

        // Recycle descriptor
        set_last_used(s.rxq_ptr, lu.wrapping_add(1));
        let ai = avail_idx(s.rxq_ptr);
        let avail_slot = (ai as usize) % QUEUE_SIZE;
        avail_ring_set(s.rxq_ptr, avail_slot, desc_idx as u16);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        avail_set_idx(s.rxq_ptr, ai.wrapping_add(1));
        mmio_write(s.device_base, QUEUE_NOTIFY, 0);

        count += 1;
    }
}

unsafe fn poll_tx(s: &mut VirtioNetState) {
    if s.initialized == 0 || s.in_chan < 0 { return; }
    let sys = &*s.syscalls;

    // Read one frame from in_chan and transmit
    let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
    if poll <= 0 || (poll as u8 & POLL_IN) == 0 { return; }

    let tx_buf = s.tx_buf_ptr as *mut u8;
    // Zero virtio-net header
    let mut i = 0;
    while i < NET_HDR_SIZE {
        write_volatile(tx_buf.add(i), 0);
        i += 1;
    }
    // Read frame after header
    let r = (sys.channel_read)(s.in_chan, tx_buf.add(NET_HDR_SIZE), MAX_FRAME_SIZE);
    if r <= 0 { return; }

    let total = NET_HDR_SIZE + r as usize;

    // Submit to TX queue
    let txq = s.txq_ptr;
    desc_set(txq, 0, tx_buf as u64, total as u32, 0);
    let ai = avail_idx(txq);
    avail_ring_set(txq, (ai as usize) % QUEUE_SIZE, 0);
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    avail_set_idx(txq, ai.wrapping_add(1));
    mmio_write(s.device_base, QUEUE_NOTIFY, 1);
}

unsafe fn ack_interrupt(s: &VirtioNetState) {
    if s.device_base == 0 { return; }
    let isr = mmio_read(s.device_base, INTERRUPT_STATUS);
    if isr != 0 {
        mmio_write(s.device_base, INTERRUPT_ACK, isr);
    }
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
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < STATE_SIZE { return -2; }

        let s = &mut *(state as *mut VirtioNetState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // Compute 4096-aligned addresses for virtqueues within state buffer
        let base = state as usize;
        let rxq_raw = base + META_SIZE;
        let rxq_aligned = (rxq_raw + 4095) & !4095;
        s.rxq_ptr = rxq_aligned;

        let txq_raw = rxq_aligned + VQ_TOTAL;
        let txq_aligned = (txq_raw + 4095) & !4095;
        s.txq_ptr = txq_aligned;

        // Buffers follow (no alignment needed)
        s.rx_bufs_ptr = txq_aligned + VQ_TOTAL;
        s.tx_buf_ptr = s.rx_bufs_ptr + RX_BUFS_TOTAL;

        // Init device
        if !init_device(s) {
            let sys = &*s.syscalls;
            dev_log(sys, 1, b"[virtio_net] no device".as_ptr(), 22);
            return -3;
        }

        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[virtio_net] init ok".as_ptr(), 20);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut VirtioNetState);
    s.step_count = s.step_count.wrapping_add(1);

    // ACK any pending interrupt (keeps QEMU happy)
    ack_interrupt(s);

    // Send MAC announcement once after init
    if s.initialized != 0 && s.mac_announced == 0 && s.out_chan >= 0 {
        let mac = s.mac_addr.as_ptr();
        if *mac != 0 || *mac.add(1) != 0 {
            let sys = &*s.syscalls;
            let mut frame = [0u8; 14];
            let fp = frame.as_mut_ptr();
            let mut m = 0usize;
            while m < 6 {
                let b = *mac.add(m);
                *fp.add(m) = b;       // dst = our MAC
                *fp.add(6 + m) = b;   // src = our MAC
                m += 1;
            }
            // EtherType 0x0000 = MAC announcement (bytes 12-13 already zero)
            let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
            if poll > 0 && (poll as u8 & POLL_OUT) != 0 {
                (sys.channel_write)(s.out_chan, fp as *const u8, 14);
                s.mac_announced = 1;
                dev_log(sys, 3, b"[virtio_net] mac announced".as_ptr(), 26);
            }
        }
    }

    // Poll RX (virtio → out_chan)
    poll_rx(s);

    // Poll TX (in_chan → virtio)
    poll_tx(s);

    0 // Continue
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 4096 }, // in[0]: frames from ip
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 4096 }, // out[0]: frames to ip
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

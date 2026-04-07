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

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const QUEUE_SIZE: usize = 16;
const NET_HDR_SIZE: usize = 10;
const MAX_FRAME_SIZE: usize = 1514;
const BUF_SIZE: usize = 1536; // >= NET_HDR + MAX_FRAME, rounded for alignment

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
const QUEUE_ALIGN_REG: usize = 0x03c;
const QUEUE_PFN: usize = 0x040;
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const INTERRUPT_STATUS: usize = 0x060;
const INTERRUPT_ACK: usize = 0x064;
const STATUS_REG: usize = 0x070;
const QUEUE_DESC_LOW: usize = 0x080;
const QUEUE_DESC_HIGH: usize = 0x084;
const QUEUE_DRIVER_LOW: usize = 0x090;
const QUEUE_DRIVER_HIGH: usize = 0x094;
const QUEUE_DEVICE_LOW: usize = 0x0a0;
const QUEUE_DEVICE_HIGH: usize = 0x0a4;
const CONFIG_SPACE: usize = 0x100;

const STATUS_ACK: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK: u32 = 4;
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
const VRING_DESC_F_WRITE: u16 = 2;

// Virtqueue layout sizes (QUEUE_SIZE=16):
//   Descriptors: 16 * 16 = 256 bytes (16-aligned)
//   Driver (avail) ring: 6 + 2*16 = 38 bytes (2-aligned)
//   Device (used) ring: 6 + 8*16 = 134 bytes (4-aligned)
const VQ_DESC_SIZE: usize = QUEUE_SIZE * 16;  // 256
const VQ_AVAIL_SIZE: usize = 6 + 2 * QUEUE_SIZE;  // 38
const VQ_USED_SIZE: usize = 6 + 8 * QUEUE_SIZE;  // 134
// Per virtqueue (v1 legacy): page-aligned, desc+avail in first page, used at +4096.
// Needs 4096 + VQ_USED_SIZE = 4230 bytes, plus page-alignment overhead (~4096).
// v2 modern: desc + avail + used contiguous, much smaller. We size for v1 (worst case).
const VQ_LEGACY_SIZE: usize = 4096 + VQ_USED_SIZE; // 4230

// State layout offsets (computed in module_new for alignment)
// Metadata (256 bytes) → RXQ (page-aligned) → TXQ (page-aligned) → RX_BUFS → TX_BUF
const META_SIZE: usize = 256;
const RX_BUFS_TOTAL: usize = QUEUE_SIZE * BUF_SIZE; // 16 * 1524 = 24384
const TX_BUF_TOTAL: usize = BUF_SIZE; // 1524

// Total state: metadata + 2 queues (page-aligned) + buffers + alignment slack
const STATE_SIZE: usize = META_SIZE + 4096 + VQ_LEGACY_SIZE + 4096 + VQ_LEGACY_SIZE + RX_BUFS_TOTAL + TX_BUF_TOTAL;

// ============================================================================
// State (in metadata region)
// ============================================================================

#[repr(C)]
struct VirtQueue {
    desc: usize,    // descriptor table base
    avail: usize,   // driver (available) ring base
    used: usize,    // device (used) ring base
    last_used: u16, // driver-side tracking
    next_avail: u16, // driver-side avail index tracking
}

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
    // Virtqueues
    rxq: VirtQueue,
    txq: VirtQueue,
    // Buffer pointers
    rx_bufs_ptr: usize,
    tx_buf_ptr: usize,
    step_count: u32,
    // Interrupt-driven RX event (bound to virtio SPI via IRQ_BIND)
    irq_event: i32,
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

// Descriptor: 16 bytes each
// [addr: u64, len: u32, flags: u16, next: u16]
unsafe fn desc_set(desc_base: usize, i: usize, addr: u64, len: u32, flags: u16) {
    let p = desc_base + i * 16;
    write_volatile(p as *mut u64, addr);
    write_volatile((p + 8) as *mut u32, len);
    write_volatile((p + 12) as *mut u16, flags);
    write_volatile((p + 14) as *mut u16, 0); // next
}

// Avail (driver) ring: [flags: u16, idx: u16, ring[N]: u16]
unsafe fn avail_set_idx(avail_base: usize, idx: u16) {
    write_volatile((avail_base + 2) as *mut u16, idx)
}

unsafe fn avail_ring_set(avail_base: usize, slot: usize, val: u16) {
    write_volatile((avail_base + 4 + slot * 2) as *mut u16, val)
}

// Used (device) ring: [flags: u16, idx: u16, ring[N]: {id: u32, len: u32}]
unsafe fn used_idx(used_base: usize) -> u16 {
    read_volatile((used_base + 2) as *const u16)
}

unsafe fn used_ring_id(used_base: usize, slot: usize) -> u32 {
    read_volatile((used_base + 4 + slot * 8) as *const u32)
}

unsafe fn used_ring_len(used_base: usize, slot: usize) -> u32 {
    read_volatile((used_base + 4 + slot * 8 + 4) as *const u32)
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

/// Setup a virtqueue (v2 modern): split desc/avail/used addresses.
unsafe fn setup_queue_v2(base: usize, queue_idx: u32, vq: &VirtQueue) -> bool {
    mmio_write(base, QUEUE_SEL, queue_idx);
    let max = mmio_read(base, QUEUE_NUM_MAX);
    if max == 0 || (max as usize) < QUEUE_SIZE { return false; }
    mmio_write(base, QUEUE_NUM, QUEUE_SIZE as u32);

    let desc = vq.desc as u64;
    let avail = vq.avail as u64;
    let used = vq.used as u64;
    mmio_write(base, QUEUE_DESC_LOW, desc as u32);
    mmio_write(base, QUEUE_DESC_HIGH, (desc >> 32) as u32);
    mmio_write(base, QUEUE_DRIVER_LOW, avail as u32);
    mmio_write(base, QUEUE_DRIVER_HIGH, (avail >> 32) as u32);
    mmio_write(base, QUEUE_DEVICE_LOW, used as u32);
    mmio_write(base, QUEUE_DEVICE_HIGH, (used >> 32) as u32);

    mmio_write(base, QUEUE_READY, 1);
    true
}

/// Setup a virtqueue (v1 legacy): PFN-based with desc+avail contiguous, used at 4096 offset.
/// Requires desc and avail to be contiguous starting at a page-aligned address,
/// with used ring at +4096 from the descriptor table base.
unsafe fn setup_queue_v1(base: usize, queue_idx: u32, vq: &mut VirtQueue, page_buf: usize) -> bool {
    mmio_write(base, QUEUE_SEL, queue_idx);
    let max = mmio_read(base, QUEUE_NUM_MAX);
    if max == 0 || (max as usize) < QUEUE_SIZE { return false; }
    mmio_write(base, QUEUE_NUM, QUEUE_SIZE as u32);
    mmio_write(base, QUEUE_ALIGN_REG, 4096);
    mmio_write(base, QUEUE_PFN, (page_buf as u64 / 4096) as u32);

    // Legacy layout: desc at base, avail immediately after, used at +4096
    vq.desc = page_buf;
    vq.avail = page_buf + VQ_DESC_SIZE;
    vq.used = page_buf + 4096;
    true
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

    // Features: negotiate VIRTIO_NET_F_MAC
    mmio_write(base, DEVICE_FEATURES_SEL, 0);
    let features = mmio_read(base, DEVICE_FEATURES);
    mmio_write(base, DRIVER_FEATURES_SEL, 0);
    // Only negotiate features we actually handle. Accepting MRG_RXBUF
    // (bit 15) without providing 12-byte header buffers causes QEMU to
    // silently drop all RX frames (buffer too small check fails).
    let wanted = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;
    mmio_write(base, DRIVER_FEATURES, features & wanted);

    if ver == 1 {
        // Legacy: set guest page size before queue setup
        mmio_write(base, GUEST_PAGE_SIZE, 4096);
    } else {
        // Modern: FEATURES_OK step
        mmio_write(base, STATUS_REG, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
        let status = mmio_read(base, STATUS_REG);
        if status & STATUS_FEATURES_OK == 0 { return false; }
    }

    // Setup queues — v1 needs page-aligned contiguous buffers, v2 uses split addresses
    if ver == 1 {
        // For v1, we need page-aligned buffers for the legacy PFN layout.
        // Recompute: desc+avail in first page, used starts at +4096.
        let rxq_page = (s.rxq.desc + 4095) & !4095; // page-align
        if !setup_queue_v1(base, 0, &mut s.rxq, rxq_page) { return false; }
        let txq_page = (s.txq.desc + 4095) & !4095;
        if !setup_queue_v1(base, 1, &mut s.txq, txq_page) { return false; }
    } else {
        if !setup_queue_v2(base, 0, &s.rxq) { return false; }
        if !setup_queue_v2(base, 1, &s.txq) { return false; }
    }

    // Pre-fill RX descriptors
    let mut i = 0usize;
    while i < QUEUE_SIZE {
        let buf_addr = s.rx_bufs_ptr + i * BUF_SIZE;
        desc_set(s.rxq.desc, i, buf_addr as u64, BUF_SIZE as u32, VRING_DESC_F_WRITE);
        avail_ring_set(s.rxq.avail, i, i as u16);
        i += 1;
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    avail_set_idx(s.rxq.avail, QUEUE_SIZE as u16);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    s.rxq.next_avail = QUEUE_SIZE as u16;

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
    if ver == 1 {
        mmio_write(base, STATUS_REG, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);
    } else {
        mmio_write(base, STATUS_REG, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    }

    // Notify RX queue that buffers are available
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
        let ui = used_idx(s.rxq.used);
        let lu = s.rxq.last_used;
        if lu == ui { break; }

        let slot = (lu as usize) % QUEUE_SIZE;
        let desc_idx = used_ring_id(s.rxq.used, slot) as usize;
        let total_len = used_ring_len(s.rxq.used, slot) as usize;

        if total_len > NET_HDR_SIZE && desc_idx < QUEUE_SIZE {
            let frame_ptr = (s.rx_bufs_ptr + desc_idx * BUF_SIZE + NET_HDR_SIZE) as *const u8;
            let frame_len = total_len - NET_HDR_SIZE;
            let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
            if poll > 0 && (poll as u8 & POLL_OUT) != 0 {
                (sys.channel_write)(s.out_chan, frame_ptr, frame_len);
            }
        }

        // Recycle descriptor back to avail ring
        s.rxq.last_used = lu.wrapping_add(1);
        let ai = s.rxq.next_avail;
        let avail_slot = (ai as usize) % QUEUE_SIZE;
        avail_ring_set(s.rxq.avail, avail_slot, desc_idx as u16);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        s.rxq.next_avail = ai.wrapping_add(1);
        avail_set_idx(s.rxq.avail, s.rxq.next_avail);
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
    desc_set(s.txq.desc, 0, tx_buf as u64, total as u32, 0);
    let ai = s.txq.next_avail;
    avail_ring_set(s.txq.avail, (ai as usize) % QUEUE_SIZE, 0);
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    s.txq.next_avail = ai.wrapping_add(1);
    avail_set_idx(s.txq.avail, s.txq.next_avail);
    mmio_write(s.device_base, QUEUE_NOTIFY, 1);
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

        // Compute page-aligned addresses for virtqueue areas.
        // v1 legacy requires page-aligned PFN with desc+avail in first page, used at +4096.
        // v2 modern requires desc 16-aligned, avail 2-aligned, used 4-aligned.
        // We allocate for v1 (page-aligned, larger) which also satisfies v2.
        // init_device will rewrite desc/avail/used for whichever version it finds.
        let base = state as usize;
        let rxq_page = (base + META_SIZE + 4095) & !4095; // page-align

        // Initial layout (will be overwritten by setup_queue_v1 or kept for v2)
        s.rxq.desc = rxq_page;
        s.rxq.avail = rxq_page + VQ_DESC_SIZE;
        s.rxq.used = rxq_page + 4096;
        s.rxq.last_used = 0;
        s.rxq.next_avail = 0;

        let txq_page = (rxq_page + VQ_LEGACY_SIZE + 4095) & !4095;
        s.txq.desc = txq_page;
        s.txq.avail = txq_page + VQ_DESC_SIZE;
        s.txq.used = txq_page + 4096;
        s.txq.last_used = 0;
        s.txq.next_avail = 0;

        // Buffers follow
        s.rx_bufs_ptr = txq_page + VQ_LEGACY_SIZE;
        s.tx_buf_ptr = s.rx_bufs_ptr + RX_BUFS_TOTAL;

        // Init device
        if !init_device(s) {
            let sys = &*s.syscalls;
            dev_log(sys, 1, b"[virtio_net] no device".as_ptr(), 22);
            return -3;
        }

        let sys = &*s.syscalls;

        // Create an event and bind it to the virtio IRQ for interrupt-driven RX.
        // QEMU virt virtio-mmio SPI 16 = GIC IRQ 48 (32 + 16).
        // The kernel's ISR will ACK the device and signal this event.
        s.irq_event = dev_event_create(sys);
        if s.irq_event >= 0 {
            let virtio_spi = 48u32; // SPI 16 = IRQ 48
            dev_irq_bind(sys, s.irq_event, virtio_spi, s.device_base);
        }

        dev_log(sys, 3, b"[virtio_net] init ok".as_ptr(), 20);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut VirtioNetState);
    s.step_count = s.step_count.wrapping_add(1);

    // ACK any pending virtio interrupt.
    // TODO: once IRQ_BIND is verified working, remove this MMIO poll and
    // let the kernel ISR handle ACK. For now, always ACK from step as fallback.
    if s.device_base != 0 {
        let isr = mmio_read(s.device_base, INTERRUPT_STATUS);
        if isr != 0 {
            mmio_write(s.device_base, INTERRUPT_ACK, isr);
        }
    }

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

    // RX: poll the used ring for received frames.
    // With interrupt-driven mode, the kernel ISR ACKs the virtio device —
    // no MMIO polling overhead here. We just check the used ring in memory.
    poll_rx(s);

    // TX: always poll (sends pending frames from IP module)
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

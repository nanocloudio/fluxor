//! Elastic Network Adapter: AWS's NIC on a Nitro instance.
//!
//! Exchanges Ethernet frames with the device over one TX and one RX queue pair
//! held in host memory, by polling. `frames_tx` carries frames from `ip`,
//! `frames_rx` carries frames to it, and the MAC address is announced on
//! `frames_rx` (ethertype 0x0000) before the module reports Ready.
//!
//! # Bring-up, a step at a time
//!
//! Bind → map BAR0 → point the device at the register-read reply → reset →
//! admin queues and the async event queue → tell it about this host → read the
//! device's attributes, its MAC among them → enable async events → set the MTU
//! → create the TX completion and submission queues → the same for RX → post
//! every RX buffer → announce.
//!
//! Admin commands complete across steps: nothing here waits for the device longer
//! than one register read.
//!
//! # What the device's interface asks
//!
//! Register reads go through the device's read-less path unless PCI revision
//! bit 0 says it has none: the driver asks for a register by writing to one, and
//! the device writes the value into host memory. A descriptor ring's owner is
//! told apart by a phase bit, which flips each time the ring wraps.
//!
//! Interface reference: the BSD-licensed `ena_com` definitions Amazon publishes.

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "the SDK's mounted matches are exhaustive on some targets"
)]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// Registers (BAR0).
const REG_AQ_BASE_LO: usize = 0x10;
const REG_AQ_BASE_HI: usize = 0x14;
const REG_AQ_CAPS: usize = 0x18;
const REG_ACQ_BASE_LO: usize = 0x20;
const REG_ACQ_BASE_HI: usize = 0x24;
const REG_ACQ_CAPS: usize = 0x28;
const REG_AQ_DB: usize = 0x2c;
const REG_AENQ_CAPS: usize = 0x34;
const REG_AENQ_BASE_LO: usize = 0x38;
const REG_AENQ_BASE_HI: usize = 0x3c;
const REG_AENQ_HEAD_DB: usize = 0x40;
const REG_DEV_CTL: usize = 0x54;
const REG_DEV_STS: usize = 0x58;
const REG_MMIO_REG_READ: usize = 0x5c;
const REG_MMIO_RESP_LO: usize = 0x60;
const REG_MMIO_RESP_HI: usize = 0x64;

const CTL_DEV_RESET: u32 = 1;
const STS_READY: u32 = 1;
const STS_RESET_IN_PROGRESS: u32 = 1 << 3;

// Admin opcodes and features.
const OP_CREATE_SQ: u8 = 1;
const OP_CREATE_CQ: u8 = 3;
const OP_GET_FEATURE: u8 = 8;
const OP_SET_FEATURE: u8 = 9;
const FEATURE_DEVICE_ATTRIBUTES: u8 = 1;
const FEATURE_MTU: u8 = 14;
const FEATURE_AENQ_CONFIG: u8 = 26;
const FEATURE_HOST_ATTR_CONFIG: u8 = 28;

// Async event groups.
const AENQ_LINK_CHANGE: u16 = 0;
const AENQ_FATAL_ERROR: u16 = 1;
const AENQ_WARNING: u16 = 2;

const AQ_DEPTH: usize = 32;
const AENQ_DEPTH: usize = 16;
const ADMIN_ENTRY: usize = 64;

/// The MSI-X vector the I/O queue pair's completion queues name: vector 0 is the
/// admin queue's. Both are given real vectors through the platform: the device
/// creates no queue whose vector the interrupt fabric does not route.
const IO_MSIX_VECTOR: u32 = 1;
/// Vectors this driver programs: admin, then the one queue pair.
const MSIX_VECTORS: usize = 2;
const DIRECTION_TX: u8 = 1;
const DIRECTION_RX: u8 = 2;
const PLACEMENT_HOST: u8 = 1;

/// Both rings of a pair, in descriptors: a power of two.
const IO_DEPTH: usize = 256;
const IO_MASK: u16 = (IO_DEPTH - 1) as u16;
const SQ_ENTRY: usize = 16;
const TX_CQ_ENTRY: usize = 8;
const RX_CQ_ENTRY: usize = 16;
const BUF_BYTES: usize = 2048;
/// Where a frame starts in its buffer: room for the channel record's length.
const HEADROOM: usize = 64;
const MTU: u32 = 1500;
const MAX_FRAME: usize = 1514;
/// Frames a step moves each way, so a burst cannot starve the rest of the graph.
const BURST: usize = 32;
const READLESS_SPINS: u32 = 200_000;
const ADMIN_TIMEOUT_US: u64 = 10_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Phase {
    Bind,
    Reset,
    ResetOn,
    ResetOff,
    Admin,
    Host,
    GetAttr,
    GetAenq,
    SetAenq,
    SetMtu,
    TxCq,
    TxSq,
    RxCq,
    RxSq,
    Fill,
    Announce,
    Run,
    Failed,
}

/// A submission and completion pair of one direction.
#[derive(Clone, Copy)]
#[repr(C)]
struct Pair {
    sq: u64,
    cq: u64,
    sq_db: usize,
    cq_db: usize,
    cq_idx: u16,
    sq_tail: u16,
    cq_head: u16,
    cq_reported: u16,
}

#[repr(C)]
struct EnaState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    pci: i32,
    bar0: usize,
    readless: u64,
    readless_seq: u16,
    use_readless: u8,
    phase: Phase,
    aq: u64,
    acq: u64,
    aenq: u64,
    aq_tail: u16,
    acq_head: u16,
    aenq_head: u16,
    command_id: u16,
    command_at_us: u64,
    mac: [u8; 6],
    tx: Pair,
    rx: Pair,
    tx_bufs: u64,
    rx_bufs: u64,
    host_info: u64,
    msix_event: i32,
    aenq_groups: u32,
    reset_deadline_us: u64,
    tx_inflight: u16,
    tx_next: u16,
    /// TX buffers the device holds, one bit per request id. The device names
    /// the request each completion is for, and need not complete in order.
    tx_busy: [u32; IO_DEPTH / 32],
    tx_malformed: u32,
}

declare_module_state_bytes!(EnaState);

fn sys(s: &EnaState) -> &'static SyscallTable {
    // SAFETY: set in `module_new`; the table outlives every module.
    unsafe { &*s.syscalls }
}

unsafe fn say(s: &EnaState, line: &[u8]) {
    dev_log(sys(s), 3, line.as_ptr(), line.len());
}

/// `text` then a value in hexadecimal.
unsafe fn say_hex(s: &EnaState, text: &[u8], value: u32) {
    let mut line = [0u8; 72];
    let n = text.len().min(line.len() - 10);
    line[..n].copy_from_slice(&text[..n]);
    line[n] = b'0';
    line[n + 1] = b'x';
    for i in 0..8 {
        let d = ((value >> (28 - i * 4)) & 0xF) as u8;
        line[n + 2 + i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
    }
    dev_log(sys(s), 3, line.as_ptr(), n + 10);
}

unsafe fn fail(s: &mut EnaState, text: &[u8], value: u32) {
    say_hex(s, text, value);
    s.phase = Phase::Failed;
}

/// A register write in a form a hypervisor can decode, should it trap one.
#[inline(always)]
unsafe fn reg_write(s: &EnaState, offset: usize, value: u32) {
    let addr = s.bar0 + offset;
    #[cfg(target_arch = "aarch64")]
    core::arch::asm!("str {v:w}, [{a}]", v = in(reg) value, a = in(reg) addr, options(nostack, preserves_flags));
    #[cfg(not(target_arch = "aarch64"))]
    write_volatile(addr as *mut u32, value);
}

#[inline(always)]
unsafe fn direct_read(addr: usize) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let v: u32;
        core::arch::asm!("ldr {v:w}, [{a}]", v = out(reg) v, a = in(reg) addr, options(nostack, preserves_flags));
        v
    }
    #[cfg(not(target_arch = "aarch64"))]
    read_volatile(addr as *const u32)
}

/// A 32-bit store to a device register outside BAR0 (the MSI-X table).
#[inline(always)]
unsafe fn reg_write_at(addr: usize, value: u32) {
    #[cfg(target_arch = "aarch64")]
    core::arch::asm!("str {v:w}, [{a}]", v = in(reg) value, a = in(reg) addr, options(nostack, preserves_flags));
    #[cfg(not(target_arch = "aarch64"))]
    write_volatile(addr as *mut u32, value);
}

/// A device register, by the path it offers. `None` if a read-less reply never
/// came, or came for another register.
unsafe fn reg_read(s: &mut EnaState, offset: usize) -> Option<u32> {
    if s.use_readless == 0 {
        return Some(direct_read(s.bar0 + offset));
    }
    s.readless_seq = s.readless_seq.wrapping_add(1);
    let seq = s.readless_seq;
    let reply = s.readless as *mut u16;
    write_volatile(reply, seq.wrapping_add(0xDEAD));
    fence();
    reg_write(
        s,
        REG_MMIO_REG_READ,
        ((offset as u32) << 16) | u32::from(seq),
    );
    for _ in 0..READLESS_SPINS {
        if read_volatile(reply) == seq {
            fence();
            // The reply names the register it answers.
            if usize::from(read_volatile(reply.add(1))) != offset {
                return None;
            }
            return Some(read_volatile((s.readless + 4) as *const u32));
        }
        core::hint::spin_loop();
    }
    None
}

#[inline(always)]
fn fence() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a barrier; descriptors must be seen before the doorbell.
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

unsafe fn put_u8(p: u64, at: usize, v: u8) {
    write_volatile((p as usize + at) as *mut u8, v);
}
unsafe fn put_u16(p: u64, at: usize, v: u16) {
    write_volatile((p as usize + at) as *mut u16, v);
}
unsafe fn put_u32(p: u64, at: usize, v: u32) {
    write_volatile((p as usize + at) as *mut u32, v);
}
unsafe fn get_u8(p: u64, at: usize) -> u8 {
    read_volatile((p as usize + at) as *const u8)
}
unsafe fn get_u16(p: u64, at: usize) -> u16 {
    read_volatile((p as usize + at) as *const u16)
}
unsafe fn get_u32(p: u64, at: usize) -> u32 {
    read_volatile((p as usize + at) as *const u32)
}

/// A 64-byte admin entry, zeroed, with its opcode. Filled, then [`admin_ring`].
unsafe fn admin_entry(s: &mut EnaState, opcode: u8) -> u64 {
    let index = usize::from(s.aq_tail) & (AQ_DEPTH - 1);
    let entry = s.aq + (index * ADMIN_ENTRY) as u64;
    let mut at = 0usize;
    while at < ADMIN_ENTRY {
        put_u32(entry, at, 0);
        at += 4;
    }
    s.command_id = (s.command_id + 1) & 0xFFF;
    put_u16(entry, 0, s.command_id);
    put_u8(entry, 2, opcode);
    entry
}

/// Hand the filled entry over: its phase last, then the doorbell.
unsafe fn admin_ring(s: &mut EnaState, entry: u64) {
    let phase = u8::from((s.aq_tail as usize / AQ_DEPTH) & 1 == 0);
    fence();
    put_u8(entry, 3, phase);
    s.aq_tail = s.aq_tail.wrapping_add(1);
    fence();
    reg_write(s, REG_AQ_DB, u32::from(s.aq_tail));
    s.command_at_us = dev_micros(sys(s));
}

/// The completion of the command in flight, once there is one. Failure moves the
/// module to `Failed`.
unsafe fn admin_done(s: &mut EnaState) -> Option<u64> {
    let index = usize::from(s.acq_head) & (AQ_DEPTH - 1);
    let entry = s.acq + (index * ADMIN_ENTRY) as u64;
    let phase = u8::from((s.acq_head as usize / AQ_DEPTH) & 1 == 0);
    if get_u8(entry, 3) & 1 != phase {
        if dev_micros(sys(s)).wrapping_sub(s.command_at_us) > ADMIN_TIMEOUT_US {
            let status = reg_read(s, REG_DEV_STS).unwrap_or(u32::MAX);
            say_hex(s, b"[ena] device status=", status);
            fail(s, b"[ena] admin timeout command=", u32::from(s.command_id));
        }
        return None;
    }
    fence();
    s.acq_head = s.acq_head.wrapping_add(1);
    let status = get_u8(entry, 2);
    if status != 0 {
        say_hex(
            s,
            b"[ena] admin refused, opcode=",
            u32::from(get_u8(
                s.aq + ((usize::from(s.aq_tail.wrapping_sub(1)) & (AQ_DEPTH - 1)) * ADMIN_ENTRY)
                    as u64,
                2,
            )),
        );
        say_hex(
            s,
            b"[ena] admin extended_status=",
            u32::from(get_u16(entry, 4)),
        );
        say_hex(s, b"[ena] admin at_phase=", s.phase as u32);
        fail(s, b"[ena] admin status=", u32::from(status));
        return None;
    }
    Some(entry)
}

unsafe fn get_feature(s: &mut EnaState, feature: u8) {
    let entry = admin_entry(s, OP_GET_FEATURE);
    put_u8(entry, 17, feature);
    admin_ring(s, entry);
}

/// A SET_FEATURE whose payload is one word.
unsafe fn set_feature(s: &mut EnaState, feature: u8, at: usize, value: u32) {
    let entry = admin_entry(s, OP_SET_FEATURE);
    put_u8(entry, 17, feature);
    put_u32(entry, at, value);
    admin_ring(s, entry);
}

unsafe fn create_cq(s: &mut EnaState, ring: u64, entry_bytes: usize) {
    let entry = admin_entry(s, OP_CREATE_CQ);
    // The device takes a CQ only with interrupt mode on. It raises none until a
    // driver writes the queue's unmask register, which this polling one never does.
    put_u8(entry, 4, 1 << 5);
    put_u8(entry, 5, (entry_bytes / 4) as u8);
    put_u16(entry, 6, IO_DEPTH as u16);
    put_u32(entry, 8, IO_MSIX_VECTOR);
    put_u32(entry, 12, ring as u32);
    put_u16(entry, 16, (ring >> 32) as u16);
    admin_ring(s, entry);
}

unsafe fn create_sq(s: &mut EnaState, direction: u8, ring: u64, cq_idx: u16) {
    let entry = admin_entry(s, OP_CREATE_SQ);
    put_u8(entry, 4, direction << 5);
    // Placement in the low bits; completion per descriptor is policy 0.
    put_u8(entry, 6, PLACEMENT_HOST);
    // Physically contiguous.
    put_u8(entry, 7, 1);
    put_u16(entry, 8, cq_idx);
    put_u16(entry, 10, IO_DEPTH as u16);
    put_u32(entry, 12, ring as u32);
    put_u16(entry, 16, (ring >> 32) as u16);
    admin_ring(s, entry);
}

unsafe fn dma(s: &mut EnaState, bytes: usize) -> u64 {
    dev_dma_alloc(sys(s), bytes as u32, 4096)
}

/// Allocate every ring. `false` if memory ran out.
unsafe fn allocate(s: &mut EnaState) -> bool {
    s.readless = dma(s, 64);
    s.host_info = dma(s, 4096);
    s.aq = dma(s, AQ_DEPTH * ADMIN_ENTRY);
    s.acq = dma(s, AQ_DEPTH * ADMIN_ENTRY);
    s.aenq = dma(s, AENQ_DEPTH * ADMIN_ENTRY);
    s.tx.sq = dma(s, IO_DEPTH * SQ_ENTRY);
    s.tx.cq = dma(s, IO_DEPTH * TX_CQ_ENTRY);
    s.rx.sq = dma(s, IO_DEPTH * SQ_ENTRY);
    s.rx.cq = dma(s, IO_DEPTH * RX_CQ_ENTRY);
    s.tx_bufs = dma(s, IO_DEPTH * BUF_BYTES);
    s.rx_bufs = dma(s, IO_DEPTH * BUF_BYTES);
    [
        s.readless,
        s.host_info,
        s.aq,
        s.acq,
        s.aenq,
        s.tx.sq,
        s.tx.cq,
        s.rx.sq,
        s.rx.cq,
        s.tx_bufs,
        s.rx_bufs,
    ]
    .iter()
    .all(|&p| p != 0)
}

/// Route vectors 0 and 1 to this module's event through the platform, program
/// them into the device's MSI-X table and enable it. The driver polls; the
/// vectors exist because the device requires them.
unsafe fn enable_msix(s: &mut EnaState) -> bool {
    const CAP_MSIX: u32 = 0x11;
    let sys_table = sys(s);
    let mut at = dev_pcie_device_cfg_read32(sys_table, s.pci, 0x34) & 0xFC;
    let mut cap = 0u32;
    for _ in 0..48 {
        if at == 0 {
            break;
        }
        let head = dev_pcie_device_cfg_read32(sys_table, s.pci, at as u16);
        if head & 0xFF == CAP_MSIX {
            cap = at;
            break;
        }
        at = (head >> 8) & 0xFC;
    }
    if cap == 0 {
        return false;
    }
    let table = dev_pcie_device_cfg_read32(sys_table, s.pci, cap as u16 + 4);
    let bar = dev_pcie_device_bar_map(sys_table, s.pci, (table & 7) as u8);
    if bar == 0 {
        return false;
    }
    s.msix_event = dev_event_create(sys_table);
    if s.msix_event < 0 {
        return false;
    }
    let entries = bar as usize + (table & !7) as usize;
    for vector in 0..MSIX_VECTORS {
        let Some((_, addr, data)) = dev_pcie_device_msi_alloc(sys_table, s.pci, s.msix_event)
        else {
            return false;
        };
        let entry = entries + vector * 16;
        reg_write_at(entry, addr as u32);
        reg_write_at(entry + 4, (addr >> 32) as u32);
        reg_write_at(entry + 8, data);
        reg_write_at(entry + 12, 0);
    }
    // Message Control: enable, function unmasked.
    let head = dev_pcie_device_cfg_read32(sys_table, s.pci, cap as u16);
    dev_pcie_device_cfg_write32(
        sys_table,
        s.pci,
        cap as u16,
        (head | (1 << 31)) & !(1 << 30),
    );
    true
}

unsafe fn step_bind(s: &mut EnaState) {
    let handle = dev_pcie_device_open(sys(s), b"@class=ethernet");
    if handle < 0 {
        fail(s, b"[ena] no device rc=", handle as u32);
        return;
    }
    s.pci = handle;
    let bar = dev_pcie_device_bar_map(sys(s), handle, 0);
    if bar == 0 {
        fail(s, b"[ena] no bar0 rc=", 0);
        return;
    }
    s.bar0 = bar as usize;
    if !allocate(s) {
        fail(s, b"[ena] dma alloc failed rc=", 0);
        return;
    }
    if !enable_msix(s) {
        fail(s, b"[ena] no msi-x vectors rc=", 0);
        return;
    }
    let class = dev_pcie_device_cfg_read32(sys(s), handle, 0x08);
    s.use_readless = u8::from(class & 1 == 0);
    say_hex(s, b"[ena] bound revision=", class & 0xFF);
    reg_write(s, REG_MMIO_RESP_LO, s.readless as u32);
    reg_write(s, REG_MMIO_RESP_HI, (s.readless >> 32) as u32);
    s.phase = Phase::Reset;
}

unsafe fn step_reset(s: &mut EnaState) {
    let Some(status) = reg_read(s, REG_DEV_STS) else {
        fail(s, b"[ena] register read timeout rc=", 0);
        return;
    };
    if status & STS_READY == 0 {
        fail(s, b"[ena] device not ready sts=", status);
        return;
    }
    reg_write(s, REG_DEV_CTL, CTL_DEV_RESET);
    // The reset drops what the device was told about the reply address.
    reg_write(s, REG_MMIO_RESP_LO, s.readless as u32);
    reg_write(s, REG_MMIO_RESP_HI, (s.readless >> 32) as u32);
    s.reset_deadline_us = dev_micros(sys(s)) + ADMIN_TIMEOUT_US;
    s.phase = Phase::ResetOn;
}

unsafe fn step_reset_wait(s: &mut EnaState, want: u32, next: Phase) {
    let Some(status) = reg_read(s, REG_DEV_STS) else {
        fail(s, b"[ena] register read timeout rc=", 0);
        return;
    };
    if status & STS_RESET_IN_PROGRESS == want {
        if want != 0 {
            reg_write(s, REG_DEV_CTL, 0);
        }
        s.reset_deadline_us = dev_micros(sys(s)) + ADMIN_TIMEOUT_US;
        s.phase = next;
    } else if dev_micros(sys(s)) > s.reset_deadline_us {
        fail(s, b"[ena] reset timeout sts=", status);
    }
}

/// Tell the device who drives it, which it asks before it will make queues.
unsafe fn send_host_info(s: &mut EnaState) {
    const NAME: &[u8] = b"fluxor";
    const OS_DIST_STR: usize = 4;
    const KERNEL_VER_STR: usize = 136;
    const OS_TYPE_DPDK: u32 = 3;
    const DRIVER_VERSION: usize = 172;
    const DRIVER_2_0_0: u32 = 2;
    const ENA_SPEC_VERSION: usize = 184;
    const NUM_CPUS: usize = 188;
    /// ENA common specification 2.0, major in the high byte.
    const SPEC_2_0: u16 = 2 << 8;
    let info = s.host_info;
    for (i, &b) in NAME.iter().enumerate() {
        put_u8(info, OS_DIST_STR + i, b);
        put_u8(info, KERNEL_VER_STR + i, b);
    }
    // The field names operating systems and the device refuses a value outside
    // them. DPDK's is the nearest truth: a driver that polls, with no interrupts.
    put_u32(info, 0, OS_TYPE_DPDK);
    // Major in the low byte. The device creates no I/O queue for a driver
    // older than the 2.x line; this one is written to the 2.0 interface.
    put_u32(info, DRIVER_VERSION, DRIVER_2_0_0);
    put_u16(info, ENA_SPEC_VERSION, SPEC_2_0);
    put_u16(info, NUM_CPUS, 1);
    fence();
    let entry = admin_entry(s, OP_SET_FEATURE);
    put_u8(entry, 17, FEATURE_HOST_ATTR_CONFIG);
    put_u32(entry, 20, info as u32);
    put_u16(entry, 24, (info >> 32) as u16);
    admin_ring(s, entry);
}

unsafe fn step_admin_init(s: &mut EnaState) {
    let aq_caps = (AQ_DEPTH as u32) | ((ADMIN_ENTRY as u32) << 16);
    reg_write(s, REG_AQ_BASE_LO, s.aq as u32);
    reg_write(s, REG_AQ_BASE_HI, (s.aq >> 32) as u32);
    reg_write(s, REG_ACQ_BASE_LO, s.acq as u32);
    reg_write(s, REG_ACQ_BASE_HI, (s.acq >> 32) as u32);
    reg_write(s, REG_AQ_CAPS, aq_caps);
    reg_write(s, REG_ACQ_CAPS, aq_caps);
    reg_write(s, REG_AENQ_BASE_LO, s.aenq as u32);
    reg_write(s, REG_AENQ_BASE_HI, (s.aenq >> 32) as u32);
    reg_write(
        s,
        REG_AENQ_CAPS,
        (AENQ_DEPTH as u32) | ((ADMIN_ENTRY as u32) << 16),
    );
    s.aenq_head = AENQ_DEPTH as u16;
    fence();
    reg_write(s, REG_AENQ_HEAD_DB, u32::from(s.aenq_head));
    say(s, b"[ena] admin queues up");
    send_host_info(s);
    s.phase = Phase::Host;
}

/// Read what the async event queue holds, and give the entries back.
unsafe fn step_aenq(s: &mut EnaState) {
    let mut consumed = false;
    for _ in 0..AENQ_DEPTH {
        let index = usize::from(s.aenq_head) & (AENQ_DEPTH - 1);
        let entry = s.aenq + (index * ADMIN_ENTRY) as u64;
        // The head starts one lap in, so odd laps are the ones the device writes
        // with phase 1.
        let phase = u8::from((usize::from(s.aenq_head) / AENQ_DEPTH) & 1 != 0);
        if get_u8(entry, 4) & 1 != phase {
            break;
        }
        fence();
        let group = get_u16(entry, 0);
        let syndrome = u32::from(get_u16(entry, 2));
        match group {
            // Bit 0 of the first data word says up.
            AENQ_LINK_CHANGE => say_hex(s, b"[ena] link up=", get_u32(entry, 16) & 1),
            AENQ_FATAL_ERROR => say_hex(s, b"[ena] device fatal error syndrome=", syndrome),
            AENQ_WARNING => say_hex(s, b"[ena] device warning syndrome=", syndrome),
            // Notifications and the keep-alive carry nothing this driver acts on.
            _ => {}
        }
        s.aenq_head = s.aenq_head.wrapping_add(1);
        consumed = true;
    }
    if consumed {
        fence();
        reg_write(s, REG_AENQ_HEAD_DB, u32::from(s.aenq_head));
    }
}

unsafe fn step_rx(s: &mut EnaState) {
    let chan = s.out_chan;
    let sys_table = sys(s);
    let mut posted = false;
    for _ in 0..BURST {
        let index = usize::from(s.rx.cq_head & IO_MASK);
        let entry = s.rx.cq + (index * RX_CQ_ENTRY) as u64;
        let status = get_u32(entry, 0);
        let phase = u32::from((usize::from(s.rx.cq_head) / IO_DEPTH) & 1 == 0);
        if (status >> 24) & 1 != phase {
            break;
        }
        fence();
        let length = usize::from(get_u16(entry, 4));
        let req = usize::from(get_u16(entry, 6)) & (IO_DEPTH - 1);
        let offset = usize::from(get_u8(entry, 14));
        let buffer = s.rx_bufs as usize + req * BUF_BYTES + HEADROOM + offset;
        if length != 0 && length <= MAX_FRAME {
            let record = (buffer - 2) as *mut u8;
            write_volatile(record, length as u8);
            write_volatile(record.add(1), (length >> 8) as u8);
            let room = (sys_table.channel_poll)(chan, POLL_OUT);
            if room > 0 && (room as u32 & POLL_OUT) != 0 {
                (sys_table.channel_write)(chan, record, 2 + length);
            }
        }
        s.rx.cq_head = s.rx.cq_head.wrapping_add(1);
        post_rx(s, req);
        posted = true;
    }
    if posted {
        fence();
        reg_write(s, s.rx.sq_db - s.bar0, u32::from(s.rx.sq_tail));
        report_cq(s, true);
    }
}

/// Tell the device how far completions were read, once half a ring is unreported.
unsafe fn report_cq(s: &mut EnaState, rx: bool) {
    let pair = if rx { s.rx } else { s.tx };
    if pair.cq_db == 0 || pair.cq_head.wrapping_sub(pair.cq_reported) < (IO_DEPTH / 2) as u16 {
        return;
    }
    // Every completion read before the device may reuse its entry.
    fence();
    reg_write(s, pair.cq_db - s.bar0, u32::from(pair.cq_head));
    if rx {
        s.rx.cq_reported = pair.cq_head;
    } else {
        s.tx.cq_reported = pair.cq_head;
    }
}

/// Put RX buffer `req` back on the ring. The doorbell is the caller's.
unsafe fn post_rx(s: &mut EnaState, req: usize) {
    const FIRST: u8 = 1 << 2;
    const LAST: u8 = 1 << 3;
    const COMP_REQ: u8 = 1 << 4;
    let index = usize::from(s.rx.sq_tail & IO_MASK);
    let entry = s.rx.sq + (index * SQ_ENTRY) as u64;
    let phase = u8::from((usize::from(s.rx.sq_tail) / IO_DEPTH) & 1 == 0);
    let buffer = s.rx_bufs + (req * BUF_BYTES + HEADROOM) as u64;
    put_u16(entry, 0, (BUF_BYTES - HEADROOM) as u16);
    put_u8(entry, 2, 0);
    put_u16(entry, 4, req as u16);
    put_u16(entry, 6, 0);
    put_u32(entry, 8, buffer as u32);
    put_u16(entry, 12, (buffer >> 32) as u16);
    put_u16(entry, 14, 0);
    fence();
    put_u8(entry, 3, phase | FIRST | LAST | COMP_REQ);
    s.rx.sq_tail = s.rx.sq_tail.wrapping_add(1);
}

/// TX completions give their request's buffer back.
unsafe fn step_tx_done(s: &mut EnaState) {
    for _ in 0..BURST {
        let index = usize::from(s.tx.cq_head & IO_MASK);
        let entry = s.tx.cq + (index * TX_CQ_ENTRY) as u64;
        let phase = u8::from((usize::from(s.tx.cq_head) / IO_DEPTH) & 1 == 0);
        if get_u8(entry, 3) & 1 != phase {
            break;
        }
        fence();
        let req = usize::from(get_u16(entry, 0) & IO_MASK);
        let bit = 1u32 << (req % 32);
        if s.tx_busy[req / 32] & bit != 0 {
            s.tx_busy[req / 32] &= !bit;
            s.tx_inflight = s.tx_inflight.saturating_sub(1);
        }
        s.tx.cq_head = s.tx.cq_head.wrapping_add(1);
    }
    report_cq(s, false);
}

/// Count a TX record that is not a frame, and say so on the first and at every
/// power of two after. The stream is written a whole record at a time, so one
/// that has gone out of step does not find its records again.
unsafe fn note_tx_malformed(s: &mut EnaState) {
    s.tx_malformed = s.tx_malformed.wrapping_add(1);
    if s.tx_malformed.is_power_of_two() {
        say_hex(s, b"[ena] tx malformed n=", s.tx_malformed);
    }
}

unsafe fn step_tx(s: &mut EnaState) {
    const PHASE_SHIFT: u32 = 24;
    const FIRST: u32 = 1 << 26;
    const LAST: u32 = 1 << 27;
    const COMP_REQ: u32 = 1 << 28;
    let chan = s.in_chan;
    if chan < 0 {
        return;
    }
    let sys_table = sys(s);
    let mut sent = false;
    for _ in 0..BURST {
        let req = usize::from(s.tx_next & IO_MASK);
        let held = s.tx_busy[req / 32] & (1 << (req % 32)) != 0;
        if held || usize::from(s.tx_inflight) >= IO_DEPTH - 1 {
            break;
        }
        let ready = (sys_table.channel_poll)(chan, POLL_IN);
        if ready <= 0 || (ready as u32 & POLL_IN) == 0 {
            break;
        }
        let mut head = [0u8; 2];
        if (sys_table.channel_read)(chan, head.as_mut_ptr(), 2) != 2 {
            break;
        }
        let want = usize::from(head[0]) | (usize::from(head[1]) << 8);
        if want == 0 || want > MAX_FRAME {
            note_tx_malformed(s);
            break;
        }
        let buffer = s.tx_bufs + (req * BUF_BYTES) as u64;
        if (sys_table.channel_read)(chan, buffer as *mut u8, want) as usize != want {
            note_tx_malformed(s);
            break;
        }
        let index = usize::from(s.tx.sq_tail & IO_MASK);
        let entry = s.tx.sq + (index * SQ_ENTRY) as u64;
        let phase = u32::from((usize::from(s.tx.sq_tail) / IO_DEPTH) & 1 == 0);
        put_u32(entry, 4, (req as u32 & 0x3FF) << 22);
        put_u32(entry, 8, buffer as u32);
        put_u32(entry, 12, ((buffer >> 32) as u32) & 0xFFFF);
        fence();
        put_u32(
            entry,
            0,
            want as u32
                | (((req as u32) >> 10) << 16)
                | (phase << PHASE_SHIFT)
                | FIRST
                | LAST
                | COMP_REQ,
        );
        s.tx.sq_tail = s.tx.sq_tail.wrapping_add(1);
        s.tx_next = s.tx_next.wrapping_add(1);
        s.tx_inflight += 1;
        s.tx_busy[req / 32] |= 1 << (req % 32);
        sent = true;
    }
    if sent {
        fence();
        reg_write(s, s.tx.sq_db - s.bar0, u32::from(s.tx.sq_tail));
    }
}

/// True on the step the MAC went out: the module is then Ready.
unsafe fn step_announce(s: &mut EnaState) -> bool {
    let mut record = [0u8; 16];
    record[0] = 14;
    record[2..8].copy_from_slice(&s.mac);
    record[8..14].copy_from_slice(&s.mac);
    let room = (sys(s).channel_poll)(s.out_chan, POLL_OUT);
    if room <= 0 || (room as u32 & POLL_OUT) == 0 {
        return false;
    }
    (sys(s).channel_write)(s.out_chan, record.as_ptr(), 16);
    say(s, b"[ena] ready, mac announced");
    s.phase = Phase::Run;
    true
}

/// The admin sequence: each arm consumes the completion of the command before it.
unsafe fn step_setup(s: &mut EnaState) {
    let Some(reply) = admin_done(s) else { return };
    match s.phase {
        Phase::Host => {
            get_feature(s, FEATURE_DEVICE_ATTRIBUTES);
            s.phase = Phase::GetAttr;
        }
        Phase::GetAttr => {
            for i in 0..6 {
                s.mac[i] = get_u8(reply, 32 + i);
            }
            say_hex(s, b"[ena] impl=", get_u32(reply, 8));
            say_hex(s, b"[ena] features=", get_u32(reply, 16));
            say_hex(s, b"[ena] max_mtu=", get_u32(reply, 40));
            get_feature(s, FEATURE_AENQ_CONFIG);
            s.phase = Phase::GetAenq;
        }
        Phase::GetAenq => {
            s.aenq_groups = get_u32(reply, 8);
            say_hex(s, b"[ena] aenq groups=", s.aenq_groups);
            // cmd.u starts at 20: supported_groups, then enabled_groups. Link
            // change, fatal error, warning, notification and keep-alive.
            const WANTED_GROUPS: u32 = 0x1F;
            let groups = s.aenq_groups & WANTED_GROUPS;
            set_feature(s, FEATURE_AENQ_CONFIG, 24, groups);
            s.phase = Phase::SetAenq;
        }
        Phase::SetAenq => {
            set_feature(s, FEATURE_MTU, 20, MTU);
            s.phase = Phase::SetMtu;
        }
        Phase::SetMtu => {
            let ring = s.tx.cq;
            create_cq(s, ring, TX_CQ_ENTRY);
            s.phase = Phase::TxCq;
        }
        Phase::TxCq => {
            s.tx.cq_idx = get_u16(reply, 8);
            let db = get_u32(reply, 16) as usize;
            s.tx.cq_db = if db != 0 { s.bar0 + db } else { 0 };
            let (ring, cq) = (s.tx.sq, s.tx.cq_idx);
            create_sq(s, DIRECTION_TX, ring, cq);
            s.phase = Phase::TxSq;
        }
        Phase::TxSq => {
            s.tx.sq_db = s.bar0 + get_u32(reply, 12) as usize;
            let ring = s.rx.cq;
            create_cq(s, ring, RX_CQ_ENTRY);
            s.phase = Phase::RxCq;
        }
        Phase::RxCq => {
            s.rx.cq_idx = get_u16(reply, 8);
            let db = get_u32(reply, 16) as usize;
            s.rx.cq_db = if db != 0 { s.bar0 + db } else { 0 };
            let (ring, cq) = (s.rx.sq, s.rx.cq_idx);
            create_sq(s, DIRECTION_RX, ring, cq);
            s.phase = Phase::RxSq;
        }
        Phase::RxSq => {
            s.rx.sq_db = s.bar0 + get_u32(reply, 12) as usize;
            s.phase = Phase::Fill;
        }
        _ => {}
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 {
    1
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<EnaState>()
}

/// # Safety
/// Called once by the kernel's loader with its syscall table.
#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Called by the kernel's loader with `state` pointing at `state_size` bytes this
/// module owns and `syscalls` at the kernel's table.
#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<EnaState>() {
        return -2;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<EnaState>());
    let s = &mut *(state as *mut EnaState);
    s.syscalls = syscalls as *const SyscallTable;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.pci = -1;
    s.msix_event = -1;
    s.phase = Phase::Bind;
    0
}

/// # Safety
/// Called by the scheduler with the state `module_new` initialised.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut EnaState);
    match s.phase {
        Phase::Bind => step_bind(s),
        Phase::Reset => step_reset(s),
        Phase::ResetOn => step_reset_wait(s, STS_RESET_IN_PROGRESS, Phase::ResetOff),
        Phase::ResetOff => step_reset_wait(s, 0, Phase::Admin),
        Phase::Admin => step_admin_init(s),
        Phase::Fill => {
            for req in 0..IO_DEPTH - 1 {
                post_rx(s, req);
            }
            fence();
            reg_write(s, s.rx.sq_db - s.bar0, u32::from(s.rx.sq_tail));
            s.phase = Phase::Announce;
        }
        Phase::Announce => {
            if step_announce(s) {
                return 3; // Ready
            }
        }
        Phase::Run => {
            if s.msix_event >= 0 {
                let _ = dev_event_poll(sys(s), s.msix_event);
            }
            step_aenq(s);
            step_rx(s);
            step_tx_done(s);
            step_tx(s);
        }
        Phase::Failed => {}
        _ => step_setup(s),
    }
    0
}

include!("../../sdk/runtime/wasm_entry.rs");

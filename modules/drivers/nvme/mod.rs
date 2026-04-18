//! NVMe block driver — Pi 5 / CM5 PCIe1 external slot.
//!
//! Polled, single-queue v1. See `README.md` for the state-machine
//! contract, spec citations, and the bring-up checklist. See
//! `hw/nvme_trace/baseline/` for the reference trace this module is
//! written against (Biwin CE430T5D100-512G on the rig, 2026-04-16).
//!
//! # Current status
//!
//! Phase 3: Reset → ConfigQueues → Enable → IdentifyController
//! implemented. Logs VID/SN/MN/FR from the Identify response.
//! Phase 4 (IdentifyNamespace + I/O queues) + Phase 5+ still stubs.
//!
//! # Register map (NVMe 1.4 §3.1)
//!
//! | Offset | Width | Name    | Notes                               |
//! |--------|-------|---------|-------------------------------------|
//! | 0x00   | 64    | CAP     | MQES, TO, DSTRD, MPSMIN, CSS        |
//! | 0x08   | 32    | VS      | Major.Minor.Tertiary                |
//! | 0x14   | 32    | CC      | EN, CSS, MPS, IOSQES, IOCQES, SHN   |
//! | 0x1C   | 32    | CSTS    | RDY, CFS, SHST                      |
//! | 0x24   | 32    | AQA     | ACQS[27:16], ASQS[11:0]             |
//! | 0x28   | 64    | ASQ     | admin SQ base phys                  |
//! | 0x30   | 64    | ACQ     | admin CQ base phys                  |
//! | 0x1000 | 32    | SQ0TDBL                                       |
//! | +DSTRD | 32    | CQ0HDBL                                       |

#![no_std]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Constants
// ============================================================================

const NIC_BAR_MAP: u32 = 0x0CF0;
const PCIE_RESCAN: u32 = 0x0CF5;

/// PCI-bus address offset into BAR1's inbound window on BCM7712 PCIe1.
/// BAR1 covers PCI bus 0x10_0000_0000..0x20_0000_0000 and is
/// UBUS-REMAP'd to fabric 0x0 (ACCESS_EN, cpu_hi=0). Device TLPs must
/// target `arm_arena_addr | PCI_DMA_OFFSET` to land in our arena.
const PCI_DMA_OFFSET: u64 = 0x10_0000_0000;

// NVMe register offsets
const REG_CAP:      u64 = 0x00;
const REG_VS:       u64 = 0x08;
const REG_CC:       u64 = 0x14;
const REG_CSTS:     u64 = 0x1C;
const REG_AQA:      u64 = 0x24;
const REG_ASQ:      u64 = 0x28;
const REG_ACQ:      u64 = 0x30;
const REG_SQ0TDBL:  u64 = 0x1000;

// CC bits (NVMe 1.4 §3.1.5)
const CC_EN:       u32 = 1 << 0;
const CC_CSS_NVM:  u32 = 0 << 4;
const CC_SHN_MASK: u32 = 0b11 << 14;
const CC_IOSQES_6: u32 = 6 << 16;
const CC_IOCQES_4: u32 = 4 << 20;

// CSTS bits (NVMe 1.4 §3.1.6)
const CSTS_RDY:    u32 = 1 << 0;
const CSTS_CFS:    u32 = 1 << 1;

// Admin queue sizing (well within any controller's MQES).
const ADMIN_Q_ENTRIES: u32 = 64;
const SQE_BYTES:       u32 = 64;
const CQE_BYTES:       u32 = 16;
const PAGE:            u32 = 4096;

// Identify Controller field offsets (NVMe 1.4 §5.15.2.1 Figure 249).
const ID_VID:  usize = 0;    // u16
const ID_SN:   usize = 4;    // 20 bytes
const ID_MN:   usize = 24;   // 40 bytes
const ID_FR:   usize = 64;   // 8 bytes

// Timeouts (ms). Declared CAP.TO can be 50 s but typical is < 100 ms.
const RESET_BUDGET_MS:  u64 = 500;
const ENABLE_BUDGET_MS: u64 = 500;
const ADMIN_CMD_BUDGET_MS: u64 = 1000;
const IO_READ_BUDGET_MS:   u64 = 1000;

// Block I/O streaming phase (state field `blk_phase`).
const BLK_PHASE_IDLE:    u8 = 0;
const BLK_PHASE_READING: u8 = 1;
const BLK_PHASE_WRITING: u8 = 2;

const BLOCK_SIZE: u32 = 512;

// ============================================================================
// State machine
// ============================================================================

const S_WAIT_PCIE:           u8 = 0;
const S_MAP_BARS:            u8 = 1;
const S_RESET:               u8 = 2;
const S_CONFIG_QUEUES:       u8 = 3;
const S_ENABLE:              u8 = 4;
const S_IDENTIFY_CONTROLLER: u8 = 5;
const S_IDENTIFY_NAMESPACE:  u8 = 6;
const S_CREATE_IO_CQ:        u8 = 7;
const S_CREATE_IO_SQ:        u8 = 8;
const S_WRITE_ONCE:          u8 = 9;
const S_READ_LBA0:           u8 = 10;
const S_READY:               u8 = 11;
const S_FAULT:               u8 = 0xFF;

// NVMe opcodes (NVMe 1.4 §5).
const OPC_DELETE_SQ:         u8 = 0x00;
const OPC_CREATE_SQ:         u8 = 0x01;
const OPC_CREATE_CQ:         u8 = 0x05;
const OPC_IDENTIFY:          u8 = 0x06;
const OPC_READ:              u8 = 0x02;
const OPC_WRITE:             u8 = 0x01;

// Command IDs — stable across admin queue lifetime so a CQE can be
// cross-referenced to the command that issued it.
const CID_IDENTIFY_CTRL:     u16 = 0x0001;
const CID_IDENTIFY_NS:       u16 = 0x0002;
const CID_CREATE_IO_CQ:      u16 = 0x0003;
const CID_CREATE_IO_SQ:      u16 = 0x0004;
const CID_READ_LBA0:         u16 = 0x0005;
const CID_WRITE_ONCE:        u16 = 0x0006;

/// Sentinel for `write_lba` disabling the one-shot boot-write.
const WRITE_LBA_DISABLED:    u32 = 0xFFFF_FFFF;

/// Maximum payload accepted for the one-shot boot-write param. Fits in
/// one 512-byte LBA; the rest of the block is zero-padded.
const WRITE_DATA_MAX:        usize = 48;

// I/O queue sizing. Single QID=1 pair for v1. 64 entries is well
// within any controller's MQES and more than enough for single-
// in-flight polled I/O.
const IO_QID:                u16 = 1;
const IO_Q_ENTRIES:          u32 = 64;

// Identify Namespace response (NVMe 1.4 §5.15.2.2 Figure 246).
const INS_NSZE:              usize = 0;     // u64
const INS_FLBAS:             usize = 26;    // u8, [3:0] = active LBAF index
const INS_LBAF0:             usize = 128;   // u32, bits [23:16] = LBADS (log2 of LBA size)

#[repr(C)]
struct NvmeState {
    syscalls: *const SyscallTable,

    pcie_in: i32,
    req_in:  i32,
    blk_out: i32,
    ctrl:    i32,

    controller_index: u8,
    queue_depth: u16,
    namespace: u32,

    // Phase 6 one-shot boot-write. If `write_lba != WRITE_LBA_DISABLED`,
    // the state machine writes `write_data[..write_data_len]` (zero-
    // padded to 512 B) to that LBA between CreateIoSQ and ReadLba0.
    write_lba:       u32,
    write_data_len:  u16,
    _pad_wr:         u16,
    write_data:      [u8; WRITE_DATA_MAX],

    state: u8,
    substate: u8,
    fault_code: u8,
    pcie_dev_idx: u8,
    logged_state: u8,
    _pad0: [u8; 3],

    bar0_virt: u64,
    cap: u64,

    // CAP-derived
    mqes: u16,
    dstrd_shift: u8,
    timeout_500ms: u8,
    mpsmin: u8,
    _pad1: [u8; 3],

    // DMA (phys == virt under identity mapping). `identify_buf` holds
    // the Identify Controller response and is never overwritten after
    // Phase 3 so the heartbeat can re-emit the acceptance line;
    // Identify Namespace gets its own buffer.
    admin_sq:        u64,
    admin_cq:        u64,
    identify_buf:    u64,
    identify_ns_buf: u64,
    io_sq:           u64,
    io_cq:           u64,
    /// DMA buffer for the read-stream pipeline (BLK_PHASE_READING
    /// fills it; BLK_PHASE_WRITING drains it byte-by-byte to
    /// `blk_out`).
    read_buf:        u64,
    /// DMA buffer for write-request payloads accepted on `req_in`.
    /// Separate from `read_buf` so an incoming write payload cannot
    /// alias an in-flight read whose contents the consumer hasn't
    /// finished draining yet.
    write_buf:       u64,

    // Admin queue indices (QID=0).
    sq_tail:  u32,
    cq_head:  u32,
    cq_phase: u32,

    // I/O queue indices (QID=1).
    io_sq_tail:  u32,
    io_cq_head:  u32,
    io_cq_phase: u32,

    // Block I/O streaming state (S_READY). `current_block` is the LBA
    // being served. `blk_phase` (0=Idle, 1=Reading, 2=Writing) drives
    // the read-stream pipeline. `write_offset` tracks bytes of the
    // 512 B block already pushed to the output channel.
    // `discard_cqe` is set when a seek arrives while a read is still
    // in flight — the CQE still has to be harvested to free the I/O
    // queue slot, but we must not write its data to the channel.
    current_block:    u32,
    write_offset:     u16,
    blk_phase:        u8,
    discard_cqe:      u8,

    // Incoming write-request pipeline (Phase 6). Producers push a
    // 16-byte header { op:u32, lba:u64, nlb:u32 } followed by
    // nlb * 512 bytes of payload onto `req_in`. `req_phase` walks:
    //   0 Header  — accumulating header into req_hdr
    //   1 Payload — accumulating payload into read_buf
    //   2 Submit  — header + payload ready; submit NVMe Write
    //   3 Wait    — write SQE issued, polling the I/O CQE
    req_phase:       u8,
    _pad_req:        u8,
    req_fill:        u16,
    req_lba:         u64,
    req_hdr:         [u8; 16],

    // Namespace geometry (extracted from IdentifyNamespace response).
    ns_size:  u64,
    ns_lbads: u8,
    _pad3:    [u8; 7],

    // Timing anchors.
    wait_start_ms: u64,

    returned_ready: u8,
    _pad2: [u8; 7],

    /// Step counter for periodic heartbeat.
    step_count: u32,
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::NvmeState;
    use super::{p_u8, p_u16, p_u32};
    use super::{SCHEMA_MAX, WRITE_DATA_MAX, WRITE_LBA_DISABLED};

    define_params! {
        NvmeState;

        1, controller_index, u8, 0
            => |s, d, len| { s.controller_index = p_u8(d, len, 0, 0); };

        2, namespace, u32, 1
            => |s, d, len| { s.namespace = p_u32(d, len, 0, 1); };

        3, queue_depth, u16, 32
            => |s, d, len| { s.queue_depth = p_u16(d, len, 0, 32); };

        // Phase 6 one-shot boot-write. `write_lba == 0xFFFFFFFF`
        // (default) disables the write; any other value enables it.
        4, write_lba, u32, 0xFFFFFFFF
            => |s, d, len| { s.write_lba = p_u32(d, len, 0, WRITE_LBA_DISABLED); };

        5, write_data, str, 0
            => |s, d, len| {
                let n = if len > WRITE_DATA_MAX { WRITE_DATA_MAX } else { len };
                let dst = s.write_data.as_mut_ptr();
                let mut i = 0usize;
                while i < n {
                    *dst.add(i) = *d.add(i);
                    i += 1;
                }
                s.write_data_len = n as u16;
            };
    }
}

// ============================================================================
// MMIO helpers — BAR0 is mapped as device memory by the kernel MMU,
// so direct volatile access works (matches rp1_gem). All offsets are
// from `bar0_virt`.
// ============================================================================

unsafe fn reg_r32(s: &NvmeState, off: u64) -> u32 {
    read_volatile((s.bar0_virt + off) as *const u32)
}

unsafe fn reg_w32(s: &NvmeState, off: u64, val: u32) {
    write_volatile((s.bar0_virt + off) as *mut u32, val);
}

unsafe fn reg_r64(s: &NvmeState, off: u64) -> u64 {
    let lo = read_volatile((s.bar0_virt + off) as *const u32) as u64;
    let hi = read_volatile((s.bar0_virt + off + 4) as *const u32) as u64;
    (hi << 32) | lo
}

unsafe fn reg_w64(s: &NvmeState, off: u64, val: u64) {
    write_volatile((s.bar0_virt + off)     as *mut u32, val as u32);
    write_volatile((s.bar0_virt + off + 4) as *mut u32, (val >> 32) as u32);
}

/// Doorbell offset for SQ/CQ n. Admin SQ is n=0.
unsafe fn sq_doorbell(s: &NvmeState, qid: u32) -> u64 {
    REG_SQ0TDBL + ((2 * qid as u64) << (2 + s.dstrd_shift as u64))
}

unsafe fn cq_doorbell(s: &NvmeState, qid: u32) -> u64 {
    REG_SQ0TDBL + (((2 * qid + 1) as u64) << (2 + s.dstrd_shift as u64))
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn log_once(s: &mut NvmeState, msg: &[u8]) {
    if s.logged_state == s.state { return; }
    s.logged_state = s.state;
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

unsafe fn fault(s: &mut NvmeState, code: u8, msg: &[u8]) -> i32 {
    s.state = S_FAULT;
    s.fault_code = code;
    dev_log(&*s.syscalls, 1, msg.as_ptr(), msg.len());
    0
}

unsafe fn now_ms(s: &NvmeState) -> u64 {
    dev_millis(&*s.syscalls)
}

/// Build a 64-byte SQE at `sq_base + slot*64`. Writes all 16 CDWs from
/// `cdw[0..16]`, issues a DMB so the device sees the complete entry,
/// and returns the pointer (useful for callers that want to patch the
/// entry further before ringing the doorbell — unused today).
unsafe fn write_sqe(sq_base: u64, slot: u32, cdw: [u32; 16]) {
    let sqe = (sq_base + (slot as u64) * SQE_BYTES as u64) as *mut u32;
    let mut i = 0usize;
    while i < 16 {
        write_volatile(sqe.add(i), cdw[i]);
        i += 1;
    }
    core::arch::asm!("dmb sy", options(nostack));
}

/// Build an admin-queue SQE for a PRP1-only command and ring the admin
/// SQ tail doorbell. `cid` is the Command Identifier; the device echoes
/// it in the CQE so callers can cross-reference. `prp1_pci` is the PCI
/// bus address (i.e. `arm_addr | PCI_DMA_OFFSET`) of the buffer.
unsafe fn submit_admin_cmd(
    s: &mut NvmeState,
    opcode: u8,
    cid: u16,
    nsid: u32,
    prp1_pci: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
) {
    let cdw = [
        ((cid as u32) << 16) | (opcode as u32),   // CDW0
        nsid,                                       // CDW1
        0, 0,                                       // CDW2-3 (reserved)
        0, 0,                                       // CDW4-5 (MPTR)
        prp1_pci as u32,                           // CDW6 (PRP1 low)
        (prp1_pci >> 32) as u32,                   // CDW7 (PRP1 high)
        0, 0,                                       // CDW8-9 (PRP2)
        cdw10,                                      // CDW10
        cdw11,                                      // CDW11
        cdw12,                                      // CDW12
        0, 0, 0,                                    // CDW13-15
    ];
    write_sqe(s.admin_sq, s.sq_tail, cdw);
    s.sq_tail = (s.sq_tail + 1) % ADMIN_Q_ENTRIES;
    reg_w32(s, sq_doorbell(s, 0), s.sq_tail);
    s.wait_start_ms = now_ms(s);
}

/// Result of polling the admin completion queue head.
enum CqeResult {
    Pending,
    Ok,
    Failed(u16), // Status Code (DW3[31:17])
    Timeout,
}

/// Poll the admin CQ head for a completion matching the current phase.
/// Advances `cq_head` + rings the CQ-head doorbell on completion.
unsafe fn poll_admin_cqe(s: &mut NvmeState) -> CqeResult {
    let cqe = (s.admin_cq + (s.cq_head as u64) * CQE_BYTES as u64) as *const u32;
    let dw3 = read_volatile(cqe.add(3));
    let phase = (dw3 >> 16) & 1;
    if phase != s.cq_phase {
        if now_ms(s).saturating_sub(s.wait_start_ms) > ADMIN_CMD_BUDGET_MS {
            return CqeResult::Timeout;
        }
        return CqeResult::Pending;
    }
    let sc = ((dw3 >> 17) & 0x7FFF) as u16;
    s.cq_head = (s.cq_head + 1) % ADMIN_Q_ENTRIES;
    if s.cq_head == 0 { s.cq_phase ^= 1; }
    reg_w32(s, cq_doorbell(s, 0), s.cq_head);
    if sc == 0 { CqeResult::Ok } else { CqeResult::Failed(sc) }
}

/// Write a hex-formatted u32 to `p[pos..pos+8]` and advance `pos`.
unsafe fn write_hex32(p: *mut u8, pos: &mut usize, v: u32) {
    for i in 0..8 {
        let n = ((v >> (28 - i * 4)) & 0xF) as u8;
        *p.add(*pos) = if n < 10 { b'0' + n } else { b'a' + n - 10 };
        *pos += 1;
    }
}

/// Write a decimal u32 (zero-padded to 3 digits) to `p[pos..pos+3]`.
unsafe fn write_dec3(p: *mut u8, pos: &mut usize, v: u32) {
    let v = v.min(999);
    *p.add(*pos)     = b'0' + ((v / 100) % 10) as u8;
    *p.add(*pos + 1) = b'0' + ((v / 10)  % 10) as u8;
    *p.add(*pos + 2) = b'0' + ( v         % 10) as u8;
    *pos += 3;
}

/// Periodic heartbeat — emitted every ~5 s while the module is live.
/// Keeps the fields that are continuously meaningful while debugging
/// admin-command + I/O-queue work: state machine position, fault
/// code, admin queue indices, current block + block-phase.
///
/// Drops the `wlba` / `id[0]` / `cqe3` fields that earlier bring-up
/// phases used — they show one-shot or quickly-stale values
/// (write_lba is constant after boot; id[0] and cqe3 are buffer
/// memory that gets clobbered by the steady-state block-stream loop).
unsafe fn heartbeat(s: &NvmeState) {
    let mut buf = [0u8; 96];
    let p = buf.as_mut_ptr();
    let mut pos = 0usize;

    let prefix = b"[nvme] hb st=";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p.add(pos), prefix.len());
    pos += prefix.len();
    write_dec3(p, &mut pos, s.state as u32);

    let fc = b" fc=";
    core::ptr::copy_nonoverlapping(fc.as_ptr(), p.add(pos), fc.len());
    pos += fc.len();
    write_dec3(p, &mut pos, s.fault_code as u32);

    let sq = b" sq=";
    core::ptr::copy_nonoverlapping(sq.as_ptr(), p.add(pos), sq.len());
    pos += sq.len();
    write_dec3(p, &mut pos, s.sq_tail);
    *p.add(pos) = b'/';
    pos += 1;
    write_dec3(p, &mut pos, s.cq_head);

    let cb = b" blk=";
    core::ptr::copy_nonoverlapping(cb.as_ptr(), p.add(pos), cb.len());
    pos += cb.len();
    write_dec3(p, &mut pos, s.current_block);
    let bp = b" bp=";
    core::ptr::copy_nonoverlapping(bp.as_ptr(), p.add(pos), bp.len());
    pos += bp.len();
    write_dec3(p, &mut pos, s.blk_phase as u32);

    dev_log(&*s.syscalls, 3, p, pos);

    // Re-emit the Phase 3 acceptance line once we're in READY. The
    // original emit from step_identify_controller fires within the
    // first few scheduler ticks — often before log_net is streaming
    // UDP — so we repeat it here until the log viewer captures it.
    // `emit_identify_info` reads `identify_buf`, which is never
    // clobbered by the steady-state block-stream loop (read_buf is).
    if s.state == S_READY {
        emit_identify_info(s);
    }
}

/// Emit the Phase 4 acceptance line: boot-sector signature at offset
/// 510-511 plus the first 16 bytes of LBA 0, both formatted as hex.
unsafe fn emit_lba0_info(s: &NvmeState) {
    if s.read_buf == 0 { return; }
    let buf = s.read_buf as *const u8;
    let sig = read_volatile(buf.add(510) as *const u16);

    let mut out = [0u8; 80];
    let p = out.as_mut_ptr();
    let mut pos = 0usize;

    let prefix = b"[nvme] LBA0 sig=0x";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
    pos += prefix.len();
    for i in 0..4 {
        let n = ((sig >> (12 - i * 4)) & 0xF) as u8;
        *p.add(pos) = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
        pos += 1;
    }

    let tag = b" first16=";
    core::ptr::copy_nonoverlapping(tag.as_ptr(), p.add(pos), tag.len());
    pos += tag.len();
    for i in 0..16 {
        let b = *buf.add(i);
        let hi = b >> 4;
        let lo = b & 0x0F;
        *p.add(pos)     = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
        *p.add(pos + 1) = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
        pos += 2;
    }

    dev_log(&*s.syscalls, 3, p, pos);
}

/// Emit the `[nvme] VID=0xNNNN MN='...' FR='...'` acceptance line.
/// Called from step_identify_controller on CQE arrival (first emit) and
/// from the heartbeat loop once the state machine is in READY (repeat
/// emit in case log_net hadn't started streaming during the first one).
unsafe fn emit_identify_info(s: &NvmeState) {
    if s.identify_buf == 0 { return; }
    let id = s.identify_buf as *const u8;
    let vid = read_volatile(id.add(ID_VID) as *const u16);

    let mut buf = [0u8; 128];
    let p = buf.as_mut_ptr();
    let prefix = b"[nvme] VID=0x";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
    let mut pos = prefix.len();
    for i in 0..4 {
        let nibble = ((vid >> (12 - i * 4)) & 0xF) as u8;
        *p.add(pos) = if nibble < 10 { b'0' + nibble } else { b'a' + (nibble - 10) };
        pos += 1;
    }
    let mn_tag = b" MN='";
    core::ptr::copy_nonoverlapping(mn_tag.as_ptr(), p.add(pos), mn_tag.len());
    pos += mn_tag.len();
    let mut mn_len = 40usize;
    while mn_len > 0 && *id.add(ID_MN + mn_len - 1) == b' ' { mn_len -= 1; }
    let mut i = 0usize;
    while i < mn_len {
        *p.add(pos) = *id.add(ID_MN + i);
        pos += 1;
        i += 1;
    }
    *p.add(pos) = b'\'';
    pos += 1;
    let fr_tag = b" FR='";
    core::ptr::copy_nonoverlapping(fr_tag.as_ptr(), p.add(pos), fr_tag.len());
    pos += fr_tag.len();
    let mut fr_len = 8usize;
    while fr_len > 0 && *id.add(ID_FR + fr_len - 1) == b' ' { fr_len -= 1; }
    let mut i = 0usize;
    while i < fr_len {
        *p.add(pos) = *id.add(ID_FR + i);
        pos += 1;
        i += 1;
    }
    *p.add(pos) = b'\'';
    pos += 1;
    dev_log(&*s.syscalls, 3, p, pos);
}

/// Zero a DMA page (4 KB, word at a time).
unsafe fn zero_page(phys: u64) {
    let p = phys as *mut u32;
    let mut i = 0usize;
    while i < 1024 {
        write_volatile(p.add(i), 0);
        i += 1;
    }
}

// ============================================================================
// States
// ============================================================================

unsafe fn step_wait_pcie(s: &mut NvmeState) -> i32 {
    log_once(s, b"[nvme] WaitPcie\0");
    if s.pcie_in < 0 {
        s.state = S_MAP_BARS;
        return 0;
    }
    let sys = &*s.syscalls;
    let mut rec = [0u8; 16];
    let n = (sys.channel_read)(s.pcie_in, rec.as_mut_ptr(), 16);
    if n == 16 {
        s.pcie_dev_idx = s.controller_index;
        s.state = S_MAP_BARS;
    }
    0
}

unsafe fn step_map_bars(s: &mut NvmeState) -> i32 {
    log_once(s, b"[nvme] MapBars\0");
    let sys = &*s.syscalls;
    let mut arg = [0u8; 10];
    arg[0] = s.pcie_dev_idx;
    arg[1] = 0;
    let rc = (sys.dev_call)(-1, NIC_BAR_MAP, arg.as_mut_ptr(), 10);
    if rc <= 0 {
        return fault(s, 1, b"[nvme] BAR map failed\0");
    }
    s.bar0_virt = u64::from_le_bytes([
        arg[2], arg[3], arg[4], arg[5], arg[6], arg[7], arg[8], arg[9],
    ]);
    if s.bar0_virt == 0 {
        return fault(s, 2, b"[nvme] BAR0 virt=0\0");
    }
    s.state = S_RESET;
    s.substate = 0;
    0
}

/// Reset: clear CC.EN + CC.SHN, poll CSTS.RDY=0.
/// Baseline: ~50 ms typical on the rig.
unsafe fn step_reset(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            log_once(s, b"[nvme] Reset\0");
            s.cap = reg_r64(s, REG_CAP);
            s.mqes         =  (s.cap        & 0xFFFF) as u16;
            s.timeout_500ms = ((s.cap >> 24) & 0xFF)  as u8;
            s.dstrd_shift   = ((s.cap >> 32) & 0xF)   as u8;
            s.mpsmin        = ((s.cap >> 48) & 0xF)   as u8;
            let _vs = reg_r32(s, REG_VS);
            let cc  = reg_r32(s, REG_CC);
            // Clear EN + SHN. Baseline notes Linux may leave SHN=01
            // after unbind; this converges fresh-power-on and
            // fresh-unbind to the same post-state.
            reg_w32(s, REG_CC, cc & !(CC_EN | CC_SHN_MASK));
            s.wait_start_ms = now_ms(s);
            s.substate = 1;
            0
        }
        _ => {
            let csts = reg_r32(s, REG_CSTS);
            if csts & CSTS_CFS != 0 {
                return fault(s, 3, b"[nvme] CSTS.CFS during reset\0");
            }
            if csts & CSTS_RDY == 0 {
                dev_log(&*s.syscalls, 3, b"[nvme] Reset: RDY=0\0".as_ptr(), 19);
                s.state = S_CONFIG_QUEUES;
                s.substate = 0;
                return 0;
            }
            if now_ms(s).saturating_sub(s.wait_start_ms) > RESET_BUDGET_MS {
                return fault(s, 4, b"[nvme] Reset timeout\0");
            }
            0
        }
    }
}

/// ConfigQueues: allocate admin SQ/CQ/identify pages, program
/// AQA/ASQ/ACQ. Each substate does one unit so the step-guard is
/// never at risk from a slow DMA alloc.
unsafe fn step_config_queues(s: &mut NvmeState) -> i32 {
    let sys = &*s.syscalls;
    match s.substate {
        0 => {
            log_once(s, b"[nvme] ConfigQueues\0");
            let p = dev_dma_alloc(sys, PAGE, PAGE);
            if p == 0 { return fault(s, 5, b"[nvme] SQ alloc fail\0"); }
            zero_page(p);
            s.admin_sq = p;
            s.substate = 1;
            0
        }
        1 => {
            let p = dev_dma_alloc(sys, PAGE, PAGE);
            if p == 0 { return fault(s, 6, b"[nvme] CQ alloc fail\0"); }
            zero_page(p);
            s.admin_cq = p;
            s.substate = 2;
            0
        }
        2 => {
            let p = dev_dma_alloc(sys, PAGE, PAGE);
            if p == 0 { return fault(s, 7, b"[nvme] identify alloc fail\0"); }
            zero_page(p);
            s.identify_buf = p;
            s.substate = 3;
            0
        }
        _ => {
            // AQA: ASQS = ACQS = ADMIN_Q_ENTRIES-1, zero-based.
            let aqa = ((ADMIN_Q_ENTRIES - 1) << 16) | (ADMIN_Q_ENTRIES - 1);
            reg_w32(s, REG_AQA, aqa);
            // ASQ/ACQ must be PCI bus addresses inside the BAR1
            // inbound window. On BCM7712 PCIe1, BAR1 covers PCI
            // 0x10_0000_0000..0x20_0000_0000 and is REMAP'd to fabric
            // 0x0 (ACCESS_EN + cpu_hi=0), so PCI addr
            // `arm_arena_addr | 0x10_0000_0000` lands at our arena.
            reg_w64(s, REG_ASQ, s.admin_sq | PCI_DMA_OFFSET);
            reg_w64(s, REG_ACQ, s.admin_cq | PCI_DMA_OFFSET);
            s.state = S_ENABLE;
            s.substate = 0;
            0
        }
    }
}

/// Enable: set CC.EN with queue entry sizes, poll CSTS.RDY=1.
/// Baseline: ~12 ms typical on the rig.
unsafe fn step_enable(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            log_once(s, b"[nvme] Enable\0");
            let cc = CC_EN | CC_CSS_NVM | CC_IOSQES_6 | CC_IOCQES_4;
            reg_w32(s, REG_CC, cc);
            s.wait_start_ms = now_ms(s);
            s.substate = 1;
            0
        }
        _ => {
            let csts = reg_r32(s, REG_CSTS);
            if csts & CSTS_CFS != 0 {
                return fault(s, 8, b"[nvme] CSTS.CFS during enable\0");
            }
            if csts & CSTS_RDY != 0 {
                dev_log(&*s.syscalls, 3, b"[nvme] Enable: RDY=1\0".as_ptr(), 20);
                s.state = S_IDENTIFY_CONTROLLER;
                s.substate = 0;
                s.sq_tail = 0;
                s.cq_head = 0;
                s.cq_phase = 1; // Initial expected phase bit (flipped each wrap).
                return 0;
            }
            if now_ms(s).saturating_sub(s.wait_start_ms) > ENABLE_BUDGET_MS {
                return fault(s, 9, b"[nvme] Enable timeout\0");
            }
            0
        }
    }
}

/// Build Identify Controller SQE at SQ[0], ring doorbell, poll CQ[0].
/// On completion, log VID/SN/MN/FR from the response buffer.
unsafe fn step_identify_controller(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            log_once(s, b"[nvme] IdentifyController\0");
            // SQE at admin_sq + sq_tail * 64. NVMe 1.4 §4.2.
            let sqe = (s.admin_sq + (s.sq_tail as u64) * SQE_BYTES as u64) as *mut u32;
            // CDW0: OPC=0x06 (Identify) in [7:0], CID=0x0001 in [31:16]
            write_volatile(sqe.add(0), (0x0001u32 << 16) | 0x06);
            write_volatile(sqe.add(1), 0); // NSID (0 for controller identify)
            write_volatile(sqe.add(2), 0);
            write_volatile(sqe.add(3), 0);
            write_volatile(sqe.add(4), 0); // MPTR lo
            write_volatile(sqe.add(5), 0); // MPTR hi
            // PRP1 = PCI bus address inside BAR1's inbound window.
            // See PCI_DMA_OFFSET — BAR1 maps PCI 0x10_0000_0000+X to
            // fabric/ARM addr X for X in low 4 GB.
            let prp1_pci = s.identify_buf | PCI_DMA_OFFSET;
            write_volatile(sqe.add(6), prp1_pci as u32);
            write_volatile(sqe.add(7), (prp1_pci >> 32) as u32);
            write_volatile(sqe.add(8), 0); // PRP2
            write_volatile(sqe.add(9), 0);
            write_volatile(sqe.add(10), 0x01); // CDW10: CNS=0x01 (Identify Controller)
            write_volatile(sqe.add(11), 0);
            write_volatile(sqe.add(12), 0);
            write_volatile(sqe.add(13), 0);
            write_volatile(sqe.add(14), 0);
            write_volatile(sqe.add(15), 0);
            // DMB before doorbell so device sees the fully-formed SQE.
            core::arch::asm!("dmb sy", options(nostack));
            s.sq_tail = (s.sq_tail + 1) % ADMIN_Q_ENTRIES;
            reg_w32(s, sq_doorbell(s, 0), s.sq_tail);
            s.wait_start_ms = now_ms(s);
            s.substate = 1;
            0
        }
        _ => {
            let cqe = (s.admin_cq + (s.cq_head as u64) * CQE_BYTES as u64) as *const u32;
            let dw3 = read_volatile(cqe.add(3));
            let phase = (dw3 >> 16) & 1;
            if phase != s.cq_phase {
                if now_ms(s).saturating_sub(s.wait_start_ms) > ADMIN_CMD_BUDGET_MS {
                    return fault(s, 10, b"[nvme] Identify CQE timeout\0");
                }
                return 0; // still waiting
            }
            // CQE present. Status field = DW3[31:17].
            let sc = (dw3 >> 17) & 0x7FFF;
            if sc != 0 {
                return fault(s, 11, b"[nvme] Identify failed\0");
            }

            emit_identify_info(s);

            // Ring CQ head doorbell.
            s.cq_head = (s.cq_head + 1) % ADMIN_Q_ENTRIES;
            if s.cq_head == 0 { s.cq_phase ^= 1; }
            reg_w32(s, cq_doorbell(s, 0), s.cq_head);

            s.state = S_IDENTIFY_NAMESPACE;
            s.substate = 0;
            0
        }
    }
}

/// Identify Namespace (CNS=0x00). Lands into a dedicated buffer so the
/// Phase 3 acceptance line can keep re-emitting from `identify_buf`.
/// Extracts namespace size + LBA format shift for later use.
unsafe fn step_identify_namespace(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            log_once(s, b"[nvme] IdentifyNamespace\0");
            let sys = &*s.syscalls;
            if s.identify_ns_buf == 0 {
                let p = dev_dma_alloc(sys, PAGE, PAGE);
                if p == 0 { return fault(s, 12, b"[nvme] id-ns alloc fail\0"); }
                zero_page(p);
                s.identify_ns_buf = p;
            }
            submit_admin_cmd(
                s, OPC_IDENTIFY, CID_IDENTIFY_NS, s.namespace,
                s.identify_ns_buf | PCI_DMA_OFFSET,
                0x00, 0, 0,
            );
            s.substate = 1;
            0
        }
        _ => match poll_admin_cqe(s) {
            CqeResult::Pending => 0,
            CqeResult::Timeout => fault(s, 13, b"[nvme] IdentifyNs CQE timeout\0"),
            CqeResult::Failed(_) => fault(s, 14, b"[nvme] IdentifyNs failed\0"),
            CqeResult::Ok => {
                let id = s.identify_ns_buf as *const u8;
                s.ns_size = read_volatile(id.add(INS_NSZE) as *const u64);
                let flbas = read_volatile(id.add(INS_FLBAS)) & 0x0F;
                let lbaf_off = INS_LBAF0 + (flbas as usize) * 4;
                let lbaf = read_volatile(id.add(lbaf_off) as *const u32);
                s.ns_lbads = ((lbaf >> 16) & 0xFF) as u8;
                s.state = S_CREATE_IO_CQ;
                s.substate = 0;
                0
            }
        }
    }
}

/// Create I/O Completion Queue (QID=1). PC=1 (physically contiguous),
/// IV=0, IEN=0 (polled — no interrupt vector).
unsafe fn step_create_io_cq(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            log_once(s, b"[nvme] CreateIoCQ\0");
            let sys = &*s.syscalls;
            if s.io_cq == 0 {
                let p = dev_dma_alloc(sys, PAGE, PAGE);
                if p == 0 { return fault(s, 15, b"[nvme] io cq alloc fail\0"); }
                zero_page(p);
                s.io_cq = p;
            }
            let cdw10 = ((IO_Q_ENTRIES - 1) << 16) | (IO_QID as u32);
            let cdw11: u32 = 0x0000_0001; // PC=1, IEN=0, IV=0
            submit_admin_cmd(
                s, OPC_CREATE_CQ, CID_CREATE_IO_CQ, 0,
                s.io_cq | PCI_DMA_OFFSET,
                cdw10, cdw11, 0,
            );
            s.substate = 1;
            0
        }
        _ => match poll_admin_cqe(s) {
            CqeResult::Pending => 0,
            CqeResult::Timeout => fault(s, 16, b"[nvme] CreateIoCQ CQE timeout\0"),
            CqeResult::Failed(_) => fault(s, 17, b"[nvme] CreateIoCQ failed\0"),
            CqeResult::Ok => {
                s.io_cq_head = 0;
                s.io_cq_phase = 1;
                s.state = S_CREATE_IO_SQ;
                s.substate = 0;
                0
            }
        }
    }
}

/// Create I/O Submission Queue (QID=1, paired with IO_QID CQ).
unsafe fn step_create_io_sq(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            log_once(s, b"[nvme] CreateIoSQ\0");
            let sys = &*s.syscalls;
            if s.io_sq == 0 {
                let p = dev_dma_alloc(sys, PAGE, PAGE);
                if p == 0 { return fault(s, 18, b"[nvme] io sq alloc fail\0"); }
                zero_page(p);
                s.io_sq = p;
            }
            let cdw10 = ((IO_Q_ENTRIES - 1) << 16) | (IO_QID as u32);
            // CDW11: CQID[31:16] | QPRIO[2:1]=0 (medium) | PC[0]=1
            let cdw11: u32 = ((IO_QID as u32) << 16) | 0x0000_0001;
            submit_admin_cmd(
                s, OPC_CREATE_SQ, CID_CREATE_IO_SQ, 0,
                s.io_sq | PCI_DMA_OFFSET,
                cdw10, cdw11, 0,
            );
            s.substate = 1;
            0
        }
        _ => match poll_admin_cqe(s) {
            CqeResult::Pending => 0,
            CqeResult::Timeout => fault(s, 19, b"[nvme] CreateIoSQ CQE timeout\0"),
            CqeResult::Failed(_) => fault(s, 20, b"[nvme] CreateIoSQ failed\0"),
            CqeResult::Ok => {
                s.io_sq_tail = 0;
                s.state = S_WRITE_ONCE;
                s.substate = 0;
                0
            }
        }
    }
}

/// Submit a 1-block Write command on the I/O SQ for `lba`, sourcing
/// DMA from `dma_buf`. Boot-time WRITE_ONCE uses `read_buf`;
/// consumer-driven writes via `req_in` use `write_buf` so they don't
/// alias an in-flight read.
unsafe fn submit_io_write(s: &mut NvmeState, lba: u64, cid: u16, dma_buf: u64) {
    let prp1_pci = dma_buf | PCI_DMA_OFFSET;
    let cdw = [
        ((cid as u32) << 16) | (OPC_WRITE as u32),
        s.namespace,
        0, 0,
        0, 0,
        prp1_pci as u32, (prp1_pci >> 32) as u32,
        0, 0,
        lba as u32,
        (lba >> 32) as u32,
        0,
        0, 0, 0,
    ];
    write_sqe(s.io_sq, s.io_sq_tail, cdw);
    s.io_sq_tail = (s.io_sq_tail + 1) % IO_Q_ENTRIES;
    reg_w32(s, sq_doorbell(s, IO_QID as u32), s.io_sq_tail);
    s.wait_start_ms = now_ms(s);
}

/// One-shot boot-time Write. Zero-pads `write_data[..write_data_len]`
/// into `read_buf` (512 B) and writes it to `write_lba`. Skipped when
/// `write_lba == WRITE_LBA_DISABLED`. Acceptance: Linux reads the
/// expected bytes back from that LBA after a power-off → Fluxor →
/// power-off → Linux cycle.
unsafe fn step_write_once(s: &mut NvmeState) -> i32 {
    if s.write_lba == WRITE_LBA_DISABLED {
        s.state = S_READ_LBA0;
        s.substate = 0;
        return 0;
    }
    match s.substate {
        0 => {
            log_once(s, b"[nvme] WriteOnce\0");
            // step_read_lba0 normally allocates `read_buf`; we run
            // before it, so allocate here on demand. Without this,
            // PRP1 = `0 | PCI_DMA_OFFSET` and the device DMAs from
            // fabric address 0 (kernel image), writing arbitrary
            // bytes to the target LBA.
            let sys = &*s.syscalls;
            if s.read_buf == 0 {
                let p = dev_dma_alloc(sys, PAGE, PAGE);
                if p == 0 { return fault(s, 29, b"[nvme] WriteOnce buf alloc fail\0"); }
                s.read_buf = p;
            }
            // Zero-pad the block, then copy the payload into the
            // front. Using write_volatile for the zero fill matches
            // the rest of the module's pattern for device-visible
            // writes on a non-cacheable page.
            let buf = s.read_buf as *mut u32;
            let mut i = 0usize;
            while i < (BLOCK_SIZE as usize) / 4 {
                write_volatile(buf.add(i), 0);
                i += 1;
            }
            let bbuf = s.read_buf as *mut u8;
            let n = s.write_data_len as usize;
            let mut j = 0usize;
            while j < n {
                write_volatile(bbuf.add(j), *s.write_data.as_ptr().add(j));
                j += 1;
            }
            submit_io_write(s, s.write_lba as u64, CID_WRITE_ONCE, s.read_buf);
            s.substate = 1;
            0
        }
        _ => match poll_io_cqe(s) {
            CqeResult::Pending => 0,
            CqeResult::Timeout => fault(s, 27, b"[nvme] WriteOnce CQE timeout\0"),
            CqeResult::Failed(_) => fault(s, 28, b"[nvme] WriteOnce failed\0"),
            CqeResult::Ok => {
                dev_log(&*s.syscalls, 3,
                    b"[nvme] WriteOnce ok\0".as_ptr(), 19);
                s.state = S_READ_LBA0;
                s.substate = 0;
                0
            }
        }
    }
}

/// One-shot read of LBA 0 via the I/O queue; log boot-sector signature
/// and the first 16 bytes. Proves the DMA + I/O queue path works
/// end-to-end before declaring READY.
unsafe fn step_read_lba0(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            log_once(s, b"[nvme] ReadLba0\0");
            let sys = &*s.syscalls;
            if s.read_buf == 0 {
                let p = dev_dma_alloc(sys, PAGE, PAGE);
                if p == 0 { return fault(s, 21, b"[nvme] read buf alloc fail\0"); }
                s.read_buf = p;
            }
            // Prime the buffer with a sentinel pattern before the
            // read so a zero-returning (blank) LBA can be distinguished
            // from a failed DMA in the acceptance log.
            let buf = s.read_buf as *mut u32;
            let mut i = 0usize;
            while i < 1024 {
                write_volatile(buf.add(i), 0xDEAD_BEEF);
                i += 1;
            }
            // If the one-shot boot-write ran, read that LBA back so
            // emit_lba0_info becomes a Phase-6 round-trip check.
            // Otherwise fall through to LBA 0 (Phase 4 proof).
            let readback_lba = if s.write_lba != WRITE_LBA_DISABLED {
                s.write_lba as u64
            } else {
                0
            };
            submit_io_read(s, readback_lba, CID_READ_LBA0);
            s.substate = 1;
            0
        }
        _ => match poll_io_cqe(s) {
            CqeResult::Pending => 0,
            CqeResult::Timeout => fault(s, 22, b"[nvme] ReadLba0 CQE timeout\0"),
            CqeResult::Failed(_) => fault(s, 23, b"[nvme] ReadLba0 failed\0"),
            CqeResult::Ok => {
                emit_lba0_info(s);
                // Hand control to the block-streaming loop starting at
                // LBA 0. A FAT32 consumer's first IOCTL_NOTIFY targets
                // LBA 0 anyway (the boot sector); starting there avoids
                // a race where fat32's seek arrives after we've
                // already streamed an unrelated LBA into its buffer.
                s.current_block = 0;
                s.write_offset = 0;
                s.blk_phase = BLK_PHASE_IDLE;
                s.state = S_READY;
                s.substate = 0;
                0
            }
        }
    }
}

/// Submit a 1-block Read command on the I/O SQ for `lba`. Data lands
/// at `s.read_buf`. Used by both Phase 4 (LBA 0 one-shot) and Phase 5
/// (block-streaming loop).
unsafe fn submit_io_read(s: &mut NvmeState, lba: u64, cid: u16) {
    let prp1_pci = s.read_buf | PCI_DMA_OFFSET;
    let cdw = [
        ((cid as u32) << 16) | (OPC_READ as u32),
        s.namespace,
        0, 0,
        0, 0,
        prp1_pci as u32, (prp1_pci >> 32) as u32,
        0, 0,
        lba as u32,         // CDW10: SLBA lo
        (lba >> 32) as u32, // CDW11: SLBA hi
        0,                  // CDW12: NLB-1 = 0 → 1 block
        0, 0, 0,
    ];
    write_sqe(s.io_sq, s.io_sq_tail, cdw);
    s.io_sq_tail = (s.io_sq_tail + 1) % IO_Q_ENTRIES;
    reg_w32(s, sq_doorbell(s, IO_QID as u32), s.io_sq_tail);
    s.wait_start_ms = now_ms(s);
}

/// Poll the I/O CQ head for a completion matching the current phase.
unsafe fn poll_io_cqe(s: &mut NvmeState) -> CqeResult {
    let cqe = (s.io_cq + (s.io_cq_head as u64) * CQE_BYTES as u64) as *const u32;
    let dw3 = read_volatile(cqe.add(3));
    let phase = (dw3 >> 16) & 1;
    if phase != s.io_cq_phase {
        if now_ms(s).saturating_sub(s.wait_start_ms) > IO_READ_BUDGET_MS {
            return CqeResult::Timeout;
        }
        return CqeResult::Pending;
    }
    let sc = ((dw3 >> 17) & 0x7FFF) as u16;
    s.io_cq_head = (s.io_cq_head + 1) % IO_Q_ENTRIES;
    if s.io_cq_head == 0 { s.io_cq_phase ^= 1; }
    reg_w32(s, cq_doorbell(s, IO_QID as u32), s.io_cq_head);
    if sc == 0 { CqeResult::Ok } else { CqeResult::Failed(sc) }
}

/// Check the block-output channel for a consumer-originated seek
/// (IOCTL_POLL_NOTIFY); apply it to `current_block` if present.
/// Returns true if a seek was applied.
unsafe fn apply_pending_seek(s: &mut NvmeState) -> bool {
    if s.blk_out < 0 { return false; }
    let mut seek: u32 = 0;
    let res = dev_channel_ioctl(
        &*s.syscalls, s.blk_out,
        IOCTL_POLL_NOTIFY,
        &mut seek as *mut u32 as *mut u8,
    );
    if res == 0 {
        s.current_block = seek;
        s.write_offset = 0;
        true
    } else {
        false
    }
}

/// READY-state block I/O loop. Drives a seek → read → stream pipeline
/// on the `blocks` output channel, matching the contract `sd.blocks →
/// fat32.blocks` uses today: sequential 512 B byte stream with a
/// consumer-originated seek via `IOCTL_POLL_NOTIFY`.
/// Phase 6 write-request pump. Drains 528-byte packets off `req_in`
/// (header + single-block payload) and issues NVMe Writes. Returns
/// `true` if the pump owns the I/O queue this tick and block-streaming
/// should stall (so it doesn't submit a concurrent SQE that would
/// share `read_buf`).
unsafe fn pump_requests(s: &mut NvmeState) -> bool {
    if s.req_in < 0 { return false; }
    let sys = &*s.syscalls;

    match s.req_phase {
        0 => {
            // Accumulate the 16-byte header.
            let need = 16 - s.req_fill as usize;
            let dst = s.req_hdr.as_mut_ptr().add(s.req_fill as usize);
            let n = (sys.channel_read)(s.req_in, dst, need);
            if n <= 0 { return false; }
            s.req_fill += n as u16;
            if s.req_fill as usize == 16 {
                // Parse: op @ 0..4, lba @ 4..12, nlb @ 12..16. v1 only
                // handles op=1 (WRITE) with nlb=1 (single-block).
                let op = u32::from_le_bytes([
                    s.req_hdr[0], s.req_hdr[1], s.req_hdr[2], s.req_hdr[3],
                ]);
                let lba = u64::from_le_bytes([
                    s.req_hdr[4],  s.req_hdr[5],  s.req_hdr[6],  s.req_hdr[7],
                    s.req_hdr[8],  s.req_hdr[9],  s.req_hdr[10], s.req_hdr[11],
                ]);
                if op != 1 {
                    // Unknown op — drop and resync. v1 has no other ops.
                    s.req_fill = 0;
                    dev_log(sys, 3, b"[nvme] req: unknown op\0".as_ptr(), 22);
                    return false;
                }
                s.req_lba = lba;
                s.req_fill = 0;
                s.req_phase = 1;
            }
            true
        }
        1 => {
            // Accumulate 512 bytes of payload into the dedicated
            // write_buf so the in-flight read pipeline (which owns
            // read_buf) is unaffected.
            if s.write_buf == 0 {
                let p = dev_dma_alloc(sys, PAGE, PAGE);
                if p == 0 {
                    fault(s, 30, b"[nvme] req buf alloc fail\0");
                    return true;
                }
                s.write_buf = p;
            }
            let need = (BLOCK_SIZE - s.req_fill as u32) as usize;
            let dst = (s.write_buf as *mut u8).add(s.req_fill as usize);
            let n = (sys.channel_read)(s.req_in, dst, need);
            if n <= 0 { return true; }
            s.req_fill += n as u16;
            if s.req_fill as u32 >= BLOCK_SIZE {
                s.req_phase = 2;
            }
            true
        }
        2 => {
            submit_io_write(s, s.req_lba, CID_WRITE_ONCE, s.write_buf);
            s.req_phase = 3;
            true
        }
        _ => match poll_io_cqe(s) {
            CqeResult::Pending => true,
            CqeResult::Timeout => {
                fault(s, 31, b"[nvme] req write CQE timeout\0");
                true
            }
            CqeResult::Failed(_) => {
                fault(s, 32, b"[nvme] req write failed\0");
                true
            }
            CqeResult::Ok => {
                dev_log(&*s.syscalls, 3, b"[nvme] req write ok\0".as_ptr(), 19);
                s.req_phase = 0;
                s.req_fill = 0;
                false
            }
        }
    }
}

unsafe fn step_ready(s: &mut NvmeState) -> i32 {
    log_once(s, b"[nvme] Ready\0");
    if s.returned_ready == 0 {
        s.returned_ready = 1;
        return 3; // signal scheduler we've reached the steady state
    }
    // Service incoming write requests first. When one is mid-flight
    // it owns the I/O queue for the duration (read_buf + CQE), so we
    // pause block-streaming until it completes.
    if pump_requests(s) {
        return 0;
    }
    if s.blk_out < 0 {
        return 0;
    }

    // Check for consumer seek on every tick. fat32 (and the
    // `sd → fat32` contract in general) calls `flush_input` + `seek`
    // before reading a specific LBA; a seek that lands while we are
    // mid-read or mid-write must abort the in-flight block so the
    // next bytes the consumer reads are from the seeked LBA, not
    // from whatever happened to be in flight.
    if apply_pending_seek(s) {
        match s.blk_phase {
            BLK_PHASE_READING => {
                // CQE still outstanding; we must harvest it to free
                // the queue slot but must not forward the data.
                s.discard_cqe = 1;
            }
            BLK_PHASE_WRITING => {
                // Abort the remaining bytes of the current block.
                // Any bytes already written were flushed from the
                // channel ring by the consumer's flush_input.
                s.write_offset = 0;
                s.blk_phase = BLK_PHASE_IDLE;
            }
            _ => {}
        }
    }

    match s.blk_phase {
        BLK_PHASE_IDLE => {
            let sys = &*s.syscalls;
            let poll = (sys.channel_poll)(s.blk_out, POLL_OUT);
            if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
                return 0;
            }
            submit_io_read(s, s.current_block as u64, CID_READ_LBA0);
            s.blk_phase = BLK_PHASE_READING;
            0
        }
        BLK_PHASE_READING => match poll_io_cqe(s) {
            CqeResult::Pending => 0,
            CqeResult::Timeout => fault(s, 24, b"[nvme] block read CQE timeout\0"),
            CqeResult::Failed(_) => fault(s, 25, b"[nvme] block read failed\0"),
            CqeResult::Ok => {
                if s.discard_cqe != 0 {
                    // A seek arrived while this read was in flight —
                    // drop the result and let the IDLE branch pick the
                    // seeked LBA on the next tick.
                    s.discard_cqe = 0;
                    s.blk_phase = BLK_PHASE_IDLE;
                } else {
                    s.write_offset = 0;
                    s.blk_phase = BLK_PHASE_WRITING;
                }
                0
            }
        },
        _ => {
            // BLK_PHASE_WRITING: push bytes to the output channel, handle
            // partial writes + backpressure.
            let sys = &*s.syscalls;
            let remaining = BLOCK_SIZE - (s.write_offset as u32);
            let src = (s.read_buf as *const u8).add(s.write_offset as usize);
            let n = (sys.channel_write)(s.blk_out, src, remaining as usize);
            if n < 0 {
                if n == E_AGAIN { return 0; }
                return fault(s, 26, b"[nvme] blocks channel write err\0");
            }
            let written = n as u32;
            s.write_offset += written as u16;
            if s.write_offset as u32 >= BLOCK_SIZE {
                s.current_block = s.current_block.wrapping_add(1);
                s.write_offset = 0;
                s.blk_phase = BLK_PHASE_IDLE;
            }
            0
        }
    }
}

unsafe fn step_fault(s: &mut NvmeState) -> i32 {
    log_once(s, b"[nvme] Fault\0");
    // Fault code 1 = MapBars failed (enumerate() returned 0 devices
    // because the link wasn't trained yet). Periodically re-trigger
    // kernel enumeration; if it now finds the device, retry the BAR
    // map and re-enter S_RESET.
    if s.fault_code == 1 && s.step_count % 5000 == 4999 {
        let sys = &*s.syscalls;
        let rescan = (sys.dev_call)(-1, PCIE_RESCAN, core::ptr::null_mut(), 0);
        let mut arg = [0u8; 10];
        arg[0] = s.pcie_dev_idx;
        arg[1] = 0;
        let rc = (sys.dev_call)(-1, NIC_BAR_MAP, arg.as_mut_ptr(), 10);

        if rescan > 0 && rc > 0 {
            s.bar0_virt = u64::from_le_bytes([
                arg[2], arg[3], arg[4], arg[5], arg[6], arg[7], arg[8], arg[9],
            ]);
            s.state = S_RESET;
            s.substate = 0;
            s.fault_code = 0;
            s.logged_state = 0xFE;
            dev_log(sys, 3, b"[nvme] link up, retrying Reset\0".as_ptr(), 30);
        }
    }
    0
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<NvmeState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<NvmeState>() { return -2; }

        let s = &mut *(state as *mut NvmeState);
        core::ptr::write_bytes(s as *mut NvmeState as *mut u8, 0, core::mem::size_of::<NvmeState>());
        s.syscalls = syscalls as *const SyscallTable;
        s.pcie_in = in_chan;
        // Second input port (`requests`, index 1) carries Phase 6
        // write-request packets from fat32 or any other producer.
        s.req_in  = dev_channel_port(&*s.syscalls, 0, 1);
        s.blk_out = out_chan;
        s.ctrl    = ctrl_chan;
        s.state = S_WAIT_PCIE;
        s.logged_state = 0xFE;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        dev_log(&*s.syscalls, 3, b"[nvme] init\0".as_ptr(), 11);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut NvmeState);

    s.step_count = s.step_count.wrapping_add(1);
    if s.step_count % 5000 == 0 {
        heartbeat(s);
    }

    match s.state {
        S_WAIT_PCIE           => step_wait_pcie(s),
        S_MAP_BARS            => step_map_bars(s),
        S_RESET               => step_reset(s),
        S_CONFIG_QUEUES       => step_config_queues(s),
        S_ENABLE              => step_enable(s),
        S_IDENTIFY_CONTROLLER => step_identify_controller(s),
        S_IDENTIFY_NAMESPACE  => step_identify_namespace(s),
        S_CREATE_IO_CQ        => step_create_io_cq(s),
        S_CREATE_IO_SQ        => step_create_io_sq(s),
        S_WRITE_ONCE          => step_write_once(s),
        S_READ_LBA0           => step_read_lba0(s),
        S_READY               => step_ready(s),
        _                     => step_fault(s),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

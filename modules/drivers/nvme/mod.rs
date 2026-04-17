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
const S_READY:               u8 = 9;
const S_FAULT:               u8 = 0xFF;

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

    // DMA (phys == virt under identity mapping).
    admin_sq: u64,
    admin_cq: u64,
    identify_buf: u64,

    // Queue indices.
    sq_tail: u32,
    cq_head: u32,
    cq_phase: u32,

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
    use super::SCHEMA_MAX;

    define_params! {
        NvmeState;

        1, controller_index, u8, 0
            => |s, d, len| { s.controller_index = p_u8(d, len, 0, 0); };

        2, namespace, u32, 1
            => |s, d, len| { s.namespace = p_u32(d, len, 0, 1); };

        3, queue_depth, u16, 32
            => |s, d, len| { s.queue_depth = p_u16(d, len, 0, 32); };
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
/// Keeps fields useful for debugging admin-command + I/O-queue work
/// (state, fault, queue indices, first word of the last admin response
/// buffer, last CQE word 3). Re-emits the Phase 3 `VID=0x...` line
/// while in READY so it reaches the UDP log viewer reliably.
unsafe fn heartbeat(s: &NvmeState) {
    let mut buf = [0u8; 128];
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

    let sq = b" sq_tail=";
    core::ptr::copy_nonoverlapping(sq.as_ptr(), p.add(pos), sq.len());
    pos += sq.len();
    write_dec3(p, &mut pos, s.sq_tail);

    let cq = b" cq_head=";
    core::ptr::copy_nonoverlapping(cq.as_ptr(), p.add(pos), cq.len());
    pos += cq.len();
    write_dec3(p, &mut pos, s.cq_head);

    let ph = b" cq_phase=";
    core::ptr::copy_nonoverlapping(ph.as_ptr(), p.add(pos), ph.len());
    pos += ph.len();
    write_dec3(p, &mut pos, s.cq_phase);

    if s.identify_buf != 0 {
        let id0 = b" id[0]=0x";
        core::ptr::copy_nonoverlapping(id0.as_ptr(), p.add(pos), id0.len());
        pos += id0.len();
        write_hex32(p, &mut pos, read_volatile(s.identify_buf as *const u32));
    }

    if s.admin_cq != 0 {
        let cqe3 = b" cqe3=0x";
        core::ptr::copy_nonoverlapping(cqe3.as_ptr(), p.add(pos), cqe3.len());
        pos += cqe3.len();
        let cqe = read_volatile((s.admin_cq + (s.cq_head as u64) * CQE_BYTES as u64 + 12) as *const u32);
        write_hex32(p, &mut pos, cqe);
    }

    dev_log(&*s.syscalls, 3, p, pos);

    // Re-emit the Phase 3 acceptance line once we're in READY. The
    // original emit from step_identify_controller fires within the
    // first few scheduler ticks — often before log_net is streaming
    // UDP — so we repeat it here until the log viewer captures it.
    if s.state == S_READY {
        emit_identify_info(s);
    }
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

unsafe fn step_identify_namespace(s: &mut NvmeState) -> i32 {
    // Phase 4 — for Phase 3 we advance straight to Ready so downstream
    // consumers (once wired) don't block forever on a stubbed state.
    log_once(s, b"[nvme] IdentifyNamespace (Phase 4 TODO)\0");
    s.state = S_CREATE_IO_CQ;
    0
}

unsafe fn step_create_io_cq(s: &mut NvmeState) -> i32 {
    log_once(s, b"[nvme] CreateIoCQ (Phase 4 TODO)\0");
    s.state = S_CREATE_IO_SQ;
    0
}

unsafe fn step_create_io_sq(s: &mut NvmeState) -> i32 {
    log_once(s, b"[nvme] CreateIoSQ (Phase 4 TODO)\0");
    s.state = S_READY;
    if s.returned_ready == 0 {
        s.returned_ready = 1;
        return 3; // Ready
    }
    0
}

unsafe fn step_ready(s: &mut NvmeState) -> i32 {
    log_once(s, b"[nvme] Ready (Phase 5/6 TODO)\0");
    0
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
        s.req_in  = -1;
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
        S_READY               => step_ready(s),
        _                     => step_fault(s),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

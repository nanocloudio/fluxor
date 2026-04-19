//! NVMe block driver — Pi 5 / CM5 PCIe1 external slot.
//!
//! See `README.md` for the state-machine contract, spec citations, and
//! the bring-up checklist. See `hw/nvme_trace/baseline/` for the
//! reference trace this module is written against (Biwin
//! CE430T5D100-512G).
//!
//! # Shape
//!
//! State machine: Reset → ConfigQueues → Enable → IdentifyController →
//! IdentifyNamespace → (per queue) CreateIoCQ → CreateIoSQ → ReadLba0
//! → Ready. In Ready the driver serves a byte-stream `blocks` channel
//! (multi-block reads into `read_buf`, drained to the consumer 512 B
//! at a time) and a `requests` channel carrying write packets (header
//! + NLB × 512 B payload, one SQE per packet, up to `inflight_cap` in
//! flight per queue concurrently).
//!
//! Up to `MAX_IO_QUEUES` I/O queue pairs (`io_queue_count` parameter,
//! default 1). With `irq_mode = 1` the driver programs MSI-X table
//! entry 0 against the brcmstb MSI mux and asks CreateIoCQ for
//! interrupt delivery; otherwise the CQ is drained by polling in
//! step_ready.
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

/// `PCIE_CFG_WRITE32` syscall opcode. Mirror of 0x0CF6 (read).
const PCIE_CFG_WRITE32: u32 = 0x0CF7;
/// `PCIE1_MSI_INIT` — brings up the brcmstb MSI controller behind
/// a caller-supplied GIC SPI. Idempotent.
const PCIE1_MSI_INIT: u32 = 0x0CD0;
/// `PCIE1_MSI_ALLOC_VECTOR` — assigns one of the 32 MSI vectors to
/// a previously-created event fd. Returns (vector, target_addr, data)
/// for writing into the peripheral's MSI-X table entry.
const PCIE1_MSI_ALLOC_VECTOR: u32 = 0x0CD1;

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

/// Max NLB per I/O SQE. PRP1 covers one 4 KB page = 8 × 512-byte
/// LBAs; callers that need more must split (no PRP2 / PRP-list).
const MAX_NLB: u16 = 8;

/// Inbound write-request header on `req_in`: op:u32 | lba:u64 | nlb:u32 |
/// nsid:u32. Producers (fat32, future block consumers) stage 20 B before
/// the payload; nsid=0 falls back to `s.namespace`.
const REQ_HDR_SIZE: usize = 20;

/// CIDs for synchronous pager I/O. Outside all other
/// ranges (admin 0x0001..=0x000F, block-read CID_READ_LBA0=0x0005,
/// inflight writes CID_IO_WRITE_BASE..=CID_IO_WRITE_BASE+7 i.e.
/// 0x0100..=0x0107) so `poll_io_cqe` routines can't mistake them.
const CID_PAGER_READ:  u16 = 0x0200;
const CID_PAGER_WRITE: u16 = 0x0201;

/// Budget for the pager's synchronous spin-poll (ms). Generous —
/// the fault handler blocks for this long on slow-media worst case.
const PAGER_SUBMIT_BUDGET_MS: u64 = 2000;

/// Opcodes the kernel's `nvme_backing::dispatch` forwards to us.
/// Must match `src/kernel/nvme_backing.rs::op`.
const PAGER_OP_READ:  u32 = 0x0001;
const PAGER_OP_WRITE: u32 = 0x0002;
const PAGER_OP_FLUSH: u32 = 0x0003;

/// New syscall opcode: `NVME_BACKING_ENABLE = 0x0CED`.
const NVME_BACKING_ENABLE: u32 = 0x0CED;

/// FNV-1a 32-bit hash of the export symbol name. The kernel
/// `resolve_register_target` resolves this back to the function
/// address inside our module image.
const NVME_BACKING_DISPATCH_HASH: u32 = fnv1a(b"nvme_backing_dispatch");

/// Module-registered ioctl on `req_in`: query namespace geometry.
///
/// Arg layout (13 B scratch provided by caller, bi-directional):
///   in:  `nsid: u32 LE` at offset 0 (0 ⇒ whatever namespace nvme was
///        configured with via the `namespace` param)
///   out: `ns_size: u64 LE` at offset 0, `ns_lbads: u8` at offset 8
///
/// Returns `CHAN_OK` on success; `-11` (EAGAIN) if IdentifyNamespace
/// hasn't completed yet; `-22` (EINVAL) if the requested nsid doesn't
/// match the controller's active namespace (the driver serves only
/// the namespace configured via the `namespace` parameter).
const IOCTL_NVME_NS_INFO: u32 = 0x4E56_0001;

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
const S_READ_LBA0:           u8 = 9;
const S_READY:               u8 = 10;
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

// I/O queue sizing. QIDs 1..=io_q_count form `io_q_count` SQ/CQ
// pairs. 64 entries is well within any controller's MQES and more
// than enough for the MAX_INFLIGHT-bounded pipelined I/O the driver
// actually submits per queue.
const IO_QID:                u16 = 1;
const IO_Q_ENTRIES:          u32 = 64;

/// Maximum I/O queue pairs. Hard cap bounded
/// by (a) controller's Number of I/O Queues Requested admin feature
/// result and (b) the CID encoding space `(q_idx << 3) | slot_idx`
/// with slot_idx∈0..8 leaving 2 bits for q_idx. 4 pairs match the
/// Pi 5 CM's 4 Cortex-A76 cores.
const MAX_IO_QUEUES:         usize = 4;

/// Maximum write requests per queue the driver keeps in flight at
/// once. Each in-flight slot owns a 4 KB DMA buffer, so this caps
/// per-instance DMA-arena usage at
/// `MAX_IO_QUEUES * MAX_INFLIGHT * 4 KB = 128 KB` on top of the
/// fixed admin/read/identify pages. The effective bound is also
/// clamped at module_new time by the `queue_depth` param and by
/// `IO_Q_ENTRIES-1` (always keep one SQE slot free so the ring
/// never looks full-empty ambiguous).
const MAX_INFLIGHT:          usize = 8;

/// Base CID for pipelined write SQEs. With multi-queue, the CID is
/// `CID_IO_WRITE_BASE | (q_idx << 3) | slot_idx`:
///   q_idx   ∈ 0..MAX_IO_QUEUES (2 bits)
///   slot_idx∈ 0..MAX_INFLIGHT  (3 bits)
/// Range: 0x0100..=0x011F (32 unique CIDs across 4 queues × 8 slots),
/// disjoint from admin CIDs 0x0001..=0x000F.
const CID_IO_WRITE_BASE:     u16 = 0x0100;

/// Sentinel for `poll_io_cqe(_, CID_NONE)` — harvest-only mode.
/// Tells the poller to drain any ready write-pipeline CQEs but not
/// consume anything else. 0xFFFF is outside every live CID range
/// (admin 0x0001..=0x003F, IO writes 0x0100..=0x011F), so it can
/// never match a real completion.
const CID_NONE: u16 = 0xFFFF;

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
    // the Identify Controller response and is never overwritten, so the
    // heartbeat can re-emit the acceptance line; Identify Namespace
    // gets its own buffer.
    admin_sq:        u64,
    admin_cq:        u64,
    identify_buf:    u64,
    identify_ns_buf: u64,
    /// Per-queue SQ/CQ DMA pages. Index i ⇒ QID i+1 (admin is QID 0).
    /// Slots past `io_q_count` stay at 0.
    io_sq:           [u64; MAX_IO_QUEUES],
    io_cq:           [u64; MAX_IO_QUEUES],
    /// DMA buffer for the read-stream pipeline (BLK_PHASE_READING
    /// fills it; BLK_PHASE_WRITING drains it byte-by-byte to
    /// `blk_out`). Reads always go through queue `read_q` — the
    /// shared buffer can't be striped across queues.
    read_buf:        u64,
    /// Per-queue ring of DMA buffers for write-request payloads
    /// accepted on `req_in`. Each entry is a 4 KB page lazily
    /// allocated on first use; separate-per-queue so concurrent
    /// writes on different queues can't alias each other's DMA.
    write_bufs:      [[u64; MAX_INFLIGHT]; MAX_IO_QUEUES],

    // Admin queue indices (QID=0).
    sq_tail:  u32,
    cq_head:  u32,
    cq_phase: u32,

    // Per-queue I/O indices (QID=1..=io_q_count). Each queue has its
    // own head/tail/phase; poll_io_cqe decodes the queue index from
    // the CID bits [4:3] and advances only that queue's head.
    io_sq_tail:  [u32; MAX_IO_QUEUES],
    io_cq_head:  [u32; MAX_IO_QUEUES],
    io_cq_phase: [u32; MAX_IO_QUEUES],

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

    // Incoming write-request pipeline. Producers push a REQ_HDR_SIZE
    // header `{ op:u32, lba:u64, nlb:u32, nsid:u32 }` followed by
    // nlb * 512 bytes of payload onto `req_in`. `req_phase` walks:
    //   0 Header  — accumulating header into req_hdr
    //   1 Payload — accumulating payload into write_bufs[req_q][tail]
    //   2 Submit  — header + payload ready; submit NVMe Write SQE,
    //                advance inflight ring, return to phase 0
    // Completion harvest happens at the top of every pump tick, so
    // there is no separate "wait" phase — the pump keeps accepting
    // further requests while earlier ones are still in-flight.
    req_phase:       u8,
    /// Queue index chosen for the request currently in phase 1/2.
    /// Stable across partial-header/payload reads that span ticks.
    req_q:           u8,
    req_fill:        u16,
    req_lba:         u64,
    req_hdr:         [u8; REQ_HDR_SIZE],
    req_nsid:        u32,

    // Per-queue in-flight write tracking. `inflight_count[q]`
    // outstanding writes; `inflight_head[q]` is the FIFO head (oldest
    // unacknowledged submission, matches the next CQE to arrive);
    // `inflight_tail[q]` is where the next submission goes.
    // `inflight_cap` is the per-queue bound, min(MAX_INFLIGHT,
    // IO_Q_ENTRIES - 1, queue_depth). `inflight_submit_ms[q][slot]`
    // is the submission timestamp used by the IO_READ_BUDGET_MS
    // stuck-write timeout.
    inflight_count:    [u8; MAX_IO_QUEUES],
    inflight_head:     [u8; MAX_IO_QUEUES],
    inflight_tail:     [u8; MAX_IO_QUEUES],
    inflight_cap:      u8,
    _pad_if:           [u8; 3],
    inflight_cid:      [[u16; MAX_INFLIGHT]; MAX_IO_QUEUES],
    inflight_submit_ms:[[u64; MAX_INFLIGHT]; MAX_IO_QUEUES],

    //  io_q_count    — active I/O queue pairs (1..=MAX_IO_QUEUES).
    //  bringup_qidx  — cursor for the CreateIoCQ/SQ admin loop.
    //  pump_q        — round-robin cursor selecting which queue the
    //                  next incoming write request is submitted on.
    //  read_q        — queue index reads go through (fixed at 0 —
    //                  shared `read_buf` can't be striped).
    io_q_count:   u8,
    bringup_qidx: u8,
    pump_q:       u8,
    read_q:       u8,
    _pad_q:       [u8; 4],

    // Namespace geometry (extracted from IdentifyNamespace response).
    ns_size:  u64,
    ns_lbads: u8,
    _pad3:    [u8; 7],

    // Timing anchors. `wait_start_ms` is owned by the admin queue
    // (submit_admin_cmd / poll_admin_cqe). `read_submit_ms` tracks
    // the last IO-queue read submission so its timeout budget is
    // independent of any concurrent write submits. Writes carry their
    // own per-slot timestamps in `inflight_submit_ms[]`.
    wait_start_ms:   u64,
    read_submit_ms:  u64,

    returned_ready: u8,
    _pad2: [u8; 7],

    /// Step counter for periodic heartbeat.
    step_count: u32,

    /// Block count of the in-flight read batch (1..=MAX_NLB). The
    /// streaming loop pushes `blk_nlb * BLOCK_SIZE` bytes per batch
    /// before advancing `current_block` by the same count.
    blk_nlb: u16,
    /// Block count parsed from an incoming write-request header
    /// (1..=MAX_NLB). Controls payload accumulation size in phase 1.
    req_nlb: u16,

    /// DMA page for synchronous pager I/O (NVMe as paged-arena
    /// backing store). Lazily allocated from the coherent arena on
    /// first call into `nvme_backing_dispatch`; coherent rather than
    /// streaming so the spin-poll path needs no cache maintenance.
    pager_buf: u64,
    /// 1 once `NVME_BACKING_ENABLE` has succeeded, so S_READY entry
    /// only registers once.
    pager_registered: u8,
    /// 1 once the PCIe capability walk has cached `msix_cap_offset`.
    msix_walked: u8,

    /// Interrupt delivery mode parameter. 0 = polled, 1 = MSI-X.
    irq_mode: u8,

    /// 1 once MSI-X table entry 0 has been programmed and the cap's
    /// Message-Control Enable bit set. `msix_table_virt` is the CPU
    /// address of table entry 0 (held for a future affinity-rewrite
    /// path).
    msix_enabled:    u8,
    _pad4:           [u8; 5],
    msix_table_virt: u64,
    msix_cap_offset: u16,
    msix_vector:     u8,
    _pad5:           [u8; 5],
    /// Event handle the kernel signals when the allocated MSI vector
    /// fires. Created lazily on the first `irq_mode=1` pass.
    msix_event:      i32,
    /// GIC SPI routed to the brcmstb MSI mux.
    msi_spi_irq:     u32,
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

        // 4: irq_mode. 0 = polled CQ drain (default),
        //    1 = program MSI-X table entry 0 + CreateIoCQ IEN=1 IV=0.
        4, irq_mode, u8, 0
            => |s, d, len| { s.irq_mode = p_u8(d, len, 0, 0); };

        // 5: msi_spi_irq. GIC SPI the brcmstb MSI mux is routed to.
        //    Default matches the Pi 5 DT `pcie@114000` MSI entry.
        5, msi_spi_irq, u32, 237
            => |s, d, len| { s.msi_spi_irq = p_u32(d, len, 0, 237); };

        // 6: io_queue_count. Number of I/O queue pairs (1..=4).
        //    Writes stripe across queues; reads stay on queue 0
        //    because `read_buf` is shared.
        6, io_queue_count, u8, 1
            => |s, d, len| {
                let v = p_u8(d, len, 0, 1);
                let clamped = if v == 0 { 1 }
                    else if (v as usize) > super::MAX_IO_QUEUES { super::MAX_IO_QUEUES as u8 }
                    else { v };
                s.io_q_count = clamped;
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
/// Prints the fields that stay meaningful in steady state: state-machine
/// position, fault code, admin queue indices, current LBA, block-phase.
///
/// Takes `&mut` because `walk_pcie_caps` now caches the discovered MSI-X
/// capability offset into state so step_create_io_cq doesn't have to
/// re-walk the cap list.
unsafe fn heartbeat(s: &mut NvmeState) {
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

    let inflight = b" if=";
    core::ptr::copy_nonoverlapping(inflight.as_ptr(), p.add(pos), inflight.len());
    pos += inflight.len();
    // Total inflight across all queues / cap per queue.
    write_dec3(p, &mut pos, total_inflight(s));
    *p.add(pos) = b'/';
    pos += 1;
    write_dec3(p, &mut pos, s.inflight_cap as u32);

    let q = b" q=";
    core::ptr::copy_nonoverlapping(q.as_ptr(), p.add(pos), q.len());
    pos += q.len();
    write_dec3(p, &mut pos, s.io_q_count as u32);

    // `pg` = pager dispatch registered; `mx` = MSI-X enabled.
    let pg = b" pg=";
    core::ptr::copy_nonoverlapping(pg.as_ptr(), p.add(pos), pg.len());
    pos += pg.len();
    *p.add(pos) = b'0' + s.pager_registered;
    pos += 1;
    let mx = b" mx=";
    core::ptr::copy_nonoverlapping(mx.as_ptr(), p.add(pos), mx.len());
    pos += mx.len();
    *p.add(pos) = b'0' + s.msix_enabled;
    pos += 1;

    dev_log(&*s.syscalls, 3, p, pos);

    // Re-emit the identification / capability / namespace lines once
    // per heartbeat while we're READY. These are printed once at boot
    // but tend to land before log_net's IP stack has come up, so a
    // viewer connecting mid-run would never see them otherwise. The
    // source buffers (`identify_buf`, `identify_ns_buf`, PCIe config
    // space) are read-only after enumeration, so repeated reads are
    // cheap and race-free.
    if s.state == S_READY {
        emit_identify_info(s);
        emit_ns_info(s);
        walk_pcie_caps(s);
    }
}

/// Emit the boot-sector signature (offset 510-511) plus the first
/// 16 bytes of LBA 0, both formatted as hex.
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

/// Emit the `[nvme] ns=N size=0xHHHHHHHHHHHHHHHH lbads=DDD` line — one
/// per controller at IdentifyNamespace completion, and repeatedly from
/// the heartbeat so it survives early-boot log-drain gaps. Consumers
/// reach the same values via the NS_INFO ioctl (B3.3).
unsafe fn emit_ns_info(s: &NvmeState) {
    let mut buf = [0u8; 64];
    let p = buf.as_mut_ptr();
    let prefix = b"[nvme] ns=";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
    let mut pos = prefix.len();
    write_dec3(p, &mut pos, s.namespace);

    let sz_tag = b" size=0x";
    core::ptr::copy_nonoverlapping(sz_tag.as_ptr(), p.add(pos), sz_tag.len());
    pos += sz_tag.len();
    write_hex32(p, &mut pos, (s.ns_size >> 32) as u32);
    write_hex32(p, &mut pos, s.ns_size as u32);

    let lb_tag = b" lbads=";
    core::ptr::copy_nonoverlapping(lb_tag.as_ptr(), p.add(pos), lb_tag.len());
    pos += lb_tag.len();
    write_dec3(p, &mut pos, s.ns_lbads as u32);

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

/// Identify Namespace (CNS=0x00). Uses its own DMA page so
/// `identify_buf` stays untouched for re-emit at heartbeat time.
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
                emit_ns_info(s);
                s.state = S_CREATE_IO_CQ;
                s.substate = 0;
                0
            }
        }
    }
}

/// Create I/O Completion Queue (QIDs 1..=io_q_count). CDW11 always
/// sets PC=1; if MSI-X bring-up succeeded it also sets IEN=1 IV=0
/// so the controller posts an MSI to the brcmstb MSI mux on each
/// completion. Otherwise the CQ is polled in step_ready.
///
/// The cursor `bringup_qidx` steps 0 → io_q_count-1, re-entering
/// this state once per queue via the transition in step_create_io_sq.
unsafe fn step_create_io_cq(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            // Bring MSI-X up before the first CreateIoCQ so CDW11.IEN
            // reflects the chosen delivery path. `enable_msix` is
            // idempotent across the per-queue loop.
            if s.irq_mode != 0 && s.msix_enabled == 0 {
                // Cap walk must populate `msix_cap_offset` before
                // `enable_msix` can look up the MSI-X Table BIR.
                if s.msix_walked == 0 {
                    s.msix_walked = 1;
                    walk_pcie_caps(s);
                }
                let _ = enable_msix(s);
            }
            let q = s.bringup_qidx as usize;
            log_once(s, b"[nvme] CreateIoCQ\0");
            let sys = &*s.syscalls;
            let slot = *s.io_cq.as_ptr().add(q);
            if slot == 0 {
                let p = dev_dma_alloc(sys, PAGE, PAGE);
                if p == 0 { return fault(s, 15, b"[nvme] io cq alloc fail\0"); }
                zero_page(p);
                *s.io_cq.as_mut_ptr().add(q) = p;
            }
            let cq_phys = *s.io_cq.as_ptr().add(q);
            let qid = IO_QID + s.bringup_qidx as u16;
            let cdw10 = ((IO_Q_ENTRIES - 1) << 16) | (qid as u32);
            // CDW11:
            //   PC=bit0, IEN=bit1, IV=bits[31:16]
            // Single-vector MSI-X: IV=0 for every CQ, IEN=1 if MSI-X
            // is up. Polled mode (default): PC=1 only.
            let cdw11: u32 = if s.msix_enabled != 0 {
                0x0000_0003 // PC=1, IEN=1, IV=0
            } else {
                0x0000_0001 // PC=1, IEN=0, IV=0
            };
            let cid = CID_CREATE_IO_CQ + (s.bringup_qidx as u16) * 0x10;
            submit_admin_cmd(
                s, OPC_CREATE_CQ, cid, 0,
                cq_phys | PCI_DMA_OFFSET,
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
                let q = s.bringup_qidx as usize;
                *s.io_cq_head.as_mut_ptr().add(q) = 0;
                *s.io_cq_phase.as_mut_ptr().add(q) = 1;
                s.state = S_CREATE_IO_SQ;
                s.substate = 0;
                0
            }
        }
    }
}

/// Create I/O Submission Queue (QIDs 1..=io_q_count, paired with the
/// same-index CQ). Re-entered once per queue from step_create_io_cq.
/// After the last SQ completes, `bringup_qidx` is reset and the
/// state machine advances to S_READ_LBA0.
unsafe fn step_create_io_sq(s: &mut NvmeState) -> i32 {
    match s.substate {
        0 => {
            let q = s.bringup_qidx as usize;
            log_once(s, b"[nvme] CreateIoSQ\0");
            let sys = &*s.syscalls;
            let slot = *s.io_sq.as_ptr().add(q);
            if slot == 0 {
                let p = dev_dma_alloc(sys, PAGE, PAGE);
                if p == 0 { return fault(s, 18, b"[nvme] io sq alloc fail\0"); }
                zero_page(p);
                *s.io_sq.as_mut_ptr().add(q) = p;
            }
            let sq_phys = *s.io_sq.as_ptr().add(q);
            let qid = IO_QID + s.bringup_qidx as u16;
            let cdw10 = ((IO_Q_ENTRIES - 1) << 16) | (qid as u32);
            // CDW11: CQID[31:16] | QPRIO[2:1]=0 (medium) | PC[0]=1.
            // Pair each SQ with the same-index CQ (one-to-one).
            let cdw11: u32 = ((qid as u32) << 16) | 0x0000_0001;
            let cid = CID_CREATE_IO_SQ + (s.bringup_qidx as u16) * 0x10;
            submit_admin_cmd(
                s, OPC_CREATE_SQ, cid, 0,
                sq_phys | PCI_DMA_OFFSET,
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
                let q = s.bringup_qidx as usize;
                *s.io_sq_tail.as_mut_ptr().add(q) = 0;
                // Advance the bring-up cursor. If more queues remain,
                // return to CreateIoCQ for queue `bringup_qidx+1`; else
                // reset the cursor and hand off to S_READ_LBA0.
                if (s.bringup_qidx as usize) + 1 < s.io_q_count as usize {
                    s.bringup_qidx += 1;
                    s.state = S_CREATE_IO_CQ;
                    s.substate = 0;
                } else {
                    s.bringup_qidx = 0;
                    s.state = S_READ_LBA0;
                    s.substate = 0;
                }
                0
            }
        }
    }
}

/// Submit an N-block Write on I/O SQ `q_idx` for `lba`, sourcing DMA
/// from `dma_buf`. `nsid` targets the destination namespace directly
/// (producer sets this per packet); pass 0 and the caller is
/// responsible for falling back to the driver-wide default. `nlb` is
/// clamped to [1, MAX_NLB] so a single PRP1 covers the transfer;
/// callers that want more must split.
///
/// `q_idx` ∈ 0..io_q_count selects which SQ to push onto. `dma_buf`
/// must not alias the read-stream buffer — pump_requests uses
/// per-queue, per-slot entries in `write_bufs[q][tail]` precisely so
/// an incoming write payload cannot clobber an in-flight read whose
/// consumer hasn't finished draining yet, nor a still-outstanding
/// write still being DMA'd by the controller.
unsafe fn submit_io_write(
    s: &mut NvmeState,
    q_idx: usize,
    lba: u64, nlb: u16, cid: u16, nsid: u32, dma_buf: u64,
) {
    let nlb = clamp_nlb(nlb);
    let prp1_pci = dma_buf | PCI_DMA_OFFSET;
    let cdw = [
        ((cid as u32) << 16) | (OPC_WRITE as u32),
        nsid,
        0, 0,
        0, 0,
        prp1_pci as u32, (prp1_pci >> 32) as u32,
        0, 0,
        lba as u32,
        (lba >> 32) as u32,
        (nlb - 1) as u32,   // CDW12: NLB-1 (zero-based)
        0, 0, 0,
    ];
    let sq_base = *s.io_sq.as_ptr().add(q_idx);
    let tail = *s.io_sq_tail.as_ptr().add(q_idx);
    write_sqe(sq_base, tail, cdw);
    let new_tail = (tail + 1) % IO_Q_ENTRIES;
    *s.io_sq_tail.as_mut_ptr().add(q_idx) = new_tail;
    let qid = IO_QID as u32 + q_idx as u32;
    reg_w32(s, sq_doorbell(s, qid), new_tail);
    // Per-write submit time is kept in `inflight_submit_ms[q][slot]`
    // by the caller; wait_start_ms must stay owned by the read path.
}

/// Clamp a caller-supplied NLB to the driver's single-PRP1 limit.
#[inline(always)]
fn clamp_nlb(nlb: u16) -> u16 {
    if nlb == 0 { 1 } else if nlb > MAX_NLB { MAX_NLB } else { nlb }
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
            // Prime the buffer with a sentinel pattern so a
            // zero-returning (blank) LBA is distinguishable from a
            // failed DMA in the acceptance log.
            let buf = s.read_buf as *mut u32;
            let mut i = 0usize;
            while i < 1024 {
                write_volatile(buf.add(i), 0xDEAD_BEEF);
                i += 1;
            }
            submit_io_read(s, 0, 1, CID_READ_LBA0);
            s.substate = 1;
            0
        }
        _ => match poll_io_cqe(s, CID_READ_LBA0) {
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

/// Submit an N-block Read command on the I/O SQ for `lba`. Data lands
/// at `s.read_buf`. `nlb` is clamped to [1, MAX_NLB].
///
/// Reads always go on queue `s.read_q` (fixed at 0) — the read-stream
/// pipeline uses a single shared `read_buf`, so striping reads across
/// queues would require per-queue read buffers.
unsafe fn submit_io_read(s: &mut NvmeState, lba: u64, nlb: u16, cid: u16) {
    let nlb = clamp_nlb(nlb);
    let q = s.read_q as usize;
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
        (nlb - 1) as u32,   // CDW12: NLB-1 (zero-based)
        0, 0, 0,
    ];
    let sq_base = *s.io_sq.as_ptr().add(q);
    let tail = *s.io_sq_tail.as_ptr().add(q);
    write_sqe(sq_base, tail, cdw);
    let new_tail = (tail + 1) % IO_Q_ENTRIES;
    *s.io_sq_tail.as_mut_ptr().add(q) = new_tail;
    reg_w32(s, sq_doorbell(s, IO_QID as u32 + q as u32), new_tail);
    s.read_submit_ms = now_ms(s);
}

/// Poll the I/O CQ for a completion with `expected_cid`.
///
/// Write-pipeline CQEs (CIDs in `CID_IO_WRITE_BASE..+MAX_INFLIGHT`)
/// are auto-absorbed into the inflight ring on every call, regardless
/// of what the caller is waiting for — reads and writes share the
/// single I/O CQ without either path consuming the other's entry.
///
/// The sentinel [`CID_NONE`] is the "harvest-only" mode used by
/// `pump_requests`: the function drains write CQEs and returns `Ok`
/// when either the inflight ring is empty or the next CQE is a non-
/// write (it is NOT consumed, so the real owner still sees it). A
/// concrete CID waits for that specific completion; `Pending` means
/// it hasn't arrived yet.
///
/// Peek at the CQ head of queue `q`: `Some((cid, sc))` if a CQE with
/// the current phase is present (does NOT consume it), `None` if not.
unsafe fn peek_io_cqe(s: &NvmeState, q: usize) -> Option<(u16, u16)> {
    let cq_base = *s.io_cq.as_ptr().add(q);
    let head    = *s.io_cq_head.as_ptr().add(q);
    let phase_want = *s.io_cq_phase.as_ptr().add(q);
    let cqe = (cq_base + (head as u64) * CQE_BYTES as u64) as *const u32;
    let dw3 = read_volatile(cqe.add(3));
    let phase = (dw3 >> 16) & 1;
    if phase != phase_want {
        None
    } else {
        let cid = (dw3 & 0xFFFF) as u16;
        let sc  = ((dw3 >> 17) & 0x7FFF) as u16;
        Some((cid, sc))
    }
}

/// Consume the CQE at the head of queue `q` — advance the head
/// pointer, flip the phase on wrap, ring CQ0HDBL. Used after
/// `peek_io_cqe` returned a match the caller wants to accept.
unsafe fn consume_io_cqe(s: &mut NvmeState, q: usize) {
    let new_head = (*s.io_cq_head.as_ptr().add(q) + 1) % IO_Q_ENTRIES;
    *s.io_cq_head.as_mut_ptr().add(q) = new_head;
    if new_head == 0 {
        let phase = *s.io_cq_phase.as_ptr().add(q);
        *s.io_cq_phase.as_mut_ptr().add(q) = phase ^ 1;
    }
    reg_w32(s, cq_doorbell(s, IO_QID as u32 + q as u32), new_head);
}

/// Decode queue index from a write CID. Layout:
/// `CID_IO_WRITE_BASE | (q_idx << 3) | slot_idx` — q_idx in bits[4:3].
#[inline(always)]
fn write_cid_queue(cid: u16) -> usize {
    ((cid - CID_IO_WRITE_BASE) >> 3) as usize
}

#[inline(always)]
fn write_cid_slot(cid: u16) -> usize {
    ((cid - CID_IO_WRITE_BASE) & 0x7) as usize
}

#[inline(always)]
fn is_write_cid(cid: u16) -> bool {
    cid >= CID_IO_WRITE_BASE
        && cid < CID_IO_WRITE_BASE + (MAX_IO_QUEUES * MAX_INFLIGHT) as u16
}

/// Total writes currently outstanding across all queues.
unsafe fn total_inflight(s: &NvmeState) -> u32 {
    let mut sum = 0u32;
    for q in 0..s.io_q_count as usize {
        sum += *s.inflight_count.as_ptr().add(q) as u32;
    }
    sum
}

/// Poll the I/O CQs for a completion with `expected_cid`. Scans all
/// `io_q_count` queues each call. Write-pipeline CQEs (CIDs in
/// `CID_IO_WRITE_BASE..CID_IO_WRITE_BASE + MAX_IO_QUEUES*MAX_INFLIGHT`)
/// are auto-absorbed into the per-queue inflight ring, regardless of
/// what the caller is waiting for — the `read_q` CQ and any write-only
/// CQs share the scanner so neither path can consume the other's entry.
///
/// The sentinel [`CID_NONE`] is the "harvest-only" mode used by
/// `pump_requests`: the function drains write CQEs and returns `Ok`
/// when either every queue's inflight ring is empty or a non-write
/// CQE blocks progress on the read_q (it is NOT consumed, so the
/// real owner still sees it). A concrete CID waits for that specific
/// completion; `Pending` means it hasn't arrived yet.
///
/// Timeout budget: `read_submit_ms` when the caller is waiting on a
/// read, the read_q's head inflight submit time otherwise.
unsafe fn poll_io_cqe(s: &mut NvmeState, expected_cid: u16) -> CqeResult {
    loop {
        let mut made_progress = false;
        // Scan every queue for a ready CQE. For a specific-CID caller,
        // the CQE we care about lives on whichever queue the submitter
        // chose: reads → read_q, writes → queue encoded in the CID.
        // `peek_io_cqe` tells us whether there's anything at the head
        // of each queue; `consume_io_cqe` advances on decision.
        let n = s.io_q_count as usize;
        for q in 0..n {
            while let Some((cid, sc)) = peek_io_cqe(s, q) {
                let is_write = is_write_cid(cid);
                // Harvest-only caller refuses to consume non-write
                // entries — the read path owns them and must not lose
                // its CQE.
                if expected_cid == CID_NONE && !is_write {
                    // Stop scanning this queue; a concurrent read on
                    // the same queue is waiting for its own peek.
                    break;
                }
                // Consume the CQE on its owning queue. For writes,
                // the slot the CID encodes MUST be this queue (bugs
                // where CIDs don't match the queue they were
                // submitted on will be loud at this point).
                consume_io_cqe(s, q);
                made_progress = true;

                if is_write {
                    let cq_idx = write_cid_queue(cid);
                    // If the CID encoding says the write belongs to a
                    // different queue than the one that just surfaced
                    // the CQE, that's a bug — log and continue rather
                    // than silently mis-retiring an inflight slot.
                    if cq_idx != q {
                        dev_log(&*s.syscalls, 2,
                                b"[nvme] write CQE on wrong queue\0".as_ptr(), 31);
                    }
                    // Retire from the head of this queue's inflight
                    // ring. Head == oldest submission, first to
                    // complete (in-order per controller, since one
                    // SQ/CQ pair is in-order).
                    let cnt = *s.inflight_count.as_ptr().add(q);
                    if cnt > 0 {
                        let head = *s.inflight_head.as_ptr().add(q);
                        let new_head = (head as usize + 1) % MAX_INFLIGHT;
                        *s.inflight_head.as_mut_ptr().add(q) = new_head as u8;
                        *s.inflight_count.as_mut_ptr().add(q) = cnt - 1;
                    }
                    if sc != 0 {
                        return CqeResult::Failed(sc);
                    }
                    continue;
                }

                // Non-write CQE — must be the read we're waiting on
                // (admin CQEs land on their own CQ, separate ring).
                if cid == expected_cid {
                    return if sc == 0 { CqeResult::Ok } else { CqeResult::Failed(sc) };
                }
                // Stray CQE with a CID we didn't submit. Hitting this
                // branch points at a CID-allocation bug.
                dev_log(&*s.syscalls, 2, b"[nvme] stray io cqe\0".as_ptr(), 20);
            }
        }

        // A full pass made no progress ⇒ either nothing's ready or
        // we drained harvest-only mode. Decide based on mode.
        if !made_progress {
            if expected_cid == CID_NONE {
                return CqeResult::Ok;
            }
            // Specific CID: pick a budget start. For the read path,
            // `read_submit_ms` is the submit anchor. For an IO-write
            // waiter (step_create_io_cq uses the admin poller, not
            // this one — so no writer ever asks by CID here, but
            // keeping symmetry), use the read_q's oldest inflight
            // submit time.
            let budget_start = if expected_cid == CID_READ_LBA0
                || expected_cid < CID_IO_WRITE_BASE
            {
                s.read_submit_ms
            } else {
                let q = write_cid_queue(expected_cid);
                let cnt = *s.inflight_count.as_ptr().add(q);
                if cnt == 0 { return CqeResult::Pending; }
                let head = *s.inflight_head.as_ptr().add(q) as usize;
                *(*s.inflight_submit_ms.as_ptr().add(q)).as_ptr().add(head)
            };
            if now_ms(s).saturating_sub(budget_start) > IO_READ_BUDGET_MS {
                return CqeResult::Timeout;
            }
            return CqeResult::Pending;
        }
        // We drained at least one CQE — loop so harvest-only mode
        // reports `Ok` when the rings are empty, or a specific-CID
        // caller re-scans to find its own entry on the next pass.
        if expected_cid == CID_NONE && total_inflight(s) == 0 {
            return CqeResult::Ok;
        }
    }
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

/// Harvest every ready write-pipeline CQE. Thin wrapper around
/// [`poll_io_cqe(s, CID_NONE)`] that converts its result into the
/// integer status the pump expects (0 on drain, -1 on fault).
unsafe fn harvest_write_cqes(s: &mut NvmeState) -> i32 {
    match poll_io_cqe(s, CID_NONE) {
        CqeResult::Ok | CqeResult::Pending => 0,
        CqeResult::Failed(_) => {
            fault(s, 32, b"[nvme] req write failed\0");
            -1
        }
        CqeResult::Timeout => {
            fault(s, 31, b"[nvme] req write CQE timeout\0");
            -1
        }
    }
}

/// Ensure `write_bufs[q][slot]` has a 4 KB DMA page allocated;
/// returns true on success, false on allocation failure (caller
/// should fault).
///
/// Uses the STREAMING (WB-cacheable) PCIe1 arena so the incoming
/// write payload accumulates into the CPU cache at memcpy speed;
/// `submit_io_write` is preceded by `dev_dma_flush` so the device
/// sees the fully-formed payload at PoC before it reads via its DMA
/// engine. Admin queues and the read-stream buffer stay on the
/// coherent (non-cacheable) arena for simplicity — the win from
/// streaming only matters on the hot payload path.
unsafe fn ensure_write_buf(s: &mut NvmeState, q: usize, slot: usize) -> bool {
    let sys = &*s.syscalls;
    let row = (*s.write_bufs.as_ptr().add(q)).as_ptr();
    let cur = *row.add(slot);
    if cur != 0 {
        return true;
    }
    let p = dev_dma_alloc_streaming(sys, PAGE, PAGE);
    if p == 0 {
        return false;
    }
    let row_mut = (*s.write_bufs.as_mut_ptr().add(q)).as_mut_ptr();
    *row_mut.add(slot) = p;
    true
}

/// Pick a queue with room for one more inflight write. Returns
/// `Some(q)` in [0, io_q_count) or `None` if all queues are full.
/// Starts at `s.pump_q` so submissions round-robin across queues;
/// a full queue is skipped, keeping throughput even under uneven
/// load.
unsafe fn pick_pump_queue(s: &NvmeState) -> Option<usize> {
    let n = s.io_q_count as usize;
    if n == 0 { return None; }
    let cap = s.inflight_cap;
    let start = (s.pump_q as usize) % n;
    for i in 0..n {
        let q = (start + i) % n;
        if *s.inflight_count.as_ptr().add(q) < cap {
            return Some(q);
        }
    }
    None
}

/// Write-request pump. Reads `{op, lba, nlb, nsid}` headers + payloads
/// off `req_in` and issues NVMe Writes with up to `inflight_cap` in
/// flight per queue concurrently (striped across `io_q_count` queues
/// by the pump_q round-robin cursor). `poll_io_cqe` is CID-aware, so
/// running the pump is safe even while a read is outstanding.
///
/// The queue chosen in phase 0 is latched into `s.req_q` and reused
/// for phase 1 (payload accumulation into the matching write_bufs
/// slot) and phase 2 (submit). Only after the submission completes
/// is `pump_q` advanced — this keeps the chosen slot stable across
/// partial channel reads that span scheduler ticks.
///
/// Returns `true` iff the pump has work in progress this tick.
unsafe fn pump_requests(s: &mut NvmeState) -> bool {
    if s.req_in < 0 { return false; }
    let sys = &*s.syscalls;

    // Always try to drain completions first so freshly completed
    // writes release slots for the submission loop below.
    if harvest_write_cqes(s) < 0 {
        return true; // fault set
    }

    loop {
        match s.req_phase {
            0 => {
                // Don't start a new request until *some* queue has
                // room. This also prevents us from reading a header
                // off the channel that we'd have to stall mid-payload
                // because every slot is busy.
                let q = match pick_pump_queue(s) {
                    Some(q) => q,
                    None => break,
                };
                s.req_q = q as u8;
                let need = REQ_HDR_SIZE - s.req_fill as usize;
                let dst = s.req_hdr.as_mut_ptr().add(s.req_fill as usize);
                let n = (sys.channel_read)(s.req_in, dst, need);
                if n <= 0 { break; }
                s.req_fill += n as u16;
                if s.req_fill as usize != REQ_HDR_SIZE {
                    // Partial header — the rest will land next tick.
                    break;
                }
                let op = u32::from_le_bytes([
                    s.req_hdr[0], s.req_hdr[1], s.req_hdr[2], s.req_hdr[3],
                ]);
                let lba = u64::from_le_bytes([
                    s.req_hdr[4],  s.req_hdr[5],  s.req_hdr[6],  s.req_hdr[7],
                    s.req_hdr[8],  s.req_hdr[9],  s.req_hdr[10], s.req_hdr[11],
                ]);
                let nlb = u32::from_le_bytes([
                    s.req_hdr[12], s.req_hdr[13], s.req_hdr[14], s.req_hdr[15],
                ]);
                let nsid = u32::from_le_bytes([
                    s.req_hdr[16], s.req_hdr[17], s.req_hdr[18], s.req_hdr[19],
                ]);
                if op != 1 {
                    s.req_fill = 0;
                    dev_log(sys, 3, b"[nvme] req: unknown op\0".as_ptr(), 22);
                    continue;
                }
                if nlb == 0 || nlb > MAX_NLB as u32 {
                    fault(s, 33, b"[nvme] req: nlb out of range\0");
                    return true;
                }
                s.req_lba = lba;
                s.req_nlb = nlb as u16;
                s.req_nsid = if nsid != 0 { nsid } else { s.namespace };
                s.req_fill = 0;
                s.req_phase = 1;
            }
            1 => {
                // Payload goes into write_bufs[q][tail]. Each buffer
                // is 4 KB so any NLB up to MAX_NLB fits.
                let q = s.req_q as usize;
                let tail = *s.inflight_tail.as_ptr().add(q) as usize;
                if !ensure_write_buf(s, q, tail) {
                    fault(s, 30, b"[nvme] req buf alloc fail\0");
                    return true;
                }
                let row = (*s.write_bufs.as_ptr().add(q)).as_ptr();
                let buf = *row.add(tail);
                let total = (s.req_nlb as u32) * BLOCK_SIZE;
                let need = (total - s.req_fill as u32) as usize;
                let dst = (buf as *mut u8).add(s.req_fill as usize);
                let n = (sys.channel_read)(s.req_in, dst, need);
                if n <= 0 { break; }
                s.req_fill += n as u16;
                if s.req_fill as u32 >= total {
                    s.req_phase = 2;
                }
            }
            _ => {
                // Submit the accumulated write. CID encodes (queue,
                // slot) so out-of-order completion across queues
                // locates the right inflight slot.
                //
                // The payload buffer is streaming (WB-cacheable), so
                // its lines must be clean at PoC before the device
                // reads them. `dev_dma_flush` issues `dc cvac` over
                // `nlb * BLOCK_SIZE` bytes + a DSB, so the SQE
                // doorbell write that follows is strictly ordered
                // after the flush.
                let q = s.req_q as usize;
                let tail = *s.inflight_tail.as_ptr().add(q) as usize;
                let row = (*s.write_bufs.as_ptr().add(q)).as_ptr();
                let buf = *row.add(tail);
                let cid = CID_IO_WRITE_BASE
                    | ((q as u16) << 3)
                    | (tail as u16);
                let payload_bytes = (s.req_nlb as u32) * BLOCK_SIZE;
                dev_dma_flush(sys, buf, payload_bytes);
                submit_io_write(s, q, s.req_lba, s.req_nlb, cid, s.req_nsid, buf);
                let cid_row = (*s.inflight_cid.as_mut_ptr().add(q)).as_mut_ptr();
                *cid_row.add(tail) = cid;
                let ts_row = (*s.inflight_submit_ms.as_mut_ptr().add(q)).as_mut_ptr();
                *ts_row.add(tail) = now_ms(s);
                let new_tail = ((tail + 1) as u8) % (MAX_INFLIGHT as u8);
                *s.inflight_tail.as_mut_ptr().add(q) = new_tail;
                let cnt = *s.inflight_count.as_ptr().add(q);
                *s.inflight_count.as_mut_ptr().add(q) = cnt + 1;
                s.req_fill = 0;
                s.req_phase = 0;
                // Advance the pump cursor so the NEXT request picks
                // a different queue first (simple round-robin).
                let n = s.io_q_count;
                if n > 1 {
                    s.pump_q = (s.pump_q + 1) % n;
                }
            }
        }
    }

    total_inflight(s) > 0 || s.req_phase != 0 || s.req_fill != 0
}

/// Walk the NVMe function's PCIe capability list, log each entry,
/// and cache the MSI-X capability offset (id 0x11) into
/// `s.msix_cap_offset` so `enable_msix` can program the table
/// without re-walking. Reads config space only; no state changes
/// beyond the cached offset.
///
/// PCI header offset 0x34 holds the capability-list pointer (u8);
/// each entry is `(id: u8, next: u8, ...)`. MSI-X adds a u16
/// Message Control at cap+2 and two BAR-offset+BIR u32 fields at
/// cap+4 (Table) and cap+8 (PBA). See PCI Base Spec 4.0 §7.5.1.1
/// (header) and §6.8.2 (MSI-X).
unsafe fn walk_pcie_caps(s: &mut NvmeState) {
    let sys = &*s.syscalls;

    // Read Status register (offset 0x04, high 16 bits) to check the
    // Capabilities List bit (bit 4). Skip the walk if the function
    // has no cap list at all.
    let status_cmd = dev_pcie_cfg_read32(sys, s.pcie_dev_idx, 0x04);
    if status_cmd == 0xFFFF_FFFF || (status_cmd & 0x0010_0000) == 0 {
        dev_log(sys, 2, b"[nvme] cap: no capability list\0".as_ptr(), 30);
        return;
    }

    // Cap pointer at 0x34 (u8, low 8 bits of the 32-bit read).
    let cap_ptr_word = dev_pcie_cfg_read32(sys, s.pcie_dev_idx, 0x34);
    let mut ptr = (cap_ptr_word & 0xFC) as u16;

    let mut guard = 0u32;
    while ptr != 0 && guard < 48 {
        let w = dev_pcie_cfg_read32(sys, s.pcie_dev_idx, ptr);
        if w == 0xFFFF_FFFF {
            break;
        }
        let id   = (w & 0xFF) as u8;
        let next = ((w >> 8) & 0xFC) as u16;

        let mut buf = [0u8; 96];
        let p = buf.as_mut_ptr();
        let mut pos = 0usize;
        let prefix = b"[nvme] cap id=0x";
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), p.add(pos), prefix.len());
        pos += prefix.len();
        // Two-hex format for the id.
        for i in 0..2 {
            let n = ((id >> (4 - i * 4)) & 0xF) as u8;
            *p.add(pos) = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
            pos += 1;
        }
        let at = b" @0x";
        core::ptr::copy_nonoverlapping(at.as_ptr(), p.add(pos), at.len());
        pos += at.len();
        for i in 0..4 {
            let n = ((ptr >> (12 - i * 4)) & 0xF) as u16;
            *p.add(pos) = if n < 10 { b'0' + n as u8 } else { b'a' + (n as u8 - 10) };
            pos += 1;
        }

        // MSI-X (cap id 0x11): decode table size + table/PBA BIRs.
        if id == 0x11 {
            if s.msix_cap_offset == 0 {
                s.msix_cap_offset = ptr;
            }
            let msg_ctrl = ((w >> 16) & 0xFFFF) as u16;
            let table_sz = (msg_ctrl & 0x07FF) + 1;
            let tbl_bir_word = dev_pcie_cfg_read32(sys, s.pcie_dev_idx, ptr + 4);
            let pba_bir_word = dev_pcie_cfg_read32(sys, s.pcie_dev_idx, ptr + 8);
            let tbl_bir = (tbl_bir_word & 0x7) as u8;
            let tbl_off = tbl_bir_word & !0x7;
            let pba_bir = (pba_bir_word & 0x7) as u8;
            let pba_off = pba_bir_word & !0x7;

            let t = b" MSI-X vec=";
            core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
            pos += t.len();
            // msix vector count (u16 up to 2048)
            let mut v = table_sz as u32;
            let mut d = [0u8; 4];
            let mut dn = 0usize;
            if v == 0 { d[0] = b'0'; dn = 1; }
            while v > 0 { d[dn] = b'0' + (v % 10) as u8; v /= 10; dn += 1; }
            while dn > 0 { dn -= 1; *p.add(pos) = d[dn]; pos += 1; }

            let tb = b" tbl=bar";
            core::ptr::copy_nonoverlapping(tb.as_ptr(), p.add(pos), tb.len());
            pos += tb.len();
            *p.add(pos) = b'0' + tbl_bir;
            pos += 1;
            *p.add(pos) = b'+';
            pos += 1;
            *p.add(pos) = b'0';
            pos += 1;
            *p.add(pos) = b'x';
            pos += 1;
            for i in 0..8 {
                let n = ((tbl_off >> (28 - i * 4)) & 0xF) as u8;
                *p.add(pos) = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
                pos += 1;
            }

            let pb = b" pba=bar";
            core::ptr::copy_nonoverlapping(pb.as_ptr(), p.add(pos), pb.len());
            pos += pb.len();
            *p.add(pos) = b'0' + pba_bir;
            pos += 1;
            *p.add(pos) = b'+';
            pos += 1;
            *p.add(pos) = b'0';
            pos += 1;
            *p.add(pos) = b'x';
            pos += 1;
            for i in 0..8 {
                let n = ((pba_off >> (28 - i * 4)) & 0xF) as u8;
                *p.add(pos) = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
                pos += 1;
            }
        }

        dev_log(sys, 3, p, pos);

        if next == 0 || next == ptr { break; }
        ptr = next;
        guard += 1;
    }
}

/// Single-vector MSI-X bring-up. Requires `walk_pcie_caps` to have
/// populated `msix_cap_offset` and `step_map_bars` to have populated
/// `bar0_virt`. Idempotent — once `msix_enabled = 1`, subsequent
/// calls return immediately.
///
/// On any step failure, `msix_enabled` stays 0 and a diagnostic line
/// is emitted; `step_create_io_cq` falls back to polled CQE delivery.
///
/// Sequence:
/// 1. Create an event fd.
/// 2. Bring up the brcmstb MSI mux on the configured GIC SPI.
/// 3. Allocate a vector, receiving `(vec, target_addr, data)`.
/// 4. Write those into MSI-X table entry 0 with `ctrl=0` (unmasked).
/// 5. Flip bit 15 (MSI-X Enable) in the cap's Message Control.
unsafe fn enable_msix(s: &mut NvmeState) -> bool {
    if s.msix_enabled != 0 { return true; }
    if s.msix_cap_offset == 0 || s.bar0_virt == 0 { return false; }

    let sys = &*s.syscalls;

    // Create the event we'll subscribe to the MSI vector.
    if s.msix_event < 0 {
        let ev = dev_event_create(sys);
        if ev < 0 {
            dev_log(sys, 2, b"[nvme] msix: event_create failed\0".as_ptr(), 32);
            return false;
        }
        s.msix_event = ev;
    }

    // Kernel-side MSI controller bring-up. Idempotent across retries.
    let mut init_arg = s.msi_spi_irq.to_le_bytes();
    let init_rc = (sys.dev_call)(-1, PCIE1_MSI_INIT, init_arg.as_mut_ptr(), 4);
    if init_rc != 0 {
        dev_log(sys, 2, b"[nvme] msix: PCIE1_MSI_INIT failed\0".as_ptr(), 34);
        return false;
    }

    // Vector allocation — returns the target address + data value
    // we must program into the MSI-X table entry.
    let (vec, addr, data) = match dev_pcie1_msi_alloc_vector(sys, s.msix_event) {
        Some(t) => t,
        None => {
            dev_log(sys, 2, b"[nvme] msix: alloc_vector failed\0".as_ptr(), 32);
            return false;
        }
    };
    s.msix_vector = vec;

    // MSI-X Table Offset + BIR live in the dword at cap+4: low 3 bits
    // are the BIR, upper bits the offset. Only BAR0-hosted tables are
    // supported; refuse anything else explicitly.
    let tbl_word = dev_pcie_cfg_read32(sys, s.pcie_dev_idx, s.msix_cap_offset + 4);
    if tbl_word == 0xFFFF_FFFF {
        dev_log(sys, 2, b"[nvme] msix: cap read failed\0".as_ptr(), 29);
        return false;
    }
    let tbl_bir = tbl_word & 0x7;
    let tbl_off = tbl_word & !0x7;
    if tbl_bir != 0 {
        dev_log(sys, 2, b"[nvme] msix: table not in BAR0\0".as_ptr(), 31);
        return false;
    }
    let tbl_virt = s.bar0_virt + tbl_off as u64;
    s.msix_table_virt = tbl_virt;

    // Table entry layout (16 bytes):
    //   +0  addr_lo   +4  addr_hi   +8  data   +12 vector control
    // `ctrl = 0` leaves the vector unmasked.
    write_volatile((tbl_virt + 0x0) as *mut u32, addr as u32);
    write_volatile((tbl_virt + 0x4) as *mut u32, (addr >> 32) as u32);
    write_volatile((tbl_virt + 0x8) as *mut u32, data);
    write_volatile((tbl_virt + 0xC) as *mut u32, 0);
    core::arch::asm!("dsb sy", options(nostack));

    // Flip bit 15 (MSI-X Enable) in the cap's Message Control, which
    // lives in the high half of the dword at `msix_cap_offset` — so
    // bit 15 of Msg Ctrl is bit 31 of the dword. Read-modify-write
    // via PCIE_CFG_WRITE32.
    let cap_word = dev_pcie_cfg_read32(sys, s.pcie_dev_idx, s.msix_cap_offset);
    if cap_word == 0xFFFF_FFFF {
        dev_log(sys, 2, b"[nvme] msix: ctrl read failed\0".as_ptr(), 30);
        return false;
    }
    let new_word = cap_word | (1u32 << 31);
    let w_rc = dev_pcie_cfg_write32(sys, s.pcie_dev_idx, s.msix_cap_offset, new_word);
    if w_rc != 0 {
        dev_log(sys, 2, b"[nvme] msix: ctrl write failed\0".as_ptr(), 31);
        return false;
    }

    s.msix_enabled = 1;
    dev_log(sys, 3, b"[nvme] msix enabled\0".as_ptr(), 20);
    true
}

unsafe fn step_ready(s: &mut NvmeState) -> i32 {
    log_once(s, b"[nvme] Ready\0");
    if s.returned_ready == 0 {
        s.returned_ready = 1;
        return 3; // signal scheduler we've reached the steady state
    }

    // One-shot: register as the paged-arena backing-store provider so
    // the kernel pager can drive synchronous page reads/writes via
    // `nvme_backing_dispatch`. A configuration without any
    // BackingType::Nvme arena never triggers the dispatch, so this
    // registration is free on the hot path. The kernel resolves the
    // FNV-1a hash to the function address in our module image.
    if s.pager_registered == 0 {
        let sys = &*s.syscalls;
        let mut arg = NVME_BACKING_DISPATCH_HASH.to_le_bytes();
        let rc = (sys.dev_call)(-1, NVME_BACKING_ENABLE, arg.as_mut_ptr(), arg.len());
        if rc == 0 {
            s.pager_registered = 1;
            dev_log(sys, 3, b"[nvme] pager dispatch registered\0".as_ptr(), 31);
        }
        // On failure: leave `pager_registered = 0` and retry on the
        // next step. This lets us recover from transient issues (e.g.
        // scheduler calling before our module's export table is
        // resolvable) and also makes the failure visible in the log —
        // the `pager_registered` flag stays 0, heartbeat will echo it
        // indirectly through the lack of a "dispatch registered" line.
    }

    // One-shot PCIe capability walk for observability — the heartbeat
    // will re-emit this until a log viewer captures it.
    if s.msix_walked == 0 {
        s.msix_walked = 1;
        walk_pcie_caps(s);
    }
    // Drain any MSI-X event the brcmstb mux raised so the event
    // ring doesn't back up. The CQ is still polled below; the event
    // is a "CQE may be ready" hint for future event-driven paths.
    if s.msix_enabled != 0 && s.msix_event >= 0 {
        let _ = dev_event_poll(&*s.syscalls, s.msix_event);
    }
    // Service incoming write requests on every tick. poll_io_cqe is
    // CID-aware (reads ask for CID_READ_LBA0, writes use the
    // 0x0100-range), so pump_requests can submit in parallel with a
    // read in flight without either path consuming the other's CQE.
    pump_requests(s);
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
            // Read one block per SQE on the stream path. The primitive
            // supports `nlb` up to MAX_NLB, but fat32 seeks between
            // metadata sectors (FAT → data → FAT → ...), so any
            // prefetched blocks beyond the first would be discarded on
            // the next seek. Batched reads are reserved for future
            // producers that stream contiguous spans.
            s.blk_nlb = 1;
            submit_io_read(s, s.current_block as u64, 1, CID_READ_LBA0);
            s.blk_phase = BLK_PHASE_READING;
            0
        }
        BLK_PHASE_READING => match poll_io_cqe(s, CID_READ_LBA0) {
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
            // BLK_PHASE_WRITING: push the whole batch byte-by-byte to the
            // output channel, handling partial writes + backpressure.
            let sys = &*s.syscalls;
            let batch_bytes = (s.blk_nlb as u32) * BLOCK_SIZE;
            let remaining = batch_bytes - (s.write_offset as u32);
            let src = (s.read_buf as *const u8).add(s.write_offset as usize);
            let n = (sys.channel_write)(s.blk_out, src, remaining as usize);
            if n < 0 {
                if n == E_AGAIN { return 0; }
                return fault(s, 26, b"[nvme] blocks channel write err\0");
            }
            let written = n as u32;
            s.write_offset += written as u16;
            if s.write_offset as u32 >= batch_bytes {
                s.current_block = s.current_block.wrapping_add(s.blk_nlb as u32);
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
// Channel ioctl handler (registered on `req_in` at module_new)
// ============================================================================

/// Services [`IOCTL_NVME_NS_INFO`] queries from any consumer wired to
/// `req_in`. Reads the requested nsid (u32 LE) from `arg`, returns
/// `{ns_size:u64 LE, ns_lbads:u8}` overwriting the same buffer.
///
/// Signature must be `unsafe extern "C"` to match
/// [`ChannelIoctlHandler`]. Kernel holds the function pointer + state
/// pointer across the module's lifetime; see `channel.rs`.
unsafe extern "C" fn nvme_ioctl_handler(state: *mut c_void, cmd: u32, arg: *mut u8) -> i32 {
    if state.is_null() || arg.is_null() {
        return E_INVAL;
    }
    if cmd != IOCTL_NVME_NS_INFO {
        return E_NOSYS;
    }
    let s = &*(state as *const NvmeState);
    // Reject queries until IdentifyNamespace has populated the
    // geometry fields. ns_size is non-zero for any real namespace.
    if s.ns_size == 0 {
        return E_AGAIN;
    }
    let requested_nsid = u32::from_le_bytes([
        *arg, *arg.add(1), *arg.add(2), *arg.add(3),
    ]);
    if requested_nsid != 0 && requested_nsid != s.namespace {
        return E_INVAL;
    }
    let size = s.ns_size.to_le_bytes();
    let mut i = 0usize;
    while i < 8 { *arg.add(i) = size[i]; i += 1; }
    *arg.add(8) = s.ns_lbads;
    0
}

// ============================================================================
// Pager backing-store dispatch
// ============================================================================
//
// Called SYNCHRONOUSLY from the kernel pager (a page-fault-handler
// invocation of `backing_store::backing_read/write` for arenas
// registered with `BackingType::Nvme`). We submit one SQE on the
// shared I/O SQ and spin-poll `io_cq` for the matching CID. On a
// single-core cooperative design where the faulting module itself
// has called into the pager, `step_ready` is not mid-step, so
// nothing else is racing on `io_cq` during this call — any write
// CQEs that land get absorbed into the in-flight ring, matching
// what `poll_io_cqe(s, CID_NONE)` does.
//
// Caller's arg layout (see src/kernel/nvme_backing.rs):
//   offset 0..8   arena_lba_base: u64 LE
//   offset 8..12  vpage_idx:      u32 LE
//   offset 12..20 buf_ptr:        u64 LE (caller's page buffer)

const PAGE_BYTES: u32 = 4096;
const PAGE_LBAS:  u16 = 8; // 4 KB page = 8 × 512 B LBAs

/// Spin-poll the I/O CQs until a CQE with `expected_cid` arrives.
/// Scans all `io_q_count` queues each pass so a write CQE that lands
/// on queue 2 while the pager issued on queue 0 doesn't starve. Any
/// write CQEs observed along the way are absorbed into the per-queue
/// inflight ring; stray CIDs are logged. Pager CIDs (CID_PAGER_READ,
/// CID_PAGER_WRITE) always live on queue 0 — the pager uses queue 0
/// exclusively for simplicity (single-vector shared synchronous path).
unsafe fn pager_spin_poll_cqe(s: &mut NvmeState, expected_cid: u16) -> i32 {
    let start = now_ms(s);
    loop {
        let mut made_progress = false;
        let n = s.io_q_count as usize;
        for q in 0..n {
            while let Some((cid, sc)) = peek_io_cqe(s, q) {
                consume_io_cqe(s, q);
                made_progress = true;

                if cid == expected_cid {
                    return if sc == 0 { 0 } else { E_INVAL };
                }

                if is_write_cid(cid) {
                    // Retire per-queue inflight head.
                    let cnt = *s.inflight_count.as_ptr().add(q);
                    if cnt > 0 {
                        let head = *s.inflight_head.as_ptr().add(q) as usize;
                        let new_head = (head + 1) % MAX_INFLIGHT;
                        *s.inflight_head.as_mut_ptr().add(q) = new_head as u8;
                        *s.inflight_count.as_mut_ptr().add(q) = cnt - 1;
                    }
                    continue;
                }

                // Any other CID is a surprise — log + keep spinning.
                dev_log(&*s.syscalls, 2, b"[nvme] pager: stray cqe\0".as_ptr(), 22);
            }
        }
        if !made_progress {
            if now_ms(s).saturating_sub(start) > PAGER_SUBMIT_BUDGET_MS {
                return E_AGAIN;
            }
        }
    }
}

/// Ensure `pager_buf` has a 4 KB DMA page allocated. Uses the
/// coherent (Non-Cacheable) arena so the spin-poll path doesn't
/// have to issue DC CVAC / DC IVAC around each I/O — simpler and
/// paging is never the latency-critical path anyway.
unsafe fn pager_ensure_buf(s: &mut NvmeState) -> bool {
    if s.pager_buf != 0 { return true; }
    let p = dev_dma_alloc(&*s.syscalls, PAGE, PAGE);
    if p == 0 { return false; }
    s.pager_buf = p;
    true
}

#[unsafe(no_mangle)]
#[link_section = ".text.nvme_backing_dispatch"]
pub unsafe extern "C" fn nvme_backing_dispatch(
    state: *mut u8, opcode: u32, arg: *mut u8, arg_len: usize,
) -> i32 {
    if state.is_null() { return E_INVAL; }
    let s = &mut *(state as *mut NvmeState);

    if opcode == PAGER_OP_FLUSH {
        // NVMe writes are synchronous (we spin-poll each one), so
        // nothing is queued at the kernel side. Could be extended to
        // issue a real Flush (0x00) in the future.
        return 0;
    }
    if opcode != PAGER_OP_READ && opcode != PAGER_OP_WRITE {
        return E_NOSYS;
    }

    // The module must be in S_READY before pager I/O is legal — the
    // I/O queue pair isn't live until CreateIoCQ/CreateIoSQ complete.
    if s.state != S_READY { return E_AGAIN; }

    if arg.is_null() || arg_len < 20 { return E_INVAL; }
    let arena_lba_base = u64::from_le_bytes([
        *arg, *arg.add(1), *arg.add(2), *arg.add(3),
        *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
    ]);
    let vpage_idx = u32::from_le_bytes([
        *arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11),
    ]);
    let buf_ptr = u64::from_le_bytes([
        *arg.add(12), *arg.add(13), *arg.add(14), *arg.add(15),
        *arg.add(16), *arg.add(17), *arg.add(18), *arg.add(19),
    ]) as *mut u8;
    if buf_ptr.is_null() { return E_INVAL; }

    if !pager_ensure_buf(s) { return E_INVAL; }

    let lba = arena_lba_base + (vpage_idx as u64) * (PAGE_LBAS as u64);

    if opcode == PAGER_OP_WRITE {
        // Stage caller's page into our coherent DMA page.
        let mut i = 0usize;
        while i < PAGE_BYTES as usize {
            write_volatile(
                (s.pager_buf as *mut u8).add(i),
                read_volatile(buf_ptr.add(i)),
            );
            i += 1;
        }
        // Pager always uses queue 0 (pinned). CID_PAGER_WRITE (0x0201)
        // is outside the 0x0100..0x011F inflight window, so it won't
        // be mis-classified as a pipelined write.
        submit_io_write(s, 0, lba, PAGE_LBAS, CID_PAGER_WRITE, s.namespace, s.pager_buf);
        let rc = pager_spin_poll_cqe(s, CID_PAGER_WRITE);
        return rc;
    }

    // READ
    // submit_io_read sources into s.read_buf, not an arbitrary target.
    // Build the SQE inline so DMA lands directly in pager_buf and we
    // avoid a read-buf-vs-pager-buf aliasing risk (pager_buf is fixed,
    // read_buf is fast-path for step_ready). Pager pinned to queue 0.
    let pager_q: usize = 0;
    let prp1_pci = s.pager_buf | PCI_DMA_OFFSET;
    let cdw = [
        ((CID_PAGER_READ as u32) << 16) | (OPC_READ as u32),
        s.namespace,
        0, 0,
        0, 0,
        prp1_pci as u32, (prp1_pci >> 32) as u32,
        0, 0,
        lba as u32, (lba >> 32) as u32,
        (PAGE_LBAS as u32) - 1,
        0, 0, 0,
    ];
    let sq_base = *s.io_sq.as_ptr().add(pager_q);
    let tail = *s.io_sq_tail.as_ptr().add(pager_q);
    write_sqe(sq_base, tail, cdw);
    let new_tail = (tail + 1) % IO_Q_ENTRIES;
    *s.io_sq_tail.as_mut_ptr().add(pager_q) = new_tail;
    reg_w32(s, sq_doorbell(s, IO_QID as u32 + pager_q as u32), new_tail);
    let rc = pager_spin_poll_cqe(s, CID_PAGER_READ);
    if rc == 0 {
        // Copy DMA page into caller's buffer.
        let mut i = 0usize;
        while i < PAGE_BYTES as usize {
            write_volatile(
                buf_ptr.add(i),
                read_volatile((s.pager_buf as *const u8).add(i)),
            );
            i += 1;
        }
    }
    rc
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
        // Second input port (`requests`, index 1) carries
        // write-request packets from fat32 or any other producer.
        s.req_in  = dev_channel_port(&*s.syscalls, 0, 1);
        s.blk_out = out_chan;
        s.ctrl    = ctrl_chan;
        s.state = S_WAIT_PCIE;
        s.logged_state = 0xFE;

        // Register the NS_INFO ioctl handler on req_in. Consumers
        // (fat32, future block users) read namespace geometry via
        // IOCTL_NVME_NS_INFO on their write channel. The handler
        // refuses queries until IdentifyNamespace has populated
        // ns_size; callers should wait for the module's Ready signal
        // before querying.
        if s.req_in >= 0 {
            dev_channel_register_ioctl(
                &*s.syscalls,
                s.req_in,
                state as *mut c_void,
                Some(nvme_ioctl_handler),
            );
        }

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Resolve the in-flight cap after params parse. A queue_depth
        // of 0 is nonsensical (would stall pump_requests forever), so
        // floor at 1; IO_Q_ENTRIES-1 keeps a free SQE slot so a ring
        // full condition is distinguishable from empty. MAX_INFLIGHT
        // caps the DMA-buffer footprint.
        let qd = if s.queue_depth == 0 { 1u32 } else { s.queue_depth as u32 };
        let cap = qd.min(MAX_INFLIGHT as u32).min(IO_Q_ENTRIES - 1) as u8;
        s.inflight_cap = if cap == 0 { 1 } else { cap };
        // Floor io_q_count to [1, MAX_IO_QUEUES] — the TLV path clamps
        // already, but set_defaults leaves this zero.
        if s.io_q_count == 0 || s.io_q_count as usize > MAX_IO_QUEUES {
            s.io_q_count = 1;
        }
        // `-1` = no event yet; `enable_msix` creates on first need.
        s.msix_event = -1;

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
        S_READ_LBA0           => step_read_lba0(s),
        S_READY               => step_ready(s),
        _                     => step_fault(s),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

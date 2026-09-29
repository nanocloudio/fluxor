//! nbd_serve — publishes a `storage.block` source as a Linux block device
//! over NBD.
//!
//! The source is the channel wired to the `blocks` input. The module listens
//! on a `net_proto` stream transport (`linux_net` on a Linux host, `ip` on
//! bare metal) and serves one NBD client at a time with the fixed-newstyle
//! handshake and simple replies; `nbd-client` attaches the export as
//! `/dev/nbdN`.
//!
//! NBD requests become `storage.block` v1 requests. A request larger than one
//! buffer slot is split into slot-sized chunks, so any request up to
//! `max_request` streams through a fixed pool. Chunks go to the source with
//! `SUBMIT`/`REAP` when it pipelines (`F_ASYNC`), otherwise with `EXEC`, and
//! replies leave in the order requests finish, each carrying its handle.
//!
//! Durability is the source's, never assumed:
//! - `FLUSH` is answered after the source's `FLUSH` completes. It covers
//!   every write already answered, because an answered write was reaped.
//! - A `FUA` write carries the source's `F_FUA` when it has one; otherwise,
//!   on a source with a volatile cache, the write is followed by a `FLUSH`
//!   and answered after that. A source without a volatile cache makes every
//!   write durable when it completes.
//!
//! A read is answered once all of its chunks are in, so a failure is the
//! reply's error. The exception is a read larger than the free pool, which
//! has to stream: a chunk that fails after its header has gone out cannot be
//! reported, so the connection is closed, as the protocol requires.
//!
//! Parameters:
//! - `port`: TCP port to listen on (the transport chooses the address).
//! - `export`: export name a client must ask for; empty accepts any.
//! - `read_only`: 1 publishes the export read-only whatever the source does.
//! - `queue_depth`: chunks in flight to the source, at most `MAX_SLOTS`.
//! - `max_request`: largest read or write accepted, in bytes.

#![cfg_attr(not(feature = "host-test"), no_std)]
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

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::storage::block::{self as blk, Cpl, Req};

// ── Limits ───────────────────────────────────────────────────────────────

/// Chunks in flight to the source, and buffers in the pool.
pub const MAX_SLOTS: usize = 8;
/// Bytes one buffer slot holds: the largest chunk a read or write is split
/// into.
pub const SLOT_SIZE: usize = 16384;
/// NBD requests admitted at once, answered or not.
pub const MAX_REQUESTS: usize = 16;
/// Ceiling on the `max_request` parameter.
pub const MAX_REQUEST_BYTES: u32 = 32 << 20;
/// Longest export name.
pub const EXPORT_NAME_CAP: usize = 64;
/// Largest option payload parsed; a longer one is drained and refused.
pub const OPT_BUF_SIZE: usize = 512;
/// Handshake replies queued at once.
const CTRL_CAP: usize = 192;
/// Reply bytes one outgoing frame carries.
const OUT_DATA_MAX: usize = 4096;
/// Transport frames read per step.
const STEP_FRAME_BUDGET: usize = 16;
/// Frames written per step.
const STEP_SEND_BUDGET: usize = 16;
/// Completions reaped per step.
const STEP_REAP_BUDGET: usize = 16;
/// Steps between `CMD_BIND` attempts until the transport answers.
const BIND_RETRY_STEPS: u16 = 256;

const IN_FRAME: usize = 3 + 2 + 1460;
const OUT_FRAME: usize = 3 + 2 + OUT_DATA_MAX;
const NONE: u8 = 0xFF;

// ── net_proto ────────────────────────────────────────────────────────────

const NET_MSG_ACCEPTED: u8 = 0x01;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_BOUND: u8 = 0x04;
const NET_MSG_ERROR: u8 = 0x06;
const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;

// ── NBD protocol ─────────────────────────────────────────────────────────

const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
const REP_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REQUEST_MAGIC: u32 = 0x2560_9513;
const REPLY_MAGIC: u32 = 0x6744_6698;

const FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
const FLAG_NO_ZEROES: u16 = 1 << 1;
const CFLAG_FIXED_NEWSTYLE: u32 = 1 << 0;
const CFLAG_NO_ZEROES: u32 = 1 << 1;

const OPT_EXPORT_NAME: u32 = 1;
const OPT_ABORT: u32 = 2;
const OPT_LIST: u32 = 3;
const OPT_INFO: u32 = 6;
const OPT_GO: u32 = 7;

const REP_ACK: u32 = 1;
const REP_SERVER: u32 = 2;
const REP_INFO: u32 = 3;
const REP_ERR_UNSUP: u32 = 0x8000_0001;
const REP_ERR_INVALID: u32 = 0x8000_0003;
const REP_ERR_UNKNOWN: u32 = 0x8000_0006;
const REP_ERR_TOO_BIG: u32 = 0x8000_0009;

const INFO_EXPORT: u16 = 0;
const INFO_BLOCK_SIZE: u16 = 3;

const TF_HAS_FLAGS: u16 = 1 << 0;
const TF_READ_ONLY: u16 = 1 << 1;
const TF_SEND_FLUSH: u16 = 1 << 2;
const TF_SEND_FUA: u16 = 1 << 3;
const TF_SEND_TRIM: u16 = 1 << 5;

const CMD_READ: u16 = 0;
const CMD_WRITE: u16 = 1;
const CMD_DISC: u16 = 2;
const CMD_FLUSH: u16 = 3;
const CMD_TRIM: u16 = 4;
const CMD_FLAG_FUA: u16 = 1 << 0;

const NBD_EPERM: u32 = 1;
const NBD_EIO: u32 = 5;
const NBD_ENOMEM: u32 = 12;
const NBD_EINVAL: u32 = 22;
const NBD_ENOSPC: u32 = 28;
const NBD_EOVERFLOW: u32 = 75;
const NBD_ENOTSUP: u32 = 95;

// Module-side errno values a request is refused with before the source sees
// it; mapped to NBD codes by `nbd_errno` like the source's own.
const E_PERM: i32 = -1;
const E_NOSPC: i32 = -28;

// ── State ────────────────────────────────────────────────────────────────

// Connection phase.
const PH_IDLE: u8 = 0;
const PH_HANDSHAKE: u8 = 1;
const PH_TRANSMIT: u8 = 2;

// Parser state.
const PS_CLIENT_FLAGS: u8 = 0;
const PS_OPT_HDR: u8 = 1;
const PS_OPT_DATA: u8 = 2;
const PS_REQ_HDR: u8 = 3;
const PS_WRITE: u8 = 4;
const PS_DRAIN: u8 = 5;
const PS_STOP: u8 = 6;

// Slot state.
const SL_FREE: u8 = 0;
/// A write chunk receiving its payload.
const SL_FILL: u8 = 1;
/// Built, waiting to go to the source.
const SL_READY: u8 = 2;
const SL_INFLIGHT: u8 = 3;
/// A read chunk holding data for its reply.
const SL_DONE: u8 = 4;

// Follow-up flush of a FUA write on a source without native FUA.
const PF_NONE: u8 = 0;
const PF_WANT: u8 = 1;
const PF_ISSUED: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct Slot {
    state: u8,
    /// Owning request.
    req: u8,
    /// `blk::op`.
    op: u8,
    /// `blk::F_*`.
    flags: u8,
    nblocks: u32,
    lba: u64,
    /// Data bytes: the chunk of a read or write, 0 otherwise.
    len: u32,
    /// Write: payload bytes received. Read: reply bytes sent.
    fill: u32,
    /// Position among the request's chunks.
    chunk: u32,
    status: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Request {
    active: u8,
    cmd: u8,
    fua: u8,
    /// Every chunk the request will need has been built.
    all_issued: u8,
    post_flush: u8,
    header_sent: u8,
    _pad: [u8; 2],
    handle: u64,
    offset: u64,
    length: u32,
    /// Bytes assigned to chunks so far.
    created: u32,
    chunks: u32,
    done: u32,
    /// Read chunks whose data has been sent.
    sent_chunks: u32,
    /// First failure, as a negative errno; 0 while none.
    err: i32,
    /// Arrival order.
    seq: u64,
    /// Completion order; 0 until complete.
    stamp: u64,
}

#[repr(C)]
pub struct NbdState {
    syscalls: *const SyscallTable,
    blocks: BlockClient,
    net_in: i32,
    net_out: i32,

    // Parameters.
    port: u16,
    read_only: u8,
    queue_depth: u8,
    max_request: u32,
    name_len: u8,
    _pad0: [u8; 3],
    name: [u8; EXPORT_NAME_CAP],

    // The source, once `CAPS` answered.
    ready: u8,
    async_src: u8,
    shift: u8,
    bound: u8,
    src_flags: u32,
    size: u64,
    chunk_bytes: u32,
    trim_bytes: u32,
    depth: u8,
    ro: u8,
    tflags: u16,
    bind_wait: u16,
    _pad1: [u8; 2],

    // The connection.
    phase: u8,
    pstate: u8,
    closing: u8,
    /// No further output: the peer has gone or the stream is unusable.
    abort: u8,
    peer_gone: u8,
    no_zeroes: u8,
    gen: u8,
    wreq: u8,
    wslot: u8,
    tx_req: u8,
    conn_id: u16,
    acc_len: u8,
    acc_need: u8,
    opt_big: u8,
    _pad2: u8,
    opt: u32,
    opt_len: u32,
    opt_fill: u32,
    drain: u32,
    rx_off: u16,
    rx_len: u16,
    ctrl_off: u16,
    ctrl_len: u16,
    next_seq: u64,
    next_stamp: u64,

    // Counters, logged per client.
    pub clients: u32,
    pub replies: u32,
    pub errors: u32,
    pub refused: u32,

    acc: [u8; 32],
    ctrl: [u8; CTRL_CAP],
    opt_buf: [u8; OPT_BUF_SIZE],
    rx: [u8; IN_FRAME],
    out: [u8; OUT_FRAME],
    reqs: [Request; MAX_REQUESTS],
    slots: [Slot; MAX_SLOTS],
    bufs: [[u8; SLOT_SIZE]; MAX_SLOTS],
}

impl NbdState {
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

mod params_def {
    use super::p_u16;
    use super::p_u32;
    use super::p_u8;
    use super::NbdState;
    use super::SCHEMA_MAX;

    define_params! {
        NbdState;

        1, port, u16, 10809
            => |s, d, len| { s.port = p_u16(d, len, 0, 10809); };

        2, export, str, 0
            => |s, d, len| {
                let n = if len > s.name.len() { s.name.len() } else { len };
                for i in 0..s.name.len() { s.name[i] = 0; }
                for i in 0..n { s.name[i] = *d.add(i); }
                s.name_len = n as u8;
            };

        3, read_only, u8, 0
            => |s, d, len| { s.read_only = p_u8(d, len, 0, 0); };

        4, queue_depth, u8, 8
            => |s, d, len| { s.queue_depth = p_u8(d, len, 0, 8); };

        5, max_request, u32, 33554432
            => |s, d, len| { s.max_request = p_u32(d, len, 0, 33554432); };
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn be16(b: &[u8], at: usize) -> u16 {
    match b.get(at..at + 2) {
        Some(x) => u16::from_be_bytes([x[0], x[1]]),
        None => 0,
    }
}

fn be32(b: &[u8], at: usize) -> u32 {
    match b.get(at..at + 4) {
        Some(x) => u32::from_be_bytes([x[0], x[1], x[2], x[3]]),
        None => 0,
    }
}

fn be64(b: &[u8], at: usize) -> u64 {
    match b.get(at..at + 8) {
        Some(x) => u64::from_be_bytes([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]]),
        None => 0,
    }
}

/// The NBD error for a negative errno from the source or the module.
fn nbd_errno(e: i32) -> u32 {
    match e {
        0 => 0,
        -1 | -13 | -30 => NBD_EPERM,
        -12 => NBD_ENOMEM,
        -22 => NBD_EINVAL,
        -28 => NBD_ENOSPC,
        -27 | -75 => NBD_EOVERFLOW,
        -38 | -95 => NBD_ENOTSUP,
        _ => NBD_EIO,
    }
}

fn min_u32(a: u32, b: u32) -> u32 {
    if a < b {
        a
    } else {
        b
    }
}

unsafe fn log(s: &NbdState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

unsafe fn net_cmd(s: &mut NbdState, cmd: u8, payload: &[u8]) -> bool {
    let mut scratch = [0u8; 8];
    net_write_frame(
        s.sys(),
        s.net_out,
        cmd,
        payload.as_ptr(),
        payload.len(),
        scratch.as_mut_ptr(),
        scratch.len(),
    ) != 0
}

// ── Source geometry ──────────────────────────────────────────────────────

/// Learn the source's geometry once `CAPS` answers. False while it attaches
/// or when it cannot be published.
unsafe fn learn_source(s: &mut NbdState) -> bool {
    let rc = s.blocks.caps(s.sys());
    if rc != 0 {
        return false;
    }
    let lbs = s.blocks.block_size();
    if lbs == 0 || lbs as usize > SLOT_SIZE {
        if s.ready == 0 {
            log(s, b"[nbd] source block size exceeds a slot; not published");
            s.ready = 2;
        }
        return false;
    }
    let shift = lbs.trailing_zeros() as u8;
    let flags = s.blocks.flags();
    let mut count = s.blocks.block_count();
    if count > (u64::MAX >> shift) {
        count = u64::MAX >> shift;
    }
    s.shift = shift;
    s.src_flags = flags;
    s.size = count << shift;
    let mb = u64::from(s.blocks.max_blocks()) << shift;
    s.chunk_bytes = if mb < SLOT_SIZE as u64 {
        mb as u32
    } else {
        SLOT_SIZE as u32
    };
    s.trim_bytes = if mb < (1u64 << 30) {
        mb as u32
    } else {
        1u32 << 30
    };
    s.async_src = u8::from(flags & blk::caps::F_ASYNC != 0);
    let mut depth = if s.queue_depth == 0 { 1 } else { s.queue_depth };
    if depth as usize > MAX_SLOTS {
        depth = MAX_SLOTS as u8;
    }
    let qd = s.blocks.queue_depth();
    if s.async_src != 0 && u16::from(depth) > qd {
        depth = qd as u8;
    }
    if depth == 0 {
        depth = 1;
    }
    s.depth = depth;
    let mut maxreq = s.max_request;
    if maxreq > MAX_REQUEST_BYTES {
        maxreq = MAX_REQUEST_BYTES;
    }
    if maxreq < lbs {
        maxreq = lbs;
    }
    s.max_request = maxreq & !(lbs - 1);
    let has = |f: u32| flags & f != 0;
    s.ro = u8::from(s.read_only != 0 || !has(blk::caps::F_WRITE));
    let mut tf = TF_HAS_FLAGS;
    if s.ro != 0 {
        tf |= TF_READ_ONLY;
    }
    if has(blk::caps::F_FLUSH) {
        tf |= TF_SEND_FLUSH;
    }
    if s.ro == 0 && (has(blk::caps::F_FUA) || has(blk::caps::F_FLUSH)) {
        tf |= TF_SEND_FUA;
    }
    if s.ro == 0 && has(blk::caps::F_DISCARD) {
        tf |= TF_SEND_TRIM;
    }
    s.tflags = tf;
    s.ready = 1;
    true
}

// ── Output ───────────────────────────────────────────────────────────────

/// Queue handshake bytes. The caller has checked they fit.
fn ctrl_push(s: &mut NbdState, bytes: &[u8]) {
    let at = s.ctrl_len as usize;
    if let Some(dst) = s.ctrl.get_mut(at..at + bytes.len()) {
        dst.copy_from_slice(bytes);
        s.ctrl_len += bytes.len() as u16;
    }
}

fn ctrl_rep(s: &mut NbdState, opt: u32, kind: u32, len: u32) {
    ctrl_push(s, &REP_MAGIC.to_be_bytes());
    ctrl_push(s, &opt.to_be_bytes());
    ctrl_push(s, &kind.to_be_bytes());
    ctrl_push(s, &len.to_be_bytes());
}

/// Write the `CMD_SEND` frame staged in `out` with `n` data bytes. False
/// when the transport has no room; nothing was sent.
unsafe fn send_staged(s: &mut NbdState, n: usize) -> bool {
    let plen = 2 + n;
    s.out[0] = NET_CMD_SEND;
    s.out[1] = plen as u8;
    s.out[2] = (plen >> 8) as u8;
    let id = s.conn_id.to_le_bytes();
    s.out[3] = id[0];
    s.out[4] = id[1];
    let total = 3 + plen;
    (s.sys().channel_write)(s.net_out, s.out.as_ptr(), total) == total as i32
}

/// Send queued handshake bytes. True when nothing is left queued.
unsafe fn flush_ctrl(s: &mut NbdState) -> bool {
    if s.ctrl_off >= s.ctrl_len {
        s.ctrl_off = 0;
        s.ctrl_len = 0;
        return true;
    }
    let from = s.ctrl_off as usize;
    let n = (s.ctrl_len as usize - from).min(OUT_DATA_MAX);
    let mut i = 0;
    while i < n {
        s.out[5 + i] = s.ctrl[from + i];
        i += 1;
    }
    if !send_staged(s, n) {
        return false;
    }
    s.ctrl_off += n as u16;
    if s.ctrl_off >= s.ctrl_len {
        s.ctrl_off = 0;
        s.ctrl_len = 0;
        return true;
    }
    false
}

// ── Requests and slots ───────────────────────────────────────────────────

fn free_slot_index(s: &NbdState) -> u8 {
    let mut i = 0;
    while i < MAX_SLOTS {
        if s.slots[i].state == SL_FREE {
            return i as u8;
        }
        i += 1;
    }
    NONE
}

/// The oldest request still building chunks: the only one allowed to take
/// a slot for new work, so a request larger than the pool cannot wait on
/// slots held by requests behind it.
fn head(s: &NbdState) -> u8 {
    let mut best = NONE;
    let mut seq = u64::MAX;
    let mut i = 0;
    while i < MAX_REQUESTS {
        let r = &s.reqs[i];
        if r.active != 0 && r.all_issued == 0 && r.seq < seq {
            seq = r.seq;
            best = i as u8;
        }
        i += 1;
    }
    best
}

fn take_slot(s: &mut NbdState, req: u8, op: u8, flags: u8, lba: u64, nblocks: u32, len: u32) -> u8 {
    let i = free_slot_index(s);
    if i == NONE {
        return NONE;
    }
    let r = &mut s.reqs[req as usize];
    let chunk = r.chunks;
    r.chunks += 1;
    s.slots[i as usize] = Slot {
        state: SL_READY,
        req,
        op,
        flags,
        nblocks,
        lba,
        len,
        fill: 0,
        chunk,
        status: 0,
    };
    i
}

/// Build the next chunks of the head request, when its chunks come from the
/// module rather than from the client's payload.
fn build_chunks(s: &mut NbdState) {
    let mut budget = MAX_SLOTS * 2;
    while budget > 0 {
        budget -= 1;
        let h = head(s);
        if h == NONE {
            return;
        }
        let r = s.reqs[h as usize];
        if r.err != 0 && r.cmd != CMD_WRITE as u8 {
            s.reqs[h as usize].all_issued = 1;
            continue;
        }
        match u16::from(r.cmd) {
            CMD_READ | CMD_TRIM => {
                let remaining = r.length - r.created;
                let (op, cap) = if u16::from(r.cmd) == CMD_READ {
                    (blk::op::READ, s.chunk_bytes)
                } else {
                    (blk::op::DISCARD, s.trim_bytes)
                };
                let len = min_u32(remaining, cap);
                let lba = (r.offset + u64::from(r.created)) >> s.shift;
                let nblocks = len >> s.shift;
                let data = if op == blk::op::READ { len } else { 0 };
                if take_slot(s, h, op, 0, lba, nblocks, data) == NONE {
                    return;
                }
                let r = &mut s.reqs[h as usize];
                r.created += len;
                if r.created >= r.length {
                    r.all_issued = 1;
                }
            }
            CMD_FLUSH => {
                if s.src_flags & blk::caps::F_FLUSH != 0
                    && take_slot(s, h, blk::op::FLUSH, 0, 0, 0, 0) == NONE
                {
                    return;
                }
                s.reqs[h as usize].all_issued = 1;
            }
            // A write's chunks are built as its payload arrives.
            _ => return,
        }
    }
}

/// Queue the follow-up flush of every FUA request whose data is all in.
fn build_post_flushes(s: &mut NbdState) {
    let mut i = 0;
    while i < MAX_REQUESTS {
        let r = s.reqs[i];
        if r.active != 0 && r.post_flush == PF_WANT && r.all_issued != 0 && r.done == r.chunks {
            if r.err != 0 {
                s.reqs[i].post_flush = PF_NONE;
            } else if take_slot(s, i as u8, blk::op::FLUSH, 0, 0, 0, 0) != NONE {
                s.reqs[i].post_flush = PF_ISSUED;
            } else {
                return;
            }
        }
        i += 1;
    }
}

/// Record a chunk's completion.
fn complete_slot(s: &mut NbdState, i: usize, status: i32) {
    if s.abort != 0 || s.peer_gone != 0 {
        s.slots[i].state = SL_FREE;
        return;
    }
    let sl = s.slots[i];
    let r = &mut s.reqs[sl.req as usize];
    r.done += 1;
    if status != 0 && r.err == 0 {
        r.err = status;
    }
    if sl.op == blk::op::READ {
        s.slots[i].status = status;
        s.slots[i].fill = 0;
        s.slots[i].state = SL_DONE;
    } else {
        s.slots[i].state = SL_FREE;
    }
    stamp(s, sl.req as usize);
}

/// Give request `i` its place in the reply order if it has just finished.
fn stamp(s: &mut NbdState, i: usize) {
    let r = s.reqs[i];
    if r.active != 0
        && r.stamp == 0
        && r.all_issued != 0
        && r.done == r.chunks
        && r.post_flush != PF_WANT
    {
        s.next_stamp += 1;
        s.reqs[i].stamp = s.next_stamp;
    }
}

fn in_flight(s: &NbdState) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < MAX_SLOTS {
        if s.slots[i].state == SL_INFLIGHT {
            n += 1;
        }
        i += 1;
    }
    n
}

/// Hand built chunks to the source.
unsafe fn issue(s: &mut NbdState) {
    let mut i = 0;
    while i < MAX_SLOTS {
        if s.slots[i].state != SL_READY {
            i += 1;
            continue;
        }
        if s.async_src != 0 && in_flight(s) >= s.depth as usize {
            return;
        }
        let sl = s.slots[i];
        let data = sl.op == blk::op::READ || sl.op == blk::op::WRITE;
        let r = Req {
            op: sl.op,
            flags: sl.flags,
            nblocks: sl.nblocks,
            lba: sl.lba,
            buf_ptr: if data {
                s.bufs[i].as_mut_ptr() as u64
            } else {
                0
            },
            buf_len: if data { sl.len } else { 0 },
            tag: (u64::from(s.gen) << 8) | i as u64,
        };
        let sys = &*s.syscalls;
        if s.async_src != 0 {
            let rc = s.blocks.submit(sys, &r);
            if rc == 0 {
                s.slots[i].state = SL_INFLIGHT;
            } else if rc == E_AGAIN {
                return;
            } else {
                complete_slot(s, i, rc);
            }
        } else {
            let rc = s.blocks.exec(sys, &r);
            if rc == E_AGAIN {
                return;
            }
            complete_slot(s, i, rc);
        }
        i += 1;
    }
}

/// Collect finished chunks from a pipelining source.
unsafe fn reap(s: &mut NbdState) {
    if s.async_src == 0 {
        return;
    }
    let mut n = 0;
    while n < STEP_REAP_BUDGET {
        n += 1;
        let mut c = Cpl::bare(0, 0);
        let sys = &*s.syscalls;
        if s.blocks.reap_one(sys, &mut c) != 1 {
            return;
        }
        let i = (c.tag & 0xFF) as usize;
        let gen = ((c.tag >> 8) & 0xFF) as u8;
        if i < MAX_SLOTS && gen == s.gen && s.slots[i].state == SL_INFLIGHT {
            complete_slot(s, i, c.status);
        }
    }
}

/// Stamp requests that finished without a completion to mark it: refused at
/// admission, or needing nothing from the source. Completions stamp as they
/// are reaped, so replies leave in the order the source finished.
fn stamp_complete(s: &mut NbdState) {
    let mut i = 0;
    while i < MAX_REQUESTS {
        stamp(s, i);
        i += 1;
    }
}

fn holds_slot(s: &NbdState, req: u8) -> bool {
    let mut i = 0;
    while i < MAX_SLOTS {
        if s.slots[i].state != SL_FREE && s.slots[i].req == req {
            return true;
        }
        i += 1;
    }
    false
}

fn find_chunk(s: &NbdState, req: u8, chunk: u32) -> u8 {
    let mut i = 0;
    while i < MAX_SLOTS {
        let sl = &s.slots[i];
        if sl.state != SL_FREE && sl.req == req && sl.chunk == chunk {
            return i as u8;
        }
        i += 1;
    }
    NONE
}

fn release_request(s: &mut NbdState, req: u8) {
    let mut i = 0;
    while i < MAX_SLOTS {
        if s.slots[i].state != SL_FREE && s.slots[i].state != SL_INFLIGHT && s.slots[i].req == req {
            s.slots[i].state = SL_FREE;
        }
        i += 1;
    }
    s.reqs[req as usize].active = 0;
}

/// The next request to answer: the first to finish, or else a read too
/// large for the pool, streamed once nothing else holds a slot.
fn pick_reply(s: &NbdState) -> u8 {
    let mut best = NONE;
    let mut stamp = u64::MAX;
    let mut i = 0;
    while i < MAX_REQUESTS {
        let r = &s.reqs[i];
        if r.active != 0 && r.stamp != 0 && r.stamp < stamp {
            stamp = r.stamp;
            best = i as u8;
        }
        i += 1;
    }
    if best != NONE {
        return best;
    }
    let h = head(s);
    if h == NONE {
        return NONE;
    }
    let r = &s.reqs[h as usize];
    if u16::from(r.cmd) != CMD_READ || r.err != 0 {
        return NONE;
    }
    let first = find_chunk(s, h, 0);
    if first == NONE || s.slots[first as usize].state != SL_DONE {
        return NONE;
    }
    let mut i = 0;
    while i < MAX_REQUESTS {
        if i != h as usize && s.reqs[i].active != 0 && holds_slot(s, i as u8) {
            return NONE;
        }
        i += 1;
    }
    h
}

/// End the connection without another byte of output: the stream can no
/// longer say anything truthful.
fn abort_conn(s: &mut NbdState) {
    s.abort = 1;
    s.closing = 1;
    s.pstate = PS_STOP;
    s.ctrl_len = 0;
    s.ctrl_off = 0;
}

/// Send replies, one frame at a time, within the step's budget.
unsafe fn send_replies(s: &mut NbdState) {
    let mut frames = 0;
    while frames < STEP_SEND_BUDGET {
        if s.abort != 0 || s.peer_gone != 0 || s.phase == PH_IDLE {
            return;
        }
        if s.ctrl_len != 0 {
            if !flush_ctrl(s) {
                return;
            }
            frames += 1;
            continue;
        }
        if s.phase != PH_TRANSMIT {
            return;
        }
        if s.tx_req == NONE {
            s.tx_req = pick_reply(s);
            if s.tx_req == NONE {
                return;
            }
        }
        let ri = s.tx_req;
        let r = s.reqs[ri as usize];
        let is_read = u16::from(r.cmd) == CMD_READ;
        if is_read && r.header_sent != 0 && r.err != 0 {
            // A streamed read failed after its header promised data: the
            // simple reply has no way left to say so.
            abort_conn(s);
            return;
        }
        let err_reply = r.header_sent == 0 && r.err != 0;
        let mut n = 0usize;
        if r.header_sent == 0 {
            // A streamed read has no error to report yet; any other request
            // is answered only once it is finished.
            let err = nbd_errno(r.err);
            let hdr = &mut s.out[5..5 + 16];
            hdr[0..4].copy_from_slice(&REPLY_MAGIC.to_be_bytes());
            hdr[4..8].copy_from_slice(&err.to_be_bytes());
            hdr[8..16].copy_from_slice(&r.handle.to_be_bytes());
            n = 16;
        }
        let mut data_slot = NONE;
        let mut take = 0usize;
        if is_read && r.err == 0 && r.sent_chunks < r.chunks {
            let si = find_chunk(s, ri, r.sent_chunks);
            if si != NONE && s.slots[si as usize].state == SL_DONE {
                let sl = s.slots[si as usize];
                let left = (sl.len - sl.fill) as usize;
                take = left.min(OUT_DATA_MAX - n);
                let from = sl.fill as usize;
                let src = &s.bufs[si as usize][from..from + take];
                s.out[5 + n..5 + n + take].copy_from_slice(src);
                data_slot = si;
            }
        }
        if n + take == 0 {
            // A streamed read waiting on its next chunk.
            return;
        }
        if !send_staged(s, n + take) {
            return;
        }
        frames += 1;
        let rr = &mut s.reqs[ri as usize];
        rr.header_sent = 1;
        if data_slot != NONE {
            let sl = &mut s.slots[data_slot as usize];
            sl.fill += take as u32;
            if sl.fill >= sl.len {
                sl.state = SL_FREE;
                s.reqs[ri as usize].sent_chunks += 1;
            }
        }
        let r = s.reqs[ri as usize];
        let finished = !is_read
            || err_reply
            || (r.all_issued != 0 && r.sent_chunks >= r.chunks && r.created >= r.length);
        if finished {
            if err_reply {
                s.errors = s.errors.wrapping_add(1);
            }
            s.replies = s.replies.wrapping_add(1);
            release_request(s, ri);
            s.tx_req = NONE;
        }
    }
}

// ── Input ────────────────────────────────────────────────────────────────

fn expect(s: &mut NbdState, pstate: u8, need: u8) {
    s.pstate = pstate;
    s.acc_len = 0;
    s.acc_need = need;
}

fn name_ok(s: &NbdState, name: &[u8]) -> bool {
    if s.name_len == 0 {
        return true;
    }
    let n = s.name_len as usize;
    name.len() == n && name == &s.name[..n]
}

fn enter_transmission(s: &mut NbdState) {
    s.phase = PH_TRANSMIT;
    expect(s, PS_REQ_HDR, 28);
}

/// Answer a whole option. Returns false to wait for the reply queue.
fn handle_option(s: &mut NbdState) -> bool {
    let opt = s.opt;
    let len = s.opt_len as usize;
    if s.opt_big != 0 {
        if opt == OPT_EXPORT_NAME {
            // No name that long matches, and this option has no error reply.
            abort_conn(s);
            return true;
        }
        let kind = if opt == OPT_INFO || opt == OPT_GO {
            REP_ERR_TOO_BIG
        } else {
            REP_ERR_UNSUP
        };
        ctrl_rep(s, opt, kind, 0);
        expect(s, PS_OPT_HDR, 16);
        return true;
    }
    match opt {
        OPT_EXPORT_NAME => {
            if !name_ok(s, &s.opt_buf[..len]) {
                abort_conn(s);
                return true;
            }
            let size = s.size;
            let tf = s.tflags;
            ctrl_push(s, &size.to_be_bytes());
            ctrl_push(s, &tf.to_be_bytes());
            if s.no_zeroes == 0 {
                ctrl_push(s, &[0u8; 124]);
            }
            enter_transmission(s);
        }
        OPT_ABORT => {
            ctrl_rep(s, opt, REP_ACK, 0);
            s.closing = 1;
            s.pstate = PS_STOP;
        }
        OPT_LIST => {
            if len != 0 {
                ctrl_rep(s, opt, REP_ERR_INVALID, 0);
            } else {
                let n = s.name_len as usize;
                ctrl_rep(s, opt, REP_SERVER, 4 + n as u32);
                ctrl_push(s, &(n as u32).to_be_bytes());
                let name = s.name;
                ctrl_push(s, &name[..n]);
                ctrl_rep(s, opt, REP_ACK, 0);
            }
            expect(s, PS_OPT_HDR, 16);
        }
        OPT_INFO | OPT_GO => {
            let d = &s.opt_buf[..len];
            let namelen = be32(d, 0) as usize;
            let well_formed = len >= 6 && namelen <= len - 6 && {
                let nreq = be16(d, 4 + namelen) as usize;
                4 + namelen + 2 + 2 * nreq == len
            };
            if !well_formed {
                ctrl_rep(s, opt, REP_ERR_INVALID, 0);
                expect(s, PS_OPT_HDR, 16);
                return true;
            }
            let nreq = be16(d, 4 + namelen) as usize;
            let mut want_bs = false;
            let mut k = 0;
            while k < nreq {
                if be16(d, 4 + namelen + 2 + 2 * k) == INFO_BLOCK_SIZE {
                    want_bs = true;
                }
                k += 1;
            }
            if !name_ok(s, &s.opt_buf[4..4 + namelen]) {
                ctrl_rep(s, opt, REP_ERR_UNKNOWN, 0);
                expect(s, PS_OPT_HDR, 16);
                return true;
            }
            let size = s.size;
            let tf = s.tflags;
            ctrl_rep(s, opt, REP_INFO, 12);
            ctrl_push(s, &INFO_EXPORT.to_be_bytes());
            ctrl_push(s, &size.to_be_bytes());
            ctrl_push(s, &tf.to_be_bytes());
            if want_bs {
                let lbs = 1u32 << s.shift;
                let pref = if lbs > 4096 { lbs } else { 4096 };
                let max = s.max_request;
                let pref = min_u32(pref, max);
                ctrl_rep(s, opt, REP_INFO, 14);
                ctrl_push(s, &INFO_BLOCK_SIZE.to_be_bytes());
                ctrl_push(s, &lbs.to_be_bytes());
                ctrl_push(s, &pref.to_be_bytes());
                ctrl_push(s, &max.to_be_bytes());
            }
            ctrl_rep(s, opt, REP_ACK, 0);
            if opt == OPT_GO {
                enter_transmission(s);
            } else {
                expect(s, PS_OPT_HDR, 16);
            }
        }
        _ => {
            ctrl_rep(s, opt, REP_ERR_UNSUP, 0);
            expect(s, PS_OPT_HDR, 16);
        }
    }
    true
}

fn free_request_index(s: &NbdState) -> u8 {
    let mut i = 0;
    while i < MAX_REQUESTS {
        if s.reqs[i].active == 0 {
            return i as u8;
        }
        i += 1;
    }
    NONE
}

/// Admit a whole request header. Returns false to wait for a free request
/// entry.
fn handle_request(s: &mut NbdState) -> bool {
    let a = s.acc;
    if be32(&a, 0) != REQUEST_MAGIC {
        abort_conn(s);
        return true;
    }
    let flags = be16(&a, 4);
    let cmd = be16(&a, 6);
    let handle = be64(&a, 8);
    let offset = be64(&a, 16);
    let length = be32(&a, 24);
    if cmd == CMD_DISC {
        s.closing = 1;
        s.pstate = PS_STOP;
        return true;
    }
    let ri = free_request_index(s);
    if ri == NONE {
        return false;
    }
    s.next_seq += 1;
    let fua = flags & CMD_FLAG_FUA != 0;
    s.reqs[ri as usize] = Request {
        active: 1,
        cmd: cmd as u8,
        fua: u8::from(fua),
        all_issued: 0,
        post_flush: PF_NONE,
        header_sent: 0,
        _pad: [0; 2],
        handle,
        offset,
        length,
        created: 0,
        chunks: 0,
        done: 0,
        sent_chunks: 0,
        err: 0,
        seq: s.next_seq,
        stamp: 0,
    };
    let mask = (1u64 << s.shift) - 1;
    let aligned = offset & mask == 0 && u64::from(length) & mask == 0 && length != 0;
    let in_range = match offset.checked_add(u64::from(length)) {
        Some(end) => end <= s.size,
        None => false,
    };
    let src_flags = s.src_flags;
    let has = |f: u32| src_flags & f != 0;
    let err = match cmd {
        CMD_READ => {
            if !aligned || length > s.max_request || !in_range {
                E_INVAL
            } else {
                0
            }
        }
        CMD_WRITE => {
            if s.ro != 0 {
                E_PERM
            } else if !aligned || length > s.max_request {
                E_INVAL
            } else if !in_range {
                E_NOSPC
            } else {
                0
            }
        }
        CMD_TRIM => {
            if s.ro != 0 {
                E_PERM
            } else if !has(blk::caps::F_DISCARD) || !aligned {
                E_INVAL
            } else if !in_range {
                E_NOSPC
            } else {
                0
            }
        }
        CMD_FLUSH => 0,
        _ => E_INVAL,
    };
    let r = &mut s.reqs[ri as usize];
    if err != 0 {
        r.err = err;
        r.all_issued = 1;
        if cmd == CMD_WRITE && length != 0 {
            // The payload follows whether or not the write is refused.
            s.drain = length;
            s.pstate = PS_DRAIN;
            s.acc_len = 0;
        } else {
            expect(s, PS_REQ_HDR, 28);
        }
        return true;
    }
    if fua
        && (cmd == CMD_WRITE || cmd == CMD_TRIM)
        && (cmd == CMD_TRIM || !has(blk::caps::F_FUA))
        && has(blk::caps::F_FLUSH)
    {
        r.post_flush = PF_WANT;
    }
    if cmd == CMD_WRITE {
        s.wreq = ri;
        s.wslot = NONE;
        s.pstate = PS_WRITE;
        s.acc_len = 0;
    } else {
        expect(s, PS_REQ_HDR, 28);
    }
    true
}

/// Move write payload into chunks. Returns false when it must wait for a
/// slot.
fn take_write_data(s: &mut NbdState) -> bool {
    let ri = s.wreq;
    while s.rx_len > 0 {
        if s.wslot == NONE {
            let r = s.reqs[ri as usize];
            if r.err != 0 {
                // A chunk already failed: the reply is decided, the rest of
                // the payload only has to be consumed.
                s.drain = r.length - r.created;
                let rr = &mut s.reqs[ri as usize];
                rr.created = rr.length;
                rr.all_issued = 1;
                s.pstate = PS_DRAIN;
                return true;
            }
            if head(s) != ri {
                return false;
            }
            let len = min_u32(r.length - r.created, s.chunk_bytes);
            let lba = (r.offset + u64::from(r.created)) >> s.shift;
            let flags = if r.fua != 0 && s.src_flags & blk::caps::F_FUA != 0 {
                blk::F_FUA
            } else {
                0
            };
            let si = take_slot(s, ri, blk::op::WRITE, flags, lba, len >> s.shift, len);
            if si == NONE {
                return false;
            }
            s.slots[si as usize].state = SL_FILL;
            s.reqs[ri as usize].created += len;
            s.wslot = si;
        }
        let si = s.wslot as usize;
        let sl = s.slots[si];
        let want = (sl.len - sl.fill) as usize;
        let n = want.min(s.rx_len as usize);
        let from = s.rx_off as usize;
        let at = sl.fill as usize;
        let src = &s.rx[from..from + n];
        s.bufs[si][at..at + n].copy_from_slice(src);
        s.rx_off += n as u16;
        s.rx_len -= n as u16;
        s.slots[si].fill += n as u32;
        if s.slots[si].fill >= sl.len {
            s.slots[si].state = SL_READY;
            s.wslot = NONE;
            let r = &mut s.reqs[ri as usize];
            if r.created >= r.length {
                r.all_issued = 1;
                expect(s, PS_REQ_HDR, 28);
                return true;
            }
        }
    }
    true
}

/// Consume the received bytes in `rx`. Returns false while the parser waits
/// for room with bytes, or a whole header, still unconsumed.
fn parse(s: &mut NbdState) -> bool {
    loop {
        match s.pstate {
            PS_CLIENT_FLAGS | PS_OPT_HDR | PS_REQ_HDR => {
                if s.acc_len == s.acc_need {
                    let ok = match s.pstate {
                        PS_CLIENT_FLAGS => {
                            let f = be32(&s.acc, 0);
                            if f & !(CFLAG_FIXED_NEWSTYLE | CFLAG_NO_ZEROES) != 0 {
                                abort_conn(s);
                            } else {
                                s.no_zeroes = u8::from(f & CFLAG_NO_ZEROES != 0);
                                expect(s, PS_OPT_HDR, 16);
                            }
                            true
                        }
                        PS_OPT_HDR => {
                            if s.ctrl_len != 0 {
                                false
                            } else if be64(&s.acc, 0) != IHAVEOPT {
                                abort_conn(s);
                                true
                            } else {
                                s.opt = be32(&s.acc, 8);
                                s.opt_len = be32(&s.acc, 12);
                                s.opt_fill = 0;
                                s.opt_big = u8::from(s.opt_len as usize > OPT_BUF_SIZE);
                                s.pstate = PS_OPT_DATA;
                                s.acc_len = 0;
                                true
                            }
                        }
                        _ => handle_request(s),
                    };
                    if !ok {
                        return false;
                    }
                    continue;
                }
                if s.rx_len == 0 {
                    return true;
                }
                let need = (s.acc_need - s.acc_len) as usize;
                let n = need.min(s.rx_len as usize);
                let from = s.rx_off as usize;
                let at = s.acc_len as usize;
                let src = &s.rx[from..from + n];
                s.acc[at..at + n].copy_from_slice(src);
                s.acc_len += n as u8;
                s.rx_off += n as u16;
                s.rx_len -= n as u16;
            }
            PS_OPT_DATA => {
                if s.opt_fill >= s.opt_len {
                    if !handle_option(s) {
                        return false;
                    }
                    continue;
                }
                if s.rx_len == 0 {
                    return true;
                }
                let n = ((s.opt_len - s.opt_fill) as usize).min(s.rx_len as usize);
                if s.opt_big == 0 {
                    let from = s.rx_off as usize;
                    let at = s.opt_fill as usize;
                    let src = &s.rx[from..from + n];
                    s.opt_buf[at..at + n].copy_from_slice(src);
                }
                s.opt_fill += n as u32;
                s.rx_off += n as u16;
                s.rx_len -= n as u16;
            }
            PS_WRITE => {
                if !take_write_data(s) {
                    return false;
                }
                if s.rx_len == 0 && s.pstate == PS_WRITE {
                    return true;
                }
            }
            PS_DRAIN => {
                if s.drain == 0 {
                    expect(s, PS_REQ_HDR, 28);
                    continue;
                }
                if s.rx_len == 0 {
                    return true;
                }
                let n = (s.drain as usize).min(s.rx_len as usize);
                s.drain -= n as u32;
                s.rx_off += n as u16;
                s.rx_len -= n as u16;
            }
            _ => {
                s.rx_len = 0;
                return true;
            }
        }
    }
}

// ── Connection lifecycle ─────────────────────────────────────────────────

unsafe fn accept(s: &mut NbdState, id: u16) {
    s.phase = PH_HANDSHAKE;
    s.conn_id = id;
    s.gen = s.gen.wrapping_add(1);
    s.closing = 0;
    s.abort = 0;
    s.peer_gone = 0;
    s.no_zeroes = 0;
    s.tx_req = NONE;
    s.wslot = NONE;
    s.wreq = NONE;
    s.rx_len = 0;
    s.rx_off = 0;
    s.ctrl_len = 0;
    s.ctrl_off = 0;
    s.next_seq = 0;
    s.next_stamp = 0;
    s.clients = s.clients.wrapping_add(1);
    expect(s, PS_CLIENT_FLAGS, 4);
    ctrl_push(s, &NBDMAGIC.to_be_bytes());
    ctrl_push(s, &IHAVEOPT.to_be_bytes());
    ctrl_push(s, &(FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES).to_be_bytes());
    log(s, b"[nbd] client connected");
}

fn any_active(s: &NbdState) -> bool {
    let mut i = 0;
    while i < MAX_REQUESTS {
        if s.reqs[i].active != 0 {
            return true;
        }
        i += 1;
    }
    false
}

/// Finish a closing connection once nothing lent to the source is still out
/// and, on an orderly close, every admitted request has been answered.
unsafe fn teardown(s: &mut NbdState) {
    if s.phase == PH_IDLE || s.closing == 0 {
        return;
    }
    let silent = s.abort != 0 || s.peer_gone != 0;
    if silent {
        // Buffers the source does not hold are ours again at once.
        let mut i = 0;
        while i < MAX_SLOTS {
            if s.slots[i].state != SL_INFLIGHT {
                s.slots[i].state = SL_FREE;
            }
            i += 1;
        }
        if in_flight(s) != 0 {
            return;
        }
    } else if any_active(s) || s.ctrl_len != 0 || in_flight(s) != 0 {
        return;
    }
    let id = s.conn_id.to_le_bytes();
    if !net_cmd(s, NET_CMD_CLOSE, &id) {
        return;
    }
    let mut i = 0;
    while i < MAX_REQUESTS {
        s.reqs[i].active = 0;
        i += 1;
    }
    let mut i = 0;
    while i < MAX_SLOTS {
        s.slots[i].state = SL_FREE;
        i += 1;
    }
    s.phase = PH_IDLE;
    s.closing = 0;
    s.pstate = PS_STOP;
    s.rx_len = 0;
    s.ctrl_len = 0;
    s.ctrl_off = 0;
    log(s, b"[nbd] client closed");
}

/// Read transport frames and feed the connection's bytes to the parser.
unsafe fn service_net(s: &mut NbdState) {
    let mut frames = 0;
    loop {
        if s.phase != PH_IDLE && !parse(s) {
            return;
        }
        if frames >= STEP_FRAME_BUDGET {
            return;
        }
        frames += 1;
        let sys = &*s.syscalls;
        let (msg, plen, full) = net_read_frame_aligned(sys, s.net_in, s.rx.as_mut_ptr(), IN_FRAME);
        if msg == 0 {
            return;
        }
        if plen < 2 || plen != full {
            continue;
        }
        let id = u16::from_le_bytes([s.rx[3], s.rx[4]]);
        let ours = s.phase != PH_IDLE && id == s.conn_id;
        match msg {
            NET_MSG_BOUND => {
                s.bound = 1;
                log(s, b"[nbd] listening");
            }
            NET_MSG_ACCEPTED => {
                let port = if plen >= 4 {
                    u16::from_le_bytes([s.rx[5], s.rx[6]])
                } else {
                    s.port
                };
                if port != s.port {
                    continue;
                }
                if s.phase != PH_IDLE {
                    // One client at a time: the export has one writer.
                    s.refused = s.refused.wrapping_add(1);
                    net_cmd(s, NET_CMD_CLOSE, &id.to_le_bytes());
                    continue;
                }
                accept(s, id);
            }
            NET_MSG_DATA if ours => {
                s.rx_off = 5;
                s.rx_len = (plen - 2) as u16;
            }
            NET_MSG_CLOSED | NET_MSG_ERROR if ours => {
                s.peer_gone = 1;
                s.closing = 1;
                s.pstate = PS_STOP;
                s.rx_len = 0;
            }
            _ => {}
        }
    }
}

// ── Module ABI ───────────────────────────────────────────────────────────

declare_module_state_bytes!(NbdState);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<NbdState>()
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<NbdState>() {
            return -2;
        }
        core::ptr::write_bytes(state, 0, core::mem::size_of::<NbdState>());
        let s = &mut *(state as *mut NbdState);
        s.syscalls = syscalls as *const SyscallTable;
        s.blocks.bind(in_chan);
        s.net_out = out_chan;
        s.net_in = dev_channel_port(s.sys(), 0, 1);
        s.tx_req = NONE;
        s.wslot = NONE;
        s.wreq = NONE;
        s.pstate = PS_STOP;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        if in_chan < 0 || s.net_in < 0 || out_chan < 0 {
            return -22;
        }
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut NbdState);
        if s.ready != 1 {
            // Listen only once the export's size is known.
            if !learn_source(s) {
                return 0;
            }
        }
        if s.bound == 0 {
            if s.bind_wait == 0 {
                let port = s.port.to_le_bytes();
                if net_cmd(s, NET_CMD_BIND, &port) {
                    s.bind_wait = BIND_RETRY_STEPS;
                }
            } else {
                s.bind_wait -= 1;
            }
        }
        service_net(s);
        if s.phase != PH_IDLE {
            build_post_flushes(s);
            build_chunks(s);
            issue(s);
            reap(s);
            build_post_flushes(s);
            build_chunks(s);
            issue(s);
            stamp_complete(s);
            send_replies(s);
            teardown(s);
        }
        0
    }
}

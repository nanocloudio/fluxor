//! A/B graph slot store (PIC module, channel-served).
//!
//! Owns the on-flash format of the two 512 KB OTA slots
//! (`abi::contracts::storage::graph_slot::SLOT_{A,B}_OFFSET`). Each slot
//! holds a full graph bundle (module table + static config) preceded by
//! a 256-byte header. The slot with a valid magic and the higher epoch
//! is live; writes target the other slot and become live when
//! ACTIVATE increments the epoch and validates the SHA-256 recorded in
//! the header.
//!
//! ## Channel protocol
//!
//! graph_slot is a channel-served module — consumers (`ota_ingest`,
//! `reconfigure`) send FMP-framed requests on `in_chan` and read
//! FMP-framed responses on `out_chan`. There is no kernel-side
//! service registry.
//!
//! Frame format (shared with net_proto / FMP convention):
//!
//!   `[type: u32 LE][len: u16 LE][payload: len bytes]`
//!
//! Request types (FNV-1a hashes of the string names):
//!
//! | Request | Type name        | Payload layout              |
//! |---------|------------------|-----------------------------|
//! | ERASE   | `gs.erase`       | empty                       |
//! | WRITE   | `gs.write`       | `[offset:u32 LE][page:256]` |
//! | ACTIVATE| `gs.activate`    | empty                       |
//! | ACTIVE  | `gs.query_active`| empty                       |
//! | CFG     | `gs.query_cfg`   | empty                       |
//!
//! Response type `gs.result` (single FNV-1a hash). Payload:
//!
//!   `[req_type: u32 LE][value: i32 LE]` (8 bytes)
//!
//! `value` is the operation result:
//! - ERASE / WRITE / ACTIVATE: 0 on success, negative errno on failure.
//! - ACTIVE: 0 or 1 (live slot index), -1 if neither slot is live.
//! - CFG: XIP absolute address of the live slot's config blob (u32
//!   cast to i32), or -1 if neither slot is live.
//!
//! The `req_type` echo lets consumers correlate responses to requests
//! when issuing multiple commands in flight.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/sha256.rs");

// ============================================================================
// Constants
// ============================================================================

const XIP_BASE: u32 = abi::platform::rp::flash_layout::XIP_BASE;
const SLOT_A_OFFSET: u32 = abi::platform::rp::flash_layout::GRAPH_SLOT_A_OFFSET;
const SLOT_B_OFFSET: u32 = abi::platform::rp::flash_layout::GRAPH_SLOT_B_OFFSET;
const SLOT_SIZE: u32 = abi::platform::rp::flash_layout::GRAPH_SLOT_SIZE;
const SLOT_MAGIC: u32 = abi::platform::rp::flash_layout::GRAPH_SLOT_MAGIC;
const SLOT_VERSION: u8 = abi::platform::rp::flash_layout::GRAPH_SLOT_VERSION;

const SECTOR_SIZE: u32 = 4096;
const PAGE_SIZE: usize = 256;

// Raw flash bridge opcodes imported from the layered ABI.
use abi::internal::flash::{
    RAW_ERASE as SYS_FLASH_RAW_ERASE,
    RAW_PROGRAM as SYS_FLASH_RAW_PROGRAM,
};

const CONTINUE: i32 = 0;
const READY: i32 = 3;

const E_IO: i32 = -5;
const NO_LIVE_SLOT: i32 = -1;

// Channel protocol — defined once in the public contract.
use abi::contracts::storage::graph_slot::channel::{
    REQ_ERASE, REQ_WRITE, REQ_ACTIVATE, REQ_ACTIVE, REQ_CFG, RESP_RESULT,
    FRAME_HDR, REQ_MAX_PAYLOAD, RESP_PAYLOAD, RESP_FRAME_LEN,
};
/// Full request frame budget.
const REQ_FRAME_MAX: usize = FRAME_HDR + REQ_MAX_PAYLOAD;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    signaled_ready: u8,
    /// Cached live-slot index: 0 = A, 1 = B, 0xFF = neither valid.
    live_slot: u8,
    _pad: [u8; 2],
    /// Cached live-slot epoch (for inactive-slot epoch bump on activate).
    live_epoch: u64,
    /// Accumulator for partial frames read from `in_chan`.
    frame_buf: [u8; REQ_FRAME_MAX],
    frame_fill: u16,
}

// ============================================================================
// Header decoding
// ============================================================================

struct HeaderFields {
    epoch: u64,
    modules_offset: u32,
    modules_size: u32,
    config_offset: u32,
    config_size: u32,
    sha256: [u8; 32],
}

unsafe fn read_u32_le(p: *const u8) -> u32 {
    (core::ptr::read(p) as u32)
        | ((core::ptr::read(p.add(1)) as u32) << 8)
        | ((core::ptr::read(p.add(2)) as u32) << 16)
        | ((core::ptr::read(p.add(3)) as u32) << 24)
}

unsafe fn read_u64_le(p: *const u8) -> u64 {
    (read_u32_le(p) as u64) | ((read_u32_le(p.add(4)) as u64) << 32)
}

unsafe fn decode_header(base_xip: *const u8) -> Option<HeaderFields> {
    if read_u32_le(base_xip) != SLOT_MAGIC { return None; }
    if core::ptr::read(base_xip.add(4)) != SLOT_VERSION { return None; }
    let epoch = read_u64_le(base_xip.add(8));
    let modules_offset = read_u32_le(base_xip.add(16));
    let modules_size = read_u32_le(base_xip.add(20));
    let config_offset = read_u32_le(base_xip.add(24));
    let config_size = read_u32_le(base_xip.add(28));

    if (modules_offset as u64) + (modules_size as u64) > SLOT_SIZE as u64 { return None; }
    if (config_offset as u64) + (config_size as u64) > SLOT_SIZE as u64 { return None; }

    let mut sha = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        sha[i] = core::ptr::read(base_xip.add(32 + i));
        i += 1;
    }

    Some(HeaderFields {
        epoch, modules_offset, modules_size, config_offset, config_size,
        sha256: sha,
    })
}

unsafe fn refresh_live(s: &mut State) {
    let a = (XIP_BASE + SLOT_A_OFFSET) as *const u8;
    let b = (XIP_BASE + SLOT_B_OFFSET) as *const u8;
    let ha = decode_header(a);
    let hb = decode_header(b);
    match (ha, hb) {
        (Some(ha), Some(hb)) => {
            if ha.epoch >= hb.epoch {
                s.live_slot = 0; s.live_epoch = ha.epoch;
            } else {
                s.live_slot = 1; s.live_epoch = hb.epoch;
            }
        }
        (Some(ha), None) => { s.live_slot = 0; s.live_epoch = ha.epoch; }
        (None, Some(hb)) => { s.live_slot = 1; s.live_epoch = hb.epoch; }
        (None, None) => { s.live_slot = 0xFF; s.live_epoch = 0; }
    }
}

fn slot_offset(idx: u8) -> u32 {
    if idx == 0 { SLOT_A_OFFSET } else { SLOT_B_OFFSET }
}

fn inactive_slot(live: u8) -> u8 {
    if live == 1 { 0 } else { 1 }
}

// ============================================================================
// Raw flash bridge
// ============================================================================

unsafe fn sys_erase_sector(sys: &SyscallTable, offset: u32) -> i32 {
    let mut arg = offset.to_le_bytes();
    (sys.provider_call)(-1, SYS_FLASH_RAW_ERASE, arg.as_mut_ptr(), 4)
}

unsafe fn sys_program_page(sys: &SyscallTable, offset: u32, page: *const u8) -> i32 {
    let mut buf = [0u8; 4 + PAGE_SIZE];
    let p = buf.as_mut_ptr();
    let ob = offset.to_le_bytes();
    core::ptr::write_volatile(p.add(0), ob[0]);
    core::ptr::write_volatile(p.add(1), ob[1]);
    core::ptr::write_volatile(p.add(2), ob[2]);
    core::ptr::write_volatile(p.add(3), ob[3]);
    let mut i = 0usize;
    while i < PAGE_SIZE {
        core::ptr::write_volatile(p.add(4 + i), *page.add(i));
        i += 1;
    }
    (sys.provider_call)(-1, SYS_FLASH_RAW_PROGRAM, buf.as_mut_ptr(), 4 + PAGE_SIZE)
}

// ============================================================================
// Operation handlers — synchronous within a step; each produces an i32
// result that gets echoed back on the response channel.
// ============================================================================

unsafe fn do_erase(s: &mut State, sys: &SyscallTable) -> i32 {
    refresh_live(s);
    let target = slot_offset(inactive_slot(s.live_slot));
    let mut off = target;
    let end = target + SLOT_SIZE;
    while off < end {
        let rc = sys_erase_sector(sys, off);
        if rc < 0 { return rc; }
        off += SECTOR_SIZE;
    }
    0
}

unsafe fn do_write(s: &mut State, sys: &SyscallTable, payload: *const u8, payload_len: usize) -> i32 {
    if payload.is_null() || payload_len < 4 + PAGE_SIZE { return E_INVAL; }
    refresh_live(s);
    let in_slot_off = read_u32_le(payload);
    if in_slot_off + PAGE_SIZE as u32 > SLOT_SIZE { return E_INVAL; }
    let target = slot_offset(inactive_slot(s.live_slot)) + in_slot_off;
    sys_program_page(sys, target, payload.add(4))
}

unsafe fn do_activate(s: &mut State) -> i32 {
    refresh_live(s);
    let candidate = inactive_slot(s.live_slot);
    let base_xip = (XIP_BASE + slot_offset(candidate)) as *const u8;
    let hdr = match decode_header(base_xip) {
        Some(h) => h,
        None => return E_IO,
    };
    let have_live = s.live_slot <= 1;
    if have_live && hdr.epoch <= s.live_epoch {
        return E_AGAIN;
    }

    let mut hasher = Sha256::new();
    hash_xip_range(&mut hasher, base_xip, hdr.modules_offset, hdr.modules_size);
    hash_xip_range(&mut hasher, base_xip, hdr.config_offset, hdr.config_size);
    let out = hasher.finalize();
    if !ct_eq32(&out, &hdr.sha256) {
        return E_IO;
    }

    s.live_slot = candidate;
    s.live_epoch = hdr.epoch;
    0
}

unsafe fn query_active(s: &mut State) -> i32 {
    refresh_live(s);
    if s.live_slot > 1 { NO_LIVE_SLOT } else { s.live_slot as i32 }
}

unsafe fn query_cfg(s: &mut State) -> i32 {
    refresh_live(s);
    if s.live_slot > 1 { return NO_LIVE_SLOT; }
    let base = XIP_BASE + slot_offset(s.live_slot);
    match decode_header(base as *const u8) {
        Some(h) => (base + h.config_offset) as i32,
        None => NO_LIVE_SLOT,
    }
}

fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < 32 {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

unsafe fn hash_xip_range(hasher: &mut Sha256, base: *const u8, off: u32, size: u32) {
    const CHUNK: usize = 1024;
    let mut buf = [0u8; CHUNK];
    let mut remaining = size as usize;
    let mut cursor = off as usize;
    while remaining > 0 {
        let n = core::cmp::min(remaining, CHUNK);
        let mut i = 0;
        while i < n {
            core::ptr::write_volatile(buf.as_mut_ptr().add(i), core::ptr::read(base.add(cursor + i)));
            i += 1;
        }
        hasher.update(&buf[..n]);
        cursor += n;
        remaining -= n;
    }
}

// ============================================================================
// Request framing — accumulates bytes on `in_chan` into `frame_buf`
// until one full request is available, dispatches it, emits a response
// on `out_chan`, and consumes the frame from the accumulator.
// ============================================================================

fn write_u32_le(dst: &mut [u8], offset: usize, value: u32) {
    let b = value.to_le_bytes();
    dst[offset]     = b[0];
    dst[offset + 1] = b[1];
    dst[offset + 2] = b[2];
    dst[offset + 3] = b[3];
}

fn write_u16_le(dst: &mut [u8], offset: usize, value: u16) {
    let b = value.to_le_bytes();
    dst[offset]     = b[0];
    dst[offset + 1] = b[1];
}

unsafe fn emit_response(s: &State, sys: &SyscallTable, req_type: u32, value: i32) {
    if s.out_chan < 0 { return; }
    let mut frame = [0u8; RESP_FRAME_LEN];
    write_u32_le(&mut frame, 0, RESP_RESULT);
    write_u16_le(&mut frame, 4, RESP_PAYLOAD as u16);
    write_u32_le(&mut frame, FRAME_HDR, req_type);
    write_u32_le(&mut frame, FRAME_HDR + 4, value as u32);
    let _ = (sys.channel_write)(s.out_chan, frame.as_ptr(), RESP_FRAME_LEN);
}

unsafe fn pump_requests(s: &mut State, sys: &SyscallTable) -> i32 {
    if s.in_chan < 0 { return CONTINUE; }

    // Best-effort fill of the request buffer.
    let room = REQ_FRAME_MAX - s.frame_fill as usize;
    if room > 0 {
        let tail = s.frame_buf.as_mut_ptr().add(s.frame_fill as usize);
        let n = (sys.channel_read)(s.in_chan, tail, room);
        if n > 0 {
            s.frame_fill += n as u16;
        }
    }

    // Process as many complete frames as we have.
    loop {
        if (s.frame_fill as usize) < FRAME_HDR { return CONTINUE; }
        let ty = read_u32_le(s.frame_buf.as_ptr());
        let len = u16::from_le_bytes([
            s.frame_buf[4], s.frame_buf[5],
        ]) as usize;
        let total = FRAME_HDR + len;
        if total > REQ_FRAME_MAX {
            // Malformed frame — drop the buffer and resync on next fill.
            s.frame_fill = 0;
            return CONTINUE;
        }
        if (s.frame_fill as usize) < total { return CONTINUE; }

        let payload_ptr = s.frame_buf.as_ptr().add(FRAME_HDR);
        let rc = match ty {
            REQ_ERASE    => do_erase(s, sys),
            REQ_WRITE    => do_write(s, sys, payload_ptr, len),
            REQ_ACTIVATE => do_activate(s),
            REQ_ACTIVE   => query_active(s),
            REQ_CFG      => query_cfg(s),
            _            => E_INVAL,
        };
        emit_response(s, sys, ty, rc);

        // Shift tail down to reclaim the consumed frame.
        let leftover = s.frame_fill as usize - total;
        if leftover > 0 {
            core::ptr::copy(
                s.frame_buf.as_ptr().add(total),
                s.frame_buf.as_mut_ptr(),
                leftover,
            );
        }
        s.frame_fill = leftover as u16;
    }
}

// ============================================================================
// Module entry points
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<State>() { return -2; }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.signaled_ready = 0;
        s.live_slot = 0xFF;
        s.live_epoch = 0;
        s._pad = [0; 2];
        s.frame_fill = 0;
        refresh_live(s);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() { return -1; }
        let sys = &*s.syscalls;

        if s.signaled_ready == 0 {
            s.signaled_ready = 1;
            return READY;
        }
        pump_requests(s, sys)
    }
}

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> i32 { 1 }

// ============================================================================
// Panic handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");

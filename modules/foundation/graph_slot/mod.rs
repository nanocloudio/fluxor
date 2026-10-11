//! A/B graph slot store (PIC module, channel-served).
//!
//! Owns the on-flash format of the two 512 KB OTA slots
//! (`abi::contracts::storage::graph_slot::SLOT_{A,B}_OFFSET`). Each slot
//! holds a full graph bundle (module table + static config) preceded by
//! a 256-byte header. The slot with a valid magic and the higher epoch
//! is the one the next boot selects.
//!
//! ## The running slot is never written
//!
//! Module code runs in place from flash on RP, so the slot the kernel
//! booted from is being fetched from for as long as the graph runs, and a
//! rebuild re-instantiates the graph from that same slot. This module
//! finds it from the address of its own code and never erases or
//! programs it: every ERASE and WRITE targets the other slot, however the
//! epochs stand. A second OTA before a reboot replaces the pending slot;
//! it cannot reach the running one.
//!
//! ## A slot is valid only once activated
//!
//! The header page — offset 0, which carries the magic and the epoch the
//! boot selector reads — is held in RAM when it is written, not
//! programmed. ACTIVATE checks it (epoch above the running slot's, ABI
//! pin, SHA-256 over the bytes already in flash) and only then programs
//! it. So a slot that was erased, half-written, or failed its digest has
//! no magic, and the boot selector cannot pick it.
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
//! - ACTIVE: the slot the next boot selects, 0 or 1, or -1 if neither slot
//!   is valid.
//! - CFG: XIP absolute address of the config blob of the slot the kernel
//!   is running (u32 cast to i32), or -1 if it did not boot from a slot.
//!   The address is readable until the next reset: that slot is never
//!   erased or programmed while it runs (see above). A consumer may hold
//!   it across an ACTIVATE and a rebuild; after a reset it asks again.
//!
//! The `req_type` echo lets consumers correlate responses to requests
//! when issuing multiple commands in flight.

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
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/crypto/sha256.rs");

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
    RAW_ERASE as SYS_FLASH_RAW_ERASE, RAW_PROGRAM as SYS_FLASH_RAW_PROGRAM,
};

const CONTINUE: i32 = 0;
const READY: i32 = 3;

const NO_LIVE_SLOT: i32 = -1;

// Channel protocol — defined once in the public contract.
use abi::contracts::storage::graph_slot::channel::{
    FRAME_HDR, REQ_ACTIVATE, REQ_ACTIVE, REQ_CFG, REQ_ERASE, REQ_MAX_PAYLOAD, REQ_WRITE,
    RESP_FRAME_LEN, RESP_PAYLOAD, RESP_RESULT,
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
    /// This build's ABI-surface digest, computed once at `module_new` —
    /// live-slot selection and activation both gate on it.
    own_digest: [u8; 32],
    /// The slot this module's own code runs from — the slot the kernel
    /// booted — or 0xFF when it did not boot from a slot.
    running_slot: u8,
    /// Whether `header` holds a written header page awaiting ACTIVATE.
    header_held: u8,
    /// The slot the last successful ACTIVATE made live, or 0xFF. A repeat
    /// ACTIVATE answers by it; ERASE clears it.
    activated: u8,
    /// The pending slot's header page, programmed by ACTIVATE.
    header: [u8; PAGE_SIZE],
    /// An ERASE in progress: the next sector's flash offset and the end of
    /// the slot. `erase_end == 0` when none is.
    erase_next: u32,
    erase_end: u32,
    /// An ACTIVATE in progress: which range is being hashed (`ACT_*`), the
    /// slot, where the next window starts in it, how much of the range is
    /// left, and the digest so far.
    act_phase: u8,
    act_slot: u8,
    act_cursor: u32,
    act_remaining: u32,
    act_hasher: Sha256,
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
    if read_u32_le(base_xip) != SLOT_MAGIC {
        return None;
    }
    if core::ptr::read(base_xip.add(4)) != SLOT_VERSION {
        return None;
    }
    let epoch = read_u64_le(base_xip.add(8));
    let modules_offset = read_u32_le(base_xip.add(16));
    let modules_size = read_u32_le(base_xip.add(20));
    let config_offset = read_u32_le(base_xip.add(24));
    let config_size = read_u32_le(base_xip.add(28));

    if (modules_offset as u64) + (modules_size as u64) > SLOT_SIZE as u64 {
        return None;
    }
    if (config_offset as u64) + (config_size as u64) > SLOT_SIZE as u64 {
        return None;
    }

    let mut sha = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        sha[i] = core::ptr::read(base_xip.add(32 + i));
        i += 1;
    }

    Some(HeaderFields {
        epoch,
        modules_offset,
        modules_size,
        config_offset,
        config_size,
        sha256: sha,
    })
}

unsafe fn refresh_live(s: &mut State) {
    let a = (XIP_BASE + SLOT_A_OFFSET) as *const u8;
    let b = (XIP_BASE + SLOT_B_OFFSET) as *const u8;
    // Pin admission mirrors the kernel's boot selector exactly: a slot the
    // kernel would reject at reboot must never be reported live (or have
    // its config served) here either — an incompatible higher-epoch slot
    // left behind by an older writer is invisible, not authoritative.
    let ha = decode_header(a).filter(|_| slot_pin_admits(a, &s.own_digest));
    let hb = decode_header(b).filter(|_| slot_pin_admits(b, &s.own_digest));
    match (ha, hb) {
        (Some(ha), Some(hb)) => {
            if ha.epoch >= hb.epoch {
                s.live_slot = 0;
                s.live_epoch = ha.epoch;
            } else {
                s.live_slot = 1;
                s.live_epoch = hb.epoch;
            }
        }
        (Some(ha), None) => {
            s.live_slot = 0;
            s.live_epoch = ha.epoch;
        }
        (None, Some(hb)) => {
            s.live_slot = 1;
            s.live_epoch = hb.epoch;
        }
        (None, None) => {
            s.live_slot = 0xFF;
            s.live_epoch = 0;
        }
    }
}

fn slot_offset(idx: u8) -> u32 {
    if idx == 0 {
        SLOT_A_OFFSET
    } else {
        SLOT_B_OFFSET
    }
}

fn inactive_slot(live: u8) -> u8 {
    if live == 1 {
        0
    } else {
        1
    }
}

/// Where this module's code is executing. Read from the program counter: a
/// function pointer taken in position-independent code is its link-time
/// offset, not where the loader placed it, so it never falls in a slot.
#[inline(never)]
fn own_code_address() -> u32 {
    #[cfg(target_arch = "arm")]
    {
        let pc: u32;
        // SAFETY: reads the program counter into a register; no memory,
        // stack or flags are touched.
        unsafe {
            core::arch::asm!("mov {0}, pc", out(reg) pc, options(nomem, nostack, preserves_flags))
        };
        pc
    }
    #[cfg(not(target_arch = "arm"))]
    {
        module_step as usize as u32
    }
}

/// The slot whose aperture holds this module's code, if any.
fn slot_of_own_code() -> u8 {
    let at = own_code_address();
    let in_slot = |offset: u32| {
        let base = XIP_BASE + offset;
        at >= base && at < base + SLOT_SIZE
    };
    if in_slot(SLOT_A_OFFSET) {
        0
    } else if in_slot(SLOT_B_OFFSET) {
        1
    } else {
        0xFF
    }
}

/// The slot ERASE, WRITE and ACTIVATE act on: never the running one.
unsafe fn pending_slot(s: &mut State) -> u8 {
    if s.running_slot <= 1 {
        return inactive_slot(s.running_slot);
    }
    refresh_live(s);
    inactive_slot(s.live_slot)
}

/// The epoch a pending slot must exceed: the running slot's, or with no
/// running slot, the other slot's if it is admissible.
unsafe fn epoch_to_beat(s: &State, pending: u8) -> Option<u64> {
    let other = inactive_slot(pending);
    let base = (XIP_BASE + slot_offset(other)) as *const u8;
    decode_header(base)
        .filter(|_| slot_pin_admits(base, &s.own_digest))
        .map(|h| h.epoch)
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

/// ERASE taken and under way; answered when the last sector is done.
const ERASE_UNDER_WAY: i32 = 1;
/// Blank sectors checked per step before one that needs erasing. Reading a
/// sector back through XIP costs a few hundred microseconds uncached, so a
/// step reads two at most.
const BLANK_CHECKS_PER_STEP: u32 = 2;

/// Start erasing the pending slot. A whole slot is 128 sectors, and a sector
/// that holds data takes the flash tens of milliseconds -- with the chip
/// stalled, since XIP is detached -- so the slot is erased a sector a step
/// (`erase_step`), and the ERASE is answered once it is all blank.
unsafe fn do_erase(s: &mut State, _sys: &SyscallTable) -> i32 {
    s.header_held = 0;
    s.activated = 0xFF;
    let target = slot_offset(pending_slot(s));
    s.erase_next = target;
    s.erase_end = target + SLOT_SIZE;
    ERASE_UNDER_WAY
}

/// Whether the sector at flash offset `off` already reads as erased.
unsafe fn sector_blank(off: u32) -> bool {
    let base = (XIP_BASE + off) as *const u32;
    let mut i = 0usize;
    while i < SECTOR_SIZE as usize / 4 {
        if core::ptr::read_volatile(base.add(i)) != u32::MAX {
            return false;
        }
        i += 1;
    }
    true
}

/// One step of an erase under way: skip sectors already blank, erase at most
/// one that is not, and answer the ERASE when the slot is done. Answers
/// whether the erase is still under way.
unsafe fn erase_step(s: &mut State, sys: &SyscallTable) -> bool {
    let mut checked = 0;
    while s.erase_next < s.erase_end && checked < BLANK_CHECKS_PER_STEP {
        let off = s.erase_next;
        if !sector_blank(off) {
            let rc = sys_erase_sector(sys, off);
            if rc < 0 {
                s.erase_end = 0;
                emit_response(s, sys, REQ_ERASE, rc);
                return false;
            }
            s.erase_next += SECTOR_SIZE;
            return true;
        }
        s.erase_next += SECTOR_SIZE;
        checked += 1;
    }
    if s.erase_next < s.erase_end {
        return true;
    }
    s.erase_end = 0;
    emit_response(s, sys, REQ_ERASE, 0);
    false
}

unsafe fn do_write(
    s: &mut State,
    sys: &SyscallTable,
    payload: *const u8,
    payload_len: usize,
) -> i32 {
    if payload.is_null() || payload_len < 4 + PAGE_SIZE {
        return E_INVAL;
    }
    let in_slot_off = read_u32_le(payload);
    if in_slot_off + PAGE_SIZE as u32 > SLOT_SIZE {
        return E_INVAL;
    }
    if in_slot_off == 0 {
        // The header page is programmed by ACTIVATE, once it checks out.
        core::ptr::copy_nonoverlapping(payload.add(4), s.header.as_mut_ptr(), PAGE_SIZE);
        s.header_held = 1;
        return 0;
    }
    let target = slot_offset(pending_slot(s)) + in_slot_off;
    sys_program_page(sys, target, payload.add(4))
}

/// This build's ABI-surface digest — sha256 of the canonical
/// `abi::abi_surface` stream. The module and the kernel it ships with are
/// built from the same tree, so this equals the kernel's own digest (the
/// lockstep is enforced by `tests/harness/tests/abi_surface_digest.rs`).
fn own_abi_surface_digest() -> [u8; 32] {
    let mut hasher = Sha256::new();
    abi::abi_surface::write_surface(&mut |bytes| hasher.update(bytes));
    hasher.finalize()
}

/// Slot ABI pin admission (mirror of the kernel selector's rule):
/// strict equality with this build's surface digest, no exemption for
/// slots built against another surface — an unprovable slot is rejected
/// like a corrupt one.
unsafe fn slot_pin_admits(base_xip: *const u8, own: &[u8; 32]) -> bool {
    let mut pin = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        pin[i] = core::ptr::read(
            base_xip.add(abi::platform::rp::flash_layout::GRAPH_SLOT_ABI_SURFACE_OFFSET + i),
        );
        i += 1;
    }
    ct_eq32(&pin, own)
}

unsafe fn do_activate(s: &mut State, _sys: &SyscallTable) -> i32 {
    if s.header_held == 0 {
        // Nothing pending: a repeat of an ACTIVATE that already succeeded
        // (`ota_ingest` and then `reconfigure` both send one) answers as it
        // did while that slot is still the one the next boot selects, and
        // anything else has nothing to activate.
        refresh_live(s);
        return if s.activated <= 1 && s.live_slot == s.activated {
            0
        } else {
            E_IO
        };
    }
    let candidate = pending_slot(s);
    let header = s.header.as_ptr();
    let hdr = match decode_header(header) {
        Some(h) => h,
        None => return E_IO,
    };
    // The digest covers what follows the header page, which is all in
    // flash by now; ranges that reach into the page cannot be checked.
    if hdr.modules_offset < PAGE_SIZE as u32 || hdr.config_offset < PAGE_SIZE as u32 {
        return E_INVAL;
    }
    if epoch_to_beat(s, candidate).is_some_and(|epoch| hdr.epoch <= epoch) {
        return E_AGAIN;
    }

    // Refuse to activate a slot the kernel's boot selector would reject:
    // reporting success here and then losing the graph at the next reboot
    // is the worst outcome — fail the activation now, with the old slot
    // still live.
    if !slot_pin_admits(header, &s.own_digest) {
        return E_INVAL;
    }

    // The digest is over up to a whole slot, read back through XIP: far
    // more than one step, so it is taken a window a step (`activate_step`)
    // and the ACTIVATE is answered once it is done.
    s.act_hasher = Sha256::new();
    s.act_slot = candidate;
    s.act_phase = ACT_MODULES;
    s.act_cursor = hdr.modules_offset;
    s.act_remaining = hdr.modules_size;
    ACTIVATE_UNDER_WAY
}

/// ACTIVATE taken and its digest under way; answered when it is decided.
const ACTIVATE_UNDER_WAY: i32 = 1;
const ACT_IDLE: u8 = 0;
const ACT_MODULES: u8 = 1;
const ACT_CONFIG: u8 = 2;
/// Bytes of the slot hashed per step.
const ACT_WINDOW: u32 = 4096;

/// One step of an ACTIVATE under way: hash the next window, and once the
/// whole image is hashed, decide. Answers whether it is still under way.
unsafe fn activate_step(s: &mut State, sys: &SyscallTable) -> bool {
    let base_xip = (XIP_BASE + slot_offset(s.act_slot)) as *const u8;
    if s.act_remaining > 0 {
        let n = core::cmp::min(s.act_remaining, ACT_WINDOW);
        let mut hasher = s.act_hasher.clone();
        hash_xip_range(&mut hasher, base_xip, s.act_cursor, n);
        s.act_hasher = hasher;
        s.act_cursor += n;
        s.act_remaining -= n;
        return true;
    }
    let Some(hdr) = decode_header(s.header.as_ptr()) else {
        s.act_phase = ACT_IDLE;
        emit_response(s, sys, REQ_ACTIVATE, E_IO);
        return false;
    };
    if s.act_phase == ACT_MODULES {
        s.act_phase = ACT_CONFIG;
        s.act_cursor = hdr.config_offset;
        s.act_remaining = hdr.config_size;
        return true;
    }
    s.act_phase = ACT_IDLE;
    let rc = activate_finish(s, sys, &hdr);
    emit_response(s, sys, REQ_ACTIVATE, rc);
    false
}

/// The image is hashed: compare, and program the header if it matches.
unsafe fn activate_finish(s: &mut State, sys: &SyscallTable, hdr: &HeaderFields) -> i32 {
    let out = s.act_hasher.clone().finalize();
    if !ct_eq32(&out, &hdr.sha256) {
        return E_IO;
    }
    let candidate = s.act_slot;
    let header = s.header.as_ptr();

    let rc = sys_program_page(sys, slot_offset(candidate), header);
    if rc < 0 {
        return rc;
    }
    s.header_held = 0;
    refresh_live(s);
    if s.live_slot != candidate {
        return E_IO;
    }
    s.activated = candidate;
    let mut line = Line::new();
    line.put(b"[graph_slot] activated slot=");
    line.slot(candidate);
    line.put(b" epoch=");
    line.num(hdr.epoch);
    line.emit(sys);
    0
}

/// One log line, built without formatting machinery: a loaded module links
/// none.
struct Line {
    buf: [u8; 64],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Self {
            buf: [0; 64],
            len: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) {
        let mut i = 0;
        while i < bytes.len() && self.len < self.buf.len() {
            self.buf[self.len] = bytes[i];
            self.len += 1;
            i += 1;
        }
    }

    fn num(&mut self, mut v: u64) {
        let mut digits = [0u8; 20];
        let mut n = 0;
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 || n == digits.len() {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            self.put(&[digits[n]]);
        }
    }

    /// A slot index as the boot selector names it, or `none`.
    fn slot(&mut self, slot: u8) {
        match slot {
            0 => self.put(b"A"),
            1 => self.put(b"B"),
            _ => self.put(b"none"),
        }
    }

    unsafe fn emit(&self, sys: &SyscallTable) {
        dev_log(sys, 3, self.buf.as_ptr(), self.len);
    }
}

unsafe fn query_active(s: &mut State) -> i32 {
    refresh_live(s);
    if s.live_slot > 1 {
        NO_LIVE_SLOT
    } else {
        s.live_slot as i32
    }
}

unsafe fn query_cfg(s: &mut State) -> i32 {
    if s.running_slot > 1 {
        return NO_LIVE_SLOT;
    }
    let base = XIP_BASE + slot_offset(s.running_slot);
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
            core::ptr::write_volatile(
                buf.as_mut_ptr().add(i),
                core::ptr::read(base.add(cursor + i)),
            );
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
    dst[offset] = b[0];
    dst[offset + 1] = b[1];
    dst[offset + 2] = b[2];
    dst[offset + 3] = b[3];
}

fn write_u16_le(dst: &mut [u8], offset: usize, value: u16) {
    let b = value.to_le_bytes();
    dst[offset] = b[0];
    dst[offset + 1] = b[1];
}

unsafe fn emit_response(s: &State, sys: &SyscallTable, req_type: u32, value: i32) {
    if s.out_chan < 0 {
        return;
    }
    let mut frame = [0u8; RESP_FRAME_LEN];
    write_u32_le(&mut frame, 0, RESP_RESULT);
    write_u16_le(&mut frame, 4, RESP_PAYLOAD as u16);
    write_u32_le(&mut frame, FRAME_HDR, req_type);
    write_u32_le(&mut frame, FRAME_HDR + 4, value as u32);
    let _ = (sys.channel_write)(s.out_chan, frame.as_ptr(), RESP_FRAME_LEN);
}

unsafe fn pump_requests(s: &mut State, sys: &SyscallTable) -> i32 {
    if s.in_chan < 0 {
        return CONTINUE;
    }
    // No request is taken while an erase is under way: the next one is
    // about the slot being erased.
    if s.erase_end != 0 && erase_step(s, sys) {
        return CONTINUE;
    }
    if s.act_phase != ACT_IDLE && activate_step(s, sys) {
        return CONTINUE;
    }

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
        if (s.frame_fill as usize) < FRAME_HDR {
            return CONTINUE;
        }
        let ty = read_u32_le(s.frame_buf.as_ptr());
        let len = u16::from_le_bytes([s.frame_buf[4], s.frame_buf[5]]) as usize;
        let total = FRAME_HDR + len;
        if total > REQ_FRAME_MAX {
            // Malformed frame — drop the buffer and resync on next fill.
            s.frame_fill = 0;
            return CONTINUE;
        }
        if (s.frame_fill as usize) < total {
            return CONTINUE;
        }

        let payload_ptr = s.frame_buf.as_ptr().add(FRAME_HDR);
        let rc = match ty {
            REQ_ERASE => do_erase(s, sys),
            REQ_WRITE => do_write(s, sys, payload_ptr, len),
            REQ_ACTIVATE => do_activate(s, sys),
            REQ_ACTIVE => query_active(s),
            REQ_CFG => query_cfg(s),
            _ => E_INVAL,
        };
        let under_way = (ty == REQ_ERASE && rc == ERASE_UNDER_WAY)
            || (ty == REQ_ACTIVATE && rc == ACTIVATE_UNDER_WAY);
        if !under_way {
            emit_response(s, sys, ty, rc);
        }

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
        if under_way {
            return CONTINUE;
        }
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

// Same figure as data, so `pack` records it in the manifest and a graph's
// state-arena demand is summable host-side.
declare_module_state_bytes!(State);

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
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.signaled_ready = 0;
        s.live_slot = 0xFF;
        s.live_epoch = 0;
        s._pad = [0; 2];
        s.frame_fill = 0;
        s.own_digest = own_abi_surface_digest();
        s.running_slot = slot_of_own_code();
        s.header_held = 0;
        s.activated = 0xFF;
        s.erase_next = 0;
        s.erase_end = 0;
        s.act_phase = ACT_IDLE;
        s.act_slot = 0;
        s.act_cursor = 0;
        s.act_remaining = 0;
        core::ptr::write(&mut s.act_hasher, Sha256::new());
        refresh_live(s);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return -1;
        }
        let sys = &*s.syscalls;

        if s.signaled_ready == 0 {
            s.signaled_ready = 1;
            // Which slot this graph runs from, and which the next boot
            // selects: the two an OTA moves apart and a reset brings
            // together again.
            refresh_live(s);
            let mut line = Line::new();
            line.put(b"[graph_slot] running=");
            line.slot(s.running_slot);
            line.put(b" next=");
            line.slot(s.live_slot);
            line.emit(sys);
            return READY;
        }
        pump_requests(s, sys)
    }
}

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> i32 {
    1
}

// ============================================================================
// Panic handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");

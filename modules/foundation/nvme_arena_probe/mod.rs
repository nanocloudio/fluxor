//! NVMe arena probe — end-to-end test for paged arenas with a
//! driver-backed external provider (`BackingType::External`).
//!
//! Registers a small arena (backing_type=External), writes a
//! deterministic pattern into each virtual page, flushes, reads the
//! pages back, and compares. Reports progress + pass/fail via the
//! heartbeat log line.
//!
//! Must be wired downstream of the `nvme` module in the graph so that
//! `backing_provider_dispatch` is registered before our first `_WRITE`
//! call. Exports `module_deferred_ready` so the scheduler gates our
//! first step until `nvme` has returned Ready.
//!
//! **Params:**
//!   pages   (u16, tag 1): virtual pages to allocate (default 16)
//!   seed    (u16, tag 2): u32 pattern seed — each vpage writes
//!                         `(seed as u32) ^ (vpage_idx * 0x0101_0101)`
//!                         repeated across 1024 words of the page.
//!                         (default 0xA55A)
//!
//! **Acceptance:** heartbeat emits
//!   `[nap] state=done pass=1 pages=NN verify_ok=NN lba=0xXXXXXXXX`
//! when everything matches. `pass=0` or `verify_ok < pages` means a
//! mismatch — the pattern is deterministic so Linux can reproduce it
//! post-reboot by `dd`ing the same LBA range.

#![no_std]

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

const PAGE_BYTES: usize = 4096;
const PAGE_WORDS: usize = PAGE_BYTES / 4;

const BACKING_EXTERNAL: u8 = 2;
const WB_DEFERRED:  u8 = 0;

/// Arena LBA base the kernel carves for the FIRST NVMe-backed arena.
/// Mirrors `NVME_ARENA_LBA_BASE` in `src/platform/bcm2712/memory.rs`. We
/// surface it in the success line so Linux verification (`dd
/// if=/dev/nvme0n1 skip=... count=...`) has a clear target.
const NVME_ARENA_LBA_BASE: u64 = 0x0020_0000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const ST_INIT:   u8 = 0;
const ST_WRITE:  u8 = 1;
const ST_FLUSH:  u8 = 2;
const ST_VERIFY: u8 = 3;
const ST_DONE:   u8 = 4;
const ST_ERR:    u8 = 0xFF;

#[repr(C)]
struct NapState {
    syscalls: *const SyscallTable,

    pages: u16,
    seed:  u16,

    state: u8,
    pass:  u8,
    arena_id: u8,
    _pad0: u8,

    /// Current vpage being written or verified.
    cursor:     u16,
    /// Count of pages that came back byte-equal to what we wrote.
    verify_ok:  u16,
    /// Last errno from a failed kernel call (0 = none).
    err:        i32,

    /// Tick counter for heartbeat cadence.
    step_count: u32,

    /// 4 KB page-sized scratch buffer. Written out for each vpage on
    /// the write pass, then compared against the read-back on the
    /// verify pass. Aligned with `align(64)` to avoid straddling
    /// cache lines inside the state arena.
    scratch: [u32; PAGE_WORDS],
}

mod params_def {
    use super::NapState;
    use super::{p_u16};
    use super::SCHEMA_MAX;

    define_params! {
        NapState;
        1, pages, u16, 16
            => |s, d, len| { s.pages = p_u16(d, len, 0, 16); };
        2, seed,  u16, 0xA55A
            => |s, d, len| { s.seed = p_u16(d, len, 0, 0xA55A); };
    }
}

#[inline(always)]
fn pattern_word(seed: u32, vpage: u16, word_idx: u32) -> u32 {
    // seed mixes with vpage so adjacent pages look different;
    // word_idx slot provides intra-page variation so a 4 KB offset
    // bug doesn't masquerade as success.
    let vp = (vpage as u32).wrapping_mul(0x0101_0101);
    seed ^ vp ^ word_idx
}

/// Fill `scratch` with the deterministic pattern for `vpage`.
unsafe fn fill_page(s: &mut NapState, vpage: u16) {
    let seed = s.seed as u32;
    let mut i = 0usize;
    while i < PAGE_WORDS {
        s.scratch[i] = pattern_word(seed, vpage, i as u32);
        i += 1;
    }
}

/// Compare `scratch` (which was just read from the arena) against the
/// expected pattern for `vpage`. Returns true iff all 1024 words match.
unsafe fn compare_page(s: &NapState, vpage: u16) -> bool {
    let seed = s.seed as u32;
    let mut i = 0usize;
    while i < PAGE_WORDS {
        if s.scratch[i] != pattern_word(seed, vpage, i as u32) {
            return false;
        }
        i += 1;
    }
    true
}

// ---------------------------------------------------------------------------
// Heartbeat — primary observability. Re-emits status every ~5s so the
// UDP-log viewer can capture it after log_net warms up.
// ---------------------------------------------------------------------------

fn write_hex32(out: *mut u8, pos: &mut usize, v: u32) {
    for i in 0..8 {
        let n = ((v >> (28 - i * 4)) & 0xF) as u8;
        let c = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
        unsafe { *out.add(*pos) = c; }
        *pos += 1;
    }
}

fn write_dec(out: *mut u8, pos: &mut usize, mut v: u32) {
    if v == 0 {
        unsafe { *out.add(*pos) = b'0'; }
        *pos += 1;
        return;
    }
    let mut d = [0u8; 10];
    let mut n = 0usize;
    while v > 0 { d[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n > 0 {
        n -= 1;
        unsafe { *out.add(*pos) = d[n]; }
        *pos += 1;
    }
}

unsafe fn emit_heartbeat(s: &NapState) {
    let mut buf = [0u8; 96];
    let p = buf.as_mut_ptr();
    let mut pos = 0usize;

    let prefix = b"[nap] state=";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p.add(pos), prefix.len());
    pos += prefix.len();
    write_dec(p, &mut pos, s.state as u32);

    let t = b" pass=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, s.pass as u32);

    let t = b" pages=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, s.pages as u32);

    let t = b" ok=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, s.verify_ok as u32);

    let t = b" lba=0x";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_hex32(p, &mut pos, NVME_ARENA_LBA_BASE as u32);

    dev_log(&*s.syscalls, 3, p, pos);
}

// ---------------------------------------------------------------------------
// Module ABI
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<NapState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32, _out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<NapState>() { return -2; }
        let s = &mut *(state as *mut NapState);
        core::ptr::write_bytes(s as *mut NapState as *mut u8, 0, core::mem::size_of::<NapState>());
        s.syscalls = syscalls as *const SyscallTable;
        s.state = ST_INIT;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut NapState);
    let sys = &*s.syscalls;

    // Sparse heartbeat — every ~1000 steps so we don't flood log_net.
    // At tick_us=1000 that's once per second.
    s.step_count = s.step_count.wrapping_add(1);
    if s.step_count % 1000 == 0 {
        emit_heartbeat(s);
    }

    match s.state {
        ST_INIT => {
            // Register a fresh External-backed arena. Passing
            // resident_max == pages is fine; the backing store doesn't
            // actually allocate physical pages on registration — it
            // just reserves a page span. backing_provider::ready() is
            // checked at each backing_read/write call, so if the
            // driver dispatch isn't registered yet we'd get ENODEV on
            // the first write — but since we export
            // `module_deferred_ready`, the scheduler should block our
            // step until the nvme upstream is Ready.
            let rc = dev_backing_arena_register(
                sys,
                s.pages as u32,
                s.pages as u32,
                BACKING_EXTERNAL,
                WB_DEFERRED,
            );
            if rc < 0 {
                s.err = rc;
                s.state = ST_ERR;
                dev_log(sys, 1, b"[nap] register failed\0".as_ptr(), 21);
                return 0;
            }
            s.arena_id = rc as u8;
            s.cursor = 0;
            s.state = ST_WRITE;
            emit_heartbeat(s);
            0
        }
        ST_WRITE => {
            // One page per tick so the scheduler stays responsive.
            if s.cursor >= s.pages {
                s.state = ST_FLUSH;
                return 0;
            }
            fill_page(s, s.cursor);
            let rc = dev_backing_arena_write(
                sys,
                s.arena_id,
                s.cursor as u32,
                s.scratch.as_ptr() as *const u8,
            );
            if rc < 0 {
                // ENODEV means nvme hasn't registered its dispatch yet.
                // Our deferred_ready flag gates on a direct upstream edge,
                // and this yaml has none — so we poll. Every other error
                // code is terminal.
                if rc == -19 {
                    // Stay in ST_WRITE; retry next tick.
                    s.err = rc;
                    return 0;
                }
                s.err = rc;
                s.state = ST_ERR;
                dev_log(sys, 1, b"[nap] write failed\0".as_ptr(), 18);
                return 0;
            }
            s.cursor += 1;
            0
        }
        ST_FLUSH => {
            let _ = dev_backing_arena_flush(sys, s.arena_id);
            s.cursor = 0;
            s.state = ST_VERIFY;
            0
        }
        ST_VERIFY => {
            if s.cursor >= s.pages {
                s.pass = if s.verify_ok == s.pages { 1 } else { 0 };
                s.state = ST_DONE;
                emit_heartbeat(s);
                return 3; // Ready — downstream may now use us
            }
            // Clear scratch then read into it so stale-data bugs show
            // up as verify_ok mismatch instead of silently passing.
            let mut i = 0usize;
            while i < PAGE_WORDS {
                s.scratch[i] = 0;
                i += 1;
            }
            let rc = dev_backing_arena_read(
                sys,
                s.arena_id,
                s.cursor as u32,
                s.scratch.as_mut_ptr() as *mut u8,
            );
            if rc < 0 {
                s.err = rc;
                s.state = ST_ERR;
                dev_log(sys, 1, b"[nap] read failed\0".as_ptr(), 17);
                return 0;
            }
            if compare_page(s, s.cursor) {
                s.verify_ok += 1;
            }
            s.cursor += 1;
            0
        }
        ST_DONE => {
            // Steady state — re-emit status periodically so the log
            // viewer can capture it after log_net starts streaming.
            emit_heartbeat(s);
            0
        }
        _ => {
            // ST_ERR — re-emit state (err value in state field).
            emit_heartbeat(s);
            0
        }
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");

//! NVMe performance probe — exercise concurrency knobs and emit
//! per-phase throughput so the hardware rig can gate on regressions.
//!
//! Sits downstream of `nvme` as a `BackingType::External` consumer
//! (same shape as `nvme_arena_probe`), but instead of one
//! correctness pass it walks a small workload matrix:
//!
//! | Phase | Pattern               | Chunk pages | What it stresses                              |
//! |-------|-----------------------|-------------|-----------------------------------------------|
//! | 0     | Sequential write      | 32          | Single-command baseline                        |
//! | 1     | Sequential read       | 32          | Single-command baseline                        |
//! | 2     | Sequential write      | 128         | 4-slot pipeline (writes stripe across queues) |
//! | 3     | Sequential read       | 128         | 4-slot pipeline (reads stripe across queues)  |
//! | 4     | Random write (stride) | 32          | Worst-case scatter — flash-cache miss rate    |
//! | 5     | Random read (stride)  | 32          | Worst-case scatter — flash-cache miss rate    |
//!
//! Each phase emits one acceptance line:
//!
//!   `[npp] phase=N name=NAME us=ELAPSED bytes=B mbps=THROUGHPUT`
//!
//! `mbps` is rounded `bytes / us` so the rig can match a numeric
//! threshold without re-computing on the host side.
//!
//! ## Acceptance / regression gates
//!
//! The hardware fixture under `tests/hardware/cm5_nvme_perf.toml`
//! pins per-phase thresholds. The probe stays scenario-agnostic —
//! it emits raw numbers; the rig owns the policy. Today's measured
//! ceilings on the CM5 + Biwin CE430T5D100-512G ride PCIe Gen2 x1:
//!
//! - Phase 0 (seq write,  32p): ~ 390 MB/s (link cap, write stripe)
//! - Phase 1 (seq read,   32p): ~ 240 MB/s (NEON memcpy + 4-queue pipeline)
//! - Phase 2 (seq write, 128p): ~ 390 MB/s (link cap)
//! - Phase 3 (seq read,  128p): ~ 315 MB/s (NEON memcpy, near Linux fio QD=1)
//! - Phase 4 (rand write, 32p): ~ 395 MB/s (4-queue stripe)
//! - Phase 5 (rand read,  32p): ~ 220 MB/s (4-queue stripe)
//!
//! ## Parameters
//!
//!   `pages` (u16, tag 1, default 1024):
//!     Page span for sequential phases. Each phase reads or writes
//!     this many 4 KB pages = `pages × 4` KB of data.
//!   `random_iterations` (u16, tag 2, default 256):
//!     Number of random-pattern I/Os per random phase. Each I/O is
//!     `random_chunk` pages.
//!   `random_chunk` (u8, tag 3, default 32):
//!     Pages per random I/O — kept at the driver's per-command
//!     ceiling so each I/O is one device command.
//!   `seed` (u16, tag 4, default 0xC0DE):
//!     Pattern + random-LBA seed. `(seed ^ vpage ^ word_idx)` for
//!     the data pattern; `seed`-based xorshift for the random LBA
//!     sequence.
//!
//! ## Layout
//!
//! Module state holds a `BULK_PAGES`-sized scratch buffer that
//! doubles as the write source and the read destination. Pre-zeroed
//! before each read so a partial fill is visible as a verify miss
//! rather than masquerading as a hit. Verifies on the write-then-read
//! phases catch silent corruption — a probe whose `mbps` is high but
//! pattern wrong is worthless.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

const PAGE_BYTES: usize = 4096;
const PAGE_WORDS: usize = PAGE_BYTES / 4;

/// Per-syscall page count. Sized to land in the driver's
/// `pager_read_pipelined` path so the read pipeline gets exercised
/// (count > driver's MAX_BULK_PAGES). 128 × 4 KB = 512 KB scratch.
const BULK_PAGES: usize = 128;
const BULK_WORDS: usize = BULK_PAGES * PAGE_WORDS;

const BACKING_EXTERNAL: u8 = 2;
const WB_DEFERRED:  u8 = 0;

// Phase identifiers — keep in sync with the `phase=` value in
// each emitted perf line and the regex gates in the hw fixture.
const PHASE_SEQ_W32:   u8 = 0;
const PHASE_SEQ_R32:   u8 = 1;
const PHASE_SEQ_W128:  u8 = 2;
const PHASE_SEQ_R128:  u8 = 3;
const PHASE_RAND_W:    u8 = 4;
const PHASE_RAND_R:    u8 = 5;
const PHASE_DONE:      u8 = 6;
const PHASE_ERR:       u8 = 0xFF;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[repr(C)]
struct NppState {
    syscalls: *const SyscallTable,

    pages: u16,
    random_iterations: u16,
    random_chunk: u8,
    seed: u16,

    /// Current phase the probe is driving.
    phase: u8,
    /// Per-phase progress cursor: page index for sequential phases,
    /// random-I/O index for random phases.
    cursor: u32,
    /// Arena handle returned by `dev_backing_arena_register`. 0 is
    /// a legitimate kernel-assigned slot, so `registered` is the
    /// sentinel that says "this field has been populated."
    arena_id: u8,
    registered: u8,
    /// Final `mbps` from the most recent phase — heartbeat carries
    /// it so a viewer joining mid-run can see the last result.
    last_mbps: u32,
    /// Phase-start timestamp from `dev_micros`. Reset on each phase
    /// transition so per-phase windows don't bleed into each other.
    phase_start_us: u64,

    /// Per-phase elapsed time, bytes, and mbps — captured during the
    /// active run and re-emitted from PHASE_DONE so a viewer that
    /// joins after the workload completes still sees every phase.
    phase_us:    [u32; 6],
    phase_bytes: [u32; 6],
    phase_mbps:  [u32; 6],
    phase_done:  [u8; 6],

    /// 1 once the probe has verified the seq-w/seq-r round trip;
    /// a bad pass is fatal — random phases assume the device is
    /// returning what we wrote.
    seq_verify_ok: u8,
    /// Set to a non-zero errno if any syscall failed; surfaced in
    /// the heartbeat so a `pass=0` outcome carries diagnostic info.
    err: i32,

    /// Tick counter for sparse heartbeat (every ~1 s at tick_us=100).
    step_count: u32,

    /// xorshift32 state for random-LBA generation.
    rng: u32,

    /// Scratch buffer reused by every phase. Pre-zeroed before each
    /// read so verify catches partial fills.
    scratch: [u32; BULK_WORDS],
}

mod params_def {
    use super::NppState;
    use super::BULK_PAGES;
    use super::{p_u8, p_u16};
    use super::SCHEMA_MAX;

    define_params! {
        NppState;
        1, pages, u16, 1024
            => |s, d, len| { s.pages = p_u16(d, len, 0, 1024); };
        2, random_iterations, u16, 256
            => |s, d, len| { s.random_iterations = p_u16(d, len, 0, 256); };
        // Clamp at parse time so `run_rand_write`, `run_rand_read`
        // and the verify-count math in PHASE_RAND_R all see the same
        // effective value. `fill_scratch`/`verify_scratch` write into
        // the fixed-size `scratch: [u32; BULK_WORDS]`, so anything
        // above BULK_PAGES (128) would corrupt adjacent state.
        3, random_chunk, u8, 32
            => |s, d, len| {
                let raw = p_u8(d, len, 0, 32);
                let cap = BULK_PAGES as u8;
                s.random_chunk = if raw > cap { cap } else { raw };
            };
        4, seed, u16, 0xC0DE
            => |s, d, len| { s.seed = p_u16(d, len, 0, 0xC0DE); };
    }
}

// ---------------------------------------------------------------------------
// Pattern + RNG helpers
// ---------------------------------------------------------------------------

#[inline(always)]
fn pattern_word(seed: u32, vpage: u32, word_idx: u32) -> u32 {
    seed ^ vpage.wrapping_mul(0x0101_0101) ^ word_idx
}

#[inline(always)]
fn xorshift32(state: &mut u32) -> u32 {
    // Marsaglia's xorshift32 — fixed for state != 0. Caller seeds with
    // `(seed << 16) | 1` so we never start at the degenerate zero state.
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

unsafe fn fill_scratch(s: &mut NppState, vpage_base: u32, count: u32) {
    let seed = s.seed as u32;
    let total_words = count as usize * PAGE_WORDS;
    let mut i = 0usize;
    while i < total_words {
        let p = i / PAGE_WORDS;
        let w = (i % PAGE_WORDS) as u32;
        s.scratch[i] = pattern_word(seed, vpage_base + p as u32, w);
        i += 1;
    }
}

unsafe fn zero_scratch(s: &mut NppState, count: u32) {
    let total_words = count as usize * PAGE_WORDS;
    let mut i = 0usize;
    while i < total_words {
        s.scratch[i] = 0;
        i += 1;
    }
}

/// Compare scratch[0..count pages] against the expected pattern for
/// page indices `vpage_base..vpage_base+count`. Returns the number
/// of pages that matched (0..=count); the caller treats anything
/// less than `count` as a verify miss.
unsafe fn verify_scratch(s: &NppState, vpage_base: u32, count: u32) -> u32 {
    let seed = s.seed as u32;
    let mut matched = 0u32;
    let mut p = 0u32;
    while p < count {
        let mut w = 0u32;
        let mut ok = true;
        while w < PAGE_WORDS as u32 {
            let idx = (p as usize) * PAGE_WORDS + (w as usize);
            if s.scratch[idx] != pattern_word(seed, vpage_base + p, w) {
                ok = false;
                break;
            }
            w += 1;
        }
        if ok { matched += 1; }
        p += 1;
    }
    matched
}

// ---------------------------------------------------------------------------
// Log emission
// ---------------------------------------------------------------------------

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

const PHASE_NAMES: [&[u8]; 6] = [
    b"seq_w32",
    b"seq_r32",
    b"seq_w128",
    b"seq_r128",
    b"rand_w",
    b"rand_r",
];

unsafe fn emit_perf(s: &NppState, phase: u8, us: u32, bytes: u32, mbps: u32) {
    let mut buf = [0u8; 128];
    let p = buf.as_mut_ptr();
    let mut pos = 0usize;
    let prefix = b"[npp] phase=";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p.add(pos), prefix.len());
    pos += prefix.len();
    write_dec(p, &mut pos, phase as u32);

    let t = b" name=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    let name = PHASE_NAMES[phase as usize];
    core::ptr::copy_nonoverlapping(name.as_ptr(), p.add(pos), name.len());
    pos += name.len();

    let t = b" us=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, us);

    let t = b" bytes=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, bytes);

    let t = b" mbps=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, mbps);

    dev_log(&*s.syscalls, 3, p, pos);
}

/// Cache per-phase numbers + emit the perf line. The cache lets
/// `replay_perf_lines` re-emit every phase from PHASE_DONE so a
/// log viewer that attaches mid-run still captures the full table.
unsafe fn record_phase(s: &mut NppState, phase: u8, us: u32, bytes: u32, mbps: u32) {
    let i = phase as usize;
    if i < 6 {
        s.phase_us[i] = us;
        s.phase_bytes[i] = bytes;
        s.phase_mbps[i] = mbps;
        s.phase_done[i] = 1;
    }
    s.last_mbps = mbps;
    emit_perf(s, phase, us, bytes, mbps);
}

unsafe fn replay_perf_lines(s: &NppState) {
    let mut i: u8 = 0;
    while (i as usize) < 6 {
        if s.phase_done[i as usize] != 0 {
            emit_perf(
                s,
                i,
                s.phase_us[i as usize],
                s.phase_bytes[i as usize],
                s.phase_mbps[i as usize],
            );
        }
        i += 1;
    }
}

unsafe fn emit_heartbeat(s: &NppState) {
    let mut buf = [0u8; 96];
    let p = buf.as_mut_ptr();
    let mut pos = 0usize;
    let prefix = b"[npp] hb phase=";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p.add(pos), prefix.len());
    pos += prefix.len();
    write_dec(p, &mut pos, s.phase as u32);

    let t = b" cur=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, s.cursor);

    let t = b" verify_ok=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, s.seq_verify_ok as u32);

    let t = b" last_mbps=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    write_dec(p, &mut pos, s.last_mbps);

    let t = b" err=";
    core::ptr::copy_nonoverlapping(t.as_ptr(), p.add(pos), t.len());
    pos += t.len();
    let neg_err = if s.err < 0 { (-s.err) as u32 } else { 0 };
    write_dec(p, &mut pos, neg_err);

    dev_log(&*s.syscalls, 3, p, pos);
}

// ---------------------------------------------------------------------------
// Phase drivers
// ---------------------------------------------------------------------------

/// Sequential write phase. `chunk` is the per-syscall page count;
/// each syscall maps to one driver-side bulk write (potentially
/// pipelined across slots for chunk > MAX_BULK_PAGES). Returns
/// (elapsed_us, bytes_written, errno) — errno is 0 on success.
unsafe fn run_seq_write(s: &mut NppState, chunk: u32) -> (u32, u32, i32) {
    let sys = &*s.syscalls;
    let pages = s.pages as u32;
    let start = dev_micros(sys);
    let mut cursor: u32 = 0;
    while cursor < pages {
        let this_chunk = (pages - cursor).min(chunk).min(BULK_PAGES as u32);
        fill_scratch(s, cursor, this_chunk);
        let rc = dev_backing_arena_write_pages(
            sys,
            s.arena_id,
            cursor,
            this_chunk,
            s.scratch.as_ptr() as *const u8,
        );
        if rc == -11 {
            // EAGAIN — driver back-pressure; retry same chunk.
            continue;
        }
        if rc < 0 {
            return (0, 0, rc);
        }
        cursor += this_chunk;
        s.cursor = cursor;
    }
    // Flush so the timing window includes the device-cache durability
    // contract the caller would have seen in real use.
    let flush_rc = dev_backing_arena_flush(sys, s.arena_id);
    if flush_rc < 0 {
        return (0, 0, flush_rc);
    }
    let elapsed = dev_micros(sys).saturating_sub(start) as u32;
    (elapsed, pages.wrapping_mul(PAGE_BYTES as u32), 0)
}

/// Sequential read phase. Pre-zeros scratch before each chunk so a
/// partial-fill miss surfaces as a verify failure rather than a
/// silent match with stale data. Returns
/// (elapsed_us, bytes_read, errno, verified_pages).
unsafe fn run_seq_read(s: &mut NppState, chunk: u32) -> (u32, u32, i32, u32) {
    let sys = &*s.syscalls;
    let pages = s.pages as u32;
    let start = dev_micros(sys);
    let mut cursor: u32 = 0;
    let mut verified: u32 = 0;
    while cursor < pages {
        let this_chunk = (pages - cursor).min(chunk).min(BULK_PAGES as u32);
        zero_scratch(s, this_chunk);
        let rc = dev_backing_arena_read_pages(
            sys,
            s.arena_id,
            cursor,
            this_chunk,
            s.scratch.as_mut_ptr() as *mut u8,
        );
        if rc == -11 {
            continue;
        }
        if rc < 0 {
            return (0, 0, rc, verified);
        }
        verified += verify_scratch(s, cursor, this_chunk);
        cursor += this_chunk;
        s.cursor = cursor;
    }
    let elapsed = dev_micros(sys).saturating_sub(start) as u32;
    (elapsed, pages.wrapping_mul(PAGE_BYTES as u32), 0, verified)
}

/// Random-LBA write phase. `random_iterations` I/Os, each
/// `random_chunk` pages, vpage chosen via xorshift modulo
/// `pages - random_chunk`. Same fill_scratch / verify_scratch
/// shape as sequential so the random_r phase can cross-check.
///
/// `random_chunk` is parsed as a free-form u8 (0..=255); cap it at
/// `BULK_PAGES` so `fill_scratch`/`verify_scratch` never write past
/// the fixed `scratch` array.
unsafe fn run_rand_write(s: &mut NppState) -> (u32, u32, i32) {
    let sys = &*s.syscalls;
    let chunk = (s.random_chunk as u32).min(BULK_PAGES as u32);
    let iters = s.random_iterations as u32;
    let pages = s.pages as u32;
    if chunk == 0 || iters == 0 || pages < chunk {
        return (0, 0, -22);
    }
    let span = pages - chunk;
    let start = dev_micros(sys);
    let mut i: u32 = 0;
    while i < iters {
        let r = xorshift32(&mut s.rng);
        let vpage = if span == 0 { 0 } else { r % (span + 1) };
        fill_scratch(s, vpage, chunk);
        let rc = dev_backing_arena_write_pages(
            sys,
            s.arena_id,
            vpage,
            chunk,
            s.scratch.as_ptr() as *const u8,
        );
        if rc == -11 { continue; }
        if rc < 0 { return (0, 0, rc); }
        i += 1;
        s.cursor = i;
    }
    let flush_rc = dev_backing_arena_flush(sys, s.arena_id);
    if flush_rc < 0 {
        return (0, 0, flush_rc);
    }
    let elapsed = dev_micros(sys).saturating_sub(start) as u32;
    let bytes = iters.wrapping_mul(chunk).wrapping_mul(PAGE_BYTES as u32);
    (elapsed, bytes, 0)
}

unsafe fn run_rand_read(s: &mut NppState) -> (u32, u32, i32, u32) {
    let sys = &*s.syscalls;
    let chunk = (s.random_chunk as u32).min(BULK_PAGES as u32);
    let iters = s.random_iterations as u32;
    let pages = s.pages as u32;
    if chunk == 0 || iters == 0 || pages < chunk {
        return (0, 0, -22, 0);
    }
    let span = pages - chunk;
    // Re-seed the RNG with the same starting value as the write
    // phase so the random vpage sequence matches; verify can then
    // cross-check that data placed at vpage X comes back from vpage X.
    s.rng = ((s.seed as u32) << 16) | 1;
    let start = dev_micros(sys);
    let mut i: u32 = 0;
    let mut verified: u32 = 0;
    while i < iters {
        let r = xorshift32(&mut s.rng);
        let vpage = if span == 0 { 0 } else { r % (span + 1) };
        zero_scratch(s, chunk);
        let rc = dev_backing_arena_read_pages(
            sys,
            s.arena_id,
            vpage,
            chunk,
            s.scratch.as_mut_ptr() as *mut u8,
        );
        if rc == -11 { continue; }
        if rc < 0 { return (0, 0, rc, verified); }
        verified += verify_scratch(s, vpage, chunk);
        i += 1;
        s.cursor = i;
    }
    let elapsed = dev_micros(sys).saturating_sub(start) as u32;
    let bytes = iters.wrapping_mul(chunk).wrapping_mul(PAGE_BYTES as u32);
    (elapsed, bytes, 0, verified)
}

#[inline(always)]
fn mbps_from(us: u32, bytes: u32) -> u32 {
    if us == 0 { return 0; }
    // bytes / us == MB/s (since both 1e6-scaled by μs and Mega).
    // Use u64 intermediate to avoid overflow on large transfers.
    ((bytes as u64) / (us as u64)) as u32
}

// ---------------------------------------------------------------------------
// Module ABI
// ---------------------------------------------------------------------------

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<NppState>()
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32, _out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<NppState>() { return -2; }
        let s = &mut *(state as *mut NppState);
        core::ptr::write_bytes(s as *mut NppState as *mut u8, 0, core::mem::size_of::<NppState>());
        s.syscalls = syscalls as *const SyscallTable;
        s.phase = PHASE_SEQ_W32;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        // Seed the RNG from the configured seed. Avoid the zero
        // state that xorshift can't escape.
        s.rng = ((s.seed as u32) << 16) | 1;
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut NppState);
    let sys = &*s.syscalls;

    s.step_count = s.step_count.wrapping_add(1);
    if s.step_count % 1000 == 0 {
        emit_heartbeat(s);
    }

    // Module is single-shot: each step runs one phase to completion
    // (sync from the probe's POV — the driver-side pipelining keeps
    // the device busy inside the syscall). On PHASE_DONE, replay
    // every phase's perf line on a slower cadence so a log viewer
    // that attaches after the workload completes still captures
    // the full table.
    if s.phase == PHASE_DONE {
        if s.step_count % 5000 == 0 {
            replay_perf_lines(s);
        }
        return 0;
    }
    if s.phase == PHASE_ERR {
        return 0;
    }

    // Lazy arena register on first entry.
    if s.registered == 0 {
        let rc = dev_backing_arena_register(
            sys,
            s.pages as u32,
            s.pages as u32,
            BACKING_EXTERNAL,
            WB_DEFERRED,
        );
        if rc < 0 {
            // ENODEV (-19): backing provider not yet exporting the
            // dispatch — retry next tick. Anything else is fatal.
            if rc == -19 { return 0; }
            s.err = rc;
            s.phase = PHASE_ERR;
            dev_log(sys, 1, b"[npp] arena register failed\0".as_ptr(), 27);
            return 0;
        }
        s.arena_id = rc as u8;
        s.registered = 1;
        s.phase_start_us = dev_micros(sys);
        emit_heartbeat(s);
    }

    // The probe's state machine runs one phase per step invocation;
    // each phase is internally a tight loop that completes the full
    // workload before returning. Returning 2 (Burst) keeps the
    // scheduler from sleeping a tick between phases.
    let phase = s.phase;
    s.cursor = 0;
    match phase {
        PHASE_SEQ_W32 => {
            let (us, bytes, rc) = run_seq_write(s, 32);
            if rc != 0 {
                if rc == -19 { return 0; } // ENODEV — provider not ready, retry
                s.err = rc; s.phase = PHASE_ERR; return 0;
            }
            let m = mbps_from(us, bytes);
            record_phase(s, phase, us, bytes, m);
            s.phase = PHASE_SEQ_R32;
            2
        }
        PHASE_SEQ_R32 => {
            let (us, bytes, rc, verified) = run_seq_read(s, 32);
            if rc != 0 {
                if rc == -19 { return 0; }
                s.err = rc; s.phase = PHASE_ERR; return 0;
            }
            if verified != s.pages as u32 {
                s.err = -5; // EIO
                s.phase = PHASE_ERR;
                dev_log(sys, 1, b"[npp] seq_r32 verify mismatch\0".as_ptr(), 29);
                return 0;
            }
            s.seq_verify_ok = 1;
            let m = mbps_from(us, bytes);
            record_phase(s, phase, us, bytes, m);
            s.phase = PHASE_SEQ_W128;
            2
        }
        PHASE_SEQ_W128 => {
            let (us, bytes, rc) = run_seq_write(s, 128);
            if rc != 0 { s.err = rc; s.phase = PHASE_ERR; return 0; }
            let m = mbps_from(us, bytes);
            record_phase(s, phase, us, bytes, m);
            s.phase = PHASE_SEQ_R128;
            2
        }
        PHASE_SEQ_R128 => {
            let (us, bytes, rc, verified) = run_seq_read(s, 128);
            if rc != 0 { s.err = rc; s.phase = PHASE_ERR; return 0; }
            if verified != s.pages as u32 {
                s.err = -5;
                s.phase = PHASE_ERR;
                dev_log(sys, 1, b"[npp] seq_r128 verify mismatch\0".as_ptr(), 30);
                return 0;
            }
            let m = mbps_from(us, bytes);
            record_phase(s, phase, us, bytes, m);
            s.phase = PHASE_RAND_W;
            2
        }
        PHASE_RAND_W => {
            let (us, bytes, rc) = run_rand_write(s);
            if rc != 0 { s.err = rc; s.phase = PHASE_ERR; return 0; }
            let m = mbps_from(us, bytes);
            record_phase(s, phase, us, bytes, m);
            s.phase = PHASE_RAND_R;
            2
        }
        PHASE_RAND_R => {
            let (us, bytes, rc, verified) = run_rand_read(s);
            if rc != 0 { s.err = rc; s.phase = PHASE_ERR; return 0; }
            let expected = (s.random_iterations as u32) * (s.random_chunk as u32);
            if verified < expected {
                s.err = -5;
                s.phase = PHASE_ERR;
                dev_log(sys, 1, b"[npp] rand_r verify mismatch\0".as_ptr(), 28);
                return 0;
            }
            let m = mbps_from(us, bytes);
            record_phase(s, phase, us, bytes, m);
            s.phase = PHASE_DONE;
            dev_log(sys, 3, b"[npp] all phases complete\0".as_ptr(), 25);
            3
        }
        _ => 0,
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");

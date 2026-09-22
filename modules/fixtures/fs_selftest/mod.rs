//! fs_selftest — drives the `fs` contract's mutation surface on real hardware.
//!
//! The host suite proves these guarantees against a RAM disk with a modelled
//! volatile write cache. That model is exactly right for crash points and
//! exactly wrong for everything a device actually is: an FTL that reorders,
//! a Flush with real cost, an atomic-write unit that is a promise rather than
//! an assumption, and latency that turns "one synchronous op" into a step
//! budget question. This fixture asks the same questions of the device the
//! graph is actually running on.
//!
//! It walks a fixed script, one operation per step, and ends by logging
//! exactly one verdict:
//!
//! ```text
//! [fs_selftest] PASS <n> checks
//! [fs_selftest] FAIL <phase> rc=<errno>
//! ```
//!
//! One operation per step is not politeness. The surface under test is
//! synchronous device I/O inside a `provider_call`, and a fixture that ran
//! the whole script in one step would hide precisely the stalls it should be
//! surfacing.
//!
//! `EAGAIN` is retried rather than failed. The contract defines it as "ask
//! again" — a mount that has not resolved, a bounded internal table that is
//! momentarily full — and a fixture that treated it as failure would report a
//! defect every time it started before the device did.

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
include!("../../sdk/runtime/params.rs");

const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_UNLINK: u32 = 0x090A;
const FS_MKDIR: u32 = 0x090B;
const FS_TRUNCATE: u32 = 0x090C;
const FS_RENAME: u32 = 0x090D;
const FS_FSYNC_NAME: u32 = 0x0912;
const FS_CAPS: u32 = 0x09FF;

const CAP_TRUNCATE: u32 = 1 << 6;
const CAP_MKDIR: u32 = 1 << 7;
const CAP_RENAME: u32 = 1 << 8;
const CAP_FSYNC_NAME: u32 = 1 << 11;

/// Payload size: more than one 4 KiB cluster, so the script exercises chain
/// allocation and a multi-cluster read-back rather than a single sector.
const PAYLOAD: usize = 9000;

/// Length the truncate step shortens the file to — inside the first cluster,
/// so the clusters behind it are genuinely released.
const TRUNC_TO: u64 = 100;

const DIR: &[u8] = b"/FSTEST";
const TMP_PATH: &[u8] = b"/FSTEST/A.BIN";
const FINAL_PATH: &[u8] = b"/FSTEST/B.BIN";

/// Script phases, in order. The verdict names whichever one failed.
const PH_CAPS: u8 = 0;
const PH_MKDIR: u8 = 1;
const PH_CREATE: u8 = 2;
const PH_WRITE: u8 = 3;
const PH_FSYNC: u8 = 4;
const PH_CLOSE: u8 = 5;
const PH_FSYNC_NAME: u8 = 6;
const PH_VERIFY: u8 = 7;
const PH_RENAME: u8 = 8;
const PH_VERIFY_RENAMED: u8 = 9;
const PH_TRUNCATE: u8 = 10;
const PH_VERIFY_TRUNC: u8 = 11;
const PH_UNLINK: u8 = 12;
const PH_VERIFY_GONE: u8 = 13;
const PH_RMDIR_NAME: u8 = 14;
const PH_DONE: u8 = 15;

/// Phase names, for the verdict line. Indexed by phase.
const PHASE_NAMES: [&[u8]; 16] = [
    b"caps",
    b"mkdir",
    b"create",
    b"write",
    b"fsync",
    b"close",
    b"fsync_name",
    b"verify",
    b"rename",
    b"verify_renamed",
    b"truncate",
    b"verify_truncated",
    b"unlink",
    b"verify_gone",
    b"publish_removal",
    b"done",
];

#[repr(C)]
struct SelfTestState {
    syscalls: *const SyscallTable,
    /// Open FS handle, or -1.
    fd: i32,
    /// Current script phase.
    phase: u8,
    /// 1 once a verdict has been logged.
    finished: u8,
    /// 1 when the verdict was PASS.
    passed: u8,
    _pad: u8,
    /// Checks that have succeeded, reported in the PASS line.
    checks: u32,
    /// Bytes written / verified so far within the current phase.
    progress: u32,
    /// Steps spent in the current phase, so a provider that answers `EAGAIN`
    /// forever is reported rather than retried silently until the scenario
    /// times out with no explanation.
    waits: u32,
    /// Capability bitmap read in the first phase.
    caps: u32,
    /// Steps since the last heartbeat.
    since_beat: u32,
    /// Errno recorded with a FAIL verdict, so the heartbeat can repeat it.
    verdict_rc: i32,
    /// Phase the verdict was reached in.
    verdict_phase: u8,
    _pad2: [u8; 3],
    /// Scratch for read-back verification.
    buf: [u8; 512],
}

/// A provider that answers `EAGAIN` for this many consecutive steps is not
/// being transiently busy any more; it is stuck, and saying so beats a
/// scenario timeout with no line explaining it.
const MAX_WAITS: u32 = 200_000;

mod params_def {
    use super::SelfTestState;
    use super::SCHEMA_MAX;

    define_params! {
        SelfTestState;
    }
}

/// The byte a given offset of the payload should hold. A position-dependent
/// pattern, so a read-back that returns the right *number* of wrong bytes —
/// another file's cluster, a stale sector — fails rather than passes.
const fn payload_byte(off: usize) -> u8 {
    ((off * 31 + 7) % 251) as u8
}

unsafe fn log_phase(s: &SelfTestState, tag: &[u8], phase: u8) {
    let mut out = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"[fs_selftest] ";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    pos += prefix.len();
    let name = PHASE_NAMES[phase as usize];
    core::ptr::copy_nonoverlapping(name.as_ptr(), out.as_mut_ptr().add(pos), name.len());
    pos += name.len();
    *out.as_mut_ptr().add(pos) = b' ';
    pos += 1;
    core::ptr::copy_nonoverlapping(tag.as_ptr(), out.as_mut_ptr().add(pos), tag.len());
    pos += tag.len();
    dev_log(&*s.syscalls, 3, out.as_ptr(), pos);
}

/// Steps between heartbeats. At 1 ms ticks this is roughly five seconds,
/// matching the cadence every other module on the lane uses.
const BEAT_STEPS: u32 = 5000;

unsafe fn fail(s: &mut SelfTestState, rc: i32) -> i32 {
    s.finished = 1;
    s.passed = 0;
    s.verdict_rc = rc;
    s.verdict_phase = s.phase;
    emit_fail(s, s.phase, rc);
    0
}

unsafe fn emit_fail(s: &SelfTestState, phase: u8, rc: i32) {
    let mut out = [0u8; 96];
    let mut pos = 0usize;
    let prefix = b"[fs_selftest] FAIL ";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    pos += prefix.len();
    let name = PHASE_NAMES[phase as usize];
    core::ptr::copy_nonoverlapping(name.as_ptr(), out.as_mut_ptr().add(pos), name.len());
    pos += name.len();
    let mid = b" rc=-";
    core::ptr::copy_nonoverlapping(mid.as_ptr(), out.as_mut_ptr().add(pos), mid.len());
    pos += mid.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), rc.unsigned_abs());
    dev_log(&*s.syscalls, 4, out.as_ptr(), pos);
}

unsafe fn pass(s: &mut SelfTestState) -> i32 {
    s.finished = 1;
    s.passed = 1;
    emit_pass(s);
    0
}

unsafe fn emit_pass(s: &SelfTestState) {
    let mut out = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"[fs_selftest] PASS ";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    pos += prefix.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.checks);
    let tail = b" checks";
    core::ptr::copy_nonoverlapping(tail.as_ptr(), out.as_mut_ptr().add(pos), tail.len());
    pos += tail.len();
    dev_log(&*s.syscalls, 3, out.as_ptr(), pos);
}

/// Advance to the next phase, counting the one just completed.
unsafe fn advance(s: &mut SelfTestState) {
    log_phase(s, b"ok", s.phase);
    s.checks += 1;
    s.phase += 1;
    s.progress = 0;
    s.waits = 0;
}

/// Build the `RENAME` argument: `[src_len u16][src][dst_len u16][dst]`.
fn rename_arg(out: &mut [u8; 64], src: &[u8], dst: &[u8]) -> usize {
    let mut pos = 0usize;
    out[0] = src.len() as u8;
    out[1] = (src.len() >> 8) as u8;
    pos += 2;
    out[pos..pos + src.len()].copy_from_slice(src);
    pos += src.len();
    out[pos] = dst.len() as u8;
    out[pos + 1] = (dst.len() >> 8) as u8;
    pos += 2;
    out[pos..pos + dst.len()].copy_from_slice(dst);
    pos + dst.len()
}

/// Build the `TRUNCATE` argument: `[len u64][path]`.
fn truncate_arg(out: &mut [u8; 64], len: u64, path: &[u8]) -> usize {
    out[..8].copy_from_slice(&len.to_le_bytes());
    out[8..8 + path.len()].copy_from_slice(path);
    8 + path.len()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<SelfTestState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
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
        if state_size < core::mem::size_of::<SelfTestState>() {
            return -2;
        }
        let s = &mut *(state as *mut SelfTestState);
        core::ptr::write_bytes(
            core::ptr::from_mut(s).cast::<u8>(),
            0,
            core::mem::size_of::<SelfTestState>(),
        );
        s.syscalls = syscalls as *const SyscallTable;
        s.fd = -1;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        dev_log(&*s.syscalls, 3, b"[fs_selftest] start".as_ptr(), 19);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut SelfTestState);
    let sys = &*s.syscalls;

    // Repeat the verdict, and the current phase while still running.
    //
    // The script finishes within the first few hundred ticks — long before
    // DHCP binds and the log ring starts reaching the network. A one-shot
    // line would therefore be written into a ring that wraps before any
    // transport can carry it, and the run would time out with no
    // explanation and a perfectly healthy-looking device. A verdict worth
    // acting on is one that keeps being said.
    s.since_beat += 1;
    if s.since_beat >= BEAT_STEPS {
        s.since_beat = 0;
        if s.finished != 0 {
            if s.passed != 0 {
                emit_pass(s);
            } else {
                emit_fail(s, s.verdict_phase, s.verdict_rc);
            }
        } else {
            log_phase(s, b"running", s.phase);
        }
    }
    if s.finished != 0 {
        return 0;
    }

    s.waits += 1;
    if s.waits > MAX_WAITS {
        return fail(s, E_AGAIN);
    }

    match s.phase {
        PH_CAPS => {
            // The capability bitmap is not readable until the volume is
            // mounted, and a consumer that latches an unread answer runs its
            // degraded tier forever. Ask until there is an answer.
            let mut caps = [0u8; 4];
            let rc = (sys.provider_call)(-1, FS_CAPS, caps.as_mut_ptr(), 4);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.caps = u32::from_le_bytes(caps);
            // Everything this script goes on to do must be advertised. A
            // provider that performs an operation whose bit is clear is as
            // wrong as one that refuses an operation whose bit is set.
            let need = CAP_MKDIR | CAP_RENAME | CAP_TRUNCATE | CAP_FSYNC_NAME;
            if s.caps & need != need {
                return fail(s, -38);
            }
            advance(s);
            0
        }

        PH_MKDIR => {
            let rc = (sys.provider_call)(-1, FS_MKDIR, DIR.as_ptr().cast_mut(), DIR.len());
            if rc == E_AGAIN {
                return 0;
            }
            // An existing directory is success, per the contract.
            if rc < 0 && rc != -17 {
                return fail(s, rc);
            }
            advance(s);
            0
        }

        PH_CREATE => {
            let rc = (sys.provider_call)(
                -1,
                FS_OPEN_CREATE,
                TMP_PATH.as_ptr().cast_mut(),
                TMP_PATH.len(),
            );
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.fd = rc;
            advance(s);
            0
        }

        PH_WRITE => {
            // One chunk per step. The provider's write path is synchronous,
            // so a fixture that pushed 9 KB in one call would be measuring
            // how long the device takes rather than whether it is correct.
            let off = s.progress as usize;
            if off >= PAYLOAD {
                advance(s);
                return 0;
            }
            let mut chunk = [0u8; 512];
            let n = core::cmp::min(512, PAYLOAD - off);
            let mut i = 0usize;
            while i < n {
                chunk[i] = payload_byte(off + i);
                i += 1;
            }
            let rc = (sys.provider_call)(s.fd, FS_WRITE, chunk.as_mut_ptr(), n);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.progress += rc as u32;
            s.waits = 0;
            0
        }

        PH_FSYNC => {
            let rc = (sys.provider_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            advance(s);
            0
        }

        PH_CLOSE => {
            let rc = (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
            if rc < 0 {
                return fail(s, rc);
            }
            s.fd = -1;
            advance(s);
            0
        }

        PH_FSYNC_NAME => {
            // File `FSYNC` fences bytes, not the name that finds them. This
            // is the step that makes the artefact discoverable after a power
            // cut, and it is the one a consumer most easily forgets.
            let rc = (sys.provider_call)(
                -1,
                FS_FSYNC_NAME,
                TMP_PATH.as_ptr().cast_mut(),
                TMP_PATH.len(),
            );
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            advance(s);
            0
        }

        PH_VERIFY => verify(s, TMP_PATH, PAYLOAD),

        PH_RENAME => {
            let mut arg = [0u8; 64];
            let n = rename_arg(&mut arg, TMP_PATH, FINAL_PATH);
            let rc = (sys.provider_call)(-1, FS_RENAME, arg.as_mut_ptr(), n);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            advance(s);
            0
        }

        PH_VERIFY_RENAMED => {
            // The bytes must have moved with the name, not merely the name.
            verify(s, FINAL_PATH, PAYLOAD)
        }

        PH_TRUNCATE => {
            let mut arg = [0u8; 64];
            let n = truncate_arg(&mut arg, TRUNC_TO, FINAL_PATH);
            let rc = (sys.provider_call)(-1, FS_TRUNCATE, arg.as_mut_ptr(), n);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            advance(s);
            0
        }

        PH_VERIFY_TRUNC => verify(s, FINAL_PATH, TRUNC_TO as usize),

        PH_UNLINK => {
            let rc = (sys.provider_call)(
                -1,
                FS_UNLINK,
                FINAL_PATH.as_ptr().cast_mut(),
                FINAL_PATH.len(),
            );
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            advance(s);
            0
        }

        PH_VERIFY_GONE => {
            let rc = (sys.provider_call)(
                -1,
                FS_OPEN,
                FINAL_PATH.as_ptr().cast_mut(),
                FINAL_PATH.len(),
            );
            if rc == E_AGAIN {
                return 0;
            }
            if rc >= 0 {
                // The name still resolves. Close the handle before reporting,
                // so a failed run does not also leak one.
                (sys.provider_call)(rc, FS_CLOSE, core::ptr::null_mut(), 0);
                return fail(s, -17);
            }
            advance(s);
            0
        }

        PH_RMDIR_NAME => {
            // Publish the removal. A name is not gone until the directory
            // entry that held it is durable, on the same reasoning that makes
            // `FSYNC_NAME` necessary after a create.
            let rc = (sys.provider_call)(
                -1,
                FS_FSYNC_NAME,
                FINAL_PATH.as_ptr().cast_mut(),
                FINAL_PATH.len(),
            );
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            advance(s);
            0
        }

        p if p >= PH_DONE => pass(s),
        _ => pass(s),
    }
}

/// Read `len` bytes of `path` back and check every byte against the pattern.
///
/// A length check alone would pass on another file's cluster; the pattern is
/// position-dependent so a read that lands on the wrong chain fails.
unsafe fn verify(s: &mut SelfTestState, path: &[u8], len: usize) -> i32 {
    let sys = &*s.syscalls;
    if s.fd < 0 {
        let rc = (sys.provider_call)(-1, FS_OPEN, path.as_ptr().cast_mut(), path.len());
        if rc == E_AGAIN {
            return 0;
        }
        if rc < 0 {
            return fail(s, rc);
        }
        s.fd = rc;
        s.progress = 0;
        // The size the entry claims must be the size that was written.
        // Reading the bytes back alone cannot catch a size field that
        // disagrees with the chain — a short read looks the same as a short
        // file — so ask the entry directly first.
        let mut st = [0u8; 16];
        let rc = (sys.provider_call)(s.fd, FS_STAT, st.as_mut_ptr(), 16);
        if rc < 0 {
            return fail(s, rc);
        }
        let size = u64::from_le_bytes([st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]]);
        if size != len as u64 {
            return fail(s, -75); // EOVERFLOW — the entry describes another file
        }
        return 0;
    }
    let off = s.progress as usize;
    if off >= len {
        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
        advance(s);
        return 0;
    }
    let want = core::cmp::min(512, len - off);
    let rc = (sys.provider_call)(s.fd, FS_READ, s.buf.as_mut_ptr(), want);
    if rc == E_AGAIN {
        return 0;
    }
    if rc <= 0 {
        // Short of the length the entry claims: the size field and the chain
        // disagree, which is the shape a lost cluster takes on read.
        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
        return fail(s, if rc == 0 { -5 } else { rc });
    }
    let n = rc as usize;
    let mut i = 0usize;
    while i < n {
        if *s.buf.as_ptr().add(i) != payload_byte(off + i) {
            (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.fd = -1;
            return fail(s, -5);
        }
        i += 1;
    }
    s.progress += n as u32;
    s.waits = 0;
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");

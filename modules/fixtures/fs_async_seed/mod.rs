//! fs_async_seed — write files through the fs contract's ASYNC fence tier,
//! on the device the graph is running on.
//!
//! `fat32_seed` proves the synchronous path (`FSYNC`, `FSYNC_NAME`). A
//! store's flush uses the other tier — `FSYNC_SUBMIT` for a ticket,
//! `FSYNC_POLL` until it answers Durable — and the question a power cut asks
//! of that tier is whether a NAME whose fence polled Durable is still in the
//! directory afterwards. This fixture creates `count` files that way, one
//! operation per step, logs each name as its fence lands, and ends with one
//! verdict:
//!
//! ```text
//! [fs_async_seed] durable /ASY0003.DAT
//! [fs_async_seed] DONE n=8 rounds=1
//! [fs_async_seed] FAIL <phase> rc=-<errno>
//! ```
//!
//! With `rounds` above 1, every pass past the first rewrites each file in
//! place (OPEN_CREATE truncates the name, new bytes, one fence): the shape
//! of a manifest slot overwritten under one name.
//!
//! The scenario cuts the power after DONE. A second boot with `verify = 1`
//! reads every file back against the last pass's bytes and reports
//!
//! ```text
//! [fs_async_seed] verify ok=<n> bad=<m>
//! ```
//!
//! where a file that is missing, short or different is bad. The verdict
//! repeats on a heartbeat, because the first can be emitted before the log's
//! transport is up.

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

use abi::contracts::storage::fs::{
    CLOSE as FS_CLOSE, FSYNC_POLL as FS_FSYNC_POLL, FSYNC_SUBMIT as FS_FSYNC_SUBMIT,
    OPEN as FS_OPEN, OPEN_CREATE as FS_OPEN_CREATE, READ as FS_READ, WRITE as FS_WRITE,
};

/// `FSYNC_POLL`'s answer while the fence is still in flight.
const FENCE_PENDING: i32 = 1;

const MAX_PREFIX: usize = 32;
/// prefix + 4 digits + ".DAT"
const MAX_PATH: usize = MAX_PREFIX + 8;
const CHUNK: usize = 512;

const PH_CREATE: u8 = 0;
const PH_WRITE: u8 = 1;
const PH_SUBMIT: u8 = 2;
const PH_POLL: u8 = 3;
const PH_CLOSE: u8 = 4;
const PH_DONE: u8 = 5;
const PH_VOPEN: u8 = 6;
const PH_VREAD: u8 = 7;
const PH_VCLOSE: u8 = 8;

name_table!(
    PHASE_NAMES = [
        b"create", b"write", b"submit", b"poll", b"close", b"done", b"vopen", b"vread", b"vclose"
    ]
);

/// Steps between repeats of the verdict line (the first can be emitted
/// before the log's transport is up).
const BEAT_STEPS: u32 = 5000;
/// A provider answering `EAGAIN` this many steps running is not busy any
/// more, and saying so beats a scenario timeout with nothing to read.
const MAX_WAITS: u32 = 200_000;

#[repr(C)]
struct SeedState {
    syscalls: *const SyscallTable,
    fd: i32,
    phase: u8,
    finished: u8,
    failed: u8,
    prefix_len: u8,
    /// File being written (0-based) and how many to write.
    idx: u32,
    count: u32,
    /// Pass over the files (0-based) and how many: a pass past the first
    /// rewrites every file IN PLACE (the manifest-slot shape: the name
    /// exists, OPEN_CREATE truncates it, the bytes change, one fence).
    round: u32,
    rounds: u32,
    /// 1 = verify: read every file back and compare it with the last
    /// pass's bytes, log `verify ok=<n> bad=<m>` — the second boot's half.
    verify: u32,
    vok: u32,
    vbad: u32,
    vmismatch: u32,
    /// Bytes written so far in this file, and the size of each.
    progress: u32,
    size: u32,
    waits: u32,
    since_beat: u32,
    verdict_rc: i32,
    verdict_phase: u8,
    _pad: [u8; 3],
    ticket: [u8; 8],
    prefix: [u8; MAX_PREFIX],
    path: [u8; MAX_PATH],
    path_len: u32,
}

mod params_def {
    use super::p_u32;
    use super::SeedState;
    use super::SCHEMA_MAX;

    define_params! {
        SeedState;

        // Path prefix of every file, e.g. "/ASY" (names are <prefix>0001.DAT).
        // On a FAT volume the name part, with its four digits, is an 8.3
        // name: four characters of prefix after the directory at most.
        1, prefix, str, 0
            => |s, d, len| {
                if len == 0 || len > super::MAX_PREFIX { return; }
                let dst = s.prefix.as_mut_ptr();
                let mut i = 0usize;
                while i < len { *dst.add(i) = *d.add(i); i += 1; }
                s.prefix_len = len as u8;
            };

        // Files to write.
        2, count, u32, 8
            => |s, d, len| { s.count = p_u32(d, len, 0, 8); };

        // Bytes per file.
        3, size, u32, 4096
            => |s, d, len| { s.size = p_u32(d, len, 0, 4096); };

        // Passes over the files; past the first each rewrites in place.
        4, rounds, u32, 1
            => |s, d, len| { s.rounds = p_u32(d, len, 0, 1); };

        // 1 = read every file back and compare with the last pass.
        5, verify, u32, 0
            => |s, d, len| { s.verify = p_u32(d, len, 0, 0); };
    }
}

const fn pattern_byte(idx: u32, round: u32, off: usize) -> u8 {
    ((off as u32)
        .wrapping_add(idx.wrapping_mul(31))
        .wrapping_add(round.wrapping_mul(97))
        & 0xFF) as u8
}

/// `<prefix><idx+1 as 4 digits>.DAT` into `s.path`.
unsafe fn build_path(s: &mut SeedState) {
    let mut pos = 0usize;
    let n = s.prefix_len as usize;
    core::ptr::copy_nonoverlapping(s.prefix.as_ptr(), s.path.as_mut_ptr(), n);
    pos += n;
    let mut v = s.idx.wrapping_add(1) % 10000;
    let mut digits = [b'0'; 4];
    let mut i = 4usize;
    while i > 0 {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    core::ptr::copy_nonoverlapping(digits.as_ptr(), s.path.as_mut_ptr().add(pos), 4);
    pos += 4;
    let ext = b".DAT";
    core::ptr::copy_nonoverlapping(ext.as_ptr(), s.path.as_mut_ptr().add(pos), ext.len());
    pos += ext.len();
    s.path_len = pos as u32;
}

unsafe fn emit_durable(s: &SeedState) {
    let mut out = [0u8; 96];
    let prefix = b"[fs_async_seed] durable ";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    let mut pos = prefix.len();
    let n = s.path_len as usize;
    core::ptr::copy_nonoverlapping(s.path.as_ptr(), out.as_mut_ptr().add(pos), n);
    pos += n;
    dev_log(&*s.syscalls, 3, out.as_ptr(), pos);
}

unsafe fn emit_done(s: &SeedState) {
    let mut out = [0u8; 64];
    let mut pos = 0usize;
    if s.verify != 0 {
        let prefix = b"[fs_async_seed] verify ok=";
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
        pos += prefix.len();
        pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.vok);
        let mid = b" bad=";
        core::ptr::copy_nonoverlapping(mid.as_ptr(), out.as_mut_ptr().add(pos), mid.len());
        pos += mid.len();
        pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.vbad);
    } else {
        let prefix = b"[fs_async_seed] DONE n=";
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
        pos += prefix.len();
        pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.count);
        let mid = b" rounds=";
        core::ptr::copy_nonoverlapping(mid.as_ptr(), out.as_mut_ptr().add(pos), mid.len());
        pos += mid.len();
        pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.rounds);
    }
    dev_log(&*s.syscalls, 3, out.as_ptr(), pos);
}

unsafe fn emit_fail(s: &SeedState, phase: u8, rc: i32) {
    let mut out = [0u8; 96];
    let prefix = b"[fs_async_seed] FAIL ";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    let mut pos = prefix.len();
    let name = PHASE_NAMES.get(phase as usize);
    core::ptr::copy_nonoverlapping(name.as_ptr(), out.as_mut_ptr().add(pos), name.len());
    pos += name.len();
    let mid = b" rc=-";
    core::ptr::copy_nonoverlapping(mid.as_ptr(), out.as_mut_ptr().add(pos), mid.len());
    pos += mid.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), rc.unsigned_abs());
    dev_log(&*s.syscalls, 4, out.as_ptr(), pos);
}

unsafe fn fail(s: &mut SeedState, rc: i32) -> i32 {
    s.finished = 1;
    s.failed = 1;
    s.verdict_rc = rc;
    s.verdict_phase = s.phase;
    emit_fail(s, s.phase, rc);
    0
}

declare_module_state_bytes!(SeedState);

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<SeedState>()
}

/// # Safety
/// Kernel module-ABI entry point: `syscalls` is the kernel's syscall table,
/// valid for the module's lifetime.
#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
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
        if state_size < core::mem::size_of::<SeedState>() {
            return -2;
        }
        let s = &mut *(state as *mut SeedState);
        core::ptr::write_bytes(
            core::ptr::from_mut(s).cast::<u8>(),
            0,
            core::mem::size_of::<SeedState>(),
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
        if s.rounds == 0 {
            s.rounds = 1;
        }
        if s.prefix_len == 0 || s.count == 0 || s.size == 0 {
            // Nothing declared to write. Idle rather than guess.
            s.finished = 1;
        } else {
            build_path(s);
            if s.verify != 0 {
                s.phase = PH_VOPEN;
            }
        }
        0
    }
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut SeedState);
    let sys = &*s.syscalls;

    s.since_beat += 1;
    if s.since_beat >= BEAT_STEPS {
        s.since_beat = 0;
        if s.finished != 0 {
            if s.failed != 0 {
                emit_fail(s, s.verdict_phase, s.verdict_rc);
            } else if s.prefix_len != 0 {
                emit_done(s);
            }
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
        PH_CREATE => {
            let rc =
                (sys.provider_call)(-1, FS_OPEN_CREATE, s.path.as_mut_ptr(), s.path_len as usize);
            if rc == E_AGAIN || rc == E_INPROGRESS {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.fd = rc;
            s.progress = 0;
            s.phase = PH_WRITE;
            s.waits = 0;
            0
        }

        PH_WRITE => {
            let off = s.progress as usize;
            let total = s.size as usize;
            if off >= total {
                s.phase = PH_SUBMIT;
                return 0;
            }
            let n = if total - off > CHUNK {
                CHUNK
            } else {
                total - off
            };
            let mut chunk = [0u8; CHUNK];
            let mut i = 0usize;
            while i < n {
                chunk[i] = pattern_byte(s.idx, s.round, off + i);
                i += 1;
            }
            let rc = (sys.provider_call)(s.fd, FS_WRITE, chunk.as_mut_ptr(), n);
            if rc == E_AGAIN || rc == E_INPROGRESS {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.progress += rc as u32;
            s.waits = 0;
            0
        }

        PH_SUBMIT => {
            let rc = (sys.provider_call)(s.fd, FS_FSYNC_SUBMIT, s.ticket.as_mut_ptr(), 8);
            if rc == E_AGAIN || rc == E_INPROGRESS {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.phase = PH_POLL;
            s.waits = 0;
            0
        }

        PH_POLL => {
            let rc = (sys.provider_call)(s.fd, FS_FSYNC_POLL, s.ticket.as_mut_ptr(), 8);
            if rc == FENCE_PENDING || rc == E_AGAIN || rc == E_INPROGRESS {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            // Durable: the name is announced only now.
            emit_durable(s);
            s.phase = PH_CLOSE;
            s.waits = 0;
            0
        }

        PH_CLOSE => {
            let rc = (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
            if rc == E_AGAIN || rc == E_INPROGRESS {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.fd = -1;
            s.idx += 1;
            s.waits = 0;
            if s.idx >= s.count {
                s.round += 1;
                if s.round >= s.rounds {
                    s.phase = PH_DONE;
                    s.finished = 1;
                    emit_done(s);
                    return 0;
                }
                s.idx = 0;
            }
            build_path(s);
            s.phase = PH_CREATE;
            0
        }

        PH_VOPEN => {
            let rc = (sys.provider_call)(-1, FS_OPEN, s.path.as_mut_ptr(), s.path_len as usize);
            if rc == E_AGAIN || rc == E_INPROGRESS {
                return 0;
            }
            if rc < 0 {
                // Absent: a name whose fence polled Durable is gone.
                s.vbad += 1;
                s.vmismatch = 0;
                s.phase = PH_VCLOSE;
                s.fd = -1;
                return 0;
            }
            s.fd = rc;
            s.progress = 0;
            s.vmismatch = 0;
            s.phase = PH_VREAD;
            s.waits = 0;
            0
        }

        PH_VREAD => {
            let off = s.progress as usize;
            let total = s.size as usize;
            if off >= total {
                if s.vmismatch == 0 {
                    s.vok += 1;
                } else {
                    s.vbad += 1;
                }
                s.phase = PH_VCLOSE;
                return 0;
            }
            let n = if total - off > CHUNK {
                CHUNK
            } else {
                total - off
            };
            let mut chunk = [0u8; CHUNK];
            let rc = (sys.provider_call)(s.fd, FS_READ, chunk.as_mut_ptr(), n);
            if rc == E_AGAIN || rc == E_INPROGRESS {
                return 0;
            }
            if rc <= 0 {
                // Short: the bytes a fence polled Durable are not there.
                s.vmismatch += 1;
                s.progress = total as u32;
                return 0;
            }
            let got = rc as usize;
            let last = s.rounds - 1;
            let mut i = 0usize;
            while i < got {
                if chunk[i] != pattern_byte(s.idx, last, off + i) {
                    s.vmismatch += 1;
                }
                i += 1;
            }
            s.progress += got as u32;
            s.waits = 0;
            0
        }

        PH_VCLOSE => {
            if s.fd >= 0 {
                let _ = (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
                s.fd = -1;
            }
            s.idx += 1;
            s.waits = 0;
            if s.idx >= s.count {
                s.phase = PH_DONE;
                s.finished = 1;
                emit_done(s);
            } else {
                build_path(s);
                s.phase = PH_VOPEN;
            }
            0
        }

        _ => {
            s.finished = 1;
            0
        }
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");

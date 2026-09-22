//! Gallery staging fixture — writes known-good image + audio assets
//! onto the DUT's FAT32 root through the public FS contract.
//!
//! Provisions the `pi5_image_viewer` rig test's gallery: the assets
//! ship inside the fmod via `include_bytes!` and are written
//! chunk-per-step through OPEN_CREATE → WRITE×N → FSYNC → CLOSE —
//! the same op sequence as the fs_write_smoke fixture — with E_AGAIN
//! retried across steps so fat32 init latency and block-ring
//! backpressure are honoured cooperatively.
//!
//! Pass signal for the rig scenario: `[gallery] staged all files`
//! (recurring — see the heartbeat below).

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
use abi::contracts::storage::fs;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

/// Oversized artifact that must not survive on the root, unlinked
/// once at start: a 1920x1080 JPEG whose single-call decode blows the
/// pi5 step budget.
const STALE_PATH: &[u8] = b"/SPIRAL.JPG";

/// Number of staged files (see `file()`).
const FILE_COUNT: usize = 2;

/// Staged files, written in order. 8.3-safe names on the FAT32 root:
/// - TEST.JPG: 64x64 baseline JPEG (~2.5 KB) — the image_viewer rig
///   test's gallery (bank formats ".bmp,.gif,.png,.jpg,.jpeg").
/// - CMAJOR.MP3: ~65 KB ID3-tagged MP3 — the audio-variant rig test's
///   asset (bank formats ".mp3").
///
/// A function with a `match`, NOT a `const` table: a static table of
/// `&[u8]` fat pointers materializes ABSOLUTE addresses in .rodata,
/// which the PIC loader does not relocate — on silicon those pointers
/// land in unrelated firmware code and the fixture writes machine
/// code as the payload under a garbage 8.3 name. Computing the slices
/// in code keeps the address PC-relative (ADRP), which PIC handles.
/// Same hazard class the fs_write_smoke stack-buffer comment
/// documents.
#[inline(never)]
fn file(idx: usize) -> (&'static [u8], &'static [u8]) {
    match idx {
        0 => (
            b"/TEST.JPG",
            include_bytes!("../../../examples/test_harness/assets/spiral_64.jpg"),
        ),
        _ => (
            b"/CMAJOR.MP3",
            include_bytes!("../../../examples/test_harness/assets/cmajor.mp3"),
        ),
    }
}

/// Bytes copied into the state buffer and handed to FS_WRITE per step.
/// Small enough that a step stays well inside the pi5 domain budget;
/// Burst (return 2) lets the scheduler drain the whole payload in a
/// handful of ticks anyway.
const CHUNK: usize = 2048;

const PHASE_OPEN: u8 = 0;
const PHASE_WRITE: u8 = 1;
const PHASE_FSYNC: u8 = 2;
const PHASE_CLOSE: u8 = 3;
const PHASE_DONE: u8 = 4;
const PHASE_FAILED: u8 = 5;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    fd: i32,
    /// Index of the file currently being staged (see `file()`).
    file_idx: usize,
    off: usize,
    /// Last error rc (OPEN retry loop, or the terminal failure),
    /// replayed by the heartbeat — a one-shot dev_log at early boot
    /// is lost in the log ring before log_net's UDP stream drains
    /// (same pattern as the codec heartbeat's last_err replay).
    last_rc: i32,
    tick: u32,
    phase: u8,
    _pad: [u8; 3],
    /// Chunk staging buffer — the payload lives in .rodata; copy each
    /// chunk here so the pointer handed across the provider boundary
    /// is plain module state (same caution as fs_write_smoke).
    chunk: [u8; CHUNK],
}

unsafe fn call(sys: &SyscallTable, handle: i32, op: u32, arg: *mut u8, len: usize) -> i32 {
    (sys.provider_call)(handle, op, arg, len)
}

unsafe fn fail(s: &mut State, rc: i32, msg: &[u8]) -> i32 {
    s.last_rc = rc;
    dev_log(&*s.syscalls, 1, msg.as_ptr(), msg.len());
    s.phase = PHASE_FAILED;
    0
}

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
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.fd = -1;
        s.file_idx = 0;
        s.off = 0;
        s.last_rc = 0;
        s.tick = 0;
        s.phase = PHASE_OPEN;
    }
    0
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

        // Phase heartbeat every ~5000 ticks, INCLUDING the terminal
        // states. With Burst the whole write can finish within the
        // first seconds of boot — before DHCP binds and log_net's UDP
        // stream starts draining — so every one-shot line (including
        // the success line) can be lost in the early log ring. The
        // DONE heartbeat replays the staged message sticky-style so
        // the rig's pass rule matches no matter when telemetry
        // attaches; same pattern as codec's last_err replay.
        s.tick = s.tick.wrapping_add(1);
        if s.tick % 5000 == 0 {
            let msg: &[u8] = match s.phase {
                PHASE_OPEN => b"[gallery] hb phase=open",
                PHASE_WRITE => b"[gallery] hb phase=write",
                PHASE_FSYNC => b"[gallery] hb phase=fsync",
                PHASE_CLOSE => b"[gallery] hb phase=close",
                // Recurring success line — rig pass rules must key on
                // steady-state logs, never one-shots (standards/rig.md
                // §5): with Burst the whole write finishes before the
                // UDP monitor attaches.
                PHASE_DONE => b"[gallery] staged all files",
                _ => b"[gallery] hb phase=FAILED",
            };
            dev_log(sys, 3, msg.as_ptr(), msg.len());
            // Replay the last error rc alongside the phase:
            // the one-shot line that carried it is lost if it fired
            // before log_net's UDP stream started draining.
            if s.last_rc != 0 {
                let prefix = b"[gallery] last_rc=";
                let mut buf = [0u8; 32];
                buf[..prefix.len()].copy_from_slice(prefix);
                let mut len = prefix.len();
                let mut v = s.last_rc as i64;
                if v < 0 {
                    buf[len] = b'-';
                    len += 1;
                    v = -v;
                }
                let mut digits = [0u8; 10];
                let mut d = 0;
                loop {
                    digits[d] = b'0' + (v % 10) as u8;
                    d += 1;
                    v /= 10;
                    if v == 0 {
                        break;
                    }
                }
                while d > 0 {
                    d -= 1;
                    buf[len] = digits[d];
                    len += 1;
                }
                dev_log(sys, 3, buf.as_ptr(), len);
            }
        }

        match s.phase {
            PHASE_OPEN => {
                // Stack path buffer, NUL-free length-delimited like the
                // smoke fixture. UNLINK first so a stale/partial file
                // from an aborted run never survives; its errors are
                // ignored (ENOENT is the normal case).
                let mut path = [0u8; 32];
                if s.file_idx == 0 {
                    // Remove the oversized artifact from the earlier
                    // staging attempt — if it survives, bank streams it
                    // first and the codec dies on it.
                    path[..STALE_PATH.len()].copy_from_slice(STALE_PATH);
                    let stale_rc = call(sys, -1, fs::UNLINK, path.as_mut_ptr(), STALE_PATH.len());
                    if stale_rc == E_AGAIN {
                        return 0; // fat32 still mounting — retry whole phase
                    }
                }
                let (dest, _) = file(s.file_idx);
                path = [0u8; 32];
                path[..dest.len()].copy_from_slice(dest);
                let _ = call(sys, -1, fs::UNLINK, path.as_mut_ptr(), dest.len());
                let fd = call(sys, -1, fs::OPEN_CREATE, path.as_mut_ptr(), dest.len());
                if fd < 0 {
                    // Retry on ANY error, not just E_AGAIN: at early boot
                    // the FS provider may not be registered yet (ENOSYS)
                    // or fat32 may still be in an init phase that maps to
                    // a non-EAGAIN errno. The scenario timeout is the
                    // failure backstop; the heartbeat shows if we're
                    // stuck here.
                    s.last_rc = fd;
                    return 0;
                }
                s.fd = fd;
                s.off = 0;
                s.last_rc = 0;
                s.phase = PHASE_WRITE;
                2 // Burst — keep draining
            }
            PHASE_WRITE => {
                let (_, payload) = file(s.file_idx);
                let remaining = payload.len() - s.off;
                let n = if remaining > CHUNK { CHUNK } else { remaining };
                s.chunk[..n].copy_from_slice(&payload[s.off..s.off + n]);
                let rc = call(sys, s.fd, fs::WRITE, s.chunk.as_mut_ptr(), n);
                if rc == E_AGAIN {
                    return 0; // block-ring backpressure — retry next tick
                }
                if rc < 0 {
                    return fail(s, rc, b"[gallery] WRITE failed");
                }
                s.off += rc as usize;
                if s.off >= payload.len() {
                    s.phase = PHASE_FSYNC;
                }
                2
            }
            PHASE_FSYNC => {
                let rc = call(sys, s.fd, fs::FSYNC, core::ptr::null_mut(), 0);
                if rc == E_AGAIN {
                    return 0;
                }
                if rc != 0 {
                    return fail(s, rc, b"[gallery] FSYNC failed");
                }
                s.phase = PHASE_CLOSE;
                2
            }
            PHASE_CLOSE => {
                let rc = call(sys, s.fd, fs::CLOSE, core::ptr::null_mut(), 0);
                if rc == E_AGAIN {
                    return 0;
                }
                if rc != 0 {
                    return fail(s, rc, b"[gallery] CLOSE failed");
                }
                s.file_idx += 1;
                if s.file_idx < FILE_COUNT {
                    s.phase = PHASE_OPEN;
                    return 2;
                }
                s.phase = PHASE_DONE;
                let msg = b"[gallery] staged all files";
                dev_log(sys, 3, msg.as_ptr(), msg.len());
                0
            }
            _ => 0, // DONE / FAILED — idle
        }
    }
}

include!("../../sdk/runtime/wasm_entry.rs");

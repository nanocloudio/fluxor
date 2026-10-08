//! fs_clean — list a volume's root, and remove the files a scenario names.
//!
//! A board's disk outlives every graph that ran on it. A scenario that needs
//! a known volume — a store that starts empty, a log with one history — has
//! two ways to get one: a host mounts the disk, or something in the graph
//! clears it. This is the second, and it says what it found first:
//!
//! ```text
//! [fs_clean] files=<n> <name> <name> ...      (one or more lines)
//! [fs_clean] removed=<k> failed=<f> last_rc=-<errno>
//! ```
//!
//! Params: `suffixes` — comma-separated, case-insensitive name endings to
//! remove (`.WAL,.RUN`); empty lists only. Nothing outside the root is
//! touched, and nothing is removed before it has been listed.
//!
//! An ordinary `fs` consumer: `OPENDIR`, `READDIR`, `CLOSE`, `UNLINK`, one
//! call per step.

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

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

const FS_CLOSE: u32 = abi::contracts::storage::fs::CLOSE;
const FS_OPENDIR: u32 = abi::contracts::storage::fs::OPENDIR;
const FS_READDIR: u32 = abi::contracts::storage::fs::READDIR;
const FS_UNLINK: u32 = abi::contracts::storage::fs::UNLINK;
const EAGAIN: i32 = abi::kernel_abi::errno::EAGAIN;
const ENOENT: i32 = abi::kernel_abi::errno::ENOENT;

/// Names kept from the listing, and the longest one.
const MAX_NAMES: usize = 64;
const MAX_NAME: usize = 32;
/// Bytes of the `suffixes` parameter kept.
const MAX_SUFFIXES: usize = 128;

const PH_OPEN: u8 = 0;
const PH_READ: u8 = 1;
const PH_REMOVE: u8 = 2;
const PH_DONE: u8 = 3;

/// Attempts per refused name, and the steps between them.
const RETRIES: u32 = 20;
const RETRY_STEPS: u32 = 250;

/// Steps between heartbeats: about five seconds at a 1 ms tick.
const BEAT_STEPS: u32 = 5000;

#[repr(C)]
struct CleanState {
    syscalls: *const SyscallTable,
    dir: i32,
    phase: u8,
    count: u8,
    /// Next name `PH_REMOVE` considers.
    cursor: u8,
    suffixes_len: u8,
    removed: u32,
    failed: u32,
    last_rc: i32,
    since_beat: u32,
    /// The listing ran out of room for names (more files than recorded).
    truncated: u32,
    /// Attempts at the current name, and steps to wait before the next.
    tries: u32,
    backoff: u32,
    suffixes: [u8; MAX_SUFFIXES],
    name_len: [u8; MAX_NAMES],
    names: [[u8; MAX_NAME]; MAX_NAMES],
    buf: [u8; 512],
}

mod params_def {
    use super::CleanState;
    use super::SCHEMA_MAX;

    define_params! {
        CleanState;

        // Comma-separated name endings to remove, matched without case.
        1, suffixes, str, 0
            => |s, d, len| {
                let n = if len > super::MAX_SUFFIXES { super::MAX_SUFFIXES } else { len };
                let mut i = 0usize;
                while i < n { s.suffixes[i] = *d.add(i); i += 1; }
                s.suffixes_len = n as u8;
            };
    }
}

fn lower(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

/// Whether `name` ends with one of the comma-separated `suffixes`.
fn matches(name: &[u8], suffixes: &[u8]) -> bool {
    for suffix in suffixes.split(|&b| b == b',') {
        if suffix.is_empty() || suffix.len() > name.len() {
            continue;
        }
        let tail = &name[name.len() - suffix.len()..];
        if tail.iter().zip(suffix).all(|(a, b)| lower(*a) == lower(*b)) {
            return true;
        }
    }
    false
}

unsafe fn log(s: &CleanState, line: &[u8]) {
    dev_log(&*s.syscalls, 3, line.as_ptr(), line.len());
}

/// The listing, in lines that fit the log transport.
unsafe fn emit_listing(s: &CleanState) {
    let mut out = [0u8; 160];
    let head = b"[fs_clean] files=";
    out[..head.len()].copy_from_slice(head);
    let mut pos = head.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), u32::from(s.count) + s.truncated);
    for i in 0..s.count as usize {
        let n = s.name_len[i] as usize;
        if pos + 1 + n > out.len() {
            log(s, &out[..pos]);
            let cont = b"[fs_clean] +";
            out[..cont.len()].copy_from_slice(cont);
            pos = cont.len();
        }
        out[pos] = b' ';
        out[pos + 1..pos + 1 + n].copy_from_slice(&s.names[i][..n]);
        pos += 1 + n;
    }
    log(s, &out[..pos]);
}

unsafe fn emit_result(s: &CleanState) {
    let mut out = [0u8; 96];
    let head = b"[fs_clean] removed=";
    out[..head.len()].copy_from_slice(head);
    let mut pos = head.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.removed);
    let mid = b" failed=";
    out[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.failed);
    let tail = b" last_rc=-";
    out[pos..pos + tail.len()].copy_from_slice(tail);
    pos += tail.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.last_rc.unsigned_abs());
    log(s, &out[..pos]);
}

/// Record the entries of one `READDIR` batch (`[count u16]` then
/// `[name_len u8][type u8][name]` each). Directories are not recorded.
unsafe fn take_batch(s: &mut CleanState, n: usize) {
    let b = &s.buf[..n.min(s.buf.len())];
    if b.len() < 2 {
        return;
    }
    let count = u16::from_le_bytes([b[0], b[1]]) as usize;
    let mut at = 2usize;
    for _ in 0..count {
        let Some(&len) = b.get(at) else { return };
        let Some(&kind) = b.get(at + 1) else { return };
        let len = len as usize;
        let Some(name) = b.get(at + 2..at + 2 + len) else {
            return;
        };
        at += 2 + len;
        if kind != 0 {
            continue;
        }
        if (s.count as usize) < MAX_NAMES && len <= MAX_NAME {
            let i = s.count as usize;
            s.names[i][..len].copy_from_slice(name);
            s.name_len[i] = len as u8;
            s.count += 1;
        } else {
            s.truncated += 1;
        }
    }
}

declare_module_state_bytes!(CleanState);

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<CleanState>()
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
        if state_size < core::mem::size_of::<CleanState>() {
            return -2;
        }
        let s = &mut *(state as *mut CleanState);
        core::ptr::write_bytes(
            core::ptr::from_mut(s).cast::<u8>(),
            0,
            core::mem::size_of::<CleanState>(),
        );
        s.syscalls = syscalls as *const SyscallTable;
        s.dir = -1;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
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
    let s = &mut *(state as *mut CleanState);
    let sys = &*s.syscalls;

    s.since_beat += 1;
    if s.since_beat >= BEAT_STEPS {
        s.since_beat = 0;
        if s.phase >= PH_REMOVE {
            emit_listing(s);
            emit_result(s);
        }
    }

    match s.phase {
        PH_OPEN => {
            let mut root = *b"/";
            let rc = (sys.provider_call)(-1, FS_OPENDIR, root.as_mut_ptr(), root.len());
            if rc == EAGAIN {
                return 0; // the volume is not mounted yet
            }
            if rc < 0 {
                s.last_rc = rc;
                s.phase = PH_DONE;
                emit_result(s);
                return 0;
            }
            s.dir = rc;
            s.phase = PH_READ;
        }
        PH_READ => {
            let rc = (sys.provider_call)(s.dir, FS_READDIR, s.buf.as_mut_ptr(), s.buf.len());
            if rc == EAGAIN {
                return 0;
            }
            if rc > 0 {
                take_batch(s, rc as usize);
                return 0;
            }
            (sys.provider_call)(s.dir, FS_CLOSE, core::ptr::null_mut(), 0);
            s.dir = -1;
            if rc < 0 {
                s.last_rc = rc;
            }
            emit_listing(s);
            s.phase = PH_REMOVE;
        }
        PH_REMOVE => {
            let suffixes = &s.suffixes[..s.suffixes_len as usize];
            while (s.cursor as usize) < s.count as usize {
                let i = s.cursor as usize;
                s.cursor += 1;
                let n = s.name_len[i] as usize;
                if !matches(&s.names[i][..n], suffixes) {
                    continue;
                }
                let mut path = [0u8; MAX_NAME];
                path[..n].copy_from_slice(&s.names[i][..n]);
                if s.backoff > 0 {
                    s.backoff -= 1;
                    s.cursor -= 1;
                    return 0;
                }
                let rc = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), n);
                if rc == EAGAIN {
                    s.cursor -= 1; // the same name, next step
                    return 0;
                }
                if rc == ENOENT || rc >= 0 {
                    // Removed, or already gone.
                    s.removed += u32::from(rc >= 0);
                    s.tries = 0;
                    return 0; // one removal per step
                }
                // Refused: say so, and ask again a little later — a
                // provider still reclaiming the last file's clusters may
                // refuse the next. Give up on a name after RETRIES.
                s.last_rc = rc;
                s.tries += 1;
                if s.tries < RETRIES {
                    s.cursor -= 1;
                    s.backoff = RETRY_STEPS;
                } else {
                    s.failed += 1;
                    s.tries = 0;
                }
                return 0;
            }
            s.phase = PH_DONE;
            emit_result(s);
        }
        _ => {}
    }
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");

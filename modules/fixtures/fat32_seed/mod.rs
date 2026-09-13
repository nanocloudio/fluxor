//! fat32_seed — write one known file to a volume at bring-up.
//!
//! A scenario that wants a file on the device before it runs has two ways to
//! get one: a host mounts the volume and copies it, or something in the graph
//! writes it. The first makes every such scenario depend on a fixture placed
//! out of band, which an unrelated run can destroy — and when it does, the
//! failure looks like broken code rather than a missing file. This is the
//! second.
//!
//! It is an ordinary `fs` consumer: `OPEN_CREATE`, `WRITE`, `FSYNC`, `CLOSE`,
//! `FSYNC_NAME`. It holds no block channel, knows nothing about clusters, and
//! shares no state with the provider — so it cannot contend with the
//! provider's own device access, and it exercises exactly the surface a real
//! consumer uses.
//!
//! Payload is either the inline `data` parameter or, for writes too large to
//! carry inline, a deterministic position-only pattern (`pattern = 1` with
//! `size` set).
//!
//! Reports on a heartbeat rather than once:
//!
//! ```text
//! [fat32_seed] wrote /BOOT.TXT bytes=8192
//! [fat32_seed] FAIL <phase> rc=-<errno>
//! ```
//!
//! A single line is emitted before DHCP binds and lost with the log ring that
//! wraps before any network transport exists.

#![no_std]
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
include!("../../sdk/runtime/params.rs");

const FS_CLOSE: u32 = 0x0903;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_FSYNC_NAME: u32 = 0x0912;

/// Longest path this fixture will address.
const MAX_PATH: usize = 96;
/// Inline payload ceiling. Past this, use `pattern = 1` and `size`.
const MAX_DATA: usize = 8192;
/// Bytes handed to one `WRITE` call — one step's worth of work.
const CHUNK: usize = 512;

const PH_CREATE: u8 = 0;
const PH_WRITE: u8 = 1;
const PH_FSYNC: u8 = 2;
const PH_CLOSE: u8 = 3;
const PH_PUBLISH: u8 = 4;
const PH_DONE: u8 = 5;

const PHASE_NAMES: [&[u8]; 6] = [b"create", b"write", b"fsync", b"close", b"publish", b"done"];

/// Steps between heartbeats — roughly five seconds at a 1 ms tick, matching
/// every other module on the lane.
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
    pattern: u8,
    /// Bytes written so far.
    progress: u32,
    /// Total bytes to write: `size` when set, else the inline length.
    total: u32,
    /// Consecutive steps spent waiting on `EAGAIN`.
    waits: u32,
    since_beat: u32,
    verdict_rc: i32,
    verdict_phase: u8,
    path_len: u8,
    _pad: [u8; 2],
    size_param: u32,
    data_len: u32,
    path: [u8; MAX_PATH],
    data: [u8; MAX_DATA],
}

mod params_def {
    use super::p_u32;
    use super::p_u8;
    use super::SeedState;
    use super::SCHEMA_MAX;

    define_params! {
        SeedState;

        // Absolute path of the file to write, e.g. "/BOOT.TXT".
        1, path, str, 0
            => |s, d, len| {
                if len == 0 || len > super::MAX_PATH { return; }
                let dst = s.path.as_mut_ptr();
                let mut i = 0usize;
                while i < len { *dst.add(i) = *d.add(i); i += 1; }
                s.path_len = len as u8;
            };

        // Inline payload. The TLV encoder splits strings past 255 bytes into
        // repeated entries with the same tag, so this appends rather than
        // overwrites.
        2, data, str, 0
            => |s, d, len| {
                let already = s.data_len as usize;
                let room = super::MAX_DATA.saturating_sub(already);
                let n = if len > room { room } else { len };
                let dst = s.data.as_mut_ptr().add(already);
                let mut i = 0usize;
                while i < n { *dst.add(i) = *d.add(i); i += 1; }
                s.data_len = (already + n) as u32;
            };

        // Byte count to write. Set it with `pattern = 1` for payloads too
        // large to carry inline; when 0 the inline length is used.
        3, size, u32, 0
            => |s, d, len| { s.size_param = p_u32(d, len, 0, 0); };

        // 1 = synthesize each byte from its offset, so the source is
        // unbounded and needs no buffer. 0 = copy the inline `data`.
        4, pattern, u8, 0
            => |s, d, len| { s.pattern = p_u8(d, len, 0, 0); };
    }
}

/// The byte belonging at `off` under the synthetic pattern.
const fn pattern_byte(off: usize) -> u8 {
    (off & 0xFF) as u8
}

unsafe fn emit_ok(s: &SeedState) {
    let mut out = [0u8; 160];
    let mut pos = 0usize;
    let prefix = b"[fat32_seed] wrote ";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    pos += prefix.len();
    let n = s.path_len as usize;
    core::ptr::copy_nonoverlapping(s.path.as_ptr(), out.as_mut_ptr().add(pos), n);
    pos += n;
    let mid = b" bytes=";
    core::ptr::copy_nonoverlapping(mid.as_ptr(), out.as_mut_ptr().add(pos), mid.len());
    pos += mid.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.progress);
    dev_log(&*s.syscalls, 3, out.as_ptr(), pos);
}

unsafe fn emit_fail(s: &SeedState, phase: u8, rc: i32) {
    let mut out = [0u8; 96];
    let mut pos = 0usize;
    let prefix = b"[fat32_seed] FAIL ";
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

unsafe fn fail(s: &mut SeedState, rc: i32) -> i32 {
    s.finished = 1;
    s.failed = 1;
    s.verdict_rc = rc;
    s.verdict_phase = s.phase;
    emit_fail(s, s.phase, rc);
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<SeedState>()
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
        s.total = if s.size_param > 0 {
            s.size_param
        } else {
            s.data_len
        };
        if s.path_len == 0 || s.total == 0 {
            // Nothing declared to write. Idle rather than guess.
            s.finished = 1;
        }
        0
    }
}

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
            } else if s.path_len != 0 {
                emit_ok(s);
            }
        }
    }
    if s.finished != 0 {
        return 0;
    }

    s.waits += 1;
    if s.waits > MAX_WAITS {
        return fail(s, -11);
    }

    let path = core::slice::from_raw_parts(s.path.as_ptr(), s.path_len as usize);

    match s.phase {
        PH_CREATE => {
            let rc = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_ptr().cast_mut(), path.len());
            if rc == -11 {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.fd = rc;
            s.phase = PH_WRITE;
            s.waits = 0;
            0
        }

        PH_WRITE => {
            let off = s.progress as usize;
            let total = s.total as usize;
            if off >= total {
                s.phase = PH_FSYNC;
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
                chunk[i] = if s.pattern != 0 {
                    pattern_byte(off + i)
                } else if off + i < s.data_len as usize {
                    *s.data.as_ptr().add(off + i)
                } else {
                    // Past the inline payload: zero-fill, matching the
                    // declared size.
                    0
                };
                i += 1;
            }
            let rc = (sys.provider_call)(s.fd, FS_WRITE, chunk.as_mut_ptr(), n);
            if rc == -11 {
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
            if rc == -11 {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.phase = PH_CLOSE;
            s.waits = 0;
            0
        }

        PH_CLOSE => {
            let rc = (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
            if rc < 0 {
                return fail(s, rc);
            }
            s.fd = -1;
            s.phase = PH_PUBLISH;
            s.waits = 0;
            0
        }

        PH_PUBLISH => {
            // The bytes are durable; the NAME that finds them is not until
            // this fence lands.
            let rc = (sys.provider_call)(-1, FS_FSYNC_NAME, path.as_ptr().cast_mut(), path.len());
            if rc == -11 {
                return 0;
            }
            if rc < 0 {
                return fail(s, rc);
            }
            s.phase = PH_DONE;
            s.finished = 1;
            emit_ok(s);
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

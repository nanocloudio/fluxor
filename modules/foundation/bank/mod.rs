//! Asset Bank PIC Module — FS_CONTRACT-based playlist player.
//!
//! Selects + streams files from any FS_CONTRACT provider (`fat32` on
//! bare-metal, `linux_fs_dispatch` on the host). Receives FMP commands
//! for navigation; emits audio bytes downstream.
//!
//! # Architecture
//!
//! ```text
//! gesture --[ctrl]--> [bank] --out.0--> decoder ---> i2s
//!                       |  \--out.1--> notifications (FMP)
//!                       v
//!                    FS_CONTRACT (provider_call)
//!                       |
//!                       v
//!                    fat32 / linux_fs_dispatch
//! ```
//!
//! Each path opens via `provider_call(-1, FS_OPEN, path, len)` and the
//! body streams out via `FS_READ`. Files are walked one at a time —
//! the next path opens only after the current FD reaches EOF (or the
//! user issues a navigation command).
//!
//! # Configuration
//!
//! ```yaml
//! - name: bank
//!   item_count: 4              # navigation count (== path count for file mode)
//!   mode: loop                 # once | loop | hold
//!   initial_index: 0
//!   auto_advance: 1            # auto-advance to next on EOF
//!   path_0: "/audio/song1.wav" # zero or more paths; `path_N` selects index N
//!   path_1: "/audio/song2.wav"
//!   ...
//! ```
//!
//! When no `path_*` are set, bank operates in preset-selector mode:
//! navigation works, status notifications fire, but no file bytes
//! flow downstream. Used by `fur_elise.yaml`, `button_control.yaml`,
//! `scale_player_inline.yaml`.
//!
//! # FMP Commands (accepted on `commands` ctrl input)
//!
//!   - `next`   : advance to next index
//!   - `prev`   : retreat to previous index
//!   - `toggle` : pause/resume playback
//!   - `select` : jump to index — payload `[u16 LE]`
//!
//! # FMP Notifications (emitted on out[1])
//!
//!   - `status` : `{ index: u16, count: u16, file_type: u8, flags: u8 }`

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Constants
// ============================================================================

/// FS_READ chunk size. 1 KB matches typical audio decoder buffering and
/// keeps the per-step memcpy cost bounded.
const BUF_SIZE: usize = 1024;

/// Maximum number of paths bank can carry. State footprint is
/// `MAX_PATHS * (MAX_PATH_LEN + 1)` ≈ 1 KB; sized to fit drum-kit
/// (5 hits) and audio-player (full 16-track playlist) configs.
const MAX_PATHS: usize = 16;
/// Maximum bytes per path. Enough for `/audio/longish-name.wav` with
/// nested dirs.
const MAX_PATH_LEN: usize = 64;

const MODE_LOOP: u8 = 1;

/// FS opcodes (mirror of `abi::contracts::storage::fs`).
const FS_OPEN:    u32 = 0x0900;
const FS_READ:    u32 = 0x0901;
const FS_CLOSE:   u32 = 0x0903;
const FS_OPENDIR: u32 = 0x0907;
const FS_READDIR: u32 = 0x0908;

// ============================================================================
// State Machine
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum BankPhase {
    Init = 0,
    Running = 1,
}

// ============================================================================
// State Structure
// ============================================================================

#[repr(C)]
struct BankState {
    syscalls: *const SyscallTable,
    /// Output channels: [0]=audio bytes, [1]=state notifications.
    out_chans: [i32; 2],
    ctrl_chan: i32,

    /// FS_CONTRACT file descriptor for the currently selected path
    /// (-1 when no file is open: between selections, or in preset-
    /// selector mode where no paths are configured).
    fs_fd: i32,

    /// Total navigation positions. Set explicitly via `item_count` /
    /// `file_count` or derived from the count of populated path slots.
    count: u16,
    /// Current navigation index (0..count).
    index: u16,

    /// Module phase — `Init` runs once to seed the first selection,
    /// then `Running` holds steady-state.
    phase: BankPhase,
    /// 1 = paused (no FS_READ; backpressure propagates naturally to
    /// the audio decoder downstream).
    paused: u8,
    /// 1 = on EOF, automatically advance to the next index. 0 = pause
    /// at EOF and wait for an explicit `next`/`prev`/`select`.
    auto_advance: u8,
    /// Navigation mode: `MODE_LOOP` wraps at the end; otherwise stops.
    mode: u8,
    /// Number of active output ports (1 if only audio out, 2 if
    /// notifications also wired). Fixed at module_new.
    out_count: u8,
    _pad0: [u8; 3],

    /// Number of path slots populated. Derived from `path_*` params or
    /// from a successful `dir:` scan. When 0, bank runs in
    /// preset-selector mode (no FS reads).
    path_count: u8,
    /// 1 once `dir`-mode init has completed (success or failure) so we
    /// don't re-scan on every tick if the FS isn't ready yet.
    dir_scanned: u8,
    /// Length of `dir_path`; 0 means dir-scan mode is disabled and the
    /// bank uses enumerated `path_*` params.
    dir_path_len: u8,
    /// Length of `formats`; 0 means accept every file in `dir_path`.
    formats_len: u8,
    /// Absolute directory path to enumerate at init via
    /// `FS_OPENDIR`/`FS_READDIR`. Up to MAX_PATHS entries with names
    /// matching `formats` get copied into `paths[]`.
    dir_path: [u8; MAX_PATH_LEN],
    /// Comma-separated extension filter, e.g. `".mp3,.wav,.aac"` or
    /// `".png,.jpg,.gif,.bmp"`. Empty = accept all. Matching is
    /// case-insensitive (input filenames lowered by the FS provider).
    formats: [u8; 64],
    /// Length of each path in `paths`; 0 means slot empty.
    path_lens: [u8; MAX_PATHS],
    /// Path bytes, one slot per index.
    paths: [[u8; MAX_PATH_LEN]; MAX_PATHS],

    /// Pending write tracking — when a `channel_write` to out[0]
    /// returns short, the residual lives in `buf[pending_offset..
    /// pending_offset + pending_out]` and gets re-flushed before the
    /// next FS_READ.
    pending_out: u16,
    pending_offset: u16,

    /// Working buffer for FS_READ → channel_write hand-off.
    buf: [u8; BUF_SIZE],
    /// Scratch for FMP message payloads (commands).
    msg_buf: [u8; 16],
}

impl BankState {
    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::BankState;
    use super::{p_u8, p_u16};
    use super::SCHEMA_MAX;

    /// Copy a path string into slot `idx` of `s.paths`. Bumps
    /// `path_count` to `idx + 1` if this is a new high-water slot,
    /// so a sparse `path_*` config still produces a contiguous count.
    unsafe fn set_path(s: &mut BankState, idx: usize, d: *const u8, len: usize) {
        if idx >= super::MAX_PATHS { return; }
        let n = if len > super::MAX_PATH_LEN { super::MAX_PATH_LEN } else { len };
        let mut i = 0usize;
        while i < n {
            s.paths[idx][i] = *d.add(i);
            i += 1;
        }
        s.path_lens[idx] = n as u8;
        if n > 0 && (idx as u8) >= s.path_count {
            s.path_count = (idx + 1) as u8;
        }
    }

    define_params! {
        BankState;

        // `file_count` and `item_count` are interchangeable aliases for
        // the navigation count; configs use whichever reads better
        // (path-driven yamls tend to omit both and let the count
        // derive from populated `path_*` slots).
        1, file_count, u16, 0
            => |s, d, len| { s.count = p_u16(d, len, 0, 0); };
        2, mode, u8, 1, enum { once=0, loop=1, hold=2 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 1); };
        3, initial_index, u8, 0
            => |s, d, len| { s.index = p_u8(d, len, 0, 0) as u16; };
        4, auto_advance, u8, 1, enum { off=0, on=1 }
            => |s, d, len| { s.auto_advance = p_u8(d, len, 0, 1); };
        5, item_count, u16, 0
            => |s, d, len| { s.count = p_u16(d, len, 0, 0); };

        10, path_0, str, 0 => |s, d, len| { set_path(s, 0, d, len); };
        11, path_1, str, 0 => |s, d, len| { set_path(s, 1, d, len); };
        12, path_2, str, 0 => |s, d, len| { set_path(s, 2, d, len); };
        13, path_3, str, 0 => |s, d, len| { set_path(s, 3, d, len); };
        14, path_4, str, 0 => |s, d, len| { set_path(s, 4, d, len); };
        15, path_5, str, 0 => |s, d, len| { set_path(s, 5, d, len); };
        16, path_6, str, 0 => |s, d, len| { set_path(s, 6, d, len); };
        17, path_7, str, 0 => |s, d, len| { set_path(s, 7, d, len); };
        18, path_8, str, 0 => |s, d, len| { set_path(s, 8, d, len); };
        19, path_9, str, 0 => |s, d, len| { set_path(s, 9, d, len); };
        20, path_10, str, 0 => |s, d, len| { set_path(s, 10, d, len); };
        21, path_11, str, 0 => |s, d, len| { set_path(s, 11, d, len); };
        22, path_12, str, 0 => |s, d, len| { set_path(s, 12, d, len); };
        23, path_13, str, 0 => |s, d, len| { set_path(s, 13, d, len); };
        24, path_14, str, 0 => |s, d, len| { set_path(s, 14, d, len); };
        25, path_15, str, 0 => |s, d, len| { set_path(s, 15, d, len); };

        // Directory-scan mode — auto-populates `paths[]` from a live
        // FS_READDIR walk at init. Use this for `standard` examples
        // where the user just drops files into `/audio` or `/images`
        // on the SD card (or under cwd on Linux); the bank discovers
        // them on its first tick and cycles through whatever's there.
        // `dir` and `path_*` are mutually exclusive: if both are set
        // the directory scan wins (paths from `dir` overwrite any
        // explicit `path_*`).
        26, dir, str, 0 => |s, d, len| {
            let n = if len > super::MAX_PATH_LEN { super::MAX_PATH_LEN } else { len };
            let mut i = 0usize;
            while i < n { s.dir_path[i] = *d.add(i); i += 1; }
            s.dir_path_len = n as u8;
        };
        // Comma-separated case-insensitive extension filter (e.g.
        // `.mp3,.wav,.aac`). Leave unset (empty) to accept every
        // regular file the FS provider returns. Each entry must start
        // with `.`; lists are tried in order against the trailing
        // bytes of each filename.
        27, formats, str, 0 => |s, d, len| {
            let n = if len > 64 { 64 } else { len };
            let mut i = 0usize;
            while i < n { s.formats[i] = *d.add(i); i += 1; }
            s.formats_len = n as u8;
        };
    }
}

// ============================================================================
// FS helpers
// ============================================================================

#[inline(always)]
unsafe fn log_info(s: &BankState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Close any currently open FD. Used between selections + on
/// auto-advance EOF detection.
#[inline]
unsafe fn fs_close_current(s: &mut BankState) {
    if s.fs_fd >= 0 {
        (s.sys().provider_call)(s.fs_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fs_fd = -1;
    }
}

/// Open the path at slot `idx` via FS_CONTRACT. Returns true on
/// success. Failure leaves `fs_fd = -1`; the next pass-through tick
/// silently produces no bytes (consumer just sees EOF / silence).
#[inline]
unsafe fn fs_open_index(s: &mut BankState, idx: u16) -> bool {
    fs_close_current(s);
    if (idx as usize) >= MAX_PATHS { return false; }
    let n = s.path_lens[idx as usize] as usize;
    if n == 0 { return false; }
    let mut path = [0u8; MAX_PATH_LEN];
    path[..n].copy_from_slice(&s.paths[idx as usize][..n]);
    let fd = (s.sys().provider_call)(-1, FS_OPEN, path.as_mut_ptr(), n);
    if fd < 0 { return false; }
    s.fs_fd = fd;
    // Fresh open → reset any stale pending writes from the previous file.
    s.pending_out = 0;
    s.pending_offset = 0;
    true
}

/// Lowercase ASCII helper (case-insensitive extension match).
#[inline(always)]
fn to_lower(c: u8) -> u8 {
    if (b'A'..=b'Z').contains(&c) { c + 32 } else { c }
}

/// Does `name[..nlen]` end with one of the comma-separated extensions
/// listed in `s.formats[..s.formats_len]`? Case-insensitive. Returns
/// `true` when the formats list is empty (= accept everything).
unsafe fn matches_format(s: &BankState, name: &[u8]) -> bool {
    let flen = s.formats_len as usize;
    if flen == 0 { return true; }
    // Walk comma-separated entries.
    let mut i = 0usize;
    while i < flen {
        // Find this entry's slice [i..end).
        let start = i;
        while i < flen && s.formats[i] != b',' { i += 1; }
        let entry_len = i - start;
        if entry_len > 0 && entry_len <= name.len() {
            let name_tail = &name[name.len() - entry_len..];
            let mut ok = true;
            let mut k = 0usize;
            while k < entry_len {
                if to_lower(name_tail[k]) != to_lower(s.formats[start + k]) {
                    ok = false;
                    break;
                }
                k += 1;
            }
            if ok { return true; }
        }
        // Skip the comma.
        if i < flen && s.formats[i] == b',' { i += 1; }
    }
    false
}

/// Append `parent/name` into the next free `paths[]` slot. Returns
/// `true` if the slot was added (or `false` if `paths[]` is full).
unsafe fn append_path(s: &mut BankState, parent: &[u8], name: &[u8]) -> bool {
    let count = s.path_count as usize;
    if count >= MAX_PATHS { return false; }
    let mut total = parent.len();
    // Insert separator unless parent already ends with '/'.
    let need_sep = !parent.is_empty() && *parent.last().unwrap() != b'/';
    if need_sep { total += 1; }
    total += name.len();
    if total > MAX_PATH_LEN { return false; }
    let mut p = 0usize;
    let mut i = 0usize;
    while i < parent.len() { s.paths[count][p] = parent[i]; p += 1; i += 1; }
    if need_sep { s.paths[count][p] = b'/'; p += 1; }
    let mut j = 0usize;
    while j < name.len() { s.paths[count][p] = name[j]; p += 1; j += 1; }
    s.path_lens[count] = p as u8;
    s.path_count = (count + 1) as u8;
    true
}

/// One-shot directory scan via FS_OPENDIR + FS_READDIR (repeat until
/// empty) + FS_CLOSE. Populates `paths[]` with files under `dir_path`
/// whose names match `formats`. Subdirectories are skipped. Called
/// once during `BankPhase::Init`; failures (provider not ready,
/// directory missing) just leave `path_count == 0`.
unsafe fn fs_scan_dir(s: &mut BankState) {
    if s.dir_path_len == 0 { return; }
    let dlen = s.dir_path_len as usize;
    // Snapshot dir_path into a local so append_path's mutable borrow
    // doesn't clash with reading it back inside the readdir loop.
    let mut dir_path = [0u8; MAX_PATH_LEN];
    dir_path[..dlen].copy_from_slice(&s.dir_path[..dlen]);
    let dir_fd = (s.sys().provider_call)(-1, FS_OPENDIR, dir_path.as_mut_ptr(), dlen);
    if dir_fd < 0 {
        log_info(s, b"[bank] OPENDIR fail");
        return;
    }
    // Reset path table — the scan owns it.
    s.path_count = 0;
    let mut i = 0;
    while i < MAX_PATHS {
        s.path_lens[i] = 0;
        i += 1;
    }
    let mut full = false;
    loop {
        // Use `s.buf` as the readdir output buffer; bank's working
        // buffer is unused during init.
        let n = (s.sys().provider_call)(
            dir_fd, FS_READDIR, s.buf.as_mut_ptr(), BUF_SIZE,
        );
        if n <= 0 { break; }
        let n = n as usize;
        if n < 2 { break; }
        let count = u16::from_le_bytes([s.buf[0], s.buf[1]]) as usize;
        let mut pos = 2usize;
        let mut emitted = 0usize;
        while emitted < count && pos + 2 <= n {
            let name_len = s.buf[pos] as usize;
            let entry_type = s.buf[pos + 1];
            pos += 2;
            if pos + name_len > n { break; }
            let name = core::slice::from_raw_parts(s.buf.as_ptr().add(pos), name_len);
            pos += name_len;
            emitted += 1;
            // Skip subdirectories; bank doesn't recurse.
            if entry_type == 1 { continue; }
            if !matches_format(s, name) { continue; }
            if !append_path(s, &dir_path[..dlen], name) {
                full = true;
                break;
            }
        }
        if full { break; }
        // Provider returned 0 entries with bytes < BUF_SIZE means it
        // just signalled "drained" — leave the loop.
        if count == 0 { break; }
    }
    (s.sys().provider_call)(dir_fd, FS_CLOSE, core::ptr::null_mut(), 0);

    // Sort paths case-insensitively so playback order is stable
    // across FS providers (Linux `readdir` returns inode order, FAT32
    // returns insertion order, neither is human-friendly). Bubble sort
    // is fine — `MAX_PATHS = 16`, so at most 120 comparisons.
    let n = s.path_count as usize;
    let mut i = 0usize;
    while i + 1 < n {
        let mut j = 0usize;
        while j + 1 < n - i {
            // Compare paths[j] vs paths[j+1] case-insensitively.
            let a_len = s.path_lens[j] as usize;
            let b_len = s.path_lens[j + 1] as usize;
            let m = if a_len < b_len { a_len } else { b_len };
            let mut k = 0usize;
            let mut swap = false;
            let mut decided = false;
            while k < m {
                let ac = to_lower(s.paths[j][k]);
                let bc = to_lower(s.paths[j + 1][k]);
                if ac > bc { swap = true; decided = true; break; }
                if ac < bc { decided = true; break; }
                k += 1;
            }
            if !decided && a_len > b_len { swap = true; }
            if swap {
                let tmp_buf = s.paths[j];
                s.paths[j] = s.paths[j + 1];
                s.paths[j + 1] = tmp_buf;
                let tmp_len = s.path_lens[j];
                s.path_lens[j] = s.path_lens[j + 1];
                s.path_lens[j + 1] = tmp_len;
            }
            j += 1;
        }
        i += 1;
    }

    // If the user didn't set `item_count`/`file_count`, derive it
    // from however many paths the scan populated.
    if s.count == 0 {
        s.count = s.path_count as u16;
    }
}

/// Flag the consumer that the current stream has ended (so a decoder
/// flushes its own input ring) — emitted on every transition and on
/// EOF detection.
#[inline]
unsafe fn signal_stream_eof(s: &BankState) {
    if s.out_chans[0] >= 0 {
        dev_channel_ioctl(s.sys(), s.out_chans[0], IOCTL_EOF, core::ptr::null_mut(), 0);
    }
}

// ============================================================================
// Navigation helpers
// ============================================================================

/// Apply the navigation mode to advance `s.index` by `delta` (±1).
/// Returns true if the index actually moved.
#[inline]
unsafe fn navigate(s: &mut BankState, delta: i32) -> bool {
    if s.count == 0 { return false; }
    let cur = s.index as i32;
    let target = cur + delta;
    if target >= 0 && target < s.count as i32 {
        s.index = target as u16;
        return true;
    }
    if s.mode == MODE_LOOP {
        // Wrap.
        if target < 0 { s.index = s.count - 1; }
        else { s.index = 0; }
        return true;
    }
    false
}

/// Send state notification as FMP message on out_chans[1] (if wired).
/// Payload: { index: u16, count: u16, file_type: u8, flags: u8 }.
#[inline]
unsafe fn emit_notification(s: &BankState) {
    if s.out_count < 2 {
        return;
    }
    let chan = s.out_chans[1];
    let poll = (s.sys().channel_poll)(chan, POLL_OUT);
    if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
        let mut payload = [0u8; 6];
        let ib = s.index.to_le_bytes();
        payload[0] = ib[0]; payload[1] = ib[1];
        let cb = s.count.to_le_bytes();
        payload[2] = cb[0]; payload[3] = cb[1];
        payload[4] = 0;
        payload[5] = s.paused;
        msg_write(s.sys(), chan, MSG_STATUS, payload.as_ptr(), 6);
    }
}

/// Common selection update: flush stale stream, OPEN the new index,
/// emit a notification. Used by the next/prev/select commands and by
/// auto-advance.
#[inline]
unsafe fn select_index(s: &mut BankState) {
    signal_stream_eof(s);
    if s.path_count > 0 {
        fs_open_index(s, s.index);
    }
    emit_notification(s);
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<BankState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<BankState>() { return -2; }
        let s = &mut *(state as *mut BankState);
        core::ptr::write_bytes(s as *mut BankState as *mut u8, 0, core::mem::size_of::<BankState>());
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chans[0] = out_chan;
        s.out_chans[1] = dev_channel_port(&*s.syscalls, 1, 1);
        s.out_count = if s.out_chans[1] >= 0 { 2 } else { 1 };
        s.ctrl_chan = ctrl_chan;
        s.fs_fd = -1;
        s.phase = BankPhase::Init;
        s.mode = MODE_LOOP;
        s.auto_advance = 1;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // If no explicit count was set, derive from populated path slots.
        if s.count == 0 && s.path_count > 0 {
            s.count = s.path_count as u16;
        }
        if s.count > 0 && s.index >= s.count {
            s.index = 0;
        }
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut BankState);
        if s.syscalls.is_null() { return -1; }

        // One-shot: scan the configured directory (if any), open the
        // initial path, emit first status.
        if s.phase == BankPhase::Init {
            // `dir:` mode — enumerate the directory and override any
            // explicit `path_*` entries. Runs once; failure (FS not
            // ready, missing dir) is silent — `path_count` stays 0
            // and the consumer just sees EOF.
            if s.dir_path_len > 0 && s.dir_scanned == 0 {
                fs_scan_dir(s);
                s.dir_scanned = 1;
            }
            if s.path_count > 0 && s.count > 0 {
                fs_open_index(s, s.index);
            }
            emit_notification(s);
            log_info(s, b"[bank] init");
            s.phase = BankPhase::Running;
            return 0;
        }

        // Process FMP commands from ctrl_chan.
        if s.ctrl_chan >= 0 {
            let sys = &*s.syscalls;
            let poll_ctrl = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
            if poll_ctrl > 0 && (poll_ctrl as u32 & POLL_IN) != 0 {
                let (ty, _len) = msg_read(sys, s.ctrl_chan, s.msg_buf.as_mut_ptr(), 16);
                match ty {
                    MSG_TOGGLE => {
                        s.paused = if s.paused != 0 { 0 } else { 1 };
                        emit_notification(s);
                    }
                    MSG_NEXT => {
                        if navigate(s, 1) {
                            s.paused = 0;
                            select_index(s);
                        }
                    }
                    MSG_PREV => {
                        if navigate(s, -1) {
                            s.paused = 0;
                            select_index(s);
                        }
                    }
                    MSG_SELECT => {
                        if _len >= 2 {
                            let target = u16::from_le_bytes([s.msg_buf[0], s.msg_buf[1]]);
                            if s.count > 0 && target < s.count {
                                s.index = target;
                                s.paused = 0;
                                select_index(s);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Audio bytes: FS_READ chunks → out_chans[0]. Skipped entirely
        // in preset-selector mode (no paths) or when paused.
        if s.paused == 0 && s.out_chans[0] >= 0 && s.path_count > 0 {
            // Drain any half-flushed buffer from the previous step
            // before issuing another FS_READ.
            if s.pending_out > 0 {
                let sys = &*s.syscalls;
                if !drain_pending(
                    sys, s.out_chans[0],
                    s.buf.as_ptr(),
                    &mut s.pending_out,
                    &mut s.pending_offset,
                ) {
                    return 0;
                }
            }

            if s.fs_fd < 0 {
                // No file open — most likely paused at EOF in `once`
                // mode. Idle until a navigation command opens a fresh
                // file (or until pause is toggled off, which still
                // requires an open fd).
                return 0;
            }

            let poll_out = (s.sys().channel_poll)(s.out_chans[0], POLL_OUT);
            if poll_out <= 0 || (poll_out as u32 & POLL_OUT) == 0 {
                return 0;
            }
            let n = (s.sys().provider_call)(
                s.fs_fd,
                FS_READ,
                s.buf.as_mut_ptr(),
                BUF_SIZE,
            );
            if n > 0 {
                let written = (s.sys().channel_write)(
                    s.out_chans[0],
                    s.buf.as_ptr(),
                    n as usize,
                );
                track_pending(written, n as usize, &mut s.pending_out, &mut s.pending_offset);
                return 2; // Burst — keep stepping while there's data.
            }
            // EAGAIN: provider has no bytes ready but the file isn't
            // finished (async FS provider). Yield and re-read next
            // tick rather than treating "not ready" as EOF.
            if n == -11 {
                return 0;
            }
            // EOF (n == 0) or hard error (n < 0): close and either
            // auto-advance or pause per policy.
            fs_close_current(s);
            signal_stream_eof(s);
            if s.auto_advance != 0 {
                if navigate(s, 1) {
                    select_index(s);
                    log_info(s, b"[bank] auto");
                }
            } else {
                s.paused = 1;
                emit_notification(s);
            }
        }

        0
    }
}

// ============================================================================
// Channel Hints
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 1, port_index: 1, buffer_size: 256 }, // out[1]: bank notifications
        ChannelHint { port_type: 2, port_index: 0, buffer_size: 256 }, // ctrl[0]: control events
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");

// Core: bank_stream — reusable navigation + streaming engine for the `bank`
// family: "select one item from a set and stream its bytes downstream".
//
// Layer: cores (reusable SDK implementation, `include!`d at a consumer
// module's top level so it shares the module's `sdk/runtime` scope —
// `drain_pending`, `track_pending`, `msg_read`, `msg_write`, `dev_log`,
// `dev_millis`, `dev_channel_ioctl`, the `POLL_*` / `IOCTL_*` / `MSG_*`
// opcodes and the `define_params!` machinery). NOT a wire contract.
//
// Owns everything a bank needs that does not depend on the
// storage backend: the `path_*` / `dir` / `formats` param schema, the
// path table + case-insensitive format filter + stable sort, index
// navigation, FMP command handling, the status notification, the
// backpressure-aware output pump (HUP gate, pending-write drain,
// flow-budget tail) and the module entry points. The consumer supplies
// only the storage seam — how a name is opened, how a chunk is read, how
// a handle is closed and how a listing is enumerated — as a small set of
// `unsafe fn` it defines in its own scope:
//
//   unsafe fn backend_close(s: &mut BankState);
//   unsafe fn backend_open_handle(s: &mut BankState, path: *mut u8, len: usize) -> i32;
//   unsafe fn backend_scan(s: &mut BankState);
//   unsafe fn backend_stream(s: &mut BankState) -> ReadOutcome;
//   unsafe fn hb_extra(s: &mut BankState, p: *mut u8, q: usize) -> usize;
//
// The consumer's `backend_scan` populates `paths[]` via the shared
// `append_path` / `matches_format` helpers and calls `finish_scan` to
// sort + derive the count.

// ============================================================================
// Constants
// ============================================================================

/// Read chunk size. 1 KB matches typical audio decoder buffering and
/// keeps the per-step memcpy cost bounded.
const BUF_SIZE: usize = 1024;

/// Maximum number of paths the player can carry. State footprint is
/// `MAX_PATHS * (MAX_PATH_LEN + 1)` ≈ 1 KB; sized to fit drum-kit
/// (5 hits) and audio-player (full 16-track playlist) configs.
const MAX_PATHS: usize = 16;
/// Maximum bytes per path. Enough for `/audio/longish-name.wav` with
/// nested dirs.
const MAX_PATH_LEN: usize = 64;

const MODE_LOOP: u8 = 1;

// ============================================================================
// State Machine
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum BankPhase {
    Init = 0,
    Running = 1,
}

/// Outcome of one `backend_stream` pump. `Yield(code)` means the pump
/// made a decision this step and `module_step` should return `code`
/// immediately (data flowing, backpressure, or a not-ready yield).
/// `EndOfStream` means the current handle reached EOF or a hard error;
/// `module_step` runs the shared close + auto-advance tail.
enum ReadOutcome {
    Yield(i32),
    EndOfStream,
}

// ============================================================================
// State Structure
// ============================================================================

#[repr(C)]
struct BankState {
    syscalls: *const SyscallTable,
    /// Output channels: [0]=stream bytes, [1]=state notifications.
    out_chans: [i32; 2],
    ctrl_chan: i32,

    /// Backend handle for the currently selected path (-1 when nothing
    /// is open: between selections, or in preset-selector mode where no
    /// paths are configured).
    fs_fd: i32,

    /// Total navigation positions. Set explicitly via `item_count` /
    /// `file_count` or derived from the count of populated path slots.
    count: u16,
    /// Current navigation index (0..count).
    index: u16,

    /// Module phase — `Init` runs once to seed the first selection,
    /// then `Running` holds steady-state.
    phase: BankPhase,
    /// 1 = paused (no reads; backpressure propagates naturally to
    /// the decoder downstream).
    paused: u8,
    /// 1 = on EOF, automatically advance to the next index. 0 = pause
    /// at EOF and wait for an explicit `next`/`prev`/`select`.
    auto_advance: u8,
    /// Navigation mode: `MODE_LOOP` wraps at the end; otherwise stops.
    mode: u8,
    /// Number of active output ports (1 if only stream out, 2 if
    /// notifications also wired). Fixed at module_new.
    out_count: u8,
    _pad0: [u8; 3],

    /// Inter-cycle pause in milliseconds. After hitting EOF on the
    /// current file with `auto_advance` on, the player waits this long
    /// before opening the next file. `0` (the default) preserves
    /// legacy back-to-back streaming. Useful for slideshow-style
    /// graphs where a downstream codec needs time to decode/present
    /// the buffered frame before the next one arrives — without it,
    /// the player cycles the directory at channel-write speed (many
    /// MB/s) and consumers exceed their max-bytes ceilings.
    interval_ms: u32,
    /// Absolute monotonic-ms deadline that the next auto-advance is
    /// gated on. `0` means no cooldown active.
    next_advance_ms: u64,

    /// Streaming read cursor for the currently-open handle. Backends
    /// that read at an explicit offset (`storage.object::RANGE_GET`)
    /// advance this; sequential backends (`FS_READ`) leave it 0.
    obj_offset: u64,

    /// Number of path slots populated. Derived from `path_*` params or
    /// from a successful `dir:` scan. When 0, the player runs in
    /// preset-selector mode (no reads).
    path_count: u8,
    /// 1 once `dir`-mode init has completed (success or failure) so we
    /// don't re-scan on every tick if the backend isn't ready yet.
    dir_scanned: u8,
    /// Length of `dir_path`; 0 means dir-scan mode is disabled and the
    /// player uses enumerated `path_*` params.
    dir_path_len: u8,
    /// Length of `formats`; 0 means accept every entry in `dir_path`.
    formats_len: u8,
    /// Absolute directory / prefix to enumerate at init. Up to
    /// MAX_PATHS entries with names matching `formats` get copied into
    /// `paths[]`.
    dir_path: [u8; MAX_PATH_LEN],
    /// Comma-separated extension filter, e.g. `".mp3,.wav,.aac"` or
    /// `".png,.jpg,.gif,.bmp"`. Empty = accept all. Matching is
    /// case-insensitive (input filenames lowered by the provider).
    formats: [u8; 64],
    /// Length of each path in `paths`; 0 means slot empty.
    path_lens: [u8; MAX_PATHS],
    /// Path bytes, one slot per index.
    paths: [[u8; MAX_PATH_LEN]; MAX_PATHS],

    /// Pending write tracking — when a `channel_write` to out[0]
    /// returns short, the residual lives in `buf[pending_offset..
    /// pending_offset + pending_out]` and gets re-flushed before the
    /// next read.
    pending_out: u16,
    pending_offset: u16,

    /// Working buffer for read → channel_write hand-off.
    buf: [u8; BUF_SIZE],
    /// Scratch for FMP message payloads (commands).
    msg_buf: [u8; 16],

    /// Tick counter for periodic diagnostics. Wraps freely.
    tick_count: u32,

    /// Bytes written to `out_chans[0]`. Surfaced in the heartbeat
    /// so an operator can see whether the producer side is flowing.
    total_bytes_emitted: u32,
    /// `total_bytes_emitted` at the previous heartbeat + consecutive
    /// heartbeats with no byte progress while a file is open — the
    /// heartbeat's `stall=` field. Non-zero with `paused=0` and a
    /// valid fd means the downstream is not draining.
    hb_last_bytes: u32,
    hb_stall: u16,
    /// FMP commands consumed from `ctrl_chan` (toggle / next / prev
    /// / select). Counterpart to `total_bytes_emitted` for the
    /// consumer side.
    total_cmds_seen: u16,
    _pad1: [u8; 2],
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
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u32, p_u8};

    /// Copy a path string into slot `idx` of `s.paths`. Bumps
    /// `path_count` to `idx + 1` if this is a new high-water slot,
    /// so a sparse `path_*` config still produces a contiguous count.
    unsafe fn set_path(s: &mut BankState, idx: usize, d: *const u8, len: usize) {
        if idx >= super::MAX_PATHS {
            return;
        }
        let n = if len > super::MAX_PATH_LEN {
            super::MAX_PATH_LEN
        } else {
            len
        };
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
        6, interval_ms, u32, 0
            => |s, d, len| { s.interval_ms = p_u32(d, len, 0, 0); };

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
        // enumeration at init. Use this for `standard` examples
        // where the user just drops files into `/audio` or `/images`
        // on the SD card (or under cwd on Linux); the player discovers
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
        // regular entry the provider returns. Each entry must start
        // with `.`; lists are tried in order against the trailing
        // bytes of each filename.
        27, formats, str, 0 => |s, d, len| {
            let n = if len > 64 { 64 } else { len };
            let mut i = 0usize;
            while i < n { s.formats[i] = *d.add(i); i += 1; }
            s.formats_len = n as u8;
        };

        // Initial paused state. Default 0 = start streaming
        // immediately. Audio players set this to 1 so the first user
        // tap unpauses (and, on the wasm target, unlocks the browser
        // AudioContext) instead of pausing an already-running stream.
        28, paused, u8, 0, enum { running=0, paused=1 }
            => |s, d, len| { s.paused = p_u8(d, len, 0, 0); };
    }
}

// ============================================================================
// Shared helpers
// ============================================================================

#[inline(always)]
unsafe fn log_info(s: &BankState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Open the path at slot `idx` via the backend. Returns true on
/// success. Failure leaves `fs_fd = -1`; the next pass-through tick
/// silently produces no bytes (consumer just sees EOF / silence).
#[inline]
unsafe fn fs_open_index(s: &mut BankState, idx: u16) -> bool {
    backend_close(s);
    if (idx as usize) >= MAX_PATHS {
        return false;
    }
    let n = s.path_lens[idx as usize] as usize;
    if n == 0 {
        return false;
    }
    let mut path = [0u8; MAX_PATH_LEN];
    path[..n].copy_from_slice(&s.paths[idx as usize][..n]);
    let fd = backend_open_handle(s, path.as_mut_ptr(), n);
    if fd < 0 {
        return false;
    }
    s.fs_fd = fd;
    // Fresh open: drop any stale pending writes from the previous
    // file. The output channel's HUP flag is left alone — its only
    // setter is `select_index`, which is the boundary signal the
    // consumer waits on.
    s.pending_out = 0;
    s.pending_offset = 0;
    true
}

/// Lowercase ASCII helper (case-insensitive extension match).
#[inline(always)]
fn to_lower(c: u8) -> u8 {
    if c.is_ascii_uppercase() {
        c + 32
    } else {
        c
    }
}

/// Does `name` end with one of the comma-separated extensions listed in
/// `s.formats[..s.formats_len]`? Case-insensitive. Returns `true` when
/// the formats list is empty (= accept everything).
unsafe fn matches_format(s: &BankState, name: &[u8]) -> bool {
    let flen = s.formats_len as usize;
    if flen == 0 {
        return true;
    }
    // Walk comma-separated entries.
    let mut i = 0usize;
    while i < flen {
        // Find this entry's slice [i..end).
        let start = i;
        while i < flen && s.formats[i] != b',' {
            i += 1;
        }
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
            if ok {
                return true;
            }
        }
        // Skip the comma.
        if i < flen && s.formats[i] == b',' {
            i += 1;
        }
    }
    false
}

/// Append `parent/name` into the next free `paths[]` slot. Returns
/// `true` if the slot was added (or `false` if `paths[]` is full).
unsafe fn append_path(s: &mut BankState, parent: &[u8], name: &[u8]) -> bool {
    let count = s.path_count as usize;
    if count >= MAX_PATHS {
        return false;
    }
    let mut total = parent.len();
    // Insert separator unless parent already ends with '/'.
    let need_sep = parent.last().is_some_and(|&b| b != b'/');
    if need_sep {
        total += 1;
    }
    total += name.len();
    if total > MAX_PATH_LEN {
        return false;
    }
    let mut p = 0usize;
    let mut i = 0usize;
    while i < parent.len() {
        s.paths[count][p] = parent[i];
        p += 1;
        i += 1;
    }
    if need_sep {
        s.paths[count][p] = b'/';
        p += 1;
    }
    let mut j = 0usize;
    while j < name.len() {
        s.paths[count][p] = name[j];
        p += 1;
        j += 1;
    }
    s.path_lens[count] = p as u8;
    s.path_count = (count + 1) as u8;
    true
}

/// Finalise a backend directory scan: sort the populated `paths[]`
/// case-insensitively so playback order is stable across providers
/// (Linux `readdir` returns inode order, FAT32 returns insertion order,
/// neither is human-friendly), then derive `count` from the scan if the
/// user didn't set `item_count`/`file_count`. Bubble sort is fine —
/// `MAX_PATHS = 16`, so at most 120 comparisons.
unsafe fn finish_scan(s: &mut BankState) {
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
                if ac > bc {
                    swap = true;
                    decided = true;
                    break;
                }
                if ac < bc {
                    decided = true;
                    break;
                }
                k += 1;
            }
            if !decided && a_len > b_len {
                swap = true;
            }
            if swap {
                s.paths.swap(j, j + 1);
                s.path_lens.swap(j, j + 1);
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
    if s.count == 0 {
        return false;
    }
    let cur = s.index as i32;
    let target = cur + delta;
    if target >= 0 && target < s.count as i32 {
        s.index = target as u16;
        return true;
    }
    if s.mode == MODE_LOOP {
        // Wrap.
        if target < 0 {
            s.index = s.count - 1;
        } else {
            s.index = 0;
        }
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
        payload[0] = ib[0];
        payload[1] = ib[1];
        let cb = s.count.to_le_bytes();
        payload[2] = cb[0];
        payload[3] = cb[1];
        payload[4] = 0;
        payload[5] = s.paused;
        msg_write(s.sys(), chan, MSG_STATUS, payload.as_ptr(), 6);
    }
}

/// Close the previous stream and open the index in `s.index`.
///
/// `flush` toggles whether the output channel's unread tail is
/// dropped before HUP is raised:
///
/// - **User navigation** (`true`): the user has interrupted the
///   current track. Any of its unread bytes still buffered in the
///   ring would be decoded as a continuation of the previous
///   stream. Drop them so the consumer sees the boundary cleanly.
///   IOCTL_FLUSH also clears HUP, so `signal_stream_eof` re-arms
///   it immediately.
///
/// - **Auto-advance** (`false`): the previous stream ended at EOF.
///   The consumer is allowed to drain whatever is queued in the
///   ring before HUP triggers its reset.
#[inline]
unsafe fn select_index(s: &mut BankState, flush: bool) {
    if flush && s.out_chans[0] >= 0 {
        dev_channel_ioctl(
            s.sys(),
            s.out_chans[0],
            IOCTL_FLUSH,
            core::ptr::null_mut(),
            0,
        );
    }
    signal_stream_eof(s);
    if s.path_count > 0 {
        fs_open_index(s, s.index);
    }
    emit_notification(s);
}

// ============================================================================
// Module API
// ============================================================================

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<BankState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
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
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<BankState>() {
            return -2;
        }
        let s = &mut *(state as *mut BankState);
        core::ptr::write_bytes(
            s as *mut BankState as *mut u8,
            0,
            core::mem::size_of::<BankState>(),
        );
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chans[0] = out_chan;
        s.out_chans[1] = dev_channel_port(&*s.syscalls, 1, 1);
        s.out_count = if s.out_chans[1] >= 0 { 2 } else { 1 };
        s.ctrl_chan = ctrl_chan;
        s.fs_fd = -1;
        s.phase = BankPhase::Init;
        s.mode = MODE_LOOP;
        s.auto_advance = 1;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
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

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut BankState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Periodic heartbeat (~500 ms at tick_us=100). Surfaces
        // the player's state to log_net once it starts draining over
        // UDP, covering the case where `[bank] init` got dropped from
        // the early-boot ring before DHCP came up. Same cadence +
        // format as `[fat32] hb`.
        s.tick_count = s.tick_count.wrapping_add(1);
        if s.tick_count.is_multiple_of(5000) {
            let mut buf = [0u8; 96];
            let p = buf.as_mut_ptr();
            let pfx = b"[bank] hb phase=";
            let mut q = 0usize;
            let mut t = 0;
            while t < pfx.len() {
                *p.add(q) = pfx[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.phase as u32);
            let pc = b" path_count=";
            let mut t = 0;
            while t < pc.len() {
                *p.add(q) = pc[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.path_count as u32);
            let cn = b" count=";
            let mut t = 0;
            while t < cn.len() {
                *p.add(q) = cn[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.count as u32);
            let ix = b" idx=";
            let mut t = 0;
            while t < ix.len() {
                *p.add(q) = ix[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.index as u32);
            let fd = b" fd=";
            let mut t = 0;
            while t < fd.len() {
                *p.add(q) = fd[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.fs_fd as u32);
            let ps = b" paused=";
            let mut t = 0;
            while t < ps.len() {
                *p.add(q) = ps[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.paused as u32);
            let be = b" bytes=";
            let mut t = 0;
            while t < be.len() {
                *p.add(q) = be[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.total_bytes_emitted);
            let cm = b" cmd_rx=";
            let mut t = 0;
            while t < cm.len() {
                *p.add(q) = cm[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.total_cmds_seen as u32);
            let cc = b" ctrl=";
            let mut t = 0;
            while t < cc.len() {
                *p.add(q) = cc[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), s.ctrl_chan as u32);
            // Backend-specific heartbeat tail (e.g. the `stall=` field).
            q += hb_extra(s, p, q);
            dev_log(s.sys(), 3, p, q);
        }

        // One-shot: scan the configured directory (if any), open the
        // initial path, emit first status.
        if s.phase == BankPhase::Init {
            // `dir:` mode — enumerate the directory and override any
            // explicit `path_*` entries. Runs once; failure (backend
            // not ready, missing dir) is silent — `path_count` stays 0
            // and the consumer just sees EOF.
            if s.dir_path_len > 0 && s.dir_scanned == 0 {
                backend_scan(s);
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

        // Lazy retry — on bare-metal targets the provider (fat32)
        // reads the boot sector + GPT entries + FAT chain before
        // reaching `Done`, which can take several hundred ms. The
        // player's `Init` may fire before the provider is ready; the
        // open/enumerate returns E_AGAIN, fs_fd stays -1 and path_count
        // stays 0. Without retry the player sits idle forever waiting
        // for a nav command that never comes. Retry every 500 ticks
        // (~50 ms at tick_us=100) until we get a real fd / path list.
        if s.tick_count.is_multiple_of(500) {
            // Dir-mode retry: re-scan the configured directory until
            // it returns at least one entry. `dir_scanned` is reset
            // here to force a fresh enumeration pass — the prior
            // failed scan latched it to 1.
            if s.dir_path_len > 0 && s.path_count == 0 {
                s.dir_scanned = 0;
                backend_scan(s);
                s.dir_scanned = 1;
                if s.count == 0 && s.path_count > 0 {
                    s.count = s.path_count as u16;
                }
            }
            // Path-mode retry: re-open the selected index when fs_fd
            // is unset and we have at least one configured path.
            if s.fs_fd < 0 && s.path_count > 0 && s.count > 0 {
                fs_open_index(s, s.index);
            }
        }

        // Process FMP commands from ctrl_chan.
        if s.ctrl_chan >= 0 {
            let sys = &*s.syscalls;
            let poll_ctrl = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
            if poll_ctrl > 0 && (poll_ctrl as u32 & POLL_IN) != 0 {
                let (ty, _len) = msg_read(sys, s.ctrl_chan, s.msg_buf.as_mut_ptr(), 16);
                s.total_cmds_seen = s.total_cmds_seen.saturating_add(1);
                match ty {
                    MSG_TOGGLE => {
                        log_info(s, b"[bank] MSG_TOGGLE");
                        s.paused = if s.paused != 0 { 0 } else { 1 };
                        emit_notification(s);
                    }
                    MSG_NEXT => {
                        log_info(s, b"[bank] MSG_NEXT");
                        if navigate(s, 1) {
                            s.paused = 0;
                            select_index(s, /*flush=*/ true);
                        } else {
                            log_info(s, b"[bank] navigate denied");
                        }
                    }
                    MSG_PREV => {
                        log_info(s, b"[bank] MSG_PREV");
                        if navigate(s, -1) {
                            s.paused = 0;
                            select_index(s, /*flush=*/ true);
                        }
                    }
                    MSG_SELECT => {
                        if _len >= 2 {
                            let target = u16::from_le_bytes([s.msg_buf[0], s.msg_buf[1]]);
                            if s.count > 0 && target < s.count {
                                s.index = target;
                                s.paused = 0;
                                select_index(s, /*flush=*/ true);
                            }
                        }
                    }
                    _ => {
                        // Unknown verb — log the type byte so an
                        // operator can distinguish a producer error
                        // (unrecognised verb) from channel-framing
                        // damage (partial write seen as garbage).
                        let mut buf = [0u8; 32];
                        let p = buf.as_mut_ptr();
                        let pfx = b"[bank] unk ty=";
                        let mut q = 0usize;
                        let mut t = 0;
                        while t < pfx.len() {
                            *p.add(q) = pfx[t];
                            q += 1;
                            t += 1;
                        }
                        q += fmt_u32_raw(p.add(q), ty);
                        dev_log(s.sys(), 3, p, q);
                    }
                }
            }
        }

        // Wake from inter-cycle pause: if the cooldown deadline has
        // passed, advance to the next file and resume streaming.
        // The player stays paused until the deadline so downstream
        // consumers have unstrained channel time to drain the
        // previously-buffered bytes.
        if s.paused != 0 && s.next_advance_ms > 0 {
            let now = dev_millis(s.sys());
            if now >= s.next_advance_ms {
                s.next_advance_ms = 0;
                s.paused = 0;
                if navigate(s, 1) {
                    select_index(s, /*flush=*/ false);
                    log_info(s, b"[bank] auto (paced)");
                }
            }
        }

        // Stream bytes: backend chunks → out_chans[0]. Skipped entirely
        // in preset-selector mode (no paths) or when paused.
        if s.paused == 0 && s.out_chans[0] >= 0 && s.path_count > 0 {
            // Hold off until the consumer has acknowledged any
            // pending stream boundary. HUP is sticky on the shared
            // channel slot; the consumer clears it via IOCTL_FLUSH
            // at the end of its reset path. Skipping this gate
            // would append the next file's bytes to the previous
            // stream's tail in the same ring — the consumer (still
            // bound to the previous stream's sub-decoder) would
            // then decode them under the wrong format.
            if (s.sys().channel_poll)(s.out_chans[0], POLL_HUP) > 0 {
                return 0;
            }
            // Drain any half-flushed buffer from the previous step
            // before issuing another read.
            if s.pending_out > 0 {
                let sys = &*s.syscalls;
                if !drain_pending(
                    sys,
                    s.out_chans[0],
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

            // Backend read pump: moves chunks and reports whether to
            // yield now or run the shared end-of-stream tail.
            match backend_stream(s) {
                ReadOutcome::Yield(code) => return code,
                ReadOutcome::EndOfStream => {}
            }

            // EOF or hard error: close and either auto-advance or pause
            // per policy.
            backend_close(s);
            signal_stream_eof(s);
            if s.auto_advance != 0 {
                // Optional inter-cycle pause — gives downstream
                // consumers (image codec, audio decoder) time to
                // drain the buffered file's bytes before the player
                // pushes the next file. Without this, the player
                // streams at channel-write speed and consumers can
                // exceed their max-bytes ceilings (see
                // host_image_codec's 16 MiB limit). `interval_ms = 0`
                // keeps legacy back-to-back behaviour.
                if s.interval_ms > 0 {
                    let now = dev_millis(s.sys());
                    s.next_advance_ms = now.saturating_add(s.interval_ms as u64);
                    s.paused = 1;
                } else if navigate(s, 1) {
                    select_index(s, /*flush=*/ false);
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

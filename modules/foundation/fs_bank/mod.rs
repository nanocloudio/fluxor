//! FS Asset Bank PIC Module — FS_CONTRACT-backed asset bank.
//!
//! Selects + streams files from any FS_CONTRACT provider (`fat32` on
//! bare-metal, `linux_fs_dispatch` on the host). Receives FMP commands
//! for navigation; emits audio bytes downstream.
//!
//! # Architecture
//!
//! ```text
//! gesture --[ctrl]--> [fs_bank] --out.0--> decoder ---> i2s
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
//! The navigation, FMP-command, param and streaming machinery lives in
//! the shared [`sdk/cores/bank_stream`](../../sdk/cores/bank_stream.rs)
//! core; this module supplies only the FS_CONTRACT storage seam.
//!
//! # Configuration
//!
//! ```yaml
//! - name: bank                 # instance name; `type: fs_bank` selects this module
//!   type: fs_bank
//!   item_count: 4              # navigation count (== path count for file mode)
//!   mode: loop                 # once | loop | hold
//!   initial_index: 0
//!   auto_advance: 1            # auto-advance to next on EOF
//!   path_0: "/audio/song1.wav" # zero or more paths; `path_N` selects index N
//!   path_1: "/audio/song2.wav"
//!   ...
//! ```
//!
//! When no `path_*` are set, fs_bank operates in preset-selector mode:
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

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

// Host-test builds skip the SDK's PIC EABI intrinsic stubs (which
// are gated to `target_os = "none"` / `wasm32`); provide a host
// fallback for the one intrinsic the audio sub-codecs reach for.
#[cfg(feature = "host-test")]
pub unsafe fn __aeabi_memclr(dest: *mut u8, n: usize) {
    core::ptr::write_bytes(dest, 0, n);
}

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/cores/bank_stream.rs");

// ============================================================================
// FS_CONTRACT storage seam
// ============================================================================

/// FS opcodes (mirror of `abi::contracts::storage::fs`).
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_CLOSE: u32 = 0x0903;
const FS_OPENDIR: u32 = 0x0907;
const FS_READDIR: u32 = 0x0908;

/// Close any currently open FD. Used between selections + on
/// auto-advance EOF detection.
#[inline]
unsafe fn backend_close(s: &mut BankState) {
    if s.fs_fd >= 0 {
        (s.sys().provider_call)(s.fs_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fs_fd = -1;
    }
}

/// Open a path via FS_OPEN. Returns the file descriptor (`< 0` on error).
#[inline]
unsafe fn backend_open_handle(s: &mut BankState, path: *mut u8, len: usize) -> i32 {
    (s.sys().provider_call)(-1, FS_OPEN, path, len)
}

/// One-shot directory scan via FS_OPENDIR + FS_READDIR (repeat until
/// empty) + FS_CLOSE. Populates `paths[]` with files under `dir_path`
/// whose names match `formats`. Subdirectories are skipped. Called
/// once during `BankPhase::Init`; failures (provider not ready,
/// directory missing) just leave `path_count == 0`.
unsafe fn backend_scan(s: &mut BankState) {
    if s.dir_path_len == 0 {
        return;
    }
    let dlen = s.dir_path_len as usize;
    // Snapshot dir_path into a local so append_path's mutable borrow
    // doesn't clash with reading it back inside the readdir loop.
    let mut dir_path = [0u8; MAX_PATH_LEN];
    dir_path[..dlen].copy_from_slice(&s.dir_path[..dlen]);
    let dir_fd = (s.sys().provider_call)(-1, FS_OPENDIR, dir_path.as_mut_ptr(), dlen);
    if dir_fd < 0 {
        // E_AGAIN is the transient "FS provider not yet Done" reply
        // from fat32 during boot; the retry block re-invokes us so
        // logging it would flood log_net. Real errors (ENOENT,
        // ENFILE, …) still surface.
        if dir_fd != -11 {
            log_info(s, b"[fs_bank] OPENDIR fail");
        }
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
        // Use `s.buf` as the readdir output buffer; the working
        // buffer is unused during init.
        let n = (s.sys().provider_call)(dir_fd, FS_READDIR, s.buf.as_mut_ptr(), BUF_SIZE);
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if n < 2 {
            break;
        }
        let count = u16::from_le_bytes([s.buf[0], s.buf[1]]) as usize;
        let mut pos = 2usize;
        let mut emitted = 0usize;
        while emitted < count && pos + 2 <= n {
            let name_len = s.buf[pos] as usize;
            let entry_type = s.buf[pos + 1];
            pos += 2;
            if pos + name_len > n {
                break;
            }
            let name = core::slice::from_raw_parts(s.buf.as_ptr().add(pos), name_len);
            pos += name_len;
            emitted += 1;
            // Skip subdirectories; fs_bank doesn't recurse.
            if entry_type == 1 {
                continue;
            }
            if !matches_format(s, name) {
                continue;
            }
            if !append_path(s, &dir_path[..dlen], name) {
                full = true;
                break;
            }
        }
        if full {
            break;
        }
        // Provider returned 0 entries with bytes < BUF_SIZE means it
        // just signalled "drained" — leave the loop.
        if count == 0 {
            break;
        }
    }
    (s.sys().provider_call)(dir_fd, FS_CLOSE, core::ptr::null_mut(), 0);

    finish_scan(s);
}

/// Stream one budget's worth of FS_READ chunks to `out_chans[0]`.
///
/// The per-step transfer budget comes from the edge's rate class
/// (MODULE_FLOW_BUDGET). Unclassed (control) edges get 0 → one chunk
/// per step, the pacing the audio graphs are tuned around. Media graphs
/// declare `rate:` on the stream edge and get a cadence-derived grant.
unsafe fn backend_stream(s: &mut BankState) -> ReadOutcome {
    let grant = dev_flow_budget(s.sys(), 0);
    let budget = if grant == 0 {
        1
    } else {
        (grant as usize).div_ceil(BUF_SIZE).clamp(1, 64)
    };
    let mut moved_any = false;
    let mut n: i32 = 0;
    let mut hit_eof_or_err = false;
    for _ in 0..budget {
        let poll_out = (s.sys().channel_poll)(s.out_chans[0], POLL_OUT);
        if poll_out <= 0 || (poll_out as u32 & POLL_OUT) == 0 {
            return ReadOutcome::Yield(if moved_any { 2 } else { 0 });
        }
        n = (s.sys().provider_call)(s.fs_fd, FS_READ, s.buf.as_mut_ptr(), BUF_SIZE);
        if n > 0 {
            let written = (s.sys().channel_write)(s.out_chans[0], s.buf.as_ptr(), n as usize);
            if written > 0 {
                s.total_bytes_emitted = s.total_bytes_emitted.saturating_add(written as u32);
            }
            track_pending(written, n as usize, &mut s.pending_out, &mut s.pending_offset);
            if (written as usize) < n as usize {
                // Ring filled mid-chunk; drain_pending picks up the
                // tail next step.
                return ReadOutcome::Yield(2);
            }
            moved_any = true;
            continue;
        }
        hit_eof_or_err = true;
        break;
    }
    if !hit_eof_or_err {
        return ReadOutcome::Yield(2); // Budget exhausted with data still flowing.
    }
    // EAGAIN: provider has no bytes ready but the file isn't finished
    // (async FS provider). Yield and re-read next tick rather than
    // treating "not ready" as EOF.
    if n == -11 {
        return ReadOutcome::Yield(if moved_any { 2 } else { 0 });
    }
    ReadOutcome::EndOfStream
}

/// Heartbeat tail: appends the `stall=` field — consecutive heartbeats
/// with no byte progress while a file is open (0 = flowing).
unsafe fn hb_extra(s: &mut BankState, p: *mut u8, q: usize) -> usize {
    let start = q;
    let mut q = q;
    if s.fs_fd >= 0 && s.total_bytes_emitted == s.hb_last_bytes {
        s.hb_stall = s.hb_stall.saturating_add(1);
    } else {
        s.hb_stall = 0;
    }
    s.hb_last_bytes = s.total_bytes_emitted;
    let st = b" stall=";
    let mut t = 0;
    while t < st.len() {
        *p.add(q) = st[t];
        q += 1;
        t += 1;
    }
    q += fmt_u32_raw(p.add(q), s.hb_stall as u32);
    q - start
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");

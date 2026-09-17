//! Object Bank PIC Module — storage.namespace/object asset bank.
//!
//! A sibling of [`foundation/fs_bank`](../fs_bank): identical navigation,
//! FMP-command, and streaming machinery (shared via the
//! [`sdk/cores/bank_stream`](../../sdk/cores/bank_stream.rs)
//! core), but its backend is swapped from the `fs` contract to the
//! **storage** surfaces — it enumerates a prefix via
//! `storage.namespace::LIST` and streams each entry via
//! `storage.object::GET`/`RANGE_GET`. On the wasm host both resolve to
//! the OPFS-backed `objStore` (plus a fetched manifest), so the shipped
//! `bank → codec → audio_out` player runs against a *persistent,
//! user-populatable* library instead of only bundle-baked `asset://`
//! tracks. On any host with a `storage.namespace`+`storage.object`
//! provider pair the same module works unchanged.
//!
//! # Architecture
//!
//! ```text
//! gesture --[ctrl]--> [object_bank] --out.0--> decoder ---> sink
//!                       |  \--out.1--> notifications (FMP)
//!                       v
//!            storage.namespace (LIST) + storage.object (GET/RANGE_GET)
//!                       |
//!                       v
//!              OPFS objStore + manifest (wasm) / any index+object pair
//! ```
//!
//! Each entry opens via `provider_call(-1, OBJ_GET, key, len)` and the
//! body streams out via `OBJ_RANGE_GET` at an advancing offset. Entries
//! are walked one at a time — the next opens only after the current
//! handle reaches EOF (or the user issues a navigation command).
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
// storage.namespace / storage.object storage seam
// ============================================================================

/// storage.namespace opcodes (enumerate) + storage.object opcodes
/// (stream). Mirror of `abi::contracts::storage::{namespace,object}`.
const NS_LOOKUP: u32 = 0x1300;
const NS_LIST: u32 = 0x1302;
const NS_CLOSE: u32 = 0x1306;
const OBJ_GET: u32 = 0x1421;
const OBJ_RANGE_GET: u32 = 0x1423;
const OBJ_CLOSE: u32 = 0x1425;

/// Close any currently open handle. Used between selections + on
/// auto-advance EOF detection.
#[inline]
unsafe fn backend_close(s: &mut BankState) {
    if s.fs_fd >= 0 {
        // storage.object consumers free BOTH the provider-side slot
        // (OBJ_CLOSE) and the kernel routing entry (provider_close) —
        // a per-track GET leaks a slot otherwise.
        (s.sys().provider_call)(s.fs_fd, OBJ_CLOSE, core::ptr::null_mut(), 0);
        (s.sys().provider_close)(s.fs_fd);
        s.fs_fd = -1;
    }
    s.obj_offset = 0;
}

/// Open an object key via OBJ_GET. Returns the handle (`< 0` on error)
/// and resets the read cursor.
#[inline]
unsafe fn backend_open_handle(s: &mut BankState, path: *mut u8, len: usize) -> i32 {
    let fd = (s.sys().provider_call)(-1, OBJ_GET, path, len);
    if fd >= 0 {
        s.obj_offset = 0;
    }
    fd
}

/// One-shot prefix scan via NS_LOOKUP (readiness gate) + NS_LIST
/// (repeat until the cursor is exhausted) + NS_CLOSE. Populates
/// `paths[]` with objects under `dir_path` whose names match `formats`.
/// Sub-namespaces are skipped. Called once during `BankPhase::Init`;
/// failures (provider not ready, prefix missing) just leave
/// `path_count == 0`.
unsafe fn backend_scan(s: &mut BankState) {
    if s.dir_path_len == 0 {
        return;
    }
    let dlen = s.dir_path_len as usize;
    // Snapshot dir_path into a local so append_path's mutable borrow
    // doesn't clash with reading it back inside the readdir loop.
    let mut dir_path = [0u8; MAX_PATH_LEN];
    dir_path[..dlen].copy_from_slice(&s.dir_path[..dlen]);
    // LOOKUP the prefix purely as a readiness gate: the wasm namespace
    // index is hydrated asynchronously, so a LOOKUP issued before it is
    // ready returns negative — the caller's retry loop re-invokes us.
    // The handle itself is NOT passed to LIST: the public contract
    // (`storage::namespace::LIST`) mandates `handle = -1` and carries the
    // prefix in the request arg, so a conforming provider would reject a
    // handle-scoped LIST. (The wasm provider ignores the handle, so the
    // old code worked there by accident.)
    let handle = (s.sys().provider_call)(-1, NS_LOOKUP, dir_path.as_mut_ptr(), dlen);
    if handle < 0 {
        if handle != -11 {
            log_info(s, b"[object_bank] LOOKUP fail");
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
    // Opaque ≤32-byte cursor; our namespace provider encodes it as a
    // 4-byte LE page index. 0 bytes = first page.
    let mut cursor = [0u8; 4];
    let mut cursor_len = 0usize;
    let mut fence = [0u8; 64]; // >= fence::WIRE_MAX_LEN (62)
    let mut full = false;
    loop {
        // Build the LIST arg (mirrors storage::namespace::LIST):
        //   [prefix_len:u16][prefix][cursor_len:u16][cursor]
        //   [out_ptr:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]
        let mut arg = [0u8; 2 + MAX_PATH_LEN + 2 + 4 + 8 + 4 + 8 + 2];
        let mut p = 0usize;
        arg[p..p + 2].copy_from_slice(&(dlen as u16).to_le_bytes());
        p += 2;
        arg[p..p + dlen].copy_from_slice(&dir_path[..dlen]);
        p += dlen;
        arg[p..p + 2].copy_from_slice(&(cursor_len as u16).to_le_bytes());
        p += 2;
        arg[p..p + cursor_len].copy_from_slice(&cursor[..cursor_len]);
        p += cursor_len;
        let out_ptr = s.buf.as_mut_ptr() as u64;
        arg[p..p + 8].copy_from_slice(&out_ptr.to_le_bytes());
        p += 8;
        arg[p..p + 4].copy_from_slice(&(BUF_SIZE as u32).to_le_bytes());
        p += 4;
        let fence_ptr = fence.as_mut_ptr() as u64;
        arg[p..p + 8].copy_from_slice(&fence_ptr.to_le_bytes());
        p += 8;
        arg[p..p + 2].copy_from_slice(&(fence.len() as u16).to_le_bytes());
        p += 2;

        // Contract: LIST is handle = -1 (prefix is in `arg`), not the
        // LOOKUP handle — see the readiness-gate note above.
        let n = (s.sys().provider_call)(-1, NS_LIST, arg.as_mut_ptr(), p);
        if n <= 0 {
            break;
        }
        let n = n as usize;

        // Parse entries `[name_len:u8][kind:u8][name]` until the
        // trailing `[0xFF][0xFF][cursor_len:u8][cursor]` record. BOTH
        // marker bytes are checked: an entry whose name is exactly 255
        // bytes carries 0xFF in its `name_len`, and testing only the
        // first byte reads that entry as the end of the page and
        // silently drops every entry behind it.
        let mut pos = 0usize;
        let mut next_cursor = [0u8; 4];
        let mut next_cursor_len = 0usize;
        let mut saw_cursor = false;
        while pos + 2 <= n {
            if s.buf[pos] == 0xFF && s.buf[pos + 1] == 0xFF {
                saw_cursor = true;
                if pos + 3 <= n {
                    let clen = s.buf[pos + 2] as usize;
                    let cl = if clen > 4 { 4 } else { clen };
                    if pos + 3 + clen <= n {
                        next_cursor[..cl].copy_from_slice(&s.buf[pos + 3..pos + 3 + cl]);
                        next_cursor_len = cl;
                    }
                }
                break;
            }
            let name_len = s.buf[pos] as usize;
            let kind = s.buf[pos + 1];
            pos += 2;
            if pos + name_len > n {
                break;
            }
            // Copy the name out of `s.buf` before append_path borrows
            // `s` mutably.
            let nl = if name_len > MAX_PATH_LEN {
                MAX_PATH_LEN
            } else {
                name_len
            };
            let mut name = [0u8; MAX_PATH_LEN];
            name[..nl].copy_from_slice(&s.buf[pos..pos + nl]);
            pos += name_len;
            // Skip sub-namespaces; object_bank doesn't recurse.
            if kind == 1 {
                continue;
            }
            if !matches_format(s, &name[..nl]) {
                continue;
            }
            if !append_path(s, &dir_path[..dlen], &name[..nl]) {
                full = true;
                break;
            }
        }
        if full {
            break;
        }
        // No trailing cursor record, or an end-of-listing cursor
        // (`cursor_len == 0`): the listing is complete.
        if !saw_cursor || next_cursor_len == 0 {
            break;
        }
        cursor[..next_cursor_len].copy_from_slice(&next_cursor[..next_cursor_len]);
        cursor_len = next_cursor_len;
    }
    (s.sys().provider_call)(handle, NS_CLOSE, core::ptr::null_mut(), 0);
    (s.sys().provider_close)(handle);

    finish_scan(s);
}

/// Stream one chunk via OBJ_RANGE_GET at the current cursor into s.buf.
/// arg = [offset:u64 LE][length:u32 LE][out_ptr:u64 LE]; the provider
/// returns the byte count (n>0), EAGAIN (-11) while pending, or 0 once
/// the window is exhausted at the tail.
unsafe fn backend_stream(s: &mut BankState) -> ReadOutcome {
    let poll_out = (s.sys().channel_poll)(s.out_chans[0], POLL_OUT);
    if poll_out <= 0 || (poll_out as u32 & POLL_OUT) == 0 {
        return ReadOutcome::Yield(0);
    }
    let mut rarg = [0u8; 8 + 4 + 8];
    rarg[..8].copy_from_slice(&s.obj_offset.to_le_bytes());
    rarg[8..12].copy_from_slice(&(BUF_SIZE as u32).to_le_bytes());
    let out_ptr = s.buf.as_mut_ptr() as u64;
    rarg[12..20].copy_from_slice(&out_ptr.to_le_bytes());
    let n = (s.sys().provider_call)(s.fs_fd, OBJ_RANGE_GET, rarg.as_mut_ptr(), rarg.len());
    if n > 0 {
        s.obj_offset = s.obj_offset.wrapping_add(n as u64);
        let written = (s.sys().channel_write)(s.out_chans[0], s.buf.as_ptr(), n as usize);
        if written > 0 {
            s.total_bytes_emitted = s.total_bytes_emitted.saturating_add(written as u32);
        }
        track_pending(
            written,
            n as usize,
            &mut s.pending_out,
            &mut s.pending_offset,
        );
        return ReadOutcome::Yield(2); // Burst — keep stepping while there's data.
    }
    // EAGAIN: provider has no bytes ready but the file isn't finished
    // (async provider). Yield and re-read next tick rather than treating
    // "not ready" as EOF.
    if n == -11 {
        return ReadOutcome::Yield(0);
    }
    ReadOutcome::EndOfStream
}

/// Heartbeat tail — object_bank tracks no per-file stall metric.
unsafe fn hb_extra(_s: &mut BankState, _p: *mut u8, _q: usize) -> usize {
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");

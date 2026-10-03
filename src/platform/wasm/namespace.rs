//! WASM `storage.namespace` provider — directory enumeration over the
//! browser key space behind the STORAGE_NAMESPACE contract.
//!
//! This is the enumeration sibling of [`super::object`]. Where the
//! object provider addresses *bytes* by key (GET/HEAD/RANGE_GET/PUT),
//! this provider answers the *directory* questions a scanner asks —
//! "what lives under this prefix?" (`LIST`) and "what is this entry?"
//! (`STAT`) — without POSIX `readdir`, which the browser has no native
//! equivalent for.
//!
//! ## One key space, two surfaces
//!
//! The index is the **same flat key space** the object provider writes:
//! a key like `saves/tetris` in the host's `objStore` (the OPFS-backed
//! write tier — see `host_shims.js`) is simultaneously a namespace entry.
//! `/` is the hierarchy separator, so that one key makes `LIST("")` yield
//! `saves` (a namespace) and `LIST("saves/")` yield `tetris` (an object).
//! The index unions two sources, both owned by the host shim:
//!
//!   - `objStore` — user-written / OPFS-hydrated keys (read-write).
//!   - a fetched **manifest** — shipped, immutable content the page
//!     serves over `fetch()` (read-only); its bytes are fetched lazily
//!     through the object provider, this surface only enumerates them.
//!
//! Pairing a namespace index with an object byte-store but keeping them
//! separate contracts is exactly the split the contract docs call out
//! (pure index providers — HTTP listings, S3 ListBucket — need not hold
//! bytes). A consumer scans here, then fetches each hit via
//! `storage.object` GET on the *same key*.
//!
//! ## Thin Rust, host-owned index
//!
//! All index logic (directory derivation, paging, etag synthesis) lives
//! in the host shim, where the key space actually is. Rust is the
//! transport: a small LOOKUP/STAT handle table plus two host bindings
//! that render the contract wire format straight into the caller's
//! buffer.
//!
//!   - `host_ns_stat` — write a `STAT` record for an exact key.
//!   - `host_ns_list` — write a `LIST` page (entries + trailing cursor
//!     record) for a prefix and a name cursor.
//!
//! ## Synchronous answers, boot-ordered hydration
//!
//! `LIST`/`STAT` answer *synchronously* from the in-memory index — a
//! consumer treats a negative/empty `LIST` as "end of listing" and does
//! not retry, so EAGAIN is not an option here. The index has two sources,
//! both in `host_shims.js`: a one-shot OPFS walk + shipped-manifest fetch
//! at boot, and synchronous mutation on object `PUT`. Because an empty
//! `LIST` is terminal, a consumer must never observe the index mid-
//! hydration — so the canonical runtime *awaits* both boot sources
//! (`onNamespaceReady`) before the kernel steps any module. By the time a
//! scanner can issue its first `LIST`, the shipped tree is fully built;
//! `PUT`s thereafter mutate it in place. The per-handle fence is
//! `ViewConsistent`-shaped but, as a volatile browser index, advertised
//! `Volatile`.

use crate::abi::contracts::storage::namespace as dev_ns;
use crate::abi::fence as dev_fence;
use crate::kernel::ipc::fd::{slot_of, tag_fd, FD_TAG_STORAGE_NAMESPACE};
use crate::kernel::sys::errno;

const MAX_OPEN: usize = 16;
/// Longest `LOOKUP` path: every path in this index is a whole key of the
/// object tier, which `PUT` bounds by `STORAGE_KEY_MAX`.
const MAX_PATH_LEN: usize = crate::abi::contracts::storage::handle::STORAGE_KEY_MAX;

struct NsSlot {
    in_use: bool,
    path: [u8; MAX_PATH_LEN],
    path_len: usize,
}

const EMPTY_SLOT: NsSlot = NsSlot {
    in_use: false,
    path: [0u8; MAX_PATH_LEN],
    path_len: 0,
};

static mut SLOTS: [NsSlot; MAX_OPEN] = [EMPTY_SLOT; MAX_OPEN];

extern "C" {
    /// Write a `STAT` record for the exact key `key_ptr[..key_len]` into
    /// `out_ptr[..out_cap]`:
    /// `[size:u64 LE][mtime:u64 LE][kind:u8][etag_len:u8][etag]`.
    /// Returns the number of bytes written, or a negative errno
    /// (`-2 ENOENT` when the key names neither an object nor a prefix).
    fn host_ns_stat(key_ptr: *const u8, key_len: usize, out_ptr: *mut u8, out_cap: usize) -> i32;

    /// Write one `LIST` page for `prefix_ptr[..prefix_len]`, resuming strictly
    /// after the name `cursor_ptr[..cursor_len]` (empty = first page), into
    /// `out_ptr[..out_cap]`. The host renders the full contract page: zero or
    /// more `[name_len:u8][kind:u8][name]` entries followed by a trailing
    /// `[0xFF][0xFF][cursor_len:u8][cursor]` record whose cursor is the last
    /// name written when more remain, or empty at end of listing. Returns
    /// bytes written, or a negative errno.
    fn host_ns_list(
        prefix_ptr: *const u8,
        prefix_len: usize,
        cursor_ptr: *const u8,
        cursor_len: usize,
        out_ptr: *mut u8,
        out_cap: usize,
    ) -> i32;
}

/// Register the provider so any module declaring
/// `requires_contract = "storage.namespace"` dispatches LOOKUP / STAT /
/// LIST / CLOSE here. Called from `wasm_init_providers`.
pub fn register() {
    use crate::kernel::module::provider;
    use crate::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::STORAGE_NAMESPACE, wasm_ns_dispatch);
}

unsafe fn wasm_ns_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    // `provider_call` passes tagged handles through unchanged (mirrors
    // the `object`/`fs` siblings); strip to recover the raw slot. LIST is
    // prefix-driven from `arg`, so a tagged or -1 handle is both fine.
    let raw = slot_of(handle);

    // Per-handle fence: a volatile browser index advertises Volatile.
    if opcode == dev_fence::QUERY_OP {
        if arg.is_null() || arg_len < dev_fence::WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let idx = raw as usize;
        let slots = &*core::ptr::addr_of!(SLOTS);
        if idx >= MAX_OPEN || !slots[idx].in_use {
            return errno::ENOSYS;
        }
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match dev_fence::Fence::Volatile.encode(buf) {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }

    match opcode {
        dev_ns::LOOKUP => ns_lookup(arg, arg_len),
        dev_ns::STAT => ns_stat(raw, arg, arg_len),
        dev_ns::LIST => ns_list(arg, arg_len),
        dev_ns::CLOSE => ns_close(raw),
        // Read-only enumeration surface: no mutation or change ops. LIST is
        // directory-shaped (namespace.rs::caps).
        dev_ns::CAPS => dev_ns::caps::CHILD_NAMES as i32,
        _ => errno::ENOSYS,
    }
}

/// `LOOKUP` — `arg` is the UTF-8 path; bind a handle to it. Resolution
/// is lenient: the handle is allocated for any non-empty path and the
/// real existence check happens in `STAT` (`host_ns_stat` → ENOENT),
/// which is exactly how `truffle_scanner` uses the pair (LOOKUP then
/// STAT, skipping entries whose STAT fails).
unsafe fn ns_lookup(path_ptr: *mut u8, path_len: usize) -> i32 {
    if path_ptr.is_null() || path_len == 0 || path_len > MAX_PATH_LEN {
        return errno::EINVAL;
    }
    let slots = &mut *core::ptr::addr_of_mut!(SLOTS);
    let idx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };
    let slot = &mut slots[idx];
    core::ptr::copy_nonoverlapping(path_ptr, slot.path.as_mut_ptr(), path_len);
    slot.path_len = path_len;
    slot.in_use = true;
    tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32)
}

/// `STAT` — `arg` is the output buffer; render the resolved entry's
/// `[size][mtime][kind][etag_len][etag]` record via the host index.
unsafe fn ns_stat(raw: i32, out_ptr: *mut u8, out_cap: usize) -> i32 {
    let idx = raw as usize;
    let slots = &*core::ptr::addr_of!(SLOTS);
    if idx >= MAX_OPEN || !slots[idx].in_use {
        return errno::EINVAL;
    }
    if out_ptr.is_null() || out_cap < 8 + 8 + 1 + 1 {
        return errno::EINVAL;
    }
    let slot = &slots[idx];
    host_ns_stat(slot.path.as_ptr(), slot.path_len, out_ptr, out_cap)
}

/// `LIST` — parse the request, render one page through the host index,
/// and write a `Volatile` fence. `arg` is the `namespace::LIST` request; the
/// cursor is the last name the previous page returned, and the host renders
/// the page in the contract's wire format.
unsafe fn ns_list(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() {
        return errno::EINVAL;
    }
    let Some(req) = dev_ns::list::parse_request(core::slice::from_raw_parts(arg, arg_len)) else {
        return errno::EINVAL;
    };
    // Names are UTF-8 and, directory-shaped, never hold a `/`: a prefix or
    // cursor that breaks either was not issued here.
    let cursor_ok = matches!(core::str::from_utf8(req.cursor), Ok(c) if !c.contains('/'));
    if core::str::from_utf8(req.prefix).is_err() || !cursor_ok {
        return errno::EINVAL;
    }
    let written = host_ns_list(
        req.prefix.as_ptr(),
        req.prefix.len(),
        req.cursor.as_ptr(),
        req.cursor.len(),
        req.out_ptr as usize as *mut u8,
        req.out_cap as usize,
    );
    if written < 0 {
        return written;
    }
    let fbuf = core::slice::from_raw_parts_mut(
        req.fence_out_ptr as usize as *mut u8,
        req.fence_out_cap as usize,
    );
    let _ = dev_fence::Fence::Volatile.encode(fbuf);
    written
}

/// `CLOSE` — free the LOOKUP slot.
unsafe fn ns_close(raw: i32) -> i32 {
    let idx = raw as usize;
    let slots = &mut *core::ptr::addr_of_mut!(SLOTS);
    if idx >= MAX_OPEN || !slots[idx].in_use {
        return errno::EINVAL;
    }
    slots[idx].in_use = false;
    slots[idx].path_len = 0;
    errno::OK
}

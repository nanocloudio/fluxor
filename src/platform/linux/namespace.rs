// ============================================================================
// Linux storage.namespace Provider — directory enumeration over the real
// filesystem via std::fs.
// ============================================================================
//
// The enumeration sibling of the Linux FS provider (`linux_fs_dispatch`,
// providers.rs) and the wasm `storage.namespace` provider
// (src/platform/wasm/namespace.rs). Where FS opens *bytes* by path, this
// answers the *directory* questions a scanner asks — "what lives under this
// prefix?" (`LIST`) and "what is this entry?" (`STAT`) — directly off the
// host filesystem with `std::fs::{read_dir, metadata}`.
//
// ## One key space with the FS provider
//
// A namespace entry's path is a raw filesystem path, byte-identical to what
// `linux_fs_dispatch` opens with `libc::open`. So a consumer LISTs here, then
// fetches each hit via the FS contract on the *same key* — exactly how
// truffle_shell's scan walks the library: `LIST(prefix)` → `.m4a` objects →
// `FS_OPEN(key)` to probe the `moov`. The prefix is itself a real path: `""`
// resolves to the process CWD, `"/tmp/music"` to that directory.
//
// ## Synchronous, like the wasm peer
//
// `LIST`/`STAT` answer synchronously from the filesystem — a consumer treats
// a negative/empty `LIST` as "end of listing" and does not retry (no EAGAIN).
// Results are name-sorted so the integer-cursor paging is deterministic. The
// per-handle fence is advertised `Volatile` (a live, mutable host fs).

// This file is `include!`'d into `src/platform/linux.rs`, sharing its flat
// namespace — so `fs`, `Path`, and `tag_fd` are already in scope from there;
// only the names not already imported are pulled in here.
use fluxor::abi::contracts::fence as dev_fence;
use fluxor::abi::contracts::storage::namespace as dev_ns;
use fluxor::kernel::errno;
use fluxor::kernel::fd::{slot_of, FD_TAG_STORAGE_NAMESPACE};
use std::time::UNIX_EPOCH;

const NS_MAX_OPEN: usize = 16;
const NS_MAX_PATH: usize = 1024;

struct LinuxNsSlot {
    in_use: bool,
    path: String,
}

const NS_EMPTY: LinuxNsSlot = LinuxNsSlot {
    in_use: false,
    path: String::new(),
};

static mut LINUX_NS_SLOTS: [LinuxNsSlot; NS_MAX_OPEN] = [NS_EMPTY; NS_MAX_OPEN];

/// FNV-1a 64-bit, for synthesising a stable etag from a path. A real
/// content hash would be sturdier, but path+size+mtime is enough for the
/// `ObjectId` identity a scanner keys on (a rename re-binds the same id only
/// if the bytes are unchanged; that is acceptable for a local fs view).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Resolve a namespace prefix/key to a filesystem path. An empty prefix is
/// the process CWD (".").
fn ns_fs_path(key: &str) -> &str {
    if key.is_empty() {
        "."
    } else {
        key
    }
}

/// `LIST` — render one page of `prefix`'s immediate children into the
/// caller's output buffer. `arg` layout mirrors `namespace.rs::LIST`:
///
/// ```text
///   [prefix_len:u16][prefix][cursor_len:u16][cursor]
///   [out_buf:u64][out_cap:u32][fence_out_ptr:u64][fence_out_cap:u16]
/// ```
///
/// Each entry is `[name_len:u8][kind:u8][name]`; the page ends with a
/// `[0xFF][cursor_len:u8][cursor]` record (a 4-byte LE next-index cursor when
/// more pages remain, `cursor_len = 0` at end of listing).
unsafe fn ns_list(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 2 {
        return errno::EINVAL;
    }
    let read_u16 = |off: usize| -> usize {
        let mut b = [0u8; 2];
        core::ptr::copy_nonoverlapping(arg.add(off), b.as_mut_ptr(), 2);
        u16::from_le_bytes(b) as usize
    };
    let prefix_len = read_u16(0);
    let mut p = 2;
    if arg_len < p + prefix_len + 2 {
        return errno::EINVAL;
    }
    let prefix = {
        let s = core::slice::from_raw_parts(arg.add(p), prefix_len);
        core::str::from_utf8(s).unwrap_or("").to_string()
    };
    p += prefix_len;
    let cursor_len = read_u16(p);
    p += 2;
    if arg_len < p + cursor_len + 8 + 4 + 8 + 2 {
        return errno::EINVAL;
    }
    // Cursor is an opaque ≤32-byte blob to the consumer; we encode it as a
    // 4-byte LE page index (the start entry).
    let mut cidx = [0u8; 4];
    let take = cursor_len.min(4);
    if take > 0 {
        core::ptr::copy_nonoverlapping(arg.add(p), cidx.as_mut_ptr(), take);
    }
    let start = u32::from_le_bytes(cidx) as usize;
    p += cursor_len;

    let read_u64 = |off: usize| -> u64 {
        let mut b = [0u8; 8];
        core::ptr::copy_nonoverlapping(arg.add(off), b.as_mut_ptr(), 8);
        u64::from_le_bytes(b)
    };
    let out_ptr = read_u64(p) as usize as *mut u8;
    p += 8;
    let out_cap = {
        let mut b = [0u8; 4];
        core::ptr::copy_nonoverlapping(arg.add(p), b.as_mut_ptr(), 4);
        u32::from_le_bytes(b) as usize
    };
    p += 4;
    let fence_out_ptr = read_u64(p) as usize as *mut u8;
    p += 8;
    let fence_out_cap = read_u16(p);

    if out_ptr.is_null() || out_cap < 2 {
        return errno::EINVAL;
    }

    // Name-sorted immediate children (stable order for deterministic paging).
    // Classify dir-ness via `fs::metadata` (which FOLLOWS symlinks), matching
    // STAT — a symlinked album dir must enumerate as a namespace, not a leaf.
    let base = ns_fs_path(&prefix);
    let mut names: Vec<(String, bool)> = Vec::new(); // (name, is_dir)
    if let Ok(rd) = fs::read_dir(base) {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if name.is_empty() {
                continue;
            }
            let child = Path::new(base).join(&name);
            let is_dir = fs::metadata(&child)
                .map(|m| m.is_dir())
                // Fall back to the (non-following) dir-entry type on stat error
                // (e.g. a broken symlink) so the entry is still listed.
                .or_else(|_| ent.file_type().map(|t| t.is_dir()))
                .unwrap_or(false);
            names.push((name, is_dir));
        }
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));

    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let mut w = 0usize;
    let mut idx = start;
    while idx < names.len() {
        let (name, is_dir) = &names[idx];
        let nb = name.as_bytes();
        if nb.len() > u8::MAX as usize {
            idx += 1;
            continue; // unrepresentable name length — skip
        }
        let need = 2 + nb.len();
        // Leave room for the trailing end/cursor record (worst case 6 bytes:
        // 0xFF + len + 4-byte cursor).
        if w + need + 6 > out_cap {
            break;
        }
        out[w] = nb.len() as u8;
        out[w + 1] = if *is_dir {
            dev_ns::KIND_NAMESPACE
        } else {
            dev_ns::KIND_OBJECT
        };
        out[w + 2..w + 2 + nb.len()].copy_from_slice(nb);
        w += need;
        idx += 1;
    }
    // Trailing cursor record.
    out[w] = 0xFF;
    if idx < names.len() {
        // More pages: encode the next start index as a 4-byte LE cursor.
        out[w + 1] = 4;
        out[w + 2..w + 6].copy_from_slice(&(idx as u32).to_le_bytes());
        w += 6;
    } else {
        out[w + 1] = 0; // end of listing
        w += 2;
    }

    if !fence_out_ptr.is_null() && fence_out_cap >= dev_fence::WIRE_MAX_LEN {
        let fbuf = core::slice::from_raw_parts_mut(fence_out_ptr, fence_out_cap);
        let _ = dev_fence::Fence::Volatile.encode(fbuf);
    }
    w as i32
}

/// `STAT` — write `[size:u64][mtime:u64][kind:u8][etag_len:u8][etag]` for the
/// LOOKUP-bound handle's path.
unsafe fn ns_stat(raw: i32, out_ptr: *mut u8, out_cap: usize) -> i32 {
    let idx = raw as usize;
    let slots = &*core::ptr::addr_of!(LINUX_NS_SLOTS);
    if idx >= NS_MAX_OPEN || !slots[idx].in_use {
        return errno::EINVAL;
    }
    if out_ptr.is_null() || out_cap < 8 + 8 + 1 + 1 {
        return errno::EINVAL;
    }
    let path = slots[idx].path.clone();
    let meta = match fs::metadata(ns_fs_path(&path)) {
        Ok(m) => m,
        Err(_) => return errno::ENODEV,
    };
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let kind = if meta.is_dir() {
        dev_ns::KIND_NAMESPACE
    } else {
        dev_ns::KIND_OBJECT
    };
    // etag: fnv1a64(path) ⊕ size ⊕ mtime → 8 stable bytes.
    let etag = fnv1a64(path.as_bytes()) ^ size ^ mtime.rotate_left(17);
    let etag_bytes = etag.to_le_bytes();

    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    out[0..8].copy_from_slice(&size.to_le_bytes());
    out[8..16].copy_from_slice(&mtime.to_le_bytes());
    out[16] = kind;
    let mut written = 18usize;
    let etag_len = if out_cap >= 18 + etag_bytes.len() {
        out[18..18 + etag_bytes.len()].copy_from_slice(&etag_bytes);
        written += etag_bytes.len();
        etag_bytes.len()
    } else {
        0
    };
    out[17] = etag_len as u8;
    written as i32
}

/// `LOOKUP` — bind a handle to `arg`'s UTF-8 path. Lenient: any path (incl.
/// the empty root prefix, which binds the CWD) gets a handle; the real
/// existence check happens in `STAT`. A scanner walking from the root opens
/// `LOOKUP("")`, so empty must succeed.
unsafe fn ns_lookup(path_ptr: *mut u8, path_len: usize) -> i32 {
    if path_len > NS_MAX_PATH {
        return errno::EINVAL;
    }
    let path = if path_len == 0 {
        String::new()
    } else if path_ptr.is_null() {
        return errno::EINVAL;
    } else {
        let bytes = core::slice::from_raw_parts(path_ptr, path_len);
        match core::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => return errno::EINVAL,
        }
    };
    let slots = &mut *core::ptr::addr_of_mut!(LINUX_NS_SLOTS);
    let idx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };
    slots[idx].path = path;
    slots[idx].in_use = true;
    tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32)
}

/// `CLOSE` — free the LOOKUP slot.
unsafe fn ns_close(raw: i32) -> i32 {
    let idx = raw as usize;
    let slots = &mut *core::ptr::addr_of_mut!(LINUX_NS_SLOTS);
    if idx >= NS_MAX_OPEN || !slots[idx].in_use {
        return errno::EINVAL;
    }
    slots[idx].in_use = false;
    slots[idx].path = String::new();
    errno::OK
}

/// Dispatch entry registered for the STORAGE_NAMESPACE contract from
/// `linux_init_providers`. `provider_call` passes tagged handles through
/// unchanged (mirrors the FS/object siblings); strip to the raw slot. LIST is
/// prefix-driven from `arg`, so a tagged or -1 handle is both fine.
unsafe fn linux_namespace_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let raw = slot_of(handle);

    // Per-handle fence introspection (provider_query LAST_FENCE path).
    if opcode == dev_fence::QUERY_OP {
        if arg.is_null() || arg_len < dev_fence::WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let idx = raw as usize;
        let slots = &*core::ptr::addr_of!(LINUX_NS_SLOTS);
        if idx >= NS_MAX_OPEN || !slots[idx].in_use {
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
        _ => errno::ENOSYS,
    }
}

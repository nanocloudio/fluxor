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
// Results are name-sorted and paged by name: the cursor is the last name a
// page returned. The per-handle fence is advertised `Volatile` (a live,
// mutable host fs).

// This file is `include!`'d into `src/platform/linux.rs`, sharing its flat
// namespace — so `fs` and `Path` are already in scope from there;
// only the names not already imported are pulled in here.
use fluxor::abi::contracts::storage::namespace as dev_ns;
use fluxor::abi::fence as dev_fence;
use fluxor::kernel::sys::errno;
use std::time::UNIX_EPOCH;

const NS_MAX_OPEN: usize = 16;
const NS_MAX_PATH: usize = dev_ns::PATH_MAX;

struct LinuxNsSlot {
    in_use: bool,
    path: String,
    /// The owner that bound the handle: the node, or an owner acting with
    /// the node's authority. The slot answers it alone and goes with it.
    opener: fluxor::kernel::workload::owner::OwnerHandle,
}

const NS_EMPTY: LinuxNsSlot = LinuxNsSlot {
    in_use: false,
    path: String::new(),
    opener: fluxor::kernel::workload::owner::OWNER_NODE,
};

static mut LINUX_NS_SLOTS: [LinuxNsSlot; NS_MAX_OPEN] = [NS_EMPTY; NS_MAX_OPEN];

/// Whether `slot` is bound and the caller's: its opener alone reaches it.
fn ns_owned(slot: &LinuxNsSlot) -> bool {
    slot.in_use && slot.opener == fluxor::kernel::exec::scheduler::caller_owner()
}

/// Free every handle `opener` bound. Part of the platform's owner-release
/// hook, for an owner that acted with the node's authority: what it opened
/// goes with it.
///
/// # Safety
/// Single-threaded platform dispatch only.
unsafe fn ns_release_opener(opener: fluxor::kernel::workload::owner::OwnerHandle) {
    let slots = &mut *core::ptr::addr_of_mut!(LINUX_NS_SLOTS);
    for s in slots.iter_mut().filter(|s| s.in_use && s.opener == opener) {
        *s = NS_EMPTY;
    }
}

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

/// `LIST` — render one page of `prefix`'s immediate children, in ascending
/// name order, into `data`. `arg` is the
/// `namespace::LIST` request and the page is written by
/// `namespace::list::PageWriter`. The cursor is the last name a page
/// returned and the next page resumes strictly after it, so a file created or
/// removed between pages never shifts the entries behind the cursor. A child
/// whose name is not UTF-8 is not expressible in the contract and is not
/// listed.
fn ns_list(arg: &mut [u8], out: &mut [u8]) -> i32 {
    let Some(req) = dev_ns::list::parse_request(arg) else {
        return errno::EINVAL;
    };
    let Ok(prefix) = core::str::from_utf8(req.prefix) else {
        return errno::EINVAL;
    };
    // Directory-shaped: the cursor is a child name, so one that is not UTF-8
    // or that holds a `/` was not issued here.
    let after = if req.cursor.is_empty() {
        None
    } else {
        match core::str::from_utf8(req.cursor) {
            Ok(c) if !c.contains('/') => Some(c),
            _ => return errno::EINVAL,
        }
    };

    // Name-sorted immediate children. Classify dir-ness via `fs::metadata`
    // (which FOLLOWS symlinks), matching STAT — a symlinked album dir must
    // enumerate as a namespace, not a leaf.
    let base = ns_fs_path(prefix);
    let mut names: Vec<(String, bool)> = Vec::new(); // (name, is_dir)
    if let Ok(rd) = fs::read_dir(base) {
        for ent in rd.flatten() {
            let Ok(name) = ent.file_name().into_string() else {
                continue;
            };
            if name.is_empty() || after.is_some_and(|a| name.as_str() <= a) {
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

    let mut page = dev_ns::list::PageWriter::new(out);
    let mut last: Option<&str> = None;
    let mut more = false;
    for (name, is_dir) in &names {
        if name.len() > fluxor::abi::contracts::storage::handle::STORAGE_KEY_MAX {
            // Refusing is the contract's answer: skipping it returns a short
            // page the caller has no way to know is short.
            return errno::EOVERFLOW;
        }
        let kind = if *is_dir {
            dev_ns::KIND_NAMESPACE
        } else {
            dev_ns::KIND_OBJECT
        };
        if !page.push(name.as_bytes(), kind) {
            more = true;
            break;
        }
        last = Some(name);
    }
    let cursor = match last {
        Some(n) if more => n.as_bytes(),
        // A page that cannot hold the next entry made no progress.
        None if more => return errno::ENOMEM,
        _ => &[],
    };
    let Some(n) = page.finish(cursor) else {
        return errno::ENOMEM;
    };
    dev_fence::trailer::put(arg, &dev_fence::Fence::Volatile);
    n as i32
}

/// `STAT` — write `[size:u64][mtime:u64][kind:u8][etag_len:u8][etag]` for the
/// LOOKUP-bound handle's path into `out`.
unsafe fn ns_stat(raw: i32, out: &mut [u8]) -> i32 {
    let idx = raw as usize;
    let slots = &*core::ptr::addr_of!(LINUX_NS_SLOTS);
    if idx >= NS_MAX_OPEN || !ns_owned(&slots[idx]) {
        return errno::EINVAL;
    }
    if out.len() < dev_ns::stat::FIXED_LEN {
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
    match dev_ns::stat::encode(out, size, mtime, kind, &etag.to_le_bytes()) {
        Some(n) => n as i32,
        None => errno::EINVAL,
    }
}

/// `LOOKUP` — bind a handle to `arg`'s UTF-8 path. Lenient: any path (incl.
/// the empty root prefix, which binds the CWD) gets a handle; the real
/// existence check happens in `STAT`. A scanner walking from the root opens
/// `LOOKUP("")`, so empty must succeed.
unsafe fn ns_lookup(path: &[u8]) -> i32 {
    if path.len() > NS_MAX_PATH {
        return errno::EINVAL;
    }
    let Ok(path) = core::str::from_utf8(path) else {
        return errno::EINVAL;
    };
    let path = path.to_string();
    let slots = &mut *core::ptr::addr_of_mut!(LINUX_NS_SLOTS);
    let idx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };
    slots[idx].path = path;
    slots[idx].in_use = true;
    slots[idx].opener = fluxor::kernel::exec::scheduler::caller_owner();
    idx as i32
}

/// `CLOSE` — free the LOOKUP slot.
unsafe fn ns_close(raw: i32) -> i32 {
    let idx = raw as usize;
    let slots = &mut *core::ptr::addr_of_mut!(LINUX_NS_SLOTS);
    if idx >= NS_MAX_OPEN || !ns_owned(&slots[idx]) {
        return errno::EINVAL;
    }
    slots[idx] = NS_EMPTY;
    errno::OK
}

/// Dispatch entry registered for the STORAGE_NAMESPACE contract from
/// `linux_init_providers`. A handle op arrives with the slot's index. LIST is
/// prefix-driven from `arg`, so an index or -1 is both fine.
fn linux_namespace_dispatch(
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    mut data: fluxor::kernel::module::user_span::UserSpan<'_>,
) -> i32 {
    // A workload's namespace is its own store's: never the host filesystem
    // and never the node's store.
    let owner = fluxor::kernel::exec::scheduler::caller_owner();
    if fluxor::platform::linux::owner_root::rooted(owner) {
        // SAFETY: platform dispatch runs on the scheduler thread alone, the
        // one thread that touches the owner roots' stores.
        let Some(store) = (unsafe { fluxor::platform::linux::owner_root::store_for(owner) }) else {
            return errno::EACCES;
        };
        return fluxor::platform::linux::store::dispatch_namespace_on(
            store, handle, opcode, arg, data,
        );
    }
    // Control-plane store mode (FLUXOR_STORE_DIR set): the versioned store backs
    // storage.namespace here (LIST/SUBSCRIBE + revision fence). Otherwise this
    // provider is the filesystem-backed enumeration surface below.
    // SAFETY: platform dispatch runs on the scheduler thread alone.
    if unsafe { fluxor::platform::linux::store::store_active() } {
        return fluxor::platform::linux::store::dispatch_namespace(handle, opcode, arg, data);
    }

    let raw = handle;

    // Per-handle fence introspection (provider_query LAST_FENCE path).
    if opcode == dev_fence::QUERY_OP {
        if arg.len() < dev_fence::WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let idx = raw as usize;
        // SAFETY: scheduler thread only, the one that touches the slot table.
        let owned = unsafe {
            let slots = &*core::ptr::addr_of!(LINUX_NS_SLOTS);
            idx < NS_MAX_OPEN && ns_owned(&slots[idx])
        };
        if !owned {
            return errno::ENOSYS;
        }
        return match dev_fence::Fence::Volatile.encode(arg) {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }

    match opcode {
        // SAFETY: scheduler thread only, the one that touches the slot table.
        dev_ns::LOOKUP => unsafe { ns_lookup(arg) },
        // SAFETY: as LOOKUP.
        dev_ns::STAT => unsafe { ns_stat(raw, arg) },
        dev_ns::LIST => ns_list(arg, data.as_mut()),
        // SAFETY: as LOOKUP.
        dev_ns::CLOSE => unsafe { ns_close(raw) },
        // Read-only enumeration surface: no mutation or change ops. LIST is
        // directory-shaped (namespace.rs::caps).
        dev_ns::CAPS => fluxor::abi::kernel_abi::caps_word::answer(arg, dev_ns::caps::CHILD_NAMES),
        _ => errno::ENOSYS,
    }
}

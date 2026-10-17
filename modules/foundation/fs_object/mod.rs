//! fs_object — a small `storage.object` and `storage.namespace` provider
//! over whatever serves the `fs` contract.
//!
//! The store a board can have without a storage cluster: objects are files
//! under one directory (`root`), so on a Pi 5 or a Pico they live on the
//! FAT32 volume `fat32` serves, and on Linux in a host directory. Every op is
//! decided by this module from the filesystem alone: there is no index, no
//! cache of objects and no background work, and a reset loses nothing a
//! write reported `LocalDurable`.
//!
//! ## On disk
//!
//! An object is one file under `root` with a legal 8.3 name drawn from
//! SHA-256(key): eight base-32 characters, then an extension whose first
//! letter is `O` for an object and `T` for its temporary, followed by two
//! more base-32 characters -- 50 bits of the digest in all. Keys are bytes
//! and FAT32 names are not -- they fold case and refuse most punctuation --
//! so the key is not the file name: it is carried in the file's header, and
//! every read, overwrite, delete and listing checks that the header names
//! the key the file name was derived from. Two keys whose names collide are
//! told apart by that check: the second is refused `EEXIST` rather than
//! written over the first. The name is 8.3 rather than long because on FAT32
//! a long name costs companion entries beside the short one and a `~N` alias
//! that must be unique in the directory, so every create and lookup walks
//! further; an 8.3 name is one directory entry and needs no alias.
//!
//! ```text
//!   [magic "FXO1"][hdr_len: u16 LE][key_len: u16 LE][key]
//!   [ct_len: u8][content type][etag: 32 bytes = SHA-256(body)]
//!   [body …]
//! ```
//!
//! A key is 1..=255 bytes of UTF-8, which is what a listing can carry; a
//! content type is at most 255 bytes. The etag is the body's digest, so it
//! changes whenever the body does and is equal for equal bodies.
//!
//! ## Writes
//!
//! The filesystem must offer `OPEN_CREATE`, `WRITE`, `FSYNC`, `UNLINK` and an
//! atomic `RENAME`; without them a `PUT` is refused `ENOSYS`, since a write
//! could not then be published whole. A `PUT` hashes the body, removes any
//! temporary an interrupted attempt left, writes the temporary, fences its
//! bytes (`FSYNC`), closes it and `RENAME`s it over the object's name. A
//! crash leaves the old object or the new one, never a torn one, and at
//! worst a temporary, which no read or listing looks at and the next `PUT`
//! of that key removes. The answer's fence is the `LocalDurable` the fsync
//! and the rename achieved. A `DELETE` checks the key, unlinks the object
//! and, where the filesystem offers `FSYNC_NAME`, fences the removal:
//! `LocalDurable` on the device the store's writes have named, `Volatile`
//! when no `PUT` has named one yet or the filesystem cannot fence a name.
//!
//! A write is a resumable sequence. Each ask does at most one filesystem
//! operation that walks a directory or writes (a create, one `WRITE_CHUNK`
//! write, a flush, a rename, an unlink) or hashes at most `HASH_CHUNK` bytes
//! of the body, because a board's step budget is a few milliseconds and the
//! whole sequence is more. Until the write is decided it answers
//! `EINPROGRESS`; the caller asks again with byte-identical arguments, which
//! is how the request is recognised, and it carries on from where it
//! stopped. A filesystem's own "not yet" (`EAGAIN` -- FAT32 answers it while
//! it walks a large directory) leaves the sequence where it was.
//!
//! The store has one write in flight, `PUT` or `DELETE`. A different write
//! is refused `EBUSY` meanwhile, so the key check a write makes and the
//! rename or unlink that acts on it see the same store; that is what makes
//! `ABSENT` honest. After `SUPERSEDE_AFTER` refusals the write in flight
//! counts as abandoned and is superseded: a `PUT` asked again afterwards
//! starts over (nothing of it was published), and a `DELETE` whose unlink had
//! already happened answers success, if it is asked again before another
//! `PUT` lands. An object held open by a `GET` handle cannot be replaced or
//! deleted on FAT32 (it refuses `EBUSY`) until the handle is closed.
//!
//! ## Reads
//!
//! `GET` opens the object's file and holds it as the handle (`READS` at
//! once); `HEAD` reads the header and closes it. Both, and `RANGE_GET`,
//! answer `EAGAIN` while the filesystem does, to be asked again. An absent
//! key -- including one whose name another key's object holds -- is `ENOENT`
//! from `GET` and `DELETE`, and `ENXIO` from `HEAD`, as the contract states
//! for `HEAD`.
//!
//! ## Listings
//!
//! `storage.object::LIST` and `storage.namespace::LIST` (key-shaped:
//! `CHILD_NAMES` clear) are served by one scan of the directory that reads
//! each object's header, so a page costs an open per object in the store,
//! whatever its prefix. That is the price of having no index, and the right
//! one for the stores this is for: tens or hundreds of keys, not millions.
//! A call reads at most `SCAN_OPENS_PER_CALL` headers and answers `EAGAIN`
//! to be asked again with the same request; the scan resumes where it
//! stopped. One scan runs at a time: another listing is answered `EAGAIN`
//! until it finishes, and supersedes it after `SUPERSEDE_AFTER` refusals. A
//! page holds at most `PAGE_KEYS` keys, and each page carries a `Volatile`
//! fence.
//!
//! ## What it does not do
//!
//! No grants (`PRESENT` answers `ENOSYS`: a store with no mesh roots), no
//! streamed puts, no `ETAG` precondition (`ENOSYS`), no change subscription,
//! and of the namespace surface only `LIST` and `CAPS`.

#![cfg_attr(not(feature = "host-test"), no_std)]
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
use abi::contracts::storage::fs;
use abi::contracts::storage::namespace as ns;
use abi::contracts::storage::object as obj;
use abi::fence::Fence;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/crypto/sha256.rs");

// ── errno ─────────────────────────────────────────────────────────────

const ERR_NOENT: i32 = -2;
const ERR_IO: i32 = -5;
const ERR_NXIO: i32 = -6;
const ERR_BADF: i32 = -9;
const ERR_AGAIN: i32 = -11;
const ERR_NOMEM: i32 = -12;
const ERR_BUSY: i32 = -16;
const ERR_EXIST: i32 = -17;
const ERR_INVAL: i32 = -22;
const ERR_NOSPC: i32 = -28;
const ERR_INPROGRESS: i32 = -36;
const ERR_NOSYS: i32 = -38;

// ── sizes ─────────────────────────────────────────────────────────────

const ROOT_MAX: usize = 96;
/// `<root>/` + an 8.3 name.
const PATH_MAX: usize = ROOT_MAX + 1 + 12;
/// An 8.3 name: eight characters, a dot, three.
const NAME_LEN: usize = 12;
/// The first letter of an object's extension, and of its temporary's.
const KIND_OBJECT: u8 = b'O';
const KIND_TEMP: u8 = b'T';
const KEY_MAX: usize = abi::contracts::storage::handle::STORAGE_KEY_MAX;
const CT_MAX: usize = 255;
const ETAG_LEN: usize = 32;
const MAGIC: [u8; 4] = *b"FXO1";
/// Magic, header length, key length.
const HDR_FIXED: usize = 4 + 2 + 2;
const HDR_MAX: usize = HDR_FIXED + KEY_MAX + 1 + CT_MAX + ETAG_LEN;
/// Read handles open at once.
const READS: usize = 8;
/// Keys one listing page holds.
const PAGE_KEYS: usize = 16;
/// Bytes of one directory read.
const DIR_BATCH: usize = 512;
/// Bytes written to the filesystem per `WRITE` call.
const WRITE_CHUNK: usize = 4096;
/// Body bytes hashed per ask while a `PUT` computes its etag.
const HASH_CHUNK: usize = 4096;
/// Object headers one listing call reads before it answers "not yet".
const SCAN_OPENS_PER_CALL: u8 = 8;
/// Refusals of other requests before a write or scan in flight counts as
/// abandoned.
const SUPERSEDE_AFTER: u16 = 64;

/// The filesystem operations a `PUT` cannot be published whole without.
const PUT_NEEDS: u32 =
    fs::caps::OPEN_CREATE | fs::caps::WRITE | fs::caps::FSYNC | fs::caps::UNLINK | fs::caps::RENAME;

// ── state ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct ReadSlot {
    fd: i32,
    hdr_len: u32,
    /// Body bytes.
    size: u64,
    live: u8,
}

const READ_EMPTY: ReadSlot = ReadSlot {
    fd: -1,
    hdr_len: 0,
    size: 0,
    live: 0,
};

/// Stages of a `PUT`, in order. Each ask runs one and answers "not yet",
/// except the last, which decides the write.
const PUT_ROOT: u8 = 0;
const PUT_CHECK: u8 = 1;
const PUT_HASH: u8 = 2;
const PUT_CLEAR: u8 = 3;
const PUT_CREATE: u8 = 4;
const PUT_WRITE: u8 = 5;
const PUT_FSYNC: u8 = 6;
const PUT_PUBLISH: u8 = 7;
/// A failed `PUT` removing its temporary before it answers the failure.
const PUT_DISCARD: u8 = 8;

/// Stages of a `DELETE`.
const DEL_CHECK: u8 = 16;
const DEL_UNLINK: u8 = 17;
/// The object is unlinked; what is left is fencing its name.
const DEL_FENCE: u8 = 18;

/// The store's one write in flight.
struct Write {
    /// SHA-256 of the opcode and the request's bytes: the same request
    /// asked again.
    ask: [u8; 32],
    live: u8,
    /// One of the `PUT_*` or `DEL_*` stages.
    stage: u8,
    /// The temporary being written, open across asks; -1 when none is.
    fd: i32,
    /// Header and body bytes written so far.
    written: u64,
    /// Body bytes hashed so far, and the running digest.
    hashed: u64,
    hash: Sha256,
    etag: [u8; ETAG_LEN],
    /// The temporary's bytes reached the device `device` names.
    durable: u8,
    /// What a `PUT_DISCARD` answers once the temporary is gone.
    failed: i32,
    /// Other writes refused while this one was in flight. A caller that
    /// stops asking would otherwise hold the store's one write slot for good.
    refused: u16,
}

/// One key a listing scan has picked, with what `storage.object::LIST`
/// reports for it.
#[derive(Clone, Copy)]
struct Picked {
    key: [u8; KEY_MAX],
    key_len: u8,
    size: u64,
    mtime: u64,
    etag: [u8; ETAG_LEN],
}

const PICKED_EMPTY: Picked = Picked {
    key: [0; KEY_MAX],
    key_len: 0,
    size: 0,
    mtime: 0,
    etag: [0; ETAG_LEN],
};

/// A listing scan, resumable across "not yet".
struct Scan {
    /// SHA-256 of the opcode and the request's bytes.
    ask: [u8; 32],
    live: u8,
    /// The open directory; -1 once the walk is whole (or the store has no
    /// directory yet).
    dir: i32,
    /// The directory batch being walked: how far into it, and how many of
    /// its entries are left.
    batch: [u8; DIR_BATCH],
    batch_len: u16,
    batch_at: u16,
    batch_left: u16,
    /// The smallest keys after the cursor, in order.
    picked: [Picked; PAGE_KEYS],
    count: u8,
    /// A matching key was passed over because the page was full.
    more: u8,
    /// Objects opened by this call.
    opens: u8,
    /// Other listings refused while this one was in flight.
    refused: u16,
}

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    root: [u8; ROOT_MAX],
    /// Bytes of `root`; above `ROOT_MAX` when the param was too long.
    root_len: usize,
    fs_caps: u32,
    caps_known: u8,
    root_made: u8,
    /// The device the filesystem's `LocalDurable` fences name, once a
    /// `PUT`'s fsync has reported one.
    device: u64,
    device_known: u8,
    /// A `DELETE` superseded after its unlink: asked again, it answers
    /// success.
    settled_ask: [u8; 32],
    settled: u8,
    reads: [ReadSlot; READS],
    write: Write,
    scan: Scan,
    hdr: [u8; HDR_MAX],
}

mod params_def {
    use super::*;
    define_params! {
        State;
        1, root, str, 0 => |s, d, len| {
            if len > ROOT_MAX {
                s.root_len = ROOT_MAX + 1;
            } else {
                core::ptr::copy_nonoverlapping(d, s.root.as_mut_ptr(), len);
                s.root_len = len;
            }
        };
    }
}

// ── filesystem calls ──────────────────────────────────────────────────

/// The loader's syscall table, held apart from `State` so a call can name a
/// buffer inside the state.
#[derive(Clone, Copy)]
struct Fs(*const SyscallTable);

impl Fs {
    fn table(self) -> &'static SyscallTable {
        // SAFETY: set by `module_new` from the loader's table, which lives
        // for the module's lifetime.
        unsafe { &*self.0 }
    }

    fn call(self, handle: i32, op: u32, arg: *mut u8, len: usize) -> i32 {
        // SAFETY: `arg` names `len` bytes the caller owns for the call (or is
        // null with `len` 0).
        unsafe { (self.table().provider_call)(handle, op, arg, len) }
    }

    /// Call `op` on a path; the path buffer is the callee's to read.
    fn path(self, op: u32, path: &mut [u8]) -> i32 {
        self.call(-1, op, path.as_mut_ptr(), path.len())
    }

    /// A call the filesystem may take and decide later (`MKDIR`, `UNLINK`,
    /// `OPEN_CREATE`, `FSYNC`, `FSYNC_NAME`, `RENAME`). Its `EINPROGRESS`
    /// ("taken, re-ask the same request") is answered as `ERR_AGAIN`: every
    /// caller is a write-slot stage that stays where it is and, on the next
    /// ask, issues the byte-identical call again, which collects the
    /// decision. Never a failure.
    fn settle(self, handle: i32, op: u32, arg: *mut u8, len: usize) -> i32 {
        let rc = self.call(handle, op, arg, len);
        if rc == ERR_INPROGRESS {
            ERR_AGAIN
        } else {
            rc
        }
    }

    /// [`Fs::settle`] on a path.
    fn settle_path(self, op: u32, path: &mut [u8]) -> i32 {
        self.settle(-1, op, path.as_mut_ptr(), path.len())
    }

    fn close(self, fd: i32) {
        let _ = self.call(fd, fs::CLOSE, core::ptr::null_mut(), 0);
    }

    /// Read exactly `len` bytes from `fd` into `out`, stopping early only at
    /// the end of the file: the count, or an errno.
    ///
    /// `ERR_AGAIN` once the filesystem defers, even after a short count: the
    /// bytes already read are not a whole answer, and the file offset has
    /// moved past them, so the caller must CLOSE `fd` and ask again from a
    /// fresh open (`read_header`'s callers do). For a read that can answer
    /// what it has, see [`Fs::read_some`].
    fn read_full(self, fd: i32, out: *mut u8, len: usize) -> i32 {
        let mut got = 0usize;
        while got < len {
            // SAFETY: `out` is writable for `len` bytes.
            let rc = self.call(fd, fs::READ, unsafe { out.add(got) }, len - got);
            if rc < 0 {
                return rc;
            }
            if rc == 0 {
                break;
            }
            if rc as usize > len - got {
                return ERR_IO;
            }
            got += rc as usize;
        }
        got as i32
    }

    /// Read up to `len` bytes from `fd` into `out`: the count moved (short
    /// when the filesystem defers part-way or the file ends — progress is
    /// never discarded), `ERR_AGAIN` only when nothing moved, or an errno.
    fn read_some(self, fd: i32, out: *mut u8, len: usize) -> i32 {
        let mut got = 0usize;
        while got < len {
            // SAFETY: `out` is writable for `len` bytes.
            let rc = self.call(fd, fs::READ, unsafe { out.add(got) }, len - got);
            if rc == ERR_AGAIN && got > 0 {
                break;
            }
            if rc < 0 {
                return rc;
            }
            if rc == 0 {
                break;
            }
            if rc as usize > len - got {
                return ERR_IO;
            }
            got += rc as usize;
        }
        got as i32
    }

    /// (size, mtime) of the open file `fd`.
    fn stat(self, fd: i32) -> Result<(u64, u64), i32> {
        let mut out = [0u8; 16];
        let rc = self.call(fd, fs::STAT, out.as_mut_ptr(), 16);
        if rc < 0 {
            return Err(rc);
        }
        if rc >= 16 {
            Ok((u64_at(&out, 0).unwrap_or(0), u64_at(&out, 8).unwrap_or(0)))
        } else {
            Ok((
                u64::from(u32_at(&out, 0).unwrap_or(0)),
                u64::from(u32_at(&out, 4).unwrap_or(0)),
            ))
        }
    }

    /// The device a `LocalDurable` fence on `fd` names, if it reports one.
    fn durable_device(self, fd: i32) -> Option<u64> {
        let mut out = [0u8; abi::fence::WIRE_MAX_LEN];
        // SAFETY: `out` is writable for its length.
        let rc = unsafe {
            (self.table().provider_query)(
                fd,
                abi::kernel_abi::query_key::LAST_FENCE,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        if rc <= 0 {
            return None;
        }
        match Fence::decode(&out[..rc as usize]) {
            Some((Fence::LocalDurable { device_id }, _)) => Some(device_id),
            _ => None,
        }
    }
}

impl State {
    fn io(&self) -> Fs {
        Fs(self.syscalls)
    }

    fn root(&self) -> &[u8] {
        &self.root[..self.root_len]
    }
}

// ── little helpers ────────────────────────────────────────────────────

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let x = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    let x = b.get(at..at + 8)?;
    let mut w = [0u8; 8];
    w.copy_from_slice(x);
    Some(u64::from_le_bytes(w))
}

/// The kind of request an identity names: the same argument bytes asked of
/// two different ops are two requests.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Ask {
    Put = 1,
    Delete = 2,
    ObjectList = 3,
    NamespaceList = 4,
}

/// SHA-256 of the request's kind and arguments: what identifies a request
/// asked again.
fn ask_of(kind: Ask, a: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[kind as u8]);
    h.update(a);
    h.finalize()
}

/// A key this store can hold: one a listing can carry.
fn valid_key(key: &[u8]) -> bool {
    !key.is_empty() && key.len() <= KEY_MAX && utf8_valid(key)
}

/// The filesystem's capability bits, asked until it answers; `None` while it
/// answers "not yet" (FAT32 does until its volume is mounted). A refusal is
/// not latched: the bitmap is asked for again on the next op.
fn caps(s: &mut State) -> Option<u32> {
    if s.caps_known == 0 {
        let mut out = [0u8; 4];
        let rc = s.io().call(-1, fs::CAPS, out.as_mut_ptr(), 4);
        if rc == ERR_AGAIN {
            return None;
        }
        if rc < 0 {
            return Some(0);
        }
        s.fs_caps = u32::from_le_bytes(out);
        s.caps_known = 1;
    }
    Some(s.fs_caps)
}

/// One base-32 symbol: a digit or an upper-case letter, legal in an 8.3
/// name and unchanged by FAT32's case folding.
fn b32(v: u64) -> u8 {
    let v = (v & 31) as u8;
    if v < 10 {
        b'0' + v
    } else {
        b'A' + (v - 10)
    }
}

/// The 8.3 name of `key`'s file of `kind` (`KIND_OBJECT` or `KIND_TEMP`):
/// `NNNNNNNN.KNN`, the top 50 bits of SHA-256(key) in base 32.
fn name_for(key: &[u8], kind: u8) -> [u8; NAME_LEN] {
    let d = sha256(key);
    let mut bits = 0u64;
    let mut i = 0;
    while i < 8 {
        bits = (bits << 8) | u64::from(d[i]);
        i += 1;
    }
    let mut out = [0u8; NAME_LEN];
    let mut c = 0;
    while c < 8 {
        out[c] = b32(bits >> (59 - 5 * c));
        c += 1;
    }
    out[8] = b'.';
    out[9] = kind;
    out[10] = b32(bits >> 19);
    out[11] = b32(bits >> 14);
    out
}

/// `<root>/<name>` into `out`; its length.
fn path_of(s: &State, name: &[u8], out: &mut [u8; PATH_MAX]) -> usize {
    let root = s.root();
    out[..root.len()].copy_from_slice(root);
    out[root.len()] = b'/';
    out[root.len() + 1..root.len() + 1 + name.len()].copy_from_slice(name);
    root.len() + 1 + name.len()
}

/// The path of `key`'s file of `kind`, into `out`; its length.
fn path_for(s: &State, key: &[u8], kind: u8, out: &mut [u8; PATH_MAX]) -> usize {
    path_of(s, &name_for(key, kind), out)
}

/// Write `fence` into a caller's `[ptr, cap]` pair, which `fence_ok` has
/// already checked.
fn write_fence(fence: Fence, ptr: u64, cap: u16) {
    // SAFETY: the caller named `cap` (>= `WIRE_MAX_LEN`) writable bytes at
    // `ptr` for the call.
    let out = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, cap as usize) };
    let _ = fence.encode(out);
}

fn fence_ok(ptr: u64, cap: u16) -> bool {
    ptr != 0 && (cap as usize) >= abi::fence::WIRE_MAX_LEN
}

// ── object files ──────────────────────────────────────────────────────

/// Where an object's header puts its parts; the bytes are in `s.hdr`.
struct Header {
    hdr_len: usize,
    key_len: usize,
    ct_at: usize,
    ct_len: usize,
    etag_at: usize,
}

impl State {
    fn hdr_key(&self, h: &Header) -> &[u8] {
        &self.hdr[HDR_FIXED..HDR_FIXED + h.key_len]
    }
}

/// Read and check the header of the open file `fd` into `s.hdr`: `ERR_NXIO`
/// for a file that is not a whole object header.
fn read_header(s: &mut State, fd: i32) -> Result<Header, i32> {
    let io = s.io();
    let rc = io.read_full(fd, s.hdr.as_mut_ptr(), HDR_FIXED);
    if rc < 0 {
        return Err(rc);
    }
    if (rc as usize) < HDR_FIXED || s.hdr[..4] != MAGIC {
        return Err(ERR_NXIO);
    }
    let hdr_len = u16_at(&s.hdr, 4).unwrap_or(0) as usize;
    let key_len = u16_at(&s.hdr, 6).unwrap_or(0) as usize;
    if key_len == 0
        || key_len > KEY_MAX
        || hdr_len > HDR_MAX
        || hdr_len < HDR_FIXED + key_len + 1 + ETAG_LEN
    {
        return Err(ERR_NXIO);
    }
    let rest = hdr_len - HDR_FIXED;
    let rc = io.read_full(fd, s.hdr[HDR_FIXED..].as_mut_ptr(), rest);
    if rc < 0 {
        return Err(rc);
    }
    if rc as usize != rest {
        return Err(ERR_NXIO);
    }
    let ct_at = HDR_FIXED + key_len + 1;
    let ct_len = s.hdr[HDR_FIXED + key_len] as usize;
    if ct_at + ct_len + ETAG_LEN != hdr_len {
        return Err(ERR_NXIO);
    }
    Ok(Header {
        hdr_len,
        key_len,
        ct_at,
        ct_len,
        etag_at: ct_at + ct_len,
    })
}

/// Who holds the file `key`'s object is named by.
enum Holder {
    /// No file, or one that is not an object (a torn or foreign file, which
    /// a write replaces).
    Nobody,
    /// `key`'s object, open as `fd` with its header in `s.hdr`.
    This(i32, Header),
    /// Another key's object: the two keys' names collide.
    Another,
}

/// Open the file `key`'s object is named by and say whose it is.
fn name_holder(s: &mut State, key: &[u8]) -> Result<Holder, i32> {
    let mut path = [0u8; PATH_MAX];
    let n = path_for(s, key, KIND_OBJECT, &mut path);
    let io = s.io();
    let fd = io.path(fs::OPEN, &mut path[..n]);
    if fd == ERR_NOENT {
        return Ok(Holder::Nobody);
    }
    if fd < 0 {
        return Err(fd);
    }
    match read_header(s, fd) {
        Ok(h) if s.hdr_key(&h) == key => Ok(Holder::This(fd, h)),
        Ok(_) => {
            io.close(fd);
            Ok(Holder::Another)
        }
        Err(e) => {
            io.close(fd);
            if e == ERR_NXIO {
                Ok(Holder::Nobody)
            } else {
                Err(e)
            }
        }
    }
}

/// Open `key`'s object: its fd and header, `ERR_NXIO` when the store does not
/// hold `key`, or the filesystem's errno.
fn open_object(s: &mut State, key: &[u8]) -> Result<(i32, Header), i32> {
    match name_holder(s, key)? {
        Holder::This(fd, h) => Ok((fd, h)),
        Holder::Nobody | Holder::Another => Err(ERR_NXIO),
    }
}

// ── the write slot ────────────────────────────────────────────────────

/// Take the store's write slot for the request `ask`, or say why not: `Ok`
/// with the slot held (fresh, or this request's own from an earlier ask),
/// `Err(EBUSY)` while another write holds it.
fn claim_write(s: &mut State, ask: [u8; 32], first_stage: u8) -> Result<(), i32> {
    if s.write.live != 0 && s.write.ask == ask {
        return Ok(());
    }
    if s.write.live != 0 {
        if s.write.refused < SUPERSEDE_AFTER {
            s.write.refused += 1;
            return Err(ERR_BUSY);
        }
        // Abandoned. A `PUT` has published nothing until its final ask, so
        // asked again it starts over; a `DELETE` past its unlink is decided,
        // and asked again it answers success.
        if s.write.stage == DEL_FENCE {
            s.settled_ask = s.write.ask;
            s.settled = 1;
        }
        release_write(s);
    }
    s.write = Write {
        ask,
        live: 1,
        stage: first_stage,
        fd: -1,
        written: 0,
        hashed: 0,
        hash: Sha256::new(),
        etag: [0; ETAG_LEN],
        durable: 0,
        failed: 0,
        refused: 0,
    };
    Ok(())
}

/// Free the write slot, closing the temporary if it is open.
fn release_write(s: &mut State) {
    if s.write.fd >= 0 {
        s.io().close(s.write.fd);
        s.write.fd = -1;
    }
    s.write.live = 0;
}

// ── PUT ───────────────────────────────────────────────────────────────

/// `[key_len:u16][key][ct_len:u8][ct][body_ptr:u64][body_len:u64][pre:u8]
/// [etag_len:u8][etag][fence_ptr:u64][fence_cap:u16]`
fn op_put(s: &mut State, a: &[u8]) -> i32 {
    let Some(kl) = u16_at(a, 0) else {
        return ERR_INVAL;
    };
    let kl = kl as usize;
    let Some(key) = a.get(2..2 + kl) else {
        return ERR_INVAL;
    };
    let at = 2 + kl;
    let Some(&cl) = a.get(at) else {
        return ERR_INVAL;
    };
    let cl = cl as usize;
    let Some(ct) = a.get(at + 1..at + 1 + cl) else {
        return ERR_INVAL;
    };
    let at = at + 1 + cl;
    let (Some(body_ptr), Some(body_len), Some(&pre), Some(&el)) = (
        u64_at(a, at),
        u64_at(a, at + 8),
        a.get(at + 16),
        a.get(at + 17),
    ) else {
        return ERR_INVAL;
    };
    let at = at + 18 + el as usize;
    let (Some(fence_ptr), Some(fence_cap)) = (u64_at(a, at), u16_at(a, at + 8)) else {
        return ERR_INVAL;
    };
    if !valid_key(key) || !fence_ok(fence_ptr, fence_cap) {
        return ERR_INVAL;
    }
    if (body_ptr == 0 && body_len != 0) || body_len > isize::MAX as u64 {
        return ERR_INVAL;
    }
    if pre == obj::precondition::ETAG {
        return ERR_NOSYS;
    }
    if pre != obj::precondition::ANY && pre != obj::precondition::ABSENT {
        return ERR_INVAL;
    }
    let Some(caps) = caps(s) else {
        return ERR_INPROGRESS;
    };
    if caps & PUT_NEEDS != PUT_NEEDS {
        return ERR_NOSYS;
    }
    // SAFETY: the caller named `body_len` readable bytes at `body_ptr`, and
    // keeps them unchanged until the write is decided.
    let body = if body_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(body_ptr as *const u8, body_len as usize) }
    };

    if let Err(e) = claim_write(s, ask_of(Ask::Put, a), PUT_ROOT) {
        return e;
    }
    let rc = put_step(s, key, ct, body, pre);
    if rc == ERR_AGAIN {
        return ERR_INPROGRESS;
    }
    if rc < 0 && s.write.stage > PUT_CREATE && s.write.stage != PUT_DISCARD {
        // The temporary exists: remove it before answering.
        if s.write.fd >= 0 {
            s.io().close(s.write.fd);
            s.write.fd = -1;
        }
        s.write.failed = rc;
        s.write.stage = PUT_DISCARD;
        return ERR_INPROGRESS;
    }
    let durable = s.write.durable != 0;
    release_write(s);
    if rc < 0 {
        return rc;
    }
    // The key exists again: a superseded `DELETE` of it no longer stands.
    s.settled = 0;
    let fence = if durable {
        Fence::LocalDurable {
            device_id: s.device,
        }
    } else {
        Fence::Volatile
    };
    write_fence(fence, fence_ptr, fence_cap);
    0
}

/// One ask's step of a `PUT`: 0 when it is done, `ERR_AGAIN` to be asked
/// again from where `s.write` says it got, or the errno that decided it.
fn put_step(s: &mut State, key: &[u8], ct: &[u8], body: &[u8], pre: u8) -> i32 {
    let io = s.io();
    let hdr_len = HDR_FIXED + key.len() + 1 + ct.len() + ETAG_LEN;
    let total = (hdr_len + body.len()) as u64;
    let mut tmp = [0u8; PATH_MAX];
    let tn = path_for(s, key, KIND_TEMP, &mut tmp);
    match s.write.stage {
        PUT_ROOT => {
            s.write.stage = PUT_CHECK;
            if s.root_made != 0 {
                return put_step(s, key, ct, body, pre);
            }
            // A deferred MKDIR stays at this stage and is asked again; an
            // existing directory is success.
            let mut root = s.root;
            let rc = io.settle_path(fs::MKDIR, &mut root[..s.root_len]);
            if rc < 0 && rc != ERR_EXIST {
                s.write.stage = PUT_ROOT;
                return rc;
            }
            s.root_made = 1;
            ERR_AGAIN
        }
        PUT_CHECK => {
            // What the object's name holds now: nothing, this key, or --
            // a collision -- another key, which a write must not replace.
            match name_holder(s, key) {
                Ok(Holder::Nobody) => {}
                Ok(Holder::This(fd, _)) => {
                    io.close(fd);
                    if pre == obj::precondition::ABSENT {
                        return ERR_EXIST;
                    }
                }
                Ok(Holder::Another) => return ERR_EXIST,
                Err(e) => return e,
            }
            s.write.stage = PUT_HASH;
            ERR_AGAIN
        }
        PUT_HASH => {
            let at = s.write.hashed as usize;
            let n = core::cmp::min(HASH_CHUNK, body.len() - at);
            s.write.hash.update(&body[at..at + n]);
            s.write.hashed += n as u64;
            if at + n == body.len() {
                let h = core::mem::take(&mut s.write.hash);
                s.write.etag = h.finalize();
                s.write.stage = PUT_CLEAR;
            }
            ERR_AGAIN
        }
        PUT_CLEAR => {
            // A temporary left by an interrupted attempt is removed, not
            // written over: OPEN_CREATE does not truncate.
            let rc = io.settle_path(fs::UNLINK, &mut tmp[..tn]);
            if rc < 0 && rc != ERR_NOENT {
                return rc;
            }
            s.write.stage = PUT_CREATE;
            ERR_AGAIN
        }
        PUT_CREATE => {
            let fd = io.settle_path(fs::OPEN_CREATE, &mut tmp[..tn]);
            if fd < 0 {
                return fd;
            }
            s.write.fd = fd;
            s.write.written = 0;
            s.write.stage = PUT_WRITE;
            ERR_AGAIN
        }
        PUT_WRITE => {
            let at = s.write.written as usize;
            let rc = if at < hdr_len {
                // The header is rebuilt each ask, the same bytes every time,
                // and written from where the last ask stopped.
                build_header(s, key, ct);
                io.call(
                    s.write.fd,
                    fs::WRITE,
                    s.hdr[at..].as_mut_ptr(),
                    hdr_len - at,
                )
            } else {
                let at = at - hdr_len;
                let n = core::cmp::min(WRITE_CHUNK, body.len() - at);
                io.call(s.write.fd, fs::WRITE, body[at..].as_ptr() as *mut u8, n)
            };
            if rc < 0 {
                return rc;
            }
            if rc == 0 {
                // A filesystem that takes no bytes is full.
                return ERR_NOSPC;
            }
            s.write.written += rc as u64;
            if s.write.written >= total {
                s.write.stage = PUT_FSYNC;
            }
            ERR_AGAIN
        }
        PUT_FSYNC => {
            let rc = io.settle(s.write.fd, fs::FSYNC, core::ptr::null_mut(), 0);
            if rc < 0 {
                return rc;
            }
            if let Some(d) = io.durable_device(s.write.fd) {
                s.device = d;
                s.device_known = 1;
                s.write.durable = 1;
            }
            s.write.stage = PUT_PUBLISH;
            ERR_AGAIN
        }
        PUT_PUBLISH => {
            if s.write.fd >= 0 {
                io.close(s.write.fd);
                s.write.fd = -1;
            }
            let mut fin = [0u8; PATH_MAX];
            let fname = path_for(s, key, KIND_OBJECT, &mut fin);
            let mut arg = [0u8; 2 * PATH_MAX + 4];
            arg[..2].copy_from_slice(&(tn as u16).to_le_bytes());
            arg[2..2 + tn].copy_from_slice(&tmp[..tn]);
            arg[2 + tn..4 + tn].copy_from_slice(&(fname as u16).to_le_bytes());
            arg[4 + tn..4 + tn + fname].copy_from_slice(&fin[..fname]);
            io.settle(-1, fs::RENAME, arg.as_mut_ptr(), 4 + tn + fname)
        }
        PUT_DISCARD => {
            let rc = io.settle_path(fs::UNLINK, &mut tmp[..tn]);
            if rc == ERR_AGAIN {
                return ERR_AGAIN;
            }
            s.write.failed
        }
        _ => ERR_INVAL,
    }
}

/// The object header for `key`, built into `s.hdr` with the etag the `PUT`
/// computed.
fn build_header(s: &mut State, key: &[u8], ct: &[u8]) {
    let hdr_len = HDR_FIXED + key.len() + 1 + ct.len() + ETAG_LEN;
    let h = &mut s.hdr;
    h[..4].copy_from_slice(&MAGIC);
    h[4..6].copy_from_slice(&(hdr_len as u16).to_le_bytes());
    h[6..8].copy_from_slice(&(key.len() as u16).to_le_bytes());
    h[8..8 + key.len()].copy_from_slice(key);
    let at = 8 + key.len();
    h[at] = ct.len() as u8;
    h[at + 1..at + 1 + ct.len()].copy_from_slice(ct);
    let at = at + 1 + ct.len();
    h[at..at + ETAG_LEN].copy_from_slice(&s.write.etag);
}

// ── DELETE ────────────────────────────────────────────────────────────

/// `[key_len:u16][key][pre:u8][etag_len:u8][etag][fence_ptr:u64][fence_cap:u16]`
fn op_delete(s: &mut State, a: &[u8]) -> i32 {
    let Some(kl) = u16_at(a, 0) else {
        return ERR_INVAL;
    };
    let kl = kl as usize;
    let Some(key) = a.get(2..2 + kl) else {
        return ERR_INVAL;
    };
    let at = 2 + kl;
    let (Some(&pre), Some(&el)) = (a.get(at), a.get(at + 1)) else {
        return ERR_INVAL;
    };
    let at = at + 2 + el as usize;
    let (Some(fp), Some(fc)) = (u64_at(a, at), u16_at(a, at + 8)) else {
        return ERR_INVAL;
    };
    if key.is_empty() || !fence_ok(fp, fc) {
        return ERR_INVAL;
    }
    if pre == obj::precondition::ABSENT || pre == obj::precondition::ETAG {
        return ERR_NOSYS;
    }
    if pre != obj::precondition::ANY {
        return ERR_INVAL;
    }
    let ask = ask_of(Ask::Delete, a);
    if s.settled != 0 && s.settled_ask == ask {
        s.settled = 0;
        write_fence(Fence::Volatile, fp, fc);
        return 0;
    }
    let Some(caps) = caps(s) else {
        return ERR_INPROGRESS;
    };
    if caps & fs::caps::UNLINK == 0 {
        return ERR_NOSYS;
    }
    if let Err(e) = claim_write(s, ask, DEL_CHECK) {
        return e;
    }
    let io = s.io();
    let mut path = [0u8; PATH_MAX];
    let n = path_for(s, key, KIND_OBJECT, &mut path);
    let rc = match s.write.stage {
        DEL_CHECK => {
            // Only this key's object: a name shared with another key is not
            // it. Checked once, in an ask of its own: on a filesystem that
            // keys a deferred walk by the name it looks for (FAT32 does), an
            // open and an unlink of one name in the same ask would resume
            // each other's walk and start their own over.
            match open_object(s, key) {
                Ok((fd, _)) => {
                    io.close(fd);
                    s.write.stage = DEL_UNLINK;
                    ERR_AGAIN
                }
                Err(ERR_NXIO) => ERR_NOENT,
                Err(e) => e,
            }
        }
        DEL_UNLINK => {
            let rc = io.settle_path(fs::UNLINK, &mut path[..n]);
            if rc < 0 {
                rc
            } else if caps & fs::caps::FSYNC_NAME != 0 {
                // The name's fence is a flush of its own: the next ask.
                s.write.stage = DEL_FENCE;
                ERR_AGAIN
            } else {
                release_write(s);
                write_fence(Fence::Volatile, fp, fc);
                return 0;
            }
        }
        DEL_FENCE => {
            let rc = io.settle_path(fs::FSYNC_NAME, &mut path[..n]);
            if rc == ERR_AGAIN {
                return ERR_INPROGRESS;
            }
            release_write(s);
            // The object is gone either way; the fence says whether its
            // removal is known to have reached the device.
            let fence = if rc >= 0 && s.device_known != 0 {
                Fence::LocalDurable {
                    device_id: s.device,
                }
            } else {
                Fence::Volatile
            };
            write_fence(fence, fp, fc);
            return 0;
        }
        _ => ERR_INVAL,
    };
    if rc == ERR_AGAIN {
        return ERR_INPROGRESS;
    }
    release_write(s);
    rc
}

// ── GET / RANGE_GET / CLOSE / HEAD ────────────────────────────────────

fn op_get(s: &mut State, a: &[u8]) -> i32 {
    if a.is_empty() || a.len() > KEY_MAX {
        return ERR_INVAL;
    }
    let Some(slot) = s.reads.iter().position(|r| r.live == 0) else {
        return ERR_BUSY;
    };
    let (fd, h) = match open_object(s, a) {
        Ok(x) => x,
        Err(ERR_NXIO) => return ERR_NOENT,
        Err(e) => return e,
    };
    let io = s.io();
    let size = match io.stat(fd) {
        Ok((size, _)) => size,
        Err(e) => {
            io.close(fd);
            return e;
        }
    };
    s.reads[slot] = ReadSlot {
        fd,
        hdr_len: h.hdr_len as u32,
        size: size.saturating_sub(h.hdr_len as u64),
        live: 1,
    };
    abi::kernel_abi::fd::tag_fd(abi::kernel_abi::fd::FD_TAG_STORAGE_OBJECT, slot as i32)
}

/// The live read slot `handle` names (the kernel strips the tag).
fn read_slot(s: &State, handle: i32) -> Option<(usize, ReadSlot)> {
    if handle < 0 {
        return None;
    }
    let slot = abi::kernel_abi::fd::slot_of(handle) as usize;
    let r = *s.reads.get(slot)?;
    if r.live == 0 {
        return None;
    }
    Some((slot, r))
}

/// `[offset:u64][length:u32][out_ptr:u64]`
fn op_range(s: &mut State, handle: i32, a: &[u8]) -> i32 {
    let Some((_, r)) = read_slot(s, handle) else {
        return ERR_BADF;
    };
    let (Some(offset), Some(len), Some(out)) = (u64_at(a, 0), u32_at(a, 8), u64_at(a, 12)) else {
        return ERR_INVAL;
    };
    if out == 0 && len != 0 {
        return ERR_INVAL;
    }
    if offset >= r.size {
        return 0;
    }
    // The count is answered as an `i32`.
    let len = core::cmp::min(u64::from(len), r.size - offset);
    let len = core::cmp::min(len, i32::MAX as u64) as usize;
    let io = s.io();
    let mut seek = (offset + u64::from(r.hdr_len)).to_le_bytes();
    let rc = io.call(r.fd, fs::SEEK, seek.as_mut_ptr(), 8);
    if rc < 0 {
        return rc;
    }
    // A short count is an answer: the caller asks for the rest at the
    // offset it reaches.
    io.read_some(r.fd, out as *mut u8, len)
}

fn op_close(s: &mut State, handle: i32) -> i32 {
    let Some((slot, r)) = read_slot(s, handle) else {
        return ERR_BADF;
    };
    s.io().close(r.fd);
    s.reads[slot] = READ_EMPTY;
    0
}

/// `[key_len:u16][key][out_ptr:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]`
fn op_head(s: &mut State, a: &[u8]) -> i32 {
    let Some(kl) = u16_at(a, 0) else {
        return ERR_INVAL;
    };
    let kl = kl as usize;
    let Some(key) = a.get(2..2 + kl) else {
        return ERR_INVAL;
    };
    let at = 2 + kl;
    let (Some(out), Some(cap), Some(fp), Some(fc)) = (
        u64_at(a, at),
        u32_at(a, at + 8),
        u64_at(a, at + 12),
        u16_at(a, at + 20),
    ) else {
        return ERR_INVAL;
    };
    if out == 0 || !fence_ok(fp, fc) {
        return ERR_INVAL;
    }
    let (fd, h) = match open_object(s, key) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let io = s.io();
    let st = io.stat(fd);
    io.close(fd);
    let (size, mtime) = match st {
        Ok(x) => x,
        Err(e) => return e,
    };
    let need = 8 + 8 + 1 + h.ct_len + 1 + ETAG_LEN;
    if (cap as usize) < need {
        return ERR_NOMEM;
    }
    // SAFETY: the caller named `cap` writable bytes at `out`.
    let o = unsafe { core::slice::from_raw_parts_mut(out as *mut u8, cap as usize) };
    o[..8].copy_from_slice(&size.saturating_sub(h.hdr_len as u64).to_le_bytes());
    o[8..16].copy_from_slice(&mtime.to_le_bytes());
    o[16] = h.ct_len as u8;
    o[17..17 + h.ct_len].copy_from_slice(&s.hdr[h.ct_at..h.ct_at + h.ct_len]);
    let at = 17 + h.ct_len;
    o[at] = ETAG_LEN as u8;
    o[at + 1..at + 1 + ETAG_LEN].copy_from_slice(&s.hdr[h.etag_at..h.etag_at + ETAG_LEN]);
    write_fence(Fence::Volatile, fp, fc);
    need as i32
}

/// `abi::fence::QUERY_OP` on a read handle: what its reads achieved, which
/// is `Volatile`.
fn op_fence_query(s: &State, handle: i32, out: *mut u8, cap: usize) -> i32 {
    if out.is_null() || cap < abi::fence::WIRE_MAX_LEN {
        return ERR_INVAL;
    }
    if read_slot(s, handle).is_none() {
        return ERR_NOSYS;
    }
    // SAFETY: the caller named `cap` writable bytes at `out`.
    let buf = unsafe { core::slice::from_raw_parts_mut(out, cap) };
    match Fence::Volatile.encode(buf) {
        Some(n) => n as i32,
        None => ERR_INVAL,
    }
}

// ── listing ───────────────────────────────────────────────────────────

/// A listing cursor this store could have issued for `prefix`: empty, or a
/// key under the prefix.
fn cursor_ok(cursor: &[u8], prefix: &[u8]) -> bool {
    cursor.is_empty() || (cursor.starts_with(prefix) && utf8_valid(cursor))
}

/// Walk the object directory, picking the `max` smallest keys that start
/// with `prefix` and sort after `cursor`. `Ok(())` once the walk is whole;
/// `Err(ERR_AGAIN)` to be resumed by the same request. A different request
/// waits (`ERR_AGAIN`) while another scan is in flight, and supersedes it
/// once it has waited `SUPERSEDE_AFTER` times.
fn scan(s: &mut State, ask: [u8; 32], prefix: &[u8], cursor: &[u8], max: usize) -> Result<(), i32> {
    let io = s.io();
    if s.scan.live != 0 && s.scan.ask != ask {
        if s.scan.refused < SUPERSEDE_AFTER {
            s.scan.refused += 1;
            return Err(ERR_AGAIN);
        }
        end_scan(s);
    }
    if s.scan.live == 0 {
        let mut root = s.root;
        let dir = io.path(fs::OPENDIR, &mut root[..s.root_len]);
        if dir < 0 && dir != ERR_NOENT {
            return Err(dir);
        }
        s.scan.ask = ask;
        s.scan.live = 1;
        // No directory: nothing has been written, an empty store.
        s.scan.dir = if dir < 0 { -1 } else { dir };
        s.scan.count = 0;
        s.scan.more = 0;
        s.scan.refused = 0;
        s.scan.batch_left = 0;
        s.scan.batch_at = 0;
        s.scan.batch_len = 0;
    }
    s.scan.opens = 0;
    while s.scan.dir >= 0 {
        if s.scan.batch_left == 0 {
            let rc = io.call(
                s.scan.dir,
                fs::READDIR,
                s.scan.batch.as_mut_ptr(),
                DIR_BATCH,
            );
            if rc < 0 {
                return Err(rc);
            }
            if rc == 0 {
                io.close(s.scan.dir);
                s.scan.dir = -1;
                break;
            }
            s.scan.batch_len = rc as u16;
            s.scan.batch_left = u16_at(&s.scan.batch, 0).unwrap_or(0);
            s.scan.batch_at = 2;
            continue;
        }
        let at = s.scan.batch_at as usize;
        let (Some(&name_len), Some(&kind)) = (s.scan.batch.get(at), s.scan.batch.get(at + 1))
        else {
            return Err(ERR_IO);
        };
        let end = at + 2 + name_len as usize;
        if end > s.scan.batch_len as usize {
            return Err(ERR_IO);
        }
        let mut name = [0u8; NAME_LEN];
        let is_object_name = kind == 0
            && name_len as usize == NAME_LEN
            && s.scan.batch[at + 2 + 8] == b'.'
            && s.scan.batch[at + 2 + 9].eq_ignore_ascii_case(&KIND_OBJECT);
        if is_object_name {
            name.copy_from_slice(&s.scan.batch[at + 2..end]);
            // The entry is consumed only once considered: when the call's
            // opens are spent or the filesystem defers, the resumed walk
            // reads that entry again.
            consider(s, &name, prefix, cursor, max)?;
        }
        s.scan.batch_at = end as u16;
        s.scan.batch_left -= 1;
    }
    Ok(())
}

/// Close the scan's directory and free the scan.
fn end_scan(s: &mut State) {
    if s.scan.dir >= 0 {
        s.io().close(s.scan.dir);
        s.scan.dir = -1;
    }
    s.scan.live = 0;
}

/// One object-named directory entry: if it holds a key that belongs on the
/// page, pick it.
fn consider(
    s: &mut State,
    name: &[u8; NAME_LEN],
    prefix: &[u8],
    cursor: &[u8],
    max: usize,
) -> Result<(), i32> {
    if s.scan.opens >= SCAN_OPENS_PER_CALL {
        return Err(ERR_AGAIN);
    }
    s.scan.opens += 1;
    let io = s.io();
    let mut path = [0u8; PATH_MAX];
    let n = path_of(s, name, &mut path);
    let fd = io.path(fs::OPEN, &mut path[..n]);
    if fd == ERR_AGAIN {
        return Err(ERR_AGAIN);
    }
    if fd < 0 {
        return Ok(());
    }
    let h = read_header(s, fd);
    let st = io.stat(fd);
    io.close(fd);
    let h = match h {
        Ok(h) => h,
        Err(ERR_AGAIN) => return Err(ERR_AGAIN),
        Err(_) => return Ok(()),
    };
    let (size, mtime) = match st {
        Ok(x) => x,
        Err(ERR_AGAIN) => return Err(ERR_AGAIN),
        Err(_) => return Ok(()),
    };
    let mut key_buf = [0u8; KEY_MAX];
    key_buf[..h.key_len].copy_from_slice(s.hdr_key(&h));
    let key = &key_buf[..h.key_len];
    // Listed only under the name its key maps to, which is where `GET`,
    // `HEAD` and `DELETE` look for it.
    let want = name_for(key, KIND_OBJECT);
    if !want.eq_ignore_ascii_case(name) {
        return Ok(());
    }
    if !key.starts_with(prefix) || (!cursor.is_empty() && key <= cursor) {
        return Ok(());
    }
    // Insert in order among the picked, keeping the `max` smallest.
    let count = s.scan.count as usize;
    let mut pos = count;
    while pos > 0 && key < &s.scan.picked[pos - 1].key[..s.scan.picked[pos - 1].key_len as usize] {
        pos -= 1;
    }
    if pos >= max {
        s.scan.more = 1;
        return Ok(());
    }
    let mut p = PICKED_EMPTY;
    p.key[..key.len()].copy_from_slice(key);
    p.key_len = key.len() as u8;
    p.size = size.saturating_sub(h.hdr_len as u64);
    p.mtime = mtime;
    p.etag
        .copy_from_slice(&s.hdr[h.etag_at..h.etag_at + ETAG_LEN]);
    let last = if count < max {
        s.scan.count += 1;
        count
    } else {
        // The page is full: the largest picked key drops off it.
        s.scan.more = 1;
        max - 1
    };
    let mut i = last;
    while i > pos {
        s.scan.picked[i] = s.scan.picked[i - 1];
        i -= 1;
    }
    s.scan.picked[pos] = p;
    Ok(())
}

/// Run the scan for a listing request, ending it unless it is to be resumed.
fn run_scan(s: &mut State, ask: [u8; 32], prefix: &[u8], cursor: &[u8], max: usize) -> i32 {
    match scan(s, ask, prefix, cursor, max) {
        Ok(()) => {
            end_scan(s);
            0
        }
        Err(ERR_AGAIN) => ERR_AGAIN,
        Err(e) => {
            end_scan(s);
            e
        }
    }
}

/// The cursor a page of the first `emitted` picked keys ends with: the
/// last of them when more remain, else empty.
fn page_cursor(s: &State, emitted: usize, cut: bool) -> &[u8] {
    if (cut || s.scan.more != 0) && emitted > 0 {
        let p = &s.scan.picked[emitted - 1];
        &p.key[..p.key_len as usize]
    } else {
        &[]
    }
}

/// `storage.object::LIST`.
fn op_obj_list(s: &mut State, a: &[u8]) -> i32 {
    let Some(req) = obj::list::parse_request(a) else {
        return ERR_INVAL;
    };
    if !cursor_ok(req.cursor, req.prefix) {
        return ERR_INVAL;
    }
    let max = core::cmp::min(req.max_keys as usize, PAGE_KEYS);
    let rc = run_scan(s, ask_of(Ask::ObjectList, a), req.prefix, req.cursor, max);
    if rc < 0 {
        return rc;
    }
    // SAFETY: the caller named `out_cap` writable bytes at `out_ptr`.
    let out =
        unsafe { core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize) };
    let mut w = obj::list::PageWriter::new(out, max as u16);
    let mut emitted = 0usize;
    let mut cut = false;
    while emitted < s.scan.count as usize {
        let p = &s.scan.picked[emitted];
        if !w.push(&p.key[..p.key_len as usize], p.size, p.mtime, &p.etag) {
            cut = true;
            break;
        }
        emitted += 1;
    }
    if cut && emitted == 0 {
        return ERR_NOMEM;
    }
    let Some(n) = w.finish(page_cursor(s, emitted, cut)) else {
        return ERR_NOMEM;
    };
    write_fence(Fence::Volatile, req.fence_out_ptr, req.fence_out_cap);
    n as i32
}

/// `storage.namespace::LIST`, key-shaped: every key under the prefix.
fn op_ns_list(s: &mut State, a: &[u8]) -> i32 {
    let Some(req) = ns::list::parse_request(a) else {
        return ERR_INVAL;
    };
    if !cursor_ok(req.cursor, req.prefix) {
        return ERR_INVAL;
    }
    let rc = run_scan(
        s,
        ask_of(Ask::NamespaceList, a),
        req.prefix,
        req.cursor,
        PAGE_KEYS,
    );
    if rc < 0 {
        return rc;
    }
    // SAFETY: the caller named `out_cap` writable bytes at `out_ptr`.
    let out =
        unsafe { core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize) };
    let mut w = ns::list::PageWriter::new(out);
    let mut emitted = 0usize;
    let mut cut = false;
    while emitted < s.scan.count as usize {
        let p = &s.scan.picked[emitted];
        if !w.push(&p.key[..p.key_len as usize], ns::KIND_OBJECT) {
            cut = true;
            break;
        }
        emitted += 1;
    }
    if cut && emitted == 0 {
        return ERR_NOMEM;
    }
    let Some(n) = w.finish(page_cursor(s, emitted, cut)) else {
        return ERR_NOMEM;
    };
    write_fence(Fence::Volatile, req.fence_out_ptr, req.fence_out_cap);
    n as i32
}

// ── module ABI ────────────────────────────────────────────────────────

declare_module_state_bytes!(State);

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
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
    if syscalls.is_null() || state.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    // SAFETY: the loader hands a block of at least `State`'s size, which is
    // zeroed here before it is read as a `State`; every field is valid at
    // all-zero bytes.
    unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.reads = [READ_EMPTY; READS];
        s.write.fd = -1;
        s.scan.dir = -1;
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        }
    }
    // SAFETY: as above; the block is a `State` now.
    let s = unsafe { &mut *(state as *mut State) };
    if s.root_len > ROOT_MAX {
        return -3;
    }
    if s.root_len == 0 {
        let d = b"/objects";
        s.root[..d.len()].copy_from_slice(d);
        s.root_len = d.len();
    }
    // A trailing separator would double in every path.
    while s.root_len > 1 && s.root[s.root_len - 1] == b'/' {
        s.root_len -= 1;
    }
    0
}

/// Providers are called through `provider_call`, never stepped for work.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(_state: *mut u8) -> i32 {
    0
}

/// Both surfaces of one store: its objects and their namespace. A
/// contract's id is its opcodes' class byte.
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provides_contracts"
)]
#[cfg_attr(not(feature = "host-test"), no_mangle)]
pub unsafe extern "C" fn module_provides_contracts(
    _state: *mut u8,
    out: *mut u16,
    cap: u32,
) -> u32 {
    if out.is_null() || cap < 2 {
        return 0;
    }
    // SAFETY: the loader named `cap` (>= 2) writable `u16`s at `out`.
    unsafe {
        *out = (obj::PUT >> 8) as u16;
        *out.add(1) = (ns::LIST >> 8) as u16;
    }
    2
}

#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_dispatch"
)]
#[cfg_attr(not(feature = "host-test"), export_name = "module_provider_dispatch")]
pub unsafe extern "C" fn fs_object_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() {
        return ERR_INVAL;
    }
    // SAFETY: the kernel passes the state block `module_new` initialised.
    let s = unsafe { &mut *(state as *mut State) };
    if opcode == abi::fence::QUERY_OP {
        return op_fence_query(s, handle, arg, arg_len);
    }
    let a: &[u8] = if arg.is_null() || arg_len == 0 {
        &[]
    } else {
        // SAFETY: the caller named `arg_len` readable bytes at `arg`.
        unsafe { core::slice::from_raw_parts(arg as *const u8, arg_len) }
    };
    match opcode {
        obj::PUT => op_put(s, a),
        obj::GET => op_get(s, a),
        obj::HEAD => op_head(s, a),
        obj::RANGE_GET => op_range(s, handle, a),
        obj::DELETE => op_delete(s, a),
        obj::CLOSE => op_close(s, handle),
        obj::LIST => op_obj_list(s, a),
        // No mesh roots: an unguarded store, served with `handle = -1`.
        obj::PRESENT => ERR_NOSYS,
        // Key-shaped, with no optional namespace opcode.
        ns::CAPS => 0,
        ns::LIST => op_ns_list(s, a),
        _ => ERR_NOSYS,
    }
}

include!("../../sdk/runtime/wasm_entry.rs");

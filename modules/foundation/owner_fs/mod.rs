//! The node's workload `fs` layer: every workload's files, each in a root of
//! its own on the node's file system.
//!
//! Registered `provider_scope = "workloads"`: the kernel shows this layer to
//! every caller acting with an authority of its own (a workload) and to no
//! caller acting with the node's, so a workload's `fs` call lands here and
//! the node's own calls pass it by. This module's dispatch runs as the node,
//! so what it asks of `fs` reaches the layer beneath it — the node's `fat32`
//! (or `mount`) on metal, the host file system on Linux.
//!
//! - every path a workload names resolves inside `<root>/<uid hex>/files/`.
//!   `..` (or any all-dots name), a backslash or a NUL is refused, so no path
//!   leads out; an empty path or `/` names the root. Nothing here makes a
//!   link (`LINK`/`READLINK` are `ENOSYS` and absent from `CAPS`), so the
//!   confinement is lexical and sound on every file system beneath;
//! - every handle opened through a root is a slot of this module's own
//!   table, stamped with its opener: it means nothing to anyone else
//!   (`EBADF`), and the handle beneath it is never handed out;
//! - what the owner holds is charged to its storage line
//!   (`resource::LEDGER_CHARGE`, always in the owner's own call: the kernel
//!   charges the call's caller) by one rule on every file system: each file
//!   [`file_cost`] of its size, each directory [`ENTRY_COST`]. Growth is
//!   charged before it is asked for and refused with `ENOSPC` past the cap; a
//!   truncate, an unlink, a rmdir and a rename over an existing name give
//!   back what they removed. An owner with no storage line is refused
//!   `EACCES` before anything is made;
//! - volumes lent to an owner (the `ctl` port's records, keyed by its uid)
//!   are reached at and under each volume's `dst`, uncharged; a read-only one refuses
//!   everything that would change it (`EROFS`).
//!
//! Nothing here waits. The layer beneath may answer `EAGAIN` or
//! `EINPROGRESS` to anything; a workload's own request is passed down with
//! its answer, byte-identical for every re-ask, and the layer's own work —
//! making a root, measuring what it holds, removing it — is a resumable job:
//! one outstanding request at a time, re-asked with the same bytes, advanced
//! by `module_step` and by the owner's own calls while its root is not
//! ready (`EAGAIN` until it is). What a job measures is charged at the
//! owner's next call, past its cap if need be.
//!
//! ## A root's life
//!
//! - **Made on first use**: `<root>`, `<root>/<hex>`, `<root>/<hex>/files`,
//!   each made and its name fenced (`MKDIR` + `FSYNC_NAME`) before the next,
//!   so a root that answered once is on the media. What it already holds is
//!   then walked and charged to the owner.
//! - **Survives** a power cut and a reboot: nothing removes a live owner's
//!   root, so a workload readmitted under the same identity finds it.
//! - **Removed when the owner is released** (`OWNER_RELEASED`, whose record
//!   names the owner's uid, so a root it never touched this boot goes too).
//!   First a tombstone, `<root>/<hex>/gone`, made and fenced; then
//!   everything else under `<root>/<hex>` unlinked and rmdir'd depth first;
//!   then the parent fenced, the tombstone unlinked and `<root>/<hex>`
//!   removed. Removal gives nothing back: the line goes with the owner.
//! - **A half-removed root is never reused.** The tombstone is durable before
//!   the first entry is removed. A root carrying one is finished, never
//!   served: its owner waits (`EAGAIN`) while it is removed and is then given
//!   an empty root, and at start every `<root>/*` carrying one is queued for
//!   removal.
//!
//! An `EINPROGRESS` a workload abandons still completes beneath; what it
//! would have given back is then not given back, in the owner's disfavour.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ =>` arms in state-machine matches, so a new variant cannot bypass the error path"
)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

use abi::contracts::resource as res;
use abi::contracts::storage::fs as op;
use abi::kernel_abi::errno;

/// What a name costs its owner besides a file's bytes: an inode and a
/// directory entry.
pub const ENTRY_COST: u64 = 4096;

/// What a regular file of `size` bytes costs its owner.
pub const fn file_cost(size: u64) -> u64 {
    ENTRY_COST.saturating_add(size)
}

/// The flags of the charge that admits a new root: an owner the kernel
/// refuses it is answered `EACCES` before anything is made.
const ROOT_ADMIT_FLAGS: u8 = 0;

/// Longest path an owner names.
const PATH_MAX: usize = 255;
/// Longest path handed down: the root prefix plus an owner's path.
const PMAX: usize = 400;
/// Longest `root` param.
const ROOT_MAX: usize = 96;
/// Undecided (`EINPROGRESS`) path operations one owner may have outstanding.
const MAX_PENDING: usize = 4;
/// Directory levels the charging walk descends; deeper is charged as a name.
const SCAN_DEPTH: usize = 12;
/// Requests a job asks per pump.
const ASKS_PER_PUMP: usize = 16;
/// A request's argument, and a `READDIR` batch.
const REQ_MAX: usize = 512;
/// A lent volume's fields.
const DST_MAX: usize = 48;
const VOL_MAX: usize = 15;
const VPATH_MAX: usize = 128;
/// A `ctl` record.
const CTL_MAX: usize = 1 + 16 + 1 + DST_MAX + 1 + VOL_MAX + 2 + VPATH_MAX + 1;
const CTL_ADD: u8 = 1;
const CTL_REMOVE: u8 = 2;

const EBADF: i32 = errno::EBADF;
const ENOTDIR: i32 = -20;
const EIO: i32 = errno::EIO;

const FILES: &[u8] = b"files";
const TOMBSTONE: &[u8] = b"gone";

/// The heap figures the manifest's `heap_per_param` states, held here so a
/// table that outgrows them fails the build.
const ROOT_BYTES: usize = 336;
const SLOT_BYTES: usize = 64;
const VOLUME_BYTES: usize = 216;
const HEAP_BASE: usize = 256;

// ── Paths ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Path {
    b: [u8; PMAX],
    n: usize,
}

impl Path {
    const EMPTY: Self = Self { b: [0; PMAX], n: 0 };

    fn of(s: &[u8]) -> Self {
        let mut p = Self::EMPTY;
        p.push(s);
        p
    }
    fn bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
    fn arg(&mut self) -> &mut [u8] {
        &mut self.b[..self.n]
    }
    fn push(&mut self, s: &[u8]) -> bool {
        let end = self.n + s.len();
        if end > PMAX {
            return false;
        }
        self.b[self.n..end].copy_from_slice(s);
        self.n = end;
        true
    }
    fn push_comp(&mut self, c: &[u8]) -> bool {
        let save = self.n;
        if self.push(b"/") && self.push(c) {
            true
        } else {
            self.n = save;
            false
        }
    }
    fn pop_comp(&mut self) {
        if let Some(i) = self.bytes().iter().rposition(|&b| b == b'/') {
            self.n = i;
        }
    }
}

/// A root's directory name under `root`: its owner's identity in hex, or the
/// name a start sweep found a tombstoned root under.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Name {
    b: [u8; 64],
    n: u8,
}

impl Name {
    const EMPTY: Self = Self { b: [0; 64], n: 0 };

    fn hex(uid: &[u8; 16]) -> Self {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = Self::EMPTY;
        for (i, b) in uid.iter().enumerate() {
            s.b[2 * i] = DIGITS[(b >> 4) as usize];
            s.b[2 * i + 1] = DIGITS[(b & 15) as usize];
        }
        s.n = 32;
        s
    }
    fn of(c: &[u8]) -> Option<Self> {
        if c.is_empty() || c.len() > 64 {
            return None;
        }
        let mut s = Self::EMPTY;
        s.b[..c.len()].copy_from_slice(c);
        s.n = c.len() as u8;
        Some(s)
    }
    fn bytes(&self) -> &[u8] {
        &self.b[..self.n as usize]
    }
    /// `<root>/<name>`.
    fn dir(&self, base: &Path) -> Path {
        let mut p = *base;
        p.push_comp(self.bytes());
        p
    }
    /// `<root>/<name>/<leaf>`.
    fn sub(&self, base: &Path, leaf: &[u8]) -> Path {
        let mut p = self.dir(base);
        p.push_comp(leaf);
        p
    }
}

/// The components of an owner's `path`, checked: empty and `.` components
/// skipped, an all-dots component (`..` above all) `EACCES`, a NUL, a
/// backslash, or a trailing dot or space (which a volume would strip into
/// another name) `EINVAL`. Calls `f` with each component in order.
fn each_comp<'a>(path: &'a [u8], mut f: impl FnMut(&'a [u8]) -> bool) -> Result<usize, i32> {
    if path.len() > PATH_MAX {
        return Err(errno::E2BIG);
    }
    let mut comps = 0usize;
    for comp in path.split(|&b| b == b'/') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if comp.iter().all(|&b| b == b'.') {
            return Err(errno::EACCES);
        }
        if comp.iter().any(|&b| b == 0 || b == b'\\')
            || matches!(comp.last(), Some(b'.') | Some(b' '))
        {
            return Err(errno::EINVAL);
        }
        if !f(comp) {
            return Err(errno::E2BIG);
        }
        comps += 1;
    }
    Ok(comps)
}

/// `path` as the owner names it, appended beneath `out`. With `allow_root`
/// false a path that names the root itself is `EINVAL`: it names no entry.
fn rooted_under(mut out: Path, path: &[u8], allow_root: bool) -> Result<Path, i32> {
    let comps = each_comp(path, |c| out.push_comp(c))?;
    if comps == 0 && !allow_root {
        return Err(errno::EINVAL);
    }
    Ok(out)
}

fn fnv64(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for &b in *p {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    h
}

/// An `OPENDIR` answer naming no directory there: nothing at the path, not
/// a directory, or (from a file system that does not tell the two apart)
/// no such device.
fn no_dir(rc: i32) -> bool {
    rc == errno::ENOENT || rc == ENOTDIR || rc == errno::ENODEV
}

fn retry(rc: i32) -> bool {
    rc == errno::EAGAIN || rc == errno::EINPROGRESS
}

// ── Tables ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Free,
    /// Being made, then measured: the scan job's.
    Setup,
    Ready,
    /// Being removed: the removal job's.
    Removing,
    /// Could not be made or removed; the owner's calls answer `failed`.
    Failed,
}

#[derive(Clone, Copy)]
struct Pending {
    live: bool,
    opcode: u32,
    hash: u64,
    len: usize,
    reserved: u64,
    refund: u64,
}

const PENDING_EMPTY: Pending = Pending {
    live: false,
    opcode: 0,
    hash: 0,
    len: 0,
    reserved: 0,
    refund: 0,
};

/// An owner as the kernel names it to a provider: `CALLER_OWNER`'s record.
type Owner = [u8; 8];
const NOBODY: Owner = [0; 8];

#[derive(Clone, Copy)]
struct Root {
    phase: Phase,
    /// The owner it serves; [`NOBODY`] once released.
    owner: Owner,
    name: Name,
    /// The name is an identity in hex (not a name a sweep found).
    hexed: bool,
    /// Removing: the tombstone is already there.
    found_tombstone: bool,
    /// Removing: the owner is waiting to be given a fresh root once done.
    then_setup: bool,
    failed: i32,
    /// What the walk found the root holding, charged at the owner's next call.
    owed: u64,
    pend: [Pending; MAX_PENDING],
}

const ROOT_EMPTY: Root = Root {
    phase: Phase::Free,
    owner: NOBODY,
    name: Name::EMPTY,
    hexed: false,
    found_tombstone: false,
    then_setup: false,
    failed: 0,
    owed: 0,
    pend: [PENDING_EMPTY; MAX_PENDING],
};

#[derive(Clone, Copy)]
struct Slot {
    in_use: bool,
    owner: Owner,
    /// The handle beneath (this module's own).
    inner: i32,
    pos: u64,
    size: u64,
    size_known: bool,
    /// On a lent volume: never charged.
    lent: bool,
    /// On a read-only volume: nothing written through it.
    ro: bool,
    /// The lent volume it was opened on.
    vol: u16,
    /// An undecided `PREALLOCATE`: its capacity and what it reserved.
    prealloc: Option<(u32, u64)>,
}

const SLOT_EMPTY: Slot = Slot {
    in_use: false,
    owner: NOBODY,
    inner: -1,
    pos: 0,
    size: 0,
    size_known: false,
    lent: false,
    ro: false,
    vol: 0,
    prealloc: None,
};

#[derive(Clone, Copy)]
struct Volume {
    in_use: bool,
    ro: bool,
    uid: [u8; 16],
    dst: [u8; DST_MAX],
    dl: u8,
    vol: [u8; VOL_MAX],
    vl: u8,
    path: [u8; VPATH_MAX],
    pl: u8,
    /// The handle bound to the volume's provider; `-1` before first use.
    bound: i32,
}

const VOLUME_EMPTY: Volume = Volume {
    in_use: false,
    ro: false,
    uid: [0; 16],
    dst: [0; DST_MAX],
    dl: 0,
    vol: [0; VOL_MAX],
    vl: 0,
    path: [0; VPATH_MAX],
    pl: 0,
    bound: -1,
};

const _: () = assert!(core::mem::size_of::<Root>() <= ROOT_BYTES);
const _: () = assert!(core::mem::size_of::<Slot>() <= SLOT_BYTES);
const _: () = assert!(core::mem::size_of::<Volume>() <= VOLUME_BYTES);

// ── Jobs ───────────────────────────────────────────────────────────────────

/// One request a job has outstanding, kept whole so a re-ask is
/// byte-identical. `arg` is the op's `arg` record, or its `data` span for a
/// `READDIR`.
#[derive(Clone, Copy)]
struct Req {
    live: bool,
    opcode: u32,
    handle: i32,
    len: usize,
    data: bool,
    arg: [u8; REQ_MAX],
}

impl Req {
    const IDLE: Self = Self {
        live: false,
        opcode: 0,
        handle: -1,
        len: 0,
        data: false,
        arg: [0; REQ_MAX],
    };

    fn path(opcode: u32, p: &Path) -> Self {
        let mut r = Self {
            live: true,
            opcode,
            handle: -1,
            len: p.n.min(REQ_MAX),
            ..Self::IDLE
        };
        r.arg[..r.len].copy_from_slice(&p.bytes()[..r.len]);
        r
    }
    fn on(opcode: u32, handle: i32, out_len: usize) -> Self {
        Self {
            live: true,
            opcode,
            handle,
            len: out_len,
            ..Self::IDLE
        }
    }
    fn read_dir(handle: i32) -> Self {
        Self {
            live: true,
            opcode: op::READDIR,
            handle,
            len: REQ_MAX,
            data: true,
            ..Self::IDLE
        }
    }
}

/// A `READDIR` batch and the position of the next entry in it.
#[derive(Clone, Copy)]
struct Batch {
    buf: [u8; REQ_MAX],
    len: usize,
    pos: usize,
    left: u16,
}

impl Batch {
    fn load(&mut self, from: &[u8; REQ_MAX], n: usize) {
        self.buf = *from;
        self.len = n.min(REQ_MAX);
        self.left = if self.len >= 2 {
            u16::from_le_bytes([self.buf[0], self.buf[1]])
        } else {
            0
        };
        self.pos = 2;
    }
    fn next(&mut self) -> Option<(Name, bool)> {
        while self.left > 0 {
            self.left -= 1;
            let nl = *self.buf.get(self.pos)? as usize;
            let kind = *self.buf.get(self.pos + 1)?;
            let name = self.buf.get(self.pos + 2..self.pos + 2 + nl)?;
            self.pos += 2 + nl;
            if let Some(n) = Name::of(name) {
                return Some((n, kind == 1));
            }
        }
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ScanStage {
    Idle,
    Tombstone,
    TombstoneClose,
    Make(u8),
    Walk,
    ReadDir,
    Entry,
    OpenSub,
    FileOpen,
    FileStat,
}

struct Scan {
    root: usize,
    stage: ScanStage,
    req: Req,
    held: i32,
    depth: usize,
    dirs: [i32; SCAN_DEPTH],
    batch: [Batch; SCAN_DEPTH],
    path: Path,
    total: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RmStage {
    SweepOpen,
    SweepRead,
    SweepEntry,
    SweepCheck,
    Idle,
    Mark,
    MarkClose,
    MarkFence,
    WalkOpen,
    WalkRead,
    Unlink,
    Rmdir,
    Fence,
    Unmark,
    RmRoot,
}

struct Remove {
    root: usize,
    stage: RmStage,
    req: Req,
    held: i32,
    path: Path,
    batch: Batch,
    candidate: Name,
}

// ── State ──────────────────────────────────────────────────────────────────

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    /// The volume records' channel (in[0]); `-1` when unwired.
    ctl: i32,
    /// The `root` param: where every owner's root lives.
    base: Path,
    /// `root` is longer than [`ROOT_MAX`] or not absolute: the instance
    /// refuses to construct rather than root owners elsewhere.
    root_bad: bool,
    n_roots: u16,
    n_slots: u16,
    max_open: u16,
    n_vols: u16,
    roots: *mut Root,
    slots: *mut Slot,
    vols: *mut Volume,
    scan: Scan,
    remove: Remove,
}

impl State {
    fn sys(&self) -> &SyscallTable {
        // SAFETY: set in `module_new` from the kernel's table, live for the
        // module's life.
        unsafe { &*self.syscalls }
    }
}

fn roots(s: &State) -> &'static mut [Root] {
    if s.roots.is_null() {
        return &mut [];
    }
    // SAFETY: `n_roots` entries of this instance's heap, taken at
    // construction; the provider runs one call at a time.
    unsafe { core::slice::from_raw_parts_mut(s.roots, usize::from(s.n_roots)) }
}

fn slots(s: &State) -> &'static mut [Slot] {
    if s.slots.is_null() {
        return &mut [];
    }
    // SAFETY: as `roots`.
    unsafe { core::slice::from_raw_parts_mut(s.slots, usize::from(s.n_slots)) }
}

fn vols(s: &State) -> &'static mut [Volume] {
    if s.vols.is_null() {
        return &mut [];
    }
    // SAFETY: as `roots`.
    unsafe { core::slice::from_raw_parts_mut(s.vols, usize::from(s.n_vols)) }
}

fn log(s: &State, level: u8, msg: &[u8]) {
    // SAFETY: `msg` is live for the call.
    unsafe { dev_log(s.sys(), level, msg.as_ptr(), msg.len()) };
}

/// Log `msg`, a name and an errno.
fn log_name(s: &State, level: u8, msg: &[u8], name: &[u8], rc: i32) {
    let mut line = [0u8; 160];
    let mut n = 0usize;
    for part in [msg, b" ", name, b" errno "] {
        let k = part.len().min(line.len() - n);
        line[n..n + k].copy_from_slice(&part[..k]);
        n += k;
    }
    if n + 11 <= line.len() {
        let v = rc.unsigned_abs();
        if rc < 0 {
            line[n] = b'-';
            n += 1;
        }
        // SAFETY: `line` has room for a u32's ten digits at `n`.
        n += unsafe { fmt_u32_raw(line.as_mut_ptr().add(n), v) };
    }
    log(s, level, &line[..n]);
}

// ── Calls down and to the kernel ───────────────────────────────────────────

/// Ask the node's file system. This dispatch runs as the node, so the
/// kernel passes this module's own workload layer by and reaches the layer
/// beneath.
fn fs_call(s: &State, handle: i32, opcode: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    let (dp, dl) = if data.is_empty() {
        (core::ptr::null_mut(), 0)
    } else {
        (data.as_mut_ptr(), data.len())
    };
    let (ap, al) = if arg.is_empty() {
        (core::ptr::null_mut(), 0)
    } else {
        (arg.as_mut_ptr(), arg.len())
    };
    // SAFETY: both spans are this frame's, disjoint, live for the call.
    unsafe { (s.sys().provider_call)(handle, opcode, ap, al, dp, dl) }
}

fn fs_close(s: &State, handle: i32) {
    if handle >= 0 {
        // SAFETY: a handle this module holds.
        unsafe { (s.sys().provider_close)(handle) };
    }
}

fn query(s: &State, key: u32, out: &mut [u8]) -> i32 {
    // SAFETY: `out` is this frame's own, live for the call.
    unsafe { (s.sys().provider_query)(-1, key, out.as_mut_ptr(), out.len()) }
}

/// The owner the current call is made for, `None` outside a call.
fn caller(s: &State) -> Option<Owner> {
    let mut r = NOBODY;
    (query(s, abi::kernel_abi::query_key::CALLER_OWNER, &mut r) == 8).then_some(r)
}

/// The current caller's durable identity.
fn caller_uid(s: &State) -> Option<[u8; 16]> {
    let mut u = [0u8; 16];
    (query(s, abi::kernel_abi::query_key::CALLER_OWNER_UID, &mut u) == 16).then_some(u)
}

/// Charge the calling owner's storage line: 0, `ENOSPC` past its cap,
/// `EACCES` when it holds no line.
fn charge(s: &State, bytes: u64, flags: u8) -> i32 {
    let mut a = [0u8; res::LEDGER_CHARGE_ARG_LEN];
    a[..2].copy_from_slice(&res::OWNER_LINE_STORAGE.to_le_bytes());
    a[2..10].copy_from_slice(&bytes.to_le_bytes());
    a[10] = flags;
    fs_call(s, -1, res::LEDGER_CHARGE, &mut a, &mut [])
}

/// Charge growth before it is asked for: 0, or what refuses it.
fn reserve(s: &State, bytes: u64) -> i32 {
    if bytes == 0 {
        return 0;
    }
    charge(s, bytes, 0)
}

/// Give `bytes` back to the calling owner's line.
fn give_back(s: &State, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let mut a = [0u8; res::LEDGER_RELEASE_ARG_LEN];
    a[..2].copy_from_slice(&res::OWNER_LINE_STORAGE.to_le_bytes());
    a[2..10].copy_from_slice(&bytes.to_le_bytes());
    fs_call(s, -1, res::LEDGER_RELEASE, &mut a, &mut []);
}

/// The size of the file at `path`: `Ok(None)` when nothing is there, `Err`
/// for `EAGAIN` (ask again; nothing was done) or a name that is not a file.
fn probe_size(s: &State, path: &Path) -> Result<Option<u64>, i32> {
    let mut p = *path;
    let rc = fs_call(s, -1, op::OPEN, p.arg(), &mut []);
    if rc == errno::ENOENT {
        return Ok(None);
    }
    if rc < 0 {
        return Err(rc);
    }
    let size = handle_size(s, rc);
    fs_close(s, rc);
    size.map(Some)
}

/// The size of the file `handle` names.
fn handle_size(s: &State, handle: i32) -> Result<u64, i32> {
    let mut st = [0u8; op::stat::LEN];
    let rc = fs_call(s, handle, op::STAT, &mut st, &mut []);
    if rc < 0 {
        return Err(rc);
    }
    op::Stat::decode(&st).map(|st| st.size).ok_or(errno::EINVAL)
}

/// Whether a directory is at `path`.
fn probe_dir(s: &State, path: &Path) -> Result<bool, i32> {
    let mut p = *path;
    let rc = fs_call(s, -1, op::OPENDIR, p.arg(), &mut []);
    if no_dir(rc) {
        return Ok(false);
    }
    if rc < 0 {
        return Err(rc);
    }
    fs_close(s, rc);
    Ok(true)
}

/// Ask a job's request (again). `None` while the answer is "ask again".
fn ask(s: &State, r: &mut Req) -> Option<i32> {
    let n = r.len;
    let rc = if r.data {
        fs_call(s, r.handle, r.opcode, &mut [], &mut r.arg[..n])
    } else {
        fs_call(s, r.handle, r.opcode, &mut r.arg[..n], &mut [])
    };
    if retry(rc) || rc == errno::EBUSY {
        return None;
    }
    r.live = false;
    Some(rc)
}

// ── Roots ──────────────────────────────────────────────────────────────────

/// The owner's root, ready to serve, or why not: `EAGAIN` while it is made,
/// measured, or waits for an old root under its identity to go; `EACCES` for
/// an owner the kernel will not charge.
fn ready_root(s: &mut State, owner: Owner) -> Result<usize, i32> {
    for attempt in 0..2 {
        let rs = roots(s);
        if let Some(i) = rs
            .iter()
            .position(|r| r.phase != Phase::Free && r.owner == owner)
        {
            return match rs[i].phase {
                Phase::Ready => {
                    // What the walk found is the owner's, past its cap if
                    // need be; charged here, in its own call.
                    if rs[i].owed > 0 {
                        let rc = charge(s, rs[i].owed, res::LEDGER_HELD);
                        if rc < 0 {
                            return Err(rc);
                        }
                        rs[i].owed = 0;
                    }
                    Ok(i)
                }
                Phase::Failed => Err(rs[i].failed),
                _ if attempt == 0 => {
                    pump(s);
                    continue;
                }
                _ => Err(errno::EAGAIN),
            };
        }
        // An owner the kernel will not charge makes no root.
        let rc = charge(s, 0, ROOT_ADMIT_FLAGS);
        if rc < 0 {
            return Err(rc);
        }
        let Some(uid) = caller_uid(s) else {
            return Err(errno::EACCES);
        };
        let name = Name::hex(&uid);
        // An old root under this identity still going: wait for it.
        let old = rs
            .iter()
            .find(|r| r.phase != Phase::Free && r.hexed && r.name == name)
            .map(|r| (r.phase, r.failed));
        match old {
            Some((Phase::Failed, failed)) => return Err(failed),
            Some(_) => {
                pump(s);
                return Err(errno::EAGAIN);
            }
            None => {}
        }
        // A node with no file system has nothing to root a workload in: say
        // so, rather than "not yet" for ever.
        let mut caps = [0u8; abi::kernel_abi::caps_word::LEN];
        let rc = fs_call(s, -1, op::CAPS, &mut caps, &mut []);
        if rc == errno::ENOSYS || rc == errno::ENODEV {
            return Err(rc);
        }
        let Some(i) = rs.iter().position(|r| r.phase == Phase::Free) else {
            return Err(errno::ENOMEM);
        };
        rs[i] = Root {
            phase: Phase::Setup,
            owner,
            name,
            hexed: true,
            ..ROOT_EMPTY
        };
        pump(s);
    }
    Err(errno::EAGAIN)
}

/// Advance both jobs by a bounded number of requests.
fn pump(s: &mut State) {
    pump_scan(s);
    pump_remove(s);
}

fn scan_fail(s: &mut State, rc: i32) {
    let rs = roots(s);
    let i = s.scan.root;
    if i < rs.len() {
        log_name(s, 1, b"[owner_fs] root not made:", rs[i].name.bytes(), rc);
        if rc == errno::ENOSYS || rc == errno::ENODEV {
            // The file system beneath went away: nothing is wrong with the
            // root, and the next call asks again.
            rs[i] = ROOT_EMPTY;
        } else {
            rs[i].phase = Phase::Failed;
            rs[i].failed = if rc < 0 { rc } else { errno::EINVAL };
        }
    }
    scan_reset(s);
}

fn scan_reset(s: &mut State) {
    while s.scan.depth > 0 {
        s.scan.depth -= 1;
        fs_close(s, s.scan.dirs[s.scan.depth]);
    }
    fs_close(s, s.scan.held);
    s.scan.held = -1;
    s.scan.root = usize::MAX;
    s.scan.stage = ScanStage::Idle;
    s.scan.req = Req::IDLE;
    s.scan.total = 0;
}

fn pump_scan(s: &mut State) {
    let rs = roots(s);
    let base = s.base;
    for _ in 0..ASKS_PER_PUMP {
        if s.scan.stage == ScanStage::Idle {
            let Some(i) = rs.iter().position(|r| r.phase == Phase::Setup) else {
                return;
            };
            s.scan.root = i;
            s.scan.stage = if rs[i].found_tombstone {
                // Its tombstone was just removed with the rest of it.
                ScanStage::Make(0)
            } else {
                ScanStage::Tombstone
            };
            s.scan.total = 0;
            s.scan.depth = 0;
            s.scan.held = -1;
        }
        let name = rs[s.scan.root].name;
        if !s.scan.req.live {
            let sc = &mut s.scan;
            sc.req = match sc.stage {
                ScanStage::Tombstone => Req::path(op::OPEN, &name.sub(&base, TOMBSTONE)),
                ScanStage::TombstoneClose => Req::on(op::CLOSE, sc.held, 0),
                ScanStage::Make(k) => {
                    let p = match k / 2 {
                        0 => base,
                        1 => name.dir(&base),
                        _ => name.sub(&base, FILES),
                    };
                    Req::path(
                        if k % 2 == 0 {
                            op::MKDIR
                        } else {
                            op::FSYNC_NAME
                        },
                        &p,
                    )
                }
                ScanStage::Walk | ScanStage::OpenSub => Req::path(op::OPENDIR, &sc.path),
                ScanStage::ReadDir => Req::read_dir(sc.dirs[sc.depth - 1]),
                ScanStage::Entry => {
                    let Some((n, is_dir)) = sc.batch[sc.depth - 1].next() else {
                        sc.stage = ScanStage::ReadDir;
                        continue;
                    };
                    if is_dir {
                        sc.total += ENTRY_COST;
                        if sc.depth >= SCAN_DEPTH || !sc.path.push_comp(n.bytes()) {
                            continue;
                        }
                        sc.stage = ScanStage::OpenSub;
                        Req::path(op::OPENDIR, &sc.path)
                    } else {
                        let mut p = sc.path;
                        if !p.push_comp(n.bytes()) {
                            sc.total += ENTRY_COST;
                            continue;
                        }
                        sc.stage = ScanStage::FileOpen;
                        Req::path(op::OPEN, &p)
                    }
                }
                ScanStage::FileStat => Req::on(op::STAT, sc.held, op::stat::LEN),
                ScanStage::FileOpen | ScanStage::Idle => return,
            };
        }
        let mut req = s.scan.req;
        let got = ask(s, &mut req);
        s.scan.req = req;
        let Some(rc) = got else {
            return;
        };
        match s.scan.stage {
            ScanStage::Tombstone => {
                if rc >= 0 {
                    s.scan.held = rc;
                    s.scan.stage = ScanStage::TombstoneClose;
                } else if rc == errno::ENOENT {
                    s.scan.stage = ScanStage::Make(0);
                } else {
                    return scan_fail(s, rc);
                }
            }
            ScanStage::TombstoneClose => {
                // An old root under this identity was being removed: finish
                // that first; the owner gets a fresh root after.
                s.scan.held = -1;
                let r = &mut rs[s.scan.root];
                r.phase = Phase::Removing;
                r.found_tombstone = true;
                r.then_setup = true;
                scan_reset(s);
            }
            ScanStage::Make(k) => {
                if rc < 0 {
                    return scan_fail(s, rc);
                }
                if k < 5 {
                    s.scan.stage = ScanStage::Make(k + 1);
                } else {
                    s.scan.path = name.sub(&base, FILES);
                    s.scan.stage = ScanStage::Walk;
                }
            }
            ScanStage::Walk | ScanStage::OpenSub => {
                if rc >= 0 {
                    s.scan.dirs[s.scan.depth] = rc;
                    s.scan.depth += 1;
                    s.scan.stage = ScanStage::ReadDir;
                } else if s.scan.stage == ScanStage::Walk {
                    return scan_fail(s, rc);
                } else {
                    // A directory that will not open is charged as a name.
                    s.scan.path.pop_comp();
                    s.scan.stage = ScanStage::Entry;
                }
            }
            ScanStage::ReadDir => {
                if rc > 0 {
                    let d = s.scan.depth - 1;
                    let buf = s.scan.req.arg;
                    s.scan.batch[d].load(&buf, rc as usize);
                    s.scan.stage = ScanStage::Entry;
                } else {
                    s.scan.depth -= 1;
                    fs_close(s, s.scan.dirs[s.scan.depth]);
                    if s.scan.depth == 0 {
                        // Walked: the owner owes what its root holds.
                        let r = &mut rs[s.scan.root];
                        r.owed = r.owed.saturating_add(s.scan.total);
                        r.phase = Phase::Ready;
                        scan_reset(s);
                    } else {
                        s.scan.path.pop_comp();
                        s.scan.stage = ScanStage::Entry;
                    }
                }
            }
            ScanStage::FileOpen => {
                if rc >= 0 {
                    s.scan.held = rc;
                    s.scan.stage = ScanStage::FileStat;
                } else {
                    s.scan.total += ENTRY_COST;
                    s.scan.stage = ScanStage::Entry;
                }
            }
            ScanStage::FileStat => {
                let mut size = 0u64;
                if rc == 0 {
                    if let Some(st) = op::Stat::decode(&s.scan.req.arg[..op::stat::LEN]) {
                        size = st.size;
                    }
                }
                s.scan.total += file_cost(size);
                fs_close(s, s.scan.held);
                s.scan.held = -1;
                s.scan.stage = ScanStage::Entry;
            }
            ScanStage::Entry | ScanStage::Idle => {}
        }
    }
}

fn rm_done(s: &mut State, failed: Option<i32>) {
    let rs = roots(s);
    fs_close(s, s.remove.held);
    s.remove.held = -1;
    let i = s.remove.root;
    if i < rs.len() {
        let r = &mut rs[i];
        match failed {
            Some(rc) => {
                log_name(
                    s,
                    1,
                    b"[owner_fs] root not removed, its tombstone stays:",
                    r.name.bytes(),
                    rc,
                );
                r.phase = Phase::Failed;
                r.failed = if rc < 0 { rc } else { EIO };
            }
            None if r.then_setup && r.owner != NOBODY => {
                r.phase = Phase::Setup;
                r.then_setup = false;
            }
            None => *r = ROOT_EMPTY,
        }
    }
    s.remove.root = usize::MAX;
    s.remove.stage = RmStage::Idle;
    s.remove.req = Req::IDLE;
}

fn pump_remove(s: &mut State) {
    let rs = roots(s);
    let base = s.base;
    for _ in 0..ASKS_PER_PUMP {
        if s.remove.stage == RmStage::Idle {
            let Some(i) = rs.iter().position(|r| r.phase == Phase::Removing) else {
                return;
            };
            s.remove.root = i;
            s.remove.stage = RmStage::Mark;
            s.remove.held = -1;
        }
        let name = if s.remove.root < rs.len() {
            rs[s.remove.root].name
        } else {
            Name::EMPTY
        };
        if !s.remove.req.live {
            let m = &mut s.remove;
            m.req = match m.stage {
                RmStage::SweepOpen => Req::path(op::OPENDIR, &base),
                RmStage::SweepRead => Req::read_dir(m.held),
                RmStage::SweepEntry => {
                    let Some((n, is_dir)) = m.batch.next() else {
                        m.stage = RmStage::SweepRead;
                        continue;
                    };
                    if !is_dir {
                        continue;
                    }
                    m.candidate = n;
                    m.stage = RmStage::SweepCheck;
                    Req::path(op::OPEN, &n.sub(&base, TOMBSTONE))
                }
                RmStage::Mark => {
                    if rs[m.root].found_tombstone {
                        // Found, not made: removal goes ahead only while it
                        // is still there, so a root made since under the same
                        // directory name is never touched.
                        Req::path(op::OPEN, &name.sub(&base, TOMBSTONE))
                    } else {
                        Req::path(op::OPEN_CREATE, &name.sub(&base, TOMBSTONE))
                    }
                }
                RmStage::MarkClose => Req::on(op::CLOSE, m.held, 0),
                RmStage::MarkFence | RmStage::Fence => {
                    Req::path(op::FSYNC_NAME, &name.sub(&base, TOMBSTONE))
                }
                RmStage::WalkOpen => Req::path(op::OPENDIR, &m.path),
                RmStage::WalkRead => Req::read_dir(m.held),
                RmStage::Unmark => Req::path(op::UNLINK, &name.sub(&base, TOMBSTONE)),
                RmStage::RmRoot => Req::path(op::RMDIR, &name.dir(&base)),
                RmStage::Unlink | RmStage::Rmdir | RmStage::SweepCheck | RmStage::Idle => return,
            };
        }
        let mut req = s.remove.req;
        let got = ask(s, &mut req);
        s.remove.req = req;
        let Some(rc) = got else {
            return;
        };
        match s.remove.stage {
            RmStage::SweepOpen => {
                if rc >= 0 {
                    s.remove.held = rc;
                    s.remove.stage = RmStage::SweepRead;
                } else {
                    if rc != errno::ENOENT {
                        log_name(s, 2, b"[owner_fs] start sweep:", base.bytes(), rc);
                    }
                    s.remove.stage = RmStage::Idle;
                }
            }
            RmStage::SweepRead => {
                if rc > 0 {
                    let buf = s.remove.req.arg;
                    s.remove.batch.load(&buf, rc as usize);
                    s.remove.stage = RmStage::SweepEntry;
                } else {
                    fs_close(s, s.remove.held);
                    s.remove.held = -1;
                    s.remove.stage = RmStage::Idle;
                }
            }
            RmStage::SweepCheck => {
                if rc >= 0 {
                    fs_close(s, rc);
                    let n = s.remove.candidate;
                    let known = rs.iter().any(|r| r.phase != Phase::Free && r.name == n);
                    if !known {
                        if let Some(i) = rs.iter().position(|r| r.phase == Phase::Free) {
                            log_name(
                                s,
                                3,
                                b"[owner_fs] tombstoned root queued for removal:",
                                n.bytes(),
                                0,
                            );
                            rs[i] = Root {
                                phase: Phase::Removing,
                                name: n,
                                found_tombstone: true,
                                ..ROOT_EMPTY
                            };
                        }
                    }
                }
                s.remove.stage = RmStage::SweepEntry;
            }
            RmStage::Mark => {
                if rc >= 0 {
                    s.remove.held = rc;
                    s.remove.stage = RmStage::MarkClose;
                } else if rc == errno::ENOENT {
                    // No root there (or no tombstone on a found one): nothing
                    // to remove.
                    return rm_done(s, None);
                } else {
                    return rm_done(s, Some(rc));
                }
            }
            RmStage::MarkClose => {
                s.remove.held = -1;
                s.remove.stage = if rs[s.remove.root].found_tombstone {
                    s.remove.path = name.dir(&base);
                    RmStage::WalkOpen
                } else {
                    RmStage::MarkFence
                };
            }
            RmStage::MarkFence => {
                if rc < 0 {
                    return rm_done(s, Some(rc));
                }
                s.remove.path = name.dir(&base);
                s.remove.stage = RmStage::WalkOpen;
            }
            RmStage::WalkOpen => {
                let top = name.dir(&base).n;
                if rc >= 0 {
                    s.remove.held = rc;
                    s.remove.stage = RmStage::WalkRead;
                } else if no_dir(rc) && s.remove.path.n > top {
                    s.remove.path.pop_comp();
                } else if no_dir(rc) {
                    return rm_done(s, None);
                } else {
                    return rm_done(s, Some(rc));
                }
            }
            RmStage::WalkRead => {
                let at_top = s.remove.path.n == name.dir(&base).n;
                if rc > 0 {
                    let buf = s.remove.req.arg;
                    s.remove.batch.load(&buf, rc as usize);
                    let mut pick = None;
                    while let Some((n, is_dir)) = s.remove.batch.next() {
                        if at_top && n.bytes().eq_ignore_ascii_case(TOMBSTONE) {
                            continue;
                        }
                        pick = Some((n, is_dir));
                        break;
                    }
                    let Some((n, is_dir)) = pick else {
                        continue; // only the tombstone here: read on
                    };
                    fs_close(s, s.remove.held);
                    s.remove.held = -1;
                    if !s.remove.path.push_comp(n.bytes()) {
                        return rm_done(s, Some(errno::E2BIG));
                    }
                    if is_dir {
                        s.remove.stage = RmStage::WalkOpen;
                    } else {
                        s.remove.req = Req::path(op::UNLINK, &s.remove.path);
                        s.remove.path.pop_comp();
                        s.remove.stage = RmStage::Unlink;
                    }
                } else {
                    fs_close(s, s.remove.held);
                    s.remove.held = -1;
                    if at_top {
                        s.remove.stage = RmStage::Fence;
                    } else {
                        s.remove.req = Req::path(op::RMDIR, &s.remove.path);
                        s.remove.path.pop_comp();
                        s.remove.stage = RmStage::Rmdir;
                    }
                }
            }
            RmStage::Unlink | RmStage::Rmdir => {
                // `ENOTEMPTY` here is an entry the walk cannot see: fail
                // rather than walk for ever.
                if rc < 0 && rc != errno::ENOENT {
                    return rm_done(s, Some(rc));
                }
                s.remove.stage = RmStage::WalkOpen;
            }
            RmStage::Fence => {
                if rc < 0 {
                    return rm_done(s, Some(rc));
                }
                s.remove.stage = RmStage::Unmark;
            }
            RmStage::Unmark => {
                if rc < 0 && rc != errno::ENOENT {
                    return rm_done(s, Some(rc));
                }
                s.remove.stage = RmStage::RmRoot;
            }
            RmStage::RmRoot => {
                if rc < 0 && rc != errno::ENOENT {
                    return rm_done(s, Some(rc));
                }
                return rm_done(s, None);
            }
            RmStage::SweepEntry | RmStage::Idle => {}
        }
    }
}

// ── Release ────────────────────────────────────────────────────────────────

/// `OWNER_RELEASED`: close every handle the owner holds, forget what it had
/// undecided, and queue its root for removal — a root it never touched this
/// run included, found by the uid the record names. A record with no uid
/// (an owner that acted with the node's authority, which no workload layer
/// served) queues nothing.
fn owner_released(s: &mut State, rec: &[u8]) {
    let Some(head) = rec.get(..8) else { return };
    let mut owner = NOBODY;
    owner.copy_from_slice(head);
    if owner == NOBODY {
        return;
    }
    for sl in slots(s)
        .iter_mut()
        .filter(|sl| sl.in_use && sl.owner == owner)
    {
        fs_close(s, sl.inner);
        *sl = SLOT_EMPTY;
    }
    let rs = roots(s);
    match rs
        .iter()
        .position(|r| r.phase != Phase::Free && r.owner == owner)
    {
        Some(i) => {
            if s.scan.root == i {
                scan_reset(s);
            }
            let r = &mut rs[i];
            r.owner = NOBODY;
            r.pend = [PENDING_EMPTY; MAX_PENDING];
            r.then_setup = false;
            r.owed = 0;
            match r.phase {
                Phase::Removing => {}
                // A failed removal keeps its tombstone; a later start
                // finishes it.
                Phase::Failed if r.found_tombstone => *r = ROOT_EMPTY,
                _ => {
                    r.phase = Phase::Removing;
                    r.found_tombstone = false;
                }
            }
        }
        None => {
            let Some(u) = rec.get(8..24) else { return };
            let mut uid = [0u8; 16];
            uid.copy_from_slice(u);
            if uid == [0u8; 16] {
                return;
            }
            let name = Name::hex(&uid);
            if rs
                .iter()
                .any(|r| r.phase == Phase::Removing && r.name == name)
            {
                return;
            }
            if let Some(i) = rs.iter().position(|r| r.phase == Phase::Free) {
                rs[i] = Root {
                    phase: Phase::Removing,
                    name,
                    hexed: true,
                    ..ROOT_EMPTY
                };
            }
        }
    }
}

// ── Volumes ────────────────────────────────────────────────────────────────

/// Apply one `ctl` record.
fn apply_ctl(s: &mut State, m: &[u8]) {
    let (Some(&cmd), Some(u)) = (m.first(), m.get(1..17)) else {
        return;
    };
    let mut uid = [0u8; 16];
    uid.copy_from_slice(u);
    let Some(&dl) = m.get(17) else { return };
    let dl = usize::from(dl);
    let Some(dst) = m.get(18..18 + dl) else {
        return;
    };
    if dl > DST_MAX || !matches!(each_comp(dst, |_| true), Ok(n) if n >= 1) {
        return;
    }
    let vs = vols(s);
    let at = vs
        .iter()
        .position(|v| v.in_use && v.uid == uid && &v.dst[..usize::from(v.dl)] == dst);
    if cmd == CTL_REMOVE {
        if let Some(i) = at {
            revoke_volume(s, i);
            fs_close(s, vs[i].bound);
            vs[i] = VOLUME_EMPTY;
        }
        return;
    }
    if cmd != CTL_ADD {
        return;
    }
    let mut at_v = 18 + dl;
    let Some(&vl) = m.get(at_v) else { return };
    let vl = usize::from(vl);
    let Some(vol) = m.get(at_v + 1..at_v + 1 + vl) else {
        return;
    };
    at_v += 1 + vl;
    let Some(pl) = m.get(at_v..at_v + 2) else {
        return;
    };
    let pl = usize::from(u16::from_le_bytes([pl[0], pl[1]]));
    let Some(path) = m.get(at_v + 2..at_v + 2 + pl) else {
        return;
    };
    let Some(&ro) = m.get(at_v + 2 + pl) else {
        return;
    };
    if vol.is_empty() || vl > VOL_MAX || pl > VPATH_MAX {
        return;
    }
    let mut v = VOLUME_EMPTY;
    v.in_use = true;
    v.ro = ro != 0;
    v.uid = uid;
    v.dst[..dl].copy_from_slice(dst);
    v.dl = dl as u8;
    v.vol[..vl].copy_from_slice(vol);
    v.vl = vl as u8;
    v.path[..pl].copy_from_slice(path);
    v.pl = pl as u8;
    // Idempotent per (uid, dst): the same record twice is one volume, and a
    // changed one replaces it.
    let i = match at {
        Some(i) => {
            let old = vs[i];
            if old.vol[..usize::from(old.vl)] == *vol && old.path[..usize::from(old.pl)] == *path {
                v.bound = old.bound;
            } else {
                revoke_volume(s, i);
                fs_close(s, old.bound);
            }
            i
        }
        None => match vs.iter().position(|v| !v.in_use) {
            Some(i) => i,
            None => {
                log(
                    s,
                    1,
                    b"[owner_fs] volume record dropped: the volume table is full",
                );
                return;
            }
        },
    };
    vs[i] = v;
}

/// Close every handle opened on volume `i`: a workload's next op on one is
/// `EBADF`.
fn revoke_volume(s: &State, i: usize) {
    for sl in slots(s).iter_mut() {
        if sl.in_use && sl.lent && usize::from(sl.vol) == i {
            fs_close(s, sl.inner);
            *sl = SLOT_EMPTY;
        }
    }
}

/// Drain the `ctl` port, one record at a time: a read is a byte stream
/// across the ring's records, so each is read at the length `RECORD_LEN`
/// gives for the head. The ring holds every record whole, and a read of
/// that length takes it whole. A record longer than any `ctl` record is
/// dropped.
fn service_ctl(s: &mut State) {
    if s.ctl < 0 {
        return;
    }
    let mut buf = [0u8; CTL_MAX];
    for _ in 0..usize::from(s.n_vols).max(1) {
        // SAFETY: the kernel's table; `s.ctl` is this module's input.
        let rl = unsafe { dev_channel_record_len(s.sys(), s.ctl) };
        if rl <= 0 {
            break;
        }
        let rl = rl as usize;
        if rl > CTL_MAX {
            // SAFETY: as above.
            unsafe { (s.sys().channel_discard)(s.ctl, rl) };
            log(
                s,
                1,
                b"[owner_fs] ctl record dropped: longer than any ctl record",
            );
            continue;
        }
        // SAFETY: `buf` is this frame's own and holds `rl` bytes.
        let n = unsafe { (s.sys().channel_read)(s.ctl, buf.as_mut_ptr(), rl) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if n < rl {
            // SAFETY: as above.
            unsafe { (s.sys().channel_discard)(s.ctl, rl - n) };
            log(s, 1, b"[owner_fs] ctl record dropped: read short");
            continue;
        }
        apply_ctl(s, &buf[..n]);
    }
}

/// Where a path the owner names lies.
enum Where {
    /// In its root, as this path beneath the node's file system.
    Root(Path),
    /// On lent volume `i`, as this path through its bound handle; `true`
    /// when the path names the volume itself.
    Lent(usize, Path, bool),
}

/// Whether the checked components of `path` begin with those of `dst`, and
/// how many `dst` has.
fn under(dst: &[u8], path: &[u8]) -> Option<usize> {
    let mut d = dst
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".");
    let mut p = path
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".");
    let mut k = 0usize;
    loop {
        match (d.next(), p.next()) {
            (None, _) => return Some(k),
            (Some(a), Some(b)) if a == b => k += 1,
            _ => return None,
        }
    }
}

/// Resolve `path` for the owner with identity `uid` (when it has volumes):
/// at or under a volume's `dst` (the deepest that matches) on that volume,
/// else beneath its root `name`.
fn resolve(
    s: &State,
    uid: Option<&[u8; 16]>,
    name: Option<&Name>,
    path: &[u8],
    allow_root: bool,
) -> Result<Where, i32> {
    // Every path is checked whole first: nothing climbs, on a volume or not.
    let total = each_comp(path, |_| true)?;
    if let Some(uid) = uid {
        let best = vols(s)
            .iter()
            .enumerate()
            .filter(|(_, v)| v.in_use && v.uid == *uid)
            .filter_map(|(i, v)| under(&v.dst[..usize::from(v.dl)], path).map(|k| (i, k)))
            .max_by_key(|&(_, k)| k);
        if let Some((i, k)) = best {
            let v = &vols(s)[i];
            let mut out = Path::of(&v.path[..usize::from(v.pl)]);
            if out.n == 0 {
                out.push(b"/");
            }
            let mut skip = k;
            each_comp(path, |c| {
                if skip > 0 {
                    skip -= 1;
                    return true;
                }
                out.push_comp(c)
            })?;
            return Ok(Where::Lent(i, out, total == k));
        }
    }
    let Some(name) = name else {
        return Err(errno::EAGAIN);
    };
    rooted_under(name.sub(&s.base, FILES), path, allow_root).map(Where::Root)
}

/// The handle bound to volume `i`, binding it on first use.
fn volume_handle(s: &State, i: usize) -> Result<i32, i32> {
    let v = &mut vols(s)[i];
    if v.bound < 0 {
        // SAFETY: the kernel's table.
        let h =
            unsafe { dev_bind_name(s.sys(), abi::registry::fs::ID, &v.vol[..usize::from(v.vl)]) };
        if h < 0 {
            return Err(h);
        }
        v.bound = h;
    }
    Ok(v.bound)
}

// ── The owner's calls ──────────────────────────────────────────────────────

fn dispatch(s: &mut State, handle: i32, opcode: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    service_ctl(s);
    let Some(owner) = caller(s) else {
        return errno::EACCES;
    };
    if opcode == op::CAPS {
        let rc = fs_call(s, -1, op::CAPS, arg, &mut []);
        if rc != 0 {
            return rc;
        }
        // No second name for a file: a hard link would be charged once and
        // could be given back twice, and a link could lead out of the root.
        return match abi::kernel_abi::caps_word::parse(arg) {
            Some(c) => {
                abi::kernel_abi::caps_word::answer(arg, c & !(op::caps::LINK | op::caps::SYMLINK))
            }
            None => errno::EINVAL,
        };
    }
    // No second name for a file, and no link that could lead out of a root
    // or a volume: refused before any root or volume is consulted.
    if opcode == op::LINK || opcode == op::READLINK {
        return errno::ENOSYS;
    }
    if handle >= 0 {
        return handle_op(s, owner, handle, opcode, arg, data);
    }
    path_entry(s, owner, opcode, arg)
}

/// A path op: on a lent volume, or in the owner's root.
fn path_entry(s: &mut State, owner: Owner, opcode: u32, arg: &mut [u8]) -> i32 {
    let has_vols = vols(s).iter().any(|v| v.in_use);
    let uid = if has_vols { caller_uid(s) } else { None };
    if let Some(uid) = uid.as_ref() {
        if let Some(rc) = lent_op(s, owner, uid, opcode, arg) {
            return rc;
        }
    }
    let ri = match ready_root(s, owner) {
        Ok(i) => i,
        Err(e) => return e,
    };
    path_op(s, owner, ri, uid.as_ref(), opcode, arg)
}

/// A free slot `owner` may take, or `ENOMEM` when the table, or the owner's
/// share of it, is full — asked before anything is opened.
fn free_slot(s: &State, owner: Owner) -> Result<usize, i32> {
    let ss = slots(s);
    if ss.iter().filter(|x| x.in_use && x.owner == owner).count() >= usize::from(s.max_open) {
        return Err(errno::ENOMEM);
    }
    ss.iter().position(|x| !x.in_use).ok_or(errno::ENOMEM)
}

fn claim(s: &State, i: usize, owner: Owner, inner: i32, created: bool) -> i32 {
    slots(s)[i] = Slot {
        in_use: true,
        owner,
        inner,
        size_known: created,
        ..SLOT_EMPTY
    };
    i as i32
}

fn handle_op(
    s: &mut State,
    owner: Owner,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: &mut [u8],
) -> i32 {
    let i = handle as usize;
    let ss = slots(s);
    let Some(sl) = ss.get_mut(i).filter(|x| x.in_use && x.owner == owner) else {
        return EBADF;
    };
    let inner = sl.inner;
    match opcode {
        op::CLOSE => {
            fs_close(s, inner);
            *sl = SLOT_EMPTY;
            0
        }
        op::READ => {
            let rc = fs_call(s, inner, opcode, arg, data);
            if rc > 0 {
                sl.pos += rc as u64;
            }
            rc
        }
        op::SEEK => {
            let Some(to) = op::seek::parse(arg) else {
                return errno::EINVAL;
            };
            let rc = fs_call(s, inner, opcode, arg, data);
            if rc == 0 {
                sl.pos = to;
            }
            rc
        }
        op::WRITE | op::WRITE_ASYNC if sl.ro => errno::EROFS,
        op::WRITE | op::WRITE_ASYNC if sl.lent => {
            let rc = fs_call(s, inner, opcode, arg, data);
            if rc > 0 {
                sl.pos += rc as u64;
            }
            rc
        }
        op::WRITE | op::WRITE_ASYNC => {
            if let Err(e) = know_size(s, sl) {
                return e;
            }
            let grow = (sl.pos + data.len() as u64).saturating_sub(sl.size);
            let rc = reserve(s, grow);
            if rc < 0 {
                return rc;
            }
            let rc = fs_call(s, inner, opcode, arg, data);
            let mut used = 0;
            if rc > 0 {
                let end = sl.pos + rc as u64;
                if end > sl.size {
                    used = end - sl.size;
                    sl.size = end;
                }
                sl.pos = end;
            }
            give_back(s, grow - used.min(grow));
            rc
        }
        op::PREALLOCATE if sl.ro => errno::EROFS,
        op::PREALLOCATE if sl.lent => fs_call(s, inner, opcode, arg, data),
        op::PREALLOCATE => {
            let Some(b) = arg.get(..4) else {
                return errno::EINVAL;
            };
            let cap = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let reserved = match sl.prealloc {
                Some((c, r)) if c == cap => r,
                _ => {
                    // A different request in place of an undecided one: what
                    // that one reserved stays charged (it still completes).
                    if sl.prealloc.take().is_some() {
                        sl.size_known = false;
                    }
                    if let Err(e) = know_size(s, sl) {
                        return e;
                    }
                    let grow = u64::from(cap).saturating_sub(sl.size);
                    let rc = reserve(s, grow);
                    if rc < 0 {
                        return rc;
                    }
                    grow
                }
            };
            let rc = fs_call(s, inner, opcode, arg, data);
            if rc == errno::EINPROGRESS {
                sl.prealloc = Some((cap, reserved));
                return rc;
            }
            sl.prealloc = None;
            if rc == 0 {
                sl.size = sl.size.max(u64::from(cap));
                sl.pos = 0;
            } else {
                give_back(s, reserved);
            }
            rc
        }
        op::STAT | op::FSYNC | op::FSYNC_SUBMIT | op::FSYNC_POLL | op::READDIR => {
            fs_call(s, inner, opcode, arg, data)
        }
        _ if opcode == abi::fence::QUERY_OP => fs_call(s, inner, opcode, arg, data),
        _ => errno::ENOSYS,
    }
}

/// Learn a handle's size from beneath, once.
fn know_size(s: &State, sl: &mut Slot) -> Result<(), i32> {
    if sl.size_known {
        return Ok(());
    }
    sl.size = handle_size(s, sl.inner)?;
    sl.size_known = true;
    Ok(())
}

/// The path, or the error, of a single-path request.
fn path_arg(arg: &[u8]) -> Result<&[u8], i32> {
    if arg.is_empty() {
        return Err(errno::EINVAL);
    }
    if arg.len() > PATH_MAX {
        return Err(errno::E2BIG);
    }
    Ok(arg)
}

/// The `RENAME` / `LINK` two-path argument.
fn two_paths(a: &[u8]) -> Option<(&[u8], &[u8])> {
    if a.len() < 4 {
        return None;
    }
    let sl = usize::from(u16::from_le_bytes([a[0], a[1]]));
    let src = a.get(2..2 + sl)?;
    let rest = a.get(2 + sl..)?;
    if rest.len() < 2 {
        return None;
    }
    let dl = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
    let dst = rest.get(2..2 + dl)?;
    Some((src, dst))
}

/// `[len u16][a][len u16][b]`.
fn two_path_req(a: &Path, b: &Path) -> Result<Path, i32> {
    let mut req = Path::EMPTY;
    let ok = req.push(&(a.n as u16).to_le_bytes())
        && req.push(a.bytes())
        && req.push(&(b.n as u16).to_le_bytes())
        && req.push(b.bytes());
    if ok {
        Ok(req)
    } else {
        Err(errno::E2BIG)
    }
}

/// A path op on a volume lent to the owner, uncharged; `None` when the path
/// is in its root. A rename between a volume and anything else is `EXDEV`.
fn lent_op(
    s: &mut State,
    owner: Owner,
    uid: &[u8; 16],
    opcode: u32,
    arg: &mut [u8],
) -> Option<i32> {
    let changes = matches!(
        opcode,
        op::OPEN_CREATE | op::UNLINK | op::MKDIR | op::RMDIR | op::TRUNCATE | op::RENAME
    );
    let (vi, mut req) = match opcode {
        op::OPEN
        | op::OPENDIR
        | op::OPEN_CREATE
        | op::UNLINK
        | op::RMDIR
        | op::MKDIR
        | op::FSYNC_NAME => {
            let p = match path_arg(arg) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            match resolve(s, Some(uid), None, p, false) {
                // The volume itself is the node's lending, not the owner's
                // entry to remove.
                Ok(Where::Lent(_, _, true)) if matches!(opcode, op::UNLINK | op::RMDIR) => {
                    return Some(errno::EBUSY)
                }
                Ok(Where::Lent(i, p, _)) => (i, p),
                Ok(Where::Root(_)) | Err(errno::EAGAIN) => return None,
                Err(e) => return Some(e),
            }
        }
        op::TRUNCATE => {
            if arg.len() < 9 {
                return Some(errno::EINVAL);
            }
            match resolve(s, Some(uid), None, &arg[8..], false) {
                Ok(Where::Lent(i, p, _)) => {
                    let mut req = Path::of(&arg[..8]);
                    if !req.push(p.bytes()) {
                        return Some(errno::E2BIG);
                    }
                    (i, req)
                }
                Ok(Where::Root(_)) | Err(errno::EAGAIN) => return None,
                Err(e) => return Some(e),
            }
        }
        op::RENAME => {
            let Some((src, dst)) = two_paths(arg) else {
                return Some(errno::EINVAL);
            };
            let a = resolve(s, Some(uid), None, src, false);
            let b = resolve(s, Some(uid), None, dst, false);
            match (a, b) {
                (Ok(Where::Lent(_, _, true)), _) | (_, Ok(Where::Lent(_, _, true))) => {
                    return Some(errno::EBUSY)
                }
                (Ok(Where::Lent(i, a, _)), Ok(Where::Lent(j, b, _))) if i == j => {
                    match two_path_req(&a, &b) {
                        Ok(r) => (i, r),
                        Err(e) => return Some(e),
                    }
                }
                (Ok(Where::Lent(..)), _) | (_, Ok(Where::Lent(..))) => return Some(errno::EXDEV),
                _ => return None,
            }
        }
        _ => return None,
    };
    if changes && vols(s)[vi].ro {
        return Some(errno::EROFS);
    }
    let bound = match volume_handle(s, vi) {
        Ok(h) => h,
        Err(e) => return Some(e),
    };
    if matches!(opcode, op::OPEN | op::OPENDIR | op::OPEN_CREATE) {
        let i = match free_slot(s, owner) {
            Ok(i) => i,
            Err(e) => return Some(e),
        };
        let rc = fs_call(s, bound, opcode, req.arg(), &mut []);
        if rc < 0 {
            return Some(rc);
        }
        let h = claim(s, i, owner, rc, false);
        let sl = &mut slots(s)[i];
        sl.lent = true;
        sl.ro = vols(s)[vi].ro;
        sl.vol = vi as u16;
        return Some(h);
    }
    Some(fs_call(s, bound, opcode, req.arg(), &mut []))
}

fn find_pending(s: &State, ri: usize, opcode: u32, hash: u64, len: usize) -> Option<usize> {
    roots(s)[ri]
        .pend
        .iter()
        .position(|p| p.live && p.opcode == opcode && p.hash == hash && p.len == len)
}

/// Settle the ledger on a path operation's answer. `EAGAIN` consumed
/// nothing: what was reserved goes back. `EINPROGRESS` is kept with what it
/// reserved and would give back, for the ask that decides it.
fn settle(
    s: &State,
    ri: usize,
    key: (u32, u64, usize),
    rc: i32,
    reserved: u64,
    refund: u64,
) -> i32 {
    if rc == errno::EINPROGRESS {
        let pend = &mut roots(s)[ri].pend;
        // Full: the oldest stays charged and is no longer tracked, which is
        // in the owner's disfavour only.
        let k = pend.iter().position(|p| !p.live).unwrap_or(0);
        pend[k] = Pending {
            live: true,
            opcode: key.0,
            hash: key.1,
            len: key.2,
            reserved,
            refund,
        };
        return rc;
    }
    if rc == errno::EAGAIN || rc < 0 {
        give_back(s, reserved);
    } else {
        give_back(s, refund);
    }
    rc
}

/// Re-ask an undecided path operation, settling it once decided.
fn reask(s: &State, ri: usize, pi: usize, req: &mut Path) -> i32 {
    let p = roots(s)[ri].pend[pi];
    let rc = fs_call(s, -1, p.opcode, req.arg(), &mut []);
    if retry(rc) {
        return rc;
    }
    roots(s)[ri].pend[pi] = PENDING_EMPTY;
    if rc < 0 {
        give_back(s, p.reserved);
    } else {
        give_back(s, p.refund);
    }
    rc
}

/// The path beneath the owner's root: `Err` for a path the owner may not
/// name, `Err(EXDEV)` for one on a lent volume (only a rename gets here
/// with one, the other end in the root).
fn in_root(
    s: &State,
    uid: Option<&[u8; 16]>,
    name: &Name,
    p: &[u8],
    allow_root: bool,
) -> Result<Path, i32> {
    match resolve(s, uid, Some(name), p, allow_root)? {
        Where::Root(p) => Ok(p),
        Where::Lent(..) => Err(errno::EXDEV),
    }
}

fn path_op(
    s: &mut State,
    owner: Owner,
    ri: usize,
    uid: Option<&[u8; 16]>,
    opcode: u32,
    arg: &[u8],
) -> i32 {
    let name = roots(s)[ri].name;
    match opcode {
        op::OPEN | op::OPENDIR => {
            let mut p = match path_arg(arg).and_then(|p| in_root(s, uid, &name, p, true)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let i = match free_slot(s, owner) {
                Ok(i) => i,
                Err(e) => return e,
            };
            let rc = fs_call(s, -1, opcode, p.arg(), &mut []);
            if rc < 0 {
                return rc;
            }
            claim(s, i, owner, rc, false)
        }
        op::OPEN_CREATE => {
            let mut p = match path_arg(arg).and_then(|p| in_root(s, uid, &name, p, false)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let i = match free_slot(s, owner) {
                Ok(i) => i,
                Err(e) => return e,
            };
            let key = (opcode, fnv64(&[p.bytes()]), p.n);
            let (rc, before) = if let Some(pi) = find_pending(s, ri, key.0, key.1, key.2) {
                (reask(s, ri, pi, &mut p), None)
            } else {
                // A new name is charged before it exists; an existing file
                // keeps what it is charged until the create says what it
                // holds now.
                let (reserved, before) = match probe_size(s, &p) {
                    Ok(Some(size)) => (0, Some(size)),
                    Ok(None) => (ENTRY_COST, None),
                    Err(errno::EAGAIN) => return errno::EAGAIN,
                    Err(_) => (0, None),
                };
                let rc = reserve(s, reserved);
                if rc < 0 {
                    return rc;
                }
                let rc = fs_call(s, -1, opcode, p.arg(), &mut []);
                (settle(s, ri, key, rc, reserved, 0), before)
            };
            if rc < 0 {
                return rc;
            }
            // A file system that truncates on create holds fewer bytes now:
            // what it cut goes back. One that keeps them keeps the charge.
            let size = handle_size(s, rc).ok();
            if let (Some(before), Some(now)) = (before, size) {
                give_back(s, before.saturating_sub(now));
            }
            let h = claim(s, i, owner, rc, size.is_some());
            if let Some(now) = size {
                slots(s)[i].size = now;
            }
            h
        }
        op::UNLINK | op::RMDIR | op::MKDIR | op::FSYNC_NAME => {
            let mut p = match path_arg(arg).and_then(|p| in_root(s, uid, &name, p, false)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let key = (opcode, fnv64(&[p.bytes()]), p.n);
            if let Some(pi) = find_pending(s, ri, key.0, key.1, key.2) {
                return reask(s, ri, pi, &mut p);
            }
            let (reserved, refund) = match opcode {
                op::UNLINK => match probe_size(s, &p) {
                    Ok(Some(size)) => (0, file_cost(size)),
                    Ok(None) => (0, 0),
                    Err(errno::EAGAIN) => return errno::EAGAIN,
                    Err(_) => (0, 0),
                },
                op::RMDIR => (0, ENTRY_COST),
                op::MKDIR => match probe_dir(s, &p) {
                    Ok(true) => (0, 0),
                    Ok(false) => (ENTRY_COST, 0),
                    Err(e) => return e,
                },
                _ => (0, 0),
            };
            let rc = reserve(s, reserved);
            if rc < 0 {
                return rc;
            }
            let rc = fs_call(s, -1, opcode, p.arg(), &mut []);
            settle(s, ri, key, rc, reserved, refund)
        }
        op::TRUNCATE => {
            if arg.len() < 9 {
                return errno::EINVAL;
            }
            let mut lb = [0u8; 8];
            lb.copy_from_slice(&arg[..8]);
            let len = u64::from_le_bytes(lb);
            let path = match path_arg(&arg[8..]).and_then(|p| in_root(s, uid, &name, p, false)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let mut req = Path::of(&lb);
            if !req.push(path.bytes()) {
                return errno::E2BIG;
            }
            let key = (opcode, fnv64(&[req.bytes()]), req.n);
            if let Some(pi) = find_pending(s, ri, key.0, key.1, key.2) {
                return reask(s, ri, pi, &mut req);
            }
            // Growth is charged before it is asked for, a cut given back.
            let (reserved, refund) = match probe_size(s, &path) {
                Ok(Some(size)) => (len.saturating_sub(size), size.saturating_sub(len)),
                Ok(None) => (0, 0),
                Err(errno::EAGAIN) => return errno::EAGAIN,
                Err(_) => (0, 0),
            };
            let rc = reserve(s, reserved);
            if rc < 0 {
                return rc;
            }
            let rc = fs_call(s, -1, opcode, req.arg(), &mut []);
            settle(s, ri, key, rc, reserved, refund)
        }
        op::RENAME => {
            let Some((src, dst)) = two_paths(arg) else {
                return errno::EINVAL;
            };
            let (a, b) = match (
                in_root(s, uid, &name, src, false),
                in_root(s, uid, &name, dst, false),
            ) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return e,
            };
            let mut req = match two_path_req(&a, &b) {
                Ok(r) => r,
                Err(e) => return e,
            };
            let key = (opcode, fnv64(&[req.bytes()]), req.n);
            if let Some(pi) = find_pending(s, ri, key.0, key.1, key.2) {
                return reask(s, ri, pi, &mut req);
            }
            // The entry the destination named, if any, goes with its charge.
            let refund = if a.bytes().eq_ignore_ascii_case(b.bytes()) {
                0
            } else {
                match probe_size(s, &b) {
                    Ok(Some(size)) => file_cost(size),
                    Ok(None) => 0,
                    Err(errno::EAGAIN) => return errno::EAGAIN,
                    Err(_) => 0,
                }
            };
            let rc = fs_call(s, -1, opcode, req.arg(), &mut []);
            settle(s, ri, key, rc, 0, refund)
        }
        // No second name for a file (one inode charged once, given back
        // twice), and no link that could lead out of the root.
        op::LINK | op::READLINK => errno::ENOSYS,
        _ => errno::ENOSYS,
    }
}

// ── Params ─────────────────────────────────────────────────────────────────

fn p_u16(d: *const u8, len: usize, dflt: u16) -> u16 {
    if d.is_null() || len < 2 {
        return dflt;
    }
    // SAFETY: `d` names `len >= 2` bytes.
    unsafe { u16::from_le_bytes([*d, *d.add(1)]) }
}

mod params_def {
    use super::State;

    fluxor_rt::define_params! {
        State;

        1, root, str, 0, max super::ROOT_MAX
            => |s, d, len| { super::set_root(s, d, len); };

        2, max_roots, u16, 80, range 1..=u16::MAX
            => |s, d, len| { s.n_roots = super::p_u16(d, len, 80); };

        3, max_slots, u16, 128, range 1..=u16::MAX
            => |s, d, len| { s.n_slots = super::p_u16(d, len, 128); };

        4, max_open_per_owner, u16, 32, range 1..=u16::MAX
            => |s, d, len| { s.max_open = super::p_u16(d, len, 32); };

        5, max_volumes, u16, 16
            => |s, d, len| { s.n_vols = super::p_u16(d, len, 16); };
    }
}

/// The `root` param: an absolute path, no trailing `/`.
fn set_root(s: &mut State, d: *const u8, len: usize) {
    if d.is_null() || len == 0 {
        return;
    }
    // SAFETY: `d` names `len` bytes of the params blob.
    let v = unsafe { core::slice::from_raw_parts(d, len) };
    if len > ROOT_MAX || v[0] != b'/' {
        s.root_bad = true;
        return;
    }
    let mut end = v.len();
    while end > 1 && v[end - 1] == b'/' {
        end -= 1;
    }
    s.base = Path::of(&v[..end]);
}

/// One table of `n` entries of `T` from the heap, filled with `empty`.
fn take_table<T: Copy>(s: &State, n: usize, empty: T) -> *mut T {
    let bytes = n.saturating_mul(core::mem::size_of::<T>());
    if bytes == 0 {
        return core::ptr::null_mut();
    }
    let Ok(b) = u32::try_from(bytes) else {
        return core::ptr::null_mut();
    };
    // SAFETY: the kernel's heap allocator, for this instance's heap.
    let p = unsafe { heap_alloc(s.sys(), b) }.cast::<T>();
    if !p.is_null() {
        for i in 0..n {
            // SAFETY: `p` names `n` fresh entries.
            unsafe { p.add(i).write(empty) };
        }
    }
    p
}

// ── Exported PIC module interface ───────────────────────────────────────────

fluxor_rt::module_facts! { state: State, arena: HEAP_BASE }

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() {
        return -2;
    }
    if state.is_null() || state_size < core::mem::size_of::<State>() {
        return -3;
    }
    // SAFETY: the loader's block, sized for `State`; written whole before
    // any field is read.
    let s = unsafe {
        let p = state.cast::<State>();
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        &mut *p
    };
    s.syscalls = syscalls.cast::<SyscallTable>();
    s.ctl = in_chan;
    s.base = Path::of(b"/owners");
    s.scan.root = usize::MAX;
    s.scan.stage = ScanStage::Idle;
    s.scan.held = -1;
    s.scan.dirs = [-1; SCAN_DEPTH];
    s.remove.root = usize::MAX;
    s.remove.stage = RmStage::SweepOpen;
    s.remove.held = -1;
    // SAFETY: the params blob the loader hands, `params_len` bytes.
    unsafe {
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
    }
    if s.root_bad {
        log(
            s,
            1,
            b"[owner_fs] refusing to construct: `root` is not an absolute path of at most 96 bytes",
        );
        return -1;
    }
    if s.n_roots == 0 || s.n_slots == 0 || s.max_open == 0 {
        log(
            s,
            1,
            b"[owner_fs] refusing to construct: max_roots, max_slots and max_open_per_owner must be at least 1",
        );
        return -1;
    }
    s.roots = take_table(s, usize::from(s.n_roots), ROOT_EMPTY);
    s.slots = take_table(s, usize::from(s.n_slots), SLOT_EMPTY);
    s.vols = take_table(s, usize::from(s.n_vols), VOLUME_EMPTY);
    if s.roots.is_null() || s.slots.is_null() || (s.n_vols > 0 && s.vols.is_null()) {
        log(
            s,
            1,
            b"[owner_fs] refusing to construct: the heap cannot hold the tables",
        );
        return -1;
    }
    0
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    if state.is_null() {
        return StepReturn::error(-1);
    }
    // SAFETY: the kernel passes this module's initialised state.
    let s = unsafe { &mut *state.cast::<State>() };
    if s.syscalls.is_null() {
        return StepReturn::error(-1);
    }
    service_ctl(s);
    pump(s);
    StepReturn::Continue
}

/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, `arg` points to `arg_len` bytes and
/// `data` to `data_len` bytes (either may be null when its length is 0),
/// valid for the call and disjoint.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_dispatch"
)]
pub unsafe extern "C" fn module_provider_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    if state.is_null() {
        return errno::EINVAL;
    }
    // SAFETY: the kernel passes this module's own state, and the caller's
    // spans, valid and disjoint for the call.
    let (s, a, d) = unsafe {
        let s = &mut *state.cast::<State>();
        let a: &mut [u8] = if arg.is_null() || arg_len == 0 {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(arg, arg_len)
        };
        let d: &mut [u8] = if data.is_null() || data_len == 0 {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(data, data_len)
        };
        (s, a, d)
    };
    if s.syscalls.is_null() {
        return errno::EINVAL;
    }
    if opcode == abi::internal::reconfigure::OWNER_RELEASED {
        owner_released(s, a);
        return 0;
    }
    dispatch(s, handle, opcode, a, d)
}

/// Apply one `ctl` record directly, as draining the port does.
#[cfg(feature = "host-test")]
pub fn apply_ctl_record(state: *mut u8, msg: &[u8]) {
    // SAFETY: the test passes this module's own state.
    let s = unsafe { &mut *state.cast::<State>() };
    apply_ctl(s, msg);
}

/// Volumes lent to owners.
#[cfg(feature = "host-test")]
pub fn lent_volumes(state: *const u8) -> usize {
    // SAFETY: the caller passes this module's own state.
    let s = unsafe { &*state.cast::<State>() };
    vols(s).iter().filter(|v| v.in_use).count()
}

/// Handles open through roots and volumes.
pub fn open_handles(state: *const u8) -> usize {
    // SAFETY: the caller passes this module's own state.
    let s = unsafe { &*state.cast::<State>() };
    slots(s).iter().filter(|x| x.in_use).count()
}

/// Roots being made or removed, and the start sweep: work the jobs still
/// have.
pub fn jobs_pending(state: *const u8) -> usize {
    // SAFETY: the caller passes this module's own state.
    let s = unsafe { &*state.cast::<State>() };
    roots(s)
        .iter()
        .filter(|r| matches!(r.phase, Phase::Setup | Phase::Removing))
        .count()
        + usize::from(matches!(
            s.remove.stage,
            RmStage::SweepOpen | RmStage::SweepRead | RmStage::SweepEntry | RmStage::SweepCheck
        ))
}

#[cfg(all(target_arch = "wasm32", not(feature = "host-test")))]
fluxor_rt::wasm_entry!();

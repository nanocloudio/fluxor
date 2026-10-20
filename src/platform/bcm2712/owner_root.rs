//! Owner-rooted storage on bare metal: the `fs` contract for workloads.
//!
//! A workload is a tenant of the node. The node's file system (`fat32` over
//! the board's NVMe, a system-owned provider layer) serves the node alone —
//! `provider::layer_visible` — so a workload's `fs` call reaches the
//! platform's kernel-registered provider instead: this one. It answers the
//! call inside a root of the workload's own, the same root Linux gives it
//! (`platform/linux/owner_root.rs`):
//!
//! - every path resolves inside `/owners/<owner uid hex>/files/` on the
//!   node's volume. `..` (or any all-dots name), a backslash or a NUL is
//!   refused, so no path leads out; an empty path or `/` names the root;
//! - the request is handed to the node's provider rewritten beneath that
//!   root, through `provider::dispatch_node_default` — the one path past
//!   `layer_visible`, and the platform's alone: a workload never names a
//!   node path, it names a path in its own root and this layer makes it one;
//! - every handle opened through a root is a slot of this layer's own
//!   table, stamped with its opener: it means nothing to anyone else
//!   (`EBADF`), and the provider's own slot behind it is never handed out;
//! - a root is the owner's only by its grant: an owner whose `CREATE`
//!   granted no node storage (`StorageGrant::None`) is answered `EACCES`;
//! - what the owner holds is charged to its storage ledger against the
//!   `storage_bytes` its `CREATE` admitted, by the costs every platform
//!   charges (`kernel::workload::storage`): each file [`file_cost`] of its
//!   size, each directory [`ENTRY_COST`]. Growth is
//!   charged before it is asked for and refused with `ENOSPC` past the cap
//!   (a cap of 0 is unlimited); a truncate, an unlink, a rmdir and a
//!   rename over an existing name give back what they removed;
//! - the `storage.object` / `storage.namespace` contracts are not rooted
//!   here: the board's store (`platform/bcm2712/store.rs`) is one volatile
//!   RAM table and the node's alone. A workload on metal keeps objects in a
//!   store provider of its own over files in this root (`fs_object`), or
//!   over a volume lent to it.
//!
//! Nothing here waits. The node's provider may answer `EAGAIN` or
//! `EINPROGRESS` to anything; a workload's own request is passed through
//! with its answer, byte-identical on the way down for every re-ask, and the
//! layer's own work — making a root, charging what it holds, removing it —
//! is a resumable job: one outstanding request at a time, re-asked with the
//! same bytes, advanced by [`step`] (from the node's file-system domain) and
//! by the owner's own calls while its root is not ready (`EAGAIN` until it
//! is). Jobs run as the node: no workload is on the provider stack, so the
//! node's provider charges them to nobody.
//!
//! ## A root's life
//!
//! - **Made on first use** by an owner that may hold storage (granted a
//!   root, and `Reserved`, `Active` or `Paused`): `/owners`, `/owners/<hex>`, `/owners/<hex>/files`,
//!   each made and its name fenced (`MKDIR` + `FSYNC_NAME`) before the next,
//!   so a root that answered once is on the media. Then what it already
//!   holds is walked and charged to the owner, past its cap if need be (it
//!   can shrink but not grow until it is back under), as on Linux.
//! - **Survives** a power cut and a reboot: nothing removes a live owner's
//!   root, so a workload readmitted under the same identity finds what it
//!   held.
//! - **Removed when the owner is released** (`DESTROY`, `KILL`, a rolled
//!   back `CREATE`: `provider::notify_owner_released`). Removal is a
//!   background job, bounded per step: first a tombstone,
//!   `/owners/<hex>/gone`, made and fenced; then everything else under
//!   `/owners/<hex>` unlinked and rmdir'd depth first; then the parent
//!   fenced, the tombstone unlinked and `/owners/<hex>` removed.
//! - **A half-removed root is never reused.** The tombstone is durable
//!   before the first entry is removed, so an interrupted removal leaves
//!   either the whole root without a tombstone (the release never reached
//!   the media: the root is intact, and is what that identity finds if it is
//!   admitted again, exactly as on Linux) or a tombstone. A root with a
//!   tombstone is finished, never served: an owner whose root carries one
//!   waits (`EAGAIN`) while it is removed and is then given an empty root,
//!   and at boot every `/owners/*` that carries one is queued for removal.
//!   A root whose tombstone is gone is empty, or holds only an empty
//!   directory, and is served as new.
//!
//! An `EINPROGRESS` a workload abandons still completes in the node's
//! provider; what it would have given back is then not given back. The
//! error is in the owner's disfavour and ends with the owner.

use crate::abi::contracts::storage::fs as op;
use crate::kernel::exec::scheduler;
use crate::kernel::ipc::fd::{slot_of, tag_fd, untag_fd, FD_TAG_FS};
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::{OwnerHandle, OWNER_SYSTEM};
use crate::kernel::workload::storage::{
    file_cost, may_hold_storage, ENTRY_COST, OWNER_MAX_OPEN_FILES,
};

/// Longest path an owner names, matching the `fs` provider's own bound.
pub const PATH_MAX: usize = 255;
/// Longest path handed down: the root prefix plus an owner's path.
const PMAX: usize = 320;
/// Roots: one per owner the node can hold, and room for roots being removed.
const MAX_ROOTS: usize = 80;
/// Handles open through every root at once.
const MAX_SLOTS: usize = 128;
/// Undecided (`EINPROGRESS`) path operations one owner may have
/// outstanding: the node provider's own operation slots.
const MAX_PENDING: usize = 4;
/// Directory levels the charging walk descends. A directory deeper than
/// this is charged as a name only.
const SCAN_DEPTH: usize = 12;
/// Requests a job asks per [`step`].
const ASKS_PER_PUMP: usize = 16;
/// A request's argument, and a `READDIR` batch.
const REQ_MAX: usize = 512;
const EBADF: i32 = -9;
const ENOTDIR: i32 = -20;
const EIO: i32 = -5;

const OWNERS: &[u8] = b"/owners";
const FILES: &[u8] = b"files";
const TOMBSTONE: &[u8] = b"gone";

/// The node's own `fs` provider: where every rooted request goes.
pub type Backend = unsafe fn(i32, u32, *mut u8, usize) -> i32;

static mut BACKEND: Option<Backend> = None;

fn backend() -> Option<Backend> {
    // SAFETY: set at boot (or by a harness) before any dispatch; read-only after.
    unsafe { *core::ptr::addr_of!(BACKEND) }
}

/// The board's backend: the node's default `fs` layer.
///
/// # Safety
/// As [`crate::kernel::module::provider::dispatch_node_default`].
pub unsafe fn node_fs(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    crate::kernel::module::provider::dispatch_node_default(
        crate::kernel::module::provider::contract::FS,
        handle,
        opcode,
        arg,
        arg_len,
    )
}

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

/// A root's directory name under `/owners`: its owner's identity in hex, or
/// the name a boot sweep found a tombstoned root under.
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
    /// `/owners/<name>`.
    fn dir(&self) -> Path {
        let mut p = Path::of(OWNERS);
        p.push_comp(self.bytes());
        p
    }
    /// `/owners/<name>/<leaf>`.
    fn sub(&self, leaf: &[u8]) -> Path {
        let mut p = self.dir();
        p.push_comp(leaf);
        p
    }
}

/// `path` as the owner names it, beneath `/owners/<name>/files`. A leading
/// `/` is the root, empty and `.` components are skipped, and an all-dots
/// component (`..` above all), a NUL, a backslash, or a trailing dot or
/// space (which the volume would strip into another name) is refused. With
/// `allow_root` false a path that names the root itself is `EINVAL`: it
/// names no entry.
fn rooted(name: &Name, path: &[u8], allow_root: bool) -> Result<Path, i32> {
    if path.len() > PATH_MAX {
        return Err(errno::E2BIG);
    }
    let mut out = name.sub(FILES);
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
        if !out.push_comp(comp) {
            return Err(errno::E2BIG);
        }
        comps += 1;
    }
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

// ── Calls down ─────────────────────────────────────────────────────────────

/// Ask the node's provider on the caller's behalf: the caller's module stays
/// on the provider stack, so the provider sees (and caps, and sweeps at
/// release) the workload's own handles.
unsafe fn owner_call(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    match backend() {
        Some(b) => b(handle, opcode, arg, arg_len),
        None => errno::ENOSYS,
    }
}

/// Ask the node's provider as the node: no module on the provider stack,
/// so the request is nobody's — the layer's own jobs and probes.
unsafe fn node_call(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let saved = scheduler::current_module_index();
    scheduler::set_current_module(u32::MAX as usize);
    let rc = owner_call(handle, opcode, arg, arg_len);
    scheduler::set_current_module(saved);
    rc
}

fn retry(rc: i32) -> bool {
    rc == errno::EAGAIN || rc == errno::EINPROGRESS
}

/// The size of the file at `path`, as the node: `Ok(None)` when nothing is
/// there, `Err` for `EAGAIN` (ask again; nothing was done) or a name that is
/// not a file the provider will open.
unsafe fn probe_size(path: &Path) -> Result<Option<u64>, i32> {
    let mut p = *path;
    let rc = node_call(-1, op::OPEN, p.b.as_mut_ptr(), p.n);
    if rc == errno::ENOENT {
        return Ok(None);
    }
    if rc < 0 {
        return Err(rc);
    }
    let h = slot_of(rc);
    let mut st = [0u8; 16];
    let s = node_call(h, op::STAT, st.as_mut_ptr(), st.len());
    node_call(h, op::CLOSE, core::ptr::null_mut(), 0);
    if s < 16 {
        return Err(if s < 0 { s } else { errno::EINVAL });
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&st[..8]);
    Ok(Some(u64::from_le_bytes(b)))
}

/// Whether a directory is at `path`, as the node.
unsafe fn probe_dir(path: &Path) -> Result<bool, i32> {
    let mut p = *path;
    let rc = node_call(-1, op::OPENDIR, p.b.as_mut_ptr(), p.n);
    if rc == errno::ENOENT || rc == ENOTDIR {
        return Ok(false);
    }
    if rc < 0 {
        return Err(rc);
    }
    node_call(slot_of(rc), op::CLOSE, core::ptr::null_mut(), 0);
    Ok(true)
}

// ── Roots ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Free,
    /// Being made, then charged: the scan job's.
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

#[derive(Clone, Copy)]
struct Root {
    phase: Phase,
    /// The owner it serves; the system owner once released.
    owner: OwnerHandle,
    name: Name,
    /// The name is an identity in hex (not a name a sweep found).
    hexed: bool,
    /// Removing: the tombstone is already there (a sweep found it, or a
    /// root's own making did), so the job only checks it is still there
    /// rather than making it.
    found_tombstone: bool,
    /// Removing: the owner is waiting to be given a fresh root once done.
    then_setup: bool,
    failed: i32,
    pend: [Pending; MAX_PENDING],
}

const ROOT_EMPTY: Root = Root {
    phase: Phase::Free,
    owner: OWNER_SYSTEM,
    name: Name::EMPTY,
    hexed: false,
    found_tombstone: false,
    then_setup: false,
    failed: 0,
    pend: [PENDING_EMPTY; MAX_PENDING],
};

static mut ROOTS: [Root; MAX_ROOTS] = [ROOT_EMPTY; MAX_ROOTS];

#[derive(Clone, Copy)]
struct Slot {
    in_use: bool,
    owner: OwnerHandle,
    /// The node provider's own handle (untagged slot).
    inner: i32,
    pos: u64,
    size: u64,
    size_known: bool,
    /// An undecided `PREALLOCATE`: its capacity and what it reserved.
    prealloc: Option<(u32, u64)>,
}

const SLOT_EMPTY: Slot = Slot {
    in_use: false,
    owner: OWNER_SYSTEM,
    inner: -1,
    pos: 0,
    size: 0,
    size_known: false,
    prealloc: None,
};

static mut SLOTS: [Slot; MAX_SLOTS] = [SLOT_EMPTY; MAX_SLOTS];

unsafe fn roots() -> &'static mut [Root; MAX_ROOTS] {
    &mut *core::ptr::addr_of_mut!(ROOTS)
}

unsafe fn slots() -> &'static mut [Slot; MAX_SLOTS] {
    &mut *core::ptr::addr_of_mut!(SLOTS)
}

fn owner_alive(owner: OwnerHandle) -> bool {
    !owner.is_system() && scheduler::owners().lookup(owner).is_some()
}

fn reserve(owner: OwnerHandle, bytes: u64) -> bool {
    bytes == 0 || scheduler::owners_mut().charge_storage(owner, bytes).is_ok()
}

fn give_back(owner: OwnerHandle, bytes: u64) {
    if bytes > 0 {
        scheduler::owners_mut().release_storage(owner, bytes);
    }
}

/// The owner's root, ready to serve, or why not: `EAGAIN` while it is made,
/// charged, or waits for an old root under its identity to go; `EACCES` for
/// an owner that may not hold storage.
unsafe fn ready_root(owner: OwnerHandle) -> Result<usize, i32> {
    for attempt in 0..2 {
        let rs = roots();
        if let Some(i) = rs
            .iter()
            .position(|r| r.phase != Phase::Free && r.owner == owner)
        {
            return match rs[i].phase {
                Phase::Ready => Ok(i),
                Phase::Failed => Err(rs[i].failed),
                _ if attempt == 0 => {
                    pump();
                    continue;
                }
                _ => Err(errno::EAGAIN),
            };
        }
        if !may_hold_storage(owner) {
            return Err(errno::EACCES);
        }
        let Some(uid) = scheduler::owners().lookup(owner).map(|e| e.owner_uid) else {
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
                pump();
                return Err(errno::EAGAIN);
            }
            None => {}
        }
        // A node with no file system has nothing to root a workload in: say
        // so, rather than "not yet" for ever.
        let mut caps = [0u8; 4];
        let rc = node_call(-1, op::CAPS, caps.as_mut_ptr(), caps.len());
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
        pump();
    }
    Err(errno::EAGAIN)
}

// ── Jobs ───────────────────────────────────────────────────────────────────

/// One request a job has outstanding, kept whole so a re-ask is
/// byte-identical.
#[derive(Clone, Copy)]
struct Req {
    live: bool,
    opcode: u32,
    handle: i32,
    len: usize,
    arg: [u8; REQ_MAX],
}

impl Req {
    const IDLE: Self = Self {
        live: false,
        opcode: 0,
        handle: -1,
        len: 0,
        arg: [0; REQ_MAX],
    };

    fn path(opcode: u32, p: &Path) -> Self {
        let mut r = Self {
            live: true,
            opcode,
            handle: -1,
            len: p.n,
            ..Self::IDLE
        };
        r.arg[..p.n].copy_from_slice(p.bytes());
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
    /// Ask (again). `None` while the answer is "ask again".
    unsafe fn ask(&mut self) -> Option<i32> {
        let rc = node_call(self.handle, self.opcode, self.arg.as_mut_ptr(), self.len);
        if retry(rc) || rc == errno::EBUSY {
            return None;
        }
        self.live = false;
        Some(rc)
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
    const EMPTY: Self = Self {
        buf: [0; REQ_MAX],
        len: 0,
        pos: 0,
        left: 0,
    };

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
    /// The next entry: its name and whether it is a directory.
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

/// Making a root and charging what it holds.
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

static mut SCAN: Scan = Scan {
    root: usize::MAX,
    stage: ScanStage::Idle,
    req: Req::IDLE,
    held: -1,
    depth: 0,
    dirs: [-1; SCAN_DEPTH],
    batch: [Batch::EMPTY; SCAN_DEPTH],
    path: Path::EMPTY,
    total: 0,
};

/// Removing roots: the boot sweep first, then each root in turn.
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

static mut REMOVE: Remove = Remove {
    root: usize::MAX,
    stage: RmStage::SweepOpen,
    req: Req::IDLE,
    held: -1,
    path: Path::EMPTY,
    batch: Batch::EMPTY,
    candidate: Name::EMPTY,
};

/// Advance both jobs by a bounded number of requests. Called from the
/// node's file-system domain each step, and from an owner's call while its
/// root is not ready.
///
/// # Safety
/// Single-threaded dispatch, as every provider call.
pub unsafe fn pump() {
    if backend().is_none() {
        return;
    }
    pump_scan();
    pump_remove();
}

/// The step hook: [`pump`].
///
/// # Safety
/// As [`pump`].
pub unsafe fn step() {
    pump();
}

unsafe fn scan_fail(s: &mut Scan, rc: i32) {
    let rs = roots();
    if s.root < MAX_ROOTS {
        log::error!(
            "[owner_root] root {} not made ({:?}): errno {rc}",
            core::str::from_utf8(rs[s.root].name.bytes()).unwrap_or("?"),
            s.stage
        );
        if rc == errno::ENOSYS || rc == errno::ENODEV {
            // The node's file system went away: nothing is wrong with the
            // root, and the next call asks again.
            rs[s.root] = ROOT_EMPTY;
        } else {
            rs[s.root].phase = Phase::Failed;
            rs[s.root].failed = if rc < 0 { rc } else { errno::EINVAL };
        }
    }
    scan_reset(s);
}

unsafe fn scan_reset(s: &mut Scan) {
    while s.depth > 0 {
        s.depth -= 1;
        node_call(s.dirs[s.depth], op::CLOSE, core::ptr::null_mut(), 0);
    }
    if s.held >= 0 {
        node_call(s.held, op::CLOSE, core::ptr::null_mut(), 0);
    }
    s.held = -1;
    s.root = usize::MAX;
    s.stage = ScanStage::Idle;
    s.req = Req::IDLE;
    s.total = 0;
}

unsafe fn pump_scan() {
    let s = &mut *core::ptr::addr_of_mut!(SCAN);
    let rs = roots();
    for _ in 0..ASKS_PER_PUMP {
        if s.stage == ScanStage::Idle {
            let Some(i) = rs.iter().position(|r| r.phase == Phase::Setup) else {
                return;
            };
            s.root = i;
            s.stage = if rs[i].found_tombstone {
                // Its tombstone was just removed with the rest of it.
                ScanStage::Make(0)
            } else {
                ScanStage::Tombstone
            };
            s.total = 0;
            s.depth = 0;
            s.held = -1;
        }
        let name = rs[s.root].name;
        if !s.req.live {
            s.req = match s.stage {
                ScanStage::Tombstone => Req::path(op::OPEN, &name.sub(TOMBSTONE)),
                ScanStage::TombstoneClose => Req::on(op::CLOSE, s.held, 0),
                ScanStage::Make(k) => {
                    let p = match k / 2 {
                        0 => Path::of(OWNERS),
                        1 => name.dir(),
                        _ => name.sub(FILES),
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
                ScanStage::Walk | ScanStage::OpenSub => Req::path(op::OPENDIR, &s.path),
                ScanStage::ReadDir => Req::on(op::READDIR, s.dirs[s.depth - 1], REQ_MAX),
                ScanStage::Entry => {
                    let Some((n, is_dir)) = s.batch[s.depth - 1].next() else {
                        s.stage = ScanStage::ReadDir;
                        continue;
                    };
                    if is_dir {
                        s.total += ENTRY_COST;
                        if s.depth >= SCAN_DEPTH || !s.path.push_comp(n.bytes()) {
                            continue;
                        }
                        s.stage = ScanStage::OpenSub;
                        Req::path(op::OPENDIR, &s.path)
                    } else {
                        let mut p = s.path;
                        if !p.push_comp(n.bytes()) {
                            s.total += ENTRY_COST;
                            continue;
                        }
                        s.stage = ScanStage::FileOpen;
                        Req::path(op::OPEN, &p)
                    }
                }
                ScanStage::FileStat => Req::on(op::STAT, s.held, 16),
                ScanStage::FileOpen | ScanStage::Idle => return,
            };
        }
        let Some(rc) = s.req.ask() else {
            return;
        };
        match s.stage {
            ScanStage::Tombstone => {
                if rc >= 0 {
                    s.held = slot_of(rc);
                    s.stage = ScanStage::TombstoneClose;
                } else if rc == errno::ENOENT {
                    s.stage = ScanStage::Make(0);
                } else {
                    return scan_fail(s, rc);
                }
            }
            ScanStage::TombstoneClose => {
                // An old root under this identity was being removed: finish
                // that first; the owner gets a fresh root after.
                s.held = -1;
                let r = &mut rs[s.root];
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
                    s.stage = ScanStage::Make(k + 1);
                } else {
                    s.path = name.sub(FILES);
                    s.stage = ScanStage::Walk;
                }
            }
            ScanStage::Walk | ScanStage::OpenSub => {
                if rc >= 0 {
                    s.dirs[s.depth] = slot_of(rc);
                    s.depth += 1;
                    s.stage = ScanStage::ReadDir;
                } else if s.stage == ScanStage::Walk {
                    return scan_fail(s, rc);
                } else {
                    // A directory that will not open is charged as a name.
                    s.path.pop_comp();
                    s.stage = ScanStage::Entry;
                }
            }
            ScanStage::ReadDir => {
                if rc > 0 {
                    let d = s.depth - 1;
                    s.batch[d].load(&s.req.arg, rc as usize);
                    s.stage = ScanStage::Entry;
                } else {
                    s.depth -= 1;
                    node_call(s.dirs[s.depth], op::CLOSE, core::ptr::null_mut(), 0);
                    if s.depth == 0 {
                        // Walked: the owner carries what its root holds.
                        let r = &mut rs[s.root];
                        if owner_alive(r.owner) {
                            scheduler::owners_mut().charge_storage_held(r.owner, s.total);
                        }
                        r.phase = Phase::Ready;
                        scan_reset(s);
                    } else {
                        s.path.pop_comp();
                        s.stage = ScanStage::Entry;
                    }
                }
            }
            ScanStage::FileOpen => {
                if rc >= 0 {
                    s.held = slot_of(rc);
                    s.stage = ScanStage::FileStat;
                } else {
                    s.total += ENTRY_COST;
                    s.stage = ScanStage::Entry;
                }
            }
            ScanStage::FileStat => {
                let mut size = 0u64;
                if rc >= 8 {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&s.req.arg[..8]);
                    size = u64::from_le_bytes(b);
                }
                s.total += file_cost(size);
                node_call(s.held, op::CLOSE, core::ptr::null_mut(), 0);
                s.held = -1;
                s.stage = ScanStage::Entry;
            }
            ScanStage::Entry | ScanStage::Idle => {}
        }
    }
}

unsafe fn rm_done(m: &mut Remove, failed: Option<i32>) {
    let rs = roots();
    if m.held >= 0 {
        node_call(m.held, op::CLOSE, core::ptr::null_mut(), 0);
        m.held = -1;
    }
    if m.root < MAX_ROOTS {
        let r = &mut rs[m.root];
        match failed {
            Some(rc) => {
                log::error!(
                    "[owner_root] root {} not removed ({:?}): errno {rc}; its tombstone stays",
                    core::str::from_utf8(r.name.bytes()).unwrap_or("?"),
                    m.stage
                );
                r.phase = Phase::Failed;
                r.failed = if rc < 0 { rc } else { EIO };
            }
            None if r.then_setup && owner_alive(r.owner) && may_hold_storage(r.owner) => {
                r.phase = Phase::Setup;
                r.then_setup = false;
            }
            None => *r = ROOT_EMPTY,
        }
    }
    m.root = usize::MAX;
    m.stage = RmStage::Idle;
    m.req = Req::IDLE;
}

unsafe fn pump_remove() {
    let m = &mut *core::ptr::addr_of_mut!(REMOVE);
    let rs = roots();
    for _ in 0..ASKS_PER_PUMP {
        if m.stage == RmStage::Idle {
            let Some(i) = rs.iter().position(|r| r.phase == Phase::Removing) else {
                return;
            };
            m.root = i;
            m.stage = RmStage::Mark;
            m.held = -1;
        }
        let name = if m.root < MAX_ROOTS {
            rs[m.root].name
        } else {
            Name::EMPTY
        };
        if !m.req.live {
            m.req = match m.stage {
                RmStage::SweepOpen => Req::path(op::OPENDIR, &Path::of(OWNERS)),
                RmStage::SweepRead => Req::on(op::READDIR, m.held, REQ_MAX),
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
                    Req::path(op::OPEN, &n.sub(TOMBSTONE))
                }
                RmStage::Mark => {
                    if rs[m.root].found_tombstone {
                        // Found, not made: removal goes ahead only while it
                        // is still there, so a root made since under the same
                        // directory name is never touched.
                        Req::path(op::OPEN, &name.sub(TOMBSTONE))
                    } else {
                        Req::path(op::OPEN_CREATE, &name.sub(TOMBSTONE))
                    }
                }
                RmStage::MarkClose => Req::on(op::CLOSE, m.held, 0),
                RmStage::MarkFence | RmStage::Fence => {
                    Req::path(op::FSYNC_NAME, &name.sub(TOMBSTONE))
                }
                RmStage::WalkOpen => Req::path(op::OPENDIR, &m.path),
                RmStage::WalkRead => Req::on(op::READDIR, m.held, REQ_MAX),
                RmStage::Unmark => Req::path(op::UNLINK, &name.sub(TOMBSTONE)),
                RmStage::RmRoot => Req::path(op::RMDIR, &name.dir()),
                RmStage::Unlink | RmStage::Rmdir | RmStage::SweepCheck | RmStage::Idle => return,
            };
        }
        let Some(rc) = m.req.ask() else {
            return;
        };
        match m.stage {
            RmStage::SweepOpen => {
                if rc >= 0 {
                    m.held = slot_of(rc);
                    m.stage = RmStage::SweepRead;
                } else if rc == errno::ENOENT {
                    m.stage = RmStage::Idle;
                } else {
                    log::warn!("[owner_root] boot sweep: /owners errno {rc}");
                    m.stage = RmStage::Idle;
                }
            }
            RmStage::SweepRead => {
                if rc > 0 {
                    m.batch.load(&m.req.arg, rc as usize);
                    m.stage = RmStage::SweepEntry;
                } else {
                    node_call(m.held, op::CLOSE, core::ptr::null_mut(), 0);
                    m.held = -1;
                    m.stage = RmStage::Idle;
                }
            }
            RmStage::SweepCheck => {
                if rc >= 0 {
                    node_call(slot_of(rc), op::CLOSE, core::ptr::null_mut(), 0);
                    let n = m.candidate;
                    let known = rs.iter().any(|r| r.phase != Phase::Free && r.name == n);
                    if !known {
                        if let Some(i) = rs.iter().position(|r| r.phase == Phase::Free) {
                            log::info!(
                                "[owner_root] tombstoned root {} queued for removal",
                                core::str::from_utf8(n.bytes()).unwrap_or("?")
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
                m.stage = RmStage::SweepEntry;
            }
            RmStage::Mark => {
                if rc >= 0 {
                    m.held = slot_of(rc);
                    m.stage = RmStage::MarkClose;
                } else if rc == errno::ENOENT {
                    // No root there (or no tombstone on a found one): nothing
                    // to remove.
                    return rm_done(m, None);
                } else {
                    return rm_done(m, Some(rc));
                }
            }
            RmStage::MarkClose => {
                m.held = -1;
                m.stage = if rs[m.root].found_tombstone {
                    m.path = name.dir();
                    RmStage::WalkOpen
                } else {
                    RmStage::MarkFence
                };
            }
            RmStage::MarkFence => {
                if rc < 0 {
                    return rm_done(m, Some(rc));
                }
                m.path = name.dir();
                m.stage = RmStage::WalkOpen;
            }
            RmStage::WalkOpen => {
                if rc >= 0 {
                    m.held = slot_of(rc);
                    m.stage = RmStage::WalkRead;
                } else if rc == errno::ENOENT && m.path.n > name.dir().n {
                    m.path.pop_comp();
                } else if rc == errno::ENOENT {
                    return rm_done(m, None);
                } else {
                    return rm_done(m, Some(rc));
                }
            }
            RmStage::WalkRead => {
                let at_top = m.path.n == name.dir().n;
                if rc > 0 {
                    m.batch.load(&m.req.arg, rc as usize);
                    let mut pick = None;
                    while let Some((n, is_dir)) = m.batch.next() {
                        if at_top && n.bytes().eq_ignore_ascii_case(TOMBSTONE) {
                            continue;
                        }
                        pick = Some((n, is_dir));
                        break;
                    }
                    let Some((n, is_dir)) = pick else {
                        continue; // only the tombstone here: read on
                    };
                    node_call(m.held, op::CLOSE, core::ptr::null_mut(), 0);
                    m.held = -1;
                    if !m.path.push_comp(n.bytes()) {
                        return rm_done(m, Some(errno::E2BIG));
                    }
                    if is_dir {
                        m.stage = RmStage::WalkOpen;
                    } else {
                        m.req = Req::path(op::UNLINK, &m.path);
                        m.path.pop_comp();
                        m.stage = RmStage::Unlink;
                    }
                } else {
                    node_call(m.held, op::CLOSE, core::ptr::null_mut(), 0);
                    m.held = -1;
                    if at_top {
                        m.stage = RmStage::Fence;
                    } else {
                        m.req = Req::path(op::RMDIR, &m.path);
                        m.path.pop_comp();
                        m.stage = RmStage::Rmdir;
                    }
                }
            }
            RmStage::Unlink | RmStage::Rmdir => {
                // `ENOTEMPTY` here is an entry the walk cannot see: fail
                // rather than walk for ever.
                if rc < 0 && rc != errno::ENOENT {
                    return rm_done(m, Some(rc));
                }
                m.stage = RmStage::WalkOpen;
            }
            RmStage::Fence => {
                if rc < 0 {
                    return rm_done(m, Some(rc));
                }
                m.stage = RmStage::Unmark;
            }
            RmStage::Unmark => {
                if rc < 0 && rc != errno::ENOENT {
                    return rm_done(m, Some(rc));
                }
                m.stage = RmStage::RmRoot;
            }
            RmStage::RmRoot => {
                if rc < 0 && rc != errno::ENOENT {
                    return rm_done(m, Some(rc));
                } else {
                    return rm_done(m, None);
                }
            }
            RmStage::SweepEntry | RmStage::Idle => {}
        }
    }
}

// ── The owner's calls ──────────────────────────────────────────────────────

/// Register the platform's rooting layer: the kernel's `fs` provider, which
/// a workload's calls reach (the node's own layer is invisible to it), and
/// the owner-release hook that removes a released owner's root.
///
/// # Safety
/// Single-threaded boot, before any provider dispatch.
pub unsafe fn init(backend: Backend) {
    use crate::kernel::module::provider;
    reset();
    BACKEND = Some(backend);
    provider::register(provider::contract::FS, dispatch);
    provider::register_owner_release_hook(release);
}

/// Forget every root, handle and job (a fresh boot), keeping the backend.
///
/// # Safety
/// Single-threaded; no handle through a root is used afterwards.
pub unsafe fn reset() {
    *roots() = [ROOT_EMPTY; MAX_ROOTS];
    *slots() = [SLOT_EMPTY; MAX_SLOTS];
    let s = &mut *core::ptr::addr_of_mut!(SCAN);
    s.root = usize::MAX;
    s.stage = ScanStage::Idle;
    s.req = Req::IDLE;
    s.held = -1;
    s.depth = 0;
    let m = &mut *core::ptr::addr_of_mut!(REMOVE);
    m.root = usize::MAX;
    m.stage = RmStage::SweepOpen;
    m.req = Req::IDLE;
    m.held = -1;
}

/// Set the backend alone (the harness mounts a provider of its own).
///
/// # Safety
/// As [`init`].
pub unsafe fn set_backend(backend: Option<Backend>) {
    BACKEND = backend;
}

/// The owner-release hook: close every handle the owner holds through its
/// root, forget what it had undecided, and queue its root for removal — a
/// root it never touched in this run included, as on Linux, since one a
/// previous run left is its own all the same. An owner that acted with the
/// node's authority has no root, and none is queued for removal.
pub fn release(owner: OwnerHandle) {
    if owner.is_system() || !crate::kernel::workload::storage::rooted(owner) {
        return;
    }
    // SAFETY: owner release runs on the scheduler thread, as every dispatch.
    unsafe {
        for s in slots().iter_mut().filter(|s| s.in_use && s.owner == owner) {
            node_call(s.inner, op::CLOSE, core::ptr::null_mut(), 0);
            *s = SLOT_EMPTY;
        }
        let rs = roots();
        let scan = &mut *core::ptr::addr_of_mut!(SCAN);
        match rs
            .iter()
            .position(|r| r.phase != Phase::Free && r.owner == owner)
        {
            Some(i) => {
                if scan.root == i {
                    scan_reset(scan);
                }
                let r = &mut rs[i];
                r.owner = OWNER_SYSTEM;
                r.pend = [PENDING_EMPTY; MAX_PENDING];
                r.then_setup = false;
                match r.phase {
                    Phase::Removing => {}
                    // A failed removal keeps its tombstone; a later boot
                    // finishes it.
                    Phase::Failed if r.found_tombstone => *r = ROOT_EMPTY,
                    _ => {
                        r.phase = Phase::Removing;
                        r.found_tombstone = false;
                    }
                }
            }
            None => {
                let Some(uid) = scheduler::owners().lookup(owner).map(|e| e.owner_uid) else {
                    return;
                };
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
}

/// The `fs` provider the kernel registers on bare metal. A workload's call
/// (the only kind that reaches it while the node has an `fs` layer of its
/// own) is served inside the workload's root; the node itself, and an owner
/// acting with its authority, has nothing here (`ENOSYS`): it reaches the
/// node's own `fs` layer.
///
/// # Safety
/// `arg` must satisfy the `fs` contract's requirements for `opcode`.
pub unsafe fn dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let owner = scheduler::caller_owner();
    if !crate::kernel::workload::storage::rooted(owner) || backend().is_none() {
        return errno::ENOSYS;
    }
    if opcode == op::CAPS {
        let rc = node_call(-1, op::CAPS, arg, arg_len);
        if rc >= 0 && !arg.is_null() && arg_len >= 4 {
            let mut b = [0u8; 4];
            core::ptr::copy_nonoverlapping(arg, b.as_mut_ptr(), 4);
            // No second name for a file: a hard link would be charged once
            // and could be given back twice.
            let caps = u32::from_le_bytes(b) & !(op::caps::LINK | op::caps::SYMLINK);
            core::ptr::copy_nonoverlapping(caps.to_le_bytes().as_ptr(), arg, 4);
        }
        return rc;
    }
    if handle >= 0 {
        return handle_op(owner, handle, opcode, arg, arg_len);
    }
    let ri = match ready_root(owner) {
        Ok(i) => i,
        Err(e) => return e,
    };
    path_op(owner, ri, opcode, arg, arg_len)
}

/// A free slot `owner` may take, or `ENOMEM` when the table, or the owner's
/// share of it, is full — asked before anything is created.
unsafe fn free_slot(owner: OwnerHandle) -> Result<usize, i32> {
    let ss = slots();
    if ss.iter().filter(|s| s.in_use && s.owner == owner).count() >= OWNER_MAX_OPEN_FILES {
        return Err(errno::ENOMEM);
    }
    ss.iter().position(|s| !s.in_use).ok_or(errno::ENOMEM)
}

unsafe fn claim(i: usize, owner: OwnerHandle, rc: i32, created: bool) -> i32 {
    let (_tag, inner) = untag_fd(rc);
    slots()[i] = Slot {
        in_use: true,
        owner,
        inner,
        size_known: created,
        ..SLOT_EMPTY
    };
    tag_fd(FD_TAG_FS, i as i32)
}

unsafe fn handle_op(
    owner: OwnerHandle,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let i = handle as usize;
    let ss = slots();
    let Some(s) = ss.get_mut(i).filter(|s| s.in_use && s.owner == owner) else {
        return EBADF;
    };
    let inner = s.inner;
    match opcode {
        op::CLOSE => {
            let rc = owner_call(inner, op::CLOSE, core::ptr::null_mut(), 0);
            *s = SLOT_EMPTY;
            rc
        }
        op::READ => {
            let rc = owner_call(inner, opcode, arg, arg_len);
            if rc > 0 {
                s.pos += rc as u64;
            }
            rc
        }
        op::SEEK => {
            let rc = owner_call(inner, opcode, arg, arg_len);
            if rc >= 0 && !arg.is_null() && arg_len >= 4 {
                let mut b = [0u8; 8];
                core::ptr::copy_nonoverlapping(arg, b.as_mut_ptr(), arg_len.min(8));
                s.pos = if arg_len >= 8 {
                    u64::from_le_bytes(b)
                } else {
                    u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                };
            }
            rc
        }
        op::WRITE | op::WRITE_ASYNC => {
            if let Err(e) = know_size(s) {
                return e;
            }
            let grow = (s.pos + arg_len as u64).saturating_sub(s.size);
            if !reserve(owner, grow) {
                return errno::ENOSPC;
            }
            let rc = owner_call(inner, opcode, arg, arg_len);
            let mut used = 0;
            if rc > 0 {
                let end = s.pos + rc as u64;
                if end > s.size {
                    used = end - s.size;
                    s.size = end;
                }
                s.pos = end;
            }
            give_back(owner, grow - used.min(grow));
            rc
        }
        op::PREALLOCATE => {
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            let mut b = [0u8; 4];
            core::ptr::copy_nonoverlapping(arg, b.as_mut_ptr(), 4);
            let cap = u32::from_le_bytes(b);
            let reserved = match s.prealloc {
                Some((c, r)) if c == cap => r,
                _ => {
                    // A different request in place of an undecided one: what
                    // that one reserved stays charged (it still completes).
                    if s.prealloc.take().is_some() {
                        s.size_known = false;
                    }
                    if let Err(e) = know_size(s) {
                        return e;
                    }
                    let grow = u64::from(cap).saturating_sub(s.size);
                    if !reserve(owner, grow) {
                        return errno::ENOSPC;
                    }
                    grow
                }
            };
            let rc = owner_call(inner, opcode, arg, arg_len);
            if rc == errno::EINPROGRESS {
                s.prealloc = Some((cap, reserved));
                return rc;
            }
            s.prealloc = None;
            if rc == 0 {
                s.size = s.size.max(u64::from(cap));
                s.pos = 0;
            } else {
                give_back(owner, reserved);
            }
            rc
        }
        op::STAT | op::FSYNC | op::FSYNC_SUBMIT | op::FSYNC_POLL | op::READDIR => {
            owner_call(inner, opcode, arg, arg_len)
        }
        _ => errno::ENOSYS,
    }
}

/// Learn a handle's size from the provider, once.
unsafe fn know_size(s: &mut Slot) -> Result<(), i32> {
    if s.size_known {
        return Ok(());
    }
    let mut st = [0u8; 16];
    let rc = owner_call(s.inner, op::STAT, st.as_mut_ptr(), st.len());
    if rc < 8 {
        return Err(if rc < 0 { rc } else { errno::EINVAL });
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&st[..8]);
    s.size = u64::from_le_bytes(b);
    s.size_known = true;
    Ok(())
}

/// The path, or the error, of a single-path request.
fn path_arg(arg: *mut u8, arg_len: usize) -> Result<&'static [u8], i32> {
    if arg.is_null() || arg_len == 0 {
        return Err(errno::EINVAL);
    }
    if arg_len > PATH_MAX {
        return Err(errno::E2BIG);
    }
    // SAFETY: the caller's `arg[..arg_len]`, read before anything else
    // touches it.
    Ok(unsafe { core::slice::from_raw_parts(arg, arg_len) })
}

/// The `RENAME` / `LINK` two-path argument.
fn two_paths(arg: *mut u8, arg_len: usize) -> Option<(&'static [u8], &'static [u8])> {
    if arg.is_null() || arg_len < 4 {
        return None;
    }
    // SAFETY: the caller's `arg[..arg_len]`.
    let a = unsafe { core::slice::from_raw_parts(arg, arg_len) };
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

unsafe fn find_pending(ri: usize, opcode: u32, hash: u64, len: usize) -> Option<usize> {
    roots()[ri]
        .pend
        .iter()
        .position(|p| p.live && p.opcode == opcode && p.hash == hash && p.len == len)
}

/// Settle the ledger on a path operation's answer. `EAGAIN` consumed
/// nothing: what was reserved goes back. `EINPROGRESS` is kept with what it
/// reserved and would give back, for the ask that decides it.
unsafe fn settle(
    owner: OwnerHandle,
    ri: usize,
    key: (u32, u64, usize),
    rc: i32,
    reserved: u64,
    refund: u64,
) -> i32 {
    if rc == errno::EINPROGRESS {
        let pend = &mut roots()[ri].pend;
        // Full: the oldest stays charged and is no longer tracked, which is
        // in the owner's disfavour only.
        let slot = pend.iter().position(|p| !p.live).unwrap_or(0);
        pend[slot] = Pending {
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
        give_back(owner, reserved);
    } else {
        give_back(owner, refund);
    }
    rc
}

/// Re-ask an undecided path operation, settling it once decided.
unsafe fn reask(owner: OwnerHandle, ri: usize, pi: usize, req: &mut Path) -> i32 {
    let p = roots()[ri].pend[pi];
    let rc = owner_call(-1, p.opcode, req.b.as_mut_ptr(), req.n);
    if retry(rc) {
        return rc;
    }
    roots()[ri].pend[pi] = PENDING_EMPTY;
    if rc < 0 {
        give_back(owner, p.reserved);
    } else {
        give_back(owner, p.refund);
    }
    rc
}

unsafe fn path_op(owner: OwnerHandle, ri: usize, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let name = roots()[ri].name;
    match opcode {
        op::OPEN | op::OPENDIR => {
            let path = match path_arg(arg, arg_len).and_then(|p| rooted(&name, p, true)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let i = match free_slot(owner) {
                Ok(i) => i,
                Err(e) => return e,
            };
            let mut p = path;
            let rc = owner_call(-1, opcode, p.b.as_mut_ptr(), p.n);
            if rc < 0 {
                return rc;
            }
            claim(i, owner, rc, false)
        }
        op::OPEN_CREATE => {
            let mut p = match path_arg(arg, arg_len).and_then(|p| rooted(&name, p, false)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let i = match free_slot(owner) {
                Ok(i) => i,
                Err(e) => return e,
            };
            let key = (opcode, fnv64(&[p.bytes()]), p.n);
            let rc = if let Some(pi) = find_pending(ri, key.0, key.1, key.2) {
                reask(owner, ri, pi, &mut p)
            } else {
                // A new name is charged before it exists; an existing file
                // is truncated by the create, and its bytes given back.
                let (reserved, refund) = match probe_size(&p) {
                    Ok(Some(size)) => (0, size),
                    Ok(None) => (ENTRY_COST, 0),
                    Err(errno::EAGAIN) => return errno::EAGAIN,
                    Err(_) => (0, 0),
                };
                if !reserve(owner, reserved) {
                    return errno::ENOSPC;
                }
                let rc = owner_call(-1, opcode, p.b.as_mut_ptr(), p.n);
                settle(owner, ri, key, rc, reserved, refund)
            };
            if rc < 0 {
                return rc;
            }
            claim(i, owner, rc, true)
        }
        op::UNLINK | op::RMDIR | op::MKDIR | op::FSYNC_NAME => {
            let mut p = match path_arg(arg, arg_len).and_then(|p| rooted(&name, p, false)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let key = (opcode, fnv64(&[p.bytes()]), p.n);
            if let Some(pi) = find_pending(ri, key.0, key.1, key.2) {
                return reask(owner, ri, pi, &mut p);
            }
            let (reserved, refund) = match opcode {
                op::UNLINK => match probe_size(&p) {
                    Ok(Some(size)) => (0, file_cost(size)),
                    Ok(None) => (0, 0),
                    Err(errno::EAGAIN) => return errno::EAGAIN,
                    Err(_) => (0, 0),
                },
                op::RMDIR => (0, ENTRY_COST),
                op::MKDIR => match probe_dir(&p) {
                    Ok(true) => (0, 0),
                    Ok(false) => (ENTRY_COST, 0),
                    Err(e) => return e,
                },
                _ => (0, 0),
            };
            if !reserve(owner, reserved) {
                return errno::ENOSPC;
            }
            let rc = owner_call(-1, opcode, p.b.as_mut_ptr(), p.n);
            settle(owner, ri, key, rc, reserved, refund)
        }
        op::TRUNCATE => {
            if arg.is_null() || arg_len < 9 {
                return errno::EINVAL;
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let mut lb = [0u8; 8];
            lb.copy_from_slice(&a[..8]);
            let len = u64::from_le_bytes(lb);
            let path = match path_arg(arg.add(8), arg_len - 8).and_then(|p| rooted(&name, p, false))
            {
                Ok(p) => p,
                Err(e) => return e,
            };
            let mut req = Path::of(&lb);
            if !req.push(path.bytes()) {
                return errno::E2BIG;
            }
            let key = (opcode, fnv64(&[req.bytes()]), req.n);
            if let Some(pi) = find_pending(ri, key.0, key.1, key.2) {
                return reask(owner, ri, pi, &mut req);
            }
            let refund = match probe_size(&path) {
                Ok(Some(size)) => size.saturating_sub(len),
                Ok(None) => 0,
                Err(errno::EAGAIN) => return errno::EAGAIN,
                Err(_) => 0,
            };
            let rc = owner_call(-1, opcode, req.b.as_mut_ptr(), req.n);
            settle(owner, ri, key, rc, 0, refund)
        }
        op::RENAME => {
            let Some((src, dst)) = two_paths(arg, arg_len) else {
                return errno::EINVAL;
            };
            let (s, d) = match (rooted(&name, src, false), rooted(&name, dst, false)) {
                (Ok(s), Ok(d)) => (s, d),
                (Err(e), _) | (_, Err(e)) => return e,
            };
            let mut req = Path::EMPTY;
            let ok = req.push(&(s.n as u16).to_le_bytes())
                && req.push(s.bytes())
                && req.push(&(d.n as u16).to_le_bytes())
                && req.push(d.bytes());
            if !ok {
                return errno::E2BIG;
            }
            let key = (opcode, fnv64(&[req.bytes()]), req.n);
            if let Some(pi) = find_pending(ri, key.0, key.1, key.2) {
                return reask(owner, ri, pi, &mut req);
            }
            // The entry the destination named, if any, goes with its charge.
            let refund = if s.bytes().eq_ignore_ascii_case(d.bytes()) {
                0
            } else {
                match probe_size(&d) {
                    Ok(Some(size)) => file_cost(size),
                    Ok(None) => 0,
                    Err(errno::EAGAIN) => return errno::EAGAIN,
                    Err(_) => 0,
                }
            };
            let rc = owner_call(-1, opcode, req.b.as_mut_ptr(), req.n);
            settle(owner, ri, key, rc, 0, refund)
        }
        // No second name for a file (one inode charged once, given back
        // twice), and the volume has no symlinks.
        op::LINK | op::READLINK => errno::ENOSYS,
        _ => errno::ENOSYS,
    }
}

/// Handles open through roots (for diagnostics and tests).
pub fn open_handles() -> usize {
    // SAFETY: scheduler-thread read.
    unsafe { slots().iter().filter(|s| s.in_use).count() }
}

/// Roots being made, removed, or failed: work the jobs still have.
pub fn jobs_pending() -> usize {
    // SAFETY: scheduler-thread read.
    unsafe {
        let m = &*core::ptr::addr_of!(REMOVE);
        roots()
            .iter()
            .filter(|r| matches!(r.phase, Phase::Setup | Phase::Removing))
            .count()
            + usize::from(matches!(
                m.stage,
                RmStage::SweepOpen | RmStage::SweepRead | RmStage::SweepEntry | RmStage::SweepCheck
            ))
    }
}

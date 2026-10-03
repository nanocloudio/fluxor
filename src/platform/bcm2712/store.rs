//! Versioned watchable key store for bare metal — the `storage.object` (0x14)
//! and `storage.namespace` (0x13) contracts on BCM2712.
//!
//! A store-backed graph needs both: every source in one SUBSCRIBEs a prefix and
//! every effect PUTs a key, so a board without these contracts runs the graph
//! and produces nothing.
//!
//! Same semantics as `platform/linux/store.rs` — monotone revision clock,
//! per-key revision as the CAS token, prefix enumeration with a paged cursor,
//! and a bounded change history that drives SUBSCRIBE with resume-from-revision
//! — and deliberately the same WIRE, because a consumer parses one encoding
//! whichever platform answers it. What differs is the backing: no `alloc` here,
//! so the store is a fixed-capacity static rather than a `BTreeMap`, and the
//! capacities below are the honest ceiling on what a bare-metal store can
//! hold.
//!
//! **VOLATILE.** There is no log and no NVMe: the store lives in RAM and a
//! reboot starts empty, so `PUT` reports `RevisionMonotone` (ordering holds)
//! and never `LocalDurable`. That is the truthful fence — under-reporting
//! durability is the safe direction, and claiming durability this store cannot
//! provide would let a caller conclude a grant survived a power cut.
//!
//! Single-writer by construction, as on Linux: the provider serialises calls
//! and the runtime is one scheduler on one core for this dispatch.

use crate::abi::contracts::storage::handle::STORAGE_KEY_MAX;
use crate::abi::contracts::storage::{namespace as ns_op, object as obj_op};
use crate::abi::fence::{Fence, WIRE_MAX_LEN};
use crate::kernel::ipc::channel::channel_write;
use crate::kernel::ipc::fd::{slot_of, tag_fd, FD_TAG_STORAGE_NAMESPACE, FD_TAG_STORAGE_OBJECT};
use crate::kernel::sys::errno;

/// Objects the store can hold — one machine's worth of state, not a fleet's.
/// Exceeding it is refused (`ENOMEM`) rather than evicting: a consumer reads a
/// missing key as a deletion, so silently evicting is how it comes to tear
/// down what that key named.
pub const MAX_OBJECTS: usize = 512;
/// Longest value. Matches `store_effect`'s own `MAX_VALUE`, so a value that
/// crosses the connector fits the store that holds it.
pub const MAX_VALUE: usize = 4096;
/// Retained change history. A watcher that falls further behind than this is
/// told to relist (the `Lost` sentinel) rather than handed a gap.
pub const HISTORY: usize = 128;
/// Concurrent subscriptions, and open read slots. One subscription per watched
/// prefix per module: a control plane of ~45 reconcilers, most watching their
/// own collection plus the ones they depend on, asks for ~95 — so the table is
/// sized for a whole control plane with headroom (~55 KiB of statics), not for
/// a handful of watchers. A refused subscription answers ENOMEM.
const MAX_SUBS: usize = 256;
const MAX_READS: usize = 32;

/// `CONTENT_TYPES` byte for `NamespaceChange` (`contracts/src/lib.rs`). A
/// watcher routes on this to tell a store change from anything else sharing
/// its sink, so it must be the vocabulary's byte and not a private one.
const CT_NAMESPACE_CHANGE: u8 = 0x23;
const EVENT_HEADER_SIZE: usize = 32;
/// The event source id. Byte-identical to Linux's: a consumer that matches on
/// it must not have to know which platform produced the change.
const STORE_SOURCE: [u8; 16] = *b"fluxor-cp-store\0";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Copy)]
struct Entry {
    in_use: bool,
    key: [u8; STORAGE_KEY_MAX],
    key_len: u16,
    val: [u8; MAX_VALUE],
    val_len: u16,
    revision: u64,
}

const ENTRY_EMPTY: Entry = Entry {
    in_use: false,
    key: [0; STORAGE_KEY_MAX],
    key_len: 0,
    val: [0; MAX_VALUE],
    val_len: 0,
    revision: 0,
};

#[derive(Clone, Copy)]
struct HistEntry {
    revision: u64,
    kind: Kind,
    key: [u8; STORAGE_KEY_MAX],
    key_len: u16,
    val: [u8; MAX_VALUE],
    val_len: u16,
}

const HIST_EMPTY: HistEntry = HistEntry {
    revision: 0,
    kind: Kind::Added,
    key: [0; STORAGE_KEY_MAX],
    key_len: 0,
    val: [0; MAX_VALUE],
    val_len: 0,
};

#[derive(Clone, Copy)]
struct Sub {
    in_use: bool,
    prefix: [u8; STORAGE_KEY_MAX],
    prefix_len: u16,
    sink_chan: u32,
    sequence: u32,
    /// The revision this watcher has been served up to.
    cursor: u64,
}

const SUB_EMPTY: Sub = Sub {
    in_use: false,
    prefix: [0; STORAGE_KEY_MAX],
    prefix_len: 0,
    sink_chan: 0,
    sequence: 0,
    cursor: 0,
};

#[derive(Clone, Copy)]
struct ReadSlot {
    in_use: bool,
    val: [u8; MAX_VALUE],
    val_len: u16,
    revision: u64,
}

const READ_EMPTY: ReadSlot = ReadSlot {
    in_use: false,
    val: [0; MAX_VALUE],
    val_len: 0,
    revision: 0,
};

/// The store itself. A static, because bare metal has no heap to put it on and
/// the capacity has to be a decision made once rather than a growth curve.
pub struct Store {
    entries: [Entry; MAX_OBJECTS],
    hist: [HistEntry; HISTORY],
    /// Next history slot, and the oldest revision still retained.
    hist_head: usize,
    hist_filled: bool,
    revision: u64,
}

static mut STORE: Store = Store {
    entries: [ENTRY_EMPTY; MAX_OBJECTS],
    hist: [HIST_EMPTY; HISTORY],
    hist_head: 0,
    hist_filled: false,
    revision: 0,
};
static mut SUBS: [Sub; MAX_SUBS] = [SUB_EMPTY; MAX_SUBS];
static mut READS: [ReadSlot; MAX_READS] = [READ_EMPTY; MAX_READS];
static mut ENABLED: bool = false;

/// Provider telemetry. A store's failures are otherwise only guessable from
/// the outside: a watcher that saw nothing looks the same whether no change
/// happened or every change was dropped. Emitted on a slow cadence over the
/// same log path everything else uses, so the rig's capture carries it.
static mut TLM_PUTS: u32 = 0;
static mut TLM_DELS: u32 = 0;
static mut TLM_LISTS: u32 = 0;
static mut TLM_PUSHED: u32 = 0;
static mut TLM_BLOCKED: u32 = 0;
static mut TLM_LOST: u32 = 0;
static mut TLM_TICK: u32 = 0;

/// `[store] objs=.. rev=.. subs=.. put=.. del=.. list=.. push=.. blk=.. lost=..`
///
/// `push` vs `blk` is the pair that matters: a change that was generated but
/// could not be written to a watcher's channel is the difference between "the
/// source never woke" and "the source was never told", and without it both look
/// like silence.
unsafe fn telemetry(store: &Store) {
    TLM_TICK = TLM_TICK.wrapping_add(1);
    if TLM_TICK % 64 != 1 {
        return;
    }
    let subs = &*core::ptr::addr_of!(SUBS);
    let live = subs.iter().filter(|s| s.in_use).count() as u32;
    let objs = store.entries.iter().filter(|e| e.in_use).count() as u32;
    let mut buf = [0u8; 160];
    let mut pos = 0usize;
    macro_rules! lit {
        ($b:expr) => {{
            let b = $b;
            buf[pos..pos + b.len()].copy_from_slice(b);
            pos += b.len();
        }};
    }
    macro_rules! num {
        ($v:expr) => {{
            let mut v: u32 = $v;
            let mut tmp = [0u8; 10];
            let mut n = 0usize;
            if v == 0 {
                tmp[0] = b'0';
                n = 1;
            }
            while v > 0 {
                tmp[n] = b'0' + (v % 10) as u8;
                v /= 10;
                n += 1;
            }
            for i in 0..n {
                buf[pos + i] = tmp[n - 1 - i];
            }
            pos += n;
        }};
    }
    lit!(b"[store] objs=");
    num!(objs);
    lit!(b" rev=");
    num!(store.revision as u32);
    lit!(b" subs=");
    num!(live);
    lit!(b" put=");
    num!(TLM_PUTS);
    lit!(b" del=");
    num!(TLM_DELS);
    lit!(b" list=");
    num!(TLM_LISTS);
    lit!(b" push=");
    num!(TLM_PUSHED);
    lit!(b" blk=");
    num!(TLM_BLOCKED);
    lit!(b" lost=");
    num!(TLM_LOST);
    // Straight into the log ring, the same sink `log::info!` lands in on this
    // board — so the rig's UDP capture carries it with everything else.
    crate::kernel::sys::log_ring::push_bytes(&buf[..pos]);
}

impl Store {
    fn find(&self, key: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.in_use && &e.key[..e.key_len as usize] == key)
    }

    fn get(&self, key: &[u8]) -> Option<(&[u8], u64)> {
        let i = self.find(key)?;
        let e = &self.entries[i];
        Some((&e.val[..e.val_len as usize], e.revision))
    }

    /// Record a change in the bounded history. The oldest is overwritten; a
    /// watcher behind the window is told to relist rather than handed a gap,
    /// which is why the window's floor is tracked rather than assumed.
    fn push_hist(&mut self, revision: u64, kind: Kind, key: &[u8], val: &[u8]) {
        let h = &mut self.hist[self.hist_head];
        h.revision = revision;
        h.kind = kind;
        h.key_len = key.len().min(STORAGE_KEY_MAX) as u16;
        h.key[..h.key_len as usize].copy_from_slice(&key[..h.key_len as usize]);
        h.val_len = val.len().min(MAX_VALUE) as u16;
        h.val[..h.val_len as usize].copy_from_slice(&val[..h.val_len as usize]);
        self.hist_head += 1;
        if self.hist_head == HISTORY {
            self.hist_head = 0;
            self.hist_filled = true;
        }
    }

    /// The oldest revision the history can still serve. A `since` below this
    /// cannot be resumed.
    fn hist_floor(&self) -> u64 {
        if !self.hist_filled {
            return 0;
        }
        self.hist[self.hist_head].revision
    }

    fn put(&mut self, key: &[u8], val: &[u8]) -> Result<u64, i32> {
        if key.len() > STORAGE_KEY_MAX || val.len() > MAX_VALUE {
            return Err(errno::EINVAL);
        }
        self.revision += 1;
        let rev = self.revision;
        match self.find(key) {
            Some(i) => {
                let e = &mut self.entries[i];
                e.val_len = val.len() as u16;
                e.val[..val.len()].copy_from_slice(val);
                e.revision = rev;
                self.push_hist(rev, Kind::Modified, key, val);
            }
            None => {
                let Some(i) = self.entries.iter().position(|e| !e.in_use) else {
                    // Undo the revision bump: nothing happened, and a clock
                    // that moved for a write that did not land makes every
                    // watcher's cursor lie about what it has seen.
                    self.revision -= 1;
                    return Err(errno::ENOMEM);
                };
                let e = &mut self.entries[i];
                e.in_use = true;
                e.key_len = key.len() as u16;
                e.key[..key.len()].copy_from_slice(key);
                e.val_len = val.len() as u16;
                e.val[..val.len()].copy_from_slice(val);
                e.revision = rev;
                self.push_hist(rev, Kind::Added, key, val);
            }
        }
        Ok(rev)
    }

    fn delete(&mut self, key: &[u8]) -> Option<u64> {
        let i = self.find(key)?;
        self.revision += 1;
        let rev = self.revision;
        self.entries[i] = ENTRY_EMPTY;
        self.push_hist(rev, Kind::Deleted, key, &[]);
        Some(rev)
    }
}

/// What a write may be made conditional on, by the contract's discriminants.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Condition {
    Any,
    Absent,
    Revision(u64),
}

impl Condition {
    /// Whether a key at `existing` (its revision, `None` when absent) refuses
    /// the write.
    fn refuses(self, existing: Option<u64>) -> bool {
        match self {
            Condition::Any => false,
            Condition::Absent => existing.is_some(),
            Condition::Revision(want) => existing != Some(want),
        }
    }
}

/// Read a `[precondition:u8][etag_len:u8][etag]` block at `*p`, advancing past
/// it. `None` when the block is cut short, names a kind this store does not
/// know, or carries `ETAG` without a whole revision: each is a malformed
/// request, and answering one as unconditional would turn a guard the caller
/// asked for into no guard at all.
fn read_condition(a: &[u8], p: &mut usize) -> Option<Condition> {
    use obj_op::precondition as pre;
    let kind = *a.get(*p)?;
    let etag_len = *a.get(*p + 1)? as usize;
    let etag = a.get(*p + 2..*p + 2 + etag_len)?;
    *p += 2 + etag_len;
    match kind {
        pre::ANY => Some(Condition::Any),
        pre::ABSENT => Some(Condition::Absent),
        pre::ETAG => Some(Condition::Revision(get_u64(etag, 0)?)),
        _ => None,
    }
}

impl Store {
    /// The in-use entry with the smallest key under `prefix` that sorts
    /// strictly after `after` (any key when `after` is `None`). The table is
    /// in slot order, not key order, so a listing selects its next entry
    /// by key each step.
    fn next_after(&self, prefix: &[u8], after: Option<&[u8]>) -> Option<usize> {
        let mut pick: Option<usize> = None;
        for (i, e) in self.entries.iter().enumerate() {
            let key = &e.key[..e.key_len as usize];
            if !e.in_use || !has_prefix(key, prefix) || after.is_some_and(|a| key <= a) {
                continue;
            }
            match pick {
                Some(j) if &self.entries[j].key[..self.entries[j].key_len as usize] <= key => {}
                _ => pick = Some(i),
            }
        }
        pick
    }
}

/// The `LIST` cursor as a key under `prefix`, or `EINVAL`: it is the last key
/// a page returned, so anything else was not issued here.
fn list_cursor<'a>(cursor: &'a [u8], prefix: &[u8]) -> Result<Option<&'a [u8]>, i32> {
    if cursor.is_empty() {
        Ok(None)
    } else if core::str::from_utf8(cursor).is_err() || !has_prefix(cursor, prefix) {
        Err(errno::EINVAL)
    } else {
        Ok(Some(cursor))
    }
}

/// A key a `PUT` may create: UTF-8, as every listed name is, and not empty,
/// which is the relist sentinel's key on the change stream and the "end of
/// listing" cursor on `LIST`.
fn writable_key(key: &[u8]) -> bool {
    !key.is_empty() && key.len() <= STORAGE_KEY_MAX && core::str::from_utf8(key).is_ok()
}

fn has_prefix(key: &[u8], prefix: &[u8]) -> bool {
    key.len() >= prefix.len() && &key[..prefix.len()] == prefix
}

/// Enable the store and register both contracts. Called from bcm2712 boot.
///
/// # Safety
/// Single-threaded startup, before any provider dispatch.
pub unsafe fn init() {
    use crate::kernel::module::provider;
    use crate::kernel::module::provider::contract as dev_class;
    ENABLED = true;
    provider::register(dev_class::STORAGE_OBJECT, dispatch_object);
    provider::register(dev_class::STORAGE_NAMESPACE, dispatch_namespace);
}

unsafe fn store_ref() -> Option<&'static mut Store> {
    if !ENABLED {
        return None;
    }
    Some(&mut *core::ptr::addr_of_mut!(STORE))
}

fn get_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn get_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn get_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn etag_from_rev(rev: u64) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..8].copy_from_slice(&rev.to_le_bytes());
    e
}

/// The `[fence_out_ptr:u64][fence_out_cap:u16]` pair at `off`, or `None` —
/// the op answers `EINVAL` before acting — when it is cut short, null, or
/// smaller than `WIRE_MAX_LEN`.
fn fence_out(a: &[u8], off: usize) -> Option<(u64, u16)> {
    let ptr = get_u64(a, off)?;
    let cap = get_u16(a, off + 8)?;
    (ptr != 0 && cap as usize >= WIRE_MAX_LEN).then_some((ptr, cap))
}

unsafe fn write_fence(fence: Fence, ptr: u64, cap: u16) {
    if ptr == 0 || cap == 0 {
        return;
    }
    let out = core::slice::from_raw_parts_mut(ptr as *mut u8, cap as usize);
    let _ = fence.encode(out);
}

/// Encode one change as a mesh Event carrying `namespace.change`. Byte-for-byte
/// what Linux emits — a consumer parses one encoding, not one per platform.
fn encode_event(seq: u32, rev: u64, kind: Kind, key: &[u8], val: &[u8], out: &mut [u8]) -> usize {
    let payload_len = 8 + 1 + 2 + 4 + key.len() + val.len();
    let total = EVENT_HEADER_SIZE + payload_len;
    if total > out.len() {
        return 0;
    }
    out[..total].fill(0);
    out[0..16].copy_from_slice(&STORE_SOURCE);
    out[16..20].copy_from_slice(&seq.to_le_bytes());
    out[28] = CT_NAMESPACE_CHANGE;
    out[29] = 0;
    out[30..32].copy_from_slice(&(payload_len as u16).to_le_bytes());
    let mut p = EVENT_HEADER_SIZE;
    out[p..p + 8].copy_from_slice(&rev.to_le_bytes());
    p += 8;
    out[p] = match kind {
        Kind::Added => 0,
        Kind::Modified => 1,
        Kind::Deleted => 2,
    };
    p += 1;
    out[p..p + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    p += 2;
    out[p..p + 4].copy_from_slice(&(val.len() as u32).to_le_bytes());
    p += 4;
    out[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    out[p..p + val.len()].copy_from_slice(val);
    total
}

/// Push every change each subscription has not yet seen onto its sink channel.
///
/// Called after every write, which is what makes a SUBSCRIBE a PUSH rather
/// than something the caller has to poll for.
///
/// # Safety
/// Single-threaded provider dispatch.
unsafe fn pump_subscriptions(store: &mut Store) {
    let subs = &mut *core::ptr::addr_of_mut!(SUBS);
    let floor = store.hist_floor();
    for s in subs.iter_mut() {
        if !s.in_use {
            continue;
        }
        if s.cursor < floor {
            // The watcher fell out of the retained window. Send the relist
            // sentinel — a Deleted with an EMPTY key — and resume from now.
            // Handing it the changes we still have would look like a complete
            // stream that silently skipped the ones we dropped.
            let mut buf = [0u8; EVENT_HEADER_SIZE + 16];
            let n = encode_event(
                s.sequence,
                store.revision,
                Kind::Deleted,
                &[],
                &[],
                &mut buf,
            );
            if n > 0 {
                let _ = channel_write(s.sink_chan as i32, buf.as_ptr(), n);
                s.sequence = s.sequence.wrapping_add(1);
            }
            s.cursor = store.revision;
            TLM_LOST = TLM_LOST.wrapping_add(1);
            continue;
        }
        // Walk the history in revision order. The ring is small and this runs
        // once per write, so a linear pass is cheaper than an index.
        loop {
            let mut pick: Option<usize> = None;
            for (i, h) in store.hist.iter().enumerate() {
                if h.revision <= s.cursor {
                    continue;
                }
                let key = &h.key[..h.key_len as usize];
                if !has_prefix(key, &s.prefix[..s.prefix_len as usize]) {
                    continue;
                }
                match pick {
                    Some(j) if store.hist[j].revision <= h.revision => {}
                    _ => pick = Some(i),
                }
            }
            let Some(i) = pick else { break };
            let h = store.hist[i];
            let mut buf = [0u8; EVENT_HEADER_SIZE + 16 + STORAGE_KEY_MAX + MAX_VALUE];
            let n = encode_event(
                s.sequence,
                h.revision,
                h.kind,
                &h.key[..h.key_len as usize],
                &h.val[..h.val_len as usize],
                &mut buf,
            );
            if n == 0 {
                break;
            }
            if channel_write(s.sink_chan as i32, buf.as_ptr(), n) <= 0 {
                TLM_BLOCKED = TLM_BLOCKED.wrapping_add(1);
                // The sink is full. Leave the cursor where it is and retry on
                // the next write: dropping the event would make the stream
                // lie, and advancing past it would lose it silently.
                break;
            }
            s.sequence = s.sequence.wrapping_add(1);
            s.cursor = h.revision;
            TLM_PUSHED = TLM_PUSHED.wrapping_add(1);
        }
    }
}

/// `storage.object` dispatch.
///
/// # Safety
/// Single-threaded platform dispatch; `arg` must be null or valid for
/// `arg_len` bytes.
pub unsafe fn dispatch_object(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(store) = store_ref() else {
        return errno::ENOSYS;
    };
    let a = if arg.is_null() {
        &[][..]
    } else {
        core::slice::from_raw_parts(arg, arg_len)
    };

    telemetry(store);
    match opcode {
        obj_op::PUT => {
            // [key_len:u16][key][ct_len:u8][ct][body_ptr:u64][body_len:u64]
            // [precondition:u8][etag_len:u8][etag][fence_out_ptr:u64][fence_out_cap:u16]
            let Some(kl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Some(key) = a.get(2..2 + kl) else {
                return errno::EINVAL;
            };
            if !writable_key(key) {
                return errno::EINVAL;
            }
            let mut p = 2 + kl;
            let Some(&ctl) = a.get(p) else {
                return errno::EINVAL;
            };
            p += 1 + ctl as usize;
            let Some(body_ptr) = get_u64(a, p) else {
                return errno::EINVAL;
            };
            let Some(body_len) = get_u64(a, p + 8) else {
                return errno::EINVAL;
            };
            p += 16;
            let Some(condition) = read_condition(a, &mut p) else {
                return errno::EINVAL;
            };
            let Some((fence_ptr, fence_cap)) = fence_out(a, p) else {
                return errno::EINVAL;
            };
            if body_len > MAX_VALUE as u64 {
                return errno::EINVAL;
            }

            let existing = store.get(key).map(|(_, r)| r);
            if condition.refuses(existing) {
                // `EEXIST`: somebody created this key, so a create-only caller
                // has LOST. `EAGAIN`: the key moved or is gone under a
                // compare-and-swap, so re-read and retry.
                return if condition == Condition::Absent {
                    errno::EEXIST
                } else {
                    errno::EAGAIN
                };
            }

            let body = if body_len == 0 {
                &[][..]
            } else {
                core::slice::from_raw_parts(body_ptr as *const u8, body_len as usize)
            };
            match store.put(key, body) {
                Ok(rev) => {
                    TLM_PUTS = TLM_PUTS.wrapping_add(1);
                    // RevisionMonotone, never LocalDurable: this store is RAM.
                    // Ordering holds; survival does not, and saying otherwise
                    // would let a caller conclude a write outlived a power cut.
                    write_fence(
                        Fence::RevisionMonotone {
                            source: STORE_SOURCE,
                            revision: rev,
                        },
                        fence_ptr,
                        fence_cap,
                    );
                    pump_subscriptions(store);
                    0
                }
                Err(e) => e,
            }
        }
        obj_op::GET => {
            let Some((val, rev)) = store.get(a) else {
                return errno::ENXIO;
            };
            let vlen = val.len();
            let reads = &mut *core::ptr::addr_of_mut!(READS);
            let Some(idx) = reads.iter().position(|r| !r.in_use) else {
                return errno::ENOMEM;
            };
            reads[idx].in_use = true;
            reads[idx].val_len = vlen as u16;
            reads[idx].val[..vlen].copy_from_slice(val);
            reads[idx].revision = rev;
            tag_fd(FD_TAG_STORAGE_OBJECT, idx as i32)
        }
        obj_op::RANGE_GET => {
            // [offset:u64][length:u32][out_ptr:u64]
            let idx = slot_of(handle) as usize;
            let reads = &*core::ptr::addr_of!(READS);
            if idx >= MAX_READS || !reads[idx].in_use {
                return errno::ENOSYS;
            }
            let Some(offset) = get_u64(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Some(length) = get_u32(a, 8).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Some(out_ptr) = get_u64(a, 12) else {
                return errno::EINVAL;
            };
            let val = &reads[idx].val[..reads[idx].val_len as usize];
            if offset >= val.len() {
                return 0;
            }
            let end = (offset + length).min(val.len());
            let n = end - offset;
            core::ptr::copy_nonoverlapping(val[offset..end].as_ptr(), out_ptr as *mut u8, n);
            n as i32
        }
        obj_op::HEAD => {
            // [key_len:u16][key][out_ptr:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]
            let Some(kl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            if a.len() < 2 + kl {
                return errno::EINVAL;
            }
            let Some((fptr, fcap)) = fence_out(a, 2 + kl + 12) else {
                return errno::EINVAL;
            };
            let Some((val, rev)) = store.get(&a[2..2 + kl]) else {
                return errno::ENXIO;
            };
            let vlen = val.len();
            let out_ptr = get_u64(a, 2 + kl).unwrap_or(0);
            let out_cap = get_u32(a, 2 + kl + 8).unwrap_or(0) as usize;
            // [size:u64][mtime:u64][ct_len:u8][ct][etag_len:u8][etag]
            let mut rec = [0u8; 8 + 8 + 1 + 1 + 32];
            rec[0..8].copy_from_slice(&(vlen as u64).to_le_bytes());
            rec[17] = 32;
            rec[18..50].copy_from_slice(&etag_from_rev(rev));
            // The count returned is the count written: a record that does not
            // fit is refused, not reported as delivered.
            if out_ptr == 0 {
                return errno::EINVAL;
            }
            if rec.len() > out_cap {
                return errno::ENOMEM;
            }
            core::ptr::copy_nonoverlapping(rec.as_ptr(), out_ptr as *mut u8, rec.len());
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: store.revision,
                },
                fptr,
                fcap,
            );
            rec.len() as i32
        }
        obj_op::DELETE => {
            // [key_len:u16][key][precondition:u8][etag_len:u8][etag]
            // [fence_ptr:u64][fence_cap:u16]
            let Some(kl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Some(key) = a.get(2..2 + kl) else {
                return errno::EINVAL;
            };
            let mut p = 2 + kl;
            let Some(condition) = read_condition(a, &mut p) else {
                return errno::EINVAL;
            };
            let Some((fptr, fcap)) = fence_out(a, p) else {
                return errno::EINVAL;
            };
            if condition.refuses(store.get(key).map(|(_, r)| r)) {
                return errno::EAGAIN;
            }
            let rev = store.delete(key).unwrap_or(store.revision);
            TLM_DELS = TLM_DELS.wrapping_add(1);
            write_fence(
                Fence::RevisionMonotone {
                    source: STORE_SOURCE,
                    revision: rev,
                },
                fptr,
                fcap,
            );
            pump_subscriptions(store);
            0
        }
        obj_op::LIST => {
            TLM_LISTS = TLM_LISTS.wrapping_add(1);
            let Some(req) = obj_op::list::parse_request(a) else {
                return errno::EINVAL;
            };
            let after = match list_cursor(req.cursor, req.prefix) {
                Ok(after) => after,
                Err(e) => return e,
            };
            let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
            let mut page = obj_op::list::PageWriter::new(out, req.max_keys);
            // Bounded by `max_keys` steps of one `MAX_OBJECTS` pass each.
            let mut last = [0u8; STORAGE_KEY_MAX];
            let mut last_len = 0usize;
            let mut more = false;
            while let Some(i) = store.next_after(
                req.prefix,
                if last_len > 0 {
                    Some(&last[..last_len])
                } else {
                    after
                },
            ) {
                if page.is_full() {
                    more = true;
                    break;
                }
                let e = &store.entries[i];
                let key = &e.key[..e.key_len as usize];
                // mtime 0, as HEAD reports it: the store keeps no clock.
                if !page.push(key, e.val_len as u64, 0, &etag_from_rev(e.revision)) {
                    more = true;
                    break;
                }
                last_len = key.len();
                last[..last_len].copy_from_slice(key);
            }
            let cursor: &[u8] = if !more {
                &[]
            } else if page.count() == 0 {
                // A page that cannot hold the next entry made no progress.
                return errno::ENOMEM;
            } else {
                &last[..last_len]
            };
            let Some(n) = page.finish(cursor) else {
                return errno::ENOMEM;
            };
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: store.revision,
                },
                req.fence_out_ptr,
                req.fence_out_cap,
            );
            n as i32
        }
        obj_op::CLOSE => {
            let idx = slot_of(handle) as usize;
            let reads = &mut *core::ptr::addr_of_mut!(READS);
            if idx < MAX_READS {
                reads[idx] = READ_EMPTY;
            }
            0
        }
        _ => errno::ENOSYS,
    }
}

/// `storage.namespace` dispatch.
///
/// # Safety
/// Single-threaded platform dispatch; `arg` must be null or valid for
/// `arg_len` bytes.
pub unsafe fn dispatch_namespace(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(store) = store_ref() else {
        return errno::ENOSYS;
    };
    let a = if arg.is_null() {
        &[][..]
    } else {
        core::slice::from_raw_parts(arg, arg_len)
    };

    telemetry(store);
    match opcode {
        ns_op::CAPS => (ns_op::caps::SUBSCRIBE | ns_op::caps::CHANGES) as i32,
        ns_op::LIST => {
            TLM_LISTS = TLM_LISTS.wrapping_add(1);
            let Some(req) = ns_op::list::parse_request(a) else {
                return errno::EINVAL;
            };
            let after = match list_cursor(req.cursor, req.prefix) {
                Ok(after) => after,
                Err(e) => return e,
            };
            let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
            let mut page = ns_op::list::PageWriter::new(out);
            let mut last = [0u8; STORAGE_KEY_MAX];
            let mut last_len = 0usize;
            let mut more = false;
            while let Some(i) = store.next_after(
                req.prefix,
                if last_len > 0 {
                    Some(&last[..last_len])
                } else {
                    after
                },
            ) {
                let e = &store.entries[i];
                let key = &e.key[..e.key_len as usize];
                if !page.push(key, ns_op::KIND_OBJECT) {
                    more = true;
                    break;
                }
                last_len = key.len();
                last[..last_len].copy_from_slice(key);
            }
            let cursor: &[u8] = if !more {
                &[]
            } else if page.count() == 0 {
                // A page that cannot hold the next entry made no progress.
                return errno::ENOMEM;
            } else {
                &last[..last_len]
            };
            let Some(n) = page.finish(cursor) else {
                return errno::ENOMEM;
            };
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: store.revision,
                },
                req.fence_out_ptr,
                req.fence_out_cap,
            );
            n as i32
        }
        ns_op::SUBSCRIBE => {
            // [prefix_len:u16][prefix][sink_chan:u32][flags:u8]
            let Some(pl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            if a.len() < 2 + pl || pl > STORAGE_KEY_MAX {
                return errno::EINVAL;
            }
            let Some(sink_chan) = get_u32(a, 2 + pl) else {
                return errno::EINVAL;
            };
            let flags = *a.get(2 + pl + 4).unwrap_or(&0);
            let include_initial = flags & 0x01 != 0;

            let subs = &mut *core::ptr::addr_of_mut!(SUBS);
            let Some(idx) = subs.iter().position(|s| !s.in_use) else {
                return errno::ENOMEM;
            };
            subs[idx] = SUB_EMPTY;
            subs[idx].in_use = true;
            subs[idx].prefix_len = pl as u16;
            subs[idx].prefix[..pl].copy_from_slice(&a[2..2 + pl]);
            subs[idx].sink_chan = sink_chan;
            subs[idx].cursor = store.revision;

            if include_initial {
                // Synthesise Added for every current entry, so the stream is a
                // complete list-then-watch with no separate GET and no window
                // between the two where a change could be missed.
                for e in store.entries.iter() {
                    if !e.in_use
                        || !has_prefix(&e.key[..e.key_len as usize], &subs[idx].prefix[..pl])
                    {
                        continue;
                    }
                    let mut buf = [0u8; EVENT_HEADER_SIZE + 16 + STORAGE_KEY_MAX + MAX_VALUE];
                    let n = encode_event(
                        subs[idx].sequence,
                        e.revision,
                        Kind::Added,
                        &e.key[..e.key_len as usize],
                        &e.val[..e.val_len as usize],
                        &mut buf,
                    );
                    if n == 0 || channel_write(sink_chan as i32, buf.as_ptr(), n) <= 0 {
                        // The snapshot could not be delivered whole. Release
                        // the slot and refuse: a watcher established on a
                        // partial list believes it has seen the full state,
                        // and nothing later in the stream corrects it.
                        subs[idx] = SUB_EMPTY;
                        return errno::EAGAIN;
                    }
                    subs[idx].sequence = subs[idx].sequence.wrapping_add(1);
                }
            }
            tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32)
        }
        ns_op::CHANGES => {
            // [prefix_len:u16][prefix][since:u64][out_buf:u64][out_cap:u32]
            // [fence_ptr:u64][fence_cap:u16]
            let Some(pl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            if a.len() < 2 + pl {
                return errno::EINVAL;
            }
            let prefix = &a[2..2 + pl];
            let mut p = 2 + pl;
            let since = get_u64(a, p).unwrap_or(0);
            p += 8;
            let out_buf = get_u64(a, p).unwrap_or(0);
            let out_cap = get_u32(a, p + 8).unwrap_or(0) as usize;
            let fptr = get_u64(a, p + 12).unwrap_or(0);
            let fcap = get_u16(a, p + 20).unwrap_or(0);

            let mut body = [0u8; 8192];
            let mut bo = 0usize;
            let mut count: u32 = 0;
            let mut status: u8 = 0;
            let mut fence_rev = since;

            // [rev:u64][kind:u8][key_len:u16][val_len:u32][key][val]
            let mut push = |bo: &mut usize, rev: u64, kind: u8, key: &[u8], val: &[u8]| -> bool {
                let need = 8 + 1 + 2 + 4 + key.len() + val.len();
                if *bo + need > body.len() {
                    return false;
                }
                body[*bo..*bo + 8].copy_from_slice(&rev.to_le_bytes());
                body[*bo + 8] = kind;
                body[*bo + 9..*bo + 11].copy_from_slice(&(key.len() as u16).to_le_bytes());
                body[*bo + 11..*bo + 15].copy_from_slice(&(val.len() as u32).to_le_bytes());
                body[*bo + 15..*bo + 15 + key.len()].copy_from_slice(key);
                body[*bo + 15 + key.len()..*bo + need].copy_from_slice(val);
                *bo += need;
                true
            };

            if since == 0 {
                fence_rev = store.revision;
                for e in store.entries.iter() {
                    if !e.in_use || !has_prefix(&e.key[..e.key_len as usize], prefix) {
                        continue;
                    }
                    if !push(
                        &mut bo,
                        e.revision,
                        0,
                        &e.key[..e.key_len as usize],
                        &e.val[..e.val_len as usize],
                    ) {
                        // The snapshot does not fit. Refused, as Linux
                        // refuses an over-cap answer: a short list handed
                        // back with `status = 0` reads as the complete
                        // state, and the caller cannot tell it is not.
                        return errno::ENOMEM;
                    }
                    count += 1;
                }
            } else if since < store.hist_floor() {
                // Out of the retained window: say so rather than serve a
                // partial history that reads as complete.
                status = 1;
                fence_rev = store.revision;
            } else {
                // Walk the retained history in ASCENDING revision order from
                // `since`. The ring is small (HISTORY entries) and this is a
                // request-time op, so a select-min pass per event is cheaper
                // than maintaining an index — and it does not depend on the
                // ring's physical order, which wraps.
                let mut cursor = since;
                loop {
                    let mut pick: Option<usize> = None;
                    for (i, h) in store.hist.iter().enumerate() {
                        if h.revision <= cursor {
                            continue;
                        }
                        if !has_prefix(&h.key[..h.key_len as usize], prefix) {
                            continue;
                        }
                        match pick {
                            Some(j) if store.hist[j].revision <= h.revision => {}
                            _ => pick = Some(i),
                        }
                    }
                    let Some(i) = pick else { break };
                    let h = store.hist[i];
                    let kind = match h.kind {
                        Kind::Added => 0u8,
                        Kind::Modified => 1u8,
                        Kind::Deleted => 2u8,
                    };
                    if !push(
                        &mut bo,
                        h.revision,
                        kind,
                        &h.key[..h.key_len as usize],
                        &h.val[..h.val_len as usize],
                    ) {
                        return errno::ENOMEM;
                    }
                    count += 1;
                    if h.revision > fence_rev {
                        fence_rev = h.revision;
                    }
                    cursor = h.revision;
                }
            }

            let total = 5 + bo;
            if out_buf != 0 {
                if total > out_cap {
                    return errno::ENOMEM;
                }
                let out = core::slice::from_raw_parts_mut(out_buf as *mut u8, total);
                out[0] = status;
                out[1..5].copy_from_slice(&count.to_le_bytes());
                out[5..total].copy_from_slice(&body[..bo]);
            }
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: fence_rev,
                },
                fptr,
                fcap,
            );
            total as i32
        }
        ns_op::LOOKUP | ns_op::STAT => errno::ENOSYS,
        ns_op::CLOSE => {
            let idx = slot_of(handle) as usize;
            let subs = &mut *core::ptr::addr_of_mut!(SUBS);
            if idx < MAX_SUBS {
                subs[idx] = SUB_EMPTY;
            }
            0
        }
        _ => errno::ENOSYS,
    }
}

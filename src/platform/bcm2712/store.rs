//! Versioned watchable key store for bare metal — the `storage.object` (0x14)
//! and `storage.namespace` (0x13) contracts on BCM2712.
//!
//! A store-backed graph needs both: every source in one SUBSCRIBEs a prefix and
//! every effect PUTs a key, so a board without these contracts runs the graph
//! and produces nothing.
//!
//! Same semantics as `platform/linux/store.rs` — monotone revision clock,
//! per-key revision as the CAS token, prefix enumeration with a paged cursor,
//! a bounded key-only change history that pages `CHANGES` from a revision, and
//! SUBSCRIBE as a doorbell on the subscriber's own kernel event (no bytes are
//! ever written to a consumer's channel) — and deliberately the same WIRE,
//! because a consumer parses one encoding
//! whichever platform answers it. What differs is the backing: no `alloc` here,
//! so the store's tables are fixed-capacity — sized once at boot from the plan
//! and carved from DRAM (`kernel::mem::carve`) — rather than a `BTreeMap`, and
//! those capacities are the honest ceiling on what a bare-metal store can
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
use crate::kernel::ipc::event::{event_owner, event_signal};
use crate::kernel::ipc::fd::{
    slot_of, tag_fd, untag_fd, FD_TAG_EVENT, FD_TAG_STORAGE_NAMESPACE, FD_TAG_STORAGE_OBJECT,
};
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::{OwnerHandle, OWNER_SYSTEM};

/// Objects the store can hold — one machine's worth of state, not a fleet's.
/// No pool names them, so this is their size; the table is carved at boot
/// ([`size_from_plan`]) rather than linked into `.bss`. Exceeding it is
/// refused (`ENOMEM`) rather than evicting: a consumer reads a missing key as
/// a deletion, so silently evicting is how it comes to tear down what that
/// key named.
pub const MAX_OBJECTS: usize = 512;
/// Longest value. Matches `store_effect`'s own `MAX_VALUE`, so a value that
/// crosses the connector fits the store that holds it.
pub const MAX_VALUE: usize = 4096;
/// Retained change history, in revisions. A `CHANGES` reader that falls
/// further behind than this is answered LOST — relist — rather than handed a
/// gap.
pub const HISTORY: usize = 128;

use crate::abi::contracts::resource as res;

/// The ceiling the boot plan gives `pool` (`resource_ledger::plan`): for the
/// store's subscriptions, what the graph's store consumers declare plus the
/// reserve (a control plane of ~45 reconcilers asks ~95); for its open read
/// slots, the envelope entry or the profile's default. A refused subscription
/// or read is counted against its pool and answers ENOMEM.
fn plan_ceiling(pool: u16) -> usize {
    crate::kernel::sys::resource_ledger::ceiling(pool) as usize
}

/// Refuse a slot past a table's ceiling: count it against `pool` and name it,
/// since a silently refused watch is a controller that silently stops.
fn refuse_slot(pool: u16, len: usize) -> i32 {
    log::warn!(
        "[store] pool '{}' at its ceiling of {len} slots; refused",
        crate::kernel::sys::resource_ledger::pool_name(pool)
    );
    crate::kernel::sys::resource_ledger::deny(pool);
    errno::ENOMEM
}

/// Slots in use in `pool`'s table: the resource ledger's sample for the
/// store's subscription and read pools, 0 for any other.
pub fn pool_in_use(pool: u16) -> usize {
    // SAFETY: a read-only walk on the scheduler core.
    unsafe {
        match pool {
            res::POOL_STORE_SUBS => (*core::ptr::addr_of!(SUBS))
                .iter()
                .filter(|s| s.in_use)
                .count(),
            res::POOL_STORE_READS => (*core::ptr::addr_of!(READS))
                .iter()
                .filter(|r| r.in_use)
                .count(),
            _ => 0,
        }
    }
}

/// The fence source id. Byte-identical to Linux's: a consumer that matches on
/// it must not have to know which platform answered.
const STORE_SOURCE: [u8; 16] = *b"fluxor-cp-store\0";

/// What a history entry did to its key — the advisory hint that labels a
/// `CHANGES` record `Added` rather than `Modified`. A record's own kind is
/// read from the key's current state, never from this.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Added,
    Modified,
    Deleted,
}

/// First byte of a relist continuation token,
/// `[CONT_RELIST][pinned revision u64][key cursor]`. Never 8 bytes long (a
/// key is never empty), so it cannot be mistaken for a bare revision.
const CONT_RELIST: u8 = b'R';
/// The longest relist continuation: the tag, the pinned revision and a key.
const RELIST_TOKEN_MAX: usize = 1 + 8 + STORAGE_KEY_MAX;

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

/// One history entry: the key a revision changed, and how. Key-only — a
/// `CHANGES` record carries the key's value at the store's current state,
/// so the history never holds a value.
#[derive(Clone, Copy)]
struct HistEntry {
    revision: u64,
    kind: Kind,
    key: [u8; STORAGE_KEY_MAX],
    key_len: u16,
}

const HIST_EMPTY: HistEntry = HistEntry {
    revision: 0,
    kind: Kind::Added,
    key: [0; STORAGE_KEY_MAX],
    key_len: 0,
};

/// One subscription: a prefix, the subscriber's kernel event, and its rung
/// bit — a doorbell, with nothing queued behind it.
#[derive(Clone, Copy)]
struct Sub {
    in_use: bool,
    prefix: [u8; STORAGE_KEY_MAX],
    prefix_len: u16,
    /// The subscriber's event, as a raw event slot.
    event: i32,
    /// Set when a change under the prefix signalled the event; cleared by
    /// the subscriber's `TAKE_RUNG`. While set, further changes do nothing.
    rung: bool,
    /// The owner that subscribed, which the slot goes with.
    opener: OwnerHandle,
    /// The subscribing module occupancy — slot index and slot generation.
    /// The subscription lives exactly as long as that occupancy does and
    /// that module owns `event`; checked before every signal.
    module: u16,
    generation: u32,
}

const SUB_EMPTY: Sub = Sub {
    in_use: false,
    prefix: [0; STORAGE_KEY_MAX],
    prefix_len: 0,
    event: -1,
    rung: false,
    opener: OWNER_SYSTEM,
    module: 0,
    generation: 0,
};

#[derive(Clone, Copy)]
struct ReadSlot {
    in_use: bool,
    val: [u8; MAX_VALUE],
    val_len: u16,
    revision: u64,
    /// The owner that opened the slot, which it goes with.
    opener: OwnerHandle,
}

const READ_EMPTY: ReadSlot = ReadSlot {
    in_use: false,
    val: [0; MAX_VALUE],
    val_len: 0,
    revision: 0,
    opener: OWNER_SYSTEM,
};

/// The store itself. Its object table is sized once, at boot, and carved
/// (bare metal has no heap): the capacity is a decision made once rather than
/// a growth curve.
pub struct Store {
    entries: crate::kernel::mem::table::Table<Entry, MAX_OBJECTS>,
    /// One entry per revision: every revision this store issues changes
    /// exactly one key, so revision `r` lives at `hist[(r - 1) % HISTORY]`
    /// while it is among the last [`HISTORY`].
    hist: [HistEntry; HISTORY],
    revision: u64,
}

fn objects_default() -> usize {
    MAX_OBJECTS
}

static mut STORE: Store = Store {
    entries: crate::kernel::mem::table::Table::new_planned(|_| ENTRY_EMPTY, objects_default),
    hist: [HIST_EMPTY; HISTORY],
    revision: 0,
};
/// Subscriptions and open read slots, sized at boot from the plan
/// ([`size_from_plan`]; the plan's defaults on first use).
static mut SUBS: crate::kernel::mem::table::Table<Sub, 0> =
    crate::kernel::mem::table::Table::new_planned(|_| SUB_EMPTY, subs_default);
static mut READS: crate::kernel::mem::table::Table<ReadSlot, 0> =
    crate::kernel::mem::table::Table::new_planned(|_| READ_EMPTY, reads_default);

fn subs_default() -> usize {
    plan_ceiling(res::POOL_STORE_SUBS)
}

fn reads_default() -> usize {
    plan_ceiling(res::POOL_STORE_READS)
}

/// Size the store's tables to the boot plan's ceilings: subscriptions and read
/// slots from their pools, objects to [`MAX_OBJECTS`]. Slots in use keep their
/// place (a handle names a slot index). Called when a graph is prepared,
/// after the plan, as `platform::linux::store::size_from_plan` is.
///
/// # Safety
/// Graph-preparation context on the scheduler core: no reference into the
/// tables is live.
pub unsafe fn size_from_plan() -> Result<(), crate::kernel::mem::table::TableError> {
    let subs = &*core::ptr::addr_of!(SUBS);
    subs.reserve(plan_ceiling(res::POOL_STORE_SUBS))?;
    subs.grow(plan_ceiling(res::POOL_STORE_SUBS))?;
    let reads = &*core::ptr::addr_of!(READS);
    reads.reserve(plan_ceiling(res::POOL_STORE_READS))?;
    reads.grow(plan_ceiling(res::POOL_STORE_READS))?;
    let objects = &(*core::ptr::addr_of!(STORE)).entries;
    objects.reserve(MAX_OBJECTS)?;
    objects.grow(MAX_OBJECTS)
}
static mut ENABLED: bool = false;

/// Provider telemetry. A store's failures are otherwise only guessable from
/// the outside: a watcher that saw nothing looks the same whether no change
/// happened or every change was dropped. Emitted on a slow cadence over the
/// same log path everything else uses, so the rig's capture carries it.
static mut TLM_PUTS: u32 = 0;
static mut TLM_DELS: u32 = 0;
static mut TLM_LISTS: u32 = 0;
static mut TLM_RUNG: u32 = 0;
static mut TLM_DROPPED: u32 = 0;
static mut TLM_LOST: u32 = 0;
static mut TLM_TICK: u32 = 0;

/// `[store] objs=.. rev=.. subs=.. put=.. del=.. list=.. ring=.. drop=.. lost=..`
///
/// `ring` counts doorbells signalled; `drop` counts subscriptions dropped at a
/// signal because their module occupancy ended or their event slot is no
/// longer that module's. A watcher that saw nothing with `ring` climbing was
/// told and did not read; with `drop` climbing it was never there to tell.
/// `lost` counts `CHANGES` reads answered LOST (behind the history).
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
    lit!(b" ring=");
    num!(TLM_RUNG);
    lit!(b" drop=");
    num!(TLM_DROPPED);
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

    /// Record revision `revision`'s change in the bounded history, over the
    /// revision [`HISTORY`] before it. A reader behind the window is told to
    /// relist rather than handed a gap, which is why the window's base is
    /// computed rather than assumed.
    fn push_hist(&mut self, revision: u64, kind: Kind, key: &[u8]) {
        let h = &mut self.hist[(revision - 1) as usize % HISTORY];
        h.revision = revision;
        h.kind = kind;
        h.key_len = key.len().min(STORAGE_KEY_MAX) as u16;
        h.key[..h.key_len as usize].copy_from_slice(&key[..h.key_len as usize]);
    }

    /// The history's base: every revision after it, up to the current one,
    /// is still retained. A `since` below it cannot be answered.
    fn hist_base(&self) -> u64 {
        self.revision.saturating_sub(HISTORY as u64)
    }

    /// The history entry for revision `rev`, while it is retained.
    fn hist_at(&self, rev: u64) -> Option<&HistEntry> {
        (rev > self.hist_base() && rev <= self.revision)
            .then(|| &self.hist[(rev - 1) as usize % HISTORY])
    }

    /// The revision of `key`'s latest retained history entry in `(after,
    /// upto]` — its last change in that span — and, when `first` is set, its
    /// earliest one instead.
    fn hist_find(&self, key: &[u8], after: u64, upto: u64, first: bool) -> Option<&HistEntry> {
        let lo = after.max(self.hist_base()) + 1;
        let mut found = None;
        for rev in lo..=upto.min(self.revision) {
            let h = self.hist_at(rev)?;
            if &h.key[..h.key_len as usize] == key {
                found = Some(h);
                if first {
                    break;
                }
            }
        }
        found
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
                self.push_hist(rev, Kind::Modified, key);
            }
            None => {
                let Some(i) = self.entries.iter().position(|e| !e.in_use) else {
                    // Undo the revision bump: nothing happened, and a clock
                    // that moved for a write that did not land leaves a
                    // revision with no history entry, and the history is
                    // addressed by revision.
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
                self.push_hist(rev, Kind::Added, key);
            }
        }
        Ok(rev)
    }

    fn delete(&mut self, key: &[u8]) -> Option<u64> {
        let i = self.find(key)?;
        self.revision += 1;
        let rev = self.revision;
        self.entries[i] = ENTRY_EMPTY;
        self.push_hist(rev, Kind::Deleted, key);
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
/// which is the "end of listing" cursor on `LIST` — and what keeps a relist
/// continuation token from ever being 8 bytes long.
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

/// Whether the caller acts with the node's authority. The store is one fixed
/// table with one history and one revision clock: a workload sharing it
/// could fill the table, flood the history the node's watchers read, and
/// read the rate of other owners' writes off the clock, so it is the node's
/// alone — the node's own modules and an owner acting with its authority. A
/// workload on this board keeps its objects in a store provider of its own,
/// over a volume lent to it.
fn node_caller() -> bool {
    !crate::kernel::workload::storage::rooted(crate::kernel::exec::scheduler::caller_owner())
}

/// Whether a slot is open and the caller opened it: a slot answers its
/// opener alone.
fn opened_by_caller(in_use: bool, opener: OwnerHandle) -> bool {
    in_use && opener == crate::kernel::exec::scheduler::caller_owner()
}

/// The calling module occupancy, `(slot index, slot generation)`, or `None`
/// in kernel context. This store is a kernel provider: its dispatch runs in
/// no provider frame, so the module making the call is the one the scheduler
/// is stepping — the same module [`caller_owner`] reads and `event::CREATE`
/// stamps an event with.
///
/// [`caller_owner`]: crate::kernel::exec::scheduler::caller_owner
fn caller_occupancy() -> Option<(u16, u32)> {
    use crate::kernel::exec::scheduler as sched;
    let idx = sched::current_module_index();
    (idx < sched::module_slots()).then(|| (idx as u16, sched::module_slot_generation(idx)))
}

/// The raw event slot a tagged event fd names, or `None` when `fd` is not
/// one.
fn event_slot(fd: i32) -> Option<i32> {
    let (tag, slot) = untag_fd(fd);
    (fd >= 0 && tag == FD_TAG_EVENT).then_some(slot)
}

/// Close every handle `opener` holds on the store: its `GET` reads and its
/// subscriptions. Part of the owner-release hook, for an owner that acted
/// with the node's authority: what it opened goes with it.
///
/// # Safety
/// Single-threaded platform dispatch only.
pub unsafe fn release_opener(opener: OwnerHandle) {
    for r in (*core::ptr::addr_of_mut!(READS))
        .iter_mut()
        .filter(|r| r.in_use && r.opener == opener)
    {
        *r = READ_EMPTY;
    }
    for s in (*core::ptr::addr_of_mut!(SUBS))
        .iter_mut()
        .filter(|s| s.in_use && s.opener == opener)
    {
        *s = SUB_EMPTY;
    }
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

/// Whether subscription `s` may still be signalled: its module occupancy is
/// live — the slot holds the same generation and its module has not finished
/// — and its event slot is still that module's. A module that was freed,
/// restarted, reassigned or finished, or that destroyed its event (whose slot
/// another module's `CREATE` may now hold), fails it, and a stranger is never
/// woken for it.
fn sub_live(s: &Sub) -> bool {
    use crate::kernel::exec::scheduler as sched;
    let idx = s.module as usize;
    idx < sched::module_slots()
        && sched::module_slot_generation(idx) == s.generation
        && !sched::module_is_finished(idx)
        && event_owner(s.event) == Some(s.module)
}

/// Drop subscription `s`: its subscriber is gone, so nothing will read it.
fn drop_sub(s: &mut Sub) {
    *s = SUB_EMPTY;
    // SAFETY: single-threaded provider dispatch.
    unsafe { TLM_DROPPED = TLM_DROPPED.wrapping_add(1) };
}

/// Signal `s`'s event, after checking it is still the subscriber's to
/// signal ([`sub_live`]); a dead subscription, or one whose signal answers
/// that the event is gone, is dropped instead. Every signal this store sends
/// goes through here.
fn signal(s: &mut Sub) -> bool {
    if !sub_live(s) || event_signal(s.event) < 0 {
        drop_sub(s);
        return false;
    }
    // SAFETY: single-threaded provider dispatch.
    unsafe { TLM_RUNG = TLM_RUNG.wrapping_add(1) };
    true
}

/// Ring `s`: a change under its prefix. A clear rung bit is set and the event
/// signalled; a set one means the subscriber has a `TAKE_RUNG` still to come,
/// which will see this change's subscription anyway, so nothing more is sent.
fn ring(s: &mut Sub) {
    if !s.rung && signal(s) {
        s.rung = true;
    }
}

/// Ring every subscription whose prefix `key` falls under. Called after every
/// write that moved the revision, which is what makes a SUBSCRIBE a doorbell
/// rather than something the caller has to poll.
///
/// # Safety
/// Single-threaded provider dispatch.
unsafe fn notify(key: &[u8]) {
    for s in (*core::ptr::addr_of_mut!(SUBS)).iter_mut() {
        if s.in_use && has_prefix(key, &s.prefix[..s.prefix_len as usize]) {
            ring(s);
        }
    }
}

/// Drop every subscription that can no longer be signalled. Run before a
/// SUBSCRIBE is refused at capacity: a dead stamp must not hold a slot a
/// live module is asking for.
///
/// # Safety
/// Single-threaded provider dispatch.
unsafe fn reap_dead_subs() {
    for s in (*core::ptr::addr_of_mut!(SUBS)).iter_mut() {
        if s.in_use && !sub_live(s) {
            drop_sub(s);
        }
    }
}

/// `storage.object` dispatch.
///
/// # Safety
/// Single-threaded platform dispatch; `arg` must be null or valid for
/// `arg_len` bytes.
pub unsafe fn dispatch_object(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    if !node_caller() {
        return errno::EACCES;
    }
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
                    notify(key);
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
                return refuse_slot(res::POOL_STORE_READS, reads.len());
            };
            reads[idx].in_use = true;
            reads[idx].opener = crate::kernel::exec::scheduler::caller_owner();
            reads[idx].val_len = vlen as u16;
            reads[idx].val[..vlen].copy_from_slice(val);
            reads[idx].revision = rev;
            tag_fd(FD_TAG_STORAGE_OBJECT, idx as i32)
        }
        obj_op::RANGE_GET => {
            // [offset:u64][length:u32][out_ptr:u64]
            let idx = slot_of(handle) as usize;
            let reads = &*core::ptr::addr_of!(READS);
            if handle < 0
                || idx >= reads.len()
                || !opened_by_caller(reads[idx].in_use, reads[idx].opener)
            {
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
            let deleted = store.delete(key);
            let rev = deleted.unwrap_or(store.revision);
            TLM_DELS = TLM_DELS.wrapping_add(1);
            write_fence(
                Fence::RevisionMonotone {
                    source: STORE_SOURCE,
                    revision: rev,
                },
                fptr,
                fcap,
            );
            // Deleting an absent key moved nothing, so there is nothing to
            // ring for.
            if deleted.is_some() {
                notify(key);
            }
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
            // Bounded by `max_keys` steps of one object-table pass each.
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
            if handle >= 0
                && idx < reads.len()
                && opened_by_caller(reads[idx].in_use, reads[idx].opener)
            {
                reads[idx] = READ_EMPTY;
            }
            0
        }
        _ => errno::ENOSYS,
    }
}

/// One `CHANGES` page for `prefix` from `token` into `out`: its byte count,
/// or a negative errno. Tokens, per the contract:
///
///   - empty: a relist, pinned at the current revision;
///   - 8 bytes: the changes after a revision, walked from the history;
///   - `[CONT_RELIST][pinned revision u64][key cursor]`: a relist's next page.
///
/// A revision walk issues no continuation of its own. Every revision here
/// changes exactly one key, so a page always ends on a revision boundary and
/// the bare revision it ends at is where the next page resumes. A walk is
/// bounded by the history — at most [`HISTORY`] revisions — and a relist page
/// by `out`.
///
/// # Safety
/// Single-threaded provider dispatch.
unsafe fn changes_page(store: &Store, prefix: &[u8], token: &[u8], out: &mut [u8]) -> i32 {
    use ns_op::changes::token_revision;
    if token.is_empty() {
        return relist_page(store, prefix, store.revision, None, out);
    }
    if let Some(since) = token_revision(token) {
        return since_page(store, prefix, since, out);
    }
    let Some((&CONT_RELIST, rest)) = token.split_first() else {
        return errno::EINVAL;
    };
    let (Some(pinned), Some(cursor)) = (get_u64(rest, 0), rest.get(8..)) else {
        return errno::EINVAL;
    };
    let Ok(Some(after)) = list_cursor(cursor, prefix) else {
        return errno::EINVAL;
    };
    if pinned > store.revision {
        // Pinned past anything this store has issued: a token from before a
        // reboot emptied it. Nothing it names can be continued.
        return lost_page(out);
    }
    relist_page(store, prefix, pinned, Some(after), out)
}

/// A LOST page: the caller's point precedes what this store can answer.
///
/// # Safety
/// Single-threaded provider dispatch.
unsafe fn lost_page(out: &mut [u8]) -> i32 {
    TLM_LOST = TLM_LOST.wrapping_add(1);
    match ns_op::changes::write_lost(out) {
        Some(n) => n as i32,
        None => errno::ENOMEM,
    }
}

/// One relist page: every object under `prefix` after `after`, in key order,
/// `Added` with its value. `pinned` is the revision the relist's first page
/// stood at; the final page hands it back as the token the consumer resumes
/// `CHANGES` from.
///
/// An object written after `pinned` is left out: the `CHANGES` from `pinned`
/// that follows the relist reports it, and reporting it here would hand the
/// consumer a `mod_rev` ahead of where it resumes. No revision is delivered
/// whole until the walk ends, so a page with `more` set says `safe_rev = 0`.
fn relist_page(
    store: &Store,
    prefix: &[u8],
    pinned: u64,
    after: Option<&[u8]>,
    out: &mut [u8],
) -> i32 {
    use ns_op::changes::{revision_token, PageWriter, KIND_ADDED};
    let Some(mut page) = PageWriter::new(out, RELIST_TOKEN_MAX) else {
        return errno::ENOMEM;
    };
    let mut last = [0u8; STORAGE_KEY_MAX];
    let mut last_len = 0usize;
    let mut more = false;
    // Bounded by one object-table pass per object under the prefix.
    while let Some(i) = store.next_after(
        prefix,
        if last_len > 0 {
            Some(&last[..last_len])
        } else {
            after
        },
    ) {
        let e = &store.entries[i];
        let key = &e.key[..e.key_len as usize];
        if e.revision <= pinned
            && !page.push(e.revision, KIND_ADDED, key, &e.val[..e.val_len as usize])
        {
            more = true;
            break;
        }
        last_len = key.len();
        last[..last_len].copy_from_slice(key);
    }
    let finished = if !more {
        page.finish(false, pinned, &revision_token(pinned))
    } else if page.count() == 0 {
        // A page that cannot hold the next record made no progress.
        return errno::ENOMEM;
    } else {
        let mut token = [0u8; RELIST_TOKEN_MAX];
        token[0] = CONT_RELIST;
        token[1..9].copy_from_slice(&pinned.to_le_bytes());
        token[9..9 + last_len].copy_from_slice(&last[..last_len]);
        page.finish(true, 0, &token[..9 + last_len])
    };
    finished.map_or(errno::ENOMEM, |n| n as i32)
}

/// One page of the changes after revision `since`, walked from the history
/// in revision order up to the current revision.
///
/// Each changed key under `prefix` is reported once, at its latest revision,
/// read at the store's current state: present → `Added` (when its first
/// change after `since` created it) or `Modified`, with its value; absent →
/// `Deleted`, stamped with the delete's revision. Nothing is omitted — a key
/// created and deleted inside the window is reported `Deleted`. A key changed
/// again past where the page is cut is left to the later page that reaches
/// its latest revision, so no `mod_rev` on a page is past the page's
/// `safe_rev`.
///
/// # Safety
/// Single-threaded provider dispatch.
unsafe fn since_page(store: &Store, prefix: &[u8], since: u64, out: &mut [u8]) -> i32 {
    use ns_op::changes::{revision_token, PageWriter, KIND_ADDED, KIND_DELETED, KIND_MODIFIED};
    if since > store.revision || since < store.hist_base() {
        // Past what this store has issued (a token from before a reboot), or
        // behind what its history retains: either way, relist.
        return lost_page(out);
    }
    let Some(mut page) = PageWriter::new(out, ns_op::changes::REVISION_TOKEN_LEN) else {
        return errno::ENOMEM;
    };
    let mut cut = since;
    let mut more = false;
    for rev in since + 1..=store.revision {
        let Some(h) = store.hist_at(rev) else {
            break;
        };
        let key = &h.key[..h.key_len as usize];
        if has_prefix(key, prefix) {
            let current = store.get(key);
            // The key's latest revision: its object's while present; while
            // absent, its latest history entry — the delete, which is at or
            // after this one and so still retained.
            let latest = match current {
                Some((_, r)) => r,
                None => store
                    .hist_find(key, rev - 1, store.revision, false)
                    .map_or(rev, |l| l.revision),
            };
            if latest == rev {
                let (kind, val) = match current {
                    None => (KIND_DELETED, &[][..]),
                    Some((val, _)) => {
                        let created = store
                            .hist_find(key, since, rev, true)
                            .is_some_and(|f| f.kind == Kind::Added);
                        (if created { KIND_ADDED } else { KIND_MODIFIED }, val)
                    }
                };
                if !page.push(rev, kind, key, val) {
                    more = true;
                    break;
                }
            }
            // Otherwise a later revision changed the key again; it is
            // reported there.
        }
        cut = rev;
    }
    if more && page.count() == 0 {
        // A page that cannot hold the next record made no progress.
        return errno::ENOMEM;
    }
    page.finish(more, cut, &revision_token(cut))
        .map_or(errno::ENOMEM, |n| n as i32)
}

/// `storage.namespace` dispatch.
///
/// # Safety
/// Single-threaded platform dispatch; `arg` must be null or valid for
/// `arg_len` bytes.
pub unsafe fn dispatch_namespace(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    if !node_caller() {
        return errno::EACCES;
    }
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
            let Some(req) = ns_op::subscribe::parse(a) else {
                return errno::EINVAL;
            };
            let pl = req.prefix.len();
            if pl > STORAGE_KEY_MAX {
                return errno::EINVAL;
            }
            // The event must be the calling module's own: a subscription
            // never wakes anybody but its subscriber.
            let (Some(event), Some((module, generation))) =
                (event_slot(req.event), caller_occupancy())
            else {
                return errno::EINVAL;
            };
            if event_owner(event) != Some(module) {
                return errno::EINVAL;
            }
            let opener = crate::kernel::exec::scheduler::caller_owner();
            let ring_now = req.flags & ns_op::subscribe::FLAG_RING_NOW != 0;

            let subs = &mut *core::ptr::addr_of_mut!(SUBS);
            // Idempotent on (owner, occupancy, event, prefix): a module that
            // re-runs its subscribe path gets the handle it already holds,
            // not a second slot.
            if let Some(idx) = subs.iter().position(|s| {
                s.in_use
                    && s.opener == opener
                    && s.module == module
                    && s.generation == generation
                    && s.event == event
                    && &s.prefix[..s.prefix_len as usize] == req.prefix
            }) {
                if ring_now {
                    ring(&mut subs[idx]);
                }
                return tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32);
            }
            // Every caller here acts with the node's authority
            // (`node_caller`), so the pool's ceiling is the one quota; dead
            // stamps are swept before it refuses.
            let free = match subs.iter().position(|s| !s.in_use) {
                Some(idx) => Some(idx),
                None => {
                    reap_dead_subs();
                    subs.iter().position(|s| !s.in_use)
                }
            };
            let Some(idx) = free else {
                return refuse_slot(res::POOL_STORE_SUBS, subs.len());
            };
            subs[idx] = SUB_EMPTY;
            subs[idx].in_use = true;
            subs[idx].opener = opener;
            subs[idx].module = module;
            subs[idx].generation = generation;
            subs[idx].event = event;
            subs[idx].prefix_len = pl as u16;
            subs[idx].prefix[..pl].copy_from_slice(req.prefix);
            // Bit 0 rings once now. The subscriber reads what the prefix
            // holds itself, with `CHANGES` from the empty token.
            if ring_now {
                ring(&mut subs[idx]);
            }
            tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32)
        }
        ns_op::TAKE_RUNG => {
            let Some(req) = ns_op::take::parse(a) else {
                return errno::EINVAL;
            };
            let (Some(event), Some((module, generation))) =
                (event_slot(req.event), caller_occupancy())
            else {
                return errno::EINVAL;
            };
            let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
            let Some(mut answer) = ns_op::take::Writer::new(out) else {
                return errno::ENOMEM;
            };
            let opener = crate::kernel::exec::scheduler::caller_owner();
            // The caller's subscriptions on an event slot it no longer owns
            // are dead — the slot is somebody else's now, or free — and are
            // dropped rather than named.
            let owned = event_owner(event) == Some(module);
            let subs = &mut *core::ptr::addr_of_mut!(SUBS);
            let mut more = false;
            for (idx, s) in subs.iter_mut().enumerate() {
                // Only subscriptions this occupancy opened on this event are
                // visible; anybody else's are as if not open.
                if !s.in_use
                    || s.event != event
                    || s.opener != opener
                    || s.module != module
                    || s.generation != generation
                {
                    continue;
                }
                if !owned {
                    drop_sub(s);
                    continue;
                }
                if !s.rung {
                    continue;
                }
                if !answer.push(tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32)) {
                    more = true;
                    break;
                }
                s.rung = false;
            }
            if more {
                // The remainder keep their bits; signal again so the caller
                // takes them on its next wake. The caller owns the event
                // (`owned`), and is the one calling, so it is live.
                let _ = event_signal(event);
            }
            answer.finish(more) as i32
        }
        ns_op::CHANGES => {
            let Some(req) = ns_op::changes::parse_request(a) else {
                return errno::EINVAL;
            };
            // `req.sub` names the subscription to re-ring after an EAGAIN;
            // this store reads RAM inside the call and never answers one.
            let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
            let rc = changes_page(store, req.prefix, req.token, out);
            if rc >= 0 {
                write_fence(
                    Fence::ViewConsistent {
                        source: STORE_SOURCE,
                        revision: store.revision,
                    },
                    req.fence_out_ptr,
                    req.fence_out_cap,
                );
            }
            rc
        }
        ns_op::LOOKUP | ns_op::STAT => errno::ENOSYS,
        ns_op::CLOSE => {
            let idx = slot_of(handle) as usize;
            let subs = &mut *core::ptr::addr_of_mut!(SUBS);
            // The opening module occupancy as well as its owner: the node's
            // modules share one owner, and a stale handle number another
            // module now holds must not close that module's subscription.
            if handle >= 0
                && idx < subs.len()
                && opened_by_caller(subs[idx].in_use, subs[idx].opener)
                && caller_occupancy() == Some((subs[idx].module, subs[idx].generation))
            {
                subs[idx] = SUB_EMPTY;
            }
            0
        }
        _ => errno::ENOSYS,
    }
}

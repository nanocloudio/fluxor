//! Lanes: a module's attachment to a node module that serves it.
//!
//! A node module that serves lanes (the node's network stack) is reached by
//! lanes alone, never by ports, whoever its consumer is: a module of the
//! node's own graph and a workload's module alike name it as an endpoint
//! (`Endpoint::Lane { key, target }`), once as the consumer of a producer's
//! commands and once as the producer of that consumer's events. The splice
//! opens both channels as for any edge and, once the target has declared,
//! hands them to it as one lane of an owner: a workload's add's own, and in
//! the node's graph the owner stamped on the module writing the lane's
//! commands (the node owner, or the workload the owner plan gives that
//! module). A workload's add is staged
//! when the target is already running, so its lane resolves at once; the
//! node's graph stages before its targets instantiate, so its lanes resolve
//! as it is published ([`resolve`] from `splice::finish`).
//!
//! A lane is a kernel fact with no content: `(owner, key, commands channel,
//! events channel)`. The kernel never asks the target whether a lane may
//! bind anything, and never reads what crosses it. A target is a node
//! module whose manifest declares lanes (`[lanes]`): its capacity is read
//! at instantiation ([`declare`]), under the name hash its lanes are reached
//! by, and it takes the lane changes the kernel queues for it with
//! `LANE_TAKE` at the top of its step, before any lane I/O — attach, detach
//! (every lane of an owner is gone) and drain (the owner admits nothing
//! new). Changes are taken in the order they happened, so a lane's detach
//! is taken before an attach that reuses its channels, and a channel the
//! kernel freed and handed on is never written by the lane that held it.
//!
//! The queue cannot lose a detach. An attach the target has not taken yet is
//! withdrawn from the queue when its owner detaches, so a detach is queued
//! only for lanes the target holds, and the target holds at most its
//! declared capacity. Per target, queued attaches are at most its capacity
//! (one per live lane), queued detaches at most its capacity (one per owner
//! whose taken lanes it still holds) and queued drains as many, so three
//! times the capacity always suffices.
//!
//! The tables are boot tables (`kernel::mem::table`) sized to the targets'
//! declared capacities together as the graph instantiates: carved on
//! aarch64, from the static pool on RP, allocated on Linux, and wasm's
//! static array of [`STATIC_LANES`]. Across a rebuild they keep
//! `max(previous, declared)`.
//! Lane attach and detach run inside a live graph change and the target's
//! take on whichever core steps it; one lock orders them, and the tables are
//! sized under it.

use crate::abi::kernel_abi::lane;
use crate::kernel::mem::table::Table as BootTable;
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::OwnerHandle;
// `portable_atomic`, not `core::sync::atomic`: the lane lock's
// compare-exchange does not exist on ARMv6-M (RP2040), which has no
// LDREX/STREX; `portable_atomic` provides it there over a critical section
// and compiles to the native instruction everywhere else.
use portable_atomic::{AtomicBool, Ordering};

/// The most lanes one target can declare: a lane key is a `u8`.
pub const LANE_CEILING: usize = 255;
const _: () = assert!(LANE_CEILING == u8::MAX as usize);

/// Lane targets one graph holds.
pub const MAX_TARGETS: usize = 4;

/// Lanes the static table holds where tables are not sized at boot (wasm):
/// the profile's compiled size, and the most the targets there may declare
/// together. RP carves its tables from the static pool, and the figure is
/// only the table type's compiled size there.
#[cfg(not(any(feature = "host-linux", feature = "aarch64-metal")))]
pub const STATIC_LANES: usize = 16;
#[cfg(any(feature = "host-linux", feature = "aarch64-metal"))]
const STATIC_LANES: usize = 0;

/// A node module that serves lanes.
#[derive(Clone, Copy)]
struct Target {
    slot: usize,
    /// The slot's occupancy when it declared: a rebuild, restart or reuse
    /// of the slot moves it, and the declaration then names no one.
    generation: u32,
    /// The name hash its lanes are reached by, which a lane endpoint names.
    name_hash: u32,
    cap: usize,
}

#[derive(Clone, Copy)]
struct LaneOp {
    op: u8,
    key: u8,
    target: usize,
    owner: OwnerHandle,
    commands: i32,
    events: i32,
}

/// A lane attached and not yet detached, and whether its target has taken
/// its attach.
#[derive(Clone, Copy)]
struct LiveLane {
    owner: OwnerHandle,
    key: u8,
    target: usize,
    taken: bool,
    drained: bool,
}

/// The FIFO's bookkeeping; its slots are [`OPS`] and the live lanes [`LIVE`].
struct LaneQueue {
    head: usize,
    len: usize,
    /// Lanes the tables are sized for: the targets' capacities together.
    cap: usize,
    targets: [Option<Target>; MAX_TARGETS],
}

static mut LANES: LaneQueue = LaneQueue {
    head: 0,
    len: 0,
    cap: 0,
    targets: [None; MAX_TARGETS],
};
/// FIFO of changes, `3 * cap` slots; a withdrawn change leaves a hole that
/// take skips.
static mut OPS: BootTable<Option<LaneOp>, { 3 * STATIC_LANES }> =
    crate::boot_table!(3 * STATIC_LANES, None);
/// Live lanes, `cap` slots.
static mut LIVE: BootTable<Option<LiveLane>, STATIC_LANES> = crate::boot_table!(STATIC_LANES, None);
static LANES_LOCK: AtomicBool = AtomicBool::new(false);

/// The lane tables, borrowed under `LANES_LOCK`.
struct Lanes<'a> {
    q: &'a mut LaneQueue,
    ops: &'a mut [Option<LaneOp>],
    live: &'a mut [Option<LiveLane>],
}

/// Run `f` on the lane tables with `LANES_LOCK` held.
fn with_lanes<R>(f: impl FnOnce(&mut Lanes<'_>) -> R) -> R {
    while LANES_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `LANES_LOCK` is held, so these are the only references; the
    // tables move only in `size_lanes`, under the same lock.
    let r = unsafe {
        let q = &mut *core::ptr::addr_of_mut!(LANES);
        let cap = q.cap;
        let ops = &mut *core::ptr::addr_of_mut!(OPS);
        let live = &mut *core::ptr::addr_of_mut!(LIVE);
        let n_ops = (3 * cap).min(ops.len());
        let n_live = cap.min(live.len());
        let mut l = Lanes {
            q,
            ops: &mut ops[..n_ops],
            live: &mut live[..n_live],
        };
        f(&mut l)
    };
    LANES_LOCK.store(false, Ordering::Release);
    r
}

/// Size the lane tables for `lanes` lanes, keeping what they hold: the
/// queued changes keep their order.
///
/// # Safety
/// `LANES_LOCK` is held.
unsafe fn size_lanes(lanes: usize) -> i32 {
    let q = &mut *core::ptr::addr_of_mut!(LANES);
    let ops = &mut *core::ptr::addr_of_mut!(OPS);
    let live = &mut *core::ptr::addr_of_mut!(LIVE);
    // RP replans its tables at a rebuild, which leaves them empty under the
    // old `cap`: those are sized again.
    if lanes <= q.cap && live.len() >= q.cap && ops.len() >= 3 * q.cap {
        return 0;
    }
    if live.len() < q.cap {
        q.cap = 0;
        q.head = 0;
        q.len = 0;
    }
    let sized = ops.reserve(3 * lanes).is_ok()
        && ops.grow(3 * lanes).is_ok()
        && live.reserve(lanes).is_ok()
        && live.grow(lanes).is_ok();
    if !sized || ops.len() < 3 * lanes || live.len() < lanes {
        return errno::ENOSPC;
    }
    // The ring's slots are `[0, 3 * old cap)`; lay the queued changes out
    // from slot 0 so the larger ring keeps their order.
    let old = 3 * q.cap;
    if old > 0 && q.head != 0 {
        ops[..old].rotate_left(q.head);
    }
    q.head = 0;
    q.cap = lanes;
    0
}

impl Lanes<'_> {
    /// Close up the holes taken or withdrawn changes left, keeping order.
    fn compact(&mut self) {
        let n = self.ops.len();
        if n == 0 {
            return;
        }
        self.ops.rotate_left(self.q.head);
        let mut kept = 0;
        for i in 0..self.q.len {
            if let Some(op) = self.ops[i].take() {
                self.ops[kept] = Some(op);
                kept += 1;
            }
        }
        self.q.head = 0;
        self.q.len = kept;
    }

    fn push(&mut self, op: LaneOp) -> bool {
        let n = self.ops.len();
        if self.q.len >= n {
            self.compact();
        }
        if self.q.len >= n {
            return false;
        }
        let at = (self.q.head + self.q.len) % n;
        match self.ops.get_mut(at) {
            Some(slot) => *slot = Some(op),
            None => return false,
        }
        self.q.len += 1;
        true
    }

    /// The oldest queued change for `target`; withdrawn changes at the head
    /// are dropped as they are passed.
    fn pop_for(&mut self, target: usize) -> Option<LaneOp> {
        let n = self.ops.len();
        if n == 0 {
            return None;
        }
        // Drop holes at the head so the queue's length stays honest.
        while self.q.len > 0 && self.ops.get(self.q.head).is_some_and(Option::is_none) {
            self.q.head = (self.q.head + 1) % n;
            self.q.len -= 1;
        }
        for i in 0..self.q.len {
            let at = (self.q.head + i) % n;
            if self.ops[at].is_some_and(|o| o.target == target) {
                let op = self.ops[at].take();
                if i == 0 {
                    self.q.head = (self.q.head + 1) % n;
                    self.q.len -= 1;
                }
                return op;
            }
        }
        None
    }

    fn clear(&mut self) {
        self.ops.fill(None);
        self.live.fill(None);
        self.q.head = 0;
        self.q.len = 0;
        self.q.targets = [None; MAX_TARGETS];
    }

    /// The target at `slot` while its declaration names the slot's current
    /// occupancy.
    fn target(&self, slot: usize) -> Option<Target> {
        self.q.targets.iter().flatten().copied().find(|t| {
            t.slot == slot
                && crate::kernel::exec::scheduler::module_slot_generation(t.slot) == t.generation
        })
    }
}

/// The module at `slot` serves up to `cap` lanes (its manifest's `[lanes]`,
/// read as it is instantiated); a lane endpoint naming `name_hash` resolves
/// to it. A refusal refuses the module. `EINVAL` for no lanes or more than a key can name, `EEXIST` when
/// another live target carries the name, `ENOSPC` when the kernel cannot
/// hold that many lanes or that many targets.
pub fn declare(slot: usize, name_hash: u32, cap: usize) -> i32 {
    if cap == 0 || cap > LANE_CEILING {
        return errno::EINVAL;
    }
    let generation = crate::kernel::exec::scheduler::module_slot_generation(slot);
    with_lanes(|l| {
        // A stale declaration (its slot re-occupied) gives way.
        for t in l.q.targets.iter_mut() {
            if t.is_some_and(|t| {
                crate::kernel::exec::scheduler::module_slot_generation(t.slot) != t.generation
                    || t.slot == slot
            }) {
                *t = None;
            }
        }
        if l.q
            .targets
            .iter()
            .flatten()
            .any(|t| t.name_hash == name_hash)
        {
            return errno::EEXIST;
        }
        let Some(free) = l.q.targets.iter().position(Option::is_none) else {
            return errno::ENOSPC;
        };
        let total: usize = l.q.targets.iter().flatten().map(|t| t.cap).sum::<usize>() + cap;
        // SAFETY: `LANES_LOCK` is held for the closure's duration.
        let rc = unsafe { size_lanes(total) };
        if rc != 0 {
            return rc;
        }
        l.q.targets[free] = Some(Target {
            slot,
            generation,
            name_hash,
            cap,
        });
        0
    })
}

/// The slot of the live lane target reached by `name_hash`.
pub fn resolve(name_hash: u32) -> Option<usize> {
    with_lanes(|l| {
        l.q.targets
            .iter()
            .flatten()
            .find(|t| t.name_hash == name_hash)
            .and_then(|t| l.target(t.slot))
            .map(|t| t.slot)
    })
}

/// Hand a lane of `owner` to the target at `target`. `ENODEV` for a slot
/// that serves no lanes, `EINVAL` for a missing or shared channel, `EEXIST`
/// for an `(owner, key)` the target already holds, `ENOSPC` past its
/// capacity.
///
/// # Safety
/// Scheduler thread; both channels are open and owned by `owner`'s edges.
pub unsafe fn attach(
    owner: OwnerHandle,
    key: u8,
    target: usize,
    commands: i32,
    events: i32,
) -> i32 {
    if commands < 0 || events < 0 || commands == events {
        return errno::EINVAL;
    }
    with_lanes(|l| {
        let Some(t) = l.target(target) else {
            return errno::ENODEV;
        };
        let mut held = 0usize;
        for x in l.live.iter().flatten().filter(|x| x.target == target) {
            if x.owner == owner && x.key == key {
                return errno::EEXIST;
            }
            held += 1;
        }
        if held >= t.cap {
            return errno::ENOSPC;
        }
        let Some(free) = l.live.iter().position(Option::is_none) else {
            return errno::ENOSPC;
        };
        let pushed = l.push(LaneOp {
            op: lane::OP_ATTACH,
            key,
            target,
            owner,
            commands,
            events,
        });
        debug_assert!(pushed, "a live lane always has queue room");
        if !pushed {
            return errno::EAGAIN;
        }
        l.live[free] = Some(LiveLane {
            owner,
            key,
            target,
            taken: false,
            drained: false,
        });
        0
    })
}

/// Queue `op` for `owner` on every target holding a lane of it it has
/// taken.
fn queue_for_held(l: &mut Lanes<'_>, owner: OwnerHandle, op: u8) {
    let mut done = [usize::MAX; MAX_TARGETS];
    for i in 0..l.live.len() {
        let Some(x) = l.live[i] else { continue };
        if x.owner != owner || !x.taken || done.contains(&x.target) {
            continue;
        }
        if let Some(d) = done.iter_mut().find(|d| **d == usize::MAX) {
            *d = x.target;
        }
        let pushed = l.push(LaneOp {
            op,
            key: 0,
            target: x.target,
            owner,
            commands: -1,
            events: -1,
        });
        debug_assert!(pushed, "the queue holds a change for every held lane");
        if !pushed {
            log::error!(
                "[lanes] queue full: owner slot {} change {op} lost",
                owner.slot
            );
        }
    }
}

/// Detach every lane of `owner`. A lane whose attach its target has not
/// taken is withdrawn; the targets holding the others are told.
///
/// # Safety
/// Scheduler thread, before the owner's channels are closed.
pub unsafe fn detach(owner: OwnerHandle) {
    with_lanes(|l| {
        queue_for_held(l, owner, lane::OP_DETACH);
        for i in 0..l.live.len() {
            let Some(x) = l.live[i] else { continue };
            if x.owner != owner {
                continue;
            }
            if !x.taken {
                for op in l.ops.iter_mut() {
                    if op.is_some_and(|o| {
                        o.op == lane::OP_ATTACH
                            && o.owner == owner
                            && o.key == x.key
                            && o.target == x.target
                    }) {
                        *op = None;
                    }
                }
            }
            l.live[i] = None;
        }
    });
}

/// `owner` is draining: every target holding a lane of it is told once, and
/// admits nothing new for it from then on.
pub fn drain(owner: OwnerHandle) {
    with_lanes(|l| {
        if !l
            .live
            .iter()
            .flatten()
            .any(|x| x.owner == owner && x.taken && !x.drained)
        {
            return;
        }
        queue_for_held(l, owner, lane::OP_DRAIN);
        for x in l.live.iter_mut().flatten() {
            if x.owner == owner {
                x.drained = true;
            }
        }
    });
}

/// Whether the target at `slot` holds a lane of `owner` it has taken: the
/// one module `OWNER_GRANTS` answers about that owner.
pub fn holds_lane(slot: usize, owner: OwnerHandle) -> bool {
    with_lanes(|l| {
        l.target(slot).is_some()
            && l.live
                .iter()
                .flatten()
                .any(|x| x.target == slot && x.taken && x.owner == owner)
    })
}

/// Lanes of `owner` attached and not yet detached, taken or not: what a
/// rollback or a free of the owner leaves none of.
pub fn lanes_of(owner: OwnerHandle) -> usize {
    with_lanes(|l| l.live.iter().flatten().filter(|x| x.owner == owner).count())
}

/// Forget every target and every lane queued for them: their graph is being
/// rebuilt, and with it every channel a lane named. The tables keep their
/// size.
pub fn reset() {
    with_lanes(|l| l.clear());
}

/// The next queued lane change for the target at `slot`, as a
/// `kernel_abi::lane` record in `out` (`LANE_TAKE`): `RECORD_LEN`, 0 when
/// none is queued, or `EACCES` for a module that serves no lanes.
pub fn take(slot: usize, out: &mut [u8]) -> i32 {
    if out.len() < lane::RECORD_LEN {
        return errno::EINVAL;
    }
    let taken = with_lanes(|l| {
        l.target(slot)?;
        let Some(op) = l.pop_for(slot) else {
            return Some(None);
        };
        if op.op == lane::OP_ATTACH {
            for x in l.live.iter_mut().flatten() {
                if x.owner == op.owner && x.key == op.key && x.target == slot {
                    x.taken = true;
                }
            }
        }
        Some(Some(op))
    });
    let op = match taken {
        None => return errno::EACCES,
        Some(None) => return 0,
        Some(Some(op)) => op,
    };
    if op.op == lane::OP_ATTACH {
        // The target reads the lane's commands and writes its events: it is
        // those ends of the two channels from here on.
        use crate::kernel::ipc::channel::{channel_bind_end, End};
        let me = slot as crate::kernel::exec::scheduler::ModuleId;
        channel_bind_end(op.commands, End::Consumer, me);
        channel_bind_end(op.events, End::Producer, me);
    }
    let r = &mut out[..lane::RECORD_LEN];
    r.fill(0);
    r[lane::OFF_OP] = op.op;
    r[lane::OFF_KEY] = op.key;
    r[lane::OFF_OWNER_SLOT..lane::OFF_OWNER_SLOT + 2].copy_from_slice(&op.owner.slot.to_le_bytes());
    r[lane::OFF_OWNER_GEN..lane::OFF_OWNER_GEN + 4]
        .copy_from_slice(&op.owner.generation.to_le_bytes());
    r[lane::OFF_COMMANDS..lane::OFF_COMMANDS + 4].copy_from_slice(&op.commands.to_le_bytes());
    r[lane::OFF_EVENTS..lane::OFF_EVENTS + 4].copy_from_slice(&op.events.to_le_bytes());
    lane::RECORD_LEN as i32
}

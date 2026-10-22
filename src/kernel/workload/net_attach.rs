//! Network attachment for a workload subgraph staged at runtime.
//!
//! A subgraph that `apply_add` stages after boot cannot join the node's
//! network by ordinary edges: the net provider reads its boot lanes once, and
//! its `net_out` is one channel every boot consumer shares. Instead a
//! subgraph names the provider as an endpoint (`Endpoint::Net(key)`), once as
//! the consumer of a producer's commands and once as the producer of that
//! consumer's events. `apply_add` opens both channels as for any edge, then
//! hands them to the provider as one lane of the workload's own:
//!
//! - commands on the lane run as the workload's owner, so binds are
//!   lease-gated and every endpoint the lane opens is stamped with it;
//! - every event for an endpoint the lane opened — accepts, data, closes,
//!   connect results — goes to the lane's own event channel and to nothing
//!   else, lossless and back-pressured there;
//! - a lane may act only on endpoints it opened.
//!
//! `free_owner` detaches every lane of the owner and the provider closes
//! what they opened. A provider built into the kernel (`linux_net`)
//! registers itself here when it is instantiated; a provider that is a
//! module (the bare-metal `ip`) claims the role and takes its lanes from a
//! queue (below), and asks the kernel to admit each bind a lane makes. With
//! no provider, a `Net` endpoint is refused.

use crate::kernel::workload::owner::OwnerHandle;

/// Attach one lane: `(owner, key, commands channel, events channel)`.
/// Returns 0, or a negative errno.
pub type AttachFn = unsafe fn(OwnerHandle, u8, i32, i32) -> i32;
/// Detach every lane of an owner and close what they opened.
pub type DetachFn = unsafe fn(OwnerHandle);

#[derive(Clone, Copy)]
struct Provider {
    slot: usize,
    /// The slot's generation when a module provider claimed the role (0 for
    /// a built-in provider, which is not a module occupancy).
    generation: u32,
    attach: AttachFn,
    detach: DetachFn,
}

static mut PROVIDER: Option<Provider> = None;

/// Register the node's net provider: its module slot and its lane hooks.
/// The last registration wins; a graph rebuild registers again.
pub fn register(slot: usize, attach: AttachFn, detach: DetachFn) {
    // SAFETY: written from the scheduler thread while the provider is
    // instantiated; read from the same thread.
    unsafe {
        *core::ptr::addr_of_mut!(PROVIDER) = Some(Provider {
            slot,
            generation: 0,
            attach,
            detach,
        });
    }
}

/// Register the module provider at `slot`, in occupancy `generation`.
fn register_module(slot: usize, generation: u32) {
    // SAFETY: as `register`.
    unsafe {
        *core::ptr::addr_of_mut!(PROVIDER) = Some(Provider {
            slot,
            generation,
            attach: queued_attach,
            detach: queued_detach,
        });
    }
}

/// Forget the registered provider (its graph is being torn down).
pub fn unregister() {
    // SAFETY: as `register`.
    unsafe { *core::ptr::addr_of_mut!(PROVIDER) = None };
}

fn provider() -> Option<Provider> {
    // SAFETY: as `register`.
    unsafe { *core::ptr::addr_of!(PROVIDER) }
}

/// The module slot a `Net` endpoint resolves to, if a provider is registered.
pub fn provider_slot() -> Option<usize> {
    provider().map(|p| p.slot)
}

/// Hand a lane to the provider. ENODEV when none is registered.
///
/// # Safety
/// Scheduler thread; both channels are open and owned by `owner`'s edges.
pub unsafe fn attach(owner: OwnerHandle, key: u8, commands: i32, events: i32) -> i32 {
    match provider() {
        Some(p) => (p.attach)(owner, key, commands, events),
        None => crate::kernel::sys::errno::ENODEV,
    }
}

/// Detach every lane of `owner`. A no-op with no provider, or an owner that
/// has none.
///
/// # Safety
/// Scheduler thread, before the owner's channels are closed.
pub unsafe fn detach(owner: OwnerHandle) {
    if let Some(p) = provider() {
        (p.detach)(owner);
    }
}

// ── A provider that is a module: lanes queued for it to take ────────────
//
// A built-in provider (linux_net) is called directly. A provider that is a
// module (the bare-metal `ip`) cannot be: the kernel holds no function of it.
// It claims the role once (`wl::NET_PROVIDE`) and the kernel then records
// each attach and detach here for it to take at the top of its step
// (`wl::NET_LANE_TAKE`), before any lane I/O. Changes are taken in the order
// they happened, so a lane's detach is taken before an attach that reuses its
// channels, and a channel the kernel freed and handed on is never written by
// the lane that held it.
//
// The queue cannot lose a detach. An attach the provider has not taken yet
// is withdrawn from the queue when its owner detaches, so a detach is queued
// only for lanes the provider holds, and the provider holds at most its
// stated capacity. Queued attaches are at most that capacity (one per live
// lane) and queued detaches at most that capacity (one per owner whose taken
// lanes the provider still holds), so twice the capacity always suffices.
//
// The capacity is the provider's to state (`wl::NET_PROVIDE [lanes:u8]`): a
// lane id is a `u8`, so it is at most 255. The tables are boot tables
// (`kernel::mem::table`) sized when the provider claims the role, which it
// does while its graph is instantiated: carved on bcm2712, allocated on
// Linux, the profile's static array elsewhere ([`STATIC_LANES`]). Across a
// rebuild they keep `max(previous, stated)`.
//
// Lane attach and detach run inside a live graph change and the provider's
// take on whichever core steps it; one lock orders them, and the tables are
// sized under it.

use crate::abi::contracts::workload::{self as wl, net_lane};
use crate::kernel::mem::table::Table as BootTable;
// `portable_atomic`, not `core::sync::atomic`: the lane lock's
// compare-exchange does not exist on ARMv6-M (RP2040), which has no
// LDREX/STREX; `portable_atomic` provides it there over a critical section
// and compiles to the native instruction everywhere else.
use portable_atomic::{AtomicBool, Ordering};

/// The most lanes a provider can state: a lane id is a `u8` (`u8::MAX`).
pub const LANE_CEILING: usize = 255;
const _: () = assert!(LANE_CEILING == u8::MAX as usize);

/// Lanes the static table holds where tables are not sized at boot (wasm,
/// RP): the profile's compiled size, and the most a provider there may
/// state.
#[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712")))]
pub const STATIC_LANES: usize = 16;
#[cfg(any(feature = "host-linux", feature = "chip-bcm2712"))]
const STATIC_LANES: usize = 0;

#[derive(Clone, Copy)]
struct LaneOp {
    op: u8,
    key: u8,
    owner: OwnerHandle,
    commands: i32,
    events: i32,
}

/// A lane attached and not yet detached, and whether the provider has taken
/// its attach.
#[derive(Clone, Copy)]
struct LiveLane {
    owner: OwnerHandle,
    key: u8,
    taken: bool,
}

/// The FIFO's bookkeeping; its slots are [`OPS`] and the live lanes [`LIVE`].
struct LaneQueue {
    head: usize,
    len: usize,
    /// Lanes the tables are sized for: the provider's stated capacity.
    cap: usize,
}

static mut LANES: LaneQueue = LaneQueue {
    head: 0,
    len: 0,
    cap: 0,
};
/// FIFO of changes, `2 * cap` slots; a withdrawn attach leaves a hole that
/// take skips.
static mut OPS: BootTable<Option<LaneOp>, { 2 * STATIC_LANES }> =
    crate::boot_table!(2 * STATIC_LANES, None);
/// Live lanes, `cap` slots.
static mut LIVE: BootTable<Option<LiveLane>, STATIC_LANES> = crate::boot_table!(STATIC_LANES, None);
static LANES_LOCK: AtomicBool = AtomicBool::new(false);

/// The lane tables, borrowed under `LANES_LOCK`.
struct Lanes<'a> {
    q: &'a mut LaneQueue,
    ops: &'a mut [Option<LaneOp>],
    live: &'a mut [Option<LiveLane>],
}

/// Run `f` on the lane queue with `LANES_LOCK` held.
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
        let n_ops = (2 * cap).min(ops.len());
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
/// queued changes keep their order. Under `LANES_LOCK`.
///
/// # Safety
/// `LANES_LOCK` is held.
unsafe fn size_lanes(lanes: usize) -> i32 {
    use crate::kernel::sys::errno;
    let q = &mut *core::ptr::addr_of_mut!(LANES);
    let ops = &mut *core::ptr::addr_of_mut!(OPS);
    let live = &mut *core::ptr::addr_of_mut!(LIVE);
    // RP replans its tables at a rebuild, which leaves them empty under the
    // old `cap`: those are sized again.
    if lanes <= q.cap && live.len() >= q.cap && ops.len() >= 2 * q.cap {
        return 0;
    }
    if live.len() < q.cap {
        q.cap = 0;
        q.head = 0;
        q.len = 0;
    }
    let sized = ops.reserve(2 * lanes).is_ok()
        && ops.grow(2 * lanes).is_ok()
        && live.reserve(lanes).is_ok()
        && live.grow(lanes).is_ok();
    if !sized || ops.len() < 2 * lanes || live.len() < lanes {
        return errno::ENOSPC;
    }
    // The ring's slots are `[0, 2 * old cap)`; lay the queued changes out
    // from slot 0 so the larger ring keeps their order.
    let old = 2 * q.cap;
    if old > 0 && q.head != 0 {
        ops[..old].rotate_left(q.head);
    }
    q.head = 0;
    q.cap = lanes;
    0
}

impl Lanes<'_> {
    fn push(&mut self, op: LaneOp) -> bool {
        let n = self.ops.len();
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

    /// The oldest queued change, skipping withdrawn attaches.
    fn pop(&mut self) -> Option<LaneOp> {
        let n = self.ops.len();
        while self.q.len > 0 && n > 0 {
            let op = self.ops.get_mut(self.q.head).and_then(Option::take);
            self.q.head = (self.q.head + 1) % n;
            self.q.len -= 1;
            if op.is_some() {
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
    }
}

unsafe fn queued_attach(owner: OwnerHandle, key: u8, commands: i32, events: i32) -> i32 {
    use crate::kernel::sys::errno;
    if commands < 0 || events < 0 || commands == events {
        return errno::EINVAL;
    }
    with_lanes(|q| {
        if q.live
            .iter()
            .flatten()
            .any(|l| l.owner == owner && l.key == key)
        {
            return errno::EEXIST;
        }
        let Some(free) = q.live.iter().position(Option::is_none) else {
            return errno::ENOSPC;
        };
        let pushed = q.push(LaneOp {
            op: net_lane::OP_ATTACH,
            key,
            owner,
            commands,
            events,
        });
        debug_assert!(pushed, "a live lane always has queue room");
        if !pushed {
            return errno::EAGAIN;
        }
        q.live[free] = Some(LiveLane {
            owner,
            key,
            taken: false,
        });
        0
    })
}

unsafe fn queued_detach(owner: OwnerHandle) {
    with_lanes(|q| {
        let mut held = false;
        for slot in q.live.iter_mut() {
            let Some(l) = *slot else { continue };
            if l.owner != owner {
                continue;
            }
            if l.taken {
                held = true;
            } else {
                // Never taken: withdraw the attach, and the provider never
                // learns of the lane at all.
                for op in q.ops.iter_mut() {
                    if op.is_some_and(|o| {
                        o.op == net_lane::OP_ATTACH && o.owner == owner && o.key == l.key
                    }) {
                        *op = None;
                    }
                }
            }
            *slot = None;
        }
        if held {
            let pushed = q.push(LaneOp {
                op: net_lane::OP_DETACH,
                key: 0,
                owner,
                commands: -1,
                events: -1,
            });
            debug_assert!(pushed, "the queue holds a detach for every held lane");
            if !pushed {
                log::error!(
                    "[net_attach] lane queue full: owner slot {} detach lost",
                    owner.slot
                );
            }
        }
    });
}

fn is_queued(p: &Provider) -> bool {
    p.attach as usize == queued_attach as usize
}

/// Whether a module provider's registration still names a live occupancy of
/// its slot: a rebuild, restart or reuse of the slot moves its generation,
/// and the registration then names no one.
fn queued_current(p: &Provider) -> bool {
    is_queued(p) && crate::kernel::exec::scheduler::module_slot_generation(p.slot) == p.generation
}

/// A module at `slot` claims the net-provider role (`wl::NET_PROVIDE`),
/// stating its capacity of `lanes` lanes. `EBUSY` when another provider,
/// built in or a module, holds it; `EINVAL` for no lanes or more than a lane
/// id can name; `ENOSPC` when the kernel cannot size its tables for them. A
/// module registration whose slot has since been re-occupied is stale, and
/// the claim takes it over.
pub fn provide_queued(slot: usize, lanes: usize) -> i32 {
    use crate::kernel::sys::errno;
    if lanes == 0 || lanes > LANE_CEILING {
        return errno::EINVAL;
    }
    let generation = crate::kernel::exec::scheduler::module_slot_generation(slot);
    match provider() {
        Some(p) if is_queued(&p) && p.slot == slot && p.generation == generation => {}
        Some(p) if !is_queued(&p) || queued_current(&p) => return errno::EBUSY,
        _ => {}
    }
    let rc = with_lanes(|_| {
        // SAFETY: `LANES_LOCK` is held for the closure's duration.
        unsafe { size_lanes(lanes) }
    });
    if rc != 0 {
        return rc;
    }
    if !provider().is_some_and(|p| is_queued(&p) && p.slot == slot && p.generation == generation) {
        // A stale module registration's lanes went with its graph.
        with_lanes(|l| l.clear());
        register_module(slot, generation);
    }
    0
}

/// Whether the module at `slot` is the module provider, in its current
/// occupancy.
fn is_queued_provider(slot: usize) -> bool {
    provider().is_some_and(|p| queued_current(&p) && p.slot == slot)
}

/// Whether the module at `slot` is the node's lane provider (in its current
/// occupancy), for the ops only the provider may call.
pub fn is_lane_provider(slot: usize) -> bool {
    is_queued_provider(slot)
}

/// The lanes the kernel holds for its module provider: the capacity it
/// stated, `max` across rebuilds.
pub fn lane_capacity() -> usize {
    with_lanes(|q| q.q.cap)
}

/// Forget a module provider and every lane queued for it: its graph is being
/// rebuilt, and with it every channel a lane named. A built-in provider is
/// left registered; it registers again as the new graph instantiates. The
/// tables keep their size.
pub fn reset_queued() {
    if provider().is_some_and(|p| is_queued(&p)) {
        unregister();
    }
    with_lanes(|l| l.clear());
}

/// The next queued lane change for the module provider at `slot`, as a
/// `wl::net_lane` record in `out`: `RECORD_LEN`, 0 when none is queued, or
/// `EACCES` for a caller that is not the provider (`wl::NET_LANE_TAKE`).
pub fn take_queued(slot: usize, out: &mut [u8]) -> i32 {
    use crate::kernel::sys::errno;
    if !is_queued_provider(slot) {
        return errno::EACCES;
    }
    if out.len() < net_lane::RECORD_LEN {
        return errno::EINVAL;
    }
    let Some(op) = with_lanes(|q| {
        let op = q.pop()?;
        if op.op == net_lane::OP_ATTACH {
            for l in q.live.iter_mut().flatten() {
                if l.owner == op.owner && l.key == op.key {
                    l.taken = true;
                }
            }
        }
        Some(op)
    }) else {
        return 0;
    };
    let r = &mut out[..net_lane::RECORD_LEN];
    r.fill(0);
    r[net_lane::OFF_OP] = op.op;
    r[net_lane::OFF_KEY] = op.key;
    r[net_lane::OFF_OWNER_SLOT..net_lane::OFF_OWNER_SLOT + 2]
        .copy_from_slice(&op.owner.slot.to_le_bytes());
    r[net_lane::OFF_OWNER_GEN..net_lane::OFF_OWNER_GEN + 4]
        .copy_from_slice(&op.owner.generation.to_le_bytes());
    r[net_lane::OFF_COMMANDS..net_lane::OFF_COMMANDS + 4]
        .copy_from_slice(&op.commands.to_le_bytes());
    r[net_lane::OFF_EVENTS..net_lane::OFF_EVENTS + 4].copy_from_slice(&op.events.to_le_bytes());
    net_lane::RECORD_LEN as i32
}

/// May the owner a module provider names bind a new endpoint
/// (`wl::NET_LANE_ADMIT`)? The gate a built-in provider applies to a lane's
/// bind: the owner must still admit work, and when the committed plan is
/// lease-aware the (protocol, port) must be granted to it.
pub fn admit_queued(slot: usize, arg: &[u8]) -> i32 {
    use crate::kernel::sys::errno;
    if !is_queued_provider(slot) {
        return errno::EACCES;
    }
    if arg.len() < net_lane::ADMIT_LEN {
        return errno::EINVAL;
    }
    let owner = OwnerHandle {
        slot: u16::from_le_bytes([arg[0], arg[1]]),
        generation: u32::from_le_bytes([arg[4], arg[5], arg[6], arg[7]]),
    };
    let protocol = arg[8];
    let port = u16::from_le_bytes([arg[10], arg[11]]);
    if protocol != wl::NET_PROTO_TCP && protocol != wl::NET_PROTO_UDP {
        return errno::EINVAL;
    }
    if !crate::kernel::exec::scheduler::owners_mut().authorize_admit(owner) {
        // EPERM: an owner that is gone or draining admits nothing new.
        return errno::ERROR;
    }
    match crate::kernel::workload::owner_plan::lease_gate(
        owner.slot,
        owner.generation,
        protocol,
        port,
    ) {
        crate::kernel::workload::owner_plan::LeaseGate::Refused => errno::EACCES,
        _ => 0,
    }
}

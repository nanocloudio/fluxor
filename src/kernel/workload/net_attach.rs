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
            attach,
            detach,
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
// only for lanes the provider holds, and the provider holds at most
// `LANES_MAX`. Queued attaches are at most `LANES_MAX` (one per live lane)
// and queued detaches at most `LANES_MAX` (one per owner whose taken lanes
// the provider still holds), so `2 * LANES_MAX` entries always suffice.
//
// Lane attach and detach run inside a live graph change and the provider's
// take on whichever core steps it; one lock orders them.

use crate::abi::contracts::workload::{self as wl, net_lane};
use core::sync::atomic::{AtomicBool, Ordering};

/// The provider's lanes at most: the kernel refuses an attach past it.
pub const LANES_MAX: usize = net_lane::LANES_MAX;
const LANE_QUEUE: usize = 2 * LANES_MAX;

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

struct LaneQueue {
    /// FIFO of changes; a withdrawn attach leaves a hole that take skips.
    ops: [Option<LaneOp>; LANE_QUEUE],
    head: usize,
    len: usize,
    live: [Option<LiveLane>; LANES_MAX],
}

static mut LANES: LaneQueue = LaneQueue {
    ops: [None; LANE_QUEUE],
    head: 0,
    len: 0,
    live: [None; LANES_MAX],
};
static LANES_LOCK: AtomicBool = AtomicBool::new(false);

/// Run `f` on the lane queue with `LANES_LOCK` held.
fn with_lanes<R>(f: impl FnOnce(&mut LaneQueue) -> R) -> R {
    while LANES_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `LANES_LOCK` is held, so this is the only reference.
    let r = f(unsafe { &mut *core::ptr::addr_of_mut!(LANES) });
    LANES_LOCK.store(false, Ordering::Release);
    r
}

impl LaneQueue {
    fn push(&mut self, op: LaneOp) -> bool {
        if self.len >= LANE_QUEUE {
            return false;
        }
        self.ops[(self.head + self.len) % LANE_QUEUE] = Some(op);
        self.len += 1;
        true
    }

    /// The oldest queued change, skipping withdrawn attaches.
    fn pop(&mut self) -> Option<LaneOp> {
        while self.len > 0 {
            let op = self.ops[self.head].take();
            self.head = (self.head + 1) % LANE_QUEUE;
            self.len -= 1;
            if op.is_some() {
                return op;
            }
        }
        None
    }

    fn clear(&mut self) {
        self.ops = [None; LANE_QUEUE];
        self.head = 0;
        self.len = 0;
        self.live = [None; LANES_MAX];
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

/// A module at `slot` claims the net-provider role (`wl::NET_PROVIDE`).
/// `EBUSY` when another provider, built in or a module, holds it.
pub fn provide_queued(slot: usize) -> i32 {
    match provider() {
        None => {
            register(slot, queued_attach, queued_detach);
            0
        }
        Some(p) if is_queued(&p) && p.slot == slot => 0,
        Some(_) => crate::kernel::sys::errno::EBUSY,
    }
}

/// Whether the module at `slot` is the module provider.
fn is_queued_provider(slot: usize) -> bool {
    provider().is_some_and(|p| is_queued(&p) && p.slot == slot)
}

/// Forget a module provider and every lane queued for it: its graph is being
/// rebuilt, and with it every channel a lane named. A built-in provider is
/// left registered; it registers again as the new graph instantiates.
pub fn reset_queued() {
    if provider().is_some_and(|p| is_queued(&p)) {
        unregister();
    }
    with_lanes(LaneQueue::clear);
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

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
//! what they opened. The node's net provider registers itself here when it
//! is instantiated; with none registered a `Net` endpoint is refused.

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

//! The endpoints a workload owner may listen on, and the one answer to
//! `OWNER_GRANTS`.
//!
//! An owner's grants come from two places, and from nowhere else:
//! - the committed owner plan (`owner_plan`), for an owner it places;
//! - the owner's admission, for an owner the splice admits: a resident
//!   workload's boot record (`WKLD`, the graph's author grants them) or the
//!   `net`/`endpoint` options of the `CREATE` that made it (its creator,
//!   acting with the node's authority, grants them).
//!
//! An owner granted nothing holds nothing: a network stack refuses its
//! every listening bind. The admitted endpoints are kept per owner slot,
//! stamped with the owner's generation, so a slot's next owner never reads
//! the last one's. An endpoint is one owner's at a time: an admission naming
//! one another live owner holds, by its admission or by the plan, is
//! refused.

use crate::abi::contracts::net::net_proto::grant;
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::{OwnerHandle, OWNER_TABLE_SLOTS};

/// One endpoint: `[protocol u8][port u16 LE]`.
pub type Endpoint = [u8; grant::ENDPOINT_LEN];

/// The endpoints one owner's admission granted it.
#[derive(Clone, Copy)]
struct Admitted {
    /// The generation of the owner they are for.
    generation: u32,
    count: u8,
    endpoints: [Endpoint; grant::MAX_ADMITTED_ENDPOINTS],
}

const NONE: Admitted = Admitted {
    generation: 0,
    count: 0,
    endpoints: [[0; grant::ENDPOINT_LEN]; grant::MAX_ADMITTED_ENDPOINTS],
};

/// One entry per owner slot.
static mut ADMITTED: crate::kernel::mem::table::Table<Admitted, OWNER_TABLE_SLOTS> = crate::boot_table!(
    OWNER_TABLE_SLOTS,
    NONE,
    crate::abi::contracts::resource::POOL_OWNERS
);

/// Size the table to the owner table's `owners` slots, every entry empty: a
/// rebuilt graph's owners are admitted again.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size(owners: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    let t = &mut *core::ptr::addr_of_mut!(ADMITTED);
    t.reserve(owners)?;
    t.grow(owners)?;
    for e in t.iter_mut() {
        *e = NONE;
    }
    Ok(())
}

/// The admitted endpoints of the live owner `owner`; empty for an owner
/// admitted with none, or one no longer live.
fn admitted_of(owner: OwnerHandle) -> &'static [Endpoint] {
    if crate::kernel::exec::scheduler::owners()
        .lookup(owner)
        .is_none()
    {
        return &[];
    }
    // SAFETY: scheduler-thread state; no mutable borrow is live.
    let t = unsafe { &*core::ptr::addr_of!(ADMITTED) };
    match t.get(usize::from(owner.slot)) {
        Some(e) if e.generation == owner.generation => {
            &e.endpoints[..usize::from(e.count).min(grant::MAX_ADMITTED_ENDPOINTS)]
        }
        _ => &[],
    }
}

/// Whether a live owner other than `me` holds `ep`: admitted with it, or
/// granted it by the plan.
fn held_elsewhere(me: OwnerHandle, ep: &Endpoint) -> bool {
    if crate::kernel::workload::owner_plan::plan_grants_elsewhere(
        me.slot,
        me.generation,
        grant::ENDPOINT,
        ep,
    ) {
        return true;
    }
    let owners = crate::kernel::exec::scheduler::owners();
    (1..owners.slot_count()).any(|slot| {
        if slot == usize::from(me.slot) {
            return false;
        }
        owners.entry_at(slot).is_some_and(|e| {
            admitted_of(OwnerHandle {
                slot: slot as u16,
                generation: e.generation,
            })
            .contains(ep)
        })
    })
}

/// Grant the just-admitted owner `owner` the endpoints `endpoints`, each
/// `[protocol u8][port u16 LE]`. `EINVAL` for a malformed endpoint (a
/// protocol other than tcp or udp, port 0, one named twice), `E2BIG` past
/// [`grant::MAX_ADMITTED_ENDPOINTS`], `EEXIST` for one another live owner
/// holds, `ESRCH` for an owner that is not live. Nothing is granted unless
/// all of them are. Scheduler thread.
pub fn admit(owner: OwnerHandle, endpoints: impl Iterator<Item = Endpoint>) -> Result<(), i32> {
    if owner.is_node()
        || crate::kernel::exec::scheduler::owners()
            .lookup(owner)
            .is_none()
    {
        return Err(errno::ESRCH);
    }
    let mut entry = Admitted {
        generation: owner.generation,
        ..NONE
    };
    for ep in endpoints {
        let i = usize::from(entry.count);
        if i == grant::MAX_ADMITTED_ENDPOINTS {
            return Err(errno::E2BIG);
        }
        let port = u16::from_le_bytes([ep[1], ep[2]]);
        if (ep[0] != grant::PROTO_TCP && ep[0] != grant::PROTO_UDP)
            || port == 0
            || entry.endpoints[..i].contains(&ep)
        {
            return Err(errno::EINVAL);
        }
        if held_elsewhere(owner, &ep) {
            return Err(errno::EEXIST);
        }
        entry.endpoints[i] = ep;
        entry.count += 1;
    }
    // SAFETY: scheduler-thread state; no other borrow of the table is live.
    let t = unsafe { &mut *core::ptr::addr_of_mut!(ADMITTED) };
    let slot = t.get_mut(usize::from(owner.slot)).ok_or(errno::ESRCH)?;
    *slot = entry;
    Ok(())
}

/// The endpoints a boot record or an option value lists back to back, each
/// [`grant::ENDPOINT_LEN`] bytes; a short tail is one malformed endpoint
/// (protocol 0), which [`admit`] refuses.
pub fn listed(bytes: &[u8]) -> impl Iterator<Item = Endpoint> + '_ {
    bytes.chunks(grant::ENDPOINT_LEN).map(|c| {
        if let [p, a, b] = *c {
            [p, a, b]
        } else {
            [0; grant::ENDPOINT_LEN]
        }
    })
}

/// `OWNER_GRANTS`: owner `(slot, generation)`'s grant records into `out`,
/// the plan's then its admission's. Their length (0: granted nothing),
/// `ERANGE` with the length needed as `[len u32]` in `arg` when `out` is
/// short. Scheduler thread only.
pub fn owner_grants(slot: u16, generation: u32, arg: &mut [u8], out: &mut [u8]) -> i32 {
    let mut need = crate::kernel::workload::owner_plan::plan_grants(slot, generation, out);
    for ep in admitted_of(OwnerHandle { slot, generation }) {
        let end = need + grant::HEAD + grant::ENDPOINT_LEN;
        if let Some(d) = out.get_mut(need..end) {
            d[0..2].copy_from_slice(&grant::ENDPOINT.to_le_bytes());
            d[2..4].copy_from_slice(&(grant::ENDPOINT_LEN as u16).to_le_bytes());
            d[4..].copy_from_slice(ep);
        }
        need = end;
    }
    if need > out.len() {
        if let Some(a) = arg.get_mut(..4) {
            a.copy_from_slice(&(need as u32).to_le_bytes());
        }
        return errno::ERANGE;
    }
    need as i32
}

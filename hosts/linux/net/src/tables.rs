//! The `net_route` and `net_policy` stores this provider serves: the shared
//! core (`fluxor_sdk::cores::net_tables`) over tables it holds, realized on
//! the host by [`crate::route`] and [`crate::policy`].
//!
//! Calls arrive one at a time on the serve loop; the stores sit behind one
//! mutex each so a reader on another thread (the periodic probe, the
//! policy renderer's segment lookup) sees a whole table.
//!
//! Identity. A caller is the module the runtime names in the call frame:
//! its `(slot, generation)` is the writer the core binds a table to, and its
//! authority (the node's, or a workload's) is what the core checks. A
//! binding stays until the runtime says the caller is gone ([`released`]):
//! the runtime tells this provider of every caller that made a call that
//! succeeded, so a binding never outlives its module unseen.

use std::sync::{Mutex, MutexGuard, OnceLock};

use fluxor_abi::contracts::net::policy as pol;
use fluxor_abi::contracts::net::route as rt;
use fluxor_sdk::cores::net_tables::{
    PolicyBinding, PolicyMeta, PolicyStore, PolicyTable, RouteMeta, RouteRealizer, RouteTables,
    Writer,
};

pub use fluxor_sdk::cores::net_tables::Caller;

/// Segments the node holds at once.
const SEGMENTS: usize = 16;
/// Peer routes the node holds at once.
const PEERS: usize = 256;
/// Held addresses the node holds at once.
const HELD: usize = 256;
/// Policy tables the node holds at once, and the rule bytes of each.
const POLICY_TABLES: usize = 8;
const POLICY_TABLE_BYTES: usize = 8192;

struct RouteStore {
    meta: RouteMeta,
    segs: Vec<rt::Segment>,
    routes: Vec<rt::Route>,
    held: Vec<rt::Held>,
    spare_segs: Vec<rt::Segment>,
    spare_routes: Vec<rt::Route>,
    spare_held: Vec<rt::Held>,
    seg_state: Vec<rt::EntryState>,
    route_state: Vec<rt::EntryState>,
    held_state: Vec<rt::EntryState>,
}

impl RouteStore {
    fn new() -> Self {
        Self {
            meta: RouteMeta::default(),
            segs: vec![rt::Segment::EMPTY; SEGMENTS],
            routes: vec![rt::Route::EMPTY; PEERS],
            held: vec![rt::Held::EMPTY; HELD],
            spare_segs: vec![rt::Segment::EMPTY; SEGMENTS],
            spare_routes: vec![rt::Route::EMPTY; PEERS],
            spare_held: vec![rt::Held::EMPTY; HELD],
            seg_state: vec![rt::EntryState::EMPTY; SEGMENTS],
            route_state: vec![rt::EntryState::EMPTY; PEERS],
            held_state: vec![rt::EntryState::EMPTY; HELD],
        }
    }

    fn tables(&mut self) -> RouteTables<'_> {
        RouteTables {
            meta: &mut self.meta,
            segs: &mut self.segs,
            routes: &mut self.routes,
            held: &mut self.held,
            spare_segs: &mut self.spare_segs,
            spare_routes: &mut self.spare_routes,
            spare_held: &mut self.spare_held,
            seg_state: &mut self.seg_state,
            route_state: &mut self.route_state,
            held_state: &mut self.held_state,
        }
    }
}

struct PolicyHold {
    meta: PolicyMeta,
    tables: Vec<PolicyTable>,
    bindings: Vec<PolicyBinding>,
    rules: Vec<u8>,
}

impl PolicyHold {
    fn new() -> Self {
        Self {
            meta: PolicyMeta::default(),
            tables: vec![PolicyTable::EMPTY; POLICY_TABLES],
            bindings: vec![PolicyBinding::EMPTY; POLICY_TABLES],
            rules: vec![0; POLICY_TABLES * POLICY_TABLE_BYTES],
        }
    }

    fn store(&mut self) -> PolicyStore<'_> {
        PolicyStore {
            meta: &mut self.meta,
            tables: &mut self.tables,
            bindings: &mut self.bindings,
            rules: &mut self.rules,
        }
    }
}

fn routes() -> MutexGuard<'static, RouteStore> {
    static S: OnceLock<Mutex<RouteStore>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(RouteStore::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn policies() -> MutexGuard<'static, PolicyHold> {
    static S: OnceLock<Mutex<PolicyHold>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(PolicyHold::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The core's caller for a call the runtime framed.
pub fn caller_of(c: &fluxor_host_lane::frame::Caller) -> Caller {
    Caller {
        node: c.acts_for_node(),
        writer: Writer {
            slot: c.slot,
            gen: c.generation,
        },
    }
}

/// A binding is live until its module is [`released`].
fn live(_: Writer) -> bool {
    true
}

/// The module `(slot, generation)` is gone: the tables it writes and the
/// tables it enforces are unbound (they stay stored).
pub fn released(slot: u16, generation: u32) {
    let w = Writer {
        slot,
        gen: generation,
    };
    routes().tables().release(w);
    policies().store().release(w);
}

/// `net_route` over this provider's tables, realized by `realizer`.
pub fn route_dispatch(
    c: Caller,
    realizer: &mut impl RouteRealizer,
    opcode: u32,
    arg: &mut [u8],
    data: &mut [u8],
) -> i32 {
    // A segment's use is the realizer's to say.
    routes()
        .tables()
        .dispatch(c, 0, opcode, arg, data, &live, &|_| false, Some(realizer))
}

/// The segment `addr` lies in, as the table holds it now.
pub fn segment_for(family: u8, addr: &[u8; rt::ADDR_LEN]) -> Option<rt::Segment> {
    routes().tables().segment_for(family, addr)
}

/// Run `f` with the segment the table holds as `id`, while no replace runs:
/// `ENOENT` when it holds none.
pub fn with_segment(id: u16, f: impl FnOnce(&rt::Segment) -> i32) -> i32 {
    let mut g = routes();
    match g.tables().segment(id) {
        Some(s) => f(&s),
        None => fluxor_abi::errno::ENOENT,
    }
}

/// `net_policy` over this provider's tables, realized by `apply` on every
/// change; `caps` what the host realizes now.
pub fn policy_dispatch(
    c: Caller,
    caps: u32,
    apply: &mut impl FnMut(&[u8], Option<&[u8]>, Option<&[u8]>) -> Result<(), i32>,
    opcode: u32,
    arg: &mut [u8],
    data: &mut [u8],
) -> i32 {
    let enforces = caps & pol::caps::ENFORCED != 0;
    policies()
        .store()
        .dispatch(c, caps, enforces, opcode, arg, data, &live, Some(apply))
}

/// The rules of stored table `name`, if it is stored.
pub fn policy_rules(name: &[u8]) -> Option<Vec<u8>> {
    policies().store().table(name).map(|(r, _)| r.to_vec())
}

/// Every stored policy table, by name and rules.
pub fn for_each_policy(f: impl FnMut(&[u8], &[u8])) {
    policies().store().for_each(f);
}

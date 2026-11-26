//! `ip` as the node's `net.route` and `net.policy` provider on bare metal.
//!
//! A provider call runs here in the caller's frame, between this module's
//! own steps (a module provider and every module it serves share one
//! execution domain): the node agent's table writes, `pkt_filter`'s ATTACH
//! and READ, and every CAPS. The tables are kept with the shared core
//! (`fluxor_sdk::cores::net_tables`) in this module's heap; `route.rs` and
//! `policy.rs` realize what is stored at the next step.
//!
//! The caller is the kernel's to say: its authority (`CALLER_AUTHORITY`,
//! the node's for a node module and for an owner admitted with the node's
//! authority) and its occupancy (`CALLER_MODULE`), which binds a table's one
//! writer and a table's one enforcer; a binding whose occupancy the kernel
//! no longer answers live (`MODULE_LIVE`) is stale.

use super::*;
use abi::contracts::net::policy as np;
use abi::contracts::net::route as nr;
use abi::kernel_abi::query_key;
use fluxor_sdk::cores::net_tables::{Caller, NoHook, NoRealizer, Writer};

const EINVAL: i32 = -22;
const ENOSYS: i32 = -38;
const ESRCH: i32 = -3;

/// What this provider realizes of `net.route`: segments (a workload
/// address joins one through `ADDR_ADD`), peer routes reached directly, and
/// held addresses in `deliver` mode. Forwarding between segments, translated
/// egress and `announce` are not realized here.
const ROUTE_CAPS: u32 = nr::caps::SEGMENTS | nr::caps::PEER_ROUTES | nr::caps::HOLD_DELIVER;

/// What this provider realizes of `net.policy`: filter rules, and
/// `scope = local` services translated for the node's own traffic; inbound
/// translation is not realized here. ENFORCED is added while anything
/// enforces a table: this instance (it names tables, `policy_tables`) or an
/// in-graph enforcer bound to one (`pkt_filter`).
const POLICY_CAPS: u32 = np::caps::FILTER | np::caps::EGRESS | np::caps::DNAT_LOCAL;

/// The caller, as the kernel attests it. `None` when nobody is calling.
unsafe fn caller(s: &IpState) -> Option<Caller> {
    let sys = &*s.syscalls;
    let mut auth = [0u8; 8];
    let rc = (sys.provider_query)(-1, query_key::CALLER_AUTHORITY, auth.as_mut_ptr(), 8);
    if rc != 8 {
        return None;
    }
    let mut m = [0u8; 12];
    let rc = (sys.provider_query)(-1, query_key::CALLER_MODULE, m.as_mut_ptr(), 12);
    if rc != 12 {
        return None;
    }
    Some(Caller {
        // The node owner's record: slot 0.
        node: auth[0] == 0 && auth[1] == 0,
        writer: Writer::from_record(&m)?,
    })
}

/// Whether the kernel still answers occupancy `w` live.
unsafe fn live(sys: *const SyscallTable, w: Writer) -> bool {
    let mut r = w.record();
    ((*sys).provider_query)(-1, query_key::MODULE_LIVE, r.as_mut_ptr(), r.len()) == 1
}

/// The provider dispatch: `net.route` and `net.policy` by opcode class.
///
/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, `arg` points to `arg_len` bytes and
/// `data` to `data_len` bytes (either may be null when its length is 0),
/// disjoint and valid for the call.
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_dispatch"
)]
#[cfg_attr(not(feature = "host-test"), export_name = "module_provider_dispatch")]
pub unsafe extern "C" fn ip_provider_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    if state.is_null() || handle >= 0 {
        return EINVAL;
    }
    let s = &mut *(state as *mut IpState);
    if s.syscalls.is_null() {
        return ENOSYS;
    }
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
    let Some(c) = caller(s) else {
        return ESRCH;
    };
    let sys = s.syscalls;
    let is_live = move |w: Writer| live(sys, w);
    let class = (opcode >> 8) as u16;
    if class == nr::CLASS {
        // The segments this module's addresses joined: read before the store
        // borrows the state.
        let mut joined = [0u16; MAX_LOCAL_ADDRS];
        let mut i = 1;
        while i < MAX_LOCAL_ADDRS {
            let a = &s.local_addrs[i];
            if a.is_active() {
                joined[i] = a.segment;
            }
            i += 1;
        }
        let attached = move |id: u16| id != 0 && joined.contains(&id);
        return route::store(s).dispatch(
            c,
            ROUTE_CAPS,
            opcode,
            a,
            d,
            &is_live,
            &attached,
            None::<&mut NoRealizer>,
        );
    }
    if class == np::CLASS {
        let own = s.pol_n > 0;
        let mut st = policy::store(s);
        let mut caps = POLICY_CAPS;
        if own || st.enforcer_attached(&is_live) {
            caps |= np::caps::ENFORCED;
        }
        return st.dispatch(c, caps, false, opcode, a, d, &is_live, None::<&mut NoHook>);
    }
    ENOSYS
}

/// Whether segment `id` holds address `a16` as a workload's: the
/// segment exists, holds the address and the address is not its gateway.
pub(super) unsafe fn segment_admits(s: &mut IpState, id: u16, family: u8, a16: &[u8; 16]) -> bool {
    route::store(s).validate_attach(family, a16, id).is_ok()
}

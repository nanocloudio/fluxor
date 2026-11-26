//! Splice a composed graph into the running schedule.
//!
//! The kernel composes nothing: a graph arrives with its fans materialised,
//! its mailbox groups assigned and its stepping order given
//! (`fluxor_contracts::graph`), at boot and live alike, and every graph takes
//! the one path here: [`admit`] (or [`admit_boot`] for the node's own graph),
//! [`instantiate_batch`], [`finish`]. Admission checks what only the kernel
//! can know, refusing on the first failure:
//!
//! 1. counts within [`MAX_ADD_MODULES`] / [`MAX_ADD_EDGES`] (the node graph is
//!    bounded by the module and edge tables its plan sized);
//! 2. the codec's own checks ([`graph::decode`]: an order that is a
//!    permutation, known kinds and bits, lengths);
//! 3. header flags admitted for the authority;
//! 4. every module's domain below the node's domain count;
//! 5. every edge end resolves (a node graph's lane ends resolve as their
//!    targets declare, in [`finish`]) and every port is below `MAX_PORTS`;
//! 6. pre-pass modules per domain within [`graph::MAX_PRE_PASS_PER_DOMAIN`];
//! 7. step budgets admitted ([`admit_step_budget`]);
//! 8. no node tag in a workload's params, and no env bind in any;
//! 9. every name resolves in the loader or the native registry;
//! 10. interrupt-mode domains: refused to a workload; for the node's graph,
//!     an `irq` domain's module carries its IRQ and an interrupt entry;
//! 11. the graph's mailbox groups fit the kernel's group span.
//!
//! Nothing is allocated before step 11 passes. The add is then staged: its
//! owner reserved (the node owner for the node's graph), its slots
//! assigned, its edges appended and their channels opened. Its modules
//! instantiate a batch at a time ([`instantiate_batch`]), and [`finish`]
//! gates them on each other, splices their order into each domain's order
//! with every peer core parked, hands interrupt-mode modules to their
//! dispatchers and activates the owner.
//!
//! What an add holds while staged is a view over the caller's blob, re-read
//! in each phase, and the global slot of each of its modules.

use super::live::{admit_step_budget, caller, StepBudget};
use super::native::{NativeInit, NativeModule};
use super::{
    module_slots, native, Edge, InstantiateResult, LaneEnd, ModuleId, ModuleSlot, SchedulerState,
    BUFFER_GROUPS, LANE_PENDING, MAX_DOMAINS, MAX_PORTS, SCHED,
};
use crate::abi::contracts::resource::{OWNER_LINE_BUFFER, OWNER_LINE_STATE, OWNER_LINE_STORAGE};
use crate::kernel::boot::config::ModuleEntry;
use crate::kernel::exec::step_guard::{FaultPolicy, ModuleFaultInfo};
use crate::kernel::module::loader::{DynamicModulePending, ModuleLoader, Signing};
use crate::kernel::workload::owner::{OwnerHandle, OwnerState, OWNER_NODE};
use fluxor_contracts::boot_config::ExecMode;
use fluxor_contracts::graph::{self, ComposedGraph, EdgeRecord, Endpoint, ModuleRecord};
use fluxor_contracts::isolation::Level;

/// Largest graph one live add admits, in modules (fans included).
pub const MAX_ADD_MODULES: usize = 64;
/// Largest graph one live add admits, in edges (fans' joining edges
/// included).
pub const MAX_ADD_EDGES: usize = 192;

/// The `irq` params tag: the hardware line an `irq`-domain module owns.
const IRQ_PARAM_TAG: u8 = 0xFC;

// ── Staging capacity ────────────────────────────────────────────────────────

/// Adds staged at once: a `CREATE` staged over several calls, and one add
/// applied whole within a call beside it.
const ADD_STAGES: usize = 2;

/// Adds an owner table of `owners` slots can stage at once: none when it
/// seats no workload owner.
pub const fn workspaces_for(owners: usize) -> usize {
    if owners > 1 {
        ADD_STAGES
    } else {
        0
    }
}

/// The adds this node can stage at once: none when its plan seats no
/// workload owner.
pub fn add_capacity() -> usize {
    workspaces_for(crate::kernel::sys::resource_ledger::ceiling(
        crate::abi::contracts::resource::POOL_OWNERS,
    ) as usize)
}

/// Adds staged now.
static mut STAGED: usize = 0;

/// One staged add's claim on the node's staging capacity, given back when
/// the add is published or rolled back.
struct Stage;

impl Stage {
    fn claim() -> Result<Stage, AddError> {
        let cap = add_capacity();
        if cap == 0 {
            return Err(AddError::NoCapacity);
        }
        // SAFETY: scheduler-thread state, as every add.
        let staged = unsafe { &mut *core::ptr::addr_of_mut!(STAGED) };
        if *staged >= cap {
            return Err(AddError::WorkspaceBusy);
        }
        *staged += 1;
        Ok(Stage)
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        // SAFETY: scheduler-thread state.
        unsafe {
            let staged = &mut *core::ptr::addr_of_mut!(STAGED);
            *staged = staged.saturating_sub(1);
        }
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// The authority an add asks for its owner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddAuthority {
    /// The node graph, under the node owner: what the boot config carries.
    Node,
    /// Its own: a workload.
    Own,
    /// Its creator's: the module at this global index places the graph to
    /// act on its behalf. Admitted only when that module acts with the
    /// node's authority; the new owner then acts with the node's.
    Creator(usize),
}

/// Why a graph was refused. A refusal leaves the running graph as it was.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddError {
    /// The codec refused the blob.
    Malformed(graph::DecodeError),
    TooManyModules,
    TooManyEdges,
    /// The creator-authority flag on an add with no creator to act for.
    FlagRefused,
    /// The add asked for its creator's authority, and the creator does not
    /// act with the node's.
    AuthorityRefused,
    /// A module names a domain the node does not run.
    BadDomain,
    /// An edge end names no module, lane or port the node has.
    BadEndpoint,
    /// A domain would run more pre-pass modules than it holds.
    PrePassOverflow,
    /// A module's declared step budget is outside what the node admits
    /// ([`admit_step_budget`]).
    BudgetRefused,
    /// A workload module's params carry a node tag (`is_node_param_tag`).
    NodeParamRefused,
    /// A workload's edge names a module of the node's graph as an
    /// `Existing` end: the node's modules are reached by `Lane`, `Caller` or
    /// `Tap` ends only, never by an edge that rebuilds their ports.
    NodeModuleRefused,
    /// A module's params still carry an env bind record.
    UnboundEnv,
    /// A module's name resolves in neither the loader nor the native
    /// registry.
    UnknownModule,
    /// A workload module names an interrupt-mode domain, or a module of the
    /// node's graph in an `irq` domain lacks its IRQ or interrupt entry.
    InterruptDomain,
    /// The graph's mailbox groups do not fit the kernel's group span.
    GroupsExhausted,
    OwnerSlotsExhausted,
    PlanMismatch,
    NoFreeSlot,
    ChannelOpenFailed,
    /// Two in-place writers share a mailbox group, or a gated module sits on
    /// a zero-copy edge.
    BufferGroupRefused,
    Instantiate,
    /// A PIC load returned `Pending`: it cannot complete within the add.
    WouldBlock,
    /// The owner's admitted `state_cap` would be exceeded.
    StateCapExceeded,
    /// The rings the add opens would exceed the owner's admitted
    /// `buffer_cap`.
    BufferCapExceeded,
    /// A lane's target is absent or refused the lane (no room, a key it
    /// already holds for the owner).
    LaneAttachFailed,
    /// An owner already carries the graph's identity.
    OwnerExists,
    /// The node's plan seats no workload owner.
    NoCapacity,
    /// Every stage is held by an add in progress.
    WorkspaceBusy,
    /// A workload's module would run unprivileged and this node has no
    /// protection backend to run it so.
    GateUnavailable,
    /// A workload brings a module that would run privileged without the
    /// node vouching for it: a provider (or a native module) that is not a
    /// `workload_instantiable` type of the node's own image.
    GateRefused,
    /// Every isolation slot is held: a gated module would have none.
    IsolationSlotsExhausted,
}

impl AddError {
    /// The negative errno the syscall surface answers, distinct wherever the
    /// meaning differs.
    pub fn code(self) -> i32 {
        use crate::kernel::sys::errno;
        match self {
            AddError::Malformed(_)
            | AddError::FlagRefused
            | AddError::BadDomain
            | AddError::BadEndpoint
            | AddError::PlanMismatch
            | AddError::BufferGroupRefused
            | AddError::UnboundEnv => errno::EINVAL,
            AddError::TooManyModules | AddError::TooManyEdges | AddError::PrePassOverflow => {
                errno::E2BIG
            }
            AddError::OwnerSlotsExhausted
            | AddError::NoFreeSlot
            | AddError::StateCapExceeded
            | AddError::BufferCapExceeded
            | AddError::GroupsExhausted
            | AddError::NoCapacity
            | AddError::IsolationSlotsExhausted => errno::ENOSPC,
            AddError::ChannelOpenFailed => errno::ENOMEM,
            AddError::Instantiate => errno::ENOEXEC,
            AddError::UnknownModule => errno::ENOENT,
            AddError::InterruptDomain => errno::ENOTSUP,
            AddError::WouldBlock => errno::EAGAIN,
            AddError::LaneAttachFailed | AddError::WorkspaceBusy => errno::EBUSY,
            AddError::OwnerExists => errno::EEXIST,
            AddError::BudgetRefused => errno::ERANGE,
            AddError::GateUnavailable => errno::ENOSYS,
            AddError::NodeParamRefused
            | AddError::AuthorityRefused
            | AddError::NodeModuleRefused
            | AddError::GateRefused => errno::EACCES,
        }
    }

    /// The refusal's name, for a log line.
    pub fn name(self) -> &'static str {
        match self {
            AddError::Malformed(e) => e.kind(),
            AddError::TooManyModules => "too many modules",
            AddError::TooManyEdges => "too many edges",
            AddError::FlagRefused => "creator flag without a creator",
            AddError::AuthorityRefused => "creator lacks the node's authority",
            AddError::BadDomain => "domain out of range",
            AddError::BadEndpoint => "edge end does not resolve",
            AddError::PrePassOverflow => "pre-pass capacity",
            AddError::BudgetRefused => "step budget refused",
            AddError::NodeParamRefused => "node tag in params",
            AddError::NodeModuleRefused => "edge into a module of the node's graph",
            AddError::UnboundEnv => "unbound env record",
            AddError::UnknownModule => "module name does not resolve",
            AddError::InterruptDomain => "interrupt-mode domain",
            AddError::GroupsExhausted => "mailbox groups exhausted",
            AddError::OwnerSlotsExhausted => "owner slots exhausted",
            AddError::PlanMismatch => "owner placement mismatch",
            AddError::NoFreeSlot => "module slots exhausted",
            AddError::ChannelOpenFailed => "channel open failed",
            AddError::BufferGroupRefused => "mailbox group refused",
            AddError::Instantiate => "instantiation failed",
            AddError::WouldBlock => "load would block",
            AddError::StateCapExceeded => "state cap exceeded",
            AddError::BufferCapExceeded => "buffer cap exceeded",
            AddError::LaneAttachFailed => "lane refused",
            AddError::OwnerExists => "owner exists",
            AddError::NoCapacity => "no staging capacity",
            AddError::WorkspaceBusy => "staging busy",
            AddError::GateUnavailable => "no protection backend for a workload module",
            AddError::GateRefused => "workload module would run privileged unvouched",
            AddError::IsolationSlotsExhausted => "isolation slots exhausted",
        }
    }
}

// ── Checks ──────────────────────────────────────────────────────────────────

#[inline]
fn sched() -> &'static mut SchedulerState {
    // SAFETY: scheduler-thread-exclusive; mirrors `sched_mut()`.
    unsafe { &mut *core::ptr::addr_of_mut!(SCHED) }
}

/// The record's step budget.
pub fn record_budget(m: &ModuleRecord<'_>) -> StepBudget {
    StepBudget {
        deadline_us: m.step_deadline_us,
        burst_us: m.burst_us,
        policy: FaultPolicy::from_graph(m.fault_policy),
    }
}

/// Steps 4 and 6 over `graph`'s modules: every domain below `domains`, and
/// each domain's pre-pass modules, with `held(d)` already running in it,
/// within its capacity.
fn check_domains(
    graph: &ComposedGraph<'_>,
    domains: usize,
    held: impl Fn(usize) -> usize,
) -> Result<(), AddError> {
    let mut pre = [0usize; MAX_DOMAINS];
    for m in graph.modules() {
        let d = usize::from(m.domain);
        if d >= domains.clamp(1, MAX_DOMAINS) {
            return Err(AddError::BadDomain);
        }
        if m.pre_pass {
            pre[d] += 1;
            if held(d) + pre[d] > graph::MAX_PRE_PASS_PER_DOMAIN {
                return Err(AddError::PrePassOverflow);
            }
        }
    }
    Ok(())
}

/// Step 5's port rule.
fn ports_in_range(e: &EdgeRecord) -> bool {
    usize::from(e.from_port) < MAX_PORTS && usize::from(e.to_port) < MAX_PORTS
}

/// Step 11: the kernel group each of the graph's mailbox groups takes,
/// written to `map[group]`: groups are the graph's own labels, numbered from
/// 1 in edge order for this splice.
fn map_groups(
    edges: impl Iterator<Item = EdgeRecord>,
    map: &mut [u8; 256],
) -> Result<(), AddError> {
    map.fill(0);
    let mut next = 1usize;
    for e in edges {
        let g = usize::from(e.buffer_group);
        if g == 0 || map[g] != 0 {
            continue;
        }
        if next >= BUFFER_GROUPS {
            return Err(AddError::GroupsExhausted);
        }
        map[g] = next as u8;
        next += 1;
    }
    Ok(())
}

fn fill_edge(edge: &mut Edge, e: &EdgeRecord, map: &[u8; 256]) {
    edge.buffer_group = map[usize::from(e.buffer_group)];
    edge.edge_class = e.class;
    edge.buffer_bytes = e.buffer_bytes;
    edge.rate_class = e.rate_class;
    edge.wake_on_write = e.wake_on_write;
    edge.retains_send = e.retains_send;
}

/// The loader a module named `name_hash` resolves from: a workload's own
/// pack while its CREATE stages it, else the node's.
fn resolving_loader(name_hash: u32, node: &ModuleLoader) -> &ModuleLoader {
    crate::kernel::workload::code_pack::resolve(name_hash, node)
}

/// Whether a running module sits at global slot `g`.
fn live_slot(g: usize) -> bool {
    g < module_slots() && !matches!(sched().modules[g], ModuleSlot::Empty)
}

/// Each lane `(target, key)` names exactly one edge from a new module into
/// the target and one from the target to a new module; each caller key at
/// most one edge of each direction, between the caller and a new module.
fn keys_valid(graph: &ComposedGraph<'_>) -> bool {
    for e in graph.edges() {
        let (lane, key) = match (e.from, e.to) {
            (Endpoint::New(_), l @ Endpoint::Lane { .. })
            | (l @ Endpoint::Lane { .. }, Endpoint::New(_)) => (true, l),
            (Endpoint::New(_), c @ Endpoint::Caller(_))
            | (c @ Endpoint::Caller(_), Endpoint::New(_)) => (false, c),
            (Endpoint::Lane { .. } | Endpoint::Caller(_), _)
            | (_, Endpoint::Lane { .. } | Endpoint::Caller(_)) => return false,
            _ => continue,
        };
        let is = |end: Endpoint| end == key;
        let into = graph.edges().filter(|x| is(x.to)).count();
        let out = graph.edges().filter(|x| is(x.from)).count();
        if (lane && (into != 1 || out != 1)) || (!lane && (into > 1 || out > 1)) {
            return false;
        }
    }
    true
}

/// Whether no input port of a module takes two edges: one (module, port,
/// control) end each. A second edge into a port would be moved to another
/// port index when the channels are collected, so it could take a port the
/// graph meant for another producer (a `Caller` lane among them).
fn inputs_unique(graph: &ComposedGraph<'_>) -> bool {
    for (i, e) in graph.edges().enumerate() {
        if !matches!(e.to, Endpoint::New(_) | Endpoint::Existing(_)) {
            continue;
        }
        if graph
            .edges()
            .skip(i + 1)
            .any(|x| x.to == e.to && x.to_port == e.to_port && x.to_ctrl == e.to_ctrl)
        {
            return false;
        }
    }
    true
}

/// Step 5. The node's own graph names its own modules and lanes to its own
/// lane targets: a lane end is held to the lane rule ([`keys_valid`]) here
/// and resolved in [`finish`], once its target has declared its lanes, so a
/// lane naming no module of the graph refuses the graph there. A
/// workload's edge has a module of its own at one end at least, and names
/// a running module as `Existing` only when that module is not the node's:
/// an `Existing` end rebuilds the module's port table, and the node's
/// modules take a workload's traffic over `Lane` and `Caller` lanes alone.
/// A graph acting with the node's authority may name the node's modules.
fn check_endpoints(graph: &ComposedGraph<'_>, authority: AddAuthority) -> Result<(), AddError> {
    if authority == AddAuthority::Node {
        let own = |end: Endpoint| matches!(end, Endpoint::New(_) | Endpoint::Lane { .. });
        if !keys_valid(graph) {
            return Err(AddError::BadEndpoint);
        }
        for e in graph.edges() {
            if !own(e.from) || !own(e.to) || !ports_in_range(&e) {
                return Err(AddError::BadEndpoint);
            }
        }
        return Ok(());
    }
    if !keys_valid(graph) || !inputs_unique(graph) {
        return Err(AddError::BadEndpoint);
    }
    for e in graph.edges() {
        if !ports_in_range(&e) {
            return Err(AddError::BadEndpoint);
        }
        if e.from.new_index().is_none() && e.to.new_index().is_none() {
            return Err(AddError::BadEndpoint);
        }
        let ok = |end: Endpoint| match end {
            Endpoint::New(_) => Ok(()),
            Endpoint::Existing(g)
                if authority == AddAuthority::Own
                    && live_slot(usize::from(g))
                    && super::module_owner(usize::from(g)).is_node() =>
            {
                Err(AddError::NodeModuleRefused)
            }
            Endpoint::Existing(g) if live_slot(usize::from(g)) => Ok(()),
            Endpoint::Tap(g) if live_slot(usize::from(g)) => {
                let ports = &sched().ports[usize::from(g)];
                let p = usize::from(e.from_port);
                if p < usize::from(ports.out_count) && ports.out_chans[p] >= 0 {
                    Ok(())
                } else {
                    Err(AddError::BadEndpoint)
                }
            }
            Endpoint::Lane { target, .. }
                if crate::kernel::workload::lanes::resolve(target).is_some() =>
            {
                Ok(())
            }
            Endpoint::Caller(_) if caller().is_some_and(live_slot) => Ok(()),
            _ => Err(AddError::BadEndpoint),
        };
        ok(e.from)?;
        ok(e.to)?;
    }
    Ok(())
}

/// Steps 7 to 10 for one module. The loader's module, when it resolves
/// there, for [`validated`].
fn check_module(
    m: &ModuleRecord<'_>,
    loader: &ModuleLoader,
    authority: AddAuthority,
) -> Result<(Option<crate::kernel::module::loader::LoadedModule>, Level), AddError> {
    let system = authority == AddAuthority::Node;
    let budget = record_budget(m);
    // The node's graph chooses any policy; a workload only one confined to
    // the faulting module. Every deadline is within the domain's ceiling.
    let admitted = StepBudget {
        policy: if system {
            FaultPolicy::Skip
        } else {
            budget.policy
        },
        ..budget
    };
    if let Err(why) = admit_step_budget(&admitted, m.domain) {
        log::warn!(
            "[splice] module {:#010x} refused its step budget (deadline {} us, burst {} us, \
             policy {:?}): {:?}",
            m.name_hash,
            budget.deadline_us,
            budget.burst_us,
            budget.policy,
            why,
        );
        return Err(AddError::BudgetRefused);
    }
    if !system {
        if let Some(tag) = super::params_node_tag(m.params) {
            log::warn!(
                "[splice] module {:#010x} refused: its params carry node tag {tag:#04x}",
                m.name_hash
            );
            return Err(AddError::NodeParamRefused);
        }
    }
    if super::params_carry_tag(m.params, fluxor_contracts::graph::env_bind::BIND_TAG) {
        return Err(AddError::UnboundEnv);
    }
    let resolver = resolving_loader(m.name_hash, loader);
    let loaded = resolver.find_by_name_hash(m.name_hash);
    let native = native::lookup(m.name_hash);
    if loaded.is_err() && native.is_none() {
        log::warn!("[splice] module {:#010x} resolves nowhere", m.name_hash);
        return Err(AddError::UnknownModule);
    }
    // The level: the node's graph names its own (params tag 0xF5); a
    // workload's is the kernel's to set, never its params'.
    let level = if system {
        super::params_level(m.params)
    } else {
        workload_level(
            m.name_hash,
            loaded.as_ref().ok(),
            core::ptr::eq(resolver, loader),
        )?
    };
    let mode = super::domain_exec_mode(usize::from(m.domain));
    if mode.is_interrupt() {
        if !system {
            return Err(AddError::InterruptDomain);
        }
        if mode == ExecMode::Irq {
            // An `irq` module owns a line and runs from its interrupt entry.
            let entry = match &loaded {
                Ok(lm) => lm
                    .get_export_addr(crate::abi::registry::entry_point::MODULE_ISR_ENTRY)
                    .is_ok(),
                Err(_) => native.is_some_and(|vt| vt.isr_entry.is_some()),
            };
            if !entry || !super::params_carry_tag(m.params, IRQ_PARAM_TAG) {
                log::warn!(
                    "[splice] module {:#010x} in an irq domain lacks its IRQ or its \
                     interrupt entry",
                    m.name_hash
                );
                return Err(AddError::InterruptDomain);
            }
        }
    }
    Ok((loaded.ok(), level))
}

/// How this node runs a workload's modules.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WorkloadGate {
    /// In the runtime's own process (the Linux runtime): not metal, and its
    /// CAPS says the isolation is the process.
    Host,
    /// Unprivileged at this level: the strongest the node implements for
    /// the module.
    Backend(Level),
    /// Not at all: a metal node with no protection backend.
    Unavailable,
}

impl WorkloadGate {
    /// The workload posture (`contracts::workload::POSTURE_*`) a node with
    /// this gate realizes for a graph workload, `None` for none: the Linux
    /// runtime `SHARED` (the isolation is its process, said as it is), a
    /// metal node with a backend `ISOLATED`, one without nothing.
    pub fn posture(self) -> Option<u8> {
        use crate::abi::contracts::workload as wl;
        match self {
            WorkloadGate::Host => Some(wl::POSTURE_SHARED),
            WorkloadGate::Backend(_) => Some(wl::POSTURE_ISOLATED),
            WorkloadGate::Unavailable => None,
        }
    }
}

/// This node's gate for a workload, before any module is known.
pub fn node_workload_gate() -> WorkloadGate {
    node_gate(None)
}

/// What admission reads of one workload module: where its type resolved and
/// what its signed manifest says.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkloadModuleFacts {
    /// A native module (kernel code): it cannot be gated.
    pub native: bool,
    /// The node's own loader resolved the type, never a code pack (which may
    /// shadow an image type by name).
    pub node_resolved: bool,
    /// The manifest's `workload_instantiable` fact.
    pub workload_instantiable: bool,
    /// The manifest's grant words: every bit the module may hold, its
    /// conditional grants among them (their block only narrows admission).
    pub grants: [u64; 2],
    /// Contracts the module provides.
    pub provides: usize,
}

/// The level a workload's module runs at under `gate`. Every module a
/// workload brings runs gated at the node's level — except a type the node's
/// own loader resolved whose signed manifest declares it
/// `workload_instantiable` and which holds no grant (no op-level grant, no
/// contract that reaches the kernel, conditional or not): the node vouches
/// for that code as it does for its own modules, and it runs privileged,
/// its memory charged to the owner. Any other provider is refused (`GateRefused`,
/// `EACCES`): other modules' calls into it would run its code privileged.
/// A native module is kernel code and is refused too. A node with no
/// backend admits no workload module (`GateUnavailable`, `ENOSYS`).
pub fn workload_module_level(
    f: &WorkloadModuleFacts,
    gate: WorkloadGate,
) -> Result<Level, AddError> {
    let backend = match gate {
        WorkloadGate::Host => return Ok(Level::Privileged),
        WorkloadGate::Unavailable => None,
        WorkloadGate::Backend(level) => Some(level),
    };
    if f.native {
        return Err(AddError::GateRefused);
    }
    let vouched = f.node_resolved
        && f.workload_instantiable
        && f.grants[1] == 0
        && f.grants[0] & crate::abi::registry::CONTRACT_REACH_KERNEL == 0;
    if vouched {
        return Ok(Level::Privileged);
    }
    if f.provides != 0 {
        return Err(AddError::GateRefused);
    }
    backend.ok_or(AddError::GateUnavailable)
}

/// Whether a workload's `isolated` modules fit the `free` isolation slots:
/// refused at admission, never run privileged for want of one.
pub fn isolated_admission(isolated: usize, free: usize) -> Result<(), AddError> {
    if isolated > free {
        Err(AddError::IsolationSlotsExhausted)
    } else {
        Ok(())
    }
}

/// The level a workload's module runs at on this node ([`workload_module_level`]).
/// Out of line: the admission walk's frame stays the size it was.
#[inline(never)]
fn workload_level(
    name_hash: u32,
    loaded: Option<&crate::kernel::module::loader::LoadedModule>,
    node_resolved: bool,
) -> Result<Level, AddError> {
    let facts = match loaded {
        None => WorkloadModuleFacts {
            native: true,
            ..WorkloadModuleFacts::default()
        },
        Some(lm) => WorkloadModuleFacts {
            native: false,
            node_resolved,
            workload_instantiable: lm.manifest_workload_instantiable(),
            grants: lm.manifest_grants(),
            provides: lm.manifest_provides_count(),
        },
    };
    let r = workload_module_level(&facts, node_gate(loaded));
    if let Err(e) = r {
        log::warn!(
            "[splice] workload module {name_hash:#010x} refused: {}",
            e.name()
        );
    }
    r
}

/// This node's [`WorkloadGate`] for `lm`. The Linux runtime is a process,
/// not metal. A metal node with a protection backend gates at the strongest
/// level it implements for the module: isolated under an MMU; on an MPU
/// isolated when the module's code can be drawn as one region, else
/// contained.
#[inline(never)]
fn node_gate(lm: Option<&crate::kernel::module::loader::LoadedModule>) -> WorkloadGate {
    if cfg!(feature = "host-linux") {
        return WorkloadGate::Host;
    }
    if crate::kernel::sys::hal::protection_gateway_table().is_null() {
        return WorkloadGate::Unavailable;
    }
    #[cfg(feature = "kernel-mpu")]
    {
        if let Some(lm) = lm {
            use fluxor_contracts::isolation::{code_region_len, region_plan, Access, Span};
            let code = Span {
                base: lm.code_base() as u64,
                len: code_region_len(u64::from(lm.header.code_size)),
                access: Access::ReadExec,
            };
            if region_plan(&[code], crate::platform::rp_protection::MODEL).is_err() {
                return WorkloadGate::Backend(Level::Contained);
            }
        }
    }
    let _ = lm;
    WorkloadGate::Backend(Level::Isolated)
}

/// Isolation slots free on this node: what a workload's isolated modules
/// may take. `usize::MAX` where isolation keeps no slot pool.
fn isolation_slots_free() -> usize {
    #[cfg(feature = "chip-bcm2712")]
    {
        crate::arch::aarch64::isolation::free_slots()
    }
    #[cfg(not(feature = "chip-bcm2712"))]
    {
        usize::MAX
    }
}

/// What a loader-resolved module's signature establishes, its bytes
/// validated once for the add (`loader::validate_module`); a native
/// module's is `Unverified`.
#[inline(never)]
fn validated(
    module: Option<crate::kernel::module::loader::LoadedModule>,
) -> Result<Signing, AddError> {
    match module {
        Some(lm) => crate::kernel::module::loader::validate_module(&lm, "admit")
            .map_err(|_| AddError::Instantiate),
        None => Ok(Signing::Unverified),
    }
}

// ── Staged add ──────────────────────────────────────────────────────────────

/// An add between its staging and its publication: the owner reserved, the
/// slots assigned, the edges and channels open, the modules instantiating a
/// batch at a time.
pub struct StagedAdd {
    /// The graph, borrowed from the caller's blob (see [`admit`]).
    graph: ComposedGraph<'static>,
    /// Each module's global slot. The node's graph is placed on a reset
    /// table, module `k` at slot `k`, and keeps nothing here.
    slots: [ModuleId; MAX_ADD_MODULES],
    authority: AddAuthority,
    handle: OwnerHandle,
    owner_uid: [u8; 16],
    edge_base: usize,
    /// Modules instantiated so far: the next local index.
    done: usize,
    /// The load of module `done`, still completing (the node's graph only:
    /// a workload's add cannot wait).
    pending: Option<DynamicModulePending>,
    _stage: Option<Stage>,
}

impl StagedAdd {
    /// The owner the add reserved.
    pub fn handle(&self) -> OwnerHandle {
        self.handle
    }

    /// The identity the add is for.
    pub fn owner_uid(&self) -> [u8; 16] {
        self.owner_uid
    }

    /// Where the add's edges begin in the scheduler's edge table.
    pub fn edge_base(&self) -> usize {
        self.edge_base
    }

    /// Whether every module has instantiated.
    pub fn complete(&self) -> bool {
        self.done == self.n()
    }

    /// Whether a module's load is completing: the caller waits before the
    /// next batch.
    pub fn loading(&self) -> bool {
        self.pending.is_some()
    }

    /// How many modules the add places.
    pub fn module_count(&self) -> usize {
        self.n()
    }

    /// The global slot of the add's `k`-th module.
    pub fn slot(&self, k: usize) -> usize {
        if self.authority == AddAuthority::Node {
            k
        } else {
            usize::from(self.slots[k])
        }
    }

    fn n(&self) -> usize {
        usize::from(self.graph.module_count())
    }

    fn e(&self) -> usize {
        usize::from(self.graph.edge_count())
    }
}

/// The `k`-th module record of `graph`.
fn module_at<'a>(graph: &ComposedGraph<'a>, k: usize) -> ModuleRecord<'a> {
    graph.modules().nth(k).unwrap_or_default()
}

/// Validate `bytes` as a live add and stage it. `creator` is the module an
/// add flagged `graph::FLAG_CREATOR_AUTHORITY` acts for; an add with the flag
/// and no creator is refused. `assignment`, when `Some((slot, generation))`,
/// asserts the owner the kernel allocates matches the one a composer chose.
///
/// # Safety
/// `bytes` stays valid and unchanged until the staged add is published or
/// abandoned: its modules' params are read from it as they instantiate.
pub unsafe fn admit(
    bytes: &[u8],
    creator: Option<usize>,
    assignment: Option<(u16, u32)>,
) -> Result<StagedAdd, AddError> {
    let stage = Stage::claim()?;
    // SAFETY: the caller's contract keeps the blob for the add's life.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), bytes.len()) };

    // 1. Counts, before the records are walked.
    let header = graph::header(bytes).map_err(AddError::Malformed)?;
    if usize::from(header.module_count) > MAX_ADD_MODULES {
        return Err(AddError::TooManyModules);
    }
    if usize::from(header.edge_count) > MAX_ADD_EDGES {
        return Err(AddError::TooManyEdges);
    }
    // 2. The codec.
    let g = graph::decode(bytes).map_err(|e| {
        log::warn!("[splice] graph refused: {} ({})", e.kind(), e.detail());
        AddError::Malformed(e)
    })?;
    // 3. Authority.
    let authority = match (header.creator_authority(), creator) {
        (false, _) => AddAuthority::Own,
        (true, Some(idx)) => AddAuthority::Creator(idx),
        (true, None) => return Err(AddError::FlagRefused),
    };
    if let AddAuthority::Creator(idx) = authority {
        if idx >= module_slots()
            || !sched()
                .owners
                .authority_of(super::module_owner(idx))
                .is_node()
        {
            return Err(AddError::AuthorityRefused);
        }
    }
    admit_decoded(g, authority, assignment, stage)
}

/// Steps 4 to 11 for a decoded live add, then its staging: its own frame,
/// so the module checks run under the decode's few locals alone.
#[inline(never)]
fn admit_decoded(
    g: ComposedGraph<'static>,
    authority: AddAuthority,
    assignment: Option<(u16, u32)>,
    stage: Stage,
) -> Result<StagedAdd, AddError> {
    let mut map = [0u8; 256];
    let mut signings = [Signing::Unverified; MAX_ADD_MODULES];
    check(
        &g,
        authority,
        usize::from(sched().domain_count),
        &mut map,
        &mut signings,
    )?;
    stage_add(g, authority, assignment, &map, &signings, Some(stage))
}

/// The shape of the node's own graph, as the config parser checks it before
/// installing it: its domains below `domains`, its pre-pass within capacity,
/// its edges between its own modules on ports in range, and its mailbox
/// groups within the kernel's span. [`admit_boot`] checks it whole.
pub fn check_boot(graph: &ComposedGraph<'_>, domains: usize) -> Result<(), AddError> {
    check_domains(graph, domains, |_| 0)?;
    check_endpoints(graph, AddAuthority::Node)?;
    let mut map = [0u8; 256];
    map_groups(graph.edges(), &mut map)
}

/// Validate the node's own graph, as the config carries it with the
/// `domains` it declares, and stage it under the node owner on the reset
/// tables, module `k` at slot `k`.
pub(crate) fn admit_boot(g: ComposedGraph<'static>, domains: usize) -> Result<StagedAdd, AddError> {
    // 1. The tables the plan sized hold it.
    if usize::from(g.module_count()) > module_slots() {
        return Err(AddError::TooManyModules);
    }
    if usize::from(g.edge_count()) > sched().edges.len() {
        return Err(AddError::TooManyEdges);
    }
    // 2-3: the config parser decoded it, and a node graph carries no owner,
    // caps or flags.
    let mut map = [0u8; 256];
    check(&g, AddAuthority::Node, domains, &mut map, &mut [])?;
    stage_add(g, AddAuthority::Node, None, &map, &[], None)
}

/// Steps 4 to 11. Each module's signing goes to `signings[k]`, or, for the
/// node's graph (an empty `signings`), to its slot `k`.
fn check(
    g: &ComposedGraph<'_>,
    authority: AddAuthority,
    domains: usize,
    map: &mut [u8; 256],
    signings: &mut [Signing],
) -> Result<(), AddError> {
    // 4, 6. Domains and pre-pass.
    check_domains(g, domains, |d| {
        usize::from(sched().domains[d].pre_pass_count)
    })?;
    // 5. Ends and ports.
    check_endpoints(g, authority)?;
    // 7-10. Each module.
    // SAFETY: scheduler-thread graph-mutation context, as every add.
    let loader = unsafe { super::static_loader() };
    let mut isolated = 0usize;
    for (k, m) in g.modules().enumerate() {
        let (module, level) = check_module(&m, loader, authority)?;
        let signing = validated(module)?;
        if level == Level::Isolated {
            isolated += 1;
        }
        // The node's graph sits at its own indices; a workload's slots are
        // assigned after its checks.
        match signings.get_mut(k) {
            Some(s) => *s = signing,
            None => sched().module_signing[k] = signing,
        }
    }
    // A workload's isolated modules each need a slot now: refused here,
    // before anything is staged, never run privileged for want of one.
    if authority != AddAuthority::Node {
        let free = isolation_slots_free();
        if let Err(e) = isolated_admission(isolated, free) {
            log::warn!(
                "[splice] add refused: {isolated} isolated modules, {free} isolation slots free"
            );
            return Err(e);
        }
    }
    // 11. Groups.
    map_groups(g.edges(), map)
}

/// Reserve the owner, assign the slots, append the edges and open their
/// channels.
fn stage_add(
    g: ComposedGraph<'static>,
    authority: AddAuthority,
    assignment: Option<(u16, u32)>,
    map: &[u8; 256],
    signings: &[Signing],
    stage: Option<Stage>,
) -> Result<StagedAdd, AddError> {
    let header = *g.header();
    let mut st = StagedAdd {
        graph: g,
        slots: [0; MAX_ADD_MODULES],
        authority,
        handle: OWNER_NODE,
        owner_uid: header.owner_uid,
        edge_base: sched().edge_count,
        done: 0,
        pending: None,
        _stage: stage,
    };
    if authority != AddAuthority::Node {
        st.handle = reserve_owner(&header, authority, assignment)?;
        if let Err(e) = assign_slots(&mut st) {
            sched().owners.free(st.handle);
            return Err(e);
        }
        for (k, &signing) in signings.iter().enumerate().take(st.n()) {
            sched().module_signing[st.slot(k)] = signing;
        }
    }
    // Each slot's domain and pre-pass flag before its edges: an edge with an
    // interrupt-mode end is bridged by its ends' domains.
    for (k, m) in st.graph.modules().enumerate() {
        let slot = st.slot(k);
        let s = sched();
        s.domain_id[slot] = m.domain;
        s.pre_pass[slot] = m.pre_pass;
    }
    if let Err(e) = append_edges(&st, map) {
        if authority != AddAuthority::Node {
            sched().owners.free(st.handle);
        }
        return Err(e);
    }
    bind_slots(&st);
    Ok(st)
}

/// The owner a workload's add runs as: lowest free slot and a monotonic
/// generation, the rule a host composer allocates by. One identity is one
/// owner.
fn reserve_owner(
    header: &graph::Header,
    authority: AddAuthority,
    assignment: Option<(u16, u32)>,
) -> Result<OwnerHandle, AddError> {
    if sched().owners.find_by_uid(header.owner_uid).is_some() {
        return Err(AddError::OwnerExists);
    }
    let handle = sched()
        .owners
        .alloc(header.owner_uid)
        .ok_or(AddError::OwnerSlotsExhausted)?;
    if let Some((slot, generation)) = assignment {
        if handle.slot != slot || handle.generation != generation {
            sched().owners.free(handle);
            return Err(AddError::PlanMismatch);
        }
    }
    sched()
        .owners
        .set_caps(handle, header.state_cap, header.buffer_cap);
    if let AddAuthority::Creator(idx) = authority {
        sched().owners.set_node_authority(handle);
        log::info!(
            "[splice] owner slot {} acts with the node's authority, placed by module {idx}",
            handle.slot
        );
    } else {
        // A workload's add holds an uncapped storage line; a `CREATE`
        // installs the one its header names over it.
        sched().owners.set_line(handle, OWNER_LINE_STORAGE, 0);
    }
    Ok(handle)
}

/// A workload's slots: the lowest free `Empty` slot each, within the plan's
/// ceiling.
fn assign_slots(st: &mut StagedAdd) -> Result<(), AddError> {
    let n = st.n();
    let s = sched();
    let mut scan = 0usize;
    let ceiling = crate::kernel::sys::resource_ledger::ceiling(
        crate::abi::contracts::resource::POOL_MODULE_SLOTS,
    ) as usize;
    for g_slot in st.slots.iter_mut().take(n) {
        let slot = loop {
            if scan >= ceiling
                || (scan >= module_slots() && s.grow_module_tables(scan + 1).is_err())
            {
                log::warn!(
                    "[splice] add refused: pool 'module_slots' at its ceiling of {ceiling} \
                     (derived + live-add reserve)"
                );
                crate::kernel::sys::resource_ledger::deny(
                    crate::abi::contracts::resource::POOL_MODULE_SLOTS,
                );
                return Err(AddError::NoFreeSlot);
            }
            let candidate = scan;
            scan += 1;
            // A torn-down module's memory is kept while a provider may still
            // write into a span lent from it; an empty slot stamped with a
            // live owner is held by another add still staging.
            let stamp = super::module_owner(candidate);
            if matches!(s.modules[candidate], ModuleSlot::Empty)
                && !crate::kernel::ipc::lend::slot_quarantined(candidate)
                && (stamp.is_node() || s.owners.lookup(stamp).is_none())
            {
                break candidate;
            }
        };
        *g_slot = slot as ModuleId;
    }
    Ok(())
}

/// Append the add's edges at the end of the edge table and open their
/// channels; on refusal nothing is left appended or open.
fn append_edges(st: &StagedAdd, map: &[u8; 256]) -> Result<(), AddError> {
    let e = st.e();
    let edge_base = st.edge_base;
    let edge_ceiling = crate::kernel::sys::resource_ledger::ceiling(
        crate::abi::contracts::resource::POOL_CHANNELS,
    ) as usize;
    if edge_base + e > edge_ceiling
        || (edge_base + e > sched().edges.len() && sched().grow_edge_tables(edge_base + e).is_err())
    {
        log::warn!(
            "[splice] add refused: pool 'channels' at its ceiling of {edge_ceiling} edges \
             (derived + live-add reserve)"
        );
        crate::kernel::sys::resource_ledger::deny(crate::abi::contracts::resource::POOL_CHANNELS);
        return Err(AddError::TooManyEdges);
    }
    // A workload's lane resolves now (step 5 checked it does); a node
    // graph's target is one of the graph's own modules, which declares its
    // lanes as it instantiates, so its lane ends resolve in `finish`.
    let resolve = |end: Endpoint| -> usize {
        match end {
            Endpoint::New(l) => st.slot(usize::from(l)),
            Endpoint::Existing(g) | Endpoint::Tap(g) => usize::from(g),
            Endpoint::Lane { target, .. } => {
                crate::kernel::workload::lanes::resolve(target).unwrap_or(LANE_PENDING)
            }
            Endpoint::Caller(_) => caller().unwrap_or(0),
        }
    };
    for (i, r) in st.graph.edges().enumerate() {
        let from = resolve(r.from);
        let to = resolve(r.to);
        let tap_source = match r.from {
            Endpoint::Tap(_) => sched().ports[from].out_chans[usize::from(r.from_port)],
            _ => -1,
        };
        let mut edge = Edge::new_indexed(
            from,
            "out",
            r.from_port,
            to,
            if r.to_ctrl { "ctrl" } else { "in" },
            r.to_port,
        );
        edge.tap = tap_source >= 0;
        edge.tap_source = tap_source;
        edge.lane = match (r.from, r.to) {
            (Endpoint::Lane { .. }, _) => LaneEnd::From,
            (_, Endpoint::Lane { .. }) => LaneEnd::To,
            _ => LaneEnd::None,
        };
        fill_edge(&mut edge, &r, map);
        sched().edges[edge_base + i] = edge;
    }

    // What sizes and gates the new edges: each new module's declared port
    // capacities and mailbox flags, and the protection level its params ask
    // for (a gated module reaches channels only through the gateway).
    {
        // SAFETY: scheduler-thread graph-mutation context.
        let loader = unsafe { super::static_loader() };
        for (k, m) in st.graph.modules().enumerate() {
            let slot = st.slot(k);
            super::collect_one_module_hints(
                resolving_loader(m.name_hash, loader),
                &entry_of(&m, slot),
                slot,
            );
            // The level admission checked: the node's from its params, a
            // workload's set by the kernel (`workload_level`, decided again
            // here from the same facts rather than carried on the stack).
            let level = if st.authority == AddAuthority::Node {
                super::params_level(m.params)
            } else {
                let ldr = resolving_loader(m.name_hash, loader);
                let lm = ldr.find_by_name_hash(m.name_hash).ok();
                match workload_level(m.name_hash, lm.as_ref(), core::ptr::eq(ldr, loader)) {
                    Ok(l) => l,
                    Err(why) => {
                        clear_edge_range(edge_base, e);
                        return Err(why);
                    }
                }
            };
            sched().protection[slot] = level;
            if level.is_gated() {
                crate::kernel::sys::hal::protection_set_enabled(true);
            }
        }
    }
    let unwind = |opened: bool| {
        if opened {
            super::close_channels(&sched().edges[edge_base..edge_base + e]);
        }
        clear_edge_range(edge_base, e);
    };
    if e > 0 && super::open_channels(&mut sched().edges[edge_base..edge_base + e]) < 0 {
        unwind(true);
        return Err(AddError::ChannelOpenFailed);
    }
    // Each tap's fresh channel mirrors the tapped port's: one mirror per
    // channel.
    for i in edge_base..edge_base + e {
        let edge = sched().edges[i];
        if edge.tap
            && !crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, edge.channel)
        {
            detach_taps(edge_base, i - edge_base);
            unwind(true);
            return Err(AddError::BadEndpoint);
        }
    }
    // Two in-place writers on one group, or a zero-copy edge into a gated
    // module, are refused before any module runs.
    if !super::validate_buffer_groups(&sched().edges[edge_base..edge_base + e])
        || !zero_copy_ungated(edge_base, e)
    {
        detach_taps(edge_base, e);
        unwind(true);
        return Err(AddError::BufferGroupRefused);
    }
    if st.authority != AddAuthority::Node && charge_rings(st, edge_base, e).is_err() {
        log::warn!(
            "[splice] owner slot {} refused: its rings exceed its buffer cap",
            st.handle.slot
        );
        detach_taps(edge_base, e);
        unwind(true);
        return Err(AddError::BufferCapExceeded);
    }
    // Edges with an interrupt-mode end move through a bridge ring.
    super::wire_isr_bridges(&mut sched().edges[edge_base..edge_base + e]);
    sched().edge_count = edge_base + e;
    super::log_dma_owned_edges(edge_base, e);
    Ok(())
}

/// Charge `owner` every ring the add's edges `edges[base..base+count]`
/// opened, lane rings included, each once: an edge sharing a ring an
/// earlier edge opened (a mailbox group's alias) carries no charge. The
/// edge that opened a ring records which of its ends is the owner's, so
/// whichever teardown closes the ring releases the charge ([`release_ring`]).
/// Nothing is charged on refusal.
fn charge_rings(st: &StagedAdd, base: usize, count: usize) -> Result<(), ()> {
    let owner = st.handle;
    let s = sched();
    let mut total: u64 = 0;
    for i in base..base + count {
        let ch = s.edges[i].channel;
        if ch < 0 || s.edges[base..i].iter().any(|x| x.channel == ch) {
            continue;
        }
        total += fluxor_contracts::ring_size::arena_bytes(
            crate::kernel::ipc::channel::channel_ring_bytes(ch),
        );
    }
    let total = u32::try_from(total).map_err(|_| ())?;
    s.owners
        .charge(owner, OWNER_LINE_BUFFER, u64::from(total), false)
        .map_err(|_| ())?;
    for (i, r) in (base..base + count).zip(st.graph.edges()) {
        let ch = s.edges[i].channel;
        if ch < 0 || s.edges[base..i].iter().any(|x| x.channel == ch) {
            continue;
        }
        s.edges[i].charge = if r.from.new_index().is_some() {
            super::EdgeCharge::Producer
        } else {
            super::EdgeCharge::Consumer
        };
    }
    Ok(())
}

/// Release the ring `edge` carries the charge of, from the owner charged:
/// called as the ring closes, before the module at the charged end leaves
/// its slot.
pub(super) fn release_ring(edge: &Edge) {
    let end = match edge.charge {
        super::EdgeCharge::None => return,
        super::EdgeCharge::Producer => edge.from_module,
        super::EdgeCharge::Consumer => edge.to_module,
    };
    let bytes = fluxor_contracts::ring_size::arena_bytes(
        crate::kernel::ipc::channel::channel_ring_bytes(edge.channel),
    );
    sched()
        .owners
        .release(super::module_owner(end), OWNER_LINE_BUFFER, bytes as u64);
}

/// No zero-copy edge of `edges[base..base+count]` touches a gated module: a
/// gated module's channels stay kernel memory it reaches only through the
/// gateway, which copies.
fn zero_copy_ungated(base: usize, count: usize) -> bool {
    for e in sched().edges[base..base + count].iter() {
        if e.buffer_group == 0 {
            continue;
        }
        for m in [e.from_module, e.to_module] {
            if super::module_level(m).is_gated() {
                log::error!(
                    "[graph] module {m} is gated and sits on a zero-copy edge; a gated \
                     module reaches channels only through the gateway"
                );
                return false;
            }
        }
    }
    true
}

/// Port tables and slot stamps: the new modules' ports, and every running
/// module a new edge attaches to (its channel table is rebuilt from every
/// committed edge; its ready gate is left alone); every slot stamped with
/// the owner before any module instantiates, so `module_new` runs as its
/// owner.
fn bind_slots(st: &StagedAdd) {
    for k in 0..st.n() {
        let slot = st.slot(k);
        if !super::populate_module_ports_from_edges(slot, slot) {
            log::error!("[graph] port limit exceeded for module {slot}");
        }
    }
    for r in st.graph.edges() {
        for end in [r.from, r.to] {
            if let Endpoint::Existing(x) = end {
                super::populate_module_ports_from_edges(usize::from(x), usize::from(x));
            }
        }
    }
    for k in 0..st.n() {
        super::set_module_owner(st.slot(k), st.handle);
    }
}

/// A module record as the instantiation path takes it.
fn entry_of(m: &ModuleRecord<'_>, slot: usize) -> ModuleEntry {
    ModuleEntry {
        name_hash: m.name_hash,
        id: slot as ModuleId,
        domain_id: m.domain,
        pre_pass: m.pre_pass,
        params_ptr: if m.params.is_empty() {
            core::ptr::null()
        } else {
            m.params.as_ptr()
        },
        params_len: m.params.len(),
        budget: record_budget(m),
    }
}

/// Seat `b` on `slot`'s fault record: a fresh record (a slot a freed owner
/// left keeps nothing of its fault history) carrying the budget.
pub fn seat_step_budget(slot: usize, b: StepBudget) {
    let mut fi = ModuleFaultInfo::new();
    fi.step_deadline_us = b.deadline_us;
    fi.step_deadline_burst_us = b.burst_us;
    fi.policy = b.policy;
    sched().fault_info[slot] = fi;
}

// ── Instantiation ───────────────────────────────────────────────────────────

/// Instantiate `max` more of the add's modules, each as the owner its slot
/// is stamped with: from the loader when it resolves the name (through the
/// platform's module host where it has one), else from the native registry.
/// `Ok(true)` once every module is in. A load that completes later holds
/// the node's graph (`Ok(false)` with [`StagedAdd::loading`]: the caller
/// waits and calls again) and refuses a workload's. An error rolls the whole
/// add back.
pub fn instantiate_batch(st: &mut StagedAdd, max: usize) -> Result<bool, AddError> {
    let n = st.n();
    // The batch counts from the module a completing load holds.
    let last = n.min(st.done.saturating_add(max));
    if st.pending.is_some() && !complete_load(st)? {
        return Ok(false);
    }
    while st.done < last {
        if !instantiate_next(st)? {
            return Ok(false);
        }
    }
    Ok(st.done == n)
}

/// Poll the load module `done` is waiting on: `true` once it is in.
#[inline(never)]
fn complete_load(st: &mut StagedAdd) -> Result<bool, AddError> {
    let Some(mut pending) = st.pending.take() else {
        return Ok(true);
    };
    let k = st.done;
    // SAFETY: `pending` is the load this add started for module `k`.
    match unsafe { pending.try_complete() } {
        Ok(Some(dynamic)) => {
            super::store_dynamic_module(st.slot(k), dynamic);
            settle(st, k)?;
            Ok(true)
        }
        Ok(None) => {
            st.pending = Some(pending);
            Ok(false)
        }
        Err(e) => {
            e.log("scheduler");
            // What its construction held goes back before the slot is.
            drop(pending);
            rollback(st, k + 1);
            Err(AddError::Instantiate)
        }
    }
}

/// Instantiate module `done` and settle it: `false` when its load completes
/// later and the node's graph holds it.
#[inline(never)]
fn instantiate_next(st: &mut StagedAdd) -> Result<bool, AddError> {
    let k = st.done;
    let slot = st.slot(k);
    let entry = entry_of(&module_at(&st.graph, k), slot);
    seat_step_budget(slot, entry.budget);
    match instantiate_one(&entry, slot) {
        Ok(None) => {}
        Ok(Some(pending)) if st.authority == AddAuthority::Node => {
            st.pending = Some(pending);
            return Ok(false);
        }
        Ok(Some(pending)) => {
            // SAFETY: `pending` is the loader handle just returned for
            // `slot`.
            unsafe { pending.abort() };
            rollback(st, k + 1);
            return Err(AddError::WouldBlock);
        }
        Err(err) => {
            log::error!(
                "[splice] module {:#010x} at slot {slot}: {}",
                entry.name_hash,
                err.name()
            );
            rollback(st, k + 1);
            return Err(err);
        }
    }
    settle(st, k)?;
    Ok(true)
}

/// Instantiate one module into `slot`: `Some` with a load that completes
/// later.
fn instantiate_one(
    entry: &ModuleEntry,
    slot: usize,
) -> Result<Option<DynamicModulePending>, AddError> {
    // SAFETY: scheduler-thread graph-mutation context.
    let loader = resolving_loader(entry.name_hash, unsafe { super::static_loader() });
    match loader.find_by_name_hash(entry.name_hash) {
        Ok(lm) => match native::loaded_module_host() {
            None => instantiate_pic(loader, slot, entry),
            Some(host) => {
                let s = sched();
                super::set_module_grants(slot, lm.manifest_grants());
                s.module_code_base[slot] = lm.code_base() as usize;
                s.module_code_size[slot] = lm.header.code_size;
                let code = (lm.code_base(), lm.header.code_size as usize);
                instantiate_native(host, Some(code), entry, slot)
            }
        },
        Err(_) => match native::lookup(entry.name_hash) {
            Some(vt) => instantiate_native(vt, None, entry, slot),
            None => Err(AddError::UnknownModule),
        },
    }
}

/// Build a native module of `vt` into `slot`; `code` the payload a
/// loaded-module host instantiates.
#[inline(never)]
fn instantiate_native(
    vt: &'static native::NativeVtable,
    code: Option<(*const u8, usize)>,
    entry: &ModuleEntry,
    slot: usize,
) -> Result<Option<DynamicModulePending>, AddError> {
    // The kernel's own params tags (protection, IRQ, interrupt budget), as
    // a PIC module's are read at its load.
    super::parse_protection_config(slot, entry.params());
    let init = NativeInit {
        slot,
        params: entry.params(),
        code,
    };
    let module = super::with_module_context(slot, || NativeModule::new(vt, &init))
        .map_err(|_| AddError::Instantiate)?;
    let s = sched();
    s.modules[slot] = ModuleSlot::Native(module);
    super::set_module_type_hash(slot, entry.name_hash);
    s.deferred_ready[slot] = false;
    Ok(None)
}

/// Instantiate a PIC module into `slot`.
fn instantiate_pic(
    loader: &ModuleLoader,
    slot: usize,
    entry: &ModuleEntry,
) -> Result<Option<DynamicModulePending>, AddError> {
    let s = sched();
    match super::instantiate_one_module(
        loader,
        entry,
        slot,
        slot,
        &mut s.edges,
        &mut s.modules,
        &mut s.ports,
    ) {
        InstantiateResult::Done => Ok(None),
        InstantiateResult::Pending(pending) => Ok(Some(pending)),
        InstantiateResult::Error(_) => Err(AddError::Instantiate),
    }
}

/// Module `k` is in: its state charged to the owner its slot is stamped
/// with (past the owner's admitted cap the whole add rolls back), and its
/// ready gate as its header says.
fn settle(st: &mut StagedAdd, k: usize) -> Result<(), AddError> {
    let slot = st.slot(k);
    let owner = super::module_owner(slot);
    if !owner.is_node() {
        let footprint = super::module_state_footprint(slot);
        if sched()
            .owners
            .charge(owner, OWNER_LINE_STATE, u64::from(footprint), false)
            .is_err()
        {
            let state = sched().owners.line(owner, OWNER_LINE_STATE);
            let (charged, cap) = state.map_or((0, 0), |l| (l.used, l.cap));
            let buffers = sched()
                .owners
                .line(owner, OWNER_LINE_BUFFER)
                .map_or(0, |l| l.used);
            log::warn!(
                "[splice] owner slot {} refused: module state {} + {} exceeds its admitted \
                 state_cap {} (buffers {})",
                owner.slot,
                charged,
                footprint,
                cap,
                buffers,
            );
            rollback(st, k + 1);
            return Err(AddError::StateCapExceeded);
        }
    }
    let s = sched();
    // Ready as the module's header says: a deferred-ready module waits for
    // its own `Ready`.
    s.ready[slot] = !s.deferred_ready[slot];
    s.finished[slot] = false;
    s.upstream_mask[slot].clear_all();
    s.completion_mask[slot].clear_all();
    st.done = k + 1;
    Ok(())
}

// ── Publication ─────────────────────────────────────────────────────────────

/// Publish an add whose every module has instantiated: hand its lanes to
/// their targets, gate its modules on each other and on the contract
/// providers they wait for, splice its order into each domain's order with
/// every peer core parked, hand its interrupt-mode modules to their
/// dispatchers and activate the owner. Each lane resolves here by the name
/// its target declared ([`lanes::resolve`]), a node graph's included, and
/// its edges take the target as their end. A lane that resolves nowhere or
/// that the target cannot take rolls the whole add back.
///
/// [`lanes::resolve`]: crate::kernel::workload::lanes::resolve
pub fn finish(mut st: StagedAdd) -> Result<OwnerHandle, AddError> {
    debug_assert!(st.complete());
    let handle = st.handle;
    let edge_base = st.edge_base;
    let n = st.n();
    let e = st.e();
    for (i, r) in st.graph.edges().enumerate() {
        let Endpoint::Lane { key, target } = r.to else {
            continue;
        };
        let events_edge = st.graph.edges().position(|x| x.from == r.to);
        let commands = sched().edges[edge_base + i].channel;
        let events = events_edge.map_or(-1, |j| sched().edges[edge_base + j].channel);
        let reader = events_edge
            .and_then(|j| st.graph.edges().nth(j))
            .map(|x| x.to);
        let owner = lane_owner(&st, r.from, reader);
        let rc = match (owner, crate::kernel::workload::lanes::resolve(target)) {
            (None, _) => crate::kernel::sys::errno::EACCES,
            (Some(owner), Some(slot)) => {
                let s = sched();
                s.edges[edge_base + i].to_module = slot;
                if let Some(j) = events_edge {
                    s.edges[edge_base + j].from_module = slot;
                }
                // SAFETY: scheduler thread; both channels were opened for
                // this owner's edges.
                unsafe {
                    crate::kernel::workload::lanes::attach(owner, key, slot, commands, events)
                }
            }
            (Some(_), None) => crate::kernel::sys::errno::ENODEV,
        };
        if rc != 0 {
            log::warn!(
                "[splice] owner slot {} lane {key} to {target:#010x} refused: {rc}",
                handle.slot,
            );
            rollback(&mut st, n);
            return Err(AddError::LaneAttachFailed);
        }
    }
    // The ready gate between the new modules: a module waits on each module
    // of the graph that feeds it from earlier in the graph's order (an edge
    // back up the order closes a cycle the composer accepted, and gating it
    // would deadlock the cycle); completion waits on every feeder.
    let position = |l: u16| st.graph.order().position(|m| m == l);
    for r in st.graph.edges() {
        if let (Endpoint::New(a), Endpoint::New(b)) = (r.from, r.to) {
            let (from, to) = (st.slot(usize::from(a)), st.slot(usize::from(b)));
            let s = sched();
            s.completion_mask[to].set(from);
            if position(a) < position(b) {
                s.upstream_mask[to].set(from);
            }
        }
    }
    let system = st.authority == AddAuthority::Node;
    super::gate_contract_consumers(if system { None } else { Some(handle) });
    downstream_latency(&st);

    let parked = crate::kernel::sys::hal::smp_quiesce_peers();
    let mut affected: u32 = 0;
    for l in st.graph.order() {
        let slot = st.slot(usize::from(l));
        affected |= super::splice_into_order(slot);
    }
    sched().active_module_count += n;
    super::refresh_domains(affected);
    // Wake-on-write for the new edges: same domain, direct edges only. An
    // edge the platform splits across domains wakes at delivery (the
    // platform's cross-domain bridging binds it there); a live add is not
    // bridged, and such an edge of its is served by the readable-channel
    // scan.
    {
        let s = sched();
        for edge in s.edges[edge_base..edge_base + e].iter() {
            if !edge.wake_on_write
                || edge.channel < 0
                || edge.bridge_slot >= 0
                || edge.consumer_channel >= 0
                || edge.edge_class == crate::kernel::boot::config::EdgeClass::CrossCore
                || s.domain_id[edge.from_module] != s.domain_id[edge.to_module]
            {
                continue;
            }
            crate::kernel::ipc::channel::channel_set_wake_module(
                edge.channel,
                edge.to_module as i32,
            );
        }
    }
    if system {
        register_isr_modules(&st);
        sched().prepare_in_progress = false;
    } else {
        sched().owners.set_state(handle, OwnerState::Active);
    }
    super::rebuild_resident_graph_index();
    if parked {
        crate::kernel::sys::hal::smp_release_peers();
    }
    Ok(handle)
}

/// Each new module's downstream latency, sinks first: the most any module
/// it feeds reports plus that module's own.
fn downstream_latency(st: &StagedAdd) {
    let s = sched();
    let n = st.n();
    for i in 0..n {
        let Some(l) = st.graph.order().nth(n - 1 - i) else {
            continue;
        };
        let m = st.slot(usize::from(l));
        let mut most = 0u32;
        for e in s.edges[..s.edge_count].iter() {
            if e.channel >= 0 && e.from_module == m && e.to_module < module_slots() {
                let to = e.to_module;
                most = most.max(s.module_latency[to].saturating_add(s.downstream_latency[to]));
            }
        }
        s.downstream_latency[m] = most;
    }
}

/// Hand the node's interrupt-mode modules to their dispatchers, then start
/// the timer dispatcher at the shortest period among the `timer` domains
/// that registered one, each core's own shortest recorded beside it.
fn register_isr_modules(st: &StagedAdd) {
    let s = sched();
    let mut registered = 0usize;
    let mut min_period_us = u32::MAX;
    let mut core_min_us = [u32::MAX; MAX_DOMAINS];
    for k in 0..st.n() {
        match super::register_isr_module(s, &s.modules, st.slot(k), true) {
            Some(super::IsrRegistration::Timer { period_us, core }) => {
                min_period_us = min_period_us.min(period_us);
                if let Some(c) = core_min_us.get_mut(usize::from(core)) {
                    *c = (*c).min(period_us);
                }
                registered += 1;
            }
            Some(super::IsrRegistration::Irq) => registered += 1,
            None => {}
        }
    }
    if min_period_us < u32::MAX {
        log::info!(
            "[isr] starting the timer dispatcher, period={min_period_us}us, {registered} modules"
        );
        for (core, &us) in core_min_us.iter().enumerate() {
            crate::kernel::exec::timer::set_core_period_us(
                core,
                if us == u32::MAX { 0 } else { us },
            );
        }
        crate::kernel::exec::timer::start(min_period_us);
    }
}

/// The owner a lane of this add is attached for: a workload's add's own;
/// in the node's graph, the owner stamped on the module writing the lane's
/// commands, so a module the owner plan gives a workload reaches the
/// network as that workload, under its grants and its drain. `None` when
/// the module reading the lane's events is another workload's: a lane
/// carries one owner's traffic, which the node may read and no other
/// workload may.
fn lane_owner(st: &StagedAdd, writer: Endpoint, reader: Option<Endpoint>) -> Option<OwnerHandle> {
    if st.authority != AddAuthority::Node {
        return Some(st.handle);
    }
    let owner_of = |e: Endpoint| match e {
        Endpoint::New(a) => Some(super::module_owner(st.slot(usize::from(a)))),
        _ => None,
    };
    let owner = owner_of(writer).unwrap_or(st.handle);
    match reader.and_then(owner_of) {
        Some(r) if r != owner && !r.is_node() => None,
        _ => Some(owner),
    }
}

/// Roll a staged add back.
pub fn abandon(mut st: StagedAdd) {
    if let Some(pending) = st.pending.take() {
        // SAFETY: the load this add started; it is abandoned with the add.
        unsafe { pending.abort() };
    }
    let done = st.done;
    rollback(&mut st, done);
}

/// Undo a staged add: the first `instantiated` slots hold modules, freed
/// with what they opened; every slot goes back to the node; the channels
/// close, the edges go and the owner is revoked.
fn rollback(st: &mut StagedAdd, instantiated: usize) {
    let handle = st.handle;
    let edge_base = st.edge_base;
    let e = st.e();
    let system = st.authority == AddAuthority::Node;
    if !system {
        crate::kernel::module::provider::notify_owner_released(handle);
    }
    // The lanes this add attached: its owner's, and in the node's graph
    // those of each owner stamped on one of its modules ([`lane_owner`]).
    // SAFETY: scheduler thread, before the owner's channels close.
    unsafe { crate::kernel::workload::lanes::detach(handle) };
    if system {
        for k in 0..st.n() {
            let owner = super::module_owner(st.slot(k));
            if owner != handle {
                // SAFETY: as above.
                unsafe { crate::kernel::workload::lanes::detach(owner) };
            }
        }
    }
    debug_assert_eq!(
        crate::kernel::workload::lanes::lanes_of(handle),
        0,
        "a rolled-back add leaves no lane of its owner"
    );
    let s = sched();
    for k in 0..instantiated.min(st.n()) {
        let slot = st.slot(k);
        crate::kernel::module::syscalls::release_module_handles(slot as ModuleId);
        super::free_module_state(slot);
        s.type_hash[slot] = 0;
        s.slot_generation[slot] = s.slot_generation[slot].wrapping_add(1);
    }
    for k in 0..st.n() {
        super::set_module_owner(st.slot(k), OWNER_NODE);
    }
    if e > 0 {
        detach_taps(edge_base, e);
        super::close_channels(&s.edges[edge_base..edge_base + e]);
    }
    clear_edge_range(edge_base, e);
    if s.edge_count == edge_base + e {
        s.edge_count = edge_base;
    }
    if !system {
        s.owners.free(handle);
    }
    st.done = st.n();
}

/// Stop mirroring into every tap edge in `edges[base..base+count]`.
pub(crate) fn detach_taps(base: usize, count: usize) {
    let s = sched();
    for i in base..base + count {
        let edge = s.edges[i];
        if edge.tap && edge.tap_source >= 0 {
            crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, -1);
        }
    }
}

/// Reset `edges[base..base+count]` to the empty default.
fn clear_edge_range(base: usize, count: usize) {
    let s = sched();
    for i in base..base + count {
        s.edges[i] = Edge::simple(0, 0);
    }
}

/// Admit, instantiate and publish `bytes` within this call.
///
/// # Safety
/// `bytes` stays valid and unchanged for the call.
pub unsafe fn apply(
    bytes: &[u8],
    creator: Option<usize>,
    assignment: Option<(u16, u32)>,
) -> Result<OwnerHandle, AddError> {
    // SAFETY: the caller's contract; the add completes within this call.
    let mut st = unsafe { admit(bytes, creator, assignment) }?;
    instantiate_batch(&mut st, usize::MAX)?;
    finish(st)
}

/// [`apply`] for the module syscall: `creator` is the calling module, which
/// a flagged add acts for. The negative errno on refusal.
///
/// # Safety
/// As [`apply`].
pub unsafe fn apply_encoded_by(bytes: &[u8], creator: usize) -> Result<OwnerHandle, i32> {
    // SAFETY: forwarded contract.
    unsafe { apply(bytes, Some(creator), None) }.map_err(AddError::code)
}

/// [`apply`] with no creator and no placement: a resident workload in the
/// config image, read in place. The negative errno on refusal.
///
/// # Safety
/// As [`apply`].
pub unsafe fn apply_borrowed(bytes: &[u8]) -> Result<OwnerHandle, i32> {
    // SAFETY: forwarded contract.
    unsafe { apply(bytes, None, None) }.map_err(AddError::code)
}

/// [`admit`] with no creator and no placement, for an add its caller
/// finishes over several calls. The negative errno on refusal.
///
/// # Safety
/// As [`admit`].
pub unsafe fn begin_encoded(bytes: &[u8]) -> Result<StagedAdd, i32> {
    // SAFETY: forwarded contract.
    unsafe { admit(bytes, None, None) }.map_err(AddError::code)
}

/// Write an owner handle as an add reports it: `[slot:u16 LE][generation:u32
/// LE]` into `out[0..6]`.
pub fn write_handle(out: &mut [u8], handle: OwnerHandle) {
    out[0..2].copy_from_slice(&handle.slot.to_le_bytes());
    out[2..6].copy_from_slice(&handle.generation.to_le_bytes());
}

// ── Reading a blob before it is admitted ────────────────────────────────────

/// One `Endpoint::Caller` edge of a graph: its position among the graph's
/// edges, its key, and whether it runs into the caller.
#[derive(Clone, Copy, Default)]
pub struct CallerEdge {
    pub index: usize,
    pub key: u8,
    pub into_caller: bool,
}

/// The `Caller` edges of a graph, in edge order, into `out`; how many there
/// are, or `None` for a blob the codec refuses or more edges than `out`.
/// An add appends a graph's edges in order, so edge `index` lands at the
/// edge count before the add plus `index`.
pub fn caller_edges(blob: &[u8], out: &mut [CallerEdge]) -> Option<usize> {
    let g = graph::decode(blob).ok()?;
    let mut n = 0;
    for (index, e) in g.edges().enumerate() {
        let found = match (e.from, e.to) {
            (Endpoint::Caller(k), _) => Some((k, false)),
            (_, Endpoint::Caller(k)) => Some((k, true)),
            _ => None,
        };
        if let Some((key, into_caller)) = found {
            *out.get_mut(n)? = CallerEdge {
                index,
                key,
                into_caller,
            };
            n += 1;
        }
    }
    Some(n)
}

/// Whether `contract` is one only claims grant: a contract a module may
/// provide, served by a provider rather than across an edge.
fn claim_granted(contract: u8) -> bool {
    u16::from(contract) < 64
        && crate::abi::registry::module_providable(u16::from(contract))
        && !crate::abi::registry::contract_is_edge(u16::from(contract))
}

/// The grants one module holds with the params it will be instantiated
/// with: its manifest words, each grant its conditions narrow kept only
/// where they hold, and each contract only claims grant kept only while one
/// of its claims holds.
fn effective_module_grants(
    m: &crate::kernel::module::loader::LoadedModule,
    params: &[u8],
) -> [u64; 2] {
    use crate::abi::wire::fmod::{
        claim, cond, for_each_condition, grant_holds, subject_holds, RESOURCE_CLAIM_AT,
        RESOURCE_RECORD_SIZE,
    };
    let mut g = m.manifest_grants();
    let block = m.manifest_conditions();
    let mut conditioned = [0u64; 2];
    for_each_condition(block, |c| {
        if c.subject <= cond::SUBJECT_OP_GRANT && c.index < 64 {
            conditioned[c.subject as usize] |= 1u64 << c.index;
        }
    });
    for word in 0..2u8 {
        let mut bits = conditioned[word as usize];
        while bits != 0 {
            let bit = bits.trailing_zeros() as u8;
            bits &= bits - 1;
            if !grant_holds(block, word, bit, params) {
                g[word as usize] &= !(1u64 << bit);
            }
        }
    }
    let (mut claimed, mut held) = (0u64, 0u64);
    for (i, r) in m
        .manifest_resources()
        .chunks_exact(RESOURCE_RECORD_SIZE)
        .enumerate()
    {
        if !claim_granted(r[0]) {
            continue;
        }
        claimed |= 1u64 << r[0];
        if r[RESOURCE_CLAIM_AT] != claim::CONDITIONAL
            || subject_holds(block, cond::SUBJECT_CLAIM, i as u8, params).unwrap_or(true)
        {
            held |= 1u64 << r[0];
        }
    }
    g[0] &= !(claimed & !held);
    g
}

/// The contracts the modules of a graph require served as configured, a bit
/// per contract id: each resource record on a contract a module may provide
/// that [`fmod::claim_required`] says is required for the module's params.
/// `None` for a blob the codec refuses.
///
/// [`fmod::claim_required`]: crate::abi::wire::fmod::claim_required
pub fn module_required_claims(blob: &[u8]) -> Option<u64> {
    use crate::abi::wire::fmod::{claim_required, RESOURCE_RECORD_SIZE};
    let g = graph::decode(blob).ok()?;
    // SAFETY: scheduler-thread context, as every caller of the add.
    let loader = unsafe { super::static_loader() };
    let mut required = 0u64;
    for m in g.modules() {
        let Ok(lm) = resolving_loader(m.name_hash, loader).find_by_name_hash(m.name_hash) else {
            continue;
        };
        let block = lm.manifest_conditions();
        for (i, r) in lm
            .manifest_resources()
            .chunks_exact(RESOURCE_RECORD_SIZE)
            .enumerate()
        {
            if claim_granted(r[0]) && claim_required(r, i as u8, block, m.params) {
                required |= 1u64 << r[0];
            }
        }
    }
    Some(required)
}

/// The contracts the modules a graph names provide, a bit per contract id,
/// each resolved against the loader as [`module_grants`] resolves it. `None`
/// for a blob the codec refuses.
pub fn module_provides(blob: &[u8]) -> Option<u64> {
    let g = graph::decode(blob).ok()?;
    // SAFETY: scheduler-thread context, as every caller of the add.
    let loader = unsafe { super::static_loader() };
    let mut provides = 0u64;
    for m in g.modules() {
        if let Ok(lm) = resolving_loader(m.name_hash, loader).find_by_name_hash(m.name_hash) {
            let (ids, n) = lm.manifest_provides();
            for &c in &ids[..n] {
                if c < 64 {
                    provides |= 1u64 << c;
                }
            }
        }
    }
    Some(provides)
}

/// The union of the grants of the modules a graph names, each resolved
/// against the loader; a name the loader cannot resolve adds nothing (the
/// add refuses it). `None` for a blob the codec refuses. Read before the
/// add, so a policy on what a graph may hold is decided before anything is
/// allocated.
pub fn module_grants(blob: &[u8]) -> Option<[u64; 2]> {
    let g = graph::decode(blob).ok()?;
    // SAFETY: scheduler-thread context, as every caller of the add.
    let loader = unsafe { super::static_loader() };
    let mut grants = [0u64; 2];
    for m in g.modules() {
        if let Ok(lm) = resolving_loader(m.name_hash, loader).find_by_name_hash(m.name_hash) {
            let w = effective_module_grants(&lm, m.params);
            grants[0] |= w[0];
            grants[1] |= w[1];
        }
    }
    Some(grants)
}

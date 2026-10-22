//! Minimal live graph mutation — add and tear down a self-contained
//! subgraph owner on a *running* graph, without a destructive rebuild.
//!
//! This is the keystone primitive behind OTA, orchestrated workloads, and
//! REPL subgraph-exec: the same mechanism under different lifecycle
//! policies. The surface is deliberately just add and teardown, plus the
//! per-owner reclaim teardown needs — enough for the cheapest caller, an
//! ephemeral REPL subgraph, which is what keeps it to the core.
//!
//! Two operations, both synchronous and owner-scoped:
//!   * [`apply_add`]  — allocate an owner, instantiate its modules, open its
//!     edges, and *append* it to the execution order. No existing owner is
//!     paused, reset, or re-ordered; the phase stays `Running` throughout.
//!   * [`free_owner`] — stop the owner's modules (one-shot drain then
//!     terminate), close its edges, reclaim its state, and revoke the handle
//!     (the generation guard in [`crate::kernel::workload::owner`] rejects it thereafter).
//!
//! Splice, not re-topo: `exec_order` is a flat `[u8; MAX_MODULES]` consumed via
//! `exec_order_count`, so a new owner's (internally topo-sorted) modules are
//! appended at the tail and the freed owner's entries are compacted out — the
//! whole-graph topological sort is never re-run, so existing modules keep their
//! slot, state, and schedule position. A NEW producer → EXISTING consumer edge
//! costs one tick of (buffered, lossless) latency; existing modules are never
//! gated on a new owner (their `upstream_mask` is never touched), so a buggy
//! ephemeral owner can't stall the system.
//!
//! On bcm2712 the per-domain dispatch tables are spliced too, with every peer
//! core parked (see the live-splice section below). A PIC module loads within
//! the add: a load that cannot complete synchronously refuses it
//! ([`AddError::WouldBlock`]). Replacing part of a running owner is not part
//! of this surface. Gated on `multitenant` (host-linux + bcm2712 enable it;
//! bare-metal rp compiles it out at zero cost).

use super::{
    module_slots, BuiltInModule, Edge, FanDirection, InstantiateResult, ModuleId, ModuleSlot,
    SchedulerState, MAX_MODULES, SCHED,
};
use crate::kernel::boot::config::ModuleEntry;
use crate::kernel::exec::step_guard::{
    FaultPolicy, ModuleFaultInfo, BURST_MULTIPLIER, DEFAULT_STEP_DEADLINE_US,
};
use crate::kernel::module::loader::ModuleLoader;
use crate::kernel::workload::owner::{OwnerHandle, OwnerState, OWNER_SYSTEM};

/// Largest subgraph one `apply_add` admits. The working set is stack-only
/// and bounded by these caps: decoding an encoded add holds every module and
/// edge record at once (~7 KiB at 64 / 128), well inside the kernel stack of
/// the targets that compile live mutation (bcm2712 and linux). A message
/// broker with durable storage is ~14 modules and ~49 edges.
pub const MAX_ADD_MODULES: usize = 64;
/// Largest edge count one `apply_add` admits.
pub const MAX_ADD_EDGES: usize = 128;
// The FLXA wire carries both counts in a byte.
const _: () = assert!(MAX_ADD_MODULES <= u8::MAX as usize);
const _: () = assert!(MAX_ADD_EDGES <= u8::MAX as usize);

/// Tees and merges the add inserts where a port of the subgraph's own
/// modules carries several edges, as the boot graph does. Each fanned port
/// takes at least two edges, and an edge sits in at most one output fan and
/// one input fan, so the edges bound the fans.
const MAX_FAN_MODULES: usize = MAX_ADD_EDGES;
/// The subgraph as apply_add stages it: the caller's modules and edges, then
/// one tee or merge per fanned port and the edge joining it to that port.
const WORK_MODULES: usize = MAX_ADD_MODULES + MAX_FAN_MODULES;
const WORK_EDGES: usize = MAX_ADD_EDGES + MAX_FAN_MODULES;
// `Endpoint::New` names a staged module in a byte.
const _: () = assert!(WORK_MODULES <= u8::MAX as usize + 1);

/// Reserved `Endpoint::Existing` global index marking a **net-facing
/// spare-lane edge** in a FLXA blob. The workload manager composes a
/// `net=own` workload's FLXA off-node and cannot express
/// `Endpoint::ExistingChannel`: the FLXA wire has no channel-endpoint kind,
/// and the spare-lane channel id is a kernel runtime value unknowable
/// off-node. So a `net=own` template emits its net-facing producer edge with
/// `to = Existing(SPARE_LANE_SENTINEL)`; the metal backend
/// (`workload_graph.rs`) resolves the boot merge's next free spare lane, and
/// the decode rewrites the edge to `ExistingChannel(lane)` (see
/// [`begin_add_encoded`] and [`apply_add_encoded_spare_lane`]). `0xFFFF` is
/// never a live module slot (`MAX_MODULES` ≪ `0xFFFF`), so the marker is
/// unambiguous, and the wire carries it as an ordinary existing endpoint
/// (`decode_endpoint(1, 0xFFFF)` is `Existing(0xFFFF)`).
pub const SPARE_LANE_SENTINEL: u16 = 0xFFFF;

/// How a new module is instantiated.
pub enum ModuleSource {
    /// A PIC `.fmod` resolved by `name_hash`, instantiated via the loader.
    /// Must complete synchronously (`InstantiateResult::Done`); an async
    /// (`Pending`) load yields [`AddError::WouldBlock`].
    Pic(ModuleEntry),
    /// A statically-linked built-in (host shims, REPL/test emitters). The
    /// module resolves its channels from its port table (populated before
    /// instantiation) — see the proof test.
    Builtin(BuiltInModule),
}

/// One new module in the added subgraph. Consumed by [`apply_add`] (the source
/// is moved out), so the caller's slice is left holding placeholders.
pub struct AddModule {
    pub source: ModuleSource,
    pub domain_id: u8,
    /// The step budget the subgraph declares for this module, admitted by
    /// [`admit_step_budget`] before anything is allocated and seated on the
    /// module's fault record when it instantiates. It is the module's only
    /// source of deadline and fault policy: an add refuses params that
    /// carry a fault tag, or any other node tag
    /// ([`super::is_node_param_tag`]).
    pub budget: StepBudget,
}

/// A module's step budget as a subgraph declares it: the same three settings
/// a base graph's YAML gives a module (`step_deadline_us`,
/// `step_deadline_burst_us`, `fault_policy`), carried per module by the FLXA
/// module record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepBudget {
    /// Step deadline in microseconds; `0` is the node's default
    /// (`DEFAULT_STEP_DEADLINE_US`).
    pub deadline_us: u32,
    /// Burst re-step deadline in microseconds; `0` is
    /// `deadline × BURST_MULTIPLIER`.
    pub burst_us: u32,
    /// What an overrun or step error does. A workload is admitted only a
    /// policy confined to the faulting module
    /// ([`FaultPolicy::confined_to_module`]).
    pub policy: FaultPolicy,
}

impl StepBudget {
    /// No declaration: the node's default deadline, the multiplier burst,
    /// `Skip`. What a module gets when its graph says nothing.
    pub const NODE_DEFAULT: StepBudget = StepBudget {
        deadline_us: 0,
        burst_us: 0,
        policy: FaultPolicy::Skip,
    };

    /// Whether the budget declares a deadline of either kind. An undeclared
    /// budget runs on the node's defaults and is never measured against the
    /// ceiling, as a base-graph module that declares none is not.
    pub const fn declares_deadline(&self) -> bool {
        self.deadline_us != 0 || self.burst_us != 0
    }

    /// The burst deadline the budget runs under: the declared one, else the
    /// declared (or default) step deadline × `BURST_MULTIPLIER` — the figure
    /// the burst path uses at run time.
    pub const fn effective_burst_us(&self) -> u32 {
        if self.burst_us != 0 {
            self.burst_us
        } else {
            let d = if self.deadline_us != 0 {
                self.deadline_us
            } else {
                DEFAULT_STEP_DEADLINE_US
            };
            d.saturating_mul(BURST_MULTIPLIER)
        }
    }
}

/// Absolute ceiling on any declared deadline, step or burst, in
/// microseconds. Mirrors the build's `HARD_BURST_CAP_US`: no module can
/// authorise stalling the scheduler longer than this.
pub const STEP_BUDGET_HARD_CAP_US: u32 = 100_000;

/// The burst ceiling, in domain ticks: a declared deadline fits in this many
/// of the domain's ticks. Mirrors the build's `16 × domain tick_us` rule.
pub const STEP_BUDGET_TICKS: u32 = 16;

/// The longest deadline, step or burst, a module in `domain_id` may declare
/// on this node: `STEP_BUDGET_TICKS` of the domain's shortest tick (its
/// `tick_min_us` when the domain runs adaptive cadence, else its tick),
/// never above [`STEP_BUDGET_HARD_CAP_US`]. The figures are the node's, not
/// the ones the subgraph's author built against.
pub fn step_budget_ceiling_us(domain_id: u8) -> u32 {
    let d = domain_id as usize;
    let tick = if super::domain_adaptive_flags(d) & super::ADAPTIVE_FLAG_CADENCE != 0 {
        super::domain_tick_min_us(d)
    } else {
        super::domain_tick_us(d)
    };
    let tick = if tick == 0 { super::tick_us() } else { tick };
    tick.saturating_mul(STEP_BUDGET_TICKS)
        .min(STEP_BUDGET_HARD_CAP_US)
}

/// Why a declared step budget was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The policy reaches past the faulting module (`Restart`,
    /// `RestartGraph`).
    Policy,
    /// The step deadline is above the domain's ceiling.
    Deadline { ceiling_us: u32 },
    /// The effective burst deadline is above the domain's ceiling.
    Burst { ceiling_us: u32 },
}

/// Admit `b` for a module of a workload in `domain_id`, bounded by the
/// node's policy: a policy confined to the module, and a step and burst
/// deadline each within [`step_budget_ceiling_us`]. Refuses rather than
/// clamps, as the build refuses a base graph's over-ceiling deadline — a
/// module silently given less time than its graph declared would fault for
/// a budget nobody chose.
pub fn admit_step_budget(b: &StepBudget, domain_id: u8) -> Result<(), BudgetRefusal> {
    if !b.policy.confined_to_module() {
        return Err(BudgetRefusal::Policy);
    }
    if !b.declares_deadline() {
        return Ok(());
    }
    let ceiling_us = step_budget_ceiling_us(domain_id);
    if b.deadline_us > ceiling_us {
        return Err(BudgetRefusal::Deadline { ceiling_us });
    }
    if b.effective_burst_us() > ceiling_us {
        return Err(BudgetRefusal::Burst { ceiling_us });
    }
    Ok(())
}

/// Seat an admitted budget on `slot`'s fault record: a fresh record (a slot
/// a freed owner left keeps nothing of its fault history) carrying the
/// budget's deadlines and policy.
fn seat_step_budget(slot: usize, b: StepBudget) {
    let mut fi = ModuleFaultInfo::new();
    fi.step_deadline_us = b.deadline_us;
    fi.step_deadline_burst_us = b.burst_us;
    fi.policy = b.policy;
    sched().fault_info[slot] = fi;
}

/// An endpoint of an [`AddEdge`]: a new module (subgraph-local index) or a
/// module already live in the running graph (global slot index).
#[derive(Clone, Copy)]
pub enum Endpoint {
    New(u8),
    Existing(u16),
    /// A pre-existing **shared channel** by id — an attachable-lane merge's
    /// spare input lane. Only valid as an edge `to`: the producer (`from`, a
    /// `New` module) is wired to write into this exact channel — which a boot
    /// merge already reads — instead of `apply_add` opening a fresh ring. This
    /// is how a runtime `net=own` workload reaches the node's one shared `ip`
    /// through the merge without any runtime merge-state mutation.
    /// Direct-API only: the FLXA wire has no channel-endpoint kind,
    /// mirroring `AddEdge::wake_on_write`'s direct-only status.
    ExistingChannel(i32),
    /// A **tap** on a live module's output port (global slot index), valid
    /// only as an edge `from`. The edge gets a fresh channel that the kernel
    /// fills with a copy of every write to that port's channel — lossy, never
    /// back-pressuring the producer — and the tapped module's own wiring is
    /// untouched. FLXA endpoint kind 2. One tap per channel.
    Tap(u16),
    /// The node's network, through a lane of the workload's own
    /// (`kernel::workload::net_attach`). As an edge `to` it receives a new
    /// module's net commands; as an edge `from` it delivers that module's net
    /// events. The key pairs the two: each key names exactly one edge of
    /// each direction, and each key is a lane. FLXA endpoint kind 3.
    Net(u8),
    /// The module that is staging this subgraph (see [`set_caller`]): the
    /// workload manager's own lanes into the graph it creates, for what it
    /// must exchange with it — a key's record, a control input. Each key
    /// names at most one edge of each direction. FLXA endpoint kind 4.
    Caller(u8),
}

/// `to_port_index` bit on an FLXA edge that addresses the consumer's control
/// input rather than a data input; the low bits are the control port index.
pub const CTRL_PORT_BIT: u8 = 0x80;

/// The module staging the next subgraph, for `Endpoint::Caller`.
static mut CALLER: Option<usize> = None;

/// Name the module on whose behalf the next `apply_add` stages a subgraph,
/// so `Endpoint::Caller` resolves to it; `None` after the add.
pub fn set_caller(slot: Option<usize>) {
    // SAFETY: scheduler thread only, like the add it brackets.
    unsafe { *core::ptr::addr_of_mut!(CALLER) = slot };
}

fn caller() -> Option<usize> {
    // SAFETY: as `set_caller`.
    unsafe { *core::ptr::addr_of!(CALLER) }
}

/// One edge of the added subgraph. `from`/`to` are subgraph-local for new
/// modules and global for existing ones.
#[derive(Clone, Copy)]
pub struct AddEdge {
    pub from: Endpoint,
    pub from_port_index: u8,
    pub to: Endpoint,
    pub to_port_index: u8,
    /// Per-edge ring-buffer byte hint (0 = derive from module hints).
    pub buffer_bytes: u32,
    /// Wake-on-write: a successful write on this edge latches the
    /// consumer's event-wake bit and rings the scheduler doorbell — same
    /// semantics as `wake: true` on a base-graph wiring entry, bound with
    /// the same rules as `prepare_graph`'s wiring pass (same-domain
    /// direct edges only). NOT expressible through the FLXA wire codec:
    /// the per-edge record has no reserved space, so
    /// `apply_add_encoded` always decodes it as `false`; only direct
    /// [`apply_add`] callers can set it.
    pub wake_on_write: bool,
}

impl AddEdge {
    /// A slot of a staging array no edge occupies.
    const UNUSED: AddEdge = AddEdge {
        from: Endpoint::New(0),
        from_port_index: 0,
        to: Endpoint::New(0),
        to_port_index: 0,
        buffer_bytes: 0,
        wake_on_write: false,
    };
}

/// A new owner's subgraph. `modules` is `&mut` because the sources are moved
/// out during instantiation; the caller's array is consumed.
pub struct AddSubgraph<'a> {
    pub owner_uid: [u8; 16],
    pub modules: &'a mut [AddModule],
    pub edges: &'a [AddEdge],
    /// Admitted hard caps from the resource profile; 0 = unlimited (the
    /// REPL/ephemeral default). Stored on the owner. `state_cap` bounds the
    /// owner's module state, charged as each module instantiates;
    /// `buffer_cap` is recorded and reported, and channel buffers are not
    /// charged against it.
    pub state_cap: u32,
    pub buffer_cap: u32,
    /// Whose authority the new owner acts with.
    pub authority: AddAuthority,
}

/// The authority an add asks for its owner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddAuthority {
    /// Its own: a workload. Every add but the one below.
    Own,
    /// Its creator's: the module at this global index places the subgraph
    /// to act on its behalf. Admitted only when that module acts with the
    /// node's authority; the new owner then acts with the node's
    /// ([`crate::kernel::workload::owner::Authority::Node`]), its lifecycle
    /// its own.
    Creator(usize),
}

/// Why `apply_add` failed. A failure leaves the running graph bit-identical.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddError {
    TooManyModules,
    TooManyEdges,
    OwnerSlotsExhausted,
    PlanMismatch,
    NoFreeSlot,
    BadEndpoint,
    ChannelOpenFailed,
    Instantiate,
    /// A PIC load returned `Pending`: it cannot complete within the add.
    WouldBlock,
    /// The owner's admitted `state_cap` would be exceeded by this subgraph's
    /// module state. Refused at admission rather than allowed to draw down the
    /// shared state arena at its neighbours' expense.
    StateCapExceeded,
    /// The node's net provider refused a lane.
    NetAttachFailed,
    /// An owner already carries the subgraph's identity: live, or staged by
    /// an add still in progress. One identity is one owner.
    OwnerExists,
    /// A module's declared step budget is outside what the node admits a
    /// workload ([`admit_step_budget`]). Refused before anything is
    /// allocated.
    BudgetRefused,
    /// A module's params carry a node tag
    /// ([`super::is_node_param_tag`]): a grant only the node's own graph
    /// makes. Refused before anything is allocated.
    NodeParamRefused,
    /// The add asked for its creator's authority, and the creator does not
    /// act with the node's. Refused before anything is allocated.
    AuthorityRefused,
}

impl AddError {
    /// The negative errno the syscall surface answers. A malformed subgraph
    /// is `EINVAL` before any of these: each refusal here is distinct from
    /// it, and from every other, wherever the meaning differs.
    pub fn code(self) -> i32 {
        use crate::kernel::sys::errno;
        match self {
            AddError::TooManyModules | AddError::TooManyEdges => errno::E2BIG,
            AddError::OwnerSlotsExhausted | AddError::NoFreeSlot | AddError::StateCapExceeded => {
                errno::ENOSPC
            }
            AddError::PlanMismatch | AddError::BadEndpoint => errno::EINVAL,
            AddError::ChannelOpenFailed => errno::ENOMEM,
            AddError::Instantiate => errno::ENOEXEC,
            AddError::WouldBlock => errno::EAGAIN,
            AddError::NetAttachFailed => errno::EBUSY,
            AddError::OwnerExists => errno::EEXIST,
            AddError::BudgetRefused => errno::ERANGE,
            AddError::NodeParamRefused | AddError::AuthorityRefused => errno::EACCES,
        }
    }
}

/// Why `free_owner` failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreeError {
    /// The handle names the system owner, which cannot be freed.
    NotWorkload,
    /// The handle is unknown or its generation no longer matches (already
    /// freed / reused) — the fail-closed path.
    StaleHandle,
    /// The owner is still being added (`Reserved`): the add that staged it
    /// publishes it or rolls it back, and nothing else frees it — freeing it
    /// underneath the add would leave the add placing modules for an owner
    /// that is gone.
    Staged,
}

impl FreeError {
    pub fn code(self) -> i32 {
        match self {
            FreeError::NotWorkload => -1,
            FreeError::StaleHandle => -2,
            FreeError::Staged => -3,
        }
    }
}

/// Why `owner_pause` / `owner_resume` failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PauseError {
    /// The handle names the system owner, which can never be paused.
    NotWorkload,
    /// Unknown handle or stale generation (already freed / reused).
    StaleHandle,
    /// The owner is in a state the verb does not apply to (`Reserved`,
    /// `Draining`, `Revoked`) — pause is Active↔Paused only; a draining
    /// owner is past the point of reversibility.
    BadState,
}

impl PauseError {
    pub fn code(self) -> i32 {
        match self {
            PauseError::NotWorkload => -1,
            PauseError::StaleHandle => -2,
            PauseError::BadState => -3,
        }
    }
}

/// Borrow the scheduler state. Single-threaded scheduler context; callers must
/// not hold the returned reference across a call that re-derives `SCHED`.
#[inline]
fn sched() -> &'static mut SchedulerState {
    // SAFETY: scheduler-thread-exclusive; mirrors `sched_mut()`.
    unsafe { &mut *core::ptr::addr_of_mut!(SCHED) }
}

// ============================================================================
// Live-splice: multicore quiesce + per-domain dispatch-table splice
//
// ============================================================================
//
// bcm2712 cores step the PER-DOMAIN `domain_exec_order` (via
// `step_domain_modules` / `..._poll`), which only the boot-only
// `finalize_resident_graphs` populates — so a *runtime* `apply_add`/`free_owner`
// that mutates only the flat `exec_order` stages a subgraph the domain runners
// never step. The per-domain splice closes that: after the exec_order
// mutation, on bcm2712, splice
// the affected domains' `domain_exec_order` incrementally
// (`scheduler::recompute_domain_orders`, byte-identical to a full recompute for
// those domains) while every peer domain core is parked.
//
// Single-domain / non-bcm builds (host-linux, host-wasm, qemu-virt single-core)
// step the flat `exec_order` directly and never read `domain_exec_order`, so the
// splice is compiled out there and `apply_add`/`free_owner` stay byte-identical.

/// Bit `d` set ⇒ a module in the mutation touches domain `d`. Bounded by
/// `multicore::MAX_DOMAINS` (≤ 32, so a `u32` mask is always sufficient).
#[cfg(feature = "smp")]
#[inline]
fn domain_bit(domain_id: u8) -> u32 {
    1u32 << (domain_id as usize).min(crate::kernel::sys::hal::smp_max_domains() - 1)
}

/// Park every peer domain core for a live schedule mutation, returning `true`
/// iff a quiesce was actually taken (so the caller must release it). At runtime
/// on bcm2712 this is the `request_quiesce`/`wait_parked` park-all-secondaries
/// pattern (`bcm2712/multicore.rs`); at boot (pre-SMP, `!smp_online`) and on
/// single-domain hosts it is a no-op — the mutation runs single-threaded.
///
/// **Invariant:** primary-core-only. `request_quiesce` is defined for domain 0;
/// the runtime callers (`apply_add`/`free_owner`) must run on the primary
/// domain's scheduler context (the metal `workload` provider dispatches on the
/// system graph, which lives on domain 0).
#[inline]
fn quiesce_peers() -> bool {
    crate::kernel::sys::hal::smp_quiesce_peers()
}

/// Release a quiesce taken by [`quiesce_peers`]. No-op when `parked` is false.
#[inline]
fn release_peers(parked: bool) {
    if parked {
        crate::kernel::sys::hal::smp_release_peers();
    }
}

// ============================================================================
// apply_add
// ============================================================================

/// Add `sub` as a new owner to the running graph. On success returns the new
/// [`OwnerHandle`]. `assignment`, when `Some((slot, generation))`, asserts the
/// kernel-allocated owner matches the placement a host-side composer chose
/// (the composer's allocation is deterministic, and the kernel's must agree
/// with it); pass `None` for a standalone caller.
///
/// Atomic: the execution-order splice is the last mutation, so any earlier
/// failure rolls back to a bit-identical graph and the scheduler never observes
/// a half-built owner.
pub fn apply_add(
    sub: AddSubgraph<'_>,
    assignment: Option<(u16, u32)>,
) -> Result<OwnerHandle, AddError> {
    let mut staged = begin_add(sub, assignment)?;
    instantiate_batch(&mut staged, usize::MAX)?;
    finish_staged(staged)
}

/// Stage `sub`'s subgraph: its fans expanded, its owner reserved, its slots
/// assigned and its channels open, with no module instantiated yet. The
/// caller instantiates with [`instantiate_batch`] and publishes with
/// [`finish_staged`], so a large subgraph can be admitted a few modules per
/// scheduler step.
pub fn begin_add(
    sub: AddSubgraph<'_>,
    assignment: Option<(u16, u32)>,
) -> Result<StagedAdd, AddError> {
    let n = sub.modules.len();
    let e = sub.edges.len();
    if n > MAX_ADD_MODULES {
        return Err(AddError::TooManyModules);
    }
    if e > MAX_ADD_EDGES {
        return Err(AddError::TooManyEdges);
    }
    // Every declared step budget is admitted before anything is allocated:
    // one module over the node's ceiling refuses the whole subgraph.
    for (i, m) in sub.modules.iter().enumerate() {
        if let Err(why) = admit_step_budget(&m.budget, m.domain_id) {
            log::warn!(
                "[live] module {} of the add refused its step budget (deadline {} us, burst {} us, \
                 policy {:?}): {:?}",
                i,
                m.budget.deadline_us,
                m.budget.burst_us,
                m.budget.policy,
                why,
            );
            return Err(AddError::BudgetRefused);
        }
        if let ModuleSource::Pic(entry) = &m.source {
            if let Some(tag) = super::params_node_tag(entry.params()) {
                log::warn!(
                    "[live] module {i} of the add refused: its params carry node tag {tag:#04x}"
                );
                return Err(AddError::NodeParamRefused);
            }
        }
    }
    let mut mods: [AddModule; WORK_MODULES] = core::array::from_fn(|_| AddModule {
        source: ModuleSource::Pic(ModuleEntry::default()),
        domain_id: 0,
        budget: StepBudget::NODE_DEFAULT,
    });
    for (w, m) in mods.iter_mut().zip(sub.modules.iter_mut()) {
        w.source = core::mem::replace(&mut m.source, ModuleSource::Pic(ModuleEntry::default()));
        w.domain_id = m.domain_id;
        w.budget = m.budget;
    }
    let mut edges = [AddEdge::UNUSED; WORK_EDGES];
    edges[..e].copy_from_slice(sub.edges);
    let mut mailbox = [false; WORK_EDGES];
    let (n, e) = expand_fans(&mut mods, n, &mut edges, e, &mut mailbox);
    begin_staged(
        sub.owner_uid,
        sub.state_cap,
        sub.buffer_cap,
        sub.authority,
        mods,
        n,
        edges,
        e,
        &mailbox[..e],
        assignment,
    )
}

/// A live add between its staging and its publication: the owner is
/// reserved, the slots are assigned, the edges and channels are open, and
/// the modules instantiate a batch at a time.
pub struct StagedAdd {
    handle: OwnerHandle,
    owner_uid: [u8; 16],
    n: usize,
    e: usize,
    edge_base: usize,
    local_to_global: [usize; WORK_MODULES],
    mods: [AddModule; WORK_MODULES],
    edges: [AddEdge; WORK_EDGES],
    /// Modules instantiated so far: the next local index.
    done: usize,
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
        self.done == self.n
    }
}

/// Steps 1 to 5 of an add over the staged (fan-expanded) subgraph:
/// `mailbox[i]` marks an edge around a record-carrying fan, which gets a
/// channel of its own in mailbox mode.
#[allow(
    clippy::too_many_arguments,
    clippy::large_types_passed_by_value,
    reason = "the staged subgraph's parts, moved in so the add owns them until it is published or rolled back"
)]
fn begin_staged(
    owner_uid: [u8; 16],
    state_cap: u32,
    buffer_cap: u32,
    authority: AddAuthority,
    mut mods: [AddModule; WORK_MODULES],
    n: usize,
    edges: [AddEdge; WORK_EDGES],
    e: usize,
    mailbox: &[bool],
    assignment: Option<(u16, u32)>,
) -> Result<StagedAdd, AddError> {
    let sub = AddSubgraph {
        owner_uid,
        modules: &mut mods[..n],
        edges: &edges[..e],
        state_cap,
        buffer_cap,
        authority,
    };

    // 0. An add on its creator's behalf is admitted only from a module that
    //    acts with the node's authority: a workload cannot pass on what it
    //    does not hold, nor gain it through an add of its own.
    if let AddAuthority::Creator(idx) = sub.authority {
        if idx >= module_slots()
            || !sched()
                .owners
                .authority_of(super::module_owner(idx))
                .is_system()
        {
            return Err(AddError::AuthorityRefused);
        }
    }

    // 1. Reserve the owner (lowest-free slot + monotonic generation — the same
    //    rule the host composer uses, so kernel-side allocation matches a plan).
    //    One identity is one owner: an identity already live, or staged by an
    //    add in progress, is refused rather than given a second owner.
    if sched().owners.find_by_uid(sub.owner_uid).is_some() {
        return Err(AddError::OwnerExists);
    }
    let handle = match sched().owners.alloc(sub.owner_uid) {
        Some(h) => h,
        None => return Err(AddError::OwnerSlotsExhausted),
    };
    if let Some((slot, generation)) = assignment {
        if handle.slot != slot || handle.generation != generation {
            sched().owners.free(handle);
            return Err(AddError::PlanMismatch);
        }
    }
    sched()
        .owners
        .set_caps(handle, sub.state_cap, sub.buffer_cap);
    // The default grant: a root of the owner's own. A workload `CREATE`
    // states its own grant over this before any of its modules runs. An
    // owner acting with the node's authority holds no root: it reaches the
    // node's storage as the node does.
    if let AddAuthority::Creator(idx) = sub.authority {
        sched().owners.set_node_authority(handle);
        log::info!(
            "[live] owner slot {} acts with the node's authority, placed by module {idx}",
            handle.slot
        );
    } else {
        sched().owners.set_storage_grant(
            handle,
            crate::kernel::workload::storage::StorageGrant::OwnRoot,
        );
    }

    // 2. Assign each new module the lowest-free `Empty` slot. NOT a watermark:
    //    freeing a non-last owner leaves holes, so we scan.
    let mut local_to_global = [0usize; WORK_MODULES];
    {
        let s = sched();
        let mut scan = 0usize;
        // The plan's ceiling: derived + live-add reserve. The tables may hold
        // more slots than that (a larger graph prepared earlier committed
        // them); the ceiling, not the committed count, is what admits.
        let ceiling = crate::kernel::sys::resource_ledger::ceiling(
            crate::abi::contracts::resource::POOL_MODULE_SLOTS,
        ) as usize;
        for (local, g) in local_to_global.iter_mut().take(n).enumerate() {
            let slot = loop {
                // Past the live slots: commit the next segment of the
                // per-module tables, within the plan's ceiling. Past the
                // ceiling the add is refused, naming the pool.
                if scan >= ceiling
                    || (scan >= module_slots() && s.grow_module_tables(scan + 1).is_err())
                {
                    // No free slot: undo the owner reservation and bail.
                    s.owners.free(handle);
                    let _ = local;
                    log::warn!(
                        "[live] add refused: pool 'module_slots' at its ceiling of {} \
                         (derived + live-add reserve)",
                        crate::kernel::sys::resource_ledger::ceiling(
                            crate::abi::contracts::resource::POOL_MODULE_SLOTS
                        )
                    );
                    crate::kernel::sys::resource_ledger::deny(
                        crate::abi::contracts::resource::POOL_MODULE_SLOTS,
                    );
                    return Err(AddError::NoFreeSlot);
                }
                let candidate = scan;
                scan += 1;
                // A torn-down module's memory is kept while a source may still
                // write into a buffer lent from it; the slot is not free yet.
                // Nor is an empty slot stamped with a live owner: another add,
                // staged and still instantiating, holds it.
                let stamp = super::module_owner(candidate);
                if matches!(s.modules[candidate], ModuleSlot::Empty)
                    && !crate::kernel::module::block_lend::slot_quarantined(candidate)
                    && (stamp.is_system() || s.owners.lookup(stamp).is_none())
                {
                    break candidate;
                }
            };
            *g = slot;
        }
    }

    // Resolve an endpoint to a global module index.
    let resolve = |ep: Endpoint| -> Option<usize> {
        match ep {
            Endpoint::New(l) => local_to_global[..n].get(l as usize).copied(),
            Endpoint::Existing(g) | Endpoint::Tap(g) => {
                let g = g as usize;
                if g < module_slots() && !matches!(sched().modules[g], ModuleSlot::Empty) {
                    Some(g)
                } else {
                    None
                }
            }
            // A raw channel id resolves to no module — attach edges are handled
            // out of band in the edge-build loop below.
            Endpoint::ExistingChannel(_) => None,
            // The node's net provider; the lane is attached once the subgraph
            // has instantiated.
            Endpoint::Net(_) => crate::kernel::workload::net_attach::provider_slot(),
            Endpoint::Caller(_) => caller().filter(|&g| {
                g < module_slots() && !matches!(sched().modules[g], ModuleSlot::Empty)
            }),
        }
    };

    // Each net key must name exactly one command edge (into the network) from
    // a new module and one event edge (out of it) to a new module.
    if !net_keys_paired(sub.edges) || !caller_keys_valid(sub.edges) {
        sched().owners.free(handle);
        return Err(AddError::BadEndpoint);
    }

    // 3. Append the new edges to `sched.edges[edge_base..]`.
    let edge_base = sched().edge_count;
    let edge_ceiling = crate::kernel::sys::resource_ledger::ceiling(
        crate::abi::contracts::resource::POOL_CHANNELS,
    ) as usize;
    if edge_base + e > edge_ceiling
        || (edge_base + e > sched().edges.len() && sched().grow_edge_tables(edge_base + e).is_err())
    {
        sched().owners.free(handle);
        log::warn!(
            "[live] add refused: pool 'channels' at its ceiling of {} edges \
             (derived + live-add reserve)",
            crate::kernel::sys::resource_ledger::ceiling(
                crate::abi::contracts::resource::POOL_CHANNELS
            )
        );
        crate::kernel::sys::resource_ledger::deny(crate::abi::contracts::resource::POOL_CHANNELS);
        return Err(AddError::TooManyEdges);
    }
    for (i, ae) in sub.edges.iter().enumerate() {
        let from = match resolve(ae.from) {
            Some(g) => g,
            None => {
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
        };
        // Attachable-lane merge: `to` names a
        // pre-existing shared spare-lane channel a boot merge already caches.
        // Wire the producer to write into THAT channel — no fresh ring — so its
        // frame reaches the shared consumer (metal `ip`) through the merge with
        // zero merge-state mutation. The lane must be a real, currently-FREE
        // lane of some live merge (producer-less ⇒ system-owned); anything else
        // is a bad endpoint.
        if let Endpoint::ExistingChannel(ch) = ae.to {
            let merge = match super::merge_owning_lane(ch) {
                Some(m) => m,
                None => {
                    sched().owners.free(handle);
                    return Err(AddError::BadEndpoint);
                }
            };
            if !super::channel_producer_owner(ch).is_system() {
                // Lane already carries a producer — refuse rather than create a
                // second producer on one SPSC lane.
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
            let mut edge = Edge::new_indexed(from, "out", ae.from_port_index, merge, "in", 0);
            edge.channel = ch;
            edge.shared_channel = true;
            edge.buffer_bytes = ae.buffer_bytes;
            edge.wake_on_write = ae.wake_on_write;
            sched().edges[edge_base + i] = edge;
            continue;
        }
        let to = match resolve(ae.to) {
            Some(g) => g,
            None => {
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
        };
        let tap_source = if let Endpoint::Tap(_) = ae.from {
            // The tapped port must be one the module already writes.
            let ports = &sched().ports[from];
            let p = ae.from_port_index as usize;
            let ch = if p < ports.out_count as usize {
                ports.out_chans[p]
            } else {
                -1
            };
            if ch < 0 || matches!(ae.to, Endpoint::Tap(_)) {
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
            ch
        } else {
            -1
        };
        let (to_port, to_index) = if ae.to_port_index & CTRL_PORT_BIT != 0 {
            ("ctrl", ae.to_port_index & !CTRL_PORT_BIT)
        } else {
            ("in", ae.to_port_index)
        };
        let mut edge = Edge::new_indexed(from, "out", ae.from_port_index, to, to_port, to_index);
        edge.tap = tap_source >= 0;
        edge.tap_source = tap_source;
        edge.buffer_bytes = ae.buffer_bytes;
        edge.wake_on_write = ae.wake_on_write;
        if mailbox[i] {
            // Its own group, distinct from every other edge this add opens:
            // the group is what makes the channel a mailbox, and a shared
            // group would alias two edges onto one channel.
            let Some(g) = super::fresh_record_group(&sched().edges[edge_base..edge_base + i])
            else {
                sched().owners.free(handle);
                return Err(AddError::ChannelOpenFailed);
            };
            edge.buffer_group = g;
        }
        sched().edges[edge_base + i] = edge;
    }

    // 4. Open only the new edges' channels, sized by the new modules' declared
    //    port capacities. On failure, close whatever opened and roll back (the
    //    appended edges are not yet committed to edge_count).
    {
        // SAFETY: scheduler-thread graph-mutation context.
        let loader = unsafe { super::static_loader() };
        for (local, m) in sub.modules.iter().enumerate().take(n) {
            if let ModuleSource::Pic(entry) = &m.source {
                super::collect_one_module_hints(
                    resolving_loader(entry.name_hash, loader),
                    entry,
                    local_to_global[local],
                );
            }
        }
    }
    if e > 0 {
        let rc = super::open_channels(&mut sched().edges[edge_base..edge_base + e]);
        if rc < 0 {
            super::close_channels(&sched().edges[edge_base..edge_base + e]);
            clear_edge_range(edge_base, e);
            sched().owners.free(handle);
            return Err(AddError::ChannelOpenFailed);
        }
    }
    // Attach each tap: its fresh channel becomes the mirror of the tapped
    // port's channel. A channel already tapped refuses the add (one mirror
    // per channel); nothing is committed yet, so the rollback is local.
    for i in edge_base..edge_base + e {
        let edge = sched().edges[i];
        if edge.tap
            && !crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, edge.channel)
        {
            detach_taps(edge_base, i - edge_base);
            super::close_channels(&sched().edges[edge_base..edge_base + e]);
            clear_edge_range(edge_base, e);
            sched().owners.free(handle);
            return Err(AddError::BadEndpoint);
        }
    }
    sched().edge_count = edge_base + e;

    // 5. Populate the new modules' port tables from the freshly opened edges so
    //    instantiation / lazy channel lookup sees them.
    for &slot in local_to_global.iter().take(n) {
        super::populate_module_ports_from_edges(slot, slot);
    }
    // Also (re)populate any EXISTING module that a new edge attaches to, so its
    // port table gains the freshly-opened data channels — e.g. an ssh module's
    // data_rx/data_tx ports bridging to a spawned `run` pipeline. This rebuilds the
    // module's channel lookup table from ALL committed edges; because
    // collect_channels places each channel at its edge's declared port index,
    // existing ports (net_in/net_out at index 0) are preserved and the new bridge
    // ports (index 1) are added. Only the channel table is touched — the module's
    // ready-gate mask is left alone (isolation).
    for ae in sub.edges.iter() {
        if let Endpoint::Existing(g) = ae.from {
            super::populate_module_ports_from_edges(g as usize, g as usize);
        }
        if let Endpoint::Existing(g) = ae.to {
            super::populate_module_ports_from_edges(g as usize, g as usize);
        }
    }

    // Every slot is stamped with the owner before any of its modules
    // instantiates: a module's `module_new` runs as its owner, so what it
    // allocates, opens and registers (its provider layers among them) is the
    // owner's, reached with the owner's authority, never with the node's
    // whose empty slot it took.
    for &slot in local_to_global.iter().take(n) {
        super::set_module_owner(slot, handle);
    }

    let _ = sub;
    Ok(StagedAdd {
        handle,
        owner_uid,
        n,
        e,
        edge_base,
        local_to_global,
        mods,
        edges,
        done: 0,
    })
}

/// Step 6 of an add, `max` modules at a time: instantiate each module, as
/// the owner its slot is stamped with. `Ok(true)` once every module is in.
/// An error rolls the whole add back; the staged add is then gone.
pub fn instantiate_batch(st: &mut StagedAdd, max: usize) -> Result<bool, AddError> {
    let n = st.n;
    let e = st.e;
    let handle = st.handle;
    let edge_base = st.edge_base;
    let last = n.min(st.done.saturating_add(max));
    while st.done < last {
        let local = st.done;
        let slot = st.local_to_global[local];
        let local_to_global = st.local_to_global;
        let m = &mut st.mods[local];
        let source = core::mem::replace(&mut m.source, ModuleSource::Pic(ModuleEntry::default()));
        // The admitted budget is in place before the module's first
        // instruction. Its params carry no fault tag (`begin_add` refused
        // any node tag), so the load leaves the record as seated.
        seat_step_budget(slot, m.budget);
        let res = match source {
            ModuleSource::Builtin(b) => {
                super::store_builtin_module(slot, b);
                Ok(())
            }
            ModuleSource::Pic(entry) => instantiate_pic(slot, &entry),
        };
        if let Err(err) = res {
            // Roll back: free this and any earlier instantiated slots, close
            // the new channels, drop the appended edges, revoke the owner.
            rollback_add(handle, &local_to_global[..n], local + 1, edge_base, e);
            st.done = n;
            return Err(err);
        }
        // Charge this module's state-arena draw against the owner's admitted
        // `state_cap` (cap 0 = unlimited). The allocation has already happened
        // — the loader is the only half that knows the size — so exceeding the
        // cap rolls the whole add back rather than trimming it: a subgraph is
        // admitted entire or not at all, and a half-admitted one would be a
        // graph nobody described.
        let footprint = super::module_state_footprint(slot);
        if sched().owners.charge_state(handle, footprint).is_err() {
            let (charged, _) = sched().owners.charged_bytes(handle);
            log::warn!(
                "[live] owner slot {} refused: module state {} + {} exceeds its admitted \
                 state_cap; raise the workload's cap or shrink the graph",
                handle.slot,
                charged,
                footprint,
            );
            rollback_add(handle, &local_to_global[..n], local + 1, edge_base, e);
            st.done = n;
            return Err(AddError::StateCapExceeded);
        }
        let domain_id = m.domain_id;
        let s = sched();
        s.ready[slot] = true;
        s.finished[slot] = false;
        s.domain_id[slot] = domain_id;
        // Ready-gate only on NEW upstream modules — never gate on existing ones,
        // and never modify an existing module's mask (isolation).
        s.upstream_mask[slot].clear_all();
        st.done = local + 1;
    }
    Ok(st.done == n)
}

/// Steps 7 and 8 of an add whose every module has instantiated: hand its
/// net lanes to the provider, gate the new modules on each other, splice
/// them into the schedule and activate the owner. A refused lane rolls the
/// whole add back.
pub fn finish_staged(st: StagedAdd) -> Result<OwnerHandle, AddError> {
    debug_assert!(st.complete());
    let n = st.n;
    let e = st.e;
    let handle = st.handle;
    let edge_base = st.edge_base;
    let local_to_global = st.local_to_global;
    let sub_edges = &st.edges[..e];
    // Hand each net key's two channels to the node's net provider as one lane
    // of this owner's. Every module has instantiated, so nothing it opens can
    // precede its lane; a refused lane rolls the whole add back.
    for (i, ae) in sub_edges.iter().enumerate() {
        let Endpoint::Net(key) = ae.to else {
            continue;
        };
        let commands = sched().edges[edge_base + i].channel;
        let events = sub_edges
            .iter()
            .position(|x| matches!(x.from, Endpoint::Net(k) if k == key))
            .map(|j| sched().edges[edge_base + j].channel)
            .unwrap_or(-1);
        // SAFETY: scheduler thread; both channels were opened above for
        // this owner's edges.
        let rc =
            unsafe { crate::kernel::workload::net_attach::attach(handle, key, commands, events) };
        if rc != 0 {
            log::warn!(
                "[live] owner slot {} net lane {key} refused: {rc}",
                handle.slot
            );
            rollback_add(handle, &local_to_global[..n], n, edge_base, e);
            return Err(AddError::NetAttachFailed);
        }
    }
    // Fill new modules' upstream masks from intra-owner edges (after all slots
    // are known) for deterministic ready-gating among the added modules.
    for ae in sub_edges.iter() {
        if let (Endpoint::New(a), Endpoint::New(b)) = (ae.from, ae.to) {
            if let (Some(&from), Some(&to)) = (
                local_to_global[..n].get(a as usize),
                local_to_global[..n].get(b as usize),
            ) {
                sched().upstream_mask[to].set(from);
            }
        }
    }

    // 7. Publish the subgraph into the live schedule. On bcm2712 every peer
    //    domain core is parked first: the exec_order splice,
    //    the per-domain dispatch-table splice, and the resident-graph reindex are
    //    the mutations a concurrently-stepping peer core must never observe half
    //    applied. No-op wrapper on single-domain hosts and at boot (both run
    //    single-threaded), so those paths stay byte-identical.
    let parked = quiesce_peers();

    //    Splice into the execution order: topo-sort the new modules over their
    //    internal edges, then append. Existing entries are untouched.
    let order = topo_order_new(&local_to_global[..n], sub_edges);
    {
        let s = sched();
        for &slot in order.iter().take(n) {
            let pos = s.exec_order_count;
            s.exec_order[pos] = slot as ModuleId;
            s.exec_order_count = pos + 1;
        }
        s.active_module_count += n;
    }

    // Per-domain splice (bcm2712 only): reproject the affected
    // domains' `domain_exec_order` from the freshly-spliced flat order so the
    // per-domain runners (`step_domain_modules`) step the new modules — not just
    // the flat-order path. Infallible (a bounded reprojection mirroring the boot
    // compute) and it runs AFTER the last fallible step (instantiation, step 6),
    // so `apply_add`'s atomic-rollback contract is preserved: any earlier failure
    // aborts before the exec_order/domain mutation and leaves the graph
    // bit-identical; once here the add is committed and cannot fail. Byte-
    // identical to a full recompute for the affected domains.
    #[cfg(feature = "smp")]
    {
        let mut affected: u32 = 0;
        for &slot in local_to_global.iter().take(n) {
            affected |= domain_bit(sched().domain_id[slot]);
        }
        super::recompute_domain_orders(affected);
    }

    // Wake-on-write wiring for the live-added edges — the same pass, with
    // the same skip set, that `prepare_graph` runs for base-graph edges:
    // bind `wake: true` edges' channels to their consumer so a successful
    // write latches the consumer's event-wake bit and rings the scheduler
    // doorbell. Same-domain direct edges only; anything the platform would
    // split across the SPSC pump (different domains, or
    // `EdgeClass::CrossCore`) must bind at consumer-side pump delivery
    // instead — a producer-side binding is the guaranteed-spurious
    // write-time wake — and the live path does no cross-domain bridging,
    // so such edges stay unbound and are served by the readable-channel
    // scan and the backstop. Runs after
    // instantiation (the last fallible step, and the point where the new
    // modules' `domain_id` is stamped), so a rollback never leaves a
    // binding behind.
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
            log::info!(
                "[wake] live edge {}→{} chan={} wake-on-write bound",
                edge.from_module,
                edge.to_module,
                edge.channel
            );
        }
    }

    // 8. Activate.
    sched().owners.set_state(handle, OwnerState::Active);
    // Refresh the multi-graph runner's bounded resident-graph index so the new
    // owner is multiplexed (and its pacer instance gets primed) on the next
    // pass. Bounded one-shot, off the hot path.
    super::rebuild_resident_graph_index();
    // Publication complete — release the parked peer cores (no-op if none).
    release_peers(parked);
    Ok(handle)
}

/// Roll a staged add back: what instantiated is freed, its channels close,
/// its edges go and its owner is revoked, as a failed add's would.
pub fn abandon_staged(st: StagedAdd) {
    rollback_add(
        st.handle,
        &st.local_to_global[..st.n],
        st.done,
        st.edge_base,
        st.e,
    );
}

/// Instantiate a PIC module into `slot`. Synchronous only: an async
/// (`Pending`) load is aborted and reported as [`AddError::WouldBlock`].
fn instantiate_pic(slot: usize, entry: &ModuleEntry) -> Result<(), AddError> {
    // SAFETY: scheduler-thread graph-mutation context; mirrors the Linux boot
    // instantiation path (disjoint sub-borrows of SCHED passed in).
    let loader = resolving_loader(entry.name_hash, unsafe { super::static_loader() });
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
        InstantiateResult::Done => Ok(()),
        // A load that cannot complete synchronously is refused; abort the
        // pending handle so no half-built slot lingers.
        InstantiateResult::Pending(pending) => {
            // SAFETY: `pending` is the loader handle just returned for `slot`.
            unsafe { pending.abort() };
            Err(AddError::WouldBlock)
        }
        InstantiateResult::Error(_) => Err(AddError::Instantiate),
    }
}

/// Whether every net key in `edges` names exactly one command edge (a new
/// module into the network) and one event edge (the network to a new module).
fn net_keys_paired(edges: &[AddEdge]) -> bool {
    for ae in edges {
        let key = match (ae.from, ae.to) {
            (Endpoint::New(_), Endpoint::Net(k)) | (Endpoint::Net(k), Endpoint::New(_)) => k,
            (Endpoint::Net(_), _) | (_, Endpoint::Net(_)) => return false,
            _ => continue,
        };
        let into = edges
            .iter()
            .filter(|x| matches!(x.to, Endpoint::Net(k) if k == key))
            .count();
        let out = edges
            .iter()
            .filter(|x| matches!(x.from, Endpoint::Net(k) if k == key))
            .count();
        if into != 1 || out != 1 {
            return false;
        }
    }
    true
}

/// Whether every caller key names at most one edge of each direction, each
/// between the caller and a new module.
fn caller_keys_valid(edges: &[AddEdge]) -> bool {
    for ae in edges {
        let key = match (ae.from, ae.to) {
            (Endpoint::New(_), Endpoint::Caller(k)) | (Endpoint::Caller(k), Endpoint::New(_)) => k,
            (Endpoint::Caller(_), _) | (_, Endpoint::Caller(_)) => return false,
            _ => continue,
        };
        let into = edges
            .iter()
            .filter(|x| matches!(x.to, Endpoint::Caller(k) if k == key))
            .count();
        let out = edges
            .iter()
            .filter(|x| matches!(x.from, Endpoint::Caller(k) if k == key))
            .count();
        if into > 1 || out > 1 {
            return false;
        }
    }
    true
}

/// Roll back a partially-applied add. The exec-order splice has not happened
/// yet, so only the staged slots (the first `instantiated` of them holding a
/// module), opened channels, and appended edges need undoing, then the owner
/// is revoked. Every staged slot goes back to the node, stamp included.
fn rollback_add(
    handle: OwnerHandle,
    slots: &[usize],
    instantiated: usize,
    edge_base: usize,
    e: usize,
) {
    // An add that failed part-way still ran `module_new` for the slots that did
    // instantiate, and those may already have asked a provider for resources.
    // Same edge, same ordering as `free_owner`: notify before anything is torn
    // down and while the handle still resolves.
    crate::kernel::module::provider::notify_owner_released(handle);
    // SAFETY: scheduler thread, before the owner's channels close.
    unsafe { crate::kernel::workload::net_attach::detach(handle) };
    let s = sched();
    for &slot in &slots[..instantiated.min(slots.len())] {
        // What a module that instantiated registered or opened (provider
        // layer, ioctl handler, events, timers) goes before its state does.
        crate::kernel::module::syscalls::release_module_handles(slot as ModuleId);
        // The module never stepped, so it lent nothing and its memory goes
        // back at once, with its protection domain and slot bookkeeping.
        super::free_module_state(slot);
        s.type_hash[slot] = 0;
        s.slot_generation[slot] = s.slot_generation[slot].wrapping_add(1);
    }
    for &slot in slots {
        super::set_module_owner(slot, OWNER_SYSTEM);
    }
    if e > 0 {
        detach_taps(edge_base, e);
        super::close_channels(&s.edges[edge_base..edge_base + e]);
    }
    clear_edge_range(edge_base, e);
    // `edge_count` was only advanced after a successful open; if we reach here
    // post-open, retract it.
    if s.edge_count == edge_base + e {
        s.edge_count = edge_base;
    }
    s.owners.free(handle);
}

/// Give every port of the subgraph's own modules (`New`, below `n`) that
/// carries several edges a tee (an output) or a merge (an input), as the boot
/// graph's fan pass does: one internal module per port, an edge joining it to
/// the port, and the fanned edges repacked onto its ports from 0. Ports the
/// boot graph leaves unfanned are left so here: a multi-inbound consumer's
/// data inputs, and a multi-outbound producer whose fan reaches exactly the
/// modules feeding it. A port carrying records (`FRAME_KIND_RECORD`) marks
/// every edge around its fan in `mailbox`. Returns the staged counts.
fn expand_fans(
    mods: &mut [AddModule; WORK_MODULES],
    n: usize,
    edges: &mut [AddEdge; WORK_EDGES],
    e: usize,
    mailbox: &mut [bool; WORK_EDGES],
) -> (usize, usize) {
    // SAFETY: scheduler-thread graph-mutation context, as every add.
    let node = unsafe { super::static_loader() };
    let (mut n2, mut e2) = (n, e);
    for dir in [FanDirection::Out, FanDirection::In] {
        for l in 0..n {
            // The edges staged before this module's pass. The joining edge
            // a fan adds is the port's only edge, so it never fans again.
            let scan = e2;
            let mut taken = [false; WORK_EDGES];
            for start in 0..scan {
                if taken[start] || !fan_touches(&edges[start], l, dir) {
                    continue;
                }
                let key = fan_port_key(&edges[start], dir);
                let mut group = [0usize; WORK_EDGES];
                let mut g = 0usize;
                for j in start..scan {
                    if !taken[j]
                        && fan_touches(&edges[j], l, dir)
                        && fan_port_key(&edges[j], dir) == key
                    {
                        taken[j] = true;
                        group[g] = j;
                        g += 1;
                    }
                }
                if g < 2 || fan_exempt(mods, l, edges, scan, &group[..g], dir, key) {
                    continue;
                }
                let kind = fan_frame_kind(node, mods, edges, &group[..g], l, dir, key);
                let record = kind == super::module_types::FRAME_KIND_RECORD;
                let f = n2;
                n2 += 1;
                mods[f] = AddModule {
                    source: ModuleSource::Pic(ModuleEntry {
                        name_hash: match dir {
                            FanDirection::Out => super::INTERNAL_TEE_HASH,
                            FanDirection::In => super::INTERNAL_MERGE_HASH,
                        },
                        domain_id: mods[l].domain_id,
                        frame_kind: kind,
                        ..ModuleEntry::default()
                    }),
                    domain_id: mods[l].domain_id,
                    budget: StepBudget::NODE_DEFAULT,
                };
                let wake = group[..g].iter().any(|&ei| edges[ei].wake_on_write);
                edges[e2] = match dir {
                    FanDirection::Out => AddEdge {
                        from: Endpoint::New(l as u8),
                        from_port_index: key,
                        to: Endpoint::New(f as u8),
                        ..AddEdge::UNUSED
                    },
                    FanDirection::In => AddEdge {
                        from: Endpoint::New(f as u8),
                        to: Endpoint::New(l as u8),
                        to_port_index: key,
                        wake_on_write: wake,
                        ..AddEdge::UNUSED
                    },
                };
                mailbox[e2] = record;
                e2 += 1;
                for (k, &ei) in group[..g].iter().enumerate() {
                    match dir {
                        FanDirection::Out => {
                            edges[ei].from = Endpoint::New(f as u8);
                            edges[ei].from_port_index = k as u8;
                        }
                        // Into the merge as plain data, whatever the port it
                        // fans into: the merge re-emits to that port.
                        FanDirection::In => {
                            edges[ei].to = Endpoint::New(f as u8);
                            edges[ei].to_port_index = k as u8;
                        }
                    }
                    mailbox[ei] |= record;
                }
            }
        }
    }
    (n2, e2)
}

/// Whether `edge` leaves (`Out`) or enters (`In`) the staged module `l`.
fn fan_touches(edge: &AddEdge, l: usize, dir: FanDirection) -> bool {
    let ep = match dir {
        FanDirection::Out => edge.from,
        FanDirection::In => edge.to,
    };
    matches!(ep, Endpoint::New(x) if x as usize == l)
}

/// The port an edge occupies on the fanned side: the output index, or the
/// input index with [`CTRL_PORT_BIT`] for a ctrl input.
fn fan_port_key(edge: &AddEdge, dir: FanDirection) -> u8 {
    match dir {
        FanDirection::Out => edge.from_port_index,
        FanDirection::In => edge.to_port_index,
    }
}

/// A staged module's type hash, or 0 for a built-in.
fn staged_hash(m: &AddModule) -> u32 {
    match &m.source {
        ModuleSource::Pic(entry) => entry.name_hash,
        ModuleSource::Builtin(_) => 0,
    }
}

/// The ports the boot graph's fan pass leaves unfanned: a multi-inbound
/// consumer keeps one channel per data edge, and a multi-outbound producer
/// keeps one per edge when its fan reaches exactly the modules feeding its
/// data input, each once.
fn fan_exempt(
    mods: &[AddModule; WORK_MODULES],
    l: usize,
    edges: &[AddEdge; WORK_EDGES],
    e: usize,
    group: &[usize],
    dir: FanDirection,
    key: u8,
) -> bool {
    let hash = staged_hash(&mods[l]);
    match dir {
        FanDirection::In => key & CTRL_PORT_BIT == 0 && super::is_multi_inbound(hash),
        FanDirection::Out => {
            if !super::is_multi_outbound(hash) {
                return false;
            }
            let into_l = |ae: &AddEdge| {
                matches!(ae.to, Endpoint::New(x) if x as usize == l)
                    && ae.to_port_index & CTRL_PORT_BIT == 0
            };
            let feeds = |c: Endpoint| {
                edges[..e]
                    .iter()
                    .any(|ae| into_l(ae) && same_endpoint(ae.from, c))
            };
            for (k, &ei) in group.iter().enumerate() {
                let c = edges[ei].to;
                if !feeds(c) || group[..k].iter().any(|&ej| same_endpoint(edges[ej].to, c)) {
                    return false;
                }
            }
            edges[..e].iter().all(|ae| {
                !into_l(ae) || group.iter().any(|&ei| same_endpoint(edges[ei].to, ae.from))
            })
        }
    }
}

/// Whether two endpoints name the same module or lane.
fn same_endpoint(a: Endpoint, b: Endpoint) -> bool {
    match (a, b) {
        (Endpoint::New(x), Endpoint::New(y)) => x == y,
        (Endpoint::Existing(x), Endpoint::Existing(y)) => x == y,
        (Endpoint::Tap(x), Endpoint::Tap(y)) => x == y,
        (Endpoint::ExistingChannel(x), Endpoint::ExistingChannel(y)) => x == y,
        (Endpoint::Net(x), Endpoint::Net(y)) => x == y,
        (Endpoint::Caller(x), Endpoint::Caller(y)) => x == y,
        _ => false,
    }
}

/// The frame kind of a fanned port, read from the fanned module's manifest
/// and, when it names none, from a peer's across the fan (both ends of an
/// edge declare compatible content), as the boot fan pass reads it.
fn fan_frame_kind(
    node: &ModuleLoader,
    mods: &[AddModule; WORK_MODULES],
    edges: &[AddEdge; WORK_EDGES],
    group: &[usize],
    l: usize,
    dir: FanDirection,
    key: u8,
) -> u8 {
    // The boot pass keys a ctrl input with bit 0x10.
    let boot_key = |k: u8| {
        if k & CTRL_PORT_BIT != 0 {
            0x10 | (k & 0x0F)
        } else {
            k
        }
    };
    let kind_of = |hash: u32, d: FanDirection, k: u8| {
        super::fanned_port_frame_kind(resolving_loader(hash, node), hash, d, boot_key(k))
    };
    let kind = kind_of(staged_hash(&mods[l]), dir, key);
    if kind != super::module_types::FRAME_KIND_NONE {
        return kind;
    }
    for &ei in group {
        let ae = &edges[ei];
        let (peer, peer_dir, peer_key) = match dir {
            FanDirection::Out => (ae.to, FanDirection::In, ae.to_port_index),
            FanDirection::In => (ae.from, FanDirection::Out, ae.from_port_index),
        };
        let Endpoint::New(p) = peer else {
            continue;
        };
        let k = kind_of(staged_hash(&mods[p as usize]), peer_dir, peer_key);
        if k != super::module_types::FRAME_KIND_NONE {
            return k;
        }
    }
    super::module_types::FRAME_KIND_NONE
}

/// Topologically order the new modules over their subgraph-internal edges so
/// producers precede consumers within the owner. Falls back to declaration
/// order on a cycle (the running graph already rejects cycles elsewhere; an
/// added subgraph is expected acyclic).
fn topo_order_new(slots: &[usize], edges: &[AddEdge]) -> [usize; WORK_MODULES] {
    let n = slots.len();
    let mut indeg = [0u8; WORK_MODULES];
    for ae in edges {
        if let (Endpoint::New(_), Endpoint::New(t)) = (ae.from, ae.to) {
            let t = t as usize;
            if t < n {
                indeg[t] += 1;
            }
        }
    }
    let mut out = [0usize; WORK_MODULES];
    let mut visited = [false; WORK_MODULES];
    let mut w = 0usize;
    // Kahn over local indices; O(n^2) is fine for n <= WORK_MODULES.
    while w < n {
        let mut progressed = false;
        for local in 0..n {
            if !visited[local] && indeg[local] == 0 {
                visited[local] = true;
                out[w] = slots[local];
                w += 1;
                for ae in edges {
                    if let (Endpoint::New(f), Endpoint::New(t)) = (ae.from, ae.to) {
                        if f as usize == local {
                            let t = t as usize;
                            if t < n && indeg[t] > 0 {
                                indeg[t] -= 1;
                            }
                        }
                    }
                }
                progressed = true;
            }
        }
        if !progressed {
            // Cycle: append remaining in declaration order.
            for local in 0..n {
                if !visited[local] {
                    out[w] = slots[local];
                    w += 1;
                }
            }
            break;
        }
    }
    out
}

/// Stop mirroring into every tap edge in `edges[base..base+count]`.
fn detach_taps(base: usize, count: usize) {
    let s = sched();
    for i in base..base + count {
        let edge = s.edges[i];
        if edge.tap && edge.tap_source >= 0 {
            crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, -1);
        }
    }
}

/// Reset `edges[base..base+count]` to the empty default (channel = -1).
fn clear_edge_range(base: usize, count: usize) {
    let s = sched();
    for i in base..base + count {
        s.edges[i] = Edge::simple(0, 0);
    }
}

// ============================================================================
// free_owner
// ============================================================================

/// Free `handle`: stop its modules, close its edges, reclaim its state, and
/// revoke the handle. Synchronous and idempotent against a stale handle.
///
/// One-shot drain only: `module_drain` is invoked once (a best-effort
/// stop-intake/flush) and the module is then terminated. Multi-tick graceful
/// drain is the reconfigure module's cross-tick policy, layered on top by
/// driving the owner's modules to `Done` *before* calling `free_owner`.
pub fn free_owner(handle: OwnerHandle) -> Result<(), FreeError> {
    if handle.is_system() {
        return Err(FreeError::NotWorkload);
    }
    let state = match sched().owners.lookup(handle) {
        Some(e) if e.state == OwnerState::Reserved => return Err(FreeError::Staged),
        Some(e) => e.state,
        None => return Err(FreeError::StaleHandle),
    };
    // Tell subscribed providers first, while the owner handle still resolves
    // and every provider module is still live and steppable. A provider that
    // holds resources on this owner's behalf (scratch objects, open files)
    // reclaims them here; after this point the handle's generation moves and
    // a provider belonging to this owner's own graph is torn down below.
    // Delivered from here rather than from the platform drain driver so the
    // paths that bypass it — the workload verbs (KILL/DESTROY) and admission
    // rollback — are covered by the same edge.
    crate::kernel::module::provider::notify_owner_released(handle);
    // Its net lanes go before its channels close, and the provider closes
    // every endpoint they opened.
    // SAFETY: scheduler thread, before the owner's channels close.
    unsafe { crate::kernel::workload::net_attach::detach(handle) };
    // Which module slots belong to this owner, and which domains they occupy —
    // captured up front (pure reads) BEFORE any mutation, because the metal
    // per-domain unsplice below needs the freed owner's domain set, and
    // step 4 clears each module's `domain_id`. `affected` (bit d ⇒ domain d) is
    // used only on bcm2712.
    let mut owned = [false; MAX_MODULES];
    let mut owned_count = 0usize;
    #[cfg(feature = "smp")]
    let mut affected: u32 = 0;
    // The live slots only: the scratch is typed by the module-index domain,
    // the tables hold what the boot plan committed.
    for (i, slot_owned) in owned.iter_mut().enumerate().take(module_slots()) {
        if matches!(sched().modules[i], ModuleSlot::Empty) {
            continue;
        }
        if super::module_owner(i) == handle {
            *slot_owned = true;
            owned_count += 1;
            #[cfg(feature = "smp")]
            {
                affected |= domain_bit(sched().domain_id[i]);
            }
        }
    }

    // Park every peer domain core for the teardown: the drain,
    // exec_order compaction, edge close, state free, per-domain unsplice, and
    // reindex are the mutations a concurrently-stepping peer core must never
    // observe half applied. No-op wrapper on single-domain hosts and at boot.
    let parked = quiesce_peers();

    if state == OwnerState::Paused {
        // Freeing a paused owner: drop its wake masking first so the
        // paused-owner count and mask bits can't outlive the owner. The
        // deferred wakes are discarded — the modules are being torn down.
        let mask = owned_module_mask(handle);
        let _ = crate::kernel::ipc::event::unpause_mask_modules(&mask);
    }
    sched().owners.begin_drain(handle);

    // 1. Stop modules: one-shot drain (if exported), then mark finished so the
    //    scheduler skips them immediately.
    {
        let s = sched();
        for (i, &is_owned) in owned.iter().enumerate() {
            if !is_owned {
                continue;
            }
            if let ModuleSlot::Dynamic(ref m) = s.modules[i] {
                // SAFETY: module is live and about to be torn down; drain runs
                // on its owning (scheduler) core. The caller (a workload
                // manager's KILL or DESTROY) gets its own context back.
                let _ = super::with_module_context(i, || unsafe { m.call_drain() });
            }
            s.finished[i] = true;
        }
    }

    // 2. Unsplice from the execution order BEFORE freeing state, so a racing
    //    step can never reach a freed slot. Stable compaction.
    {
        let s = sched();
        let mut w = 0usize;
        for r in 0..s.exec_order_count {
            let idx = s.exec_order[r] as usize;
            if idx < module_slots() && owned[idx] {
                continue;
            }
            s.exec_order[w] = s.exec_order[r];
            w += 1;
        }
        s.exec_order_count = w;
    }

    // A module with buffers lent to a block source is being torn down: from
    // here the kernel reaps its completions itself (see `block_lend`).
    for (i, &is_owned) in owned.iter().enumerate() {
        if is_owned {
            crate::kernel::module::block_lend::mark_dying(i);
        }
    }

    // 3. Close the owner's edges and compact the edges array. Nothing
    //    references edges by array index, and channel handles are unchanged by
    //    the shift, so surviving owners are untouched. `channel_close` resets
    //    the slot, which also clears any wake-on-write `wake_module` binding —
    //    a reused channel slot can never latch wakes for a freed module index.
    {
        let s = sched();
        let mut w = 0usize;
        for r in 0..s.edge_count {
            let edge = s.edges[r];
            let from_owned = edge.from_module < module_slots() && owned[edge.from_module];
            let to_owned = edge.to_module < module_slots() && owned[edge.to_module];
            if edge.tap && edge.tap_source >= 0 && (from_owned || to_owned) {
                // Either end going stops the mirror.
                crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, -1);
            }
            if edge.tap && from_owned && !to_owned {
                // The TAPPED module went; its observer lives on. End the tap's
                // stream (the observer completes by EOF) and keep the edge —
                // and its channel, which the observer still reads — until the
                // observer's own owner is freed.
                crate::kernel::ipc::channel::channel_mark_hup(edge.channel);
                let mut kept = edge;
                kept.tap_source = -1;
                s.edges[w] = kept;
                w += 1;
                continue;
            }
            if from_owned || to_owned {
                // A shared spare-lane edge (attachable-lane merge) is
                // removed with the owner but its channel is NEVER closed — the
                // boot merge caches it. Dropping the edge alone frees the lane
                // (`channel_producer_owner` reverts to system on the next scan).
                //
                // A channel carrying a buffer lent from a torn-down module stays
                // open: the source can only be asked to return it there. The
                // ledger closes it once the lends are back.
                if edge.channel >= 0
                    && !edge.shared_channel
                    && !crate::kernel::module::block_lend::adopt_channel(edge.channel)
                {
                    crate::kernel::module::syscalls::channel_close(edge.channel);
                }
                continue;
            }
            if w != r {
                s.edges[w] = s.edges[r];
            }
            w += 1;
        }
        for i in w..s.edge_count {
            s.edges[i] = Edge::simple(0, 0);
        }
        s.edge_count = w;
    }

    // 4. Free state and clear each owned slot.
    {
        let s = sched();
        for (i, &is_owned) in owned.iter().enumerate() {
            if !is_owned {
                continue;
            }
            // A live-added module may hold events, timers and platform handles,
            // a channel ioctl handler, and a contract-provider layer (e.g. a
            // mounted volume backend). Release them before its state is freed,
            // or a later dispatch would call into freed code. Boot modules
            // reach this through the finish path; the live-splice teardown
            // does it explicitly.
            crate::kernel::module::syscalls::release_module_handles(i as ModuleId);
            // Memory, protection domain and per-slot bookkeeping, as one
            // teardown. A module with buffers lent to a block source keeps its
            // memory until they are back.
            super::free_module_state(i);
            s.slot_generation[i] = s.slot_generation[i].wrapping_add(1);
            s.type_hash[i] = 0;
            super::set_module_owner(i, OWNER_SYSTEM);
        }
        s.active_module_count = s.active_module_count.saturating_sub(owned_count);
    }

    // Per-domain unsplice (bcm2712 only): reproject the affected
    // domains' `domain_exec_order` from the now-compacted flat order. The freed
    // modules are already gone from `exec_order` (step 2) and their slots are
    // `Empty` (step 4), so the reprojection naturally drops them and compacts —
    // byte-identical to a full recompute for those domains. Runs after the state
    // free so the rebuilt per-domain wake masks reflect only survivors.
    #[cfg(feature = "smp")]
    super::recompute_domain_orders(affected);

    // 5. Revoke the handle. The generation guard now rejects it.
    sched().owners.free(handle);
    // The owner's own modules' code, when it brought a pack: nothing of the
    // owner runs any more (its modules are unspliced, their handles and
    // provider layers released), and a module whose state is quarantined
    // for a lend keeps only that state.
    #[cfg(feature = "multitenant")]
    crate::kernel::workload::code_pack::release_owner(handle.slot);
    // Drop the freed owner from the resident-graph index. A later slot reuse
    // bumps the generation, so its pacer instance resets and the re-added
    // entry is re-primed.
    super::rebuild_resident_graph_index();
    // Teardown complete — release the parked peer cores (no-op if none).
    release_peers(parked);
    Ok(())
}

// ============================================================================
// owner_pause / owner_resume
// ============================================================================
//
// The metal PAUSE verb: a reversible quiesce built from exactly the two
// primitives drain is built from — admission close (the
// `authorize_admit` gate, closed by the `Paused` owner state) and
// per-owner wake masking (`event::pause_mask_modules`) — plus the re-latch
// path `owner_resume` owns. Deliberately weaker than drain: no
// `module_drain`, no channel-empty requirement, no deadline. In-flight
// steps complete naturally (pause runs on the scheduler thread between
// steps — there is no preemption to suppress); from the next runner pass
// the runner's runnable predicate treats the owner's graphs as not-runnable
// regardless of readable inbound data, and inbound writes simply buffer in
// the owner's channels: deferred, not refused, because channel rings are
// lossless and bounded, so buffering IS the deferral; producers see normal
// backpressure when the ring fills.

/// The owner's stamped module set. Bounded scan; scheduler-thread only.
fn owned_module_mask(handle: OwnerHandle) -> crate::kernel::workload::bitmask::ModuleMask {
    let s = sched();
    let mut mask = crate::kernel::workload::bitmask::ModuleMask::new();
    for i in 0..module_slots() {
        if !matches!(s.modules[i], ModuleSlot::Empty) && super::module_owner(i) == handle {
            mask.set(i);
        }
    }
    mask
}

/// Pause `handle`: close admission and mask its wake sources so its graphs
/// stop being stepped. Idempotent (pause of a paused owner is a no-op).
/// The system owner is refused. Scheduler-thread only (same access class
/// as `apply_add` / `free_owner`).
pub fn owner_pause(handle: OwnerHandle) -> Result<(), PauseError> {
    if handle.is_system() {
        return Err(PauseError::NotWorkload);
    }
    let state = match sched().owners.lookup(handle) {
        Some(e) => e.state,
        None => return Err(PauseError::StaleHandle),
    };
    match state {
        OwnerState::Paused => return Ok(()), // idempotent
        OwnerState::Active => {}
        _ => return Err(PauseError::BadState),
    }
    let mask = owned_module_mask(handle);
    // Mask-then-check (lost-wakeup discipline): divert NEW wakes first,
    // then sweep bits that latched before the mask was visible. A signal
    // racing the sweep lands in EVENT_WAKE_PENDING and is deferred by the
    // runner's per-pass straggler sweep / the woken-step guard.
    crate::kernel::ipc::event::pause_mask_modules(&mask);
    let latched = crate::kernel::ipc::event::take_wake_in_mask(&mask);
    crate::kernel::ipc::event::defer_masked_wakes(&latched);
    // State last: the runner skips on `Paused`, admission closes via
    // `authorize_admit` (the same gate, reversible).
    sched().owners.set_state(handle, OwnerState::Paused);
    Ok(())
}

/// Resume `handle`: reopen admission and re-latch every wake that arrived
/// while paused, so deferred producers/timers are serviced on the next
/// pass — a module with masked-arrived data steps exactly once with
/// `event_wake = true`, as if the wake had just fired. Idempotent (resume
/// of an Active owner is a no-op).
pub fn owner_resume(handle: OwnerHandle) -> Result<(), PauseError> {
    if handle.is_system() {
        return Err(PauseError::NotWorkload);
    }
    let state = match sched().owners.lookup(handle) {
        Some(e) => e.state,
        None => return Err(PauseError::StaleHandle),
    };
    match state {
        OwnerState::Active => return Ok(()), // idempotent
        OwnerState::Paused => {}
        _ => return Err(PauseError::BadState),
    }
    sched().owners.set_state(handle, OwnerState::Active);
    let mask = owned_module_mask(handle);
    // Unmask-then-drain: after the mask clears, new wakes latch normally;
    // the returned set is everything that was diverted while masked. Both
    // orders of a racing signal deliver — none are lost, a duplicate
    // event-wake step is benign (level-triggered semantics).
    let deferred = crate::kernel::ipc::event::unpause_mask_modules(&mask);
    if !deferred.is_empty() {
        for idx in deferred.iter_set() {
            crate::kernel::ipc::event::relatch_module_wake(idx);
        }
        crate::kernel::sys::hal::wake_scheduler();
    }
    Ok(())
}

// ============================================================================
// Syscall codec (APPLY_ADD / FREE_OWNER)
// ============================================================================
//
// Bounded binary `AddSubgraph` for the on-device caller (REPL / node agent).
// Big-endian, fixed-width — same discipline as the composed-plan codec in
// `tools/src/compose.rs`. PIC modules only (a built-in has no serialisable
// form); a module whose load cannot complete within the call refuses the add
// (`WouldBlock`, `EAGAIN`).
// Integrity/signature verification of the blob is the signing
// layer's job and the channel is authenticated (the node agent's), so this
// decoder validates structure and bounds, not a content digest.
//
// FLXA layout (all integers big-endian):
//
//   header   magic u32 "FLXA" | version u16 = 1 | flags u16
//            owner_uid [16] | state_cap u32 | buffer_cap u32
//            module_count u8 | edge_count u8
//   module   name_hash u32 | domain_id u8
//            step_deadline_us u32 | step_deadline_burst_us u32 | fault_policy u8
//            params_len u16 | params [params_len]
//   edge     from_kind u8 | from_idx u16 | from_port u8
//            to_kind u8 | to_idx u16 | to_port u8 | buffer_bytes u32
//
// The module record's step budget is the base graph's three per-module YAML
// settings: a deadline of `0` is the node's default, a burst of `0` is
// `deadline × BURST_MULTIPLIER`, and `fault_policy` is numbered as the params
// TLV's tag `0xF1` (0 skip, 1 restart, 2 restart_graph, 3 tolerate). A policy
// byte outside that set fails the decode (`EINVAL`); a known policy or a
// deadline the node does not admit a workload refuses the add
// ([`admit_step_budget`], `ERANGE`).
//
// `flags` holds one bit, `ADD_FLAG_CREATOR_AUTHORITY` (0x0001): the new owner
// acts with its creator's authority. Only the module syscall names a creator
// ([`apply_add_encoded_by`]); every other decode refuses the bit (`EINVAL`),
// and every decode refuses an undefined bit.
//
// A module's params are its own: an add refuses (`EACCES`) params whose TLV
// carries a node tag (`is_node_param_tag`: the fault tags, trust tier,
// protection level, quarantine partner, ISR budget, IRQ, device window),
// before anything is allocated. Only the node's own graph grants those.

/// Wire magic: "FLXA".
pub const ADD_MAGIC: u32 = 0x464C_5841;
/// Wire version.
pub const ADD_VERSION: u16 = 1;
/// The header's one flag: act with the creator's authority.
pub const ADD_FLAG_CREATOR_AUTHORITY: u16 =
    crate::abi::internal::reconfigure::ADD_FLAG_CREATOR_AUTHORITY;
/// Bytes of a module record before its params: name_hash, domain_id,
/// step_deadline_us, step_deadline_burst_us, fault_policy, params_len.
pub const ADD_MODULE_FIXED_BYTES: usize = 4 + 1 + 4 + 4 + 1 + 2;

/// Minimal big-endian reading cursor over the encoded blob.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cur<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Cur { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

fn decode_endpoint(kind: u8, idx: u16) -> Option<Endpoint> {
    match kind {
        0 if idx <= u16::from(u8::MAX) => Some(Endpoint::New(idx as u8)),
        1 => Some(Endpoint::Existing(idx)),
        2 => Some(Endpoint::Tap(idx)),
        3 if idx <= u16::from(u8::MAX) => Some(Endpoint::Net(idx as u8)),
        4 if idx <= u16::from(u8::MAX) => Some(Endpoint::Caller(idx as u8)),
        _ => None,
    }
}

/// A module record's step budget: deadline, burst, policy. `None` for a
/// short record or a policy byte no [`FaultPolicy`] names — the decode fails
/// closed rather than reading an unknown policy as some default.
fn decode_step_budget(c: &mut Cur<'_>) -> Option<StepBudget> {
    let deadline_us = c.u32()?;
    let burst_us = c.u32()?;
    let policy = FaultPolicy::from_wire(c.u8()?)?;
    Some(StepBudget {
        deadline_us,
        burst_us,
        policy,
    })
}

/// One `Endpoint::Caller` edge of an encoded subgraph: its position among
/// the blob's edges, its key, and whether it runs into the caller.
#[derive(Clone, Copy, Default)]
pub struct CallerEdge {
    pub index: usize,
    pub key: u8,
    pub into_caller: bool,
}

/// The `Endpoint::Caller` edges of an encoded subgraph, in edge order, into
/// `out`; how many there are, or `None` for a blob that does not decode.
/// `apply_add` appends a subgraph's edges in blob order, so edge `index`
/// lands at the edge count before the add plus `index`.
pub fn caller_edges(blob: &[u8], out: &mut [CallerEdge]) -> Option<usize> {
    let mut c = Cur::new(blob);
    if c.u32()? != ADD_MAGIC || c.u16()? != ADD_VERSION {
        return None;
    }
    c.u16()?;
    c.take(16 + 4 + 4)?;
    let mc = c.u8()? as usize;
    let ec = c.u8()? as usize;
    for _ in 0..mc {
        c.take(ADD_MODULE_FIXED_BYTES - 2)?;
        let plen = c.u16()? as usize;
        c.take(plen)?;
    }
    let mut n = 0;
    for index in 0..ec {
        let (fk, fi) = (c.u8()?, c.u16()?);
        c.u8()?;
        let (tk, ti) = (c.u8()?, c.u16()?);
        c.take(1 + 4)?;
        let found = match (fk, tk) {
            (4, _) => Some((fi, false)),
            (_, 4) => Some((ti, true)),
            _ => None,
        };
        if let Some((key, into_caller)) = found {
            let slot = out.get_mut(n)?;
            *slot = CallerEdge {
                index,
                key: u8::try_from(key).ok()?,
                into_caller,
            };
            n += 1;
        }
    }
    Some(n)
}

/// The loader a staged module named `name_hash` resolves from: a
/// workload's own pack while its CREATE stages it (`code_pack`), else the
/// node's.
fn resolving_loader(name_hash: u32, node: &ModuleLoader) -> &ModuleLoader {
    #[cfg(feature = "multitenant")]
    {
        crate::kernel::workload::code_pack::resolve(name_hash, node)
    }
    #[cfg(not(feature = "multitenant"))]
    {
        let _ = name_hash;
        node
    }
}

/// The fmod header's module type that runs at `CAP_FULL` (see the loader's
/// cap-class mapping in `wiring.rs`).
const MODULE_TYPE_PROTOCOL: u8 = 5;

/// The union of the manifest permissions of the modules an `AddSubgraph`
/// blob names, each resolved by `name_hash` against the node's loader; a
/// name the loader cannot resolve adds nothing (the add itself refuses it).
/// `None` for a malformed blob. Read before the add, so a policy on what a
/// subgraph may hold is decided before anything is allocated.
pub fn module_permissions(blob: &[u8]) -> Option<u16> {
    let mut c = Cur::new(blob);
    if c.u32()? != ADD_MAGIC || c.u16()? != ADD_VERSION {
        return None;
    }
    c.u16()?;
    c.take(16 + 4 + 4)?;
    let mc = c.u8()? as usize;
    c.u8()?;
    // SAFETY: scheduler-thread context, as every caller of the add.
    let loader = unsafe { super::static_loader() };
    let mut perms = 0u16;
    for _ in 0..mc {
        let name_hash = c.u32()?;
        c.take(ADD_MODULE_FIXED_BYTES - 4 - 2)?;
        let plen = c.u16()? as usize;
        c.take(plen)?;
        if let Ok(m) = resolving_loader(name_hash, loader).find_by_name_hash(name_hash) {
            // A `Protocol` module runs at `CAP_FULL`, which reaches every
            // contract and passes every permission check: it holds them all.
            perms |= if m.header.module_type == MODULE_TYPE_PROTOCOL {
                u16::MAX
            } else {
                m.manifest_permissions()
            };
        }
    }
    Some(perms)
}

/// Decode a bounded binary `AddSubgraph` and apply it. On success writes the
/// 6-byte `OwnerHandle` (`slot:u16 LE, generation:u32 LE`) into `arg[0..6]` and
/// returns 0; otherwise a negative error (`-EINVAL` for a malformed blob, or
/// the negative [`AddError::code`]).
///
/// A [`SPARE_LANE_SENTINEL`] `to` endpoint is **not** rewritten here: it decodes
/// to `Existing(0xFFFF)`, which resolves to no live module and fails
/// [`AddError::BadEndpoint`] — a plain FLXA apply never carries the metal
/// net-facing sentinel. The metal backend uses [`apply_add_encoded_spare_lane`]
/// instead.
///
/// # Safety
/// `arg` must be a writable buffer of at least `arg_len` bytes, valid for the
/// duration of the call (module params are borrowed from it in place).
pub unsafe fn apply_add_encoded(arg: *mut u8, arg_len: usize) -> i32 {
    // SAFETY: forwarded contract; `None` = no spare-lane rewrite (the sentinel,
    // if present, falls through to `BadEndpoint`), and no creator.
    unsafe { apply_add_encoded_inner(arg, arg_len, None, None) }
}

/// [`apply_add_encoded`] for the module syscall: `creator` is the calling
/// module's global index, which an add flagged
/// [`ADD_FLAG_CREATOR_AUTHORITY`] acts on behalf of
/// ([`AddAuthority::Creator`]). An unflagged add is the same as through
/// [`apply_add_encoded`].
///
/// # Safety
/// As [`apply_add_encoded`].
pub unsafe fn apply_add_encoded_by(arg: *mut u8, arg_len: usize, creator: usize) -> i32 {
    // SAFETY: forwarded contract.
    unsafe { apply_add_encoded_inner(arg, arg_len, None, Some(creator)) }
}

/// The metal `net=own` variant of [`apply_add_encoded`] — the
/// decode→inject→apply seam. Identical to
/// `apply_add_encoded`, except a net-facing [`SPARE_LANE_SENTINEL`] `to`
/// endpoint is rewritten to `Endpoint::ExistingChannel(spare_lane)` before
/// apply, wiring the workload's producer into the boot merge's pre-cached spare
/// lane so its egress reaches the node's shared `ip`.
///
/// `spare_lane` is the caller-resolved free lane channel
/// (`merge_next_free_lane(find_spare_lane_merge_for_channel(ingress))`, resolved from the registered net-identity provider):
///   * `>= 0` — a sentinel edge is rewritten to `ExistingChannel(spare_lane)`,
///   * `< 0`  — a sentinel edge means the caller found NO free lane, so the
///     apply is refused `ENOMEM` (spare-lane exhaustion / no boot merge) with
///     nothing allocated — a clean fail-closed rollback.
///
/// A blob with **no** sentinel edge ignores `spare_lane` and is byte-identical
/// to `apply_add_encoded` (the host-shared path).
///
/// # Safety
/// As [`apply_add_encoded`].
pub unsafe fn apply_add_encoded_spare_lane(arg: *mut u8, arg_len: usize, spare_lane: i32) -> i32 {
    // SAFETY: forwarded contract.
    unsafe { apply_add_encoded_inner(arg, arg_len, Some(spare_lane), None) }
}

/// Shared decode+apply body for [`apply_add_encoded`],
/// [`apply_add_encoded_by`] and [`apply_add_encoded_spare_lane`]: the whole
/// add in this call.
///
/// # Safety
/// As [`apply_add_encoded`].
unsafe fn apply_add_encoded_inner(
    arg: *mut u8,
    arg_len: usize,
    spare_lane: Option<i32>,
    creator: Option<usize>,
) -> i32 {
    if arg.is_null() {
        return crate::kernel::sys::errno::EINVAL;
    }
    // SAFETY: caller guarantees `arg`/`arg_len` describe a valid buffer.
    let bytes = unsafe { core::slice::from_raw_parts(arg, arg_len) };
    // SAFETY: the modules' params are borrowed from `bytes`, which outlives
    // the add: it completes within this call.
    match unsafe { decode_add(bytes, spare_lane, creator, |sub| apply_add(sub, None)) } {
        Ok(Ok(handle)) => {
            // SAFETY: a decoded blob is longer than the handle's 6 bytes.
            unsafe { write_handle(core::slice::from_raw_parts_mut(arg, 6), handle) };
            0
        }
        Ok(Err(e)) => e.code(),
        Err(e) => e,
    }
}

/// Decode an encoded subgraph and stage it, for an add its caller finishes
/// over several calls (see [`StagedAdd`]). `spare_lane` as for
/// [`apply_add_encoded_spare_lane`]. `EINVAL` for a malformed blob, or the
/// negative [`AddError::code`].
///
/// # Safety
/// `bytes` must stay valid and unchanged until the staged add is published
/// or abandoned: its modules' params are read from it as they instantiate.
pub unsafe fn begin_add_encoded(bytes: &[u8], spare_lane: Option<i32>) -> Result<StagedAdd, i32> {
    // SAFETY: forwarded contract.
    match unsafe { decode_add(bytes, spare_lane, None, |sub| begin_add(sub, None)) } {
        Ok(Ok(st)) => Ok(st),
        Ok(Err(e)) => Err(e.code()),
        Err(e) => Err(e),
    }
}

/// Write an owner handle as an add reports it: `[slot:u16 LE][generation:u32
/// LE]` into `out[0..6]`.
pub fn write_handle(out: &mut [u8], handle: OwnerHandle) {
    out[0..2].copy_from_slice(&handle.slot.to_le_bytes());
    out[2..6].copy_from_slice(&handle.generation.to_le_bytes());
}

/// Decode an encoded subgraph and hand it to `f`. `spare_lane`:
///   * `None`         — no metal rewrite (sentinel → `BadEndpoint`),
///   * `Some(l)` l>=0 — rewrite a sentinel `to` to `ExistingChannel(l)`,
///   * `Some(l)` l<0  — a sentinel with no resolved lane → `-ENOMEM`.
///
/// `creator` is the module an [`ADD_FLAG_CREATOR_AUTHORITY`] add acts on
/// behalf of; with `None` the flag is refused.
///
/// `Err(EINVAL)` for a malformed blob, before `f` runs.
///
/// # Safety
/// The decoded modules' params borrow `bytes`; `f` and whatever it keeps
/// must not outlive it.
unsafe fn decode_add<R>(
    bytes: &[u8],
    spare_lane: Option<i32>,
    creator: Option<usize>,
    f: impl FnOnce(AddSubgraph<'_>) -> R,
) -> Result<R, i32> {
    const EINVAL: i32 = -22;
    const ENOMEM: i32 = -12;
    let mut c = Cur::new(bytes);

    if c.u32() != Some(ADD_MAGIC) || c.u16() != Some(ADD_VERSION) {
        return Err(EINVAL);
    }
    let authority = match (c.u16(), creator) {
        (Some(0), _) => AddAuthority::Own,
        (Some(ADD_FLAG_CREATOR_AUTHORITY), Some(idx)) => AddAuthority::Creator(idx),
        _ => return Err(EINVAL),
    };
    let owner_uid: [u8; 16] = match c.take(16) {
        Some(s) => s.try_into().unwrap(),
        None => return Err(EINVAL),
    };
    let (state_cap, buffer_cap) = match (c.u32(), c.u32()) {
        (Some(s), Some(b)) => (s, b),
        _ => return Err(EINVAL),
    };
    let mc = match c.u8() {
        Some(n) if (n as usize) <= MAX_ADD_MODULES => n as usize,
        _ => return Err(EINVAL),
    };
    let ec = match c.u8() {
        Some(n) if (n as usize) <= MAX_ADD_EDGES => n as usize,
        _ => return Err(EINVAL),
    };

    let mut mods: [AddModule; MAX_ADD_MODULES] = core::array::from_fn(|_| AddModule {
        source: ModuleSource::Pic(ModuleEntry::default()),
        domain_id: 0,
        budget: StepBudget::NODE_DEFAULT,
    });
    for m in mods.iter_mut().take(mc) {
        let name_hash = match c.u32() {
            Some(v) => v,
            None => return Err(EINVAL),
        };
        let domain_id = match c.u8() {
            Some(v) => v,
            None => return Err(EINVAL),
        };
        let budget = match decode_step_budget(&mut c) {
            Some(b) => b,
            None => return Err(EINVAL),
        };
        let plen = match c.u16() {
            Some(v) => v as usize,
            None => return Err(EINVAL),
        };
        let params = match c.take(plen) {
            Some(s) => s,
            None => return Err(EINVAL),
        };
        let entry = ModuleEntry {
            name_hash,
            domain_id,
            params_ptr: if plen == 0 {
                core::ptr::null()
            } else {
                params.as_ptr()
            },
            params_len: plen,
            ..ModuleEntry::default()
        };
        m.source = ModuleSource::Pic(entry);
        m.domain_id = domain_id;
        m.budget = budget;
    }

    let mut edges = [AddEdge {
        from: Endpoint::New(0),
        from_port_index: 0,
        to: Endpoint::New(0),
        to_port_index: 0,
        buffer_bytes: 0,
        // The per-edge wire record (kind/idx/port ×2 + buffer_bytes) has
        // no reserved space to carry the wake flag; encoded edges are never
        // wake-flagged. See the field doc on `AddEdge::wake_on_write`.
        wake_on_write: false,
    }; MAX_ADD_EDGES];
    for edge in edges.iter_mut().take(ec) {
        let from_kind = c.u8();
        let from_idx = c.u16();
        let from_port = c.u8();
        let to_kind = c.u8();
        let to_idx = c.u16();
        let to_port = c.u8();
        let buffer_bytes = c.u32();
        let (Some(fk), Some(fi), Some(fp), Some(tk), Some(ti), Some(tp), Some(bb)) = (
            from_kind,
            from_idx,
            from_port,
            to_kind,
            to_idx,
            to_port,
            buffer_bytes,
        ) else {
            return Err(EINVAL);
        };
        let (Some(from), Some(mut to)) = (decode_endpoint(fk, fi), decode_endpoint(tk, ti)) else {
            return Err(EINVAL);
        };
        // Net-facing spare-lane sentinel: the composer marks the
        // net-facing producer's `to` as `Existing(SPARE_LANE_SENTINEL)` because
        // it cannot name a kernel runtime channel off-node. Rewrite it to the
        // caller-resolved boot-merge spare lane (`ExistingChannel`) so the
        // producer edges straight into the merge.
        if matches!(to, Endpoint::Existing(SPARE_LANE_SENTINEL)) {
            match spare_lane {
                Some(l) if l >= 0 => to = Endpoint::ExistingChannel(l),
                // net=own with no free spare lane / no boot merge — fail closed
                // before anything is allocated (clean, no rollback needed).
                Some(_) => return Err(ENOMEM),
                // Plain apply (host-shared): leave the sentinel; it resolves to
                // no module and `apply_add` rejects it (BadEndpoint), unchanged.
                None => {}
            }
        }
        edge.from = from;
        edge.from_port_index = fp;
        edge.to = to;
        edge.to_port_index = tp;
        edge.buffer_bytes = bb;
    }

    Ok(f(AddSubgraph {
        owner_uid,
        modules: &mut mods[..mc],
        edges: &edges[..ec],
        state_cap,
        buffer_cap,
        authority,
    }))
}

/// Decode `[slot:u16 LE, generation:u32 LE]` and free that owner.
///
/// # Safety
/// `arg` must point to at least `arg_len` readable bytes.
pub unsafe fn free_owner_encoded(arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 6 {
        return -22;
    }
    // SAFETY: caller guarantees >= 6 readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(arg, 6) };
    let slot = u16::from_le_bytes([bytes[0], bytes[1]]);
    let generation = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    match free_owner(OwnerHandle { slot, generation }) {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

/// Decode `[slot:u16 LE, generation:u32 LE]` and pause that owner
/// (`OWNER_PAUSE = 0x0C49`). Same handle record as `FREE_OWNER`.
///
/// # Safety
/// `arg` must point to at least `arg_len` readable bytes.
pub unsafe fn owner_pause_encoded(arg: *const u8, arg_len: usize) -> i32 {
    match decode_owner_handle(arg, arg_len) {
        Some(h) => match owner_pause(h) {
            Ok(()) => 0,
            Err(e) => e.code(),
        },
        None => -22,
    }
}

/// Decode `[slot:u16 LE, generation:u32 LE]` and resume that owner
/// (`OWNER_RESUME = 0x0C4A`).
///
/// # Safety
/// `arg` must point to at least `arg_len` readable bytes.
pub unsafe fn owner_resume_encoded(arg: *const u8, arg_len: usize) -> i32 {
    match decode_owner_handle(arg, arg_len) {
        Some(h) => match owner_resume(h) {
            Ok(()) => 0,
            Err(e) => e.code(),
        },
        None => -22,
    }
}

/// Shared `[slot:u16 LE, generation:u32 LE]` handle decode.
fn decode_owner_handle(arg: *const u8, arg_len: usize) -> Option<OwnerHandle> {
    if arg.is_null() || arg_len < 6 {
        return None;
    }
    // SAFETY: non-null with >= 6 readable bytes, checked above; callers
    // guarantee validity for the call duration.
    let bytes = unsafe { core::slice::from_raw_parts(arg, 6) };
    Some(OwnerHandle {
        slot: u16::from_le_bytes([bytes[0], bytes[1]]),
        generation: u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
    })
}

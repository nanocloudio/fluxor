//! Workload owner model (rfc_k8s.md §6.2, §6.4, §10, §14).
//!
//! Each resident Pod maps to a bounded `OwnerHandle { slot, generation }`,
//! distinct from its durable Kubernetes Pod UID and from scheduler module
//! indices. Every workload-owned object (module, channel, buffer, provider
//! handle, endpoint lease, timer, telemetry record) is stamped with its owner
//! so the runtime can authorize access, account resources, and reclaim
//! everything on deletion. System graph components use [`OWNER_SYSTEM`]
//! (slot 0).
//!
//! Generation guard: every slot carries a reuse generation that increases on
//! each allocation. A handle from a deleted Pod fails [`OwnerTable::authorize`]
//! after the slot is reused, because the generation no longer matches; it also
//! fails immediately on free, because the slot's state is no longer `Active`.
//!
//! Zero cost on single-tenant targets: when the `multitenant` feature is off
//! `MAX_OWNERS == 1`, the table holds only the system slot, and the
//! authorization helpers ([`same_or_system`]) compile to `true`. Owner fields
//! on graph objects are themselves `#[cfg(feature = "multitenant")]`, so
//! bare-metal targets carry no per-object ownership state.

/// Maximum number of concurrently resident owners, including the system slot.
#[cfg(feature = "multitenant")]
pub const MAX_OWNERS: usize = 64;
/// Single-tenant: only the system owner exists.
#[cfg(not(feature = "multitenant"))]
pub const MAX_OWNERS: usize = 1;

const _: () = assert!(MAX_OWNERS >= 1, "MAX_OWNERS must include the system slot");
const _: () = assert!(
    (MAX_OWNERS > 1) == cfg!(feature = "multitenant"),
    "MAX_OWNERS > 1 must coincide with the `multitenant` feature"
);
// Slot is a u16; keep the table within that index domain.
const _: () = assert!(MAX_OWNERS <= u16::MAX as usize);

/// A bounded runtime capability identifying one workload owner. Not persisted
/// as identity — the Pod UID is the durable identity (rfc_k8s.md §6.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnerHandle {
    pub slot: u16,
    pub generation: u32,
}

/// The system owner. Platform drivers, the network/storage/telemetry
/// substrate, the graph manager, OTA, and the node agent run as this owner and
/// cannot be replaced by ordinary Pod updates (rfc_k8s.md §6.4).
pub const OWNER_SYSTEM: OwnerHandle = OwnerHandle {
    slot: 0,
    generation: 0,
};

impl OwnerHandle {
    #[inline]
    pub const fn is_system(&self) -> bool {
        self.slot == 0
    }
}

/// Lifecycle state of an owner slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnerState {
    Free,
    Reserved,
    Active,
    Draining,
    Revoked,
    /// Reversible quiesce (rfc_workload_lifecycle.md §3.2): admission is
    /// closed (`authorize_admit` fails) and the scheduler skips the owner's
    /// graphs, but held resources stay valid (`authorize_use` passes) so
    /// `owner_resume` restores the exact pre-pause posture. Weaker than
    /// `Draining` — no `module_drain`, no channel-empty requirement.
    Paused,
}

/// Per-owner resource accounting and hard caps. Caps are populated from the
/// signed resource profile at reservation; the allocator and admission paths
/// charge against them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnerAccounting {
    pub state_bytes: u32,
    pub state_cap: u32,
    pub buffer_bytes: u32,
    pub buffer_cap: u32,
    pub modules: u16,
    pub edges: u16,
    pub endpoints: u16,
    pub providers: u16,
    pub timers: u16,
    pub isolated_slots: u16,
}

impl OwnerAccounting {
    pub const ZERO: OwnerAccounting = OwnerAccounting {
        state_bytes: 0,
        state_cap: 0,
        buffer_bytes: 0,
        buffer_cap: 0,
        modules: 0,
        edges: 0,
        endpoints: 0,
        providers: 0,
        timers: 0,
        isolated_slots: 0,
    };
}

/// One entry in the owner table.
#[derive(Clone, Copy)]
pub struct OwnerEntry {
    pub pod_uid: [u8; 16],
    pub generation: u32,
    pub state: OwnerState,
    pub acct: OwnerAccounting,
}

impl OwnerEntry {
    const EMPTY: OwnerEntry = OwnerEntry {
        pod_uid: [0; 16],
        generation: 0,
        state: OwnerState::Free,
        acct: OwnerAccounting::ZERO,
    };

    const SYSTEM: OwnerEntry = OwnerEntry {
        pod_uid: [0; 16],
        generation: 0,
        state: OwnerState::Active,
        acct: OwnerAccounting::ZERO,
    };
}

/// Bounded table of owner slots. Slot 0 is permanently the system owner.
pub struct OwnerTable {
    entries: [OwnerEntry; MAX_OWNERS],
}

impl OwnerTable {
    /// A fresh table with only the system slot active.
    pub const fn new() -> Self {
        let mut entries = [OwnerEntry::EMPTY; MAX_OWNERS];
        entries[0] = OwnerEntry::SYSTEM;
        OwnerTable { entries }
    }

    /// Allocate the lowest free slot for `pod_uid`. The reuse generation is
    /// bumped monotonically so a stale handle cannot match after reuse. Returns
    /// `None` when every workload slot is occupied. The lowest-free-slot rule
    /// is required by the deterministic-composition contract (rfc_k8s.md §11).
    pub fn alloc(&mut self, pod_uid: [u8; 16]) -> Option<OwnerHandle> {
        // `1..MAX_OWNERS` is empty on single-tenant (MAX_OWNERS == 1) builds —
        // no workload slots exist, so alloc correctly returns None.
        #[allow(
            clippy::reversed_empty_ranges,
            reason = "empty by design when MAX_OWNERS == 1 (single-tenant)"
        )]
        for slot in 1..MAX_OWNERS {
            if matches!(self.entries[slot].state, OwnerState::Free) {
                let generation = self.entries[slot].generation.wrapping_add(1);
                self.entries[slot] = OwnerEntry {
                    pod_uid,
                    generation,
                    state: OwnerState::Reserved,
                    acct: OwnerAccounting::ZERO,
                };
                return Some(OwnerHandle {
                    slot: slot as u16,
                    generation,
                });
            }
        }
        None
    }

    /// Install an owner at a specific `slot`/`generation` as dictated by a
    /// composed plan (rfc_k8s.md §11 — the plan is authoritative for slot and
    /// generation, unlike [`alloc`](Self::alloc) which picks them). The owner is
    /// installed `Active`. Returns `None` for the system slot, an out-of-range
    /// slot, or a `generation` that would *decrease* the slot's reuse counter.
    /// Used by the kernel plan-apply path.
    ///
    /// The composer is trusted to keep generations monotonic, but the kernel
    /// enforces it independently: `reset_workloads` preserves each slot's
    /// generation counter, and a plan (corrupt, rolled-back, or a forward
    /// generation that nonetheless regresses one slot) that tried to install a
    /// generation below the retained counter would let a stale handle from the
    /// slot's previous occupant re-validate. Such an install is refused — the
    /// slot stays `Free` (fail-closed: its old handles already fail `authorize`),
    /// so isolation is never silently weakened.
    pub fn install(
        &mut self,
        slot: u16,
        generation: u32,
        pod_uid: [u8; 16],
        state_cap: u32,
        buffer_cap: u32,
    ) -> Option<OwnerHandle> {
        let s = slot as usize;
        if s == 0 || s >= MAX_OWNERS {
            return None;
        }
        // Never lower a slot's generation: that is the reuse guard's core
        // invariant. Equal is allowed (idempotent re-apply of the same plan).
        if generation < self.entries[s].generation {
            return None;
        }
        let mut acct = OwnerAccounting::ZERO;
        acct.state_cap = state_cap;
        acct.buffer_cap = buffer_cap;
        self.entries[s] = OwnerEntry {
            pod_uid,
            generation,
            state: OwnerState::Active,
            acct,
        };
        Some(OwnerHandle { slot, generation })
    }

    #[inline]
    fn slot_valid(&self, h: OwnerHandle) -> bool {
        (h.slot as usize) < MAX_OWNERS
    }

    /// Look up a live entry for `h`. `None` if the slot is out of range, freed,
    /// or the generation no longer matches (stale handle).
    pub fn lookup(&self, h: OwnerHandle) -> Option<&OwnerEntry> {
        if !self.slot_valid(h) {
            return None;
        }
        let e = &self.entries[h.slot as usize];
        if e.generation == h.generation && !matches!(e.state, OwnerState::Free) {
            Some(e)
        } else {
            None
        }
    }

    /// Mutable variant of [`lookup`](Self::lookup).
    pub fn lookup_mut(&mut self, h: OwnerHandle) -> Option<&mut OwnerEntry> {
        if !self.slot_valid(h) {
            return None;
        }
        let e = &mut self.entries[h.slot as usize];
        if e.generation == h.generation && !matches!(e.state, OwnerState::Free) {
            Some(e)
        } else {
            None
        }
    }

    /// Resolve the live owner handle for a durable `pod_uid` — the bridge from
    /// the persistent identity (the Pod UID, rfc_k8s.md §6.5) to the runtime
    /// capability. A provider admitting owner-scoped work (e.g. the `workload`
    /// host-process backend spawning a Pod's container) references the
    /// plan-allocated owner this way rather than allocating one itself. Returns
    /// `None` if no non-`Free` slot carries that uid. The caller still gates on
    /// [`authorize_admit`](Self::authorize_admit) — a `Draining`/`Revoked`
    /// owner resolves but must not admit new work.
    pub fn find_by_uid(&self, pod_uid: [u8; 16]) -> Option<OwnerHandle> {
        #[allow(
            clippy::reversed_empty_ranges,
            reason = "empty by design when MAX_OWNERS == 1 (single-tenant)"
        )]
        for slot in 1..MAX_OWNERS {
            let e = &self.entries[slot];
            if !matches!(e.state, OwnerState::Free) && e.pod_uid == pod_uid {
                return Some(OwnerHandle {
                    slot: slot as u16,
                    generation: e.generation,
                });
            }
        }
        None
    }

    /// True when `h` may keep USING resources it already holds — established
    /// connections, held provider handles, committed queue slots. `Active`,
    /// `Draining`, and `Paused` qualify: a draining owner keeps serving until
    /// revoked (rfc_owner_drain_and_logs.md §3.5), and a paused owner keeps
    /// everything it holds — pause is reversible, so revoking use would turn
    /// resume into a partial re-admission (rfc_workload_lifecycle.md §3.2).
    pub fn authorize_use(&self, h: OwnerHandle) -> bool {
        self.lookup(h)
            .map(|e| {
                matches!(
                    e.state,
                    OwnerState::Active | OwnerState::Draining | OwnerState::Paused
                )
            })
            .unwrap_or(false)
    }

    /// True when `h` may ADMIT new work — new allocation, open, accept, queue
    /// grant, timer arm. Only `Active` qualifies: admission closes the moment a
    /// drain begins, which is what lets in-flight work run dry
    /// (rfc_owner_drain_and_logs.md §3.5). A `Paused` owner is likewise
    /// admission-closed — the same §3.5 gate, reopened by `owner_resume`.
    pub fn authorize_admit(&self, h: OwnerHandle) -> bool {
        self.lookup(h)
            .map(|e| matches!(e.state, OwnerState::Active))
            .unwrap_or(false)
    }

    /// Transition an owner to a new state. Returns `false` for a stale handle.
    pub fn set_state(&mut self, h: OwnerHandle, state: OwnerState) -> bool {
        match self.lookup_mut(h) {
            Some(e) => {
                e.state = state;
                true
            }
            None => false,
        }
    }

    /// Move an owner into `Draining` (rfc_k8s.md §12.3).
    pub fn begin_drain(&mut self, h: OwnerHandle) -> bool {
        self.set_state(h, OwnerState::Draining)
    }

    /// Free `h`'s slot. The generation is retained so the next `alloc` bumps it;
    /// the slot's state becomes `Free`, which already invalidates outstanding
    /// handles via `lookup`/`authorize`. Caller is responsible for reclaiming
    /// owner-scoped resources first. The system slot cannot be freed.
    pub fn free(&mut self, h: OwnerHandle) -> bool {
        if h.is_system() || !self.slot_valid(h) {
            return false;
        }
        let e = &mut self.entries[h.slot as usize];
        if e.generation != h.generation || matches!(e.state, OwnerState::Free) {
            return false;
        }
        e.state = OwnerState::Free;
        e.pod_uid = [0; 16];
        e.acct = OwnerAccounting::ZERO;
        true
    }

    /// Free every non-system owner slot (generation counters preserved, so
    /// later installs still issue strictly higher generations). Used by the
    /// plan-apply path: the composed plan is authoritative for residency
    /// (rfc_k8s.md §11), so owners absent from the new plan are revoked here
    /// before the plan's owners are installed.
    pub fn reset_workloads(&mut self) {
        for e in self.entries.iter_mut().skip(1) {
            e.state = OwnerState::Free;
            e.pod_uid = [0; 16];
            e.acct = OwnerAccounting::ZERO;
        }
    }

    /// The entry at `slot`, regardless of state. `None` only for an
    /// out-of-range slot. Read-only view for status/telemetry aggregation
    /// (rfc_k8s.md §18.2 — the owner-status surface walks resident slots).
    pub fn entry_at(&self, slot: usize) -> Option<&OwnerEntry> {
        self.entries.get(slot)
    }

    /// Number of active workload owners (excludes the system slot).
    pub fn active_workload_count(&self) -> usize {
        self.entries[1..]
            .iter()
            .filter(|e| !matches!(e.state, OwnerState::Free))
            .count()
    }

    // ── Per-owner resource accounting ───────────────────────────────────────
    //
    // Caps are the admitted hard limits from the signed resource profile,
    // installed by the node agent at reservation. A cap of 0 means
    // "unset/unlimited"; the system owner is never charged or capped. While
    // every allocation is system-owned, this accounting is inert.

    /// Install the admitted state/buffer byte caps for an owner.
    pub fn set_caps(&mut self, h: OwnerHandle, state_cap: u32, buffer_cap: u32) -> bool {
        match self.lookup_mut(h) {
            Some(e) => {
                e.acct.state_cap = state_cap;
                e.acct.buffer_cap = buffer_cap;
                true
            }
            None => false,
        }
    }

    /// Charge `bytes` of module state to `h`. Returns `Err(())` if it would
    /// exceed the owner's cap (the caller must then reject the allocation), or
    /// if `h` is stale. The system owner is always permitted.
    #[allow(
        clippy::result_unit_err,
        reason = "the failure is a payload-free cap-exceeded/stale signal; the \
                  caller only branches on success vs failure"
    )]
    pub fn charge_state(&mut self, h: OwnerHandle, bytes: u32) -> Result<(), ()> {
        if h.is_system() {
            return Ok(());
        }
        let e = self.lookup_mut(h).ok_or(())?;
        let next = e.acct.state_bytes.saturating_add(bytes);
        if e.acct.state_cap != 0 && next > e.acct.state_cap {
            return Err(());
        }
        e.acct.state_bytes = next;
        Ok(())
    }

    /// Release `bytes` of previously charged module state. Saturating.
    pub fn uncharge_state(&mut self, h: OwnerHandle, bytes: u32) {
        if h.is_system() {
            return;
        }
        if let Some(e) = self.lookup_mut(h) {
            e.acct.state_bytes = e.acct.state_bytes.saturating_sub(bytes);
        }
    }

    /// Charge `bytes` of channel-buffer memory to `h`. See [`charge_state`].
    #[allow(
        clippy::result_unit_err,
        reason = "the failure is a payload-free cap-exceeded/stale signal; the \
                  caller only branches on success vs failure"
    )]
    pub fn charge_buffer(&mut self, h: OwnerHandle, bytes: u32) -> Result<(), ()> {
        if h.is_system() {
            return Ok(());
        }
        let e = self.lookup_mut(h).ok_or(())?;
        let next = e.acct.buffer_bytes.saturating_add(bytes);
        if e.acct.buffer_cap != 0 && next > e.acct.buffer_cap {
            return Err(());
        }
        e.acct.buffer_bytes = next;
        Ok(())
    }

    /// Release `bytes` of previously charged channel-buffer memory. Saturating.
    pub fn uncharge_buffer(&mut self, h: OwnerHandle, bytes: u32) {
        if h.is_system() {
            return;
        }
        if let Some(e) = self.lookup_mut(h) {
            e.acct.buffer_bytes = e.acct.buffer_bytes.saturating_sub(bytes);
        }
    }

    /// Bytes currently charged to `h` (state, buffer). Zero for a stale handle.
    pub fn charged_bytes(&self, h: OwnerHandle) -> (u32, u32) {
        match self.lookup(h) {
            Some(e) => (e.acct.state_bytes, e.acct.buffer_bytes),
            None => (0, 0),
        }
    }
}

impl Default for OwnerTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross-owner access predicate: a caller may touch a target resource when the
/// target is system-owned or the same owner. Explicit cross-owner bindings
/// (rfc_k8s.md §10.2, §14 invariant 6) are not modeled by this predicate.
///
/// On single-tenant builds this is a compile-time `true` with no instructions.
#[cfg(feature = "multitenant")]
#[inline]
pub fn same_or_system(caller: OwnerHandle, target: OwnerHandle) -> bool {
    target.is_system() || caller.slot == target.slot
}

/// Single-tenant no-op (everything is the one owner).
#[cfg(not(feature = "multitenant"))]
#[inline(always)]
pub fn same_or_system(_caller: OwnerHandle, _target: OwnerHandle) -> bool {
    true
}

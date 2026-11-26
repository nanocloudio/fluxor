//! Workload owner model.
//!
//! Each resident workload maps to a bounded `OwnerHandle { slot, generation }`,
//! distinct from its durable `owner_uid` and from scheduler module
//! indices. Every workload-owned object (module, channel, buffer, provider
//! handle, endpoint lease, timer, telemetry record) is stamped with its owner
//! so the runtime can authorize access, account resources, and reclaim
//! everything on deletion. Node graph components use [`OWNER_NODE`]
//! (slot 0).
//!
//! Generation guard: every slot carries a reuse generation that increases on
//! each allocation. A handle from a deleted workload fails [`OwnerTable::authorize`]
//! after the slot is reused, because the generation no longer matches; it also
//! fails immediately on free, because the slot's state is no longer `Active`.
//!
//! One shape on every target: the owner table is sized at boot from the
//! plan's `owners` ceiling (`resource_ledger::plan`), so an image whose plan
//! holds only the node owner carries one slot and every handle it stamps is
//! [`OWNER_NODE`].
//!
//! Authority: an owner is also the authority its modules act with, unless it
//! was admitted to act with the node's ([`Authority::Node`]). The owner
//! handle stays the lifecycle — what is stamped, charged, paused, freed and
//! released — while [`OwnerTable::authority_of`] answers whose authority a
//! call carries: which provider layers it reaches, the node's own or the
//! workload layers that serve workloads. Only a live add that a
//! node-authority module places with `ADD_FLAG_CREATOR_AUTHORITY` acts with
//! the node's.

use crate::abi::contracts::resource::{
    OWNER_LINE_BUFFER, OWNER_LINE_COUNT, OWNER_LINE_STATE, OWNER_LINE_STORAGE,
};

/// The owner-slot RANGE, not a table size: the owner table — and every
/// per-owner table beside it (log rings, code-pack regions, workload slots)
/// — is sized at boot from the plan's `owners` ceiling (the node owner's slot, the
/// resident workloads and the owner reserve, `resource_ledger::plan`). What
/// this bounds is what a slot may be at all: the graph backend's workload
/// index, which shares a handle index space with the host-process backend's
/// above `0x1000` (`platform::linux::workload::HOST_SLOT_BASE`). A plan past
/// it is refused at boot naming `owners`. Wire fields carrying a slot are
/// `u16`.
pub const MAX_OWNERS: usize = 4096;

/// The compiled size of an owner-keyed table: the profile's static owner
/// figure where its tables are static arrays (wasm), else the domain, which a
/// table sized at boot does not reserve.
pub const OWNER_TABLE_SLOTS: usize =
    match crate::kernel::config::static_pool(crate::abi::contracts::resource::POOL_OWNERS) {
        Some(n) => n,
        None => MAX_OWNERS,
    };

const _: () = assert!(
    MAX_OWNERS >= 1,
    "MAX_OWNERS must include the node owner's slot"
);
const _: () = assert!(OWNER_TABLE_SLOTS >= 1 && OWNER_TABLE_SLOTS <= MAX_OWNERS);
// Slot is a u16; keep the table within that index range.
const _: () = assert!(MAX_OWNERS <= u16::MAX as usize);

/// A bounded runtime capability identifying one workload owner. Not persisted
/// as identity — the owner UID is the durable identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnerHandle {
    pub slot: u16,
    pub generation: u32,
}

/// The node owner. Platform drivers, the network/storage/telemetry
/// substrate, the graph manager, OTA, and the node agent run as this owner and
/// cannot be replaced by ordinary workload updates.
pub const OWNER_NODE: OwnerHandle = OwnerHandle {
    slot: 0,
    generation: 0,
};

impl OwnerHandle {
    #[inline]
    pub const fn is_node(&self) -> bool {
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
    /// Reversible quiesce: admission is closed (`authorize_admit` fails)
    /// and the scheduler skips the owner's graphs, but held resources stay
    /// valid (`authorize_use` passes) so `owner_resume` restores the exact
    /// pre-pause posture. Weaker than `Draining` — no `module_drain`, no
    /// channel-empty requirement.
    Paused,
}

/// One ledger line of an owner: bytes charged against a cap (0 = uncapped).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Line {
    pub used: u64,
    pub cap: u64,
}

/// Why a charge to an owner's line was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChargeRefused {
    /// The handle is stale, or the owner holds no such line.
    NoLine,
    /// The charge would take the line past its cap.
    Cap,
}

/// Per-owner resource accounting and hard caps: one ledger line per
/// `resource::OWNER_LINE_*`, and the counts of what the owner holds. The
/// state and buffer lines every owner holds; the storage line only an owner
/// whose admission installed one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnerAccounting {
    pub lines: [Line; OWNER_LINE_COUNT],
    /// Bit `n` set: line `n` is installed.
    pub present: u8,
    pub modules: u16,
    pub edges: u16,
    pub endpoints: u16,
    pub providers: u16,
    pub timers: u16,
    pub isolated_slots: u16,
}

/// The lines every owner holds from allocation: state and buffer.
const BASE_LINES: u8 = 0b011;

impl OwnerAccounting {
    pub const ZERO: OwnerAccounting = OwnerAccounting {
        lines: [Line { used: 0, cap: 0 }; OWNER_LINE_COUNT],
        present: BASE_LINES,
        modules: 0,
        edges: 0,
        endpoints: 0,
        providers: 0,
        timers: 0,
        isolated_slots: 0,
    };

    /// A planned owner's accounting: the base lines and an uncapped storage
    /// line. An allocated owner holds the base lines alone until its
    /// admission installs a storage line (a live add's, a `CREATE`'s header).
    const ADMITTED: OwnerAccounting = OwnerAccounting {
        present: BASE_LINES | 1 << OWNER_LINE_STORAGE,
        ..OwnerAccounting::ZERO
    };

    /// Line `line` when installed.
    pub fn line(&self, line: u16) -> Option<Line> {
        let i = line as usize;
        (i < OWNER_LINE_COUNT && self.present & (1 << i) != 0).then(|| self.lines[i])
    }
}

/// Whose authority an owner's modules act with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Authority {
    /// Its own: a workload, walled from the node's providers and served by
    /// the node's workload layers.
    Own,
    /// The node's: it reaches the node's provider layers as the node does,
    /// and no workload layer, while its lifecycle stays its own.
    Node,
}

/// One entry in the owner table.
#[derive(Clone, Copy)]
pub struct OwnerEntry {
    pub owner_uid: [u8; 16],
    pub generation: u32,
    pub state: OwnerState,
    pub acct: OwnerAccounting,
    pub authority: Authority,
    /// How many times the kernel instantiated this owner's modules: 1 from
    /// its first activation, one more for each install of the same owner
    /// (a rebuild re-instantiates its modules). Kept when the slot is freed.
    pub activations: u32,
    /// How the drain of the owner at this `generation` ended
    /// (`workload::owners::DRAIN_*`), kept when the slot is freed until a
    /// new owner takes it.
    pub drain: u8,
    /// When the drain freed it, unix seconds of the platform's clock (0:
    /// not freed by a drain).
    pub drained_at: u64,
}

impl OwnerEntry {
    const EMPTY: OwnerEntry = OwnerEntry {
        owner_uid: [0; 16],
        generation: 0,
        state: OwnerState::Free,
        acct: OwnerAccounting::ZERO,
        authority: Authority::Own,
        activations: 0,
        drain: 0,
        drained_at: 0,
    };

    const NODE: OwnerEntry = OwnerEntry {
        owner_uid: [0; 16],
        generation: 0,
        state: OwnerState::Active,
        acct: OwnerAccounting::ZERO,
        authority: Authority::Node,
        activations: 0,
        drain: 0,
        drained_at: 0,
    };
}

/// Bounded table of owner slots. Slot 0 is permanently the node owner.
///
/// On Linux, aarch64 bare metal and RP the table is sized at boot to the
/// plan's `owners` ceiling — the node owner's slot, the resident workloads and the
/// owner reserve — within the owner-slot range `MAX_OWNERS`; on wasm it is
/// the profile's static array.
pub struct OwnerTable {
    entries: crate::kernel::mem::table::Table<OwnerEntry, OWNER_TABLE_SLOTS>,
    /// The kernel's table ([`OwnerTable::kernel`]): its owners' log rings
    /// are created with them and freed with them. A free-standing table (a
    /// test's) holds no rings.
    #[cfg(feature = "host-linux")]
    logs: bool,
}

/// Slot 0 is the node owner; every other slot starts free.
#[cfg(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp"))]
fn owner_init(slot: usize) -> OwnerEntry {
    if slot == 0 {
        OwnerEntry::NODE
    } else {
        OwnerEntry::EMPTY
    }
}

/// The owners a table no plan has sized takes on first use: the plan's
/// defaults, within the owner-slot range.
#[cfg(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp"))]
fn owner_default() -> usize {
    (crate::kernel::sys::resource_ledger::ceiling(crate::abi::contracts::resource::POOL_OWNERS)
        as usize)
        .clamp(1, MAX_OWNERS)
}

impl OwnerTable {
    /// A fresh table with only the node owner's slot active.
    pub const fn new() -> Self {
        #[cfg(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp"))]
        {
            OwnerTable {
                entries: crate::kernel::mem::table::Table::new_planned(owner_init, owner_default),
                #[cfg(feature = "host-linux")]
                logs: false,
            }
        }
        #[cfg(not(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp")))]
        {
            let mut entries = [OwnerEntry::EMPTY; OWNER_TABLE_SLOTS];
            entries[0] = OwnerEntry::NODE;
            OwnerTable {
                entries: crate::kernel::mem::table::Table::from_array(entries),
            }
        }
    }

    /// The kernel's table: as [`new`](Self::new), and on a hosted kernel each
    /// owner's log ring (`owner_log`) lives exactly as long as the owner.
    pub const fn kernel() -> Self {
        #[cfg(feature = "host-linux")]
        {
            let mut t = Self::new();
            t.logs = true;
            t
        }
        #[cfg(not(feature = "host-linux"))]
        {
            Self::new()
        }
    }

    /// Size the table to `n` slots, all live (slot 0 the node owner).
    ///
    /// # Safety
    /// Graph-preparation context: no reference into the table is live.
    pub unsafe fn size(&self, n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
        if n > MAX_OWNERS {
            return Err(crate::kernel::mem::table::TableError::Ceiling);
        }
        self.entries.reserve(n)?;
        self.entries.grow(n)
    }

    /// Slots the table holds, the node owner's slot among them: its live length,
    /// what a per-owner walk iterates.
    pub fn slot_count(&self) -> usize {
        self.slots().len()
    }

    /// A new owner took `slot`: its log ring starts (or, for the same
    /// triple, carries on).
    #[inline]
    fn ring_installed(&self, _slot: u16, _uid: [u8; 16], _generation: u32) {
        #[cfg(feature = "host-linux")]
        if self.logs {
            crate::kernel::workload::owner_log::install_slot(_slot as usize, _uid, _generation);
        }
    }

    /// `slot`'s owner is gone: its log ring goes with it.
    #[inline]
    fn ring_released(&self, _slot: u16) {
        #[cfg(feature = "host-linux")]
        if self.logs {
            crate::kernel::workload::owner_log::release_slot(_slot as usize);
        }
    }

    /// Release the log ring of every free slot: after a plan is applied,
    /// the owners it did not re-install are gone, and their rings with them.
    /// A re-installed owner kept its ring (rebuild survival).
    pub fn release_free_rings(&self) {
        for (slot, e) in self.slots().iter().enumerate().skip(1) {
            if matches!(e.state, OwnerState::Free) {
                self.ring_released(slot as u16);
            }
        }
    }

    /// The live slots.
    #[inline]
    fn slots(&self) -> &[OwnerEntry] {
        &self.entries
    }

    /// Mutable view of the live slots.
    #[inline]
    fn slots_mut(&mut self) -> &mut [OwnerEntry] {
        let _ = self.slots();
        &mut self.entries
    }

    /// Allocate the lowest free slot for `owner_uid`. The reuse generation is
    /// bumped monotonically so a stale handle cannot match after reuse.
    /// Returns `None` when every workload slot is occupied. The
    /// lowest-free-slot rule is required by the deterministic-composition
    /// contract.
    pub fn alloc(&mut self, owner_uid: [u8; 16]) -> Option<OwnerHandle> {
        {
            use crate::abi::contracts::resource::POOL_OWNERS;
            use crate::kernel::sys::resource_ledger as ledger;
            let live = self.active_workload_count() as u32;
            if !ledger::enforced_allows(POOL_OWNERS, live + 1) {
                ledger::deny(POOL_OWNERS);
                return None;
            }
        }
        // Empty on a table of the node owner's slot alone.
        for slot in 1..self.slots().len() {
            if matches!(self.entries[slot].state, OwnerState::Free) {
                let generation = self.entries[slot].generation.wrapping_add(1);
                self.entries[slot] = OwnerEntry {
                    owner_uid,
                    generation,
                    state: OwnerState::Reserved,
                    acct: OwnerAccounting::ZERO,
                    authority: Authority::Own,
                    activations: 1,
                    drain: 0,
                    drained_at: 0,
                };
                self.ring_installed(slot as u16, owner_uid, generation);
                return Some(OwnerHandle {
                    slot: slot as u16,
                    generation,
                });
            }
        }
        crate::kernel::sys::resource_ledger::deny(crate::abi::contracts::resource::POOL_OWNERS);
        None
    }

    /// Install an owner at a specific `slot`/`generation` as dictated by a
    /// composed plan (the plan is authoritative for slot and
    /// generation, unlike [`alloc`](Self::alloc) which picks them). The owner is
    /// installed `Active`. Returns `None` for the node owner's slot, an out-of-range
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
        owner_uid: [u8; 16],
        state_cap: u32,
        buffer_cap: u32,
    ) -> Option<OwnerHandle> {
        let s = slot as usize;
        if s == 0 || s >= self.slots().len() {
            return None;
        }
        // Never lower a slot's generation: that is the reuse guard's core
        // invariant. Equal is allowed (idempotent re-apply of the same plan).
        if generation < self.entries[s].generation {
            return None;
        }
        let mut acct = OwnerAccounting::ADMITTED;
        acct.lines[OWNER_LINE_STATE as usize].cap = u64::from(state_cap);
        acct.lines[OWNER_LINE_BUFFER as usize].cap = u64::from(buffer_cap);
        // The same owner installed again is instantiated again.
        let activations = if generation == self.entries[s].generation {
            self.entries[s].activations.saturating_add(1)
        } else {
            1
        };
        self.entries[s] = OwnerEntry {
            owner_uid,
            generation,
            state: OwnerState::Active,
            acct,
            authority: Authority::Own,
            activations,
            drain: 0,
            drained_at: 0,
        };
        self.ring_installed(slot, owner_uid, generation);
        Some(OwnerHandle { slot, generation })
    }

    #[inline]
    fn slot_valid(&self, h: OwnerHandle) -> bool {
        (h.slot as usize) < self.slots().len()
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

    /// Resolve the live owner handle for a durable `owner_uid` — the bridge from
    /// the persistent identity (the owner UID) to the runtime
    /// capability. A provider admitting owner-scoped work (e.g. the `workload`
    /// host-process backend spawning a workload's container) references the
    /// plan-allocated owner this way rather than allocating one itself. Returns
    /// `None` if no non-`Free` slot carries that uid. The caller still gates on
    /// [`authorize_admit`](Self::authorize_admit) — a `Draining`/`Revoked`
    /// owner resolves but must not admit new work.
    pub fn find_by_uid(&self, owner_uid: [u8; 16]) -> Option<OwnerHandle> {
        // Empty on a table of the node owner's slot alone.
        for slot in 1..self.slots().len() {
            let e = &self.entries[slot];
            if !matches!(e.state, OwnerState::Free) && e.owner_uid == owner_uid {
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
    /// revoked, and a paused owner keeps everything it holds — pause is
    /// reversible, so revoking use would turn resume into a partial
    /// re-admission.
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
    /// grant, timer arm. Only `Active` qualifies: admission closes the moment
    /// a drain begins, which is what lets in-flight work run dry. A `Paused`
    /// owner is likewise admission-closed — the same gate, reopened by
    /// `owner_resume`.
    pub fn authorize_admit(&self, h: OwnerHandle) -> bool {
        self.lookup(h)
            .map(|e| matches!(e.state, OwnerState::Active))
            .unwrap_or(false)
    }

    /// True when `h`'s own modules may admit new work for themselves — the
    /// gate on a module's own allocations, opens and arms. An `Active`
    /// owner's may, and so may a `Reserved` one's: an add is instantiating
    /// it, and each module's `module_new` allocates, opens and arms what it
    /// will run with, as its owner, before the add publishes. A reserved
    /// owner's modules are not yet scheduled, so `module_new` is the only code
    /// that runs as it, and an add rolled back releases what it admitted.
    /// Work admitted on an owner's behalf by anyone else is gated by
    /// [`authorize_admit`](Self::authorize_admit).
    pub fn authorize_own_admit(&self, h: OwnerHandle) -> bool {
        self.lookup(h)
            .map(|e| matches!(e.state, OwnerState::Reserved | OwnerState::Active))
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

    /// Move an owner into `Draining`.
    pub fn begin_drain(&mut self, h: OwnerHandle) -> bool {
        let drained = self.set_state(h, OwnerState::Draining);
        if drained {
            // The modules serving its lanes admit nothing new for it.
            crate::kernel::workload::lanes::drain(h);
        }
        drained
    }

    /// Free `h`'s slot. The generation is retained so the next `alloc` bumps it;
    /// the slot's state becomes `Free`, which already invalidates outstanding
    /// handles via `lookup`/`authorize`. Caller is responsible for reclaiming
    /// owner-scoped resources first. The node owner's slot cannot be freed.
    pub fn free(&mut self, h: OwnerHandle) -> bool {
        if h.is_node() || !self.slot_valid(h) {
            return false;
        }
        let e = &mut self.entries[h.slot as usize];
        if e.generation != h.generation || matches!(e.state, OwnerState::Free) {
            return false;
        }
        e.state = OwnerState::Free;
        e.owner_uid = [0; 16];
        e.acct = OwnerAccounting::ZERO;
        e.authority = Authority::Own;
        self.ring_released(h.slot);
        true
    }

    /// Free every non-node owner slot (generation counters preserved, so
    /// later installs still issue strictly higher generations). Used by the
    /// plan-apply path: the composed plan is authoritative for residency,
    /// so owners absent from the new plan are revoked here before the
    /// plan's owners are installed. Log rings are left for the apply to
    /// release ([`release_free_rings`](Self::release_free_rings)) once it
    /// knows which owners came back.
    pub fn reset_workloads(&mut self) {
        for e in self.slots_mut().iter_mut().skip(1) {
            e.state = OwnerState::Free;
            e.owner_uid = [0; 16];
            e.acct = OwnerAccounting::ZERO;
            e.authority = Authority::Own;
        }
    }

    /// Record how the drain of owner `(slot, generation)` ended, on its
    /// freed slot: `outcome` (`workload::owners::DRAIN_*`) at `at` (unix
    /// seconds, 0 when no drain ran here). A slot this table never held
    /// at that generation takes it, so the owner's handles stay dead and the
    /// next owner there gets a higher one; a slot a newer owner holds, or a
    /// live one, is left as it is. Returns whether the outcome was recorded.
    pub fn record_drain(&mut self, slot: u16, generation: u32, outcome: u8, at: u64) -> bool {
        let s = slot as usize;
        if s == 0 || s >= self.slots().len() {
            return false;
        }
        let e = &mut self.slots_mut()[s];
        if generation < e.generation
            || (generation == e.generation && !matches!(e.state, OwnerState::Free))
        {
            return false;
        }
        if generation > e.generation {
            e.generation = generation;
            e.activations = 0;
        }
        e.drain = outcome;
        e.drained_at = at;
        true
    }

    /// The entry at `slot`, regardless of state. `None` only for an
    /// out-of-range slot. Read-only view for status/telemetry aggregation
    /// (the owner-status surface walks resident slots).
    pub fn entry_at(&self, slot: usize) -> Option<&OwnerEntry> {
        self.slots().get(slot)
    }

    /// Number of active workload owners (excludes the node owner's slot).
    pub fn active_workload_count(&self) -> usize {
        self.entries[1..]
            .iter()
            .filter(|e| !matches!(e.state, OwnerState::Free))
            .count()
    }

    // ── Per-owner ledger lines ──────────────────────────────────────────────
    //
    // Caps are the admitted hard limits, installed at reservation. A cap of
    // 0 means uncapped; the node owner is never charged or capped.

    /// Install the admitted state/buffer byte caps for an owner.
    pub fn set_caps(&mut self, h: OwnerHandle, state_cap: u32, buffer_cap: u32) -> bool {
        self.set_line(h, OWNER_LINE_STATE, u64::from(state_cap))
            && self.set_line(h, OWNER_LINE_BUFFER, u64::from(buffer_cap))
    }

    /// Install line `line` for `h` with `cap` (0 = uncapped), keeping what
    /// it has charged. Returns `false` for a stale handle or an unknown line.
    pub fn set_line(&mut self, h: OwnerHandle, line: u16, cap: u64) -> bool {
        let i = line as usize;
        if i >= OWNER_LINE_COUNT {
            return false;
        }
        match self.lookup_mut(h) {
            Some(e) => {
                e.acct.present |= 1 << i;
                e.acct.lines[i].cap = cap;
                true
            }
            None => false,
        }
    }

    /// Remove line `line` from `h`: every later charge to it is refused.
    /// The base lines cannot be removed.
    pub fn remove_line(&mut self, h: OwnerHandle, line: u16) -> bool {
        let i = line as usize;
        if i >= OWNER_LINE_COUNT || BASE_LINES & (1 << i) != 0 {
            return false;
        }
        match self.lookup_mut(h) {
            Some(e) => {
                e.acct.present &= !(1 << i);
                e.acct.lines[i] = Line::default();
                true
            }
            None => false,
        }
    }

    /// Admit an owner to act with the node's authority. It holds no storage
    /// line: the workload layers do not serve it, so nothing roots its
    /// storage. Returns `false` for a stale handle.
    pub fn set_node_authority(&mut self, h: OwnerHandle) -> bool {
        match self.lookup_mut(h) {
            Some(e) => {
                e.authority = Authority::Node;
                e.acct.present &= !(1 << OWNER_LINE_STORAGE);
                e.acct.lines[OWNER_LINE_STORAGE as usize] = Line::default();
                true
            }
            None => false,
        }
    }

    /// The authority `h` acts with: [`OWNER_NODE`] for the node owner and
    /// for an owner admitted with the node's authority, `h` itself otherwise
    /// — including a handle that no longer resolves, which so fails closed as
    /// the workload it was.
    pub fn authority_of(&self, h: OwnerHandle) -> OwnerHandle {
        if h.is_node() {
            return OWNER_NODE;
        }
        match self.lookup(h) {
            Some(e) if e.authority == Authority::Node => OWNER_NODE,
            _ => h,
        }
    }

    /// Charge `bytes` to `h`'s line `line`. `held`: bytes the owner already
    /// holds, charged past the cap if need be — an owner over its cap can
    /// shrink but not grow. The node owner is never charged.
    pub fn charge(
        &mut self,
        h: OwnerHandle,
        line: u16,
        bytes: u64,
        held: bool,
    ) -> Result<(), ChargeRefused> {
        if h.is_node() {
            return Ok(());
        }
        let i = line as usize;
        let e = self.lookup_mut(h).ok_or(ChargeRefused::NoLine)?;
        if i >= OWNER_LINE_COUNT || e.acct.present & (1 << i) == 0 {
            return Err(ChargeRefused::NoLine);
        }
        let l = &mut e.acct.lines[i];
        let next = l.used.saturating_add(bytes);
        if !held && l.cap != 0 && next > l.cap {
            return Err(ChargeRefused::Cap);
        }
        l.used = next;
        Ok(())
    }

    /// Give `bytes` back to `h`'s line `line`. Saturating; nothing for the
    /// node owner, a stale handle or an absent line.
    pub fn release(&mut self, h: OwnerHandle, line: u16, bytes: u64) {
        if h.is_node() {
            return;
        }
        let i = line as usize;
        if let Some(e) = self.lookup_mut(h) {
            if i < OWNER_LINE_COUNT && e.acct.present & (1 << i) != 0 {
                e.acct.lines[i].used = e.acct.lines[i].used.saturating_sub(bytes);
            }
        }
    }

    /// `h`'s line `line`: `None` for a stale handle or an absent line.
    pub fn line(&self, h: OwnerHandle, line: u16) -> Option<Line> {
        self.lookup(h).and_then(|e| e.acct.line(line))
    }

    /// Drop every workload owner's charges on `line` back to zero, keeping
    /// their caps. The resident instantiation pass re-folds the state
    /// charges from the live module table on each rebuild; without this it
    /// would add a rebuild's modules to the previous pass's total for any
    /// slot that survived.
    pub fn clear_charges(&mut self, line: u16) {
        let i = line as usize;
        if i >= OWNER_LINE_COUNT {
            return;
        }
        for e in self.slots_mut().iter_mut().skip(1) {
            e.acct.lines[i].used = 0;
        }
    }
}

impl Default for OwnerTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross-owner access predicate: a caller may touch a target resource when the
/// target is node-owned or the same owner — slot and generation both, so a
/// resource stamped by an owner that is gone is never the next owner of its
/// slot's. Explicit cross-owner bindings are not modeled by this predicate.
#[inline]
pub fn same_or_node(caller: OwnerHandle, target: OwnerHandle) -> bool {
    target.is_node() || caller == target
}

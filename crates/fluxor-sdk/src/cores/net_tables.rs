// Core: net_tables — the node's `net.route` and `net.policy` stores, as the
// one provider of each holds them.
//
// Layer: cores (library code in `fluxor-sdk`, linked by its consumers — NOT a
// wire contract, so it is not ABI and not hashed into the ABI-surface
// digest).
//
// A provider of `net.route` / `net.policy` is this store plus a realization:
// the bare-metal `ip` realizes the tables itself in its next step (it reads
// them here and records each entry's state with `set_state`); the Linux host
// provider renders them to the host as a replace arrives (a [`RouteRealizer`]
// or a policy apply hook, run before the store keeps the table). The
// argument decoding, the bounds, the validation, the one-writer binding, the
// generations and the READ answers live here once, so every provider refuses
// the same tables and answers the same bytes.
//
// Storage is the caller's: every table is a slice it carved from its heap,
// sized from its own params, and nothing here allocates. A provider's calls
// arrive one at a time: a module provider and every module it serves share
// one execution domain (the composer's rule), and the host provider serves
// its lane from one thread. So there are no locks here.
//
// Identity. A writer or an enforcer is a module occupancy — `(module slot,
// slot generation)` as the kernel attests it (`CALLER_MODULE`) — and is live
// while the kernel says so (`MODULE_LIVE`). A binding whose occupancy ended
// is stale: the next caller takes it over. Authority (the node's, from
// `CALLER_AUTHORITY`) is the dispatcher's check, made before the call
// reaches a store.
//
// Panic-free and table-free: every access is bounds-checked and every hook
// is a generic, never a trait object (a vtable is a table of absolute
// pointers, which a module loaded at any address cannot hold), as modules
// link this under the strict PIC rules.

use fluxor_abi::contracts::net::policy as pol;
use fluxor_abi::contracts::net::route as rt;

const EINVAL: i32 = -22;
const EBUSY: i32 = -16;
const ENOSPC: i32 = -28;
const ENOENT: i32 = -2;
const ERANGE: i32 = -34;
const EEXIST: i32 = -17;
const E2BIG: i32 = -7;
const EACCES: i32 = -13;
const ENOSYS: i32 = -38;

/// A module occupancy: the module slot and that slot's generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Writer {
    pub slot: u16,
    pub gen: u32,
}

impl Writer {
    /// The occupancy in a `CALLER_MODULE` record (`[idx u16][pad u16][gen
    /// u32]…`).
    pub fn from_record(r: &[u8]) -> Option<Writer> {
        Some(Writer {
            slot: u16::from_le_bytes([*r.first()?, *r.get(1)?]),
            gen: u32::from_le_bytes([*r.get(4)?, *r.get(5)?, *r.get(6)?, *r.get(7)?]),
        })
    }

    /// The 8-byte occupancy record `MODULE_LIVE` takes.
    pub fn record(self) -> [u8; 8] {
        let s = self.slot.to_le_bytes();
        let g = self.gen.to_le_bytes();
        [s[0], s[1], 0, 0, g[0], g[1], g[2], g[3]]
    }
}

/// Who is calling, as the dispatcher learned it from the kernel.
#[derive(Clone, Copy, Debug)]
pub struct Caller {
    /// The caller acts with the node's authority.
    pub node: bool,
    /// The caller's occupancy.
    pub writer: Writer,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    let mut v = [0u8; 8];
    for (i, d) in v.iter_mut().enumerate() {
        *d = *b.get(at + i)?;
    }
    Some(u64::from_le_bytes(v))
}

/// Copy `src` into `dst` from `at`; false when it does not fit.
fn put(dst: &mut [u8], at: usize, src: &[u8]) -> bool {
    let Some(end) = at.checked_add(src.len()) else {
        return false;
    };
    match dst.get_mut(at..end) {
        Some(d) => {
            for (d, s) in d.iter_mut().zip(src) {
                *d = *s;
            }
            true
        }
        None => false,
    }
}

/// Answer a CAPS call: the word into `arg`.
pub fn answer_caps(arg: &mut [u8], caps: u32) -> i32 {
    if put(arg, 0, &caps.to_le_bytes()) {
        0
    } else {
        EINVAL
    }
}

// ───────────────────────────── net.route ─────────────────────────────

const T_SEG: usize = 0;
const T_ROUTE: usize = 1;
const T_HELD: usize = 2;

/// The route store's scalars: what a provider keeps in its state between
/// calls (the tables are its heap slices, [`RouteTables`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct RouteMeta {
    /// Entries each table holds: segments, routes, held.
    pub count: [u16; 3],
    /// Each table's writer, once bound.
    pub writer: [Option<Writer>; 3],
    /// Moves on every stored replace.
    pub table_gen: u64,
    /// Moves on every stored replace and every entry state change; READ's
    /// leading word.
    pub state_gen: u64,
}

/// A platform's realization of the route tables, run as a replace arrives
/// (the host provider). A provider that realizes in its own step (bare-metal
/// `ip`) passes none and states entries with [`RouteTables::set_state`].
pub trait RouteRealizer {
    /// What the realization does now (`route::caps`).
    fn caps(&mut self) -> u32;
    /// Realize the whole segment table; `Err(errno)` refuses the replace and
    /// the stored table is left as it was.
    fn segments(&mut self, new: &[rt::Segment]) -> Result<(), i32>;
    /// Realize the whole peer-route table.
    fn routes(&mut self, new: &[rt::Route]) -> Result<(), i32>;
    /// Realize the whole held-address table.
    fn held(&mut self, new: &[rt::Held]) -> Result<(), i32>;
    /// Whether a workload is attached to segment `id` now.
    fn segment_in_use(&mut self, id: u16) -> bool;
    /// `(state, reason)` of entry `index` of table `kind`.
    fn state(&mut self, kind: u8, index: usize) -> (u8, u8);
    /// Held address `index`'s fence evidence `(install_gen, cutoff,
    /// cutoff_kind)`, zeros where there is none.
    fn held_evidence(&mut self, index: usize) -> (u32, u64, u8);
}

/// The realizer of a provider that realizes in its own step: passed as
/// `None::<&mut NoRealizer>`, never called.
pub struct NoRealizer;

impl RouteRealizer for NoRealizer {
    fn caps(&mut self) -> u32 {
        0
    }
    fn segments(&mut self, _: &[rt::Segment]) -> Result<(), i32> {
        Ok(())
    }
    fn routes(&mut self, _: &[rt::Route]) -> Result<(), i32> {
        Ok(())
    }
    fn held(&mut self, _: &[rt::Held]) -> Result<(), i32> {
        Ok(())
    }
    fn segment_in_use(&mut self, _: u16) -> bool {
        false
    }
    fn state(&mut self, _: u8, _: usize) -> (u8, u8) {
        (rt::state::PENDING, 0)
    }
    fn held_evidence(&mut self, _: usize) -> (u32, u64, u8) {
        (0, 0, 0)
    }
}

/// The route store over the caller's slices. Each table has a spare of the
/// same capacity, where a replace is decoded and checked before it is kept,
/// so a refused replace never touches the table in force.
pub struct RouteTables<'a> {
    pub meta: &'a mut RouteMeta,
    pub segs: &'a mut [rt::Segment],
    pub routes: &'a mut [rt::Route],
    pub held: &'a mut [rt::Held],
    pub spare_segs: &'a mut [rt::Segment],
    pub spare_routes: &'a mut [rt::Route],
    pub spare_held: &'a mut [rt::Held],
    pub seg_state: &'a mut [rt::EntryState],
    pub route_state: &'a mut [rt::EntryState],
    pub held_state: &'a mut [rt::EntryState],
}

impl RouteTables<'_> {
    fn n(&self, t: usize) -> usize {
        self.meta.count.get(t).copied().unwrap_or(0) as usize
    }

    /// The segments held.
    pub fn segments(&self) -> &[rt::Segment] {
        self.segs.get(..self.n(T_SEG)).unwrap_or(&[])
    }

    /// The peer routes held.
    pub fn peer_routes(&self) -> &[rt::Route] {
        self.routes.get(..self.n(T_ROUTE)).unwrap_or(&[])
    }

    /// The held addresses.
    pub fn held_addrs(&self) -> &[rt::Held] {
        self.held.get(..self.n(T_HELD)).unwrap_or(&[])
    }

    /// Segment `id`, if held.
    pub fn segment(&self, id: u16) -> Option<rt::Segment> {
        self.segments().iter().find(|s| s.id == id).copied()
    }

    /// The most specific segment whose prefix holds `addr` (of `family`).
    pub fn segment_for(&self, family: u8, addr: &[u8; rt::ADDR_LEN]) -> Option<rt::Segment> {
        self.segments()
            .iter()
            .filter(|s| s.prefix.contains(family, addr))
            .max_by_key(|s| s.prefix.len)
            .copied()
    }

    /// What an address naming `segment_id` (≥ 1) must satisfy before it is
    /// installed on it: the segment exists (`ENOENT`), and the address is the
    /// segment's family, inside its prefix and not its gateway (`EINVAL`).
    pub fn validate_attach(
        &self,
        family: u8,
        addr: &[u8; rt::ADDR_LEN],
        segment_id: u16,
    ) -> Result<rt::Segment, i32> {
        let Some(s) = self.segment(segment_id) else {
            return Err(ENOENT);
        };
        if !s.prefix.contains(family, addr) || s.gateway == *addr {
            return Err(EINVAL);
        }
        Ok(s)
    }

    fn may_write(&self, t: usize, w: Writer, live: &impl Fn(Writer) -> bool) -> bool {
        match self.meta.writer.get(t).copied().flatten() {
            None => true,
            Some(b) => b == w || !live(b),
        }
    }

    /// Release the bindings `w` holds (its module finished, faulted or was
    /// removed). Its tables stay.
    pub fn release(&mut self, w: Writer) {
        for b in self.meta.writer.iter_mut() {
            if *b == Some(w) {
                *b = None;
            }
        }
    }

    /// Clear every binding: a rebuilt graph's modules start unbound.
    pub fn reset_bindings(&mut self) {
        self.meta.writer = [None; 3];
    }

    fn kind(t: usize) -> u8 {
        match t {
            T_SEG => rt::entry::KIND_SEGMENT,
            T_ROUTE => rt::entry::KIND_ROUTE,
            _ => rt::entry::KIND_HELD,
        }
    }

    fn states(&mut self, t: usize) -> &mut [rt::EntryState] {
        match t {
            T_SEG => self.seg_state,
            T_ROUTE => self.route_state,
            _ => self.held_state,
        }
    }

    fn stored(&mut self, t: usize, n: usize, w: Writer) {
        if let Some(c) = self.meta.count.get_mut(t) {
            *c = n as u16;
        }
        let kind = Self::kind(t);
        for (i, e) in self.states(t).iter_mut().take(n).enumerate() {
            *e = rt::EntryState {
                kind,
                index: i as u16,
                ..rt::EntryState::EMPTY
            };
        }
        self.meta.table_gen = self.meta.table_gen.wrapping_add(1);
        self.meta.state_gen = self.meta.state_gen.wrapping_add(1);
        if let Some(b) = self.meta.writer.get_mut(t) {
            *b = Some(w);
        }
    }

    /// Capacity and writer: `ENOSPC` past the table, `EBUSY` while another
    /// live module is its writer.
    fn admit(
        &self,
        t: usize,
        n: usize,
        cap: usize,
        w: Writer,
        live: &impl Fn(Writer) -> bool,
    ) -> Result<(), i32> {
        if n > cap {
            return Err(ENOSPC);
        }
        if !self.may_write(t, w, live) {
            return Err(EBUSY);
        }
        Ok(())
    }

    /// SEGMENTS: replace the segment table, whole.
    pub fn replace_segments(
        &mut self,
        a: &[u8],
        w: Writer,
        live: &impl Fn(Writer) -> bool,
        attached: &impl Fn(u16) -> bool,
        mut realizer: Option<&mut impl RouteRealizer>,
    ) -> i32 {
        let Some(&n) = a.first() else {
            return EINVAL;
        };
        let n = n as usize;
        if let Err(e) = self.admit(
            T_SEG,
            n,
            self.segs.len().min(self.spare_segs.len()),
            w,
            live,
        ) {
            return e;
        }
        let mut at = 1;
        for i in 0..n {
            let Some((s, next)) = rt::segment_at(a, at) else {
                return EINVAL;
            };
            // Ids and gateways name one segment each.
            let dup = self.spare_segs.iter().take(i).any(|o| {
                o.id == s.id || (o.prefix.family == s.prefix.family && o.gateway == s.gateway)
            });
            if dup {
                return EINVAL;
            }
            match self.spare_segs.get_mut(i) {
                Some(d) => *d = s,
                None => return ENOSPC,
            }
            at = next;
        }
        if at != a.len() {
            return EINVAL;
        }
        // A segment a workload is attached to may not go or change.
        let had = self.n(T_SEG);
        let new = self.spare_segs.get(..n).unwrap_or(&[]);
        for o in self.segs.iter().take(had) {
            let kept = new
                .iter()
                .any(|s| s.id == o.id && s.prefix == o.prefix && s.gateway == o.gateway);
            let in_use = match realizer.as_deref_mut() {
                Some(r) => r.segment_in_use(o.id),
                None => attached(o.id),
            };
            if !kept && in_use {
                return EBUSY;
            }
        }
        if let Some(r) = realizer {
            if let Err(e) = r.segments(new) {
                return e;
            }
        }
        for (d, s) in self.segs.iter_mut().zip(self.spare_segs.iter().take(n)) {
            *d = *s;
        }
        self.stored(T_SEG, n, w);
        0
    }

    /// ROUTES: replace the peer-route table, whole.
    pub fn replace_routes(
        &mut self,
        a: &[u8],
        w: Writer,
        live: &impl Fn(Writer) -> bool,
        realizer: Option<&mut impl RouteRealizer>,
    ) -> i32 {
        let Some(n) = u16_at(a, 0).map(usize::from) else {
            return EINVAL;
        };
        let cap = self.routes.len().min(self.spare_routes.len());
        if let Err(e) = self.admit(T_ROUTE, n, cap, w, live) {
            return e;
        }
        if a.len() != 2 + n * rt::peer::SIZE {
            return EINVAL;
        }
        for i in 0..n {
            match rt::route_at(a, 2 + i * rt::peer::SIZE) {
                // A default route through a peer would take every destination
                // the node has no better route to — its uplink's included.
                Some(r) if r.prefix.len > 0 => match self.spare_routes.get_mut(i) {
                    Some(d) => *d = r,
                    None => return ENOSPC,
                },
                _ => return EINVAL,
            }
        }
        if let Some(r) = realizer {
            if let Err(e) = r.routes(self.spare_routes.get(..n).unwrap_or(&[])) {
                return e;
            }
        }
        for (d, s) in self.routes.iter_mut().zip(self.spare_routes.iter().take(n)) {
            *d = *s;
        }
        self.stored(T_ROUTE, n, w);
        0
    }

    /// HOLD: replace the held-address table, whole.
    pub fn replace_held(
        &mut self,
        a: &[u8],
        w: Writer,
        live: &impl Fn(Writer) -> bool,
        realizer: Option<&mut impl RouteRealizer>,
    ) -> i32 {
        let Some(n) = u16_at(a, 0).map(usize::from) else {
            return EINVAL;
        };
        let cap = self.held.len().min(self.spare_held.len());
        if let Err(e) = self.admit(T_HELD, n, cap, w, live) {
            return e;
        }
        if a.len() != 2 + n * rt::held::SIZE {
            return EINVAL;
        }
        for i in 0..n {
            let Some(h) = rt::held_at(a, 2 + i * rt::held::SIZE) else {
                return EINVAL;
            };
            let dup = self
                .spare_held
                .iter()
                .take(i)
                .any(|o| o.family == h.family && o.addr == h.addr);
            if dup {
                return EINVAL;
            }
            match self.spare_held.get_mut(i) {
                Some(d) => *d = h,
                None => return ENOSPC,
            }
        }
        if let Some(r) = realizer {
            if let Err(e) = r.held(self.spare_held.get(..n).unwrap_or(&[])) {
                return e;
            }
        }
        for (d, s) in self.held.iter_mut().zip(self.spare_held.iter().take(n)) {
            *d = *s;
        }
        self.stored(T_HELD, n, w);
        0
    }

    /// Record entry `index` of table `kind`'s state (the provider's own
    /// realization). READ's generation moves when anything changed.
    pub fn set_state(&mut self, e: rt::EntryState) {
        let t = match e.kind {
            rt::entry::KIND_SEGMENT => T_SEG,
            rt::entry::KIND_ROUTE => T_ROUTE,
            rt::entry::KIND_HELD => T_HELD,
            _ => return,
        };
        let n = self.n(t);
        let i = e.index as usize;
        if i >= n {
            return;
        }
        let changed = match self.states(t).get_mut(i) {
            Some(slot) if *slot != e => {
                *slot = e;
                true
            }
            _ => false,
        };
        if changed {
            self.meta.state_gen = self.meta.state_gen.wrapping_add(1);
        }
    }

    /// Ask the realizer for every entry's state and record what changed.
    fn refresh(&mut self, r: &mut impl RouteRealizer) {
        for t in [T_SEG, T_ROUTE, T_HELD] {
            let n = self.n(t);
            let kind = Self::kind(t);
            for i in 0..n {
                let (state, reason) = r.state(kind, i);
                let (install_gen, cutoff, cutoff_kind) = if t == T_HELD {
                    r.held_evidence(i)
                } else {
                    (0, 0, 0)
                };
                self.set_state(rt::EntryState {
                    kind,
                    state,
                    reason,
                    cutoff_kind,
                    index: i as u16,
                    install_gen,
                    cutoff,
                });
            }
        }
    }

    /// READ: `[state_generation:u64]` then every entry, in table order.
    /// `ERANGE` when they do not fit (the generation is still written).
    pub fn read(&mut self, out: &mut [u8], realizer: Option<&mut impl RouteRealizer>) -> i32 {
        if out.len() < 8 {
            return EINVAL;
        }
        if let Some(r) = realizer {
            self.refresh(r);
        }
        put(out, 0, &self.meta.state_gen.to_le_bytes());
        let total = self.n(T_SEG) + self.n(T_ROUTE) + self.n(T_HELD);
        let need = 8 + total * rt::entry::SIZE;
        if need > out.len() {
            return ERANGE;
        }
        let mut at = 8;
        for t in [T_SEG, T_ROUTE, T_HELD] {
            let n = self.n(t);
            let states: &[rt::EntryState] = match t {
                T_SEG => self.seg_state,
                T_ROUTE => self.route_state,
                _ => self.held_state,
            };
            for e in states.iter().take(n) {
                at += rt::write_entry(out, at, e).unwrap_or(0);
            }
        }
        at as i32
    }

    /// The contract's dispatch. `caps` is what the provider realizes now
    /// (a realizer's own answer wins); `attached` says whether a workload is
    /// attached to a segment where no realizer does. Tables travel in `data`;
    /// CAPS answers in `arg`.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call carries the caller, the op and the provider's hooks"
    )]
    pub fn dispatch(
        &mut self,
        caller: Caller,
        caps: u32,
        opcode: u32,
        arg: &mut [u8],
        data: &mut [u8],
        live: &impl Fn(Writer) -> bool,
        attached: &impl Fn(u16) -> bool,
        mut realizer: Option<&mut impl RouteRealizer>,
    ) -> i32 {
        // The node's routing is the node's: only a module acting with its
        // authority reaches it, whatever else it holds.
        if !caller.node {
            return EACCES;
        }
        let w = caller.writer;
        match opcode {
            rt::CAPS => {
                let c = match realizer.as_deref_mut() {
                    Some(r) => r.caps(),
                    None => caps,
                };
                answer_caps(arg, c)
            }
            rt::SEGMENTS => self.replace_segments(data, w, live, attached, realizer),
            rt::ROUTES => self.replace_routes(data, w, live, realizer),
            rt::HOLD => self.replace_held(data, w, live, realizer),
            rt::READ => self.read(data, realizer),
            // The tables keep nothing across a start; a realization that
            // keeps host state ends its resync before the call reaches here.
            rt::RESYNC_END => 0,
            _ => ENOSYS,
        }
    }
}

// ───────────────────────────── net.policy ─────────────────────────────

/// One stored table's header; its rules are `rules[slot * table_bytes..]`.
#[derive(Clone, Copy, Debug)]
pub struct PolicyTable {
    pub live: bool,
    pub name: [u8; pol::MAX_TABLE_NAME],
    pub name_len: u8,
    pub generation: u64,
    pub len: u32,
    /// The generation the provider's own realization applied (0: none).
    pub self_applied: u64,
}

impl PolicyTable {
    pub const EMPTY: PolicyTable = PolicyTable {
        live: false,
        name: [0; pol::MAX_TABLE_NAME],
        name_len: 0,
        generation: 0,
        len: 0,
        self_applied: 0,
    };

    /// The table's name.
    pub fn name(&self) -> &[u8] {
        self.name.get(..self.name_len as usize).unwrap_or(&[])
    }

    fn is(&self, name: &[u8]) -> bool {
        self.live && self.name() == name
    }
}

/// An in-graph enforcer's claim on one table name.
#[derive(Clone, Copy, Debug)]
pub struct PolicyBinding {
    pub live: bool,
    pub name: [u8; pol::MAX_TABLE_NAME],
    pub name_len: u8,
    pub enforcer: Writer,
    pub applied: u64,
    /// The most rule bytes the enforcer holds of the table (0: no bound).
    pub capacity: u32,
}

impl PolicyBinding {
    pub const EMPTY: PolicyBinding = PolicyBinding {
        live: false,
        name: [0; pol::MAX_TABLE_NAME],
        name_len: 0,
        enforcer: Writer { slot: 0, gen: 0 },
        applied: 0,
        capacity: 0,
    };

    fn is(&self, name: &[u8]) -> bool {
        self.live && self.name.get(..self.name_len as usize) == Some(name)
    }

    fn current(&self, live: &impl Fn(Writer) -> bool) -> bool {
        self.live && live(self.enforcer)
    }
}

/// What a platform does with a table it accepted, called as
/// `hook(name, old, new)`: `old` is what the store held (None: no such
/// table), `new` what it will hold (None: a CLEAR). `Err(errno)` refuses the
/// change and the stored table is left as it was. [`NoHook`] names the type
/// of a provider that passes none.
pub type NoHook = fn(&[u8], Option<&[u8]>, Option<&[u8]>) -> Result<(), i32>;

/// The policy store's scalars.
#[derive(Clone, Copy, Debug)]
pub struct PolicyMeta {
    /// Generations are store-wide and never reused, so a table deleted and
    /// recreated never presents an old generation to a reader that cached
    /// it.
    pub next_generation: u64,
}

impl Default for PolicyMeta {
    fn default() -> Self {
        PolicyMeta { next_generation: 1 }
    }
}

/// The policy store over the caller's slices: `tables.len()` tables of
/// `rules.len() / tables.len()` rule bytes each, and as many bindings.
pub struct PolicyStore<'a> {
    pub meta: &'a mut PolicyMeta,
    pub tables: &'a mut [PolicyTable],
    pub bindings: &'a mut [PolicyBinding],
    pub rules: &'a mut [u8],
}

fn name_at(arg: &[u8]) -> Option<&[u8]> {
    let n = *arg.first()? as usize;
    if n == 0 || n > pol::MAX_TABLE_NAME {
        return None;
    }
    arg.get(1..1 + n)
}

/// A table name copied out of the `arg` the answer overwrites.
struct Name {
    buf: [u8; pol::MAX_TABLE_NAME],
    len: usize,
}

impl Name {
    fn of(name: &[u8]) -> Name {
        let mut buf = [0u8; pol::MAX_TABLE_NAME];
        for (d, s) in buf.iter_mut().zip(name) {
            *d = *s;
        }
        Name {
            buf,
            len: name.len().min(pol::MAX_TABLE_NAME),
        }
    }
    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

/// One ATTACH entry at `a[at..]`: name, `applied_gen`, declared capacity
/// (None: none declared) and the offset past it.
fn attach_entry(a: &[u8], at: usize) -> Option<(&[u8], u64, Option<u32>, usize)> {
    let len_byte = *a.get(at)?;
    let with_cap = len_byte & pol::ATTACH_CAPACITY != 0;
    let n = (len_byte & !pol::ATTACH_CAPACITY) as usize;
    if n == 0 || n > pol::MAX_TABLE_NAME {
        return None;
    }
    let name = a.get(at + 1..at + 1 + n)?;
    let applied = u64_at(a, at + 1 + n)?;
    let mut next = at + 1 + n + pol::ATTACH_TAIL;
    let cap = if with_cap {
        let c = u32_at(a, next)?;
        next += pol::ATTACH_CAPACITY_TAIL;
        Some(c)
    } else {
        None
    };
    Some((name, applied, cap, next))
}

fn state_bytes(generation: u64, applied: u64, flags: u32) -> [u8; pol::state::BYTES] {
    let mut s = [0u8; pol::state::BYTES];
    put(&mut s, pol::state::GENERATION, &generation.to_le_bytes());
    put(&mut s, pol::state::APPLIED, &applied.to_le_bytes());
    put(&mut s, pol::state::FLAGS, &flags.to_le_bytes());
    s
}

impl PolicyStore<'_> {
    /// Rule bytes one table holds.
    pub fn table_bytes(&self) -> usize {
        if self.tables.is_empty() {
            return 0;
        }
        self.rules.len() / self.tables.len()
    }

    fn rules_of(&self, i: usize) -> &[u8] {
        let b = self.table_bytes();
        let len = self.tables.get(i).map_or(0, |t| t.len as usize).min(b);
        self.rules.get(i * b..i * b + len).unwrap_or(&[])
    }

    /// The last generation any REPLACE or CLEAR issued (0: none yet).
    pub fn store_generation(&self) -> u64 {
        self.meta.next_generation.wrapping_sub(1)
    }

    /// Table `name`'s rules and generation, if stored.
    pub fn table(&self, name: &[u8]) -> Option<(&[u8], u64)> {
        let i = self.tables.iter().position(|t| t.is(name))?;
        Some((self.rules_of(i), self.tables.get(i)?.generation))
    }

    /// Visit every stored table's name and rules.
    pub fn for_each(&self, mut f: impl FnMut(&[u8], &[u8])) {
        for (i, t) in self.tables.iter().enumerate() {
            if t.live {
                f(t.name(), self.rules_of(i));
            }
        }
    }

    /// The provider's own realization applied generation `gen` of table
    /// `name` (0: none): READ reports it ENFORCED while it equals the stored
    /// one.
    pub fn mark_applied(&mut self, name: &[u8], gen: u64) {
        if let Some(t) = self.tables.iter_mut().find(|t| t.is(name)) {
            t.self_applied = gen;
        }
    }

    /// Whether any in-graph enforcer is bound.
    pub fn enforcer_attached(&self, live: &impl Fn(Writer) -> bool) -> bool {
        self.bindings.iter().any(|b| b.current(live))
    }

    /// Drop every binding `w` holds: it stops vouching for its tables.
    pub fn release(&mut self, w: Writer) {
        for b in self.bindings.iter_mut() {
            if b.live && b.enforcer == w {
                *b = PolicyBinding::EMPTY;
            }
        }
    }

    fn table_state(&self, t: &PolicyTable, live: &impl Fn(Writer) -> bool) -> (u64, u32) {
        if t.self_applied != 0 {
            let mut f = pol::state::BOUND;
            if t.self_applied == t.generation {
                f |= pol::state::ENFORCED;
            }
            return (t.self_applied, f);
        }
        match self
            .bindings
            .iter()
            .find(|b| b.is(t.name()) && b.current(live))
        {
            Some(b) if b.applied == t.generation => {
                (b.applied, pol::state::BOUND | pol::state::ENFORCED)
            }
            Some(b) => (b.applied, pol::state::BOUND),
            None => (0, 0),
        }
    }

    /// ATTACH: bind (or report on) every named table, all or none.
    pub fn attach(&mut self, a: &[u8], w: Writer, live: &impl Fn(Writer) -> bool) -> i32 {
        if a.is_empty() {
            return EINVAL;
        }
        let mut at = 0;
        while at < a.len() {
            let Some((_, _, _, next)) = attach_entry(a, at) else {
                return EINVAL;
            };
            at = next;
        }
        // Pass 1: every name is free, already ours, or bound to an enforcer
        // that is gone; and there is room for the new ones.
        let mut needed = 0usize;
        let mut at = 0;
        while let Some((name, _, _, next)) = attach_entry(a, at) {
            match self.bindings.iter().find(|b| b.is(name)) {
                Some(b) if b.current(live) && b.enforcer != w => return EBUSY,
                Some(b) if b.current(live) => {}
                _ => needed += 1,
            }
            at = next;
        }
        let free = self
            .bindings
            .iter()
            .filter(|b| !b.live || !b.current(live))
            .count();
        if needed > free {
            return ENOSPC;
        }
        // Pass 2: bind and record.
        let mut at = 0;
        while let Some((name, applied, cap, next)) = attach_entry(a, at) {
            let idx = match self.bindings.iter().position(|b| b.is(name)) {
                Some(i) => Some(i),
                None => self
                    .bindings
                    .iter()
                    .position(|b| !b.live || !b.current(live)),
            };
            if let Some(b) = idx.and_then(|i| self.bindings.get_mut(i)) {
                // A re-report without a capacity keeps the bound the same
                // binding declared; a new binding starts with none.
                let ours = b.live && b.enforcer == w && live(w);
                let capacity = match cap {
                    Some(c) => c,
                    None if ours => b.capacity,
                    None => 0,
                };
                let mut n = [0u8; pol::MAX_TABLE_NAME];
                for (d, s) in n.iter_mut().zip(name) {
                    *d = *s;
                }
                *b = PolicyBinding {
                    live: true,
                    name: n,
                    name_len: name.len() as u8,
                    enforcer: w,
                    applied,
                    capacity,
                };
            }
            at = next;
        }
        0
    }

    /// REPLACE: the new generation, or the refusal. `enforces`: the
    /// provider's own realization applies the table (its hook, or its own
    /// enforcement), so it is ENFORCED from the moment it is stored.
    pub fn replace(
        &mut self,
        name: &[u8],
        rules: &[u8],
        caps: u32,
        enforces: bool,
        live: &impl Fn(Writer) -> bool,
        hook: Option<&mut impl FnMut(&[u8], Option<&[u8]>, Option<&[u8]>) -> Result<(), i32>>,
    ) -> Result<u64, i32> {
        if rules.len() > self.table_bytes() {
            return Err(ENOSPC);
        }
        pol::validate(rules, caps)?;
        // A service is one table's: one that overlaps a service another
        // stored table defines is refused, so no packet ever meets two
        // translations.
        for (i, t) in self.tables.iter().enumerate() {
            if t.live && !t.is(name) && pol::shares_service(rules, self.rules_of(i)) {
                return Err(EEXIST);
            }
        }
        // A table its bound enforcer cannot hold is refused before it is
        // stored: what a controller wrote is never a table nothing applies.
        let bound = self
            .bindings
            .iter()
            .find(|b| b.is(name) && b.current(live))
            .map(|b| b.capacity)
            .filter(|c| *c != 0);
        if let Some(cap) = bound {
            if rules.len() > cap as usize {
                return Err(E2BIG);
            }
        }
        let existing = self.tables.iter().position(|t| t.is(name));
        let idx = match existing {
            Some(i) => i,
            None => self.tables.iter().position(|t| !t.live).ok_or(ENOSPC)?,
        };
        // Apply before storing: a platform that refuses the table leaves the
        // old one in force and in the store.
        if let Some(h) = hook {
            let old = existing.map(|i| self.rules_of(i));
            h(name, old, Some(rules))?;
        }
        let b = self.table_bytes();
        if let Some(dst) = self.rules.get_mut(idx * b..idx * b + rules.len()) {
            for (d, s) in dst.iter_mut().zip(rules) {
                *d = *s;
            }
        }
        let g = self.meta.next_generation;
        self.meta.next_generation = g.wrapping_add(1);
        if let Some(t) = self.tables.get_mut(idx) {
            let mut n = [0u8; pol::MAX_TABLE_NAME];
            for (d, s) in n.iter_mut().zip(name) {
                *d = *s;
            }
            *t = PolicyTable {
                live: true,
                name: n,
                name_len: name.len() as u8,
                generation: g,
                len: rules.len() as u32,
                self_applied: if enforces { g } else { 0 },
            };
        }
        Ok(g)
    }

    /// CLEAR: delete table `name` (idempotent). Deleting one consumes a
    /// generation.
    pub fn clear(
        &mut self,
        name: &[u8],
        hook: Option<&mut impl FnMut(&[u8], Option<&[u8]>, Option<&[u8]>) -> Result<(), i32>>,
    ) -> i32 {
        let Some(i) = self.tables.iter().position(|t| t.is(name)) else {
            return 0;
        };
        if let Some(h) = hook {
            if let Err(e) = h(name, Some(self.rules_of(i)), None) {
                return e;
            }
        }
        if let Some(t) = self.tables.get_mut(i) {
            *t = PolicyTable::EMPTY;
        }
        self.meta.next_generation = self.meta.next_generation.wrapping_add(1);
        0
    }

    /// READ: a table's state (into `arg`) and rules (into `out`), or with a
    /// zero-length name the store-wide generation.
    pub fn read(&self, arg: &mut [u8], out: &mut [u8], live: &impl Fn(Writer) -> bool) -> i32 {
        let name = match arg.first() {
            Some(0) => Name::of(&[]),
            _ => match name_at(arg) {
                Some(n) => Name::of(n),
                None => return EINVAL,
            },
        };
        if arg.len() < pol::state::BYTES {
            return EINVAL;
        }
        if name.len == 0 {
            put(arg, 0, &state_bytes(self.store_generation(), 0, 0));
            return 0;
        }
        let Some(i) = self.tables.iter().position(|t| t.is(name.bytes())) else {
            return ENOENT;
        };
        let Some(t) = self.tables.get(i) else {
            return ENOENT;
        };
        let (applied, flags) = self.table_state(t, live);
        put(arg, 0, &state_bytes(t.generation, applied, flags));
        let rules = self.rules_of(i);
        if !put(out, 0, rules) {
            return ERANGE;
        }
        rules.len() as i32
    }

    /// The contract's dispatch, for a provider that realizes `caps` and
    /// runs `hook` (if any) on every change; `enforces`: the provider's own
    /// realization applies what it stores. `arg` = the name record (and the
    /// answer); `data` = the rules.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call carries the caller, the op and the provider's hooks"
    )]
    pub fn dispatch(
        &mut self,
        caller: Caller,
        caps: u32,
        enforces: bool,
        opcode: u32,
        arg: &mut [u8],
        data: &mut [u8],
        live: &impl Fn(Writer) -> bool,
        hook: Option<&mut impl FnMut(&[u8], Option<&[u8]>, Option<&[u8]>) -> Result<(), i32>>,
    ) -> i32 {
        match opcode {
            pol::CAPS => answer_caps(arg, caps),
            pol::READ => self.read(arg, data, live),
            // The tables are the node's: replacing, clearing and vouching
            // for them need its authority.
            _ if !caller.node => EACCES,
            pol::ATTACH => self.attach(arg, caller.writer, live),
            pol::REPLACE => {
                let Some(n) = name_at(arg) else {
                    return EINVAL;
                };
                let name = Name::of(n);
                if arg.len() < 8 {
                    return EINVAL;
                }
                match self.replace(name.bytes(), data, caps, enforces, live, hook) {
                    Ok(g) => {
                        put(arg, 0, &g.to_le_bytes());
                        0
                    }
                    Err(e) => e,
                }
            }
            pol::CLEAR => {
                let Some(n) = name_at(arg) else {
                    return EINVAL;
                };
                let name = Name::of(n);
                self.clear(name.bytes(), hook)
            }
            _ => ENOSYS,
        }
    }
}

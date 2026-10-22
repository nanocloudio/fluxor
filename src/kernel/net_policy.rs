//! net.policy (0x1E) — the table store every platform provider shares.
//!
//! A provider is this store plus a platform's answer to "what happens when a
//! table changes": the linux provider renders it to the host's packet filter,
//! the bare-metal provider leaves it for the in-graph packet filter to read,
//! and the wasm provider leaves it recorded and says it enforces nothing. So
//! the argument decoding, the bounds, the validation, the generation count and
//! the enforcer bindings live here once, and a platform supplies only its
//! capabilities and its hook.
//!
//! Bounded and allocation-free on the dispatch path: kernel static memory on
//! the static profiles, tables sized at boot on Linux.
//!
//! ## Enforcers and per-table ENFORCED
//!
//! A table is in force only where something applies it. A platform that
//! realizes tables itself (its hook, with `caps::ENFORCED`) is the enforcer
//! of every table it applied. Elsewhere an in-graph enforcer ATTACHes naming
//! the tables it applies; each table binds at most one, by `(slot, slot
//! generation)`, and the enforcer reports the generation it applied by
//! re-issuing ATTACH. READ's per-table `ENFORCED` holds only while the
//! binding is live and that generation equals the stored one.
//!
//! ## Authority
//!
//! REPLACE, CLEAR and ATTACH answer `EACCES` to a module not acting with the
//! node's authority (`caller_authority`), whatever it holds; REPLACE and
//! CLEAR also need `platform_raw`, checked in the syscall layer before
//! dispatch reaches here. PROBE, CAPS and READ are reads.
//!
//! ## Concurrency
//!
//! The store is shared across cores (bcm2712 steps one domain per core): an
//! enforcer READs on one core while a controller REPLACEs on another. It is
//! guarded by a sequence lock. Writers serialise on a short writer flag and
//! hold the sequence odd only while they mutate; a reader retries a bounded
//! number of times and answers `EAGAIN` past that, so the enforcer keeps its
//! previous copy. A REPLACE or CLEAR additionally serialises its platform
//! hook (which may take milliseconds on Linux) on an apply flag that readers
//! and binding changes never wait for.

use crate::abi::contracts::net::policy as wire;
use crate::kernel::exec::scheduler::ModuleId;
use crate::kernel::sys::errno;

use crate::abi::contracts::resource as res;
use crate::kernel::mem::table::Table as BootTable;
use portable_atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

/// Tables held at once: the profile's static count, or on Linux the plan's
/// `net_policy_tables` pool, its envelope entry or default. A controller owns
/// one (`netpolicy`, `proxy`); a deployment needing more has more controllers
/// than its envelope sized, and REPLACE says so (`ENOSPC`). A Cortex-M
/// profile (no packet policy to enforce, 264 KB of RAM) holds none, and wasm
/// (records, enforces nothing) holds two small ones.
pub const MAX_TABLES: usize = crate::kernel::config::static_slots(res::POOL_NET_POLICY_TABLES);
/// Bytes of rule records per table: the profile's static figure, or on Linux
/// the plan's `net_policy_table_bytes` (by default ~500 filter rules, or ~40
/// fully loaded services' DNAT with their backends).
pub const MAX_TABLE_BYTES: usize =
    crate::kernel::config::static_slots(res::POOL_NET_POLICY_TABLE_BYTES);

/// Reader attempts against a moving sequence before READ answers `EAGAIN`.
const READ_RETRIES: u32 = 8;
/// Spins a writer waits for the writer flag (held only across a table copy)
/// or the apply flag, before answering `EAGAIN`.
const WRITER_SPINS: u32 = 1 << 16;

/// One table's header. Its rule bytes are `RULES[slot * table_bytes()..]`.
#[derive(Clone, Copy)]
struct Table {
    live: bool,
    name: [u8; wire::MAX_TABLE_NAME],
    name_len: u8,
    generation: u64,
    len: usize,
    /// The generation the platform's own realization applied (0: none) —
    /// set only by a provider whose hook enforces.
    platform_applied: u64,
}

impl Table {
    const fn empty() -> Self {
        Self {
            live: false,
            name: [0; wire::MAX_TABLE_NAME],
            name_len: 0,
            generation: 0,
            len: 0,
            platform_applied: 0,
        }
    }
    fn is(&self, name: &[u8]) -> bool {
        self.live && self.name.get(..self.name_len as usize) == Some(name)
    }
}

/// An in-graph enforcer's claim on one table name.
#[derive(Clone, Copy)]
struct Binding {
    live: bool,
    name: [u8; wire::MAX_TABLE_NAME],
    name_len: u8,
    slot: ModuleId,
    slot_gen: u32,
    applied: u64,
}

impl Binding {
    const fn empty() -> Self {
        Self {
            live: false,
            name: [0; wire::MAX_TABLE_NAME],
            name_len: 0,
            slot: 0,
            slot_gen: 0,
            applied: 0,
        }
    }
    fn is(&self, name: &[u8]) -> bool {
        self.live && self.name.get(..self.name_len as usize) == Some(name)
    }
    /// The module that bound it still occupies its slot. A rebuild or a
    /// restart moves the slot's generation, so a binding never outlives the
    /// occupancy that made it, even on a path that never released it.
    fn current(&self) -> bool {
        self.live
            && crate::kernel::exec::scheduler::module_slot_generation(self.slot as usize)
                == self.slot_gen
    }
}

static mut TABLES: BootTable<Table, MAX_TABLES> = crate::boot_table!(MAX_TABLES, Table::empty());
/// Enforcer bindings: one per bound table name, as many as tables.
static mut BINDINGS: BootTable<Binding, MAX_TABLES> =
    crate::boot_table!(MAX_TABLES, Binding::empty());
/// Every table's rule bytes, `table_bytes()` per table, back to back.
static mut RULES: BootTable<u8, { MAX_TABLES * MAX_TABLE_BYTES }> =
    crate::boot_table!(MAX_TABLES * MAX_TABLE_BYTES, 0);
/// Rule bytes one table holds, as sized.
static TABLE_BYTES: AtomicUsize = AtomicUsize::new(MAX_TABLE_BYTES);

/// The sequence: odd while a writer mutates the store.
static SEQ: AtomicU32 = AtomicU32::new(0);
/// Held by the one writer mutating the store.
static WRITER: AtomicBool = AtomicBool::new(false);
/// Held by the one REPLACE/CLEAR running its platform hook.
static APPLYING: AtomicBool = AtomicBool::new(false);

fn take(flag: &AtomicBool) -> bool {
    for _ in 0..WRITER_SPINS {
        if flag
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Enter a mutation: the writer flag, then the sequence odd.
fn write_begin() -> bool {
    if !take(&WRITER) {
        return false;
    }
    SEQ.fetch_add(1, Ordering::AcqRel);
    portable_atomic::fence(Ordering::Release);
    true
}

fn write_end() {
    SEQ.fetch_add(1, Ordering::Release);
    WRITER.store(false, Ordering::Release);
}

/// Run `f` as a sequence-locked read: `None` when the store kept moving for
/// every retry.
fn read_locked<T>(mut f: impl FnMut() -> T) -> Option<T> {
    for _ in 0..READ_RETRIES {
        let s = SEQ.load(Ordering::Acquire);
        if s & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let v = f();
        portable_atomic::fence(Ordering::Acquire);
        if SEQ.load(Ordering::Relaxed) == s {
            return Some(v);
        }
    }
    None
}

/// Size the store to `tables` tables of `bytes` rule bytes each. A store
/// already holding tables keeps them only while the layout is unchanged; a
/// boot plan sizes it before any controller has written one.
///
/// # Safety
/// Boot or graph-preparation context, before any REPLACE.
pub unsafe fn size(
    tables: usize,
    bytes: usize,
) -> Result<(), crate::kernel::mem::table::TableError> {
    let t = &*core::ptr::addr_of!(TABLES);
    let b = &*core::ptr::addr_of!(BINDINGS);
    let r = &*core::ptr::addr_of!(RULES);
    let total = tables
        .checked_mul(bytes)
        .ok_or(crate::kernel::mem::table::TableError::NoMemory)?;
    t.reserve(tables)?;
    t.grow(tables)?;
    b.reserve(tables)?;
    b.grow(tables)?;
    r.reserve(total)?;
    r.grow(total)?;
    TABLE_BYTES.store(bytes, Ordering::Relaxed);
    Ok(())
}

/// Size the store from the plan's defaults when no plan has.
unsafe fn ensure_sized() {
    let t = &*core::ptr::addr_of!(TABLES);
    if t.is_empty() && t.ceiling() == 0 {
        let _ = size(
            crate::kernel::sys::resource_ledger::ceiling(res::POOL_NET_POLICY_TABLES) as usize,
            crate::kernel::sys::resource_ledger::ceiling(res::POOL_NET_POLICY_TABLE_BYTES) as usize,
        );
    }
}

/// Rule bytes one table holds.
fn table_bytes() -> usize {
    TABLE_BYTES.load(Ordering::Relaxed)
}

/// Table `i`'s rule bytes.
unsafe fn rules(i: usize) -> &'static mut [u8] {
    let b = table_bytes();
    &mut (&mut (*core::ptr::addr_of_mut!(RULES)))[i * b..(i + 1) * b]
}
/// Generations are store-wide and never reused, so a table deleted and
/// recreated can never present an old generation to a reader that cached it.
/// Written under the writer flag, read under the sequence.
static mut NEXT_GENERATION: u64 = 1;

/// The last generation any REPLACE or CLEAR issued (0: none yet).
///
/// # Safety
/// Provider-dispatch context.
pub unsafe fn store_generation() -> u64 {
    read_locked(|| NEXT_GENERATION - 1).unwrap_or(0)
}

/// What a platform does with a table it accepted: `old` is what the store
/// held before (None: no such table), `new` what it will hold (None: a
/// CLEAR). `Err(errno)` refuses the change and the stored table is left as
/// it was.
pub type ApplyHook = fn(name: &[u8], old: Option<&[u8]>, new: Option<&[u8]>) -> Result<(), i32>;

fn name_at(arg: &[u8]) -> Option<(&[u8], usize)> {
    let n = *arg.first()? as usize;
    if n == 0 || n > wire::MAX_TABLE_NAME {
        return None;
    }
    Some((arg.get(1..1 + n)?, 1 + n))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Visit every live table's name and rules (the linux provider renders the
/// whole set when it applies one, so a table that failed never half-lands).
///
/// # Safety
/// Provider-dispatch context on the store's writing thread.
pub unsafe fn for_each(mut f: impl FnMut(&[u8], &[u8])) {
    ensure_sized();
    let tables = &raw const TABLES;
    for (i, t) in (*tables).iter().enumerate().filter(|(_, t)| t.live) {
        f(&t.name[..t.name_len as usize], &rules(i)[..t.len]);
    }
}

/// Whether any in-graph enforcer is bound (for a platform whose CAPS report
/// ENFORCED once one is). Per table, READ's state says whether it is in force.
///
/// # Safety
/// Provider-dispatch context.
pub unsafe fn enforcer_attached() -> bool {
    ensure_sized();
    read_locked(|| {
        let b = &raw const BINDINGS;
        (*b).iter().any(|b| b.current())
    })
    .unwrap_or(false)
}

/// `(applied, flags)` of table `t`, from the platform's realization or its
/// in-graph enforcer.
unsafe fn table_state(t: &Table) -> (u64, u32) {
    if t.platform_applied != 0 {
        let mut f = wire::state::BOUND;
        if t.platform_applied == t.generation {
            f |= wire::state::ENFORCED;
        }
        return (t.platform_applied, f);
    }
    let b = &raw const BINDINGS;
    let name = &t.name[..t.name_len as usize];
    match (*b).iter().find(|b| b.is(name) && b.current()) {
        Some(b) if b.applied == t.generation => {
            (b.applied, wire::state::BOUND | wire::state::ENFORCED)
        }
        Some(b) => (b.applied, wire::state::BOUND),
        None => (0, 0),
    }
}

fn state_bytes(generation: u64, applied: u64, flags: u32) -> [u8; wire::state::BYTES] {
    let mut s = [0u8; wire::state::BYTES];
    for (d, v) in s.iter_mut().zip(generation.to_le_bytes()) {
        *d = v;
    }
    for (d, v) in s[wire::state::APPLIED..]
        .iter_mut()
        .zip(applied.to_le_bytes())
    {
        *d = v;
    }
    for (d, v) in s[wire::state::FLAGS..].iter_mut().zip(flags.to_le_bytes()) {
        *d = v;
    }
    s
}

/// Drop every enforcer binding module `idx` holds: the
/// `release_module_providers` hook, so a finished, faulted, quarantined or
/// removed enforcer stops vouching for its tables at once.
pub fn release_enforcer(idx: ModuleId) {
    // SAFETY: the store's statics are reached only under the writer flag.
    unsafe {
        ensure_sized();
        if !write_begin() {
            // Unreachable short of a wedged writer; the slot-generation check
            // still ends the binding when the slot is next occupied.
            log::warn!("[net_policy] release of enforcer {idx}: store busy");
            return;
        }
        let b = &raw mut BINDINGS;
        for b in (*b).iter_mut().filter(|b| b.live && b.slot == idx) {
            *b = Binding::empty();
        }
        write_end();
    }
}

/// ATTACH: bind (or report on) every named table, all or none.
unsafe fn attach(a: &[u8]) -> i32 {
    if a.is_empty() {
        return errno::EINVAL;
    }
    // Validate the whole argument before touching anything.
    let mut at = 0;
    while at < a.len() {
        let Some((_, p)) = name_at(&a[at..]) else {
            return errno::EINVAL;
        };
        if u64_at(a, at + p).is_none() {
            return errno::EINVAL;
        }
        at += p + wire::ATTACH_TAIL;
    }
    // The module stepping is the caller (this provider is the platform's,
    // not a module's); kernel context parks at the out-of-range index, which
    // names no module and is a distinct identity of its own.
    let slot = crate::kernel::exec::scheduler::current_module_index() as ModuleId;
    let slot_gen = crate::kernel::exec::scheduler::module_slot_generation(slot as usize);
    if !write_begin() {
        return errno::EAGAIN;
    }
    let bindings = &raw mut BINDINGS;
    // Pass 1: every name is free, already ours, or bound to an enforcer that
    // is gone; and there is room for the new ones.
    let mut needed = 0usize;
    let mut at = 0;
    while let Some((name, p)) = a.get(at..).and_then(name_at) {
        match (*bindings).iter().find(|b| b.is(name)) {
            Some(b) if b.current() && (b.slot != slot || b.slot_gen != slot_gen) => {
                write_end();
                return errno::EBUSY;
            }
            Some(b) if b.current() => {}
            _ => needed += 1,
        }
        at += p + wire::ATTACH_TAIL;
    }
    let free = (*bindings)
        .iter()
        .filter(|b| !b.live || !b.current())
        .count();
    if needed > free {
        write_end();
        return errno::ENOSPC;
    }
    // Pass 2: bind and record.
    let mut at = 0;
    while let Some((name, p)) = a.get(at..).and_then(name_at) {
        let applied = u64_at(a, at + p).unwrap_or(0);
        let idx = match (*bindings).iter().position(|b| b.is(name)) {
            Some(i) => i,
            None => match (*bindings).iter().position(|b| !b.live || !b.current()) {
                Some(i) => i,
                None => break, // counted above; unreachable
            },
        };
        let b = &mut (&mut (*bindings))[idx];
        let mut n = [0u8; wire::MAX_TABLE_NAME];
        for (d, s) in n.iter_mut().zip(name) {
            *d = *s;
        }
        *b = Binding {
            live: true,
            name: n,
            name_len: name.len() as u8,
            slot,
            slot_gen,
            applied,
        };
        at += p + wire::ATTACH_TAIL;
    }
    write_end();
    0
}

/// Whether the caller acts with the node's authority. The node's packet
/// policy and service translation are the node's: REPLACE and CLEAR rewrite
/// what every owner's traffic meets, and ATTACH vouches for it, so a module
/// acting for a workload owner is refused all three whatever it holds.
fn node_authority() -> bool {
    crate::kernel::exec::scheduler::caller_authority().is_system()
}

/// The contract's dispatch, for a provider whose platform realizes `caps` and
/// runs `hook` on every change. A provider with a hook and
/// `caps::ENFORCED` is the enforcer of every table its hook applied.
///
/// # Safety
/// `arg` points to `arg_len` caller-owned bytes for the call; pointers inside
/// it are caller-owned buffers of the lengths they state (the provider
/// contract).
pub unsafe fn dispatch(
    caps: u32,
    hook: Option<ApplyHook>,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if handle >= 0 {
        return errno::EINVAL;
    }
    ensure_sized();
    let a: &[u8] = if arg.is_null() || arg_len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(arg, arg_len)
    };
    let platform_enforces = hook.is_some() && caps & wire::caps::ENFORCED != 0;
    match opcode {
        wire::PROBE => 1,
        wire::ATTACH => {
            // A bound enforcer makes its tables report ENFORCED, so attaching
            // is a claim about the node's packet policy: only a module acting
            // with the node's authority may make it. Not platform_raw — an
            // in-graph enforcer parses untrusted frames and deliberately does
            // not hold it.
            if !node_authority() {
                return errno::EACCES;
            }
            attach(a)
        }
        wire::CAPS => {
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            core::ptr::copy_nonoverlapping(caps.to_le_bytes().as_ptr(), arg, 4);
            0
        }
        wire::REPLACE => {
            if !node_authority() {
                return errno::EACCES;
            }
            let Some((name, p)) = name_at(a) else {
                return errno::EINVAL;
            };
            let (Some(rptr), Some(rlen), Some(gptr)) =
                (u64_at(a, p), u32_at(a, p + 8), u64_at(a, p + 12))
            else {
                return errno::EINVAL;
            };
            let rlen = rlen as usize;
            if rlen > table_bytes() {
                return errno::ENOSPC;
            }
            let rule_bytes: &[u8] = if rlen == 0 || rptr == 0 {
                &[]
            } else {
                core::slice::from_raw_parts(rptr as *const u8, rlen)
            };
            if let Err(e) = wire::validate(rule_bytes, caps) {
                return e;
            }
            if !take(&APPLYING) {
                return errno::EAGAIN;
            }
            let r = replace(name, rule_bytes, hook, platform_enforces);
            APPLYING.store(false, Ordering::Release);
            match r {
                Ok(g) => {
                    if gptr != 0 {
                        core::ptr::copy_nonoverlapping(
                            g.to_le_bytes().as_ptr(),
                            gptr as *mut u8,
                            8,
                        );
                    }
                    0
                }
                Err(e) => e,
            }
        }
        wire::CLEAR => {
            if !node_authority() {
                return errno::EACCES;
            }
            let Some((name, _)) = name_at(a) else {
                return errno::EINVAL;
            };
            if !take(&APPLYING) {
                return errno::EAGAIN;
            }
            let r = clear(name, hook);
            APPLYING.store(false, Ordering::Release);
            r
        }
        wire::READ => read(a),
        _ => errno::ENOSYS,
    }
}

/// REPLACE under the apply flag: the hook, then the store.
unsafe fn replace(
    name: &[u8],
    rule_bytes: &[u8],
    hook: Option<ApplyHook>,
    platform_enforces: bool,
) -> Result<u64, i32> {
    let tables = &raw mut TABLES;
    let existing = (*tables).iter().position(|t| t.is(name));
    let idx = match existing {
        Some(i) => i,
        None => match (*tables).iter().position(|t| !t.live) {
            Some(i) => i,
            None => {
                crate::kernel::sys::resource_ledger::deny(res::POOL_NET_POLICY_TABLES);
                return Err(errno::ENOSPC);
            }
        },
    };
    // Apply BEFORE storing: a platform that refuses the table leaves the old
    // one in force and in the store, so what READ reports is what is
    // enforced. Only this flag's holder writes the store's tables, so the
    // old rules are stable while the hook reads them.
    if let Some(h) = hook {
        let old = existing.map(|i| &rules(i)[..(&(*tables))[i].len]);
        h(name, old, Some(rule_bytes))?;
    }
    if !write_begin() {
        return Err(errno::EAGAIN);
    }
    let t = &mut (&mut (*tables))[idx];
    t.live = true;
    for (d, s) in t.name.iter_mut().zip(name) {
        *d = *s;
    }
    t.name_len = name.len() as u8;
    rules(idx)[..rule_bytes.len()].copy_from_slice(rule_bytes);
    t.len = rule_bytes.len();
    let g = NEXT_GENERATION;
    NEXT_GENERATION += 1;
    t.generation = g;
    t.platform_applied = if platform_enforces { g } else { 0 };
    write_end();
    Ok(g)
}

/// CLEAR under the apply flag. Deleting a table consumes a generation.
unsafe fn clear(name: &[u8], hook: Option<ApplyHook>) -> i32 {
    let tables = &raw mut TABLES;
    let Some(i) = (*tables).iter().position(|t| t.is(name)) else {
        return 0;
    };
    if let Some(h) = hook {
        if let Err(e) = h(name, Some(&rules(i)[..(&(*tables))[i].len]), None) {
            return e;
        }
    }
    if !write_begin() {
        return errno::EAGAIN;
    }
    (&mut (*tables))[i] = Table::empty();
    NEXT_GENERATION += 1;
    write_end();
    0
}

/// READ: a table's state and rules, or (zero-length name) the store-wide
/// generation.
unsafe fn read(a: &[u8]) -> i32 {
    let (name, p) = match a.first() {
        Some(0) => (&[][..], 1),
        _ => match name_at(a) {
            Some(v) => v,
            None => return errno::EINVAL,
        },
    };
    let (Some(optr), Some(ocap), Some(sptr)) = (u64_at(a, p), u32_at(a, p + 8), u64_at(a, p + 12))
    else {
        return errno::EINVAL;
    };
    let ocap = ocap as usize;
    let result = read_locked(|| {
        if name.is_empty() {
            return (0, state_bytes(NEXT_GENERATION - 1, 0, 0));
        }
        let tables = &raw const TABLES;
        let Some((ti, t)) = (*tables).iter().enumerate().find(|(_, t)| t.is(name)) else {
            return (errno::ENOENT, [0u8; wire::state::BYTES]);
        };
        let (applied, flags) = table_state(t);
        let st = state_bytes(t.generation, applied, flags);
        if t.len > ocap {
            return (errno::ERANGE, st);
        }
        if t.len > 0 && optr != 0 {
            core::ptr::copy_nonoverlapping(rules(ti).as_ptr(), optr as *mut u8, t.len);
        }
        (t.len as i32, st)
    });
    let Some((rc, st)) = result else {
        return errno::EAGAIN;
    };
    if rc != errno::ENOENT && sptr != 0 {
        core::ptr::copy_nonoverlapping(st.as_ptr(), sptr as *mut u8, wire::state::BYTES);
    }
    rc
}

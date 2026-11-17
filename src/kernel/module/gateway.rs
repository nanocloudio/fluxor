//! The gateway: the only way a gated module reaches the kernel.
//!
//! A module running `contained` or `isolated` is unprivileged. It is handed a
//! gateway `SyscallTable` whose every entry is a veneer that traps; the
//! platform's trap handler identifies the operation and calls [`dispatch`]
//! with the caller's arguments. Nothing the module passes is trusted:
//!
//! - **Spans** must lie wholly inside the caller's own memory — its private
//!   regions (state, heap, stack) for anything the kernel writes, and those or
//!   its code/rodata for anything the kernel only reads.
//! - **Channel handles** must be one of the caller's own ports.
//! - **Provider handles** must be ones the gateway minted for this caller.
//! - **Opcodes** must have a shape in the registry (`rule_for`); everything
//!   else is refused.
//!
//! One generic rule serves every op: a call is a handle slot, a flat `arg`
//! record and a bulk `data` span. The gateway copies `arg` into kernel memory
//! (bounded by the op's registry maximum) before anything checks it, so what
//! the provider reads is what was checked, and copies it back for an op that
//! answers into it; it checks `data` in place by direction and never copies
//! it. Nothing inside either is an address or a handle, so the gateway parses
//! no contract's record.
//!
//! The mechanism that traps (SVC on Arm, a host import on wasm) is the
//! platform's; the decision is made here, once, for every target.

use core::sync::atomic::{AtomicBool, Ordering};
use portable_atomic::AtomicU64;

use crate::kernel::exec::scheduler::MAX_MODULES;
use crate::kernel::sys::errno;

/// Operations, one per function slot of `SyscallTable`, numbered in the
/// table's order (the `telemetry_enabled` data slot has no op). A gated
/// module is handed a table whose slot `i` is the veneer for op `i`.
pub mod op {
    pub const CHANNEL_READ: u32 = 0;
    pub const CHANNEL_WRITE: u32 = 1;
    pub const CHANNEL_POLL: u32 = 2;
    pub const HEAP_ALLOC: u32 = 3;
    pub const HEAP_FREE: u32 = 4;
    pub const HEAP_REALLOC: u32 = 5;
    pub const PROVIDER_OPEN: u32 = 6;
    pub const PROVIDER_CALL: u32 = 7;
    pub const PROVIDER_QUERY: u32 = 8;
    pub const PROVIDER_CLOSE: u32 = 9;
    pub const CHANNEL_PEEK: u32 = 10;
    pub const CHANNEL_DISCARD: u32 = 11;
    /// Number of operations; veneers exist for `0..COUNT`.
    pub const COUNT: u32 = 12;
    /// The module's entry returned. Not a table slot: the return veneer sits
    /// after the operation veneers, and its outcome is the step's.
    pub const RETURN: u32 = COUNT;
}

/// A span of the caller's memory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Region {
    pub base: usize,
    pub len: usize,
}

impl Region {
    pub const EMPTY: Region = Region { base: 0, len: 0 };

    /// Whether `[ptr, ptr + len)` lies wholly inside this region. A zero
    /// length touches nothing and is always inside; overflow never is.
    pub fn contains(&self, ptr: usize, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let Some(end) = ptr.checked_add(len) else {
            return false;
        };
        self.len != 0 && ptr >= self.base && end <= self.base + self.len
    }
}

/// Most private regions a gated module has: state, heap and stack on an MMU
/// target; one combined region on an MPU target.
pub const MAX_PRIVATE: usize = 3;

/// What the gateway knows about one gated module.
#[derive(Clone, Copy)]
struct Gated {
    code: Region,
    heap: Region,
    stack: Region,
    private: [Region; MAX_PRIVATE],
}

impl Gated {
    const NONE: Gated = Gated {
        code: Region::EMPTY,
        heap: Region::EMPTY,
        stack: Region::EMPTY,
        private: [Region::EMPTY; MAX_PRIVATE],
    };

    /// Memory the kernel may write for this caller.
    fn writable(&self, ptr: usize, len: usize) -> bool {
        (self.stack.len != 0 && self.stack.contains(ptr, len))
            || self
                .private
                .iter()
                .any(|r| r.len != 0 && r.contains(ptr, len))
    }

    /// Memory the kernel may read for this caller.
    fn readable(&self, ptr: usize, len: usize) -> bool {
        self.writable(ptr, len) || self.code.contains(ptr, len)
    }
}

static GATED_ACTIVE: [AtomicBool; MAX_MODULES] = [const { AtomicBool::new(false) }; MAX_MODULES];
static mut GATED: [Gated; MAX_MODULES] = [Gated::NONE; MAX_MODULES];

/// Record a gated module's memory, before any of its code runs.
///
/// `private` lists the regions the module owns read-write; `heap` is the one
/// of them its allocator hands out (empty when it has none).
pub fn register(module: usize, code: Region, heap: Region, private: &[Region]) {
    if module >= MAX_MODULES {
        return;
    }
    let mut g = Gated::NONE;
    g.code = code;
    g.heap = heap;
    for (slot, r) in g.private.iter_mut().zip(private.iter()) {
        *slot = *r;
    }
    // SAFETY: written during graph setup, before the module's first entry and
    // before GATED_ACTIVE publishes it; readers check GATED_ACTIVE first.
    unsafe { GATED[module] = g };
    GATED_ACTIVE[module].store(true, Ordering::Release);
}

/// Record a registered module's stack: allocated by the platform after the
/// loader registers state and heap (bcm2712), or by the loader as the bottom
/// of the module's private region (RP).
pub fn set_stack(module: usize, stack: Region) {
    if module >= MAX_MODULES {
        return;
    }
    // SAFETY: as `register`; called on the setup path before first entry.
    unsafe { GATED[module].stack = stack };
}

/// A gated module's memory: its code, its stack, and its private regions.
pub fn regions(module: usize) -> Option<(Region, Region, [Region; MAX_PRIVATE])> {
    gated(module).map(|g| (g.code, g.stack, g.private))
}

/// Whether `module`'s regions are registered with the gateway: set when a
/// gated module is set up, cleared when it is released. Its level is the
/// scheduler's (`scheduler::module_level`); this is the gateway's own state.
pub fn is_registered(module: usize) -> bool {
    module < MAX_MODULES && GATED_ACTIVE[module].load(Ordering::Acquire)
}

/// Forget a module: its regions and every handle minted for it.
pub fn release(module: usize) {
    if module >= MAX_MODULES {
        return;
    }
    GATED_ACTIVE[module].store(false, Ordering::Release);
    // SAFETY: no longer published; the module is not running.
    unsafe { GATED[module] = Gated::NONE };
    handles::release_all(module);
}

fn gated(module: usize) -> Option<Gated> {
    if !is_registered(module) {
        return None;
    }
    // SAFETY: published by `register` with Release; read after Acquire.
    Some(unsafe { GATED[module] })
}

// ── Provider handles ─────────────────────────────────────────────────

/// Provider handles minted for gated callers. A gated module may name only a
/// handle the kernel returned to it; guessing another module's handle number
/// gets it nothing.
mod handles {
    use super::*;

    const SLOTS: usize = 128;
    /// `(module + 1) << 32 | handle`; 0 is a free slot.
    static MINTED: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

    fn key(module: usize, handle: i32) -> u64 {
        ((module as u64 + 1) << 32) | u64::from(handle as u32)
    }

    pub fn mint(module: usize, handle: i32) -> bool {
        let k = key(module, handle);
        for s in MINTED.iter() {
            if s.compare_exchange(0, k, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
        false
    }

    pub fn owns(module: usize, handle: i32) -> bool {
        let k = key(module, handle);
        MINTED.iter().any(|s| s.load(Ordering::Acquire) == k)
    }

    pub fn forget(module: usize, handle: i32) {
        let k = key(module, handle);
        for s in MINTED.iter() {
            let _ = s.compare_exchange(k, 0, Ordering::AcqRel, Ordering::Relaxed);
        }
    }

    pub fn release_all(module: usize) {
        for s in MINTED.iter() {
            let v = s.load(Ordering::Acquire);
            if v >> 32 == module as u64 + 1 {
                let _ = s.compare_exchange(v, 0, Ordering::AcqRel, Ordering::Relaxed);
            }
        }
    }
}

// ── Operation rules ──────────────────────────────────────────────────

pub use crate::abi::registry::gate::{Bound, Dir, HandleUse, OpRule as Rule, ARG_MAX};

/// The shape of `op`, if the registry declares one. Default deny: an opcode
/// without a shape is refused with `EACCES`, whatever the caller's grants.
pub fn rule_for(op: u32) -> Option<Rule> {
    crate::abi::registry::gate::op_rule(op & !crate::abi::registry::CHAIN_NEXT)
}

// ── Dispatch ─────────────────────────────────────────────────────────

/// Why the gateway refused a call, for the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    NotGated,
    UnknownOp,
    Pointer,
    Channel,
    Handle,
    Opcode,
}

impl Refusal {
    fn errno(self) -> i32 {
        match self {
            Refusal::Pointer => errno::EFAULT,
            Refusal::UnknownOp => errno::ENOSYS,
            _ => errno::EACCES,
        }
    }
}

/// Whether `handle` names a channel. Which end of it the caller is, the
/// channel itself checks on every op.
fn is_channel(handle: i32) -> bool {
    crate::abi::kernel_abi::handle::contract_of(handle) == Some(crate::abi::registry::channel::ID)
}

/// Whether `[ptr, ptr + len)` may move `dir` for this caller, `len` within
/// `max`: readable for what the kernel reads, private for what it writes.
fn check_span(g: &Gated, dir: Dir, max: usize, ptr: usize, len: usize) -> Result<(), Refusal> {
    let ok = match dir {
        Dir::None => len == 0,
        Dir::In => len <= max && g.readable(ptr, len),
        Dir::Out | Dir::InOut => len <= max && g.writable(ptr, len),
    };
    if ok {
        Ok(())
    } else {
        Err(Refusal::Pointer)
    }
}

fn data_max(b: Bound) -> usize {
    match b {
        Bound::Bytes(n) => n,
        // The caller's own region bounds it: the region check refuses past it.
        Bound::Any => usize::MAX,
    }
}

fn check_handle(module: usize, rule: &Rule, handle: i32) -> Result<(), Refusal> {
    let ok = match rule.handle {
        HandleUse::Global | HandleUse::Mints => handle == -1,
        HandleUse::Scoped | HandleUse::ScopedMints => handle == -1 || handles::owns(module, handle),
        HandleUse::Value => true,
        HandleUse::Channel => is_channel(handle),
        HandleUse::Minted | HandleUse::MintedMints => handles::owns(module, handle),
    };
    if ok {
        Ok(())
    } else {
        Err(Refusal::Handle)
    }
}

fn mints(rule: &Rule) -> bool {
    matches!(
        rule.handle,
        HandleUse::Mints | HandleUse::ScopedMints | HandleUse::MintedMints
    )
}

/// Authorise one call without performing it. Pure over the gateway's tables
/// and its arguments, so the refusal matrix is host-testable.
pub fn authorise(module: usize, op: u32, a: &[usize; 6]) -> Result<(), Refusal> {
    let g = gated(module).ok_or(Refusal::NotGated)?;
    let h = a[0] as i32;
    match op {
        op::CHANNEL_READ | op::CHANNEL_PEEK => {
            if !is_channel(h) {
                return Err(Refusal::Channel);
            }
            check_span(&g, Dir::Out, usize::MAX, a[1], a[2])
        }
        op::CHANNEL_WRITE => {
            if !is_channel(h) {
                return Err(Refusal::Channel);
            }
            check_span(&g, Dir::In, usize::MAX, a[1], a[2])
        }
        op::CHANNEL_POLL | op::CHANNEL_DISCARD => {
            if is_channel(h) {
                Ok(())
            } else {
                Err(Refusal::Channel)
            }
        }
        op::HEAP_ALLOC => Ok(()),
        op::HEAP_FREE | op::HEAP_REALLOC => {
            // Null frees nothing; anything else must be inside the heap.
            if a[0] == 0 || g.heap.contains(a[0], 1) {
                Ok(())
            } else {
                Err(Refusal::Pointer)
            }
        }
        op::PROVIDER_OPEN => {
            // provider_open(contract, open_op, arg, len): only opens the
            // registry lists as minting.
            let rule = rule_for(a[1] as u32).ok_or(Refusal::Opcode)?;
            if !mints(&rule) || rule.addr_answer {
                return Err(Refusal::Opcode);
            }
            check_span(&g, Dir::In, rule.arg_max, a[2], a[3])
        }
        op::PROVIDER_CALL => {
            let rule = rule_for(a[1] as u32).ok_or(Refusal::Opcode)?;
            check_handle(module, &rule, h)?;
            check_span(&g, rule.arg, rule.arg_max, a[2], a[3])?;
            check_span(&g, rule.data, data_max(rule.data_max), a[4], a[5])?;
            if crate::kernel::module::user_span::overlaps(
                a[2] as *const u8,
                a[3],
                a[4] as *const u8,
                a[5],
            ) {
                return Err(Refusal::Pointer);
            }
            Ok(())
        }
        op::PROVIDER_QUERY => {
            let key = a[1] as u32;
            let max = crate::abi::registry::gate::query_max(key).ok_or(Refusal::Opcode)?;
            if h != -1 {
                return Err(Refusal::Handle);
            }
            check_span(&g, Dir::Out, max, a[2], a[3])
        }
        op::PROVIDER_CLOSE => {
            if handles::owns(module, h) {
                Ok(())
            } else {
                Err(Refusal::Handle)
            }
        }
        _ => Err(Refusal::UnknownOp),
    }
}

/// Serve one call from gated `module`. `a` holds the call's arguments in
/// order (unused trailing ones are zero). Returns the value the module's
/// veneer returns: the operation's result, or a negative errno.
///
/// # Safety
/// Called from the platform's trap path, with the caller's memory mapped for
/// the kernel and the caller not running.
pub unsafe fn dispatch(module: usize, op: u32, a: [usize; 6]) -> isize {
    if let Err(why) = authorise(module, op, &a) {
        note_refusal(module, op, &a, why);
        return why.errno() as isize;
    }
    let sys = crate::kernel::module::syscalls::get_syscall_table();
    let h = a[0] as i32;
    // SAFETY: every span below was checked against the caller's own regions
    // by `authorise`, and every handle against what it holds.
    unsafe {
        match op {
            op::CHANNEL_READ => (sys.channel_read)(h, a[1] as *mut u8, a[2]) as isize,
            op::CHANNEL_WRITE => (sys.channel_write)(h, a[1] as *const u8, a[2]) as isize,
            op::CHANNEL_POLL => (sys.channel_poll)(h, a[1] as u32) as isize,
            op::CHANNEL_PEEK => (sys.channel_peek)(h, a[1] as *mut u8, a[2]) as isize,
            op::CHANNEL_DISCARD => (sys.channel_discard)(h, a[1]) as isize,
            op::HEAP_ALLOC => {
                let p = (sys.heap_alloc)(a[0] as u32);
                heap_result(module, p)
            }
            op::HEAP_FREE => {
                (sys.heap_free)(a[0] as *mut u8);
                0
            }
            op::HEAP_REALLOC => {
                let p = (sys.heap_realloc)(a[0] as *mut u8, a[1] as u32);
                heap_result(module, p)
            }
            op::PROVIDER_OPEN => {
                // The open's record goes in as the kernel's copy: the caller
                // cannot change what was checked before the provider reads it.
                let mut copy = [0u8; ARG_MAX];
                let n = a[3];
                copy[..n].copy_from_slice(core::slice::from_raw_parts(a[2] as *const u8, n));
                let rc = (sys.provider_open)(a[0] as u32, a[1] as u32, copy.as_ptr(), n);
                mint_result(module, rc)
            }
            op::PROVIDER_CALL => call(module, sys, h, a),
            op::PROVIDER_QUERY => {
                (sys.provider_query)(h, a[1] as u32, a[2] as *mut u8, a[3]) as isize
            }
            op::PROVIDER_CLOSE => {
                let rc = (sys.provider_close)(h);
                handles::forget(module, h);
                rc as isize
            }
            _ => errno::ENOSYS as isize,
        }
    }
}

/// A gated `provider_call`, authorised: `arg` is copied in, the provider
/// handed the copy, and the copy written back for an op that answers into
/// it. `data` is the caller's own span, checked in place.
///
/// # Safety
/// `authorise` passed for `a`, with the caller suspended.
unsafe fn call(
    module: usize,
    sys: &crate::abi::kernel_abi::SyscallTable,
    h: i32,
    a: [usize; 6],
) -> isize {
    let Some(rule) = rule_for(a[1] as u32) else {
        return errno::EACCES as isize;
    };
    let n = a[3];
    let mut copy = [0u8; ARG_MAX];
    if matches!(rule.arg, Dir::In | Dir::InOut) {
        // SAFETY: `[a[2], a[2] + n)` is the caller's readable memory and
        // `n <= rule.arg_max <= ARG_MAX` (`authorise`).
        copy[..n].copy_from_slice(unsafe { core::slice::from_raw_parts(a[2] as *const u8, n) });
    }
    // SAFETY: the copy is kernel memory of `n` bytes; `data` was checked.
    let rc = unsafe {
        (sys.provider_call)(
            h,
            a[1] as u32,
            if n == 0 {
                core::ptr::null_mut()
            } else {
                copy.as_mut_ptr()
            },
            n,
            a[4] as *mut u8,
            a[5],
        )
    };
    if rule.addr_answer && rc >= 0 && !answer_in_mapping(module, &copy[..n]) {
        // The kernel granted something the caller's mapping cannot reach:
        // the answer would name memory it does not hold.
        return errno::EFAULT as isize;
    }
    if matches!(rule.arg, Dir::Out | Dir::InOut) {
        // SAFETY: `authorise` checked `[a[2], a[2] + n)` writable.
        unsafe { core::ptr::copy_nonoverlapping(copy.as_ptr(), a[2] as *mut u8, n) };
    }
    if mints(&rule) {
        mint_result(module, rc)
    } else if rule.closes && rc >= 0 {
        handles::forget(module, h);
        rc as isize
    } else {
        rc as isize
    }
}

/// Whether an address answer (`[addr u64][len u32]` at the head of `arg`)
/// lies in the caller's own mapping: memory it may read, or the region over
/// its programs it is granted read-only. An empty answer names nothing.
fn answer_in_mapping(module: usize, ans: &[u8]) -> bool {
    let (Some(a), Some(l)) = (ans.get(0..8), ans.get(8..12)) else {
        return false;
    };
    let addr = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]);
    let len = u32::from_le_bytes([l[0], l[1], l[2], l[3]]) as usize;
    if len == 0 {
        return true;
    }
    match (usize::try_from(addr), gated(module)) {
        (Ok(addr), Some(g)) => {
            g.readable(addr, len)
                || crate::kernel::exec::scheduler::module_program_region(module).is_some_and(
                    |(base, n)| {
                        Region {
                            base: base as usize,
                            len: n,
                        }
                        .contains(addr, len)
                    },
                )
        }
        _ => false,
    }
}

/// An allocation is returned only if it lies inside the caller's heap; the
/// allocator is the kernel's, but the check is what the caller is promised.
fn heap_result(module: usize, p: *mut u8) -> isize {
    if p.is_null() {
        return 0;
    }
    match gated(module) {
        Some(g) if g.heap.contains(p as usize, 1) => p as isize,
        _ => {
            let sys = crate::kernel::module::syscalls::get_syscall_table();
            // SAFETY: `p` came from this module's allocator a moment ago.
            unsafe { (sys.heap_free)(p) };
            0
        }
    }
}

fn mint_result(module: usize, rc: i32) -> isize {
    if rc >= 0 && !handles::mint(module, rc) {
        log::warn!("[gate] module {module}: handle table full, handle {rc} not minted");
        return errno::ENOSPC as isize;
    }
    rc as isize
}

fn note_refusal(module: usize, op: u32, a: &[usize; 6], why: Refusal) {
    use portable_atomic::AtomicU32;
    // A refusal is the module misbehaving; logging every one would let it
    // flood the log. The first few say what happened, and a steady trickle
    // after that keeps a persistent offender visible.
    static LOGGED: AtomicU32 = AtomicU32::new(0);
    let n = LOGGED.fetch_add(1, Ordering::Relaxed);
    if n < 16 || n.is_multiple_of(256) {
        log::warn!(
            "[gate] module {} op {} refused: {:?} (a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x})",
            module,
            op,
            why,
            a[0],
            a[1],
            a[2],
            a[3],
            a[4],
            a[5]
        );
    }
}

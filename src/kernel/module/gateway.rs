//! The gateway: the only way a gated module reaches the kernel.
//!
//! A module running `contained` or `isolated` is unprivileged. It is handed a
//! gateway `SyscallTable` whose every entry is a veneer that traps; the
//! platform's trap handler identifies the operation and calls [`dispatch`]
//! with the caller's arguments. Nothing the module passes is trusted:
//!
//! - **Pointers** must lie wholly inside the caller's own memory — its private
//!   regions (state, heap, stack) for anything the kernel writes, and those or
//!   its code/rodata for anything the kernel only reads.
//! - **Channel handles** must be one of the caller's own ports.
//! - **Provider handles** must be ones the gateway minted for this caller.
//! - **Opcodes** must appear in [`RULES`]; everything else is refused.
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
    pub const PROVIDER_CALL_SEL: u32 = 11;
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

/// Whether `module` is gated.
pub fn is_gated(module: usize) -> bool {
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
    if !is_gated(module) {
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

/// What a rule lets the caller name as the handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandleUse {
    /// A global operation: the handle must be -1.
    Global,
    /// The handle carries a small value, not a handle (`LOG_WRITE`'s level).
    Value,
    /// One of the caller's channel ports.
    Channel,
    /// A provider handle minted for the caller.
    Minted,
    /// Global, and a non-negative result is a new handle minted for the
    /// caller.
    Mints,
}

/// How the kernel uses the argument buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arg {
    /// No buffer; the length must be 0.
    None,
    /// The kernel reads at most this many bytes.
    In(usize),
    /// The kernel writes at most this many bytes.
    Out(usize),
    /// The kernel reads and writes at most this many bytes.
    InOut(usize),
}

/// An argument struct that carries pointers the provider follows: how to
/// find each of them in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walker {
    /// `storage.object` PUT: key, content type, body (in), etag, fence out.
    StoragePut,
    /// `storage.object` HEAD: key, record out, fence out.
    StorageHead,
    /// `storage.object` DELETE: key, etag, fence out.
    StorageDelete,
    /// `storage.object` RANGE_GET: offset, length, out (`length` bytes).
    StorageRangeGet,
    /// `channel::IOCTL`: `[cmd: u32]` then the command's own argument. Only
    /// the kernel's built-in commands and the `storage.block` requests are
    /// admitted; a block request's buffer is the pointer walked.
    ChannelIoctl,
}

/// One opcode a gated module may use.
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub op: u32,
    pub handle: HandleUse,
    pub arg: Arg,
    /// Pointers inside the argument struct, when it carries any. The struct
    /// is copied into kernel memory, each pointer checked against the
    /// caller's own, and the provider handed the copy.
    pub walk: Option<Walker>,
    /// The op releases the handle it names; the gateway forgets it.
    pub closes: bool,
}

const fn rule(op: u32, handle: HandleUse, arg: Arg) -> Rule {
    Rule {
        op,
        handle,
        arg,
        walk: None,
        closes: false,
    }
}

const fn walked(op: u32, handle: HandleUse, max: usize, walker: Walker) -> Rule {
    Rule {
        op,
        handle,
        arg: Arg::In(max),
        walk: Some(walker),
        closes: false,
    }
}

/// A walked struct the provider also writes results into. The kernel's
/// checked copy is handed over and copied back to the caller afterwards.
const fn walked_inout(op: u32, handle: HandleUse, max: usize, walker: Walker) -> Rule {
    Rule {
        op,
        handle,
        arg: Arg::InOut(max),
        walk: Some(walker),
        closes: false,
    }
}

const fn closing(op: u32) -> Rule {
    Rule {
        op,
        handle: HandleUse::Minted,
        arg: Arg::None,
        walk: None,
        closes: true,
    }
}

/// `usize::MAX` as a length bound: bounded by the caller's own region, which
/// the pointer check enforces.
const ANY: usize = usize::MAX;

/// The provider operations served to gated modules. Default deny: an opcode
/// not listed here is refused with `EACCES`, whatever the caller's grants.
///
/// None of these operations registers code for the kernel to call. The one
/// that keeps a pointer past its call is a `storage.block` `SUBMIT`, whose
/// buffer is lent to the source until the completion is reaped. An operation
/// whose argument struct carries pointers is listed with the walker that
/// finds them, and every one is checked.
pub static RULES: &[Rule] = &[
    // Time.
    rule(0x0602, HandleUse::Global, Arg::Out(8)), // timer::MILLIS
    rule(0x0603, HandleUse::Global, Arg::Out(8)), // timer::MICROS
    rule(0x0608, HandleUse::Global, Arg::Out(8)), // timer::UNIX_MILLIS
    rule(0x0609, HandleUse::Global, Arg::Out(36)), // timer::TRUSTED_UNIX
    // Identity and entropy.
    rule(0x0C2F, HandleUse::Global, Arg::Out(16)), // BOOT_INCARNATION
    rule(0x0C3C, HandleUse::Global, Arg::Out(ANY)), // CSPRNG_FILL
    // Log and telemetry.
    rule(0x0C40, HandleUse::Value, Arg::In(ANY)), // LOG_WRITE (level in handle)
    rule(0x0C3E, HandleUse::Global, Arg::In(ANY)), // telemetry::TLM_EMIT
    // Scheduling reports and budgets.
    rule(0x0C45, HandleUse::Global, Arg::In(1)), // REPORT_STEP_EFFECT
    rule(0x0C46, HandleUse::Global, Arg::InOut(ANY)), // MODULE_FLOW_BUDGET
    rule(0x0C50, HandleUse::Global, Arg::In(4)), // REPORT_LATENCY
    // Handles the caller holds.
    rule(0x0C41, HandleUse::Channel, Arg::InOut(1)), // HANDLE_POLL on a port
    // Channels: port discovery, the kernel's built-in ioctls and the
    // `storage.block` requests. Registering a handler (REGISTER_IOCTL,
    // 0x0507) is not served: it hands the kernel code to call.
    rule(0x050C, HandleUse::Global, Arg::InOut(2)), // channel::PORT
    walked_inout(0x0506, HandleUse::Channel, WALK_MAX, Walker::ChannelIoctl),
    // Events.
    rule(0x0B00, HandleUse::Mints, Arg::None), // event::CREATE
    rule(0x0B01, HandleUse::Minted, Arg::None), // event::SIGNAL
    rule(0x0B02, HandleUse::Minted, Arg::None), // event::POLL
    closing(0x0B03),                           // event::DESTROY
    // The caller's own heap arena.
    rule(0x0C3A, HandleUse::Global, Arg::Out(4)), // ARENA_GET
    // storage.object — persistence. Synchronous: no provider keeps a pointer
    // past the call (the contract's write path takes the bytes and returns).
    walked(0x1420, HandleUse::Global, WALK_MAX, Walker::StoragePut),
    rule(0x1421, HandleUse::Mints, Arg::In(ANY)), // GET: arg is the key
    walked(0x1422, HandleUse::Global, WALK_MAX, Walker::StorageHead),
    walked(0x1423, HandleUse::Minted, WALK_MAX, Walker::StorageRangeGet),
    walked(0x1424, HandleUse::Global, WALK_MAX, Walker::StorageDelete),
    closing(0x1425), // CLOSE
];

/// Longest argument struct the gateway copies to walk.
const WALK_MAX: usize = 512;

/// A pointer an argument struct carries: where, how long, and whether the
/// provider writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Embedded {
    pub ptr: usize,
    pub len: usize,
    pub write: bool,
}

/// Find the pointers `walker`'s struct carries in `arg`, or `None` if the
/// struct is malformed (a length that runs past its end).
pub fn walk(walker: Walker, arg: &[u8]) -> Option<([Embedded; 3], usize)> {
    struct R<'a>(&'a [u8], usize);
    impl R<'_> {
        fn take(&mut self, n: usize) -> Option<&[u8]> {
            let s = self.0.get(self.1..self.1.checked_add(n)?)?;
            self.1 += n;
            Some(s)
        }
        fn u8(&mut self) -> Option<usize> {
            self.take(1).map(|b| b[0] as usize)
        }
        fn u16(&mut self) -> Option<usize> {
            self.take(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        }
        fn u32(&mut self) -> Option<usize> {
            self.take(4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        }
        fn u64(&mut self) -> Option<usize> {
            let b = self.take(8)?;
            usize::try_from(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
            .ok()
        }
    }
    let none = Embedded {
        ptr: 0,
        len: 0,
        write: false,
    };
    let mut out = [none; 3];
    let mut r = R(arg, 0);
    let n = match walker {
        Walker::StoragePut => {
            let k = r.u16()?;
            r.take(k)?;
            let c = r.u8()?;
            r.take(c)?;
            out[0] = Embedded {
                ptr: r.u64()?,
                len: r.u64()?,
                write: false,
            };
            r.u8()?; // precondition
            let e = r.u8()?;
            r.take(e)?;
            out[1] = Embedded {
                ptr: r.u64()?,
                len: r.u16()?,
                write: true,
            };
            2
        }
        Walker::StorageHead => {
            let k = r.u16()?;
            r.take(k)?;
            out[0] = Embedded {
                ptr: r.u64()?,
                len: r.u32()?,
                write: true,
            };
            out[1] = Embedded {
                ptr: r.u64()?,
                len: r.u16()?,
                write: true,
            };
            2
        }
        Walker::StorageDelete => {
            let k = r.u16()?;
            r.take(k)?;
            r.u8()?; // precondition
            let e = r.u8()?;
            r.take(e)?;
            out[0] = Embedded {
                ptr: r.u64()?,
                len: r.u16()?,
                write: true,
            };
            1
        }
        Walker::StorageRangeGet => {
            r.u64()?; // offset
            let len = r.u32()?;
            out[0] = Embedded {
                ptr: r.u64()?,
                len,
                write: true,
            };
            1
        }
        Walker::ChannelIoctl => {
            use crate::abi::contracts::storage::block::{ioctl, Req};
            let cmd = r.u32()? as u32;
            let rest = arg.get(4..)?;
            match cmd {
                ioctl::SUBMIT | ioctl::EXEC => {
                    let q = Req::decode(rest)?;
                    if q.buf_len == 0 {
                        0
                    } else {
                        out[0] = Embedded {
                            ptr: usize::try_from(q.buf_ptr).ok()?,
                            len: q.buf_len as usize,
                            write: q.writes_buffer(),
                        };
                        1
                    }
                }
                // The data comes back on the channel; the buffer fields are
                // not followed.
                ioctl::READ_STREAM => {
                    Req::decode(rest)?;
                    0
                }
                _ if channel_ioctl_admitted(cmd) => 0,
                _ => return None,
            }
        }
    };
    Some((out, n))
}

/// Whether a gated module may issue channel ioctl `cmd`.
///
/// The kernel's built-in commands carry no pointers, and the `storage.block`
/// requests carry one the gateway walks. Any other command is served by a
/// module-registered handler whose argument layout the gateway cannot see
/// into, so a pointer inside it would reach a privileged module unchecked.
pub fn channel_ioctl_admitted(cmd: u32) -> bool {
    use crate::abi::contracts::storage::block::ioctl;
    use crate::kernel::ipc::channel as ch;
    matches!(
        cmd,
        ch::IOCTL_NOTIFY
            | ch::IOCTL_POLL_NOTIFY
            | ch::IOCTL_FLUSH
            | ch::IOCTL_SET_HUP
            | ioctl::CAPS
            | ioctl::REAP
            | ioctl::SUBMIT
            | ioctl::EXEC
            | ioctl::READ_STREAM
    )
}

/// Query keys served to gated modules; each writes at most the given bytes.
pub static QUERIES: &[(u32, usize)] = &[
    (0x0C30, 24), // STREAM_TIME
    (0x0C31, 4),  // GRAPH_SAMPLE_RATE
    (0x0C33, 4),  // DOWNSTREAM_LATENCY
    (0x0C3B, 4),  // SYS_CLOCK_HZ
];

/// The rule for `op`, if gated modules may use it.
pub fn rule_for(op: u32) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.op == op)
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

/// Whether `handle` is one of `module`'s channel ports.
fn owns_channel(module: usize, handle: i32) -> bool {
    if handle < 0 {
        return false;
    }
    crate::kernel::exec::scheduler::module_owns_channel(module, handle)
}

fn check_arg(g: &Gated, arg: Arg, ptr: usize, len: usize) -> Result<(), Refusal> {
    let ok = match arg {
        Arg::None => len == 0,
        Arg::In(max) => len <= max && g.readable(ptr, len),
        Arg::Out(max) | Arg::InOut(max) => len <= max && g.writable(ptr, len),
    };
    if ok {
        Ok(())
    } else {
        Err(Refusal::Pointer)
    }
}

/// Every pointer a walked struct carries must be the caller's: readable for
/// what the provider reads, private for what it writes.
fn check_walk(g: &Gated, w: Walker, arg: &[u8]) -> Result<(), Refusal> {
    let (ptrs, n) = walk(w, arg).ok_or(Refusal::Pointer)?;
    for e in &ptrs[..n] {
        let ok = if e.write {
            g.writable(e.ptr, e.len)
        } else {
            g.readable(e.ptr, e.len)
        };
        if !ok {
            return Err(Refusal::Pointer);
        }
    }
    Ok(())
}

fn check_handle(module: usize, rule: &Rule, handle: i32) -> Result<(), Refusal> {
    let ok = match rule.handle {
        HandleUse::Global | HandleUse::Mints => handle == -1,
        HandleUse::Value => true,
        HandleUse::Channel => owns_channel(module, handle),
        HandleUse::Minted => handles::owns(module, handle),
    };
    if ok {
        Ok(())
    } else {
        Err(Refusal::Handle)
    }
}

/// Authorise one call without performing it. Pure over the gateway's tables
/// and its arguments, so the refusal matrix is host-testable.
///
/// `walked` is the kernel's copy of the argument struct for an op whose
/// rule walks one — copied before it is checked, so the pointers the check
/// sees are the pointers the provider is handed. `None` for every other op;
/// a walked op with no copy is refused.
pub fn authorise(
    module: usize,
    op: u32,
    a: &[usize; 6],
    walked: Option<&[u8]>,
) -> Result<(), Refusal> {
    let g = gated(module).ok_or(Refusal::NotGated)?;
    let h = a[0] as i32;
    match op {
        op::CHANNEL_READ | op::CHANNEL_PEEK => {
            if !owns_channel(module, h) {
                return Err(Refusal::Channel);
            }
            check_arg(&g, Arg::Out(ANY), a[1], a[2])
        }
        op::CHANNEL_WRITE => {
            if !owns_channel(module, h) {
                return Err(Refusal::Channel);
            }
            check_arg(&g, Arg::In(ANY), a[1], a[2])
        }
        op::CHANNEL_POLL => {
            if owns_channel(module, h) {
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
            // provider_open(contract, open_op, config, len): only opens the
            // rule table lists as minting.
            let rule = rule_for(a[1] as u32).ok_or(Refusal::Opcode)?;
            if rule.handle != HandleUse::Mints {
                return Err(Refusal::Opcode);
            }
            check_arg(&g, Arg::In(ANY), a[2], a[3])
        }
        op::PROVIDER_CALL => {
            let rule = rule_for(a[1] as u32).ok_or(Refusal::Opcode)?;
            check_handle(module, rule, h)?;
            check_arg(&g, rule.arg, a[2], a[3])?;
            if let Some(w) = rule.walk {
                let arg = walked.ok_or(Refusal::Pointer)?;
                if arg.len() != a[3] {
                    return Err(Refusal::Pointer);
                }
                if w == Walker::ChannelIoctl {
                    let cmd = arg
                        .get(..4)
                        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                        .ok_or(Refusal::Pointer)?;
                    if !channel_ioctl_admitted(cmd) {
                        return Err(Refusal::Opcode);
                    }
                }
                check_walk(&g, w, arg)?;
            }
            Ok(())
        }
        op::PROVIDER_QUERY => {
            let key = a[1] as u32;
            let max = QUERIES
                .iter()
                .find(|q| q.0 == key)
                .map(|q| q.1)
                .ok_or(Refusal::Opcode)?;
            if h != -1 {
                return Err(Refusal::Handle);
            }
            check_arg(&g, Arg::Out(max), a[2], a[3])
        }
        op::PROVIDER_CLOSE => {
            if handles::owns(module, h) {
                Ok(())
            } else {
                Err(Refusal::Handle)
            }
        }
        // A selector names a provider by its own identity, which a gated
        // module has no business addressing directly.
        op::PROVIDER_CALL_SEL => Err(Refusal::Opcode),
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
    // An argument struct the provider follows pointers in is copied into
    // kernel memory first and checked there: the caller cannot change what
    // was checked before the provider reads it. The copy itself is bounded
    // by the rule's length and taken only from the caller's own memory.
    let walks = op == op::PROVIDER_CALL && rule_for(a[1] as u32).is_some_and(|r| r.walk.is_some());
    let mut copy = [0u8; WALK_MAX];
    let walked: Option<&[u8]> = if walks {
        let readable = a[3] <= WALK_MAX && gated(module).is_some_and(|g| g.readable(a[2], a[3]));
        if !readable {
            note_refusal(module, op, &a, Refusal::Pointer);
            return Refusal::Pointer.errno() as isize;
        }
        // SAFETY: `[a[2], a[2] + a[3])` lies in the caller's own memory,
        // checked above, and the caller is suspended.
        copy[..a[3]]
            .copy_from_slice(unsafe { core::slice::from_raw_parts(a[2] as *const u8, a[3]) });
        Some(&copy[..a[3]])
    } else {
        None
    };
    if let Err(why) = authorise(module, op, &a, walked) {
        note_refusal(module, op, &a, why);
        return why.errno() as isize;
    }
    let is_walked = walked.is_some();
    let sys = crate::kernel::module::syscalls::get_syscall_table();
    let h = a[0] as i32;
    // SAFETY: every pointer below was checked against the caller's own
    // regions by `authorise`, and every handle against what it holds.
    unsafe {
        match op {
            op::CHANNEL_READ => (sys.channel_read)(h, a[1] as *mut u8, a[2]) as isize,
            op::CHANNEL_WRITE => (sys.channel_write)(h, a[1] as *const u8, a[2]) as isize,
            op::CHANNEL_POLL => (sys.channel_poll)(h, a[1] as u32) as isize,
            op::CHANNEL_PEEK => (sys.channel_peek)(h, a[1] as *mut u8, a[2]) as isize,
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
                let rc = (sys.provider_open)(a[0] as u32, a[1] as u32, a[2] as *const u8, a[3]);
                mint_result(module, rc)
            }
            op::PROVIDER_CALL => {
                let rule = rule_for(a[1] as u32);
                // A walked struct is handed over as the kernel's checked copy.
                let arg = if is_walked {
                    copy.as_mut_ptr()
                } else {
                    a[2] as *mut u8
                };
                let rc = (sys.provider_call)(h, a[1] as u32, arg, a[3]);
                // A walked struct the provider writes into goes back to the
                // caller: `authorise` checked `[a[2], a[2] + a[3])` writable.
                if is_walked && rule.is_some_and(|r| matches!(r.arg, Arg::InOut(_))) {
                    core::ptr::copy_nonoverlapping(copy.as_ptr(), a[2] as *mut u8, a[3]);
                }
                match rule {
                    Some(r) if r.handle == HandleUse::Mints => mint_result(module, rc),
                    Some(r) if r.closes && rc >= 0 => {
                        handles::forget(module, h);
                        rc as isize
                    }
                    _ => rc as isize,
                }
            }
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
            "[gate] module {} op {} refused: {:?} (a0={:#x} a1={:#x} a2={:#x} a3={:#x})",
            module,
            op,
            why,
            a[0],
            a[1],
            a[2],
            a[3]
        );
    }
}

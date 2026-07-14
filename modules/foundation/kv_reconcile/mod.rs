//! Keyspace reconcile probe — a minimal control-plane reconciler as a PIC
//! module, proving the fmod-migration Phase-D architecture: a module inside a
//! fluxor graph drives the versioned keyspace provider (contract 0x17) through
//! the full reconcile loop via `provider_call`.
//!
//! It watches an input prefix and, on any change, recomputes a derived output
//! and writes it back — the shape every controller reduces to (the nanocloud
//! endpoints controller's `compute_service_endpoints` is the real payload; here
//! the "computation" is a mirror, so the loop itself is what's under test):
//!
//!   module_new/first step → SUBSCRIBE "/recon/in/"
//!   each step             → DRAIN the watch; on change: GET "/recon/in/svc",
//!                           PUT "/recon/out/svc" = the value
//!
//! Every op carries the keyspace provider's caller-output convention: the arg
//! ends with `[out_ptr:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]` so the
//! result and its fence land in module-owned buffers. Ops are one-shot
//! (handle = -1, class-byte routed on `op >> 8 == 0x17`).

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::convert::TryInto;
use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// Keyspace wire opcodes (mirror of provider::contract::KEYSPACE = 0x17xx; the
// slice-based dispatch lives in src/platform/linux/keyspace.rs).
const KS_PUT: u32 = 0x1701;
const KS_GET: u32 = 0x1702;
const KS_SUBSCRIBE: u32 = 0x1705;
const KS_DRAIN: u32 = 0x1706;
const DRAIN_EVENTS: u8 = 0;
const DRAIN_LOST: u8 = 1;

const IN_PREFIX: &[u8] = b"/recon/in/";
const IN_KEY: &[u8] = b"/recon/in/svc";
const OUT_KEY: &[u8] = b"/recon/out/svc";

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    out_chan: i32,
    /// The open watch handle (0 = not yet subscribed).
    watch_id: u64,
    /// Count of completed reconcile writes — the observable of progress.
    reconciles: u32,
}

/// Append the caller-output block `[out_ptr][out_cap][fence_ptr][fence_cap]` to
/// `arg` after `input_len` bytes of op input, then invoke the provider. `out`
/// and `fence` are module-owned buffers distinct from `arg`. Returns the
/// provider's i32 result.
unsafe fn ks_call(
    sys: &SyscallTable,
    op: u32,
    arg: &mut [u8],
    input_len: usize,
    out: &mut [u8],
    fence: &mut [u8],
) -> i32 {
    let mut p = input_len;
    arg[p..p + 8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    p += 8;
    arg[p..p + 4].copy_from_slice(&(out.len() as u32).to_le_bytes());
    p += 4;
    arg[p..p + 8].copy_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
    p += 8;
    arg[p..p + 2].copy_from_slice(&(fence.len() as u16).to_le_bytes());
    p += 2;
    (sys.provider_call)(-1, op, arg.as_mut_ptr(), p)
}

/// SUBSCRIBE the input prefix; returns the watch handle or 0 on failure.
unsafe fn subscribe(sys: &SyscallTable) -> u64 {
    let mut arg = [0u8; 128];
    let mut out = [0u8; 32];
    let mut fence = [0u8; 62];
    // input: [since:u64 = 0][prefix_len:u16][prefix]
    arg[0..8].copy_from_slice(&0u64.to_le_bytes());
    arg[8..10].copy_from_slice(&(IN_PREFIX.len() as u16).to_le_bytes());
    arg[10..10 + IN_PREFIX.len()].copy_from_slice(IN_PREFIX);
    let rc = ks_call(sys, KS_SUBSCRIBE, &mut arg, 10 + IN_PREFIX.len(), &mut out, &mut fence);
    if rc == 8 {
        u64::from_le_bytes(out[..8].try_into().unwrap())
    } else {
        0
    }
}

/// DRAIN the watch; true if anything changed (events or a LOST marker) — the
/// level-triggered trigger to re-reconcile.
unsafe fn drained_changed(sys: &SyscallTable, watch_id: u64) -> bool {
    let mut arg = [0u8; 32];
    let mut out = [0u8; 256];
    let mut fence = [0u8; 62];
    arg[0..8].copy_from_slice(&watch_id.to_le_bytes());
    arg[8..10].copy_from_slice(&0u16.to_le_bytes()); // max = 0 → all
    let rc = ks_call(sys, KS_DRAIN, &mut arg, 10, &mut out, &mut fence);
    if rc < 1 {
        return false;
    }
    match out[0] {
        DRAIN_LOST => true,
        DRAIN_EVENTS => u32::from_le_bytes(out[1..5].try_into().unwrap()) > 0,
        _ => false,
    }
}

/// Reconcile: GET the input, PUT the derived output. Returns true on a write.
unsafe fn reconcile(sys: &SyscallTable) -> bool {
    // GET input: [key_len:u16][key]
    let mut garg = [0u8; 64];
    let mut gout = [0u8; 256];
    let mut gfence = [0u8; 62];
    garg[0..2].copy_from_slice(&(IN_KEY.len() as u16).to_le_bytes());
    garg[2..2 + IN_KEY.len()].copy_from_slice(IN_KEY);
    let grc = ks_call(sys, KS_GET, &mut garg, 2 + IN_KEY.len(), &mut gout, &mut gfence);
    if grc < 8 {
        return false; // absent input → nothing to reconcile
    }
    let val_len = grc as usize - 8;
    if 8 + val_len > gout.len() {
        return false;
    }

    // PUT output (unconditional): [key_len:u16][if_match:u64][val_len:u32][key][val]
    let mut parg = [0u8; 512];
    let mut pout = [0u8; 32];
    let mut pfence = [0u8; 62];
    parg[0..2].copy_from_slice(&(OUT_KEY.len() as u16).to_le_bytes());
    parg[2..10].copy_from_slice(&u64::MAX.to_le_bytes()); // unconditional
    parg[10..14].copy_from_slice(&(val_len as u32).to_le_bytes());
    let mut p = 14;
    parg[p..p + OUT_KEY.len()].copy_from_slice(OUT_KEY);
    p += OUT_KEY.len();
    parg[p..p + val_len].copy_from_slice(&gout[8..8 + val_len]);
    p += val_len;
    let prc = ks_call(sys, KS_PUT, &mut parg, p, &mut pout, &mut pfence);
    prc == 8
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.watch_id = 0;
        s.reconciles = 0;
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return 0;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return 0;
        }
        let sys = &*s.syscalls;

        // Lazy subscribe on the first step (setup-safe: the graph is running).
        if s.watch_id == 0 {
            s.watch_id = subscribe(sys);
            return 0; // next step drains
        }
        // Level-triggered: on any change, recompute + write.
        if drained_changed(sys, s.watch_id) && reconcile(sys) {
            s.reconciles = s.reconciles.wrapping_add(1);
        }
        0
    }
}

include!("../../sdk/wasm_entry.rs");

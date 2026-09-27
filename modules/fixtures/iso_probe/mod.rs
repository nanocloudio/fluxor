//! Isolation probe — a purpose-built PIC module that runs gated
//! (`protection: isolated`, or `contained`) and demonstrates, one `mode` at a
//! time, that the boundary behaves as designed:
//!
//! | mode | name            | expected result                                          |
//! |------|-----------------|----------------------------------------------------------|
//! | 0    | `self_rw`       | reads+writes its own state, returns Continue             |
//! | 1    | `write_gateway` | writes the kernel's gateway table (read-only) → abort     |
//! | 2    | `oob_read`      | reads far outside its own memory → abort                  |
//! | 3    | `exec_state`    | jumps into its (execute-never) state → instruction abort  |
//! | 4    | `write_code`    | writes its own (read-only) code → permission abort        |
//! | 5    | `done`          | returns Done (clean round-trip)                           |
//! | 6    | `bad_channel`   | reads a channel it does not own → the gateway's EACCES    |
//! | 7    | `spin`          | never returns → forced out at its step deadline           |
//! | 8    | `bad_pointer`   | hands the gateway memory it does not own → EFAULT          |
//! | 9    | `overflow`      | recurses until its stack runs out → stack-bound fault     |
//! | 10   | `write_kernel`  | writes kernel RAM just below its own memory → abort       |
//! | 11   | `device_window` | reads its device window's first register and logs it,    |
//! |      |                 | then reads the byte just past the window → abort          |
//!
//! It is an ordinary SDK module: it reaches the kernel through the
//! `SyscallTable` it was given, which for a gated module is the gateway's —
//! every entry a veneer that traps. Its `module_new` runs gated too, so the
//! `[iso_probe] init` line is itself a gateway call.
//!
//! Modes 1-4 and 7 are expected faults: each becomes a module fault
//! (MON_FAULT plus a kernel log line), the configured fault policy runs, and
//! a healthy sibling keeps stepping. Modes 6 and 8 are refusals the module
//! observes: on the expected errno it returns an error so a restart policy
//! re-steps it; a success would mean the gateway served what it must not.

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct IsoProbeState {
    /// The syscall table the kernel handed this module — for a gated module
    /// the gateway's, in a kernel-owned page it may read but not write.
    syscalls: *const SyscallTable,
    /// Input channel handle captured at `module_new`. Mode `bad_channel`
    /// derives a deliberately-foreign handle from it.
    in_chan: i32,
    /// Probe mode (see table above).
    mode: u8,
    /// Steps to run cleanly before performing the probed access. Lets the
    /// fixture observe a few healthy EL0 round-trips first.
    delay_steps: u16,
    /// Step counter.
    step_count: u32,
    /// Sentinel the probe writes to (and reads back from) its own state in
    /// mode `self_rw`, proving own-state RW works at EL0.
    sentinel: u32,
    /// Scratch the probe reads OOB values into so the load can't be
    /// optimised away.
    sink: u64,
    /// The device window the graph granted, (base, size); size 0 for none.
    window_base: u64,
    window_size: u32,
}

declare_module_state_bytes!(IsoProbeState);
// The recursion in `overflow` has no bound the build can measure; this is
// the stack every other mode needs, which `overflow` then runs past.
declare_module_stack_bytes!(512);

const SENTINEL_MAGIC: u32 = 0x5130_B0E0; // "iso probe"

/// The gateway's refusals, as the module sees them.
const EACCES: i32 = -13;
const EFAULT: i32 = -14;

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::p_u16;
    use super::p_u8;
    use super::IsoProbeState;
    use super::SCHEMA_MAX;

    define_params! {
        IsoProbeState;

        1, mode, u8, 0,
            enum { self_rw=0, write_gateway=1, oob_read=2, exec_state=3, write_code=4, done=5, bad_channel=6, spin=7, bad_pointer=8, overflow=9, write_kernel=10, device_window=11 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

        2, delay_steps, u16, 3
            => |s, d, len| { s.delay_steps = p_u16(d, len, 0, 3); };
    }
}

// ============================================================================
// Exported functions
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<IsoProbeState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // Runs gated like `module_step`: `dev_log` below is a gateway call.
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<IsoProbeState>() {
            return -3;
        }
        let s = &mut *(state as *mut IsoProbeState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.step_count = 0;
        s.sentinel = 0;
        s.sink = 0;
        let (wb, wz) = device_window(params, params_len).unwrap_or((0, 0));
        s.window_base = wb;
        s.window_size = wz;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // The mode in the line, so a rig reading the console knows this
        // image's probe from the previous one's.
        let mut line = *b"[iso_probe] init mode=00";
        let n = line.len();
        line[n - 2] = b'0' + (s.mode / 10) % 10;
        line[n - 1] = b'0' + s.mode % 10;
        dev_log(&*s.syscalls, 3, line.as_ptr(), line.len());
        0 // Ready
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // Reports via the return value and via deliberately-raised faults.
    unsafe {
        let s = &mut *(state as *mut IsoProbeState);
        s.step_count += 1;

        // A few clean round-trips first so the fixture observes healthy EL0
        // execution before any probed access.
        if s.step_count <= s.delay_steps as u32 {
            // Own-state RW always exercised on the warm-up path.
            s.sentinel = SENTINEL_MAGIC ^ s.step_count;
            if s.sentinel != (SENTINEL_MAGIC ^ s.step_count) {
                return -100; // own state RW broken (should be impossible)
            }
            return 0; // Continue
        }

        match s.mode {
            // Own state read/write works at EL0.
            0 => {
                s.sentinel = SENTINEL_MAGIC;
                let read_back = core::ptr::read_volatile(&s.sentinel);
                if read_back == SENTINEL_MAGIC {
                    0 // Continue — isolation lets the module touch its own state
                } else {
                    -101
                }
            }
            // Write the kernel's gateway table: kernel-owned, mapped
            // read-only so the module can call through it → permission abort.
            1 => {
                let table = s.syscalls as *mut u32;
                core::ptr::write_volatile(table, 0);
                // Reaching here means the kernel's page was writable.
                -110
            }
            // Read far outside any mapped region (stands in for a neighbour
            // module's state / arbitrary kernel RAM) → EL0 data abort.
            2 => {
                let oob = (state as usize).wrapping_add(0x0040_0000) as *const u64; // +4 MiB
                s.sink = core::ptr::read_volatile(oob);
                -111
            }
            // Execute the (execute-never) state buffer → instruction abort.
            3 => {
                let f: extern "C" fn() = core::mem::transmute::<*mut u8, extern "C" fn()>(state);
                f();
                -112
            }
            // Write the module's own (read-only at EL0) code → permission
            // abort. `module_step` is in the RO+X code region.
            4 => {
                let code = module_step as *mut u32;
                core::ptr::write_volatile(code, 0);
                -113
            }
            // Clean finish — proves the full EL0→SVC→EL1 round-trip with a
            // terminal outcome.
            5 => 1, // Done
            // Channel authority: read a handle this module was never given.
            // The gateway must refuse it (EACCES) before touching any channel.
            // The buffer is its own state, so only the handle can be refused.
            6 => {
                let foreign = s.in_chan.wrapping_add(1000);
                let r = ((*s.syscalls).channel_read)(
                    foreign,
                    core::ptr::addr_of_mut!(s.sink) as *mut u8,
                    core::mem::size_of::<u64>(),
                );
                if r == EACCES {
                    -121
                } else {
                    -120 // served a foreign channel → breach
                }
            }
            // Never return: the kernel must force it out at its deadline.
            7 => loop {
                s.sink = s.sink.wrapping_add(1);
                core::hint::spin_loop();
            },
            // Hand the gateway memory the module does not own: a log message
            // "at" an address outside its regions. It must be refused with
            // EFAULT before the kernel reads a byte of it.
            8 => {
                let r = ((*s.syscalls).provider_call)(
                    3,
                    0x0C40, // LOG_WRITE
                    (state as usize).wrapping_add(0x0040_0000) as *mut u8,
                    16,
                );
                if r == EFAULT {
                    -122
                } else {
                    -123 // read memory it does not own → breach
                }
            }
            // Write RAM that is not the module's: the page below its own
            // memory, which is the kernel's or another module's. Contained
            // and isolated both forbid it.
            10 => {
                let below = (state as usize & !0xFFF).wrapping_sub(0x1000) as *mut u32;
                core::ptr::write_volatile(below, 0xDEAD_BEEF);
                -125 // wrote memory it does not own → breach
            }
            // Recurse with a large frame until the stack runs out: the
            // hardware bound (a limit register, a guard, or the end of the
            // module's own memory) must fault it before it writes past.
            9 => {
                s.sink = deeper(s.sink as u32) as u64;
                -124 // returned: the recursion was bounded by something else
            }
            // The granted device window: the first probed step reads its
            // first register and says what it held (the window reaches the
            // peripheral); every later step reads the register just past it,
            // the next block's, which is not the module's → abort.
            11 => {
                if s.window_size == 0 {
                    return -130; // no window granted
                }
                if s.step_count == s.delay_steps as u32 + 1 {
                    let v = core::ptr::read_volatile(s.window_base as usize as *const u32);
                    let mut line = *b"[iso_probe] device ok reg=0x00000000";
                    let n = line.len();
                    for i in 0..8 {
                        let nib = ((v >> (28 - 4 * i)) & 0xF) as u8;
                        line[n - 8 + i] = if nib < 10 {
                            b'0' + nib
                        } else {
                            b'a' + nib - 10
                        };
                    }
                    dev_log(&*s.syscalls, 3, line.as_ptr(), line.len());
                    s.sink = v as u64;
                    return 0;
                }
                let past = (s.window_base as usize + s.window_size as usize) as *const u32;
                s.sink = core::ptr::read_volatile(past) as u64;
                -131 // read a register beside its window → breach
            }
            _ => 0,
        }
    }
}

/// One level of unbounded recursion with a 256-byte frame the compiler
/// cannot elide. The depth is data: the build's stack measurement sees one
/// frame, as it would for any recursion it cannot bound.
#[inline(never)]
fn deeper(n: u32) -> u32 {
    let mut frame = [0u8; 256];
    for (i, b) in frame.iter_mut().enumerate() {
        *b = (n as usize + i) as u8;
    }
    if n == u32::MAX {
        return 0;
    }
    let r = deeper(n.wrapping_add(1));
    // Read the frame after the call, so every level keeps its own: without
    // this the recursion becomes a loop that never grows the stack.
    unsafe { core::ptr::read_volatile(&frame[r as usize % 256]) as u32 }.wrapping_add(r)
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");

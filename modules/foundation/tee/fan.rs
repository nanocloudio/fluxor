// The part of a fan module `tee` and `merge` share: the instance, its
// params, and the whole-record rule. Included by both (`include!`), so each
// stays one crate.
//
// A fan moves what one port carries to several, or several to one, one
// record per transfer: every channel keeps its writes' boundaries, so the
// fan asks the kernel how long the record at the head is (`RECORD_LEN`) and
// never reads what is in it. A record moves only when every side it goes to
// can take it whole; otherwise nothing is consumed and the step ends, so
// back pressure reaches the producer and the fan holds nothing between
// steps.

/// The ports a fan has on its many side: the kernel's per-module port
/// table.
pub const LANES: usize = 16;

/// The scratch a fan is given when its params leave `scratch_bytes` unset:
/// the composer always sets it, to the largest ring beside the fan.
#[cfg(target_arch = "aarch64")]
pub const SCRATCH_DEFAULT: u32 = 32768;
#[cfg(target_arch = "arm")]
pub const SCRATCH_DEFAULT: u32 = 2048;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
pub const SCRATCH_DEFAULT: u32 = 8192;

/// The heap a fan needs besides its scratch: the block header, rounding to
/// the allocator's 16-byte granularity and the canary.
const ARENA_BASE: u32 = 64;

#[repr(C)]
pub struct FanState {
    syscalls: *const SyscallTable,
    /// The record being moved, `scratch_len` bytes from the heap.
    scratch: *mut u8,
    scratch_len: u32,
    frames_per_step: u16,
    /// The ports in use on the many side.
    lanes_len: u8,
    /// The one side: a tee's input, a merge's output.
    one: i32,
    /// The many side: a tee's outputs, a merge's inputs, in port order.
    lanes: [i32; LANES],
    /// A merge's next input in its round robin.
    next: u8,
}

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        FanState;
        1, frames_per_step, u16, 64, range 1..=u16::MAX => |s, d, len| { s.frames_per_step = p_u16(d, len, 0, 64); };
        2, scratch_bytes, u32, SCRATCH_DEFAULT, range 1..=u32::MAX => |s, d, len| {
            s.scratch_len = p_u32(d, len, 0, SCRATCH_DEFAULT);
        };
    }
}

fluxor_rt::module_facts! { state: FanState, arena: ARENA_BASE }

/// Why a step fails. A fan that cannot move a record whole faults rather
/// than spin on it.
///
/// The record is larger than the scratch: a topology the composer should not
/// have built.
const E_RECORD_TOO_LARGE: i32 = abi::errno::EOVERFLOW;
/// A transfer the checks before it said would land did not.
const E_SHORT: i32 = abi::errno::EIO;

/// The length of the record at the head of `chan`; 0 when none is waiting
/// (or a mailbox's record is lent out).
#[inline(always)]
unsafe fn head(s: &FanState, chan: i32) -> usize {
    dev_channel_record_len(&*s.syscalls, chan).max(0) as usize
}

/// Whether `chan` takes a `len`-byte record now: a ring with that much room,
/// or a mailbox (which states no room) free to be written.
#[inline(always)]
unsafe fn takes(s: &FanState, chan: i32, len: usize) -> bool {
    match writable(s, chan) {
        0 => polls(s, chan, POLL_OUT),
        room => room >= len,
    }
}

/// The record at the head of `chan`, read into the scratch only when `room`
/// says every side it goes to can take it: `Ok(Some(len))` once read,
/// `Ok(None)` when it waits (nothing consumed).
unsafe fn take(
    s: &FanState,
    chan: i32,
    room: impl Fn(usize) -> bool,
) -> Result<Option<usize>, i32> {
    let len = head(s, chan);
    if len == 0 {
        return Ok(None);
    }
    if len > s.scratch_len as usize {
        return Err(E_RECORD_TOO_LARGE);
    }
    if !room(len) {
        return Ok(None);
    }
    if ((*s.syscalls).channel_read)(chan, s.scratch, len) != len as i32 {
        return Err(E_SHORT);
    }
    Ok(Some(len))
}

/// `len` bytes of the scratch to `chan`, whole.
#[inline(always)]
unsafe fn put(s: &FanState, chan: i32, len: usize) -> Result<(), i32> {
    if ((*s.syscalls).channel_write)(chan, s.scratch, len) != len as i32 {
        return Err(E_SHORT);
    }
    Ok(())
}

/// The largest write `chan` takes now; 0 when it cannot say.
#[inline(always)]
unsafe fn writable(s: &FanState, chan: i32) -> usize {
    dev_channel_writable(&*s.syscalls, chan).max(0) as usize
}

#[inline(always)]
unsafe fn polls(s: &FanState, chan: i32, event: u32) -> bool {
    ((*s.syscalls).channel_poll)(chan, event) > 0
}

/// A fan's ports as `module_new` is handed them.
struct Wiring {
    /// The one side's channel.
    one: i32,
    /// The many side's port 0.
    first: i32,
    /// The many side's port direction: 0 the inputs, 1 the outputs.
    many_dir: u8,
}

/// Construct a fan: params, its wiring, and the scratch.
unsafe fn construct(
    wiring: Wiring,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return abi::errno::EINVAL;
    }
    if state_size < core::mem::size_of::<FanState>() {
        return abi::errno::ENOMEM;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<FanState>());
    let s = &mut *(state as *mut FanState);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    } else {
        params_def::set_defaults(s);
    }
    let Wiring {
        one,
        first,
        many_dir,
    } = wiring;
    s.one = one;
    let mut k = 0;
    while k < LANES {
        let chan = if k == 0 {
            first
        } else {
            dev_channel_port(sys, many_dir, k as u8)
        };
        if chan >= 0 {
            s.lanes[s.lanes_len as usize] = chan;
            s.lanes_len += 1;
        }
        k += 1;
    }
    let refuse: Option<&[u8]> = if s.one < 0 || s.lanes_len == 0 {
        Some(b"refusing to construct: a port of the fan is not wired")
    } else if s.frames_per_step == 0 || s.scratch_len == 0 {
        Some(b"refusing to construct: frames_per_step and scratch_bytes must be non-zero")
    } else {
        None
    };
    if let Some(m) = refuse {
        dev_log(sys, 1, m.as_ptr(), m.len());
        return abi::errno::EINVAL;
    }
    s.scratch = (sys.heap_alloc)(s.scratch_len);
    if s.scratch.is_null() {
        let m = b"refusing to construct: the heap cannot hold scratch_bytes \
                  (heap.arena_bytes below what heap_per_param sizes)";
        dev_log(sys, 1, m.as_ptr(), m.len());
        return abi::errno::ENOMEM;
    }
    0
}

/// Run `one` up to `frames_per_step` times, while it moves something.
#[inline(always)]
unsafe fn burst(
    s: &mut FanState,
    mut one: impl FnMut(&mut FanState) -> Result<bool, i32>,
) -> StepReturn {
    for _ in 0..s.frames_per_step {
        match one(s) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => return StepReturn::error(e),
        }
    }
    StepReturn::Continue
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

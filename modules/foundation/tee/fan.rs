// The part of a fan module `tee` and `merge` share: the instance, its
// params, and the whole-frame rule. Included by both (`include!`), so each
// stays one crate.
//
// A fan moves what one port carries to several, or several to one, and
// keeps the producer's units whole: the composer names the port's frame
// kind in the fan's params, and the fan reads each frame's length from its
// header before it consumes anything. A frame moves only when it is all
// buffered and every side it goes to can take it whole; otherwise nothing
// is consumed and the step ends, so back pressure reaches the producer and
// the fan holds nothing between steps.

/// The frame kinds, `fluxor_contracts::graph::plan::FrameKind`'s
/// discriminants (the `frame_kind` param).
///
/// Bytes, moved as they come.
pub const KIND_STREAM: u8 = 0;
/// `[len u16 LE][payload]` Ethernet frames.
pub const KIND_ETH: u8 = 1;
/// `[msg_type u8][len u16 LE][payload]` network-protocol records.
pub const KIND_NET: u8 = 2;
/// Telemetry records, whose length their `signal` and `kind` bytes give.
pub const KIND_TELEMETRY: u8 = 3;
/// Records that state no length: one mailbox record each.
pub const KIND_RECORD: u8 = 4;

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
    /// The frame being moved, `scratch_len` bytes from the heap.
    scratch: *mut u8,
    scratch_len: u32,
    frames_per_step: u16,
    frame_kind: u8,
    /// The ports in use on the many side.
    lanes_len: u8,
    /// The one side: a tee's input, a merge's output.
    one: i32,
    /// The many side: a tee's outputs, a merge's inputs, in port order.
    lanes: [i32; LANES],
    /// A merge's next input in its round robin.
    next: u8,
    /// A merge of a stream: the input a transfer was cut short on, drained
    /// to empty before another is read, so no other producer's bytes land
    /// inside the unit the cut split; -1 when none is owed.
    owed: i8,
}

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        FanState;
        1, frame_kind, u8, 0,
            enum { stream = 0, eth = 1, net = 2, telemetry = 3, record = 4 }
            => |s, d, len| { s.frame_kind = p_u8(d, len, 0, 0); };
        2, frames_per_step, u16, 64 => |s, d, len| { s.frames_per_step = p_u16(d, len, 0, 64); };
        3, scratch_bytes, u32, SCRATCH_DEFAULT => |s, d, len| {
            s.scratch_len = p_u32(d, len, 0, SCRATCH_DEFAULT);
        };
    }
}

fluxor_rt::module_facts! { state: FanState, arena: ARENA_BASE }

/// Why a step fails. A fan that cannot move a frame whole faults rather than
/// spin on it.
///
/// The frame is larger than the scratch: a topology the composer should not
/// have built.
const E_FRAME_TOO_LARGE: i32 = abi::errno::EOVERFLOW;
/// The frame header is malformed: a zero-length Ethernet frame, an
/// unrecognised telemetry record.
const E_MALFORMED: i32 = abi::errno::EINVAL;
/// A transfer the checks before it said would land did not.
const E_SHORT: i32 = abi::errno::EIO;

/// Bytes of the header a frame's length is read from.
#[inline(always)]
fn hdr_len(kind: u8) -> usize {
    match kind {
        KIND_ETH | KIND_TELEMETRY => 2,
        KIND_NET => 3,
        _ => 0,
    }
}

/// The bytes after the header, from the header.
#[inline(always)]
fn body_len(kind: u8, hdr: &[u8; 3]) -> usize {
    match kind {
        KIND_ETH => u16::from_le_bytes([hdr[0], hdr[1]]) as usize,
        KIND_NET => u16::from_le_bytes([hdr[1], hdr[2]]) as usize,
        KIND_TELEMETRY => abi::contracts::telemetry::record_len(hdr[0], hdr[1]).saturating_sub(2),
        _ => 0,
    }
}

/// The whole frame at the head of `chan`, read into the scratch only when
/// it is all buffered and `room` says every side it goes to can take it:
/// `Ok(Some(total))` once read, `Ok(None)` when it waits (nothing consumed).
unsafe fn take_frame(
    s: &FanState,
    chan: i32,
    room: impl Fn(usize) -> bool,
) -> Result<Option<usize>, i32> {
    let sys = &*s.syscalls;
    let h = hdr_len(s.frame_kind);
    let mut hdr = [0u8; 3];
    if (sys.channel_peek)(chan, hdr.as_mut_ptr(), h) < h as i32 {
        return Ok(None);
    }
    let body = body_len(s.frame_kind, &hdr);
    let total = h + body;
    if total > s.scratch_len as usize {
        return Err(E_FRAME_TOO_LARGE);
    }
    if body == 0 && (s.frame_kind == KIND_ETH || s.frame_kind == KIND_TELEMETRY) {
        return Err(E_MALFORMED);
    }
    if (sys.channel_peek)(chan, s.scratch, total) < total as i32 || !room(total) {
        return Ok(None);
    }
    if (sys.channel_read)(chan, s.scratch, total) != total as i32 {
        return Err(E_SHORT);
    }
    Ok(Some(total))
}

/// The record at the head of a mailbox, read whole into the scratch:
/// `Ok(Some(len))`, or `Ok(None)` when none is pending.
unsafe fn take_record(s: &FanState, chan: i32) -> Result<Option<usize>, i32> {
    let sys = &*s.syscalls;
    let read = (sys.channel_read)(chan, s.scratch, s.scratch_len as usize);
    if read == abi::errno::EINVAL {
        // A mailbox refuses a read too small for its record and keeps it.
        return Err(E_FRAME_TOO_LARGE);
    }
    Ok((read > 0).then_some(read as usize))
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
    s.owed = -1;
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
    } else if s.frame_kind > KIND_RECORD {
        Some(b"refusing to construct: frame_kind is not a frame kind")
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

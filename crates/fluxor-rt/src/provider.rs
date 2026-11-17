// ============================================================================
// provider_call convenience wrappers
// ============================================================================
//
// Thin typed wrappers around common `provider_call(handle=-1, op, ...)`
// global operations — logging, timing, arena queries, channel ops,
// bridge I/O, flash sideband, runtime params.
// Everything routes through `SyscallTable::provider_call`.

use crate::*;

/// Monotonic time in milliseconds (TIMER::MILLIS).
#[inline(always)]
pub unsafe fn dev_millis(sys: &SyscallTable) -> u64 {
    let mut buf = [0u8; 8];
    (sys.provider_call)(
        -1,
        abi::registry::timer::MILLIS,
        buf.as_mut_ptr(),
        8,
        core::ptr::null_mut(),
        0,
    );
    u64::from_le_bytes(buf)
}

/// Monotonic time in microseconds (TIMER::MICROS). Useful for
/// per-phase profiling at sub-millisecond granularity.
#[inline(always)]
pub unsafe fn dev_micros(sys: &SyscallTable) -> u64 {
    let mut buf = [0u8; 8];
    (sys.provider_call)(
        -1,
        abi::registry::timer::MICROS,
        buf.as_mut_ptr(),
        8,
        core::ptr::null_mut(),
        0,
    );
    u64::from_le_bytes(buf)
}

/// A security-grade time observation (`TIMER::TRUSTED_UNIX`).
///
/// Returns the raw record; `abi::kernel_abi::trusted_time` names its offsets
/// and the meaning of `source_class` / `flags`. Use this, not
/// `dev_unix_millis`, for anything that decides whether a credential is
/// still valid: a bare `u64` cannot say whether it is worth trusting, and on
/// a board with no RTC it is zero — which every current caller silently
/// treats as "1970", i.e. as an expiry that has not happened yet.
#[inline(always)]
pub unsafe fn dev_trusted_unix(sys: &SyscallTable) -> [u8; 36] {
    // 36 is `trusted_time::LEN`, reserved word included: the syscall refuses
    // anything shorter, and a refused call reads as UNAVAILABLE below.
    let mut buf = [0u8; 36];
    let rc = (sys.provider_call)(
        -1,
        abi::registry::timer::TRUSTED_UNIX,
        buf.as_mut_ptr(),
        buf.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        // A platform without the surface is UNAVAILABLE, which is the same
        // answer as a platform with no clock — and the same refusal.
        buf = [0u8; 36];
    }
    buf
}

/// This boot's incarnation (`BOOT_INCARNATION` `kernel::BOOT_INCARNATION`): 16 bytes fresh per
/// boot, shared by every module. `None` until the kernel's entropy source
/// has answered — a consumer minting a token waits rather than minting
/// against zeros.
#[inline(always)]
pub unsafe fn dev_boot_incarnation(sys: &SyscallTable) -> Option<[u8; 16]> {
    let mut buf = [0u8; 16];
    let rc = (sys.provider_call)(
        -1,
        abi::registry::kernel::BOOT_INCARNATION,
        buf.as_mut_ptr(),
        16,
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 || buf == [0u8; 16] {
        None
    } else {
        Some(buf)
    }
}

/// Wall-clock milliseconds since the Unix epoch (TIMER::UNIX_MILLIS), or 0 on a
/// platform with no real-time clock. Distinct from `dev_millis` (monotonic uptime); use for
/// absolute-time checks (certificate validity, JWT `exp`). See docs/surface-auth.md.
#[inline(always)]
pub unsafe fn dev_unix_millis(sys: &SyscallTable) -> u64 {
    let mut buf = [0u8; 8];
    (sys.provider_call)(
        -1,
        abi::registry::timer::UNIX_MILLIS,
        buf.as_mut_ptr(),
        8,
        core::ptr::null_mut(),
        0,
    );
    u64::from_le_bytes(buf)
}

/// Per-step flow-budget grant for one of this module's output ports
/// (MODULE_FLOW_BUDGET `kernel::MODULE_FLOW_BUDGET`). Returns 0 when the wired edge
/// carries no streaming rate class; callers keep their own
/// unit-per-step pacing in that case.
#[inline(always)]
pub unsafe fn dev_flow_budget(sys: &SyscallTable, port_index: u8) -> u32 {
    let mut arg = [port_index, 0];
    let r = (sys.provider_call)(
        -1,
        abi::registry::kernel::MODULE_FLOW_BUDGET,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if r > 0 {
        r as u32
    } else {
        0
    }
}

/// Per-step consumption budget for one of this module's input ports. Uses the
/// same class and live domain period as [`dev_flow_budget`].
#[inline(always)]
pub unsafe fn dev_input_flow_budget(sys: &SyscallTable, input_port_index: u8) -> u32 {
    let mut arg = [input_port_index, 1];
    let r = (sys.provider_call)(
        -1,
        abi::registry::kernel::MODULE_FLOW_BUDGET,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if r > 0 {
        r as u32
    } else {
        0
    }
}

/// Log a message (kernel primitive LOG_WRITE, opcode `kernel::LOG_WRITE`). Level encoded as handle.
#[inline(always)]
pub unsafe fn dev_log(sys: &SyscallTable, level: u8, msg: *const u8, len: usize) {
    (sys.provider_call)(
        level as i32,
        abi::registry::kernel::LOG_WRITE,
        core::ptr::null_mut(),
        0,
        msg as *mut u8,
        len,
    );
}

/// Poll any fd via provider_call (kernel primitive HANDLE_POLL, opcode `kernel::HANDLE_POLL`).
#[inline(always)]
pub unsafe fn dev_fd_poll(sys: &SyscallTable, fd: i32, events: u32) -> i32 {
    let mut buf = [events as u8];
    (sys.provider_call)(
        fd,
        abi::registry::kernel::HANDLE_POLL,
        buf.as_mut_ptr(),
        1,
        core::ptr::null_mut(),
        0,
    )
}

/// Create an event via provider_call (EVENT::CREATE `event::CREATE`).
#[inline(always)]
pub unsafe fn dev_event_create(sys: &SyscallTable) -> i32 {
    (sys.provider_call)(
        -1,
        abi::registry::event::CREATE,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    )
}

/// Poll an event via provider_call (EVENT::POLL `event::POLL`). Returns 1 if signaled (clears it), 0 if not.
#[inline(always)]
pub unsafe fn dev_event_poll(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.provider_call)(
        handle,
        abi::registry::event::POLL,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    )
}

/// Bind an event to a hardware IRQ (kernel primitive BIND_IRQ, opcode `event::BIND_IRQ`).
/// `irq`: GIC interrupt number. `ack`: how the kernel quiets the device
/// behind the line before it signals (`abi::kernel_abi::event::ack`).
pub unsafe fn dev_irq_bind(sys: &SyscallTable, event_handle: i32, irq: u32, ack: u8) -> i32 {
    let mut arg = [0u8; 5];
    arg[0..4].copy_from_slice(&irq.to_le_bytes());
    arg[4] = ack;
    (sys.provider_call)(
        event_handle,
        abi::registry::event::BIND_IRQ,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    )
}

/// Query graph-level sample rate (kernel primitive GRAPH_SAMPLE_RATE, opcode `kernel::GRAPH_SAMPLE_RATE`).
/// Returns 0 if not configured.
#[inline(always)]
pub unsafe fn dev_graph_sample_rate(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.provider_query)(
        -1,
        abi::registry::kernel::GRAPH_SAMPLE_RATE,
        buf.as_mut_ptr(),
        4,
    );
    if r >= 0 {
        u32::from_le_bytes(buf)
    } else {
        0
    }
}

/// Query system clock frequency (kernel primitive SYS_CLOCK_HZ, opcode `kernel::SYS_CLOCK_HZ`).
/// Returns 0 on error (should not happen in practice).
#[inline(always)]
pub unsafe fn dev_sys_clock_hz(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.provider_query)(-1, abi::registry::kernel::SYS_CLOCK_HZ, buf.as_mut_ptr(), 4);
    if r >= 0 {
        u32::from_le_bytes(buf)
    } else {
        0
    }
}

/// Query stream time via `provider_query(-1, kernel_abi::STREAM_TIME)`.
/// Returns the first active PIO stream's (consumed_units, queued_units,
/// units_per_sec_q16, t0_micros), or zeros if no stream is active.
#[inline(always)]
pub unsafe fn dev_stream_time(sys: &SyscallTable) -> (u64, u32, u32, u64) {
    let mut buf = [0u8; 24]; // StreamTime is 24 bytes
    let r = (sys.provider_query)(-1, abi::kernel_abi::STREAM_TIME, buf.as_mut_ptr(), 24);
    if r < 0 {
        return (0, 0, 0, 0);
    }
    let consumed = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let queued = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let rate_q16 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let t0 = u64::from_le_bytes([
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]);
    (consumed, queued, rate_q16, t0)
}

/// Query downstream latency (kernel primitive DOWNSTREAM_LATENCY, opcode `kernel::DOWNSTREAM_LATENCY`).
/// Returns frames of latency downstream from the calling module, or 0.
#[inline(always)]
pub unsafe fn dev_downstream_latency(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.provider_query)(
        -1,
        abi::registry::kernel::DOWNSTREAM_LATENCY,
        buf.as_mut_ptr(),
        4,
    );
    if r >= 0 {
        u32::from_le_bytes(buf)
    } else {
        0
    }
}

/// Report module's processing latency (kernel primitive REPORT_LATENCY, opcode `kernel::REPORT_LATENCY`).
#[inline(always)]
pub unsafe fn dev_report_latency(sys: &SyscallTable, frames: u32) {
    let mut buf = frames.to_le_bytes();
    (sys.provider_call)(
        -1,
        abi::registry::kernel::REPORT_LATENCY,
        buf.as_mut_ptr(),
        4,
        core::ptr::null_mut(),
        0,
    );
}

/// `StepEffect` codes for [`dev_report_step_effect`]. Mirrors
/// `kernel_abi::step_effect` and the kernel's `step_effect`.
#[allow(
    dead_code,
    reason = "module SDK surface; not every module reports every variant"
)]
pub mod step_effect {
    pub const IDLE: u8 = 0;
    pub const WAITING: u8 = 1;
    pub const WORK_DONE: u8 = 2;
    pub const RUNNABLE_BACKLOG: u8 = 3;
    pub const BURST: u8 = 4;
}

/// Report this module's `StepEffect` for the current pass (kernel primitive
/// `REPORT_STEP_EFFECT`, opcode `kernel::REPORT_STEP_EFFECT`). `WorkDone`/`RunnableBacklog`/`Burst`
/// keep the adaptive pacer hot without an immediate same-module re-step; the
/// re-step decision stays with the `StepOutcome::Burst` return value. A module
/// that never calls this is treated as `Idle`.
#[inline(always)]
pub unsafe fn dev_report_step_effect(sys: &SyscallTable, effect: u8) {
    let mut buf = [effect];
    (sys.provider_call)(
        -1,
        abi::registry::kernel::REPORT_STEP_EFFECT,
        buf.as_mut_ptr(),
        1,
        core::ptr::null_mut(),
        0,
    );
}

/// Discover channel port via provider_call (CHANNEL::PORT `channel::PORT`).
#[inline(always)]
pub unsafe fn dev_channel_port(sys: &SyscallTable, port_type: u8, index: u8) -> i32 {
    let mut buf = [0u8; 2];
    // Volatile stores: PIC aarch64 otherwise dead-stores the buffer and
    // provider_call sees zeros on entry.
    core::ptr::write_volatile(buf.as_mut_ptr(), port_type);
    core::ptr::write_volatile(buf.as_mut_ptr().add(1), index);
    (sys.provider_call)(
        -1,
        abi::registry::channel::PORT,
        buf.as_mut_ptr(),
        2,
        core::ptr::null_mut(),
        0,
    )
}

/// One no-argument channel op on `handle`: its result.
#[inline(always)]
unsafe fn channel_op(sys: &SyscallTable, handle: i32, op: u32) -> i32 {
    (sys.provider_call)(
        handle,
        op,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    )
}

/// Drop what the channel holds and start its stream over
/// (`kernel_abi::channel::FLUSH`): either end. `EBUSY` while a mailbox
/// record is lent.
#[inline(always)]
pub unsafe fn dev_channel_flush(sys: &SyscallTable, handle: i32) -> i32 {
    channel_op(sys, handle, abi::kernel_abi::channel::FLUSH)
}

/// End the stream (`kernel_abi::channel::SET_HUP`): the producer.
#[inline(always)]
pub unsafe fn dev_channel_set_hup(sys: &SyscallTable, handle: i32) -> i32 {
    channel_op(sys, handle, abi::kernel_abi::channel::SET_HUP)
}

/// The largest write the channel's ring takes now
/// (`kernel_abi::channel::WRITABLE`), or a negative errno: the producer. 0
/// for a full ring and for a mailbox.
#[inline(always)]
pub unsafe fn dev_channel_writable(sys: &SyscallTable, handle: i32) -> i32 {
    let mut out = [0u8; 4];
    let rc = (sys.provider_call)(
        handle,
        abi::kernel_abi::channel::WRITABLE,
        out.as_mut_ptr(),
        4,
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return rc;
    }
    u32::from_le_bytes(out).min(i32::MAX as u32) as i32
}

/// The unread bytes of the record at the head of the channel
/// (`kernel_abi::channel::RECORD_LEN`): the consumer. `EAGAIN` when nothing
/// is buffered.
#[inline(always)]
pub unsafe fn dev_channel_record_len(sys: &SyscallTable, handle: i32) -> i32 {
    channel_op(sys, handle, abi::kernel_abi::channel::RECORD_LEN)
}

/// Run one of the three mailbox acquires (`kernel_abi::channel`): the buffer,
/// or null, and the length the kernel reported through `len_out` when it is
/// not null. The address comes back in the call's argument record, never in
/// its `i32` result, so it survives on a 64-bit target.
#[inline(always)]
pub unsafe fn dev_buffer_acquire(
    sys: &SyscallTable,
    chan: i32,
    op: u32,
    len_out: *mut u32,
) -> *mut u8 {
    use abi::kernel_abi::channel::acquired;
    let mut rec = [0u8; acquired::SIZE];
    let rc = (sys.provider_call)(
        chan,
        op,
        rec.as_mut_ptr(),
        rec.len(),
        core::ptr::null_mut(),
        0,
    );
    if !len_out.is_null() {
        *len_out = u32::from_le_bytes([
            rec[acquired::LEN],
            rec[acquired::LEN + 1],
            rec[acquired::LEN + 2],
            rec[acquired::LEN + 3],
        ]);
    }
    if rc != 0 {
        return core::ptr::null_mut();
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&rec[acquired::PTR..acquired::PTR + 8]);
    u64::from_le_bytes(a) as usize as *mut u8
}

/// Acquire write access to a mailbox channel's buffer
/// (`kernel_abi::channel::ACQUIRE_WRITE`). Returns the buffer, or null.
/// `capacity_out` receives the buffer's capacity, also when the mailbox is
/// busy, so a producer can tell "busy" (non-zero) from "not a mailbox" (zero).
#[inline(always)]
pub unsafe fn dev_buffer_acquire_write(
    sys: &SyscallTable,
    chan: i32,
    capacity_out: *mut u32,
) -> *mut u8 {
    dev_buffer_acquire(
        sys,
        chan,
        abi::kernel_abi::channel::ACQUIRE_WRITE,
        capacity_out,
    )
}

/// Release a write buffer (`kernel_abi::channel::RELEASE_WRITE`).
#[inline(always)]
pub unsafe fn dev_buffer_release_write(sys: &SyscallTable, chan: i32, len: u32) -> i32 {
    let mut buf = len.to_le_bytes();
    (sys.provider_call)(
        chan,
        abi::registry::channel::RELEASE_WRITE,
        buf.as_mut_ptr(),
        4,
        core::ptr::null_mut(),
        0,
    )
}

/// Acquire in-place access to the pending message
/// (`kernel_abi::channel::ACQUIRE_INPLACE`). Returns the buffer, or null;
/// `len_out` receives the message length.
#[inline(always)]
pub unsafe fn dev_buffer_acquire_inplace(
    sys: &SyscallTable,
    chan: i32,
    len_out: *mut u32,
) -> *mut u8 {
    dev_buffer_acquire(
        sys,
        chan,
        abi::kernel_abi::channel::ACQUIRE_INPLACE,
        len_out,
    )
}

/// Acquire read access to the pending message
/// (`kernel_abi::channel::ACQUIRE_READ`). Returns the buffer, or null;
/// `len_out` receives the message length.
#[inline(always)]
pub unsafe fn dev_buffer_acquire_read(
    sys: &SyscallTable,
    chan: i32,
    len_out: *mut u32,
) -> *const u8 {
    dev_buffer_acquire(sys, chan, abi::kernel_abi::channel::ACQUIRE_READ, len_out) as *const u8
}

/// Release a read buffer (`kernel_abi::channel::RELEASE_READ`).
#[inline(always)]
pub unsafe fn dev_buffer_release_read(sys: &SyscallTable, chan: i32) -> i32 {
    (sys.provider_call)(
        chan,
        abi::registry::channel::RELEASE_READ,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    )
}

/// One provider call with no `data` span.
///
/// # Safety
/// `arg[..arg_len]` is this module's own memory, live for the call.
#[inline(always)]
pub unsafe fn dev_call(
    sys: &SyscallTable,
    handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    (sys.provider_call)(handle, op, arg, arg_len, core::ptr::null_mut(), 0)
}

/// One provider call with a `data` span: the op's bulk bytes (a body, a
/// page, a range), valid for this call only.
///
/// # Safety
/// `arg[..arg_len]` and `data[..data_len]` are this module's own disjoint
/// memory, live for the call.
#[inline(always)]
pub unsafe fn dev_call_data(
    sys: &SyscallTable,
    handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    (sys.provider_call)(handle, op, arg, arg_len, data, data_len)
}

/// A handle bound to the provider of `contract` registered under `name`: a
/// keyed volume, or `platform` for the platform's own provider beneath the
/// graph (`kernel::BIND`). Every op through it reaches that provider, and a
/// handle an op through it mints is bound to the same one. Negative errno:
/// `EINVAL` for a name past `bind::NAME_MAX`, `ENODEV` when nothing carries
/// it.
#[inline(always)]
pub unsafe fn dev_bind_name(sys: &SyscallTable, contract: u16, name: &[u8]) -> i32 {
    use abi::kernel_abi::bind;
    let mut arg = [0u8; bind::ARG_MAX];
    let Some(n) = bind::name(name, &mut arg) else {
        return -22;
    };
    (sys.provider_open)(u32::from(contract), bind::BIND, arg.as_ptr(), n)
}

/// A handle bound to the module at the other end of this module's port
/// `index` of `port_type` (`bind::PORT_IN` / `PORT_OUT` / `PORT_CTRL`), which
/// serves the edge contract `contract` there. `ENODEV` when the port is not
/// wired, `ENOSYS` when the module there does not serve `contract`.
#[inline(always)]
pub unsafe fn dev_bind_port(sys: &SyscallTable, contract: u16, port_type: u8, index: u8) -> i32 {
    use abi::kernel_abi::bind;
    let arg = bind::port(port_type, index);
    (sys.provider_open)(u32::from(contract), bind::BIND, arg.as_ptr(), arg.len())
}

/// Lend `span[..len]` to the provider serving `session` (a bound or minted
/// handle), named in that session's requests by `cookie`
/// (`lend::OPEN`). `dir` is `LEND_IN` (the provider reads it), `LEND_OUT`
/// (writes it) or `LEND_INOUT`. Returns the lend handle, closed with
/// [`dev_lend_close`]; the memory must stay this module's until then.
///
/// # Safety
/// `span[..len]` is this module's own memory and stays so, unmoved, until the
/// lend is closed and every borrow of it returned.
#[inline(always)]
pub unsafe fn dev_lend_open(
    sys: &SyscallTable,
    session: i32,
    dir: u8,
    cookie: u32,
    span: *mut u8,
    len: usize,
) -> i32 {
    let mut arg = [0u8; 8];
    arg[0] = dir;
    arg[4..8].copy_from_slice(&cookie.to_le_bytes());
    (sys.provider_call)(
        session,
        abi::registry::lend::OPEN,
        arg.as_mut_ptr(),
        8,
        span,
        len,
    )
}

/// Close a lend this module opened. A span still borrowed is released by the
/// borrower's last return.
#[inline(always)]
pub unsafe fn dev_lend_close(sys: &SyscallTable, lend: i32) -> i32 {
    (sys.provider_call)(
        lend,
        abi::registry::lend::CLOSE,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    )
}

/// The provider borrows: the span lent under `cookie` to its session
/// `inner` (the handle it was handed for that session), and its direction,
/// one more borrow out. `None` when no such lend is bound to this module.
/// Every borrow is given back with [`dev_lend_return`] before the request
/// that used it is reported complete.
#[inline(always)]
pub unsafe fn dev_lend_resolve(
    sys: &SyscallTable,
    inner: i32,
    cookie: u32,
) -> Option<(*mut u8, usize, u8)> {
    let mut arg = [0u8; 13];
    arg[0..4].copy_from_slice(&inner.to_le_bytes());
    arg[4..8].copy_from_slice(&cookie.to_le_bytes());
    let rc = (sys.provider_call)(
        -1,
        abi::registry::lend::RESOLVE,
        arg.as_mut_ptr(),
        13,
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return None;
    }
    let addr = u64::from_le_bytes([
        arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6], arg[7],
    ]);
    let len = u32::from_le_bytes([arg[8], arg[9], arg[10], arg[11]]) as usize;
    Some((addr as usize as *mut u8, len, arg[12]))
}

/// Give back one borrow of the span lent under `cookie` to session `inner`.
#[inline(always)]
pub unsafe fn dev_lend_return(sys: &SyscallTable, inner: i32, cookie: u32) -> i32 {
    let mut arg = [0u8; 8];
    arg[0..4].copy_from_slice(&inner.to_le_bytes());
    arg[4..8].copy_from_slice(&cookie.to_le_bytes());
    (sys.provider_call)(
        -1,
        abi::registry::lend::RETURN,
        arg.as_mut_ptr(),
        8,
        core::ptr::null_mut(),
        0,
    )
}

/// `dev_lend_open` directions: what the provider may do with the span.
pub const LEND_IN: u8 = 1;
pub const LEND_OUT: u8 = 2;
pub const LEND_INOUT: u8 = 3;

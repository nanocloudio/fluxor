// ============================================================================
// provider_call convenience wrappers
// ============================================================================
//
// Thin typed wrappers around common `provider_call(handle=-1, op, ...)`
// global operations — logging, timing, arena queries, channel ioctl,
// bridge I/O, flash sideband, paged-arena ops, runtime params.
// Everything routes through `SyscallTable::provider_call`.

/// Monotonic time in milliseconds (TIMER::MILLIS 0x0602).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_millis(sys: &SyscallTable) -> u64 {
    let mut buf = [0u8; 8];
    (sys.provider_call)(-1, 0x0602, buf.as_mut_ptr(), 8);
    u64::from_le_bytes(buf)
}

/// Monotonic time in microseconds (TIMER::MICROS 0x0603). Useful for
/// per-phase profiling at sub-millisecond granularity.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_micros(sys: &SyscallTable) -> u64 {
    let mut buf = [0u8; 8];
    (sys.provider_call)(-1, 0x0603, buf.as_mut_ptr(), 8);
    u64::from_le_bytes(buf)
}

/// A security-grade time observation (`TIMER::TRUSTED_UNIX` 0x0609).
///
/// Returns the raw record; `abi::kernel_abi::trusted_time` names its offsets
/// and the meaning of `source_class` / `flags`. Use this, not
/// `dev_unix_millis`, for anything that decides whether a credential is
/// still valid: a bare `u64` cannot say whether it is worth trusting, and on
/// a board with no RTC it is zero — which every current caller silently
/// treats as "1970", i.e. as an expiry that has not happened yet.
#[allow(
    dead_code,
    reason = "used by credential-validation consumers; not every module reads it"
)]
#[inline(always)]
unsafe fn dev_trusted_unix(sys: &SyscallTable) -> [u8; 36] {
    // 36, which is `trusted_time::LEN`. It was 34 — the sum of the fields
    // through `flags` — and the syscall refuses anything shorter than `LEN`,
    // so EVERY call returned `E_INVAL` and every consumer saw `UNAVAILABLE`.
    // The surface answered "no clock" on a machine with a synchronised one,
    // and did it silently, because `UNAVAILABLE` is exactly what a platform
    // with no RTC returns.
    let mut buf = [0u8; 36];
    let rc = (sys.provider_call)(-1, 0x0609, buf.as_mut_ptr(), buf.len());
    if rc < 0 {
        // A platform without the surface is UNAVAILABLE, which is the same
        // answer as a platform with no clock — and the same refusal.
        buf = [0u8; 36];
    }
    buf
}

/// Wall-clock milliseconds since the Unix epoch (TIMER::UNIX_MILLIS 0x0608), or 0 on a
/// platform with no real-time clock. Distinct from `dev_millis` (monotonic uptime); use for
/// absolute-time checks (certificate validity, JWT `exp`). See docs/surface-auth.md.
#[allow(
    dead_code,
    reason = "used by absolute-time consumers (surface auth); not every module reads it"
)]
#[inline(always)]
unsafe fn dev_unix_millis(sys: &SyscallTable) -> u64 {
    let mut buf = [0u8; 8];
    (sys.provider_call)(-1, 0x0608, buf.as_mut_ptr(), 8);
    u64::from_le_bytes(buf)
}

/// Per-step flow-budget grant for one of this module's output ports
/// (MODULE_FLOW_BUDGET 0x0C46). Returns 0 when the wired edge
/// carries no streaming rate class; callers keep their own
/// unit-per-step pacing in that case.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_flow_budget(sys: &SyscallTable, port_index: u8) -> u32 {
    let arg = [port_index];
    let r = (sys.provider_call)(-1, 0x0C46, arg.as_ptr() as *mut u8, 1);
    if r > 0 {
        r as u32
    } else {
        0
    }
}

/// Per-step consumption budget for one of this module's input ports. Uses the
/// same class and live domain period as [`dev_flow_budget`].
#[allow(dead_code, reason = "only bounded consumer pumps use input budgets")]
#[inline(always)]
unsafe fn dev_input_flow_budget(sys: &SyscallTable, input_chan: i32, input_port_index: u8) -> u32 {
    let channel = input_chan.to_le_bytes();
    let arg = [
        input_port_index,
        1,
        channel[0],
        channel[1],
        channel[2],
        channel[3],
    ];
    let r = (sys.provider_call)(-1, 0x0C46, arg.as_ptr() as *mut u8, arg.len());
    if r > 0 {
        r as u32
    } else {
        0
    }
}

/// Log a message (kernel primitive LOG_WRITE, opcode 0x0C40). Level encoded as handle.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_log(sys: &SyscallTable, level: u8, msg: *const u8, len: usize) {
    (sys.provider_call)(level as i32, 0x0C40, msg as *mut u8, len);
}

/// Poll any fd via provider_call (kernel primitive HANDLE_POLL, opcode 0x0C41).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_fd_poll(sys: &SyscallTable, fd: i32, events: u32) -> i32 {
    let mut buf = [events as u8];
    (sys.provider_call)(fd, 0x0C41, buf.as_mut_ptr(), 1)
}

/// Create an event via provider_call (EVENT::CREATE 0x0B00).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_event_create(sys: &SyscallTable) -> i32 {
    (sys.provider_call)(-1, 0x0B00, core::ptr::null_mut(), 0)
}

/// Poll an event via provider_call (EVENT::POLL 0x0B02). Returns 1 if signaled (clears it), 0 if not.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_event_poll(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.provider_call)(handle, 0x0B02, core::ptr::null_mut(), 0)
}

/// Bind an event to a hardware IRQ (kernel primitive BIND_IRQ, opcode 0x0C51).
/// `irq`: GIC interrupt number. `mmio_base`: virtio-mmio base for auto-ACK (0 = none).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
unsafe fn dev_irq_bind(sys: &SyscallTable, event_handle: i32, irq: u32, mmio_base: usize) -> i32 {
    let mut buf = [0u8; 12];
    let bp = buf.as_mut_ptr();
    let irq_bytes = irq.to_le_bytes();
    *bp = irq_bytes[0];
    *bp.add(1) = irq_bytes[1];
    *bp.add(2) = irq_bytes[2];
    *bp.add(3) = irq_bytes[3];
    let mb = (mmio_base as u64).to_le_bytes();
    let mut i = 0;
    while i < 8 {
        *bp.add(4 + i) = mb[i];
        i += 1;
    }
    (sys.provider_call)(event_handle, 0x0C51, bp, 12)
}

/// Query graph-level sample rate (kernel primitive GRAPH_SAMPLE_RATE, opcode 0x0C31).
/// Returns 0 if not configured.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_graph_sample_rate(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.provider_query)(-1, 0x0C31, buf.as_mut_ptr(), 4);
    if r >= 0 {
        u32::from_le_bytes(buf)
    } else {
        0
    }
}

/// Query system clock frequency (kernel primitive SYS_CLOCK_HZ, opcode 0x0C3B).
/// Returns 0 on error (should not happen in practice).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_sys_clock_hz(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.provider_query)(-1, 0x0C3B, buf.as_mut_ptr(), 4);
    if r >= 0 {
        u32::from_le_bytes(buf)
    } else {
        0
    }
}

/// Query stream time via `provider_query(-1, kernel_abi::STREAM_TIME)`.
/// Returns the first active PIO stream's (consumed_units, queued_units,
/// units_per_sec_q16, t0_micros), or zeros if no stream is active.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_stream_time(sys: &SyscallTable) -> (u64, u32, u32, u64) {
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

/// Query downstream latency (kernel primitive DOWNSTREAM_LATENCY, opcode 0x0C33).
/// Returns frames of latency downstream from the calling module, or 0.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_downstream_latency(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.provider_query)(-1, 0x0C33, buf.as_mut_ptr(), 4);
    if r >= 0 {
        u32::from_le_bytes(buf)
    } else {
        0
    }
}

/// Report module's processing latency (kernel primitive REPORT_LATENCY, opcode 0x0C50).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_report_latency(sys: &SyscallTable, frames: u32) {
    let mut buf = frames.to_le_bytes();
    (sys.provider_call)(-1, 0x0C50, buf.as_mut_ptr(), 4);
}

/// `StepEffect` codes for [`dev_report_step_effect`]. Mirrors
/// `kernel_abi::step_effect` and the kernel's `step_effect`.
#[allow(
    dead_code,
    reason = "module SDK surface; not every module reports every variant"
)]
mod step_effect {
    pub const IDLE: u8 = 0;
    pub const WAITING: u8 = 1;
    pub const WORK_DONE: u8 = 2;
    pub const RUNNABLE_BACKLOG: u8 = 3;
    pub const BURST: u8 = 4;
}

/// Report this module's `StepEffect` for the current pass (kernel primitive
/// `REPORT_STEP_EFFECT`, opcode 0x0C45). `WorkDone`/`RunnableBacklog`/`Burst`
/// keep the adaptive pacer hot without an immediate same-module re-step; the
/// re-step decision stays with the `StepOutcome::Burst` return value. A module
/// that never calls this is treated as `Idle`.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_report_step_effect(sys: &SyscallTable, effect: u8) {
    let mut buf = [effect];
    (sys.provider_call)(-1, 0x0C45, buf.as_mut_ptr(), 1);
}

/// Discover channel port via provider_call (CHANNEL::PORT 0x050C).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_channel_port(sys: &SyscallTable, port_type: u8, index: u8) -> i32 {
    let mut buf = [0u8; 2];
    // Volatile stores: PIC aarch64 otherwise dead-stores the buffer and
    // provider_call sees zeros on entry.
    core::ptr::write_volatile(buf.as_mut_ptr(), port_type);
    core::ptr::write_volatile(buf.as_mut_ptr().add(1), index);
    (sys.provider_call)(-1, 0x050C, buf.as_mut_ptr(), 2)
}

/// Channel ioctl via provider_call (CHANNEL::IOCTL 0x0506).
///
/// Wire format is `[cmd:u32 LE][arg:arg_len bytes]`. Built-in cmds
/// (`IOCTL_NOTIFY`, `IOCTL_POLL_NOTIFY` — `arg_len = 4`; `IOCTL_FLUSH`,
/// `IOCTL_EOF` — `arg_len = 0`) are handled in the kernel. Any other
/// Owner of the module that invoked the provider frame currently running,
/// as `(slot, generation)`, or `None` when nothing is on the provider stack.
///
/// A provider inside a dispatch uses this to attribute the request it is
/// serving: which owner's quota to charge, whose permissions apply. `None`
/// means this module is stepping its own work rather than serving anybody —
/// background reclamation, a heartbeat — and a provider MUST NOT fall back to
/// the last caller it saw there, which would charge its own housekeeping to
/// whoever happened to call it most recently.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_caller_owner(sys: &SyscallTable) -> Option<(u16, u32)> {
    let mut buf = [0u8; 8];
    let rc = (sys.provider_query)(
        -1,
        abi::kernel_abi::query_key::CALLER_OWNER,
        buf.as_mut_ptr(),
        buf.len(),
    );
    if rc < 8 {
        return None;
    }
    Some((
        u16::from_le_bytes([buf[0], buf[1]]),
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    ))
}

/// `cmd` is forwarded to a module-registered handler bound via
/// [`dev_channel_register_ioctl`]; that handler reads up to `arg_len`
/// bytes from `arg` and may write back into the same buffer.
///
/// On return the first `arg_len` bytes of `arg` carry the handler's
/// response. Pass `arg = null` and `arg_len = 0` for arg-less cmds.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_channel_ioctl(
    sys: &SyscallTable,
    handle: i32,
    cmd: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    const MAX_IOCTL_ARG: usize = 64;
    if arg_len > MAX_IOCTL_ARG {
        return -22;
    }
    let mut buf = [0u8; 4 + MAX_IOCTL_ARG];
    buf[..4].copy_from_slice(&cmd.to_le_bytes());
    if arg_len > 0 {
        if arg.is_null() {
            return -22;
        }
        core::ptr::copy_nonoverlapping(arg, buf.as_mut_ptr().add(4), arg_len);
    }
    let result = (sys.provider_call)(handle, 0x0506, buf.as_mut_ptr(), 4 + arg_len);
    if arg_len > 0 {
        core::ptr::copy_nonoverlapping(buf.as_ptr().add(4), arg, arg_len);
    }
    result
}

/// Bind a module-provided ioctl handler to `handle`. When any
/// [`dev_channel_ioctl`] cmd arrives that the kernel does not recognise,
/// the kernel calls `handler(state, cmd, arg)` with the opaque `state`
/// pointer captured here. Pass `handler = None` to clear.
///
/// Registration is one-shot per channel; the last call wins. The
/// `state` pointer is typically `&mut MyState as *mut c_void`.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_channel_register_ioctl(
    sys: &SyscallTable,
    handle: i32,
    state: *mut core::ffi::c_void,
    handler: Option<
        unsafe extern "C" fn(state: *mut core::ffi::c_void, cmd: u32, arg: *mut u8) -> i32,
    >,
) -> i32 {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&(state as u64).to_le_bytes());
    let hfn = match handler {
        Some(h) => h as usize as u64,
        None => 0u64,
    };
    buf[8..16].copy_from_slice(&hfn.to_le_bytes());
    (sys.provider_call)(handle, 0x0507, buf.as_mut_ptr(), 16)
}

/// Acquire write access to mailbox buffer via provider_call (BUFFER::ACQUIRE_WRITE 0x0A00).
/// Returns pointer (as *mut u8) or null. capacity_out receives buffer capacity.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_buffer_acquire_write(
    sys: &SyscallTable,
    chan: i32,
    capacity_out: *mut u32,
) -> *mut u8 {
    (sys.provider_call)(chan, 0x0A00, capacity_out as *mut u8, 4) as *mut u8
}

/// Release write buffer via provider_call (BUFFER::RELEASE_WRITE 0x0A01).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_buffer_release_write(sys: &SyscallTable, chan: i32, len: u32) -> i32 {
    let mut buf = len.to_le_bytes();
    (sys.provider_call)(chan, 0x0A01, buf.as_mut_ptr(), 4)
}

/// Acquire in-place buffer access via provider_call (BUFFER::ACQUIRE_INPLACE 0x0A04).
/// Returns pointer to existing data or null. len_out receives data length.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_buffer_acquire_inplace(sys: &SyscallTable, chan: i32, len_out: *mut u32) -> *mut u8 {
    (sys.provider_call)(chan, 0x0A04, len_out as *mut u8, 4) as *mut u8
}

/// Acquire read access to buffer via provider_call (BUFFER::ACQUIRE_READ 0x0A02).
/// Returns pointer to data or null. len_out receives data length.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_buffer_acquire_read(sys: &SyscallTable, chan: i32, len_out: *mut u32) -> *const u8 {
    (sys.provider_call)(chan, 0x0A02, len_out as *mut u8, 4) as *const u8
}

/// Release read buffer via provider_call (BUFFER::RELEASE_READ 0x0A03).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_buffer_release_read(sys: &SyscallTable, chan: i32) -> i32 {
    (sys.provider_call)(chan, 0x0A03, core::ptr::null_mut(), 0)
}

/// Call an instance-keyed provider selected by name (`sel`, a short volume
/// string). The contract is the opcode's class byte, so the `mount` policy
/// module names the target volume inline on every op. `op_handle` carries
/// the op's OWN handle (`-1` for open-style ops, or a provider-local slot);
/// `sel` is purely routing. Returns the provider's result, or negative
/// errno (`EINVAL` / `ENODEV` when no layer carries that selector).
#[allow(
    dead_code,
    reason = "consumed by the mount policy module; not every module routes by selector"
)]
#[inline(always)]
unsafe fn dev_provider_call_sel(
    sys: &SyscallTable,
    sel: &[u8],
    op_handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    (sys.provider_call_sel)(sel.as_ptr(), sel.len(), op_handle, op, arg, arg_len)
}


// ============================================================================
// Self-index + MON_SESSION telemetry
// ============================================================================

/// Query the calling module's own scheduler index.
/// See `kernel_abi::SELF_INDEX` (0x0C42). Returns 0..MAX_MODULES-1 on
/// success, negative errno on failure (e.g. called outside step). Used
/// by anchors / workers / directories to render the `mod=` field of
/// `MON_SESSION` telemetry lines.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_self_index(sys: &SyscallTable) -> i32 {
    (sys.provider_call)(-1, 0x0C42, core::ptr::null_mut(), 0)
}

/// Query the calling module's owner slot (`owner_tag`). See
/// `kernel_abi::OWNER_TAG` (0x0C4B). Returns the module's owner slot as a
/// `u16`: slot 0 (`OWNER_SYSTEM`) for a base-graph / host-owned module — the
/// legitimate host / wildcard tag — or the workload's owner slot (>= 1) for a
/// module `apply_add` staged for a `net=own` workload. A negative errno
/// (called outside step, unsupported) maps to 0 (host), so an unstamped/host
/// path binds host-wildcard. Used by a
/// bind-emitting module (http, a DG binder) to append the trailing `owner_tag`
/// on its `NET_CMD_BIND` / `DG_CMD_BIND`.
#[allow(
    dead_code,
    reason = "owner-scoped bind stamping; used only by net-facing binders (http, DG)"
)]
#[inline(always)]
unsafe fn dev_owner_tag(sys: &SyscallTable) -> u16 {
    let rc = (sys.provider_call)(-1, 0x0C4B, core::ptr::null_mut(), 0);
    if rc < 0 {
        0
    } else {
        (rc as u32).min(u16::MAX as u32) as u16
    }
}

/// Stream-surface requester tag for this module: `module index + 1`, so the
/// "untagged" sentinel `REQUESTER_TAG_NONE` (0) never collides with a valid
/// zero-based module index. Saturates at `u8::MAX`. Used to tag `CMD_CONNECT_TO`
/// and to recognise the matching `MSG_CONNECTED` when `ip.net_out` is fanned to
/// several stream consumers. Returns 0 only if the index is unavailable.
#[allow(
    dead_code,
    reason = "stream-surface routing; used by instrumented connectors"
)]
unsafe fn dev_requester_tag(sys: &SyscallTable) -> u8 {
    let idx = dev_self_index(sys);
    if idx < 0 {
        0
    } else {
        ((idx as u32).saturating_add(1)).min(u8::MAX as u32) as u8
    }
}

/// Producer-side enabled gate: a plain, trap-free single-word read of the
/// kernel-published flag. `true` when at least one telemetry consumer is
/// subscribed, so a record is built only when something would consume it. A
/// null pointer means "cannot check", not "disabled" — a table without the
/// word (the wasm host, an isolated module whose protection domain does not
/// map kernel memory) emits unconditionally and the ring drops when no
/// consumer is active.
#[allow(
    dead_code,
    reason = "emit-side helper; invoked only by instrumented modules"
)]
#[inline(always)]
unsafe fn dev_telemetry_enabled(sys: &SyscallTable) -> bool {
    sys.telemetry_enabled.is_null() || *sys.telemetry_enabled != 0
}

/// Emit a scalar metric (counter / up-down) to the kernel telemetry ring via
/// `TLM_EMIT`. Gated by [`dev_telemetry_enabled`] so it is zero-cost when nothing
/// is collecting. The kernel stamps the emitter's identity, so `module_idx` here
/// is advisory (overwritten). `t_micros` is a best-effort monotonic stamp (the
/// host collector applies receive time). `_chan` is accepted so instrumented
/// call sites keep one shape across signals; emission is ring-based and reaches
/// every consumer without a wired port.
#[allow(
    dead_code,
    reason = "emit-side helper; invoked only by instrumented modules"
)]
#[inline]
unsafe fn dev_telemetry_metric(
    sys: &SyscallTable,
    _chan: i32,
    module_idx: u16,
    t_micros: u64,
    kind: u8,
    id: u16,
    value: u64,
) {
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let mut buf = [0u8; abi::contracts::telemetry::METRIC_SCALAR_SIZE];
    if let Some(n) = abi::contracts::telemetry::write_metric_scalar(
        &mut buf, module_idx, t_micros, kind, id, value,
    ) {
        let _ = (sys.provider_call)(-1, abi::contracts::telemetry::TLM_EMIT, buf.as_mut_ptr(), n);
    }
}

/// Emit a scalar metric carrying a composite dimension index: the
/// row-major index over the instrument's declared dimension domains.
/// `DIM_OTHER` folds an out-of-domain tuple; the undimensioned path is
/// [`dev_telemetry_metric`]. Gated like every other emit helper.
#[allow(
    dead_code,
    reason = "emit-side helper; invoked only by instrumented modules"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "flat args keep the emit path allocation-free and one shape across signals"
)]
#[inline]
unsafe fn dev_telemetry_metric_dim(
    sys: &SyscallTable,
    _chan: i32,
    module_idx: u16,
    t_micros: u64,
    kind: u8,
    id: u16,
    dim: u16,
    value: u64,
) {
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let mut buf = [0u8; abi::contracts::telemetry::METRIC_SCALAR_SIZE];
    if let Some(n) = abi::contracts::telemetry::write_metric_scalar_dim(
        &mut buf, module_idx, t_micros, kind, id, dim, value,
    ) {
        let _ = (sys.provider_call)(-1, abi::contracts::telemetry::TLM_EMIT, buf.as_mut_ptr(), n);
    }
}

/// Emit a histogram metric (`HIST_BUCKETS` log2-spaced counts) to the kernel
/// telemetry ring. Gated by [`dev_telemetry_enabled`], like the scalar path.
#[allow(
    dead_code,
    reason = "emit-side helper; invoked only by instrumented modules"
)]
#[inline]
unsafe fn dev_telemetry_histogram(
    sys: &SyscallTable,
    _chan: i32,
    module_idx: u16,
    t_micros: u64,
    id: u16,
    buckets: &[u64; abi::contracts::telemetry::HIST_BUCKETS],
) {
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let mut buf = [0u8; abi::contracts::telemetry::METRIC_HIST_SIZE];
    if let Some(n) = abi::contracts::telemetry::write_metric_histogram(
        &mut buf, module_idx, t_micros, id, buckets,
    ) {
        let _ = (sys.provider_call)(-1, abi::contracts::telemetry::TLM_EMIT, buf.as_mut_ptr(), n);
    }
}

/// Emit a 16-bucket histogram (`METRIC_HISTOGRAM_16`): cumulative counts
/// against the instrument's 15 manifest-declared bounds plus `+Inf`, with a
/// composite dimension index (`DIM_NONE` when undimensioned). Bounds are
/// id-table metadata and never ride the record. Gated like the scalar path.
#[allow(
    dead_code,
    reason = "emit-side helper; invoked only by instrumented modules"
)]
#[inline]
unsafe fn dev_telemetry_histogram16(
    sys: &SyscallTable,
    _chan: i32,
    module_idx: u16,
    t_micros: u64,
    id: u16,
    dim: u16,
    buckets: &[u64; abi::contracts::telemetry::HIST16_BUCKETS],
) {
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let mut buf = [0u8; abi::contracts::telemetry::METRIC_HIST16_SIZE];
    if let Some(n) = abi::contracts::telemetry::write_metric_histogram16(
        &mut buf, module_idx, t_micros, id, dim, buckets,
    ) {
        let _ = (sys.provider_call)(-1, abi::contracts::telemetry::TLM_EMIT, buf.as_mut_ptr(), n);
    }
}

/// Emit a span to the kernel telemetry ring. Gated by [`dev_telemetry_enabled`],
/// so a graph nobody is collecting from costs nothing. `ctx` carries the W3C
/// trace context (trace/span/parent ids); `start_micros`/`end_micros` come from
/// [`dev_micros`]. The header stamp is the span end. See
/// `modules/sdk/contracts/telemetry.rs` and `standards/observability.md`.
#[allow(
    dead_code,
    reason = "emit-side helper; invoked only by instrumented modules"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "a span carries the full W3C context plus timing as flat args to stay allocation-free on the emit path"
)]
#[inline]
unsafe fn dev_telemetry_span(
    sys: &SyscallTable,
    _chan: i32,
    module_idx: u16,
    name_id: u16,
    span_kind: u8,
    status: u8,
    ctx: &abi::contracts::telemetry::SpanContext,
    start_micros: u64,
    end_micros: u64,
) {
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let mut buf = [0u8; abi::contracts::telemetry::SPAN_SIZE];
    if let Some(n) = abi::contracts::telemetry::write_span(
        &mut buf,
        module_idx,
        end_micros,
        name_id,
        span_kind,
        status,
        ctx,
        start_micros,
        end_micros,
    ) {
        let _ = (sys.provider_call)(-1, abi::contracts::telemetry::TLM_EMIT, buf.as_mut_ptr(), n);
    }
}

/// Render `bytes` as lowercase hex into `out`. Caller must ensure
/// `out.len() >= bytes.len() * 2`.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn hex_render(bytes: *const u8, n: usize, out: *mut u8) {
    let h = b"0123456789abcdef";
    let mut i = 0;
    while i < n {
        let b = *bytes.add(i);
        *out.add(i * 2) = h[(b >> 4) as usize];
        *out.add(i * 2 + 1) = h[(b & 0xF) as usize];
        i += 1;
    }
}

/// Render a `mod=<n>` decimal field. `n` is the module's own scheduler
/// index (from `dev_self_index`); we cap at three digits since the
/// scheduler's `MAX_MODULES` is well under 1000. Returns bytes written.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
unsafe fn fmt_u32_dec(mut n: u32, out: *mut u8) -> usize {
    if n == 0 {
        *out = b'0';
        return 1;
    }
    let mut buf = [0u8; 10];
    let mut len = 0usize;
    while n > 0 && len < buf.len() {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut i = 0;
    while i < len {
        *out.add(i) = buf[len - 1 - i];
        i += 1;
    }
    len
}

/// `MON_SESSION` line buffer size — fits the longest attach event with
/// all optional fields populated. See `docs/architecture/monitor-protocol.md`.
const MON_SESSION_BUF_SIZE: usize = 192;

/// `MON_SESSION` event tag codes for `dev_mon_session`. Strings live in
/// the helper to keep call sites short. Wire format remains the
/// human-readable name from `monitor-protocol.md`.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_ATTACH_REQ: u8 = 1;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_ATTACHED: u8 = 2;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_ATTACH_FAILED: u8 = 3;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_DRAINED: u8 = 4;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_EXPORTED: u8 = 5;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_IMPORTED: u8 = 6;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_RESUMED: u8 = 7;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_DETACH_REQ: u8 = 8;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_DETACHED: u8 = 9;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_RELOCATED: u8 = 10;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_REJECTED: u8 = 11;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_ERROR: u8 = 12;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_EPOCH_BUMP: u8 = 13;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_EXPORT_REQ: u8 = 14;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_RESUME_REQ: u8 = 15;
// Failover records for platform-replicated-state transport_migratable
// sessions (monitor-protocol.md §MON_SESSION Failover records).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_FENCE_INITIATED: u8 = 16;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_FENCE_CONFIRMED: u8 = 17;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_VIP_MOVED: u8 = 18;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_RESERVATION_GRANTED: u8 = 19;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_RESERVATION_EXHAUSTED_STALL: u8 = 20;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_RPO_LOSS: u8 = 21;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_UNSAFE_RECOVERY_EPOCH_VOID: u8 = 22;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const MON_EV_CLASS_REPORT: u8 = 23;

/// Map an event code to its on-the-wire string. Empty for unknown codes.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
fn mon_event_name(ev: u8) -> &'static [u8] {
    match ev {
        MON_EV_ATTACH_REQ => b"attach_req",
        MON_EV_ATTACHED => b"attached",
        MON_EV_ATTACH_FAILED => b"attach_failed",
        MON_EV_DRAINED => b"drained",
        MON_EV_EXPORTED => b"exported",
        MON_EV_IMPORTED => b"imported",
        MON_EV_RESUMED => b"resumed",
        MON_EV_DETACH_REQ => b"detach_req",
        MON_EV_DETACHED => b"detached",
        MON_EV_RELOCATED => b"relocated",
        MON_EV_REJECTED => b"rejected",
        MON_EV_ERROR => b"error",
        MON_EV_EPOCH_BUMP => b"epoch_bump",
        MON_EV_EXPORT_REQ => b"export_req",
        MON_EV_RESUME_REQ => b"resume_req",
        MON_EV_FENCE_INITIATED => b"fence_initiated",
        MON_EV_FENCE_CONFIRMED => b"fence_confirmed",
        MON_EV_VIP_MOVED => b"vip_moved",
        MON_EV_RESERVATION_GRANTED => b"reservation_granted",
        MON_EV_RESERVATION_EXHAUSTED_STALL => b"reservation_exhausted_stall",
        MON_EV_RPO_LOSS => b"rpo_loss",
        MON_EV_UNSAFE_RECOVERY_EPOCH_VOID => b"unsafe_recovery_epoch_void",
        MON_EV_CLASS_REPORT => b"class_report",
        _ => b"unknown",
    }
}

/// Map a `CC_*` continuity-class wire constant (see
/// `contracts/net/session_ctrl.rs`) to its `MON_SESSION` class name.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub fn mon_class_name(cc: u8) -> &'static [u8] {
    match cc {
        1 => b"reroutable",
        2 => b"drain_only",
        3 => b"resumable",
        4 => b"edge_anchored",
        5 => b"transport_migratable",
        _ => b"unknown",
    }
}

/// Emit a `MON_SESSION` line via `dev_log`. Fields: `mod=<idx>
/// event=<name> session=<32hex> epoch=<n>` plus any optional
/// `anchor=<16hex>` / `worker=<16hex>` (pass null pointers to omit).
/// `reason` is the named DETACH_* reason (or empty `b""` to omit);
/// `status` is the named STATUS_* code (or empty to omit). The line
/// is written via the kernel log path so it reaches every active
/// debug transport (UART, log_net, etc.).
///
/// Caller-allocated `scratch` buffer must be at least
/// `MON_SESSION_BUF_SIZE` bytes — typical state structs have a small
/// fixed buffer for this. Returns bytes written, or 0 if the buffer
/// was too small.
///
/// See `docs/architecture/monitor-protocol.md` §`MON_SESSION` for the
/// authoritative line-format spec.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "MON_SESSION line-format: signature mirrors the documented monitor-protocol fields"
)]
unsafe fn dev_mon_session(
    sys: &SyscallTable,
    self_idx: u8,
    event: u8,
    session_id: *const u8, // 16 BE bytes
    epoch: u32,
    anchor_id: *const u8, // 8 BE bytes, or null to omit
    worker_id: *const u8, // 8 BE bytes, or null to omit
    reason: &[u8],        // empty to omit
    status: &[u8],        // empty to omit
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    if scratch_max < MON_SESSION_BUF_SIZE {
        return 0;
    }
    let mut pos = 0usize;
    let emit = |bytes: &[u8], pos: &mut usize| {
        let mut i = 0;
        while i < bytes.len() && *pos < scratch_max {
            *scratch.add(*pos) = bytes[i];
            *pos += 1;
            i += 1;
        }
    };

    emit(b"MON_SESSION mod=", &mut pos);
    pos += fmt_u32_dec(self_idx as u32, scratch.add(pos));

    emit(b" event=", &mut pos);
    emit(mon_event_name(event), &mut pos);

    emit(b" session=", &mut pos);
    if pos + 32 <= scratch_max {
        hex_render(session_id, 16, scratch.add(pos));
        pos += 32;
    }

    emit(b" epoch=", &mut pos);
    pos += fmt_u32_dec(epoch, scratch.add(pos));

    if !anchor_id.is_null() {
        emit(b" anchor=", &mut pos);
        if pos + 16 <= scratch_max {
            hex_render(anchor_id, 8, scratch.add(pos));
            pos += 16;
        }
    }
    if !worker_id.is_null() {
        emit(b" worker=", &mut pos);
        if pos + 16 <= scratch_max {
            hex_render(worker_id, 8, scratch.add(pos));
            pos += 16;
        }
    }
    if !reason.is_empty() {
        emit(b" reason=", &mut pos);
        emit(reason, &mut pos);
    }
    if !status.is_empty() {
        emit(b" status=", &mut pos);
        emit(status, &mut pos);
    }

    // Severity 3 = info; same as other [echo_anc]/[echo_wkr] lines.
    dev_log(sys, 3, scratch, pos);
    pos
}

/// Emit a `MON_SESSION event=class_report` line: the per-session
/// `declared_class` vs `achieved_class` pair required for
/// platform-replicated-state `transport_migratable` sessions
/// (monitor-protocol.md §Failover records). A session running below
/// its declared class MUST surface the degradation through this line
/// so a silent fall-back (budget miss, missing fence, encrypted
/// implicit-counter AEAD) is visible in production, not inferred.
///
/// `declared_cc` / `achieved_cc` are `CC_*` wire constants from
/// `contracts/net/session_ctrl.rs`.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "MON_SESSION_CLASS line-format: signature mirrors the documented monitor-protocol fields"
)]
unsafe fn dev_mon_session_class(
    sys: &SyscallTable,
    self_idx: u8,
    session_id: *const u8, // 16 BE bytes
    epoch: u32,
    declared_cc: u8,
    achieved_cc: u8,
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    if scratch_max < MON_SESSION_BUF_SIZE {
        return 0;
    }
    let mut pos = 0usize;
    let emit = |bytes: &[u8], pos: &mut usize| {
        let mut i = 0;
        while i < bytes.len() && *pos < scratch_max {
            *scratch.add(*pos) = bytes[i];
            *pos += 1;
            i += 1;
        }
    };

    emit(b"MON_SESSION mod=", &mut pos);
    pos += fmt_u32_dec(self_idx as u32, scratch.add(pos));
    emit(b" event=class_report session=", &mut pos);
    if pos + 32 <= scratch_max {
        hex_render(session_id, 16, scratch.add(pos));
        pos += 32;
    }
    emit(b" epoch=", &mut pos);
    pos += fmt_u32_dec(epoch, scratch.add(pos));
    emit(b" declared_class=", &mut pos);
    emit(mon_class_name(declared_cc), &mut pos);
    emit(b" achieved_class=", &mut pos);
    emit(mon_class_name(achieved_cc), &mut pos);

    dev_log(sys, 3, scratch, pos);
    pos
}

// ============================================================================
// Per-module telemetry counters (`[<mod>] tlm …`)
// ============================================================================
//
// Modules on a hot path (storage, ip, http, fat32, …) embed `TlmCounters`
// in their state and bump `bytes_in` / `bytes_out` at every data-flow seam
// and `bp_steps` whenever a step was held up by a full downstream channel
// (back-pressure). `idle_steps` is derived at end-of-step using
// `tlm_idle_if_unchanged` — a step counts as idle only when no bytes
// moved AND it wasn't a back-pressure step. The two counters are
// therefore mutually exclusive, so every step lands in exactly one of
// {data-moved, idle, back-pressured} buckets and the three add up to
// `dt`. Every `period_steps` ticks `dev_tlm_maybe_emit` formats a
// single line and resets the deltas:
//
//     [<mod>] tlm dt=<step_delta> rx=<bytes> tx=<bytes> idle=<steps> bp=<steps>
//
// The host-side rig parser converts to bytes/sec by dividing by
// `dt * tick_us / 1_000_000`. Deltas (not cumulative totals) avoid u32
// wraparound at sustained gigabit rates and make rate computation a single
// subtraction-free divide.
//
// Worst-case line length: tag (≤16 chars) + `" tlm "` + 5 fields × `field=4294967295`
// + 4 separators ≈ 90 chars. Callers should pass a 128-byte scratch buffer.

/// One-line emit budget for a `[<mod>] tlm …` line. Caller-allocated
/// scratch must be at least this long.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub const TLM_LINE_BUF_SIZE: usize = 128;

/// Per-module hot-path counters. Modules embed this in state and bump
/// individual fields at data-flow points. `last_emit_step` tracks the
/// step count at which the previous line was emitted so the helper can
/// compute the delta. Initialise with `TlmCounters::new()`.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub struct TlmCounters {
    pub bytes_in: u32,
    pub bytes_out: u32,
    pub idle_steps: u32,
    pub bp_steps: u32,
    pub last_emit_step: u32,
}

#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
impl TlmCounters {
    pub const fn new() -> Self {
        Self {
            bytes_in: 0,
            bytes_out: 0,
            idle_steps: 0,
            bp_steps: 0,
            last_emit_step: 0,
        }
    }
}

#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
impl Default for TlmCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller-side end-of-step idle accounting. Bumps `idle_steps` iff
/// the step moved no bytes and didn't bump `bp_steps`. Pass the
/// `bytes_in / bytes_out / bp_steps` snapshots taken at the top of
/// `module_step`. Keeps idle and bp mutually exclusive — without
/// this, a step that polled a full downstream channel was
/// double-counted as both back-pressured and idle (idle_steps and
/// bp_steps each → period_steps for a steady-state stalled module).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
fn tlm_idle_if_unchanged(tlm: &mut TlmCounters, rx_pre: u32, tx_pre: u32, bp_pre: u32) {
    if tlm.bytes_in == rx_pre && tlm.bytes_out == tx_pre && tlm.bp_steps == bp_pre {
        tlm.idle_steps = tlm.idle_steps.wrapping_add(1);
    }
}

/// If at least `period_steps` ticks have elapsed since the last emit,
/// format and emit a `[<prefix>] tlm dt=… rx=… tx=… idle=… bp=…` line
/// and reset the deltas. Returns the number of bytes written, or 0 if
/// nothing was emitted (cadence not yet reached) or the scratch buffer
/// was too small.
///
/// `prefix` is the bracketed module tag without trailing space, e.g.
/// `b"[ip]"` or `b"[nvme]"`. `step_count` is the module's own per-step
/// monotonic counter (any module that already increments one for
/// existing periodic logs can reuse it). `scratch` must point to at
/// least `TLM_LINE_BUF_SIZE` writable bytes.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
unsafe fn dev_tlm_maybe_emit(
    sys: &SyscallTable,
    prefix: &[u8],
    tlm: &mut TlmCounters,
    step_count: u32,
    period_steps: u32,
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    if scratch_max < TLM_LINE_BUF_SIZE {
        return 0;
    }
    let dt = step_count.wrapping_sub(tlm.last_emit_step);
    if dt < period_steps {
        return 0;
    }

    let mut pos = 0usize;
    let emit = |bytes: &[u8], pos: &mut usize| {
        let mut i = 0;
        while i < bytes.len() && *pos < scratch_max {
            *scratch.add(*pos) = bytes[i];
            *pos += 1;
            i += 1;
        }
    };

    emit(prefix, &mut pos);
    emit(b" tlm dt=", &mut pos);
    pos += fmt_u32_dec(dt, scratch.add(pos));
    emit(b" rx=", &mut pos);
    pos += fmt_u32_dec(tlm.bytes_in, scratch.add(pos));
    emit(b" tx=", &mut pos);
    pos += fmt_u32_dec(tlm.bytes_out, scratch.add(pos));
    emit(b" idle=", &mut pos);
    pos += fmt_u32_dec(tlm.idle_steps, scratch.add(pos));
    emit(b" bp=", &mut pos);
    pos += fmt_u32_dec(tlm.bp_steps, scratch.add(pos));

    dev_log(sys, 3, scratch, pos);

    tlm.bytes_in = 0;
    tlm.bytes_out = 0;
    tlm.idle_steps = 0;
    tlm.bp_steps = 0;
    tlm.last_emit_step = step_count;
    pos
}

/// Register a backing-store arena for the calling module. Returns
/// arena_id (>=0) or negative errno. `backing_type`: 0=None,
/// 1=RamDisk, 2=External. `writeback`: 0=Deferred, 1=WriteThrough.
/// When backing_type=External, a driver module (NVMe, SD, …) must be
/// loaded and have registered its `backing_provider_dispatch` via
/// `BACKING_PROVIDER_ENABLE` — otherwise later read/write calls
/// return ENODEV.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_backing_arena_register(
    sys: &SyscallTable,
    virtual_pages: u32,
    resident_max: u32,
    backing_type: u8,
    writeback: u8,
) -> i32 {
    let mut buf = [0u8; 10];
    let bp = buf.as_mut_ptr();
    let vp = virtual_pages.to_le_bytes();
    *bp = vp[0];
    *bp.add(1) = vp[1];
    *bp.add(2) = vp[2];
    *bp.add(3) = vp[3];
    let rm = resident_max.to_le_bytes();
    *bp.add(4) = rm[0];
    *bp.add(5) = rm[1];
    *bp.add(6) = rm[2];
    *bp.add(7) = rm[3];
    *bp.add(8) = backing_type;
    *bp.add(9) = writeback;
    (sys.provider_call)(-1, 0x0CEE, bp, 10)
}

/// Write one 4 KB page from `buf` to a registered backing arena.
/// `buf` must point to at least 4096 bytes of readable memory.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_backing_arena_write(
    sys: &SyscallTable,
    arena_id: u8,
    vpage_idx: u32,
    buf: *const u8,
) -> i32 {
    let mut a = [0u8; 14];
    let bp = a.as_mut_ptr();
    *bp = arena_id;
    *bp.add(1) = 0;
    let vp = vpage_idx.to_le_bytes();
    *bp.add(2) = vp[0];
    *bp.add(3) = vp[1];
    *bp.add(4) = vp[2];
    *bp.add(5) = vp[3];
    let pb = (buf as u64).to_le_bytes();
    *bp.add(6) = pb[0];
    *bp.add(7) = pb[1];
    *bp.add(8) = pb[2];
    *bp.add(9) = pb[3];
    *bp.add(10) = pb[4];
    *bp.add(11) = pb[5];
    *bp.add(12) = pb[6];
    *bp.add(13) = pb[7];
    (sys.provider_call)(-1, 0x0CFE, bp, 14)
}

/// Read one 4 KB page from a registered backing arena into `buf`.
/// `buf` must point to at least 4096 bytes of writable memory.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_backing_arena_read(
    sys: &SyscallTable,
    arena_id: u8,
    vpage_idx: u32,
    buf: *mut u8,
) -> i32 {
    let mut a = [0u8; 14];
    let bp = a.as_mut_ptr();
    *bp = arena_id;
    *bp.add(1) = 0;
    let vp = vpage_idx.to_le_bytes();
    *bp.add(2) = vp[0];
    *bp.add(3) = vp[1];
    *bp.add(4) = vp[2];
    *bp.add(5) = vp[3];
    let pb = (buf as u64).to_le_bytes();
    *bp.add(6) = pb[0];
    *bp.add(7) = pb[1];
    *bp.add(8) = pb[2];
    *bp.add(9) = pb[3];
    *bp.add(10) = pb[4];
    *bp.add(11) = pb[5];
    *bp.add(12) = pb[6];
    *bp.add(13) = pb[7];
    (sys.provider_call)(-1, 0x0CEF, bp, 14)
}

/// Flush any pending writes for a backing arena.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_backing_arena_flush(sys: &SyscallTable, arena_id: u8) -> i32 {
    let mut a = [arena_id];
    (sys.provider_call)(-1, 0x0CFF, a.as_mut_ptr(), 1)
}

/// Write `count` contiguous 4 KB pages from `buf` to a registered
/// backing arena. `buf` must point to `count * 4096` readable bytes.
/// Drivers that support multi-block transfers (NVMe with PRP-lists)
/// translate this to a single device command — far higher sustained
/// throughput than per-page writes.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_backing_arena_write_pages(
    sys: &SyscallTable,
    arena_id: u8,
    vpage_start: u32,
    count: u32,
    buf: *const u8,
) -> i32 {
    dev_backing_arena_bulk(sys, arena_id, 0, vpage_start, count, buf as u64)
}

/// Read `count` contiguous 4 KB pages from a registered backing arena
/// into `buf`. `buf` must point to `count * 4096` writable bytes.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_backing_arena_read_pages(
    sys: &SyscallTable,
    arena_id: u8,
    vpage_start: u32,
    count: u32,
    buf: *mut u8,
) -> i32 {
    dev_backing_arena_bulk(sys, arena_id, 1, vpage_start, count, buf as u64)
}

/// Internal helper — both bulk read and bulk write share one syscall
/// (ARENA_BULK = 0x0CE9) with `op` in arg byte 1 (0=WRITE, 1=READ).
#[inline(always)]
unsafe fn dev_backing_arena_bulk(
    sys: &SyscallTable,
    arena_id: u8,
    op: u8,
    vpage_start: u32,
    count: u32,
    buf_u64: u64,
) -> i32 {
    let mut a = [0u8; 18];
    let bp = a.as_mut_ptr();
    *bp = arena_id;
    *bp.add(1) = op;
    let vp = vpage_start.to_le_bytes();
    *bp.add(2) = vp[0];
    *bp.add(3) = vp[1];
    *bp.add(4) = vp[2];
    *bp.add(5) = vp[3];
    let c = count.to_le_bytes();
    *bp.add(6) = c[0];
    *bp.add(7) = c[1];
    *bp.add(8) = c[2];
    *bp.add(9) = c[3];
    let pb = buf_u64.to_le_bytes();
    *bp.add(10) = pb[0];
    *bp.add(11) = pb[1];
    *bp.add(12) = pb[2];
    *bp.add(13) = pb[3];
    *bp.add(14) = pb[4];
    *bp.add(15) = pb[5];
    *bp.add(16) = pb[6];
    *bp.add(17) = pb[7];
    (sys.provider_call)(-1, 0x0CE9, bp, 18)
}

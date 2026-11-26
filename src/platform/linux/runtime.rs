// ============================================================================
// Monotonic clock (CLOCK_MONOTONIC via std::time)
// ============================================================================

static mut BOOT_INSTANT: Option<Instant> = None;

fn elapsed_micros() -> u64 {
    // SAFETY: `BOOT_INSTANT` is set once at boot by the bin's main()
    // before any timer reader is alive; this reads through `&raw const`
    // to avoid materialising a long-lived reference.
    unsafe {
        let ptr = &raw const BOOT_INSTANT;
        match &*ptr {
            Some(t) => t.elapsed().as_micros() as u64,
            None => 0,
        }
    }
}

// ============================================================================
// HAL implementation
// ============================================================================

fn linux_disable_interrupts() -> u32 {
    0
}
fn linux_restore_interrupts(_state: u32) {}

/// Domain-loop thread handle, captured before the first pass.
/// `linux_wake_scheduler` clones and unparks it so an event signaled
/// from any thread (or from an ISR-equivalent callback) can interrupt
/// the runtime's `park_timeout` and run woken modules — the host analogue
/// of RP's `WakeLatch` + `SEV` breaking it out of `WFE`.
static LINUX_MAIN_THREAD: OnceLock<thread::Thread> = OnceLock::new();

/// Capture the current thread as the wake target. Call once, before
/// the scheduler loop starts.
fn linux_install_wake_thread() {
    let _ = LINUX_MAIN_THREAD.set(thread::current());
}

fn linux_wake_scheduler() {
    // Best-effort: if the runtime thread has been captured, unpark it.
    // Spurious unparks are fine — the domain loop drains wake bits each
    // iteration. Before capture (early boot) wake is a no-op; the bit
    // still latches in EVENT_WAKE_PENDING and the first scheduler tick
    // observes it.
    if let Some(t) = LINUX_MAIN_THREAD.get() {
        t.unpark();
    }
}

fn linux_now_millis() -> u64 {
    elapsed_micros() / 1000
}

fn linux_now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
/// What the kernel knows about the wall clock. Lives in the library
/// (`platform::linux::clock`) so the host harness can hold it against a
/// raw `adjtimex(2)` reading.
fn linux_clock_sync_status() -> Option<(bool, u64)> {
    fluxor::platform::linux::clock::sync_status()
}

/// Where the Linux sealing key comes from.
///
/// `HostReadable`, and that is the honest answer rather than a placeholder.
/// The key is `FLUXOR_SEAL_KEY`, readable by anything running as this user.
/// Sealing under it protects a stored key from a compromised MODULE and not
/// from a compromised HOST, and the vault's custody stays `SOFTWARE`
/// because of it.
///
/// A Linux box with a TPM could report `DeviceUnique` by sealing to the
/// storage root key. That is a real path and deliberately not taken here on
/// the quiet: claiming it requires actually talking to the TPM, and a
/// provenance that overstates itself is worse than no sealing at all — it
/// raises a vault's custody and, with it, what a deployment believes about
/// keys it has not actually protected.
fn linux_seal_provenance() -> fluxor::kernel::sys::hal::SealProvenance {
    if linux_seal_key().is_some() {
        fluxor::kernel::sys::hal::SealProvenance::HostReadable
    } else {
        fluxor::kernel::sys::hal::SealProvenance::None
    }
}

/// The sealing key, or `None` when this deployment configured none.
///
/// From `FLUXOR_SEAL_KEY` (64 hex characters). Absent rather than
/// defaulted: a built-in constant would make every fluxor install share one
/// sealing key, which is indistinguishable from not sealing while looking
/// like it seals.
fn linux_seal_key() -> Option<[u8; 32]> {
    let hex = std::env::var("FLUXOR_SEAL_KEY").ok()?;
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        key[i] = ((hi << 4) | lo) as u8;
    }
    Some(key)
}

fn linux_now_micros() -> u64 {
    elapsed_micros()
}
fn linux_tick_count() -> u32 {
    // Wall-clock milliseconds: a domain's pass count is not a clock under
    // adaptive pacing.
    (elapsed_micros() / 1000) as u32
}

/// Portable `sleep_until`. Parks the calling (scheduler) thread until
/// `deadline_us` or until `linux_wake_scheduler` unparks it — the same
/// primitive the native Linux loop uses. A spurious unpark just returns early;
/// the caller re-checks its work state.
fn linux_sleep_until(deadline_us: u64) -> u32 {
    let now = elapsed_micros();
    if deadline_us <= now {
        return fluxor::kernel::sys::hal::WOKEN_DEADLINE;
    }
    let remaining = deadline_us - now;
    std::thread::park_timeout(std::time::Duration::from_micros(remaining));
    // Distinguish deadline vs early wake by re-reading the clock.
    if elapsed_micros() >= deadline_us {
        fluxor::kernel::sys::hal::WOKEN_DEADLINE
    } else {
        fluxor::kernel::sys::hal::WOKEN_EVENT
    }
}

fn linux_flash_base() -> usize {
    0
}
fn linux_flash_end() -> usize {
    0
}
fn linux_apply_code_bit(addr: usize) -> usize {
    addr
}
fn linux_validate_fn_addr(addr: usize) -> bool {
    // Non-null + 4-byte aligned. Checking the address against the
    // mmap region would need the platform main to publish that base and
    // length to a static; alignment alone is the cheap catch, and it
    // catches the ABI corruption that matters — a garbage pointer.
    addr != 0 && (addr & 0x3) == 0
}
fn linux_validate_module_base(addr: usize) -> bool {
    // Module headers are 4-byte aligned in `.fmod` images.
    addr != 0 && (addr & 0x3) == 0
}
fn linux_validate_fn_in_code(addr: usize, base: usize, size: u32) -> bool {
    // A function pointer claimed by a module manifest must fall inside
    // the module's `[code_base, code_base + code_size)`. The
    // export-offset bounds check in `get_export_addr` already rejects
    // manifests that claim out-of-range offsets; this is the
    // platform-side belt-and-braces check.
    if base == 0 || size == 0 {
        return false;
    }
    let end = base.saturating_add(size as usize);
    addr >= base && addr < end
}
/// Linux platform integrity hook — byte-compare the computed digest
/// against the manifest-stored value, matching the RP and BCM hooks.
/// The cost is one O(n) slice compare per module load.
fn linux_verify_integrity(computed: &[u8], expected: &[u8]) -> bool {
    computed == expected
}

/// Staged-code page-permission flip, for the OTA staging buffers and the
/// workload code pool: RW while bytes land, RX once committed (W^X — a
/// staged region is only ever writable OR executable). `region` must start
/// a host page, and the caller owns its buffer out to the end of the last
/// page `region` reaches: the range is rounded up, never down, so no change
/// reaches a neighbour before it. A region that does not start a page is
/// refused rather than rounded onto a neighbour.
fn linux_ota_stage_protect(region: &mut [u8], executable: bool) -> bool {
    // SAFETY: sysconf on a valid selector.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return false;
    }
    let page = page as usize;
    let start = region.as_mut_ptr() as usize;
    if !start.is_multiple_of(page) {
        log::error!(
            "[ota] stage protect: base {start:#x} is not aligned to the host's {page}-byte page"
        );
        return false;
    }
    let end = (start + region.len() + page - 1) & !(page - 1);
    let prot = if executable {
        libc::PROT_READ | libc::PROT_EXEC
    } else {
        libc::PROT_READ | libc::PROT_WRITE
    };
    // SAFETY: whole-page range over the static staging buffer; mprotect
    // on BSS pages is well-defined.
    unsafe { libc::mprotect(start as *mut libc::c_void, end - start, prot) == 0 }
}
fn linux_pic_barrier() {}

fn linux_step_guard_init() {}
fn linux_step_guard_arm(_deadline_us: u32) {}
fn linux_step_guard_disarm() {}
fn linux_step_guard_post_check() {}

fn linux_read_cycle_count() -> u32 {
    elapsed_micros() as u32
}

fn linux_module_timer_init() {}
fn linux_module_timer_start(_period_us: u32) {}
fn linux_module_timer_stop() {}
fn linux_module_timer_poll() {}

/// The handles this platform's provider tables can hand modules at once.
fn linux_handle_slots() -> usize {
    fluxor::platform::linux::providers::handle_slots()
}

fn linux_init_providers() {
    // `FLUXOR_STATE_DIR` first: this instance's own state directory, locked
    // for the runtime's life. One another live runtime holds stops the
    // runtime here, before it touches anything host-global. (The instance
    // tag and the host registry are the network provider's.)
    if let Err(e) = fluxor::platform::linux::state_dir::lock_from_env() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    // The host filesystem, for the node alone: a workload reaches node
    // storage through the node graph's workload `fs` layer (`owner_fs`), which
    // roots it and reaches this provider in its own frame. The dispatcher
    // also answers `contracts::fence::QUERY_OP`, surfacing the per-handle
    // fence through `provider_query(handle, query_key::LAST_FENCE, …)`.
    use fluxor::kernel::module::provider;
    use fluxor::kernel::module::provider::contract as dev_class;
    provider::register_node_only(dev_class::FS, linux_fs_dispatch);
    provider::register_platform_handle_slots(linux_handle_slots);
    provider::register(dev_class::STREAM_CLOCK, linux_stream_time_dispatch);
    // The platform's verdict on a certificate chain. Registered only where
    // the verifier is built in; without it nothing answers class `trust` and a
    // graph naming `trust = "system"` is refused at compose rather than
    // quietly composing against some other trust source.
    #[cfg(feature = "trust-system")]
    provider::register(dev_class::TRUST, trust_provider::dispatch);
    // Platform-neutral isolated-workload surface: parses the spec header, binds
    // to a plan-allocated owner + lease, enforces the options envelope
    // fail-closed, and delegates to the owner-bound host-process backend.
    // Host-linux; gated by the `workload.create` and `host_process.exec` grants.
    provider::register(dev_class::WORKLOAD, linux_workload_dispatch);
    // What an owner holds of the host (network endpoints, host processes,
    // terminals) goes with the owner: the workload provider hears every
    // release.
    provider::observe_owner_release(dev_class::WORKLOAD);
    provider::register(
        dev_class::HOST_PROCESS,
        fluxor::platform::linux::workload::host_process_dispatch,
    );
    // Host mounts of block devices under the operator's mount root. Gated by
    // the `host_mount.mount` grant.
    provider::register(
        dev_class::HOST_MOUNT,
        fluxor::platform::linux::host_mount::host_mount_dispatch,
    );
}
/// Platform-specific per-module cleanup for Linux host.
///
/// **Intentional no-op.** The Linux runtime relies on:
///   * The kernel-generic `syscalls::release_module_handles` which
///     already releases events, fd-based timers, and module-registered
///     provider handles (all of which record `owner_module`).
///   * Process-exit cleanup for `mmap`'d module images — the kernel
///     holds module code for the lifetime of the process.
///   * `provider::reset_handle_tracking` from `prepare_graph` on
///     each reconfigure, which strips any provider handles a
///     finalised module might have leaked.
///
/// Per-module unload of mmap'd memory before process exit would
/// require the runtime to track each `.fmod` → mmap mapping by
/// module index; v1 leaves the process model as the outer cleanup
/// boundary.
fn linux_release_module_handles(_module_idx: fluxor::kernel::exec::scheduler::ModuleId) {
    // Generic kernel cleanup in `syscalls::release_module_handles`
    // covers event/timer/provider resources; Linux mmap mappings
    // live for the process.
}
fn linux_boot_scan() {
    param_store::boot_scan();
}

/// The params a module is handed: compiled params in place unless the
/// parameter store holds an override for it (`param_store::runtime_params`).
fn linux_runtime_params(
    module_id: u16,
    compiled: &[u8],
) -> fluxor::kernel::sys::hal::RuntimeParams {
    use fluxor::kernel::sys::hal::RuntimeParams;
    match param_store::merged_params(module_id, compiled) {
        None => RuntimeParams::Compiled,
        Some((ptr, len)) => RuntimeParams::Merged(ptr, len),
    }
}

static LINUX_HAL_OPS: HalOps = HalOps {
    disable_interrupts: linux_disable_interrupts,
    restore_interrupts: linux_restore_interrupts,
    wake_scheduler: linux_wake_scheduler,
    now_millis: linux_now_millis,
    now_unix_millis: linux_now_unix_millis,
    clock_sync_status: linux_clock_sync_status,
    seal_provenance: linux_seal_provenance,
    seal_key: linux_seal_key,
    signing_root: fluxor::kernel::security::root::image_root,
    now_micros: linux_now_micros,
    tick_count: linux_tick_count,
    flash_base: linux_flash_base,
    flash_end: linux_flash_end,
    apply_code_bit: linux_apply_code_bit,
    validate_fn_addr: linux_validate_fn_addr,
    validate_module_base: linux_validate_module_base,
    validate_fn_in_code: linux_validate_fn_in_code,
    verify_integrity: linux_verify_integrity,
    ota_stage_protect: linux_ota_stage_protect,
    pic_barrier: linux_pic_barrier,
    step_guard_init: linux_step_guard_init,
    step_guard_arm: linux_step_guard_arm,
    step_guard_disarm: linux_step_guard_disarm,
    step_guard_post_check: linux_step_guard_post_check,
    read_cycle_count: linux_read_cycle_count,
    module_timer_init: linux_module_timer_init,
    module_timer_start: linux_module_timer_start,
    module_timer_stop: linux_module_timer_stop,
    module_timer_poll: linux_module_timer_poll,
    init_providers: linux_init_providers,
    release_module_handles: linux_release_module_handles,
    boot_scan: linux_boot_scan,
    runtime_params: linux_runtime_params,
    init_gpio: |_| 0,
    csprng_fill: linux_csprng_fill,
    core_id: || 0,
    irq_bind: |_, _, _, _| fluxor::kernel::sys::errno::ENOSYS,
    irq_unbind: |_| 0,
    irq_mask: |_, _| {},
    sleep_until: linux_sleep_until,
    smp_quiesce_peers: || false,
    smp_release_peers: || {},
    smp_max_domains: || 1,
    protection_set_enabled: |_| {},
    protection_reset: || {},
    protection_register_module: |_, _, _, _, _, _, _| false,
    protection_release_module: |_| {},
    protection_gateway_table: fluxor::kernel::sys::hal::no_gateway_table,
    protected_call: fluxor::kernel::sys::hal::protected_call_unavailable,
    // Modules step on a host thread's stack, which the OS guards.
    stack_fence_arm: |_| {},
    stack_fence_intact: || true,
    // Host serial sink = stderr (fd 2), unbuffered so framed telemetry bytes
    // land verbatim for a capture tool. Binary-safe (no UTF-8 filtering).
    serial_write: |b| unsafe {
        let n = libc::write(2, b.as_ptr() as *const libc::c_void, b.len());
        if n < 0 {
            0
        } else {
            n as usize
        }
    },
    metal_device: None,
};

fn linux_csprng_fill(buf: &mut [u8]) -> i32 {
    // `libc::SYS_getrandom` is the canonical per-arch syscall selector
    // and `libc::syscall` handles the platform-specific calling
    // convention, so this compiles correctly (or fails loudly) on any
    // architecture libc supports — no hand-rolled `svc`/asm or
    // hardcoded syscall numbers.
    let len = buf.len();
    // SAFETY: `libc::syscall` invoked with the per-arch SYS_getrandom
    // selector and `(buf, len, flags=0)` matches `getrandom(2)`; `buf` is
    // a live exclusive slice, writable for its whole length.
    let ret = unsafe { libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr() as *mut libc::c_void, len, 0u32) };
    if ret < 0 || ret as usize != len {
        return -1;
    }
    0
}

// ============================================================================

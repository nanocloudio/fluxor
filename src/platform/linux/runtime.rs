// Linker symbol stub
// ============================================================================

// The config module references __end_block_addr (a linker symbol for flash
// layout trailers). On Linux we don't use flash layout — we load config from
// files directly. Provide a dummy symbol so the code links.
#[no_mangle]
#[used]
static __end_block_addr: u8 = 0;

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

/// Main-loop thread handle, captured before stepping starts.
/// `linux_wake_scheduler` clones and unparks it so an event signaled
/// from any thread (or from an ISR-equivalent callback) can interrupt
/// the runtime's `park_timeout` and run woken modules in the same way
/// RP breaks out of `embassy_futures::select` on a SIGNAL fire.
static LINUX_MAIN_THREAD: OnceLock<thread::Thread> = OnceLock::new();

/// Capture the current thread as the wake target. Call once, before
/// the scheduler loop starts.
fn linux_install_wake_thread() {
    let _ = LINUX_MAIN_THREAD.set(thread::current());
}

fn linux_wake_scheduler() {
    // Best-effort: if the runtime thread has been captured, unpark it.
    // Spurious unparks are fine — the main loop drains wake bits each
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
fn linux_now_micros() -> u64 {
    elapsed_micros()
}
fn linux_tick_count() -> u32 {
    // RFC adaptive_tick §7.6 (D8 rule 8): back the HAL `tick_count`
    // with wall-clock milliseconds instead of `DBG_TICK`. The identity
    // "1 tick == 1 ms" holds only at the fixed 1 ms default; mechanism (b)
    // varies the period and mechanism (a) stops advancing `DBG_TICK` during
    // idle, so a `DBG_TICK`-backed `tick_count` returns wrong "ms since boot"
    // under adaptive tick. Wall-clock `elapsed_micros()/1000` is correct under
    // any pacing — matching rp's `Instant`-based `rp_tick_count` (rp.rs:449).
    // The internal logical tick counter (`scheduler::tick_count()` → DBG_TICK)
    // is unchanged; only this outward HAL op is decoupled.
    (elapsed_micros() / 1000) as u32
}

/// Portable `sleep_until` (RFC adaptive_tick §5.5 Option B). Parks the calling
/// (scheduler) thread until `deadline_us` or until `linux_wake_scheduler`
/// unparks it — the same primitive the native Linux loop uses. A spurious
/// unpark just returns early; the caller re-checks its work state.
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
    // Non-null + 4-byte aligned. mmap-region bounds tracking would
    // require the platform main to publish the mmap base+len to a
    // static; for now alignment is a cheap catch for ABI corruption.
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

/// OTA staging page-permission flip: RW while staging bytes land, RX
/// once committed (W^X — the staged region is only ever writable OR
/// executable). The staging buffer is 16 KiB-aligned static BSS —
/// covering the host kernel's actual page size (Raspberry Pi OS
/// aarch64 runs 16 KiB pages), which is also what the range is
/// rounded to here; a 4 KiB assumption made `mprotect` fail EINVAL on
/// such kernels.
fn linux_ota_stage_protect(base: *mut u8, len: usize, executable: bool) -> bool {
    // SAFETY: sysconf on a valid selector; falls back defensively.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = if page > 0 { page as usize } else { 16384 };
    let start = (base as usize) & !(page - 1);
    let end = (base as usize + len + page - 1) & !(page - 1);
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

fn linux_isr_tier_init() {}
fn linux_isr_tier_start(_period_us: u32) {}
fn linux_isr_tier_stop() {}
fn linux_isr_tier_poll() {}

fn linux_init_providers() {
    // Override the default stub FS provider with one backed by real
    // libc I/O. The dispatcher also answers
    // `contracts::fence::QUERY_OP`, surfacing the per-handle fence
    // through `provider_query(handle, query_key::LAST_FENCE, …)`.
    use fluxor::kernel::module::provider;
    use fluxor::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::FS, linux_fs_dispatch);
    provider::register(dev_class::STREAM_CLOCK, linux_stream_time_dispatch);
    // storage.object over HTTP `Range:` — wasm peer in
    // `src/platform/wasm/object.rs`; shared windowing in
    // `abi::contracts::storage::object::range`.
    provider::register(dev_class::STORAGE_OBJECT, linux_object_dispatch);
    // storage.namespace over the real filesystem (std::fs read_dir/metadata)
    // — the directory-enumeration sibling of the FS provider; wasm peer in
    // `src/platform/wasm/namespace.rs`. Lets a scanner walk a host library on
    // Linux exactly as it walks the manifest-backed index in the browser.
    provider::register(dev_class::STORAGE_NAMESPACE, linux_namespace_dispatch);
    // Control-plane store: if FLUXOR_STORE_DIR is set, the two storage providers
    // above route to an in-runtime versioned watchable store instead of
    // HTTP/filesystem. A no-op when the env is unset.
    // SAFETY: single-threaded startup, before any provider dispatch — the
    // store singleton is initialised exactly once with no concurrent access.
    let _ = unsafe { fluxor::platform::linux::store::store_init_from_env() };
    // The impure boundary: host process executor (sector `do`). Gated by
    // `requires_contract="proc"`; only registered on host-linux (a PIC module
    // can't fork/exec, so a "worker" is by definition a Linux node).
    provider::register(
        fluxor::abi::platform::linux::host_process::PROC_CLASS,
        linux_proc_dispatch,
    );
    provider::register_fd_tag_route(
        fluxor::abi::platform::linux::host_process::FD_TAG_PROC,
        fluxor::abi::platform::linux::host_process::PROC_CLASS,
    );
    // Platform-neutral isolated-workload surface: parses the Tier-1 spec, binds
    // to a plan-allocated owner + lease, enforces the Tier-2 options envelope
    // fail-closed, and delegates to the owner-bound host-process backend.
    // Host-linux; gated by requires_contract = "workload" + platform_raw.
    provider::register(dev_class::WORKLOAD, linux_workload_dispatch);
    provider::register(
        dev_class::HOST_PROCESS,
        fluxor::platform::linux::workload::host_process_dispatch,
    );
    // KEY_VAULT hardware override (rfc_crypto_extensions §4.1/§4.3):
    // when a PKCS#11 token is configured, re-register both KEY_VAULT
    // dispatch paths over the kernel software default. Runs after the
    // kernel-core registrations, so the override wins; unconfigured or
    // failed, the software backend stays live and reports TIER=SOFTWARE.
    #[cfg(feature = "host-hsm")]
    fluxor::platform::linux::hsm_key_vault::try_register_from_env();
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
fn linux_release_module_handles(_module_idx: u8) {
    // Generic kernel cleanup in `syscalls::release_module_handles`
    // covers event/timer/provider resources; Linux mmap mappings
    // live for the process.
}
fn linux_boot_scan() {}
fn linux_merge_runtime_overrides(_module_id: u16, _buf: *mut u8, len: usize, _max: usize) -> usize {
    len
}


/// HalOps protection impls: the portable MPU facade (no-op internally on
/// non-RP silicon) and the shared direct step dispatch.
fn prot_register_module(
    module_idx: usize,
    code_base: usize,
    code_size: usize,
    state_ptr: *mut u8,
    state_size: usize,
    heap_ptr: *mut u8,
    heap_size: usize,
) {
    fluxor::platform::mpu::register_module(
        module_idx,
        code_base as u32,
        code_size as u32,
        state_ptr,
        state_size,
        heap_ptr,
        heap_size,
    );
}
fn prot_set_channel_region(module_idx: usize, base: usize, size: usize) {
    fluxor::platform::mpu::set_channel_region(module_idx, base as u32, size as u32);
}
use fluxor::kernel::sys::hal::protected_step_direct as fluxor_protected_step_direct;

static LINUX_HAL_OPS: HalOps = HalOps {
    disable_interrupts: linux_disable_interrupts,
    restore_interrupts: linux_restore_interrupts,
    wake_scheduler: linux_wake_scheduler,
    now_millis: linux_now_millis,
    now_unix_millis: linux_now_unix_millis,
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
    isr_tier_init: linux_isr_tier_init,
    isr_tier_start: linux_isr_tier_start,
    isr_tier_stop: linux_isr_tier_stop,
    isr_tier_poll: linux_isr_tier_poll,
    init_providers: linux_init_providers,
    release_module_handles: linux_release_module_handles,
    boot_scan: linux_boot_scan,
    merge_runtime_overrides: linux_merge_runtime_overrides,
    init_gpio: |_| 0,
    csprng_fill: linux_csprng_fill,
    core_id: || 0,
    irq_bind: |_, _, _, _| fluxor::kernel::sys::errno::ENOSYS,
    sleep_until: linux_sleep_until,
    smp_quiesce_peers: || false,
    smp_release_peers: || {},
    smp_max_domains: || 1,
    protection_set_enabled: fluxor::platform::mpu::set_enabled,
    protection_reset: || {},
    protection_register_module: prot_register_module,
    protection_set_channel_region: prot_set_channel_region,
    protection_set_isolated_channels: |_, _, _, _| {},
    protected_step: fluxor_protected_step_direct,
    protection_map_page: |_, _, _, _| {},
    protection_unmap_page: |_, _| {},
    stack_canary_check: fluxor::platform::mpu::check_stack_canary,
    stack_canary_reinit: fluxor::platform::mpu::reinit_stack_canary,
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
};

fn linux_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    // `libc::SYS_getrandom` is the canonical per-arch syscall selector
    // and `libc::syscall` handles the platform-specific calling
    // convention, so this compiles correctly (or fails loudly) on any
    // architecture libc supports — no hand-rolled `svc`/asm or
    // hardcoded syscall numbers.
    // SAFETY: `libc::syscall` invoked with the per-arch SYS_getrandom
    // selector and `(buf, len, flags=0)` matches `getrandom(2)`. The
    // caller supplies `buf`/`len` from a Rust slice, so the pointer
    // is valid for writes of `len` bytes.
    let ret =
        unsafe { libc::syscall(libc::SYS_getrandom, buf as *mut libc::c_void, len, 0u32) };
    if ret < 0 || ret as usize != len {
        return -1;
    }
    0
}

// ============================================================================

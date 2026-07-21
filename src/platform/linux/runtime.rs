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
        return fluxor::kernel::hal::WOKEN_DEADLINE;
    }
    let remaining = deadline_us - now;
    std::thread::park_timeout(std::time::Duration::from_micros(remaining));
    // Distinguish deadline vs early wake by re-reading the clock.
    if elapsed_micros() >= deadline_us {
        fluxor::kernel::hal::WOKEN_DEADLINE
    } else {
        fluxor::kernel::hal::WOKEN_EVENT
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
    use fluxor::kernel::provider;
    use fluxor::kernel::provider::contract as dev_class;
    provider::register(dev_class::FS, linux_fs_dispatch);
    provider::register(dev_class::HAL_PIO, linux_stream_time_dispatch);
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
    provider::register(dev_class::PROC, linux_proc_dispatch);
    // Platform-neutral isolated-workload surface: parses the Tier-1 spec, binds
    // to a plan-allocated owner + lease, enforces the Tier-2 options envelope
    // fail-closed, and delegates to the owner-bound host-process backend.
    // Host-linux; gated by requires_contract = "workload" + platform_raw.
    provider::register(dev_class::WORKLOAD, linux_workload_dispatch);
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
    irq_bind: |_, _, _, _| fluxor::kernel::errno::ENOSYS,
    sleep_until: linux_sleep_until,
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

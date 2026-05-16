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
fn linux_wake_scheduler() {}

fn linux_now_millis() -> u64 {
    elapsed_micros() / 1000
}
fn linux_now_micros() -> u64 {
    elapsed_micros()
}
fn linux_tick_count() -> u32 {
    scheduler::tick_count()
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
    irq_bind: |_, _, _| fluxor::kernel::errno::ENOSYS,
};

fn linux_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    // Use `libc::syscall(SYS_getrandom, …)` instead of a handwritten
    // `svc 0` + hardcoded per-arch syscall number. The previous
    // implementation:
    //   - had aarch64-only inline asm but an x86_64 `cfg` branch (the
    //     branch would have compiled but the asm used `x0..x8`
    //     registers, so on x86_64 the symbol set was wrong);
    //   - hardcoded `SYS_GETRANDOM = 278` for aarch64 (correct today)
    //     and `318` for x86_64 (also correct, but type-fragile);
    //   - didn't compile-fail when invoked on an architecture the
    //     match didn't cover.
    // `libc::SYS_getrandom` is the canonical per-arch constant and
    // `libc::syscall` handles the platform-specific calling
    // convention. See.
    let ret =
        unsafe { libc::syscall(libc::SYS_getrandom, buf as *mut libc::c_void, len, 0u32) };
    if ret < 0 || ret as usize != len {
        return -1;
    }
    0
}

// ============================================================================

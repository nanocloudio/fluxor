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
    addr != 0
}
fn linux_validate_module_base(addr: usize) -> bool {
    addr != 0
}
fn linux_validate_fn_in_code(_addr: usize, _base: usize, _size: u32) -> bool {
    true
}
fn linux_verify_integrity(_computed: &[u8], _expected: &[u8]) -> bool {
    true
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
    // Override the default stub FS provider with one backed by real libc I/O.
    use fluxor::kernel::provider;
    use fluxor::kernel::provider::contract as dev_class;
    provider::register(dev_class::FS, linux_fs_dispatch);
}
fn linux_release_module_handles(_module_idx: u8) {}
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
    unsafe {
        // getrandom() syscall (318 on aarch64 Linux, 318 on x86_64)
        #[cfg(target_arch = "aarch64")]
        const SYS_GETRANDOM: i64 = 278;
        #[cfg(target_arch = "x86_64")]
        const SYS_GETRANDOM: i64 = 318;
        let ret: i64;
        core::arch::asm!(
            "svc 0",
            in("x8") SYS_GETRANDOM,
            in("x0") buf as u64,
            in("x1") len as u64,
            in("x2") 0u64,  // flags: 0 = /dev/urandom
            lateout("x0") ret,
        );
        if ret < 0 || ret as usize != len {
            return -1;
        }
        0
    }
}

// ============================================================================

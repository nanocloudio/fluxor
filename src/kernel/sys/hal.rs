//! Hardware Abstraction Layer — function-pointer dispatch table.
//!
//! Kernel code calls `hal::now_millis()`, `hal::disable_interrupts()`, etc.
//! Each platform (RP, BCM2712) provides a static `HalOps` table and registers
//! it at boot via `hal::init()`. This eliminates all `#[cfg]` blocks from
//! kernel code — platform differences are resolved through a single function
//! pointer indirection.
//!
//! ## Concurrency
//!
//! `HAL_OPS` is assigned once during `kernel::boot(...)` on core 0
//! before any secondary core is released. Subsequent reads from any
//! core see the same `&'static HalOps`. See
//! `docs/architecture/concurrency.md`.

/// Function-pointer table for all platform-specific operations.
///
/// Each platform constructs a `static HalOps` and passes it to `hal::init()`.
/// Zero-cost at rest (single pointer dereference per call).
#[repr(C)]
pub struct HalOps {
    // ── Interrupt control ─────────────────────────────────────────────
    /// Disable interrupts and return saved state (PRIMASK / DAIF).
    pub disable_interrupts: fn() -> u32,
    /// Restore interrupt state from a previous `disable_interrupts`.
    pub restore_interrupts: fn(u32),
    /// Wake the scheduler from its idle sleep (Embassy signal / SEV).
    pub wake_scheduler: fn(),

    // ── Timer ─────────────────────────────────────────────────────────
    /// Current time in milliseconds since boot.
    pub now_millis: fn() -> u64,
    /// Current time in microseconds since boot.
    pub now_micros: fn() -> u64,
    /// Wall-clock time in milliseconds since the Unix epoch, or 0 if the platform has no
    /// real-time clock. Distinct from `now_millis` (monotonic uptime); needed for absolute-
    /// time checks like certificate validity and JWT `exp` (see docs/surface-auth.md).
    pub now_unix_millis: fn() -> u64,
    /// Monotonic tick count (wrapping).
    pub tick_count: fn() -> u32,

    // ── Memory model ──────────────────────────────────────────────────
    /// Flash base address (0x10000000 on RP, 0 on aarch64).
    pub flash_base: fn() -> usize,
    /// Flash end address.
    pub flash_end: fn() -> usize,
    /// Apply code bit (Thumb bit on Cortex-M, identity on aarch64).
    pub apply_code_bit: fn(usize) -> usize,
    /// Validate a function address (Thumb+flash check / non-null check).
    pub validate_fn_addr: fn(usize) -> bool,
    /// Validate module base address (within flash / non-null).
    pub validate_module_base: fn(usize) -> bool,
    /// Validate that a function address is within a code region.
    pub validate_fn_in_code: fn(addr: usize, code_base: usize, code_size: u32) -> bool,
    /// Verify integrity of module code (SHA-256 on RP, skip on aarch64).
    pub verify_integrity: fn(computed: &[u8], expected: &[u8]) -> bool,
    /// Transition an OTA staging region between writable (staging) and
    /// executable (committed): cache maintenance to the point of
    /// unification on bare-metal aarch64, page-permission flips on
    /// hosted targets. Returns `false` on targets without a RAM
    /// staging surface (RP delivers OTA through flash graph slots).
    pub ota_stage_protect: fn(base: *mut u8, len: usize, executable: bool) -> bool,
    /// Pipeline barrier after PIC call (DSB+ISB + interrupt restore check).
    pub pic_barrier: fn(),

    // ── Step guard ────────────────────────────────────────────────────
    /// Initialize step guard hardware.
    pub step_guard_init: fn(),
    /// Arm step guard with deadline in microseconds.
    pub step_guard_arm: fn(u32),
    /// Disarm step guard (normal return).
    pub step_guard_disarm: fn(),
    /// Post-step elapsed check (aarch64 advisory; no-op on Cortex-M).
    pub step_guard_post_check: fn(),

    // ── ISR tier ──────────────────────────────────────────────────────
    /// Read hardware cycle counter (DWT CYCCNT / CNTPCT_EL0).
    pub read_cycle_count: fn() -> u32,
    /// Initialize ISR tier hardware (enable DWT cycle counter, etc).
    pub isr_tier_init: fn(),
    /// Start Tier 1b periodic timer with period in microseconds.
    pub isr_tier_start: fn(u32),
    /// Stop Tier 1b periodic timer.
    pub isr_tier_stop: fn(),
    /// Poll Tier 1b from main loop (aarch64 only; no-op on Cortex-M).
    pub isr_tier_poll: fn(),

    // ── Platform dispatch ─────────────────────────────────────────────
    /// Platform-specific provider initialization (GPIO, SPI, etc.).
    pub init_providers: fn(),
    /// Release platform-specific handles for a module.
    pub release_module_handles: fn(u8),
    /// Boot-time scan of flash parameter store (no-op on aarch64).
    pub boot_scan: fn(),
    /// Merge runtime parameter overrides into param buffer.
    /// Returns new length.
    pub merge_runtime_overrides: fn(module_id: u16, buf: *mut u8, len: usize, max: usize) -> usize,
    /// Initialize GPIO pins from config. Returns count of pins initialized.
    pub init_gpio: fn(gpio: &[Option<crate::kernel::boot::config::GpioConfig>]) -> usize,

    /// Fill buffer with cryptographically secure random bytes.
    /// Returns 0 on success, negative errno on failure.
    pub csprng_fill: fn(buf: *mut u8, len: usize) -> i32,

    /// Return the current CPU core ID (0-3). Returns 0 on single-core platforms.
    pub core_id: fn() -> usize,

    /// Bind an event handle to a hardware IRQ. Platform-specific.
    /// `target_core` is the core that should take the IRQ (the core running the
    /// owning domain — on the multi-core platform domain id == core id). On
    /// single-core / no-IRQ platforms it is ignored.
    /// Returns 0 on success, negative errno on failure.
    pub irq_bind: fn(irq: u32, event_handle: i32, mmio_base: usize, target_core: u8) -> i32,

    /// Block until the absolute `deadline_us` (microseconds since boot) OR an
    /// event/IRQ wakes the scheduler, whichever comes first; returns a
    /// `WOKEN_*` reason. The portable unification of the per-platform split wake
    /// arms (RFC adaptive_tick §5.5 Option B / D5): platform loops may keep
    /// using their native arms (Embassy select, thread park, WFI/WFE), and this
    /// field provides the single portable primitive a loop can adopt instead,
    /// without per-platform `#[cfg]` branching. Supplied on every platform.
    pub sleep_until: fn(deadline_us: u64) -> u32,

    /// Park every online secondary core at a safe point for a structural graph
    /// mutation. Returns `true` if peers were actually parked (the caller must
    /// then call [`HalOps::smp_release_peers`]); `false` on single-core
    /// platforms or before SMP is online.
    pub smp_quiesce_peers: fn() -> bool,
    /// Release peers parked by [`HalOps::smp_quiesce_peers`].
    pub smp_release_peers: fn(),
    /// Number of execution domains the platform can actually run in parallel
    /// (cores). Kernel-side domain masks clamp to this.
    pub smp_max_domains: fn() -> usize,

    // ── Module protection (MPU / MMU / none) ─────────────────────────
    /// Enable module protection after the first `protection: isolated` module
    /// is admitted (MPU regions on Cortex-M, EL0 page tables on aarch64).
    pub protection_set_enabled: fn(bool),
    /// Drop all per-module protection state for a graph reconfigure.
    pub protection_reset: fn(),
    /// Register a module's code/state/heap footprints with the protection
    /// hardware. `code_base`/`code_size` in bytes (platforms narrow as needed).
    pub protection_register_module: fn(
        module_idx: usize,
        code_base: usize,
        code_size: usize,
        state_ptr: *mut u8,
        state_size: usize,
        heap_ptr: *mut u8,
        heap_size: usize,
    ),
    /// Register a module's channel-buffer range so an isolated module sees
    /// only its own buffers. Platforms apply their own alignment/rounding and
    /// fail-closed policies.
    pub protection_set_channel_region: fn(module_idx: usize, base: usize, size: usize),
    /// Record the channel handles an isolated module may name in a mediated
    /// gateway call.
    pub protection_set_isolated_channels:
        fn(module_idx: usize, in_chan: i32, out_chan: i32, ctrl_chan: i32),
    /// Run one isolated module step under the platform's protection domain
    /// (EL0 entry on aarch64). Platforms without a protected-call mechanism
    /// install [`protected_step_direct`].
    pub protected_step:
        unsafe fn(step_fn: crate::kernel::module::loader::ModuleStepFn, state_ptr: *mut u8) -> i32,
    /// Map / unmap one 4 KiB page in a module's protection tables (paged
    /// arena). No-ops where module page tables don't exist.
    pub protection_map_page: fn(module_idx: usize, vaddr: usize, phys: usize, writable: bool),
    pub protection_unmap_page: fn(module_idx: usize, vaddr: usize),
    /// Stack-canary check / re-arm around module steps.
    pub stack_canary_check: fn() -> bool,
    pub stack_canary_reinit: fn(),
    /// Write raw bytes to the platform's debug serial sink (the same UART / USB
    /// CDC the log ring drains to). Binary-safe (no UTF-8 filtering, unlike the
    /// log path), so a telemetry `transport_buffer` can push framed records to a host
    /// collector on network-less targets. Returns bytes accepted; `0` if the sink
    /// isn't ready or the target has none.
    pub serial_write: fn(bytes: &[u8]) -> usize,
}

/// Default `protected_step` for platforms without a protected-call mechanism:
/// the plain module call with the post-PIC barrier (identical to the loader's
/// direct dispatch path).
///
/// # Safety
/// Same contract as any module step dispatch: `step_fn`/`state_ptr` validated
/// at module construction.
pub unsafe fn protected_step_direct(
    step_fn: crate::kernel::module::loader::ModuleStepFn,
    state_ptr: *mut u8,
) -> i32 {
    let r = step_fn(state_ptr);
    pic_barrier();
    r
}

/// Park every online secondary core for a structural mutation. `true` iff
/// parked — pair with [`smp_release_peers`].
#[inline]
pub fn smp_quiesce_peers() -> bool {
    (ops().smp_quiesce_peers)()
}

/// Release cores parked by [`smp_quiesce_peers`].
#[inline]
pub fn smp_release_peers() {
    (ops().smp_release_peers)()
}

/// Parallel-domain (core) count for domain-mask clamping.
#[inline]
pub fn smp_max_domains() -> usize {
    (ops().smp_max_domains)()
}

#[inline]
pub fn protection_set_enabled(enabled: bool) {
    (ops().protection_set_enabled)(enabled)
}
#[inline]
pub fn protection_reset() {
    (ops().protection_reset)()
}
#[inline]
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the HalOps protection_register_module field signature"
)]
pub fn protection_register_module(
    module_idx: usize,
    code_base: usize,
    code_size: usize,
    state_ptr: *mut u8,
    state_size: usize,
    heap_ptr: *mut u8,
    heap_size: usize,
) {
    (ops().protection_register_module)(
        module_idx, code_base, code_size, state_ptr, state_size, heap_ptr, heap_size,
    )
}
#[inline]
pub fn protection_set_channel_region(module_idx: usize, base: usize, size: usize) {
    (ops().protection_set_channel_region)(module_idx, base, size)
}
#[inline]
pub fn protection_set_isolated_channels(
    module_idx: usize,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
) {
    (ops().protection_set_isolated_channels)(module_idx, in_chan, out_chan, ctrl_chan)
}
/// # Safety
/// `step_fn`/`state_ptr` validated at module construction; scheduler-thread.
#[inline]
pub unsafe fn protected_step(
    step_fn: crate::kernel::module::loader::ModuleStepFn,
    state_ptr: *mut u8,
) -> i32 {
    (ops().protected_step)(step_fn, state_ptr)
}
#[inline]
pub fn protection_map_page(module_idx: usize, vaddr: usize, phys: usize, writable: bool) {
    (ops().protection_map_page)(module_idx, vaddr, phys, writable)
}
#[inline]
pub fn protection_unmap_page(module_idx: usize, vaddr: usize) {
    (ops().protection_unmap_page)(module_idx, vaddr)
}
#[inline]
pub fn stack_canary_check() -> bool {
    (ops().stack_canary_check)()
}
#[inline]
pub fn stack_canary_reinit() {
    (ops().stack_canary_reinit)()
}

/// `sleep_until` returned because its programmed deadline elapsed.
pub const WOKEN_DEADLINE: u32 = 0;
/// `sleep_until` returned because an event/IRQ woke the scheduler early.
pub const WOKEN_EVENT: u32 = 1;
/// `sleep_until` returned for an indeterminate reason (e.g. a bare WFI that
/// cannot distinguish the wake source). The caller must re-check its own
/// wake/work state — `sleep_until` is a hint, never an authority on readiness.
pub const WOKEN_UNKNOWN: u32 = 2;

/// Global HAL operations table. Set once at boot by `init()`.
static mut HAL_OPS: Option<&'static HalOps> = None;

/// Register the platform's HAL operations table. Must be called once at boot.
///
/// # Safety
/// Must be called exactly once before any kernel code runs.
pub fn init(ops: &'static HalOps) {
    // SAFETY: `init` is documented as call-once before any kernel code
    // runs; at that point no other thread observes `HAL_OPS`.
    unsafe {
        HAL_OPS = Some(ops);
    }
}

/// Get the HAL ops table. Boot order guarantees `init()` runs before
/// any kernel code that touches the HAL; calling `ops()` before
/// `init()` panics with a useful diagnostic so a misordered
/// refactor fails loudly instead of trapping as undefined behaviour.
#[inline(always)]
fn ops() -> &'static HalOps {
    // SAFETY: `HAL_OPS` is set once at boot by `init`; the panic-on-None
    // branch catches the boot-ordering bug if a caller jumps the gun.
    unsafe {
        match HAL_OPS {
            Some(ops) => ops,
            None => panic!("hal::ops() called before hal::init() — boot ordering bug"),
        }
    }
}

// ── Interrupt control ─────────────────────────────────────────────────

#[inline(always)]
pub fn disable_interrupts() -> u32 {
    (ops().disable_interrupts)()
}

#[inline(always)]
pub fn restore_interrupts(state: u32) {
    (ops().restore_interrupts)(state)
}

#[inline(always)]
pub fn wake_scheduler() {
    (ops().wake_scheduler)()
}

// ── Timer ─────────────────────────────────────────────────────────────

#[inline(always)]
pub fn now_millis() -> u64 {
    (ops().now_millis)()
}

#[inline(always)]
pub fn now_micros() -> u64 {
    (ops().now_micros)()
}

/// Write raw bytes to the platform debug serial sink (binary-safe). Returns the
/// number of bytes accepted.
#[inline(always)]
pub fn serial_write(bytes: &[u8]) -> usize {
    (ops().serial_write)(bytes)
}

/// Wall-clock milliseconds since the Unix epoch (0 = no RTC on this platform).
#[inline(always)]
pub fn now_unix_millis() -> u64 {
    (ops().now_unix_millis)()
}

#[inline(always)]
pub fn tick_count() -> u32 {
    (ops().tick_count)()
}

/// Block until `deadline_us` (µs since boot) or an event/IRQ wakes the
/// scheduler. Returns a `WOKEN_*` reason; treat it as a hint and re-check
/// work state regardless (RFC adaptive_tick §5.5 Option B).
#[inline(always)]
pub fn sleep_until(deadline_us: u64) -> u32 {
    (ops().sleep_until)(deadline_us)
}

// ── Memory model ──────────────────────────────────────────────────────

#[inline(always)]
pub fn flash_base() -> usize {
    (ops().flash_base)()
}

#[inline(always)]
pub fn flash_end() -> usize {
    (ops().flash_end)()
}

#[inline(always)]
pub fn apply_code_bit(addr: usize) -> usize {
    (ops().apply_code_bit)(addr)
}

#[inline(always)]
pub fn validate_fn_addr(addr: usize) -> bool {
    (ops().validate_fn_addr)(addr)
}

#[inline(always)]
pub fn validate_module_base(addr: usize) -> bool {
    (ops().validate_module_base)(addr)
}

#[inline(always)]
pub fn validate_fn_in_code(addr: usize, code_base: usize, code_size: u32) -> bool {
    (ops().validate_fn_in_code)(addr, code_base, code_size)
}

#[inline(always)]
pub fn verify_integrity(computed: &[u8], expected: &[u8]) -> bool {
    (ops().verify_integrity)(computed, expected)
}

/// See [`HalOps::ota_stage_protect`].
pub fn ota_stage_protect(base: *mut u8, len: usize, executable: bool) -> bool {
    (ops().ota_stage_protect)(base, len, executable)
}

#[inline(always)]
pub fn pic_barrier() {
    (ops().pic_barrier)()
}

/// Full barrier between a CPU-side write to a DMA buffer and the
/// register write that arms the controller. Call immediately before
/// any MMIO that hands a descriptor or queue index to a device — the
/// `dsb sy` on aarch64 covers the system shareability domain that
/// `dmb ish` does not (PCIe-attached devices sit outside the inner
/// shareable). Cortex-M relies on the strongly-ordered system bus
/// plus a compiler fence against reordering.
#[inline(always)]
pub fn dma_kick_barrier() {
    // SAFETY: DSB is a system-control hint; no register or memory
    // side-effects beyond the architectural ordering barrier.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Minimum measurable wall-clock increment from `now_micros()` on
/// this target, in nanoseconds. Reports the **API's** resolution,
/// not the underlying counter — `now_micros()` returns integer
/// microseconds everywhere except WASM, where browsers clamp
/// `performance.now()` to 100 µs as a Spectre mitigation. Modules
/// that depend on sub-µs timing should query this and adjust their
/// math (or refuse to run on coarse platforms).
#[inline(always)]
pub fn tick_us_granularity_ns() -> u32 {
    #[cfg(target_arch = "wasm32")]
    {
        100_000
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        1_000
    }
}

/// `true` when the running target's scheduler tick is coarsened by
/// an external constraint — currently only WASM. `step_period_ticks`
/// counts scheduler returns, not wall-clock microseconds; on a
/// coarsened platform a `step_period_ticks == 1` module may not run
/// more often than the platform's tick floor. Modules that need
/// sub-millisecond `tick_us` deltas (audio resampling, control
/// loops) gate themselves out via this query.
#[inline(always)]
pub fn is_tick_coarsened() -> bool {
    cfg!(target_arch = "wasm32")
}

// ── Step guard ────────────────────────────────────────────────────────

#[inline(always)]
pub fn step_guard_init() {
    (ops().step_guard_init)()
}

#[inline(always)]
pub fn step_guard_arm(deadline_us: u32) {
    (ops().step_guard_arm)(deadline_us)
}

#[inline(always)]
pub fn step_guard_disarm() {
    (ops().step_guard_disarm)()
}

#[inline(always)]
pub fn step_guard_post_check() {
    (ops().step_guard_post_check)()
}

// ── ISR tier ──────────────────────────────────────────────────────────

#[inline(always)]
pub fn read_cycle_count() -> u32 {
    (ops().read_cycle_count)()
}

#[inline(always)]
pub fn isr_tier_init() {
    (ops().isr_tier_init)()
}

#[inline(always)]
pub fn isr_tier_start(period_us: u32) {
    (ops().isr_tier_start)(period_us)
}

#[inline(always)]
pub fn isr_tier_stop() {
    (ops().isr_tier_stop)()
}

#[inline(always)]
pub fn isr_tier_poll() {
    (ops().isr_tier_poll)()
}

// ── Platform dispatch ─────────────────────────────────────────────────

#[inline(always)]
pub fn init_providers() {
    (ops().init_providers)()
}

#[inline(always)]
pub fn release_platform_handles(module_idx: u8) {
    (ops().release_module_handles)(module_idx)
}

#[inline(always)]
pub fn boot_scan() {
    (ops().boot_scan)()
}

#[inline(always)]
pub fn merge_runtime_overrides(module_id: u16, buf: *mut u8, len: usize, max: usize) -> usize {
    (ops().merge_runtime_overrides)(module_id, buf, len, max)
}

#[inline(always)]
pub fn init_gpio(gpio: &[Option<crate::kernel::boot::config::GpioConfig>]) -> usize {
    (ops().init_gpio)(gpio)
}

#[inline(always)]
pub fn csprng_fill(buf: *mut u8, len: usize) -> i32 {
    (ops().csprng_fill)(buf, len)
}

/// Return the current CPU core ID (0-3). Returns 0 on single-core platforms.
#[inline(always)]
pub fn core_id() -> usize {
    (ops().core_id)()
}

/// Bind an event handle to a hardware IRQ.
#[inline(always)]
pub fn irq_bind(irq: u32, event_handle: i32, mmio_base: usize, target_core: u8) -> i32 {
    (ops().irq_bind)(irq, event_handle, mmio_base, target_core)
}

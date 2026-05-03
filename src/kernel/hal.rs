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
    pub init_gpio: fn(gpio: &[Option<crate::kernel::config::GpioConfig>]) -> usize,

    /// Fill buffer with cryptographically secure random bytes.
    /// Returns 0 on success, negative errno on failure.
    pub csprng_fill: fn(buf: *mut u8, len: usize) -> i32,

    /// Return the current CPU core ID (0-3). Returns 0 on single-core platforms.
    pub core_id: fn() -> usize,

    /// Bind an event handle to a hardware IRQ. Platform-specific.
    /// Returns 0 on success, negative errno on failure.
    pub irq_bind: fn(irq: u32, event_handle: i32, mmio_base: usize) -> i32,
}

/// Global HAL operations table. Set once at boot by `init()`.
static mut HAL_OPS: Option<&'static HalOps> = None;

/// Register the platform's HAL operations table. Must be called once at boot.
///
/// # Safety
/// Must be called exactly once before any kernel code runs.
pub fn init(ops: &'static HalOps) {
    unsafe {
        HAL_OPS = Some(ops);
    }
}

/// Get the HAL ops table. Panics if not initialized (boot bug).
#[inline(always)]
fn ops() -> &'static HalOps {
    unsafe { HAL_OPS.unwrap_unchecked() }
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

#[inline(always)]
pub fn tick_count() -> u32 {
    (ops().tick_count)()
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

/// Read the root-of-trust Ed25519 signing pubkey into `out`.
///
/// Returns true if a pubkey is provisioned (writes 32 bytes into `out`);
/// false otherwise. The loader uses this to authenticate module signatures
/// when the `enforce_signatures` feature is set.
///
/// Provisioning: the pubkey is a compile-time constant taken from the
/// `FLUXOR_SIGNING_PUBKEY_HEX` environment variable at build time (64 hex
/// characters, 32 bytes). Unset means the device is unprovisioned and
/// module signatures cannot be checked; with `enforce_signatures` set,
/// the loader then refuses to load any module.
pub fn otp_read_signing_key(out: &mut [u8; 32]) -> bool {
    match option_env!("FLUXOR_SIGNING_PUBKEY_HEX") {
        Some(hex) if hex.len() == 64 => {
            let bytes = hex.as_bytes();
            for i in 0..32 {
                let hi = match bytes[i * 2] {
                    b'0'..=b'9' => bytes[i * 2] - b'0',
                    b'a'..=b'f' => bytes[i * 2] - b'a' + 10,
                    b'A'..=b'F' => bytes[i * 2] - b'A' + 10,
                    _ => return false,
                };
                let lo = match bytes[i * 2 + 1] {
                    b'0'..=b'9' => bytes[i * 2 + 1] - b'0',
                    b'a'..=b'f' => bytes[i * 2 + 1] - b'a' + 10,
                    b'A'..=b'F' => bytes[i * 2 + 1] - b'A' + 10,
                    _ => return false,
                };
                out[i] = (hi << 4) | lo;
            }
            true
        }
        _ => false,
    }
}

#[inline(always)]
pub fn pic_barrier() {
    (ops().pic_barrier)()
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
pub fn init_gpio(gpio: &[Option<crate::kernel::config::GpioConfig>]) -> usize {
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
pub fn irq_bind(irq: u32, event_handle: i32, mmio_base: usize) -> i32 {
    (ops().irq_bind)(irq, event_handle, mmio_base)
}

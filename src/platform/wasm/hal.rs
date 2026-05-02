//! WASM platform HAL ops.
//!
//! The kernel's `hal::HalOps` is a fn-pointer table the platform
//! populates at boot — all `hal::*` calls dispatch through it. Without
//! a registered table, `hal::ops()` calls `unwrap_unchecked()` on a
//! `None`, which on wasm32 traps as `call_indirect to a signature
//! that does not match` (the empty None turns into an indirect call
//! to fn-table index 0, which has the wrong type).
//!
//! WASM is single-threaded, sandboxed, has no flash / interrupts /
//! step guard / ISR tier — most ops are no-ops. The few that matter
//! (timers, csprng) bridge to host imports.
//!
//! Mirrors the Linux platform's HAL approach: same table shape, all
//! the bare-metal-only entries stubbed out, time + crypto plumbed
//! through the host.

use crate::kernel::config::GpioConfig;
use crate::kernel::hal::HalOps;

extern "C" {
    fn host_now_us() -> u64;
    /// Fill `len` bytes at `buf` with cryptographically secure random
    /// data. Returns 0 on success, negative errno on failure.
    /// Browser implementations should call `crypto.getRandomValues`;
    /// non-browser hosts should use the OS RNG (e.g. `getrandom(2)`
    /// in wasmtime, `crypto/rand` in edge runtimes). Hosts that
    /// cannot provide a CSPRNG **must** return a negative errno —
    /// downstream consumers (TLS, key generation) treat
    /// `dev_csprng_fill` as cryptographic entropy and will produce
    /// insecure output if seeded with anything weaker.
    fn host_csprng_fill(buf: *mut u8, len: usize) -> i32;
}

fn wasm_disable_interrupts() -> u32 {
    0
}
fn wasm_restore_interrupts(_state: u32) {}
fn wasm_wake_scheduler() {}

fn wasm_now_micros() -> u64 {
    unsafe { host_now_us() }
}
fn wasm_now_millis() -> u64 {
    wasm_now_micros() / 1000
}
fn wasm_tick_count() -> u32 {
    // Cheap monotonic counter shape — millis fits in u32 for ~50
    // days of uptime, plenty for a browser tab.
    wasm_now_millis() as u32
}

// No flash on wasm — all addresses are linear-memory pointers, which
// the kernel's PIC checks treat as "always valid" by construction
// (the wasm engine sandboxes accesses).
fn wasm_flash_base() -> usize {
    0
}
fn wasm_flash_end() -> usize {
    usize::MAX
}
fn wasm_apply_code_bit(addr: usize) -> usize {
    addr
}
fn wasm_validate_fn_addr(_addr: usize) -> bool {
    true
}
fn wasm_validate_module_base(_base: usize) -> bool {
    true
}
fn wasm_validate_fn_in_code(_addr: usize, _code_base: usize, _code_size: u32) -> bool {
    true
}
fn wasm_verify_integrity(computed: &[u8], expected: &[u8]) -> bool {
    if computed.len() != expected.len() {
        return false;
    }
    let mut i = 0;
    while i < computed.len() {
        if computed[i] != expected[i] {
            return false;
        }
        i += 1;
    }
    true
}
fn wasm_pic_barrier() {}

fn wasm_step_guard_init() {}
fn wasm_step_guard_arm(_us: u32) {}
fn wasm_step_guard_disarm() {}
fn wasm_step_guard_post_check() {}

fn wasm_read_cycle_count() -> u32 {
    wasm_tick_count()
}
fn wasm_isr_tier_init() {}
fn wasm_isr_tier_start(_us: u32) {}
fn wasm_isr_tier_stop() {}
fn wasm_isr_tier_poll() {}

fn wasm_init_providers() {}
fn wasm_release_module_handles(_id: u8) {}
fn wasm_boot_scan() {}
fn wasm_merge_runtime_overrides(
    _module_id: u16,
    _buf: *mut u8,
    len: usize,
    _max: usize,
) -> usize {
    len
}
fn wasm_init_gpio(_gpio: &[Option<GpioConfig>]) -> usize {
    0
}
fn wasm_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    // Delegate to the host. Browser shim wires this to
    // `crypto.getRandomValues` (a Web Crypto CSPRNG); wasmtime / edge
    // shims use the OS entropy source. The host import returns a
    // negative errno if no CSPRNG is available — we propagate that
    // rather than fall back to a non-cryptographic generator. TLS,
    // key generation, and any other consumer of `dev_csprng_fill`
    // would silently produce insecure output if seeded with
    // anything weaker than what the host calls a CSPRNG.
    if buf.is_null() || len == 0 {
        return 0;
    }
    unsafe { host_csprng_fill(buf, len) }
}
fn wasm_core_id() -> usize {
    0
}
fn wasm_irq_bind(_irq: u32, _event_handle: i32, _mmio_base: usize) -> i32 {
    -38 // ENOSYS — wasm has no hardware IRQs
}

pub static WASM_HAL_OPS: HalOps = HalOps {
    disable_interrupts: wasm_disable_interrupts,
    restore_interrupts: wasm_restore_interrupts,
    wake_scheduler: wasm_wake_scheduler,
    now_millis: wasm_now_millis,
    now_micros: wasm_now_micros,
    tick_count: wasm_tick_count,
    flash_base: wasm_flash_base,
    flash_end: wasm_flash_end,
    apply_code_bit: wasm_apply_code_bit,
    validate_fn_addr: wasm_validate_fn_addr,
    validate_module_base: wasm_validate_module_base,
    validate_fn_in_code: wasm_validate_fn_in_code,
    verify_integrity: wasm_verify_integrity,
    pic_barrier: wasm_pic_barrier,
    step_guard_init: wasm_step_guard_init,
    step_guard_arm: wasm_step_guard_arm,
    step_guard_disarm: wasm_step_guard_disarm,
    step_guard_post_check: wasm_step_guard_post_check,
    read_cycle_count: wasm_read_cycle_count,
    isr_tier_init: wasm_isr_tier_init,
    isr_tier_start: wasm_isr_tier_start,
    isr_tier_stop: wasm_isr_tier_stop,
    isr_tier_poll: wasm_isr_tier_poll,
    init_providers: wasm_init_providers,
    release_module_handles: wasm_release_module_handles,
    boot_scan: wasm_boot_scan,
    merge_runtime_overrides: wasm_merge_runtime_overrides,
    init_gpio: wasm_init_gpio,
    csprng_fill: wasm_csprng_fill,
    core_id: wasm_core_id,
    irq_bind: wasm_irq_bind,
};

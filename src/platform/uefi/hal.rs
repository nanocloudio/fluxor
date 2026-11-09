// The kernel's hooks into the `uefi` runtime: the counter for time, the console
// for serial, and what this runtime lacks reported as such.
//
// Nitro offers a guest no hardware key, so nothing seals (`SealProvenance::None`)
// and the vault keeps its keys in RAM. Entropy is the firmware's seed and the
// architecture's RNDR where the core has it; with neither, `csprng_fill` fails
// closed.

use core::sync::atomic::{AtomicBool, Ordering};

use fluxor::arch::aarch64::cpu::current_core_id;
use fluxor::arch::aarch64::{exception, gic, timer};
use fluxor::kernel::security::crypto::sha256;
use fluxor::kernel::sys::hal::{self, HalOps};

fn disable_interrupts() -> u32 {
    let daif: u32;
    // SAFETY: reads and writes the interrupt mask; no memory effects.
    unsafe {
        core::arch::asm!(
            "mrs {0:x}, daif",
            "msr daifset, #2",
            out(reg) daif,
            options(nomem, nostack, preserves_flags),
        );
    }
    daif
}

fn restore_interrupts(saved: u32) {
    // SAFETY: writes the interrupt mask; no memory effects.
    unsafe {
        core::arch::asm!("msr daif, {0:x}", in(reg) saved, options(nomem, nostack, preserves_flags));
    }
}

fn wake_scheduler() {
    // SAFETY: an event hint, and an SGI to this core, since the run loop idles
    // on WFI, which an event alone does not end.
    unsafe {
        core::arch::asm!("sev");
        gic::send_sgi_self(gic::WAKE_SGI);
    }
}

fn read_cycle_count() -> u32 {
    timer::read_timer_count_64() as u32
}

fn core_id() -> usize {
    current_core_id() as usize
}

fn now_micros() -> u64 {
    let freq = timer::timer_freq().max(1);
    let count = u128::from(timer::read_timer_count_64());
    (count * 1_000_000 / u128::from(freq)) as u64
}

fn now_millis() -> u64 {
    now_micros() / 1000
}

fn step_guard_arm(deadline_us: u32) {
    use fluxor::kernel::exec::step_guard;
    step_guard::clear_timed_out();
    step_guard::set_armed(true);
    step_guard::set_window(
        timer::read_timer_count_64(),
        u64::from(deadline_us) * timer::timer_freq() / 1_000_000,
    );
}

fn step_guard_post_check() {
    use fluxor::kernel::exec::step_guard;
    if !step_guard::is_armed() {
        return;
    }
    let (at, deadline) = step_guard::window();
    let took = timer::read_timer_count_64().wrapping_sub(at);
    if took >= deadline {
        step_guard::set_timed_out();
        // Where the step was when the tick last interrupted it: what made it
        // long, when that was not the module's own work.
        let core = (current_core_id() as usize).min(exception::CORE_LAST_ELR.len() - 1);
        let pc = exception::CORE_LAST_ELR[core].load(Ordering::Relaxed);
        log::warn!(
            "[guard] overrun took_us={} last_tick_pc={pc:#x}",
            took * 1_000_000 / timer::timer_freq().max(1)
        );
    }
    step_guard::set_armed(false);
}

fn sleep_until(_deadline_us: u64) -> u32 {
    // SAFETY: parks the core until an interrupt; the periodic tick is armed.
    unsafe { core::arch::asm!("wfi") };
    hal::WOKEN_UNKNOWN
}

/// Make code written through the data cache fetchable before it runs: clean it
/// to the point of unification by the smallest data-cache line `CTR_EL0`
/// reports, then invalidate every core's instruction cache (ARM DDI 0487, the
/// sequence for modified code). A region that is not to be executed needs
/// nothing: the kernel's RAM is mapped writable and executable.
fn ota_stage_protect(base: *mut u8, len: usize, executable: bool) -> bool {
    if !executable {
        return true;
    }
    let ctr: u64;
    // SAFETY: reads an identification register.
    unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let line = 4usize << ((ctr >> 16) & 0xF);
    let end = (base as usize).saturating_add(len);
    let mut p = base as usize & !(line - 1);
    while p < end {
        // SAFETY: cache maintenance by address over the caller's mapped region.
        unsafe { core::arch::asm!("dc cvau, {}", in(reg) p, options(nostack, preserves_flags)) };
        p += line;
    }
    // SAFETY: barriers and an instruction-cache invalidate; no data effects.
    unsafe {
        core::arch::asm!(
            "dsb ish",
            "ic ialluis",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        )
    };
    true
}

static mut SEED: [u8; 32] = [0; 32];
static SEEDED: AtomicBool = AtomicBool::new(false);

/// The core's RNDR, if `ID_AA64ISAR0_EL1` says it has one and it delivered.
fn rndr() -> Option<u64> {
    let isar0: u64;
    // SAFETY: reads an identification register.
    unsafe {
        core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack))
    };
    if (isar0 >> 60) & 0xF == 0 {
        return None;
    }
    let (value, ok): (u64, u64);
    // SAFETY: the register exists, by the check above; NZCV says whether it
    // delivered.
    unsafe {
        core::arch::asm!(
            "mrs {v}, s3_3_c2_c4_0",
            "cset {o}, ne",
            v = out(reg) value,
            o = out(reg) ok,
            options(nomem, nostack),
        );
    }
    (ok != 0).then_some(value)
}

/// Mix the firmware's bytes and the core's into the pool. Returns which sources
/// gave anything: `(firmware, rndr)`.
pub fn seed_entropy(firmware: &[u8]) -> (bool, bool) {
    let hardware = rndr();
    let mut h = sha256::Sha256::new();
    h.update(firmware);
    if let Some(v) = hardware {
        h.update(&v.to_le_bytes());
    }
    h.update(&timer::read_timer_count_64().to_le_bytes());
    let digest = h.finalize();
    // SAFETY: the boot core, before any module can ask for bytes.
    unsafe { SEED = digest };
    let sources = (!firmware.is_empty(), hardware.is_some());
    SEEDED.store(sources.0 || sources.1, Ordering::Release);
    sources
}

fn csprng_fill(buf: *mut u8, len: usize) -> i32 {
    if !SEEDED.load(Ordering::Acquire) {
        return -1;
    }
    // SAFETY: stepped on one core, with interrupts unable to reach this pool.
    let state = unsafe { SEED };
    let mut block = 0u64;
    let mut done = 0usize;
    let fresh = rndr().unwrap_or(0);
    while done < len {
        let mut h = sha256::Sha256::new();
        h.update(&state);
        h.update(&[1]);
        h.update(&block.to_le_bytes());
        h.update(&fresh.to_le_bytes());
        let out = h.finalize();
        let take = out.len().min(len - done);
        // SAFETY: `buf` holds `len` bytes, by the caller's contract.
        unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), buf.add(done), take) };
        done += take;
        block += 1;
    }
    // Ratchet, so bytes already handed out cannot be recomputed from the pool.
    let mut h = sha256::Sha256::new();
    h.update(&state);
    h.update(&[2]);
    h.update(&fresh.to_le_bytes());
    let next = h.finalize();
    // SAFETY: as above.
    unsafe { SEED = next };
    0
}

unsafe fn net_policy_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use fluxor::abi::contracts::net::policy::caps;
    let mut c = caps::FILTER | caps::EGRESS | caps::DNAT_LOCAL;
    if fluxor::kernel::net_policy::enforcer_attached() {
        c |= caps::ENFORCED;
    }
    fluxor::kernel::net_policy::dispatch(c, None, handle, opcode, arg, arg_len)
}

unsafe fn net_route_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    fluxor::kernel::net_route::dispatch(None, handle, opcode, arg, arg_len)
}

fn init_providers() {
    use fluxor::kernel::module::provider::{self, contract};
    provider::register(contract::NET_POLICY, net_policy_dispatch);
    provider::register(contract::NET_ROUTE, net_route_dispatch);
    fluxor::kernel::module::syscalls::register_system_extension(super::devices::dispatch);
}

pub static HAL_OPS: HalOps = HalOps {
    disable_interrupts,
    restore_interrupts,
    wake_scheduler,
    now_millis,
    now_micros,
    now_unix_millis: || fluxor::kernel::sys::time_sync::unix_millis(now_micros()),
    clock_sync_status: || fluxor::kernel::sys::time_sync::status(now_micros()),
    seal_provenance: || hal::SealProvenance::None,
    seal: |_, _, _| None,
    unseal: |_, _, _| None,
    seal_blob_write: |_, _| false,
    seal_blob_store: || false,
    seal_blob_delete: |_| true,
    seal_blob_read: |_, _| None,
    seal_blob_ready: || true,
    tick_count: || now_millis() as u32,
    flash_base: || 0,
    flash_end: || 0,
    apply_code_bit: |addr| addr,
    validate_fn_addr: |addr| addr != 0 && addr & 0x3 == 0,
    validate_module_base: |addr| addr != 0 && addr & 0x3 == 0,
    validate_fn_in_code: |addr, base, size| {
        base != 0 && size != 0 && addr >= base && addr < base.saturating_add(size as usize)
    },
    verify_integrity: |computed, expected| computed == expected,
    ota_stage_protect,
    pic_barrier: || {
        // SAFETY: barriers after a module call; no memory effects of their own.
        unsafe { core::arch::asm!("dsb sy", "isb") };
    },
    step_guard_init: || {},
    step_guard_arm,
    step_guard_disarm: || fluxor::kernel::exec::step_guard::set_armed(false),
    step_guard_post_check,
    read_cycle_count,
    isr_tier_init: || {},
    isr_tier_start: |_| {},
    isr_tier_stop: || {},
    isr_tier_poll: || {},
    init_providers,
    release_module_handles: |_| {},
    boot_scan: || {},
    runtime_params: |_, _| hal::RuntimeParams::Compiled,
    init_gpio: |_| 0,
    csprng_fill,
    core_id,
    irq_bind: gic::irq_bind,
    sleep_until,
    smp_quiesce_peers: fluxor::kernel::exec::domains::quiesce_peers,
    smp_release_peers: fluxor::kernel::exec::domains::release_quiesce,
    smp_max_domains: || fluxor::kernel::exec::scheduler::MAX_DOMAINS,
    protection_set_enabled: |_| {},
    protection_reset: || {},
    protection_register_module: |_, _, _, _, _, _, _| false,
    protection_release_module: |_| {},
    protection_gateway_table: core::ptr::null,
    protected_call: fluxor::arch::aarch64::isolation::protected_call,
    protection_map_page: |_, _, _, _| {},
    protection_unmap_page: |_, _| {},
    stack_fence_arm: |_| {},
    stack_fence_intact: || true,
    serial_write: super::serial_write,
};

// Platform: RP family (RP2040, RP2350A/B) — Cortex-M.
//
// One thread, one loop: the reset vector, clock bring-up, USB device stack
// and step loop are all this tree's own, and the graph is stepped from a
// single synchronous loop that idles in `WFE`.

use fluxor::platform::rp_io::pio as pio_util;

use fluxor::kernel::exec::scheduler::{self, setup, RunnerConfig, StepResult};
use fluxor::kernel::module::syscalls;
use fluxor::platform::planner::Hardware;
use fluxor::platform::planner::{self, PioRole};


/// HAL `irq_bind` for RP: enable the NVIC line for a Tier 2 module's IRQ so it
/// dispatches through the vector table's default interrupt handler →
/// `isr_tier2_trampoline`. The `event_handle` / `trampoline` parameters are
/// unused on RP (dispatch is by IRQ number). Returns 0.
fn rp_irq_bind(irq: u32, _event_handle: i32, _trampoline_or_mmio: usize, _target_core: u8) -> i32 {
    // NVIC line ceiling, from the rp-pac `Interrupt` enum: the highest line on
    // each chip is SWI_IRQ_5 — 31 on RP2040, 52 on RP235x. The build-time
    // ISR-tier validator rejects out-of-range IRQs; this is the runtime backstop
    // — `NVIC::unmask` past the ceiling would index the ISER/ICER registers out
    // of bounds.
    #[cfg(feature = "chip-rp2040")]
    const NVIC_IRQ_MAX: u32 = 31;
    #[cfg(not(feature = "chip-rp2040"))]
    const NVIC_IRQ_MAX: u32 = 52;
    if irq > NVIC_IRQ_MAX {
        return fluxor::kernel::sys::errno::EINVAL;
    }
    // Unmasking is sound: the line only fires once its peripheral asserts,
    // and an unowned fire is masked by `DefaultHandler`. A number outside the
    // NVIC window is refused rather than wrapped onto another line.
    if !fluxor::arch::cortex_m::nvic_unmask(irq as u16) {
        return fluxor::kernel::sys::errno::EINVAL;
    }
    0
}

// ============================================================================
// Log backend — formats log records into the kernel log ring.
// ============================================================================
//
// The log backend on RP. Every log crate record
// becomes plain UTF-8 bytes in `kernel::sys::log_ring`, which is the canonical
// log bus across all boards. A transport overlay (`log_net`, `log_usb`,
// `log_uart`) drains the ring and forwards the bytes on its wire; if no
// overlay is loaded, log output stays in the ring until it overflows and
// drops.

struct RingLogger;

impl log::Log for RingLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        use core::fmt::Write;

        // Format into a stack buffer first. A full log line fits in 256 B
        // in practice; anything longer gets truncated to the buffer limit
        // rather than spilling into adjacent bytes. The alternative —
        // formatting byte-by-byte into the ring — is O(lines × capacity)
        // of atomic RMWs per log event, which is too heavy for the hot path.
        struct BufWriter<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }
        impl<'a> Write for BufWriter<'a> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let remaining = self.buf.len().saturating_sub(self.pos);
                let take = bytes.len().min(remaining);
                self.buf[self.pos..self.pos + take].copy_from_slice(&bytes[..take]);
                self.pos += take;
                Ok(())
            }
        }

        let mut buf = [0u8; 256];
        let written = {
            let mut w = BufWriter {
                buf: &mut buf,
                pos: 0,
            };
            let _ = core::fmt::write(&mut w, *record.args());
            if w.pos + 2 <= w.buf.len() {
                w.buf[w.pos] = b'\r';
                w.buf[w.pos + 1] = b'\n';
                w.pos += 2;
            }
            w.pos
        };
        fluxor::kernel::sys::log_ring::push_bytes(&buf[..written]);
    }
    fn flush(&self) {}
}

static RING_LOGGER: RingLogger = RingLogger;

fn init_logger() {
    // SAFETY: called exactly once at boot, before any task spawns;
    // set_max_level_racy / set_logger_racy work on Cortex-M0+ which
    // lacks target_has_atomic = "ptr".
    unsafe {
        let _ = log::set_logger_racy(&RING_LOGGER);
        log::set_max_level_racy(log::LevelFilter::Info);
    }
}

// ── The console sink ─────────────────────────────────────────────────────

struct RpUsbSink;

impl fluxor::platform::debug::DebugTx for RpUsbSink {
    fn write(&mut self, bytes: &[u8]) -> usize {
        // Only what the CDC ring can hold; the drain keeps the rest pending
        // and offers it again next pass. Pushing everything and letting the
        // ring discard its oldest would lose exactly the lines a reader
        // opening the port is there for — the backlog is released all at
        // once, and it is larger than the ring.
        let accepted = {
            let cdc = usb().pump.cdc();
            let n = bytes.len().min(cdc.free());
            cdc.write(&bytes[..n]);
            n
        };
        // The UART takes what fits and no more — and only the bytes the CDC
        // side accepted, so a retry does not repeat them. Waiting for room
        // holds this loop for tens of milliseconds a chunk, and this loop is
        // also the one servicing the USB device stack; a host gives up on a
        // device that cannot answer within a frame or two, so a burst of
        // console output at boot would take the board off the bus before it
        // ever enumerates. The console must not be able to do that to the
        // thing it is reporting on.
        for b in &bytes[..accepted] {
            if !fluxor::platform::rp_uart::try_write_byte(*b) {
                break;
            }
        }
        accepted
    }
}

static mut DEBUG_DRAIN: fluxor::platform::debug::DebugDrain<256> =
    fluxor::platform::debug::DebugDrain::new();
static mut DEBUG_SINK: RpUsbSink = RpUsbSink;

/// Drain queued log bytes into the console sink. Called from the step loop only.
#[inline]
fn debug_drain_poll() {
    // SAFETY: single consumer of `log_ring`; the step loop is the only
    // caller (no ISR touches DEBUG_DRAIN).
    unsafe {
        let drain_p = &raw mut DEBUG_DRAIN;
        let sink_p = &raw mut DEBUG_SINK;
        let drain = &mut *drain_p;
        let sink = &mut *sink_p;
        drain.poll(sink);
    }
}


/// Hardware bring-up, shared by both runtimes.
///
/// Resolves the resource plan, boots the kernel, and configures the buses and
/// pins the plan names. None of it is runtime-specific, and one copy is what
/// keeps the two runtimes from diverging on the sequence that reaches the
/// hardware.
///
/// Returns the resolved hardware, or `None` when the plan cannot be
/// satisfied. How to park on failure is the runtime's own — it is the only
/// part of this sequence that is.
fn rp_boot_hardware() -> Option<(Hardware, planner::ResourcePlan)> {
    log::info!("[fluxor] starting");

    // --- Resolve resource plan (max_gpio from config target) ---
    let hw = Hardware::new();
    let max_gpio = hw.raw_config().max_gpio;
    fluxor::platform::rp_io::gpio::set_runtime_max_gpio(max_gpio);
    let plan = match planner::resolve(hw.raw_config(), max_gpio) {
        Ok(p) => p,
        Err(e) => {
            log::error!("[boot] resource conflict: {e:?}");
            return None;
        }
    };

    planner::log_plan(&plan);

    // HAL ops, syscall table, providers — must run before any bus
    // init so module syscalls reach a populated dispatch table.
    fluxor::kernel::boot(&RP_HAL_OPS);

    // --- SPI: mark available buses (PIC module does actual peripheral init) ---
    for spi_cfg in plan.spi.iter().flatten() {
        syscalls::mark_spi_initialized(spi_cfg.bus);
    }

    // --- I2C: mark available buses (PIC module does actual peripheral init) ---
    for i2c_cfg in plan.i2c.iter().flatten() {
        syscalls::mark_i2c_initialized(i2c_cfg.bus);
        log::info!(
            "[boot] i2c{} sda={} scl={}",
            i2c_cfg.bus,
            i2c_cfg.sda,
            i2c_cfg.scl
        );
    }

    // --- GPIO ---
    hw.init_gpio();

    // --- PIO pin setup from plan (PIC pio_stream module handles SM/DMA at runtime) ---
    for entry in plan.pio.iter().flatten() {
        let pull = match entry.role {
            PioRole::Cmd => pio_util::PioPull::None,
            _ => pio_util::PioPull::PullUp,
        };
        pio_util::setup_pio_pin(entry.data_pin, entry.pio_idx, pull);
        if entry.clk_pin != 0xFF {
            pio_util::setup_pio_pin(entry.clk_pin, entry.pio_idx, pull);
        }
        if entry.extra_pin != 0xFF {
            pio_util::setup_pio_pin(entry.extra_pin, entry.pio_idx, pull);
        }
        log::info!(
            "[boot] pio{} {:?} data={} clk={} extra={}",
            entry.pio_idx,
            entry.role,
            entry.data_pin,
            entry.clk_pin,
            entry.extra_pin
        );
    }

    // PIO blocks are accessed via raw PAC through the PIO register bridge
    // (provider_call opcodes 0x0C70-0x0C7B). PIC pio_stream module
    // manages SM/DMA at runtime.

    Some((hw, plan))
}

// ============================================================================
// RP HAL Ops — function pointer table for all platform-specific operations
// ============================================================================

use fluxor::kernel::exec::bare_metal::WakeLatch;
use fluxor::kernel::sys::hal::HalOps;

/// Scheduler wake latch. Producers set it and then `SEV`; the synchronous
/// `sleep_until` HAL entry consumes it. Latch first, event second — the
/// reverse order loses a wake whenever the consumer's `WFE` returns between
/// the two.
pub static SCHEDULER_WAKE: WakeLatch = WakeLatch::new();

fn rp_disable_interrupts() -> u32 {
    let primask: u32;
    // SAFETY: MRS PRIMASK + CPSID i are interrupt-control instructions
    // on Cortex-M; no operands beyond the register variable.
    unsafe {
        core::arch::asm!(
            "mrs {}, PRIMASK",
            "cpsid i",
            out(reg) primask,
            options(nomem, nostack, preserves_flags),
        );
    }
    primask
}

fn rp_restore_interrupts(saved: u32) {
    // SAFETY: MSR PRIMASK restores the prior interrupt-disable mask;
    // counterpart to rp_disable_interrupts above.
    unsafe {
        core::arch::asm!(
            "msr PRIMASK, {}",
            in(reg) saved,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn rp_wake_scheduler() {
    // Latch first, event second. The reverse order loses a wake whenever the
    // consumer's `WFE` returns between the two.
    SCHEDULER_WAKE.signal();
    fluxor::arch::cortex_m::sev();
}

// All three read one counter (`platform::rp_timer`), which is also the one
// `step_guard` arms its alarms from. A second clock sharing only the rate
// would let a deadline and the guard measuring it disagree.

fn rp_now_millis() -> u64 {
    fluxor::platform::rp_timer::now_ms()
}

fn rp_now_micros() -> u64 {
    fluxor::platform::rp_timer::now_us()
}

fn rp_tick_count() -> u32 {
    fluxor::platform::rp_timer::now_ms() as u32
}

/// Portable `sleep_until`: park until the deadline or a wake.
///
/// Arms the scheduler's own alarm so the core is woken at the deadline, then
/// parks on `WFE` until the latch is set or the clock passes it. The wake
/// reason is decided by re-reading the clock and the latch — never by
/// trusting which interrupt fired — so a spurious `WFE` return cannot be
/// mistaken for either.
fn rp_sleep_until(deadline_us: u64) -> u32 {
    fluxor::platform::rp_timer::arm_scheduler_alarm(deadline_us);
    let reason = fluxor::kernel::exec::bare_metal::wait_for_wake(
        &SCHEDULER_WAKE,
        deadline_us,
        fluxor::platform::rp_timer::now_us,
        fluxor::arch::cortex_m::wfe,
    );
    // Always disarm: an alarm left over from an abandoned deadline fires
    // later against a deadline nobody is waiting for.
    fluxor::platform::rp_timer::disarm_scheduler_alarm();
    reason
}

// Flash bounds come from linker symbols declared in
// `linker/memory-rp2350.x` / `linker/memory-rp2040.x` (`__flash_start__` /
// `__flash_end__`) rather than being hardcoded. The linker's view is
// the authoritative one — RP2350 ships with a 4 MiB flash region and
// RP2040 with 2 MiB, so any constant baked into the kernel would
// either be permissive (admitting tampered addresses past the real
// end) or fragile across silicon variants.
extern "C" {
    static __flash_start__: u8;
    static __flash_end__: u8;
}

#[inline(always)]
fn flash_start() -> usize {
    // SAFETY: linker-defined symbol; we only take its address, never deref.
    unsafe { &__flash_start__ as *const u8 as usize }
}
#[inline(always)]
fn flash_end_addr() -> usize {
    // SAFETY: linker-defined symbol; we only take its address, never deref.
    unsafe { &__flash_end__ as *const u8 as usize }
}

fn rp_flash_base() -> usize {
    flash_start()
}
fn rp_flash_end() -> usize {
    flash_end_addr()
}
fn rp_apply_code_bit(addr: usize) -> usize {
    addr | 1
}

fn rp_validate_fn_addr(addr: usize) -> bool {
    if addr & 1 == 0 {
        return false;
    }
    let instr_addr = addr & !1;
    (flash_start()..flash_end_addr()).contains(&instr_addr)
}

fn rp_validate_module_base(addr: usize) -> bool {
    (flash_start()..flash_end_addr()).contains(&addr)
}

fn rp_validate_fn_in_code(addr: usize, code_base: usize, code_size: u32) -> bool {
    let fn_addr = addr & !1;
    let code_end = code_base.wrapping_add(code_size as usize);
    fn_addr >= code_base && fn_addr < code_end
}

fn rp_verify_integrity(computed: &[u8], expected: &[u8]) -> bool {
    computed == expected
}

/// RP has no RAM OTA staging surface — OTA delivery is the flash
/// graph-slot A/B path (`graph_slot` + `ota_ingest`).
fn rp_ota_stage_protect(_base: *mut u8, _len: usize, _executable: bool) -> bool {
    false
}

fn rp_pic_barrier() {
    fluxor::arch::cortex_m::dsb();
    fluxor::arch::cortex_m::isb();
    if !fluxor::arch::cortex_m::primask_is_active() {
        // SAFETY: counter increment + interrupt re-enable; we only enable
        // when PRIMASK shows IRQs were already enabled (mirroring caller state).
        unsafe {
            fluxor::kernel::module::loader::increment_irq_disabled_count();
            fluxor::arch::cortex_m::enable_interrupts();
        }
    }
}

use fluxor::platform::rp_step_guard as step_guard_backend;

fn rp_step_guard_post_check() {
    // No-op on Cortex-M
}

fn rp_read_cycle_count() -> u32 {
    // SAFETY: DWT CYCCNT at 0xE000_1004 is a Cortex-M debug-block register.
    unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
}

fn rp_isr_tier_init() {
    // SAFETY: DEMCR (TRCENA) and DWT_CTRL (CYCCNTENA) are Cortex-M debug
    // registers; single boot-thread enabler.
    unsafe {
        let demcr = 0xE000_EDFC as *mut u32;
        let val = core::ptr::read_volatile(demcr);
        core::ptr::write_volatile(demcr, val | (1 << 24));
        let dwt_ctrl = 0xE000_1000 as *mut u32;
        let val = core::ptr::read_volatile(dwt_ctrl);
        core::ptr::write_volatile(dwt_ctrl, val | 1);
    }
}

fn rp_isr_tier_start(period_us: u32) {
    step_guard_backend::rp_isr_backend_start(period_us);
}

fn rp_isr_tier_stop() {
    step_guard_backend::rp_isr_backend_stop();
}

fn rp_isr_tier_poll() {
    // No-op on Cortex-M
}

fn rp_init_providers() {
    fluxor::platform::rp_providers::init();
}

fn rp_release_module_handles(module_idx: u8) {
    fluxor::platform::rp_providers::release_handles(module_idx);
}

fn rp_boot_scan() {
    fluxor::platform::rp_flash::store::boot_scan();
}

fn rp_merge_runtime_overrides(module_id: u16, buf: *mut u8, len: usize, max: usize) -> usize {
    // SAFETY: forwards buf/len/max from the kernel's persistent-storage
    // caller; flash_store::merge_runtime_overrides documents the contract.
    unsafe {
        fluxor::platform::rp_flash::store::merge_runtime_overrides(module_id as u8, buf, len, max)
    }
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

static RP_HAL_OPS: HalOps = HalOps {
    // No durable home for a sealed blob on this platform yet, and saying so
    // is the point: the vault keeps its in-RAM entry and behaves exactly as
    // before. A platform gains cold-restart persistence by implementing
    // these two and loses nothing by not.
    seal_blob_write: |_, _| false,
    seal_blob_read: |_, _| None,
    disable_interrupts: rp_disable_interrupts,
    restore_interrupts: rp_restore_interrupts,
    wake_scheduler: rp_wake_scheduler,
    now_millis: rp_now_millis,
    now_unix_millis: || 0, // no RTC on this platform
    // No RTC, so nothing to say about its synchronisation either.
    // `None` rather than `Some((false, _))`: this board cannot tell, which
    // is a different fact from telling us the clock is unsynchronised.
    clock_sync_status: || None,
    // No sealing on this platform yet.
    //
    // `None` rather than a host-readable stand-in: a sealing key stored in
    // flash beside the blob it seals protects nothing and would still read
    // as `HostReadable`, which is a stronger claim than the truth. bcm2712
    // has OTP fuses that could back `DeviceUnique` — claiming it requires
    // actually deriving from them, and a provenance that overstates itself
    // raises a vault's isolation tier and with it what a deployment
    // believes about keys it has not protected.
    seal_provenance: || fluxor::kernel::sys::hal::SealProvenance::None,
    seal: |_, _| None,
    unseal: |_, _| None,
    now_micros: rp_now_micros,
    tick_count: rp_tick_count,
    flash_base: rp_flash_base,
    flash_end: rp_flash_end,
    apply_code_bit: rp_apply_code_bit,
    validate_fn_addr: rp_validate_fn_addr,
    validate_module_base: rp_validate_module_base,
    validate_fn_in_code: rp_validate_fn_in_code,
    verify_integrity: rp_verify_integrity,
    ota_stage_protect: rp_ota_stage_protect,
    pic_barrier: rp_pic_barrier,
    step_guard_init: step_guard_backend::rp_step_guard_init,
    step_guard_arm: step_guard_backend::rp_step_guard_arm,
    step_guard_disarm: step_guard_backend::rp_step_guard_disarm,
    step_guard_post_check: rp_step_guard_post_check,
    read_cycle_count: rp_read_cycle_count,
    isr_tier_init: rp_isr_tier_init,
    isr_tier_start: rp_isr_tier_start,
    isr_tier_stop: rp_isr_tier_stop,
    isr_tier_poll: rp_isr_tier_poll,
    init_providers: rp_init_providers,
    release_module_handles: rp_release_module_handles,
    boot_scan: rp_boot_scan,
    merge_runtime_overrides: rp_merge_runtime_overrides,
    init_gpio: |gpio| fluxor::platform::rp_io::gpio::init_all_from_config(gpio),
    csprng_fill: rp_csprng_fill,
    core_id: || 0,
    irq_bind: rp_irq_bind,
    sleep_until: rp_sleep_until,
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
    // Bytes for the console, written directly rather than through the log
    // ring: the fallback UART, which exists whether or not a host has the
    // CDC port open.
    serial_write: |b| {
        for byte in b {
            fluxor::platform::rp_uart::write_byte(*byte);
        }
        b.len()
    },
};

/// Fill a buffer with conditioned entropy.
///
/// Delegates to [`rp_entropy`], which owns the source choice: RP2350's
/// hardware TRNG with its health tests, or RP2040's ring oscillator paced as
/// the datasheet requires. Either way the raw source is hashed before it
/// reaches a caller.
///
/// **Fails closed.** A health-test failure or a source timeout returns an
/// error rather than whatever bytes were collected. The alternative is worse
/// than useless: output from a failed source still looks random to anyone not
/// testing for it, so a silent fallback would hide exactly the condition the
/// health test exists to surface.
///
/// Returns 0 on success, negative errno on failure — the
/// [`HalOps::csprng_fill`] contract. A byte count is not a success value
/// here: callers test the result against 0, so returning `len` reads as a
/// failure for every non-empty fill.
///
/// [`HalOps::csprng_fill`]: crate::kernel::sys::hal::HalOps::csprng_fill
/// [`rp_entropy`]: fluxor::platform::rp_entropy
fn rp_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    // SAFETY: caller is `hal::csprng_fill`, which guarantees `buf` is valid
    // for `len` bytes and is not aliased for the duration of this call.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    match fluxor::platform::rp_entropy::fill_conditioned(out) {
        Ok(()) => 0,
        Err(e) => {
            // Leave no usable bytes behind: a caller that ignores the return
            // value must not find plausible-looking key material.
            out.fill(0);
            log::error!("[entropy] refusing to produce key material: {e:?}");
            fluxor::kernel::sys::errno::ERROR
        }
    }
}

// ============================================================================
// Async graph setup and main loop (moved from scheduler.rs)
// ============================================================================

/// Graph setup.
///
/// The shared walk, with a bounded spin on the monotonic clock between
/// polls. The spin is sound only because nothing else runs yet — this is
/// boot, before the step loop.
fn rp_setup_graph() -> i32 {
    use fluxor::kernel::exec::graph_build::GraphWalk;

    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Ownership must be live before any provider handle is opened.
    if let Err(e) = fluxor::kernel::exec::bare_metal::apply_owner_plan() {
        log::error!("[owner] staged plan invalid ({e:?}); refusing the graph");
        return -1;
    }

    // SAFETY: shared globals; this is the only thread and the scheduler runs
    // serially within it.
    let loader = unsafe { scheduler::static_loader() };
    // SAFETY: as above.
    let sched = unsafe { scheduler::sched_mut() };

    let mut walk = GraphWalk::new(module_count);
    while !walk.is_finished() {
        let module_idx = walk.next_entry();
        let Some(entry) = module_list[module_idx].as_ref() else {
            walk.advance_skipped();
            continue;
        };

        let instantiated = walk.instantiated();
        scheduler::set_current_module(instantiated);
        match scheduler::instantiate_one_module(
            loader,
            entry,
            module_idx,
            instantiated,
            &mut sched.edges,
            &mut sched.modules,
            &mut sched.ports,
        ) {
            scheduler::InstantiateResult::Done => {}
            scheduler::InstantiateResult::Pending(mut pending) => {
                let mut settled = false;
                loop {
                    rp_spin_ms(1);
                    if !walk.record_poll() {
                        break;
                    }
                    // SAFETY: `pending` is owned here and not aliased.
                    match unsafe { pending.try_complete() } {
                        Ok(Some(dynamic)) => {
                            sched.modules[instantiated] = scheduler::ModuleSlot::Dynamic(dynamic);
                            settled = true;
                            break;
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            e.log("scheduler");
                            return -1;
                        }
                    }
                }
                if !settled {
                    log::error!(
                        "[inst] module={module_idx} pending timeout after {} polls",
                        walk.polls()
                    );
                    return -1;
                }
            }
            scheduler::InstantiateResult::Error(e) => {
                log::error!("[inst] failed module={module_idx} error={e}");
                return e;
            }
        }

        fluxor::platform::rp_io::gpio::grant_pending_pins(walk.instantiated() as u8);
        walk.advance_instantiated();
        rp_spin_ms(1);
    }

    let result = walk.instantiated() as i32;
    scheduler::compute_downstream_latency(sched, module_count);
    result
}

/// Spin for roughly `ms` milliseconds on the monotonic clock.
///
/// Only used during boot, where nothing else is running. Bounded by
/// the clock rather than a cycle count, so it does not change with the
/// system frequency.
fn rp_spin_ms(ms: u64) {
    let deadline = fluxor::platform::rp_timer::now_us().saturating_add(ms * 1000);
    while fluxor::platform::rp_timer::now_us() < deadline {
        fluxor::arch::cortex_m::nop();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use fluxor::kernel::exec::scheduler::{CRASH_DATA, CRASH_MAGIC};

    let crash = (&raw mut CRASH_DATA) as *mut u32;
    // SAFETY: an 8-word .uninit array; magic written last so a recorder that
    // faults part-way leaves an incomplete record reading as invalid.
    unsafe {
        core::ptr::write_volatile(crash.add(1), PANIC_MARKER);
        core::ptr::write_volatile(crash, CRASH_MAGIC);
    }

    fluxor::platform::rp_uart::write_str("[fluxor] panic: ");
    if let Some(loc) = info.location() {
        fluxor::platform::rp_uart::write_str(loc.file());
    }
    fluxor::platform::rp_uart::write_str("\r\n");
    fluxor::platform::rp_uart::flush();

    if fluxor::arch::cortex_m::debugger_attached() {
        loop {
            fluxor::arch::cortex_m::nop();
        }
    }
    fluxor::arch::cortex_m::system_reset()
}

/// Written where the fault handler puts the faulting PC, so a crash record
/// from a panic is distinguishable from one from a fault.
const PANIC_MARKER: u32 = 0x5041_4E49; // "PANI"

/// The entry point, called by the reset handler once `.data` and `.bss` are
/// initialised (`platform/rp/boot.rs` declares it `extern "C"`).
///
/// Brings up the console and the clock tree, disables the watchdog, starts
/// the monotonic tick, attaches the USB device stack, plans the hardware,
/// builds the graph and runs it. Every failure parks with the device stack
/// still running, so the reason reaches the console.
///
/// # Safety
/// Called once, by the reset handler, with statics initialised and nothing
/// else running.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fluxor_rp_main() -> ! {
    use fluxor::platform::chip::{SYS_CLK_HZ, XOSC_HZ};

    // The console before the PLLs, running from the crystal.
    //
    // `clk_peri` is disabled out of reset, so a UART brought up before this
    // has no clock at all: it takes a few bytes into its FIFO, never shifts
    // them out, and drops the rest. The console would then be silent for
    // exactly the window it exists to cover — everything up to and including
    // clock bring-up, which is where a boot is most likely to die.
    //
    // If even the crystal will not start there is nothing left to report
    // with, so that case parks. A board dead this early is dead before any
    // instrument exists, and saying so requires the instrument.
    match fluxor::platform::rp_clocks::bringup::start_peri_from_xosc(XOSC_HZ) {
        Ok(peri_hz) => {
            fluxor::platform::rp_uart::init(peri_hz);
            fluxor::platform::rp_uart::write_str("[fluxor] boot\r\n");
        }
        Err(_) => loop {
            fluxor::arch::cortex_m::nop();
        },
    }

    // The clock tree. Everything after this depends on it, and nothing
    // before it does.
    let clocks_up = fluxor::platform::rp_clocks::bringup::init(XOSC_HZ, SYS_CLK_HZ);

    // `init` re-parents `clk_peri` onto `clk_sys` as its last act, so on
    // success the divisors computed against the crystal are now wrong by the
    // PLL's whole multiplier. On failure it returned before that write and
    // the crystal is still the parent. Re-init against whichever actually
    // happened — getting this backwards turns the message describing the
    // failure into garbage on the wire.
    fluxor::platform::rp_uart::init(if clocks_up.is_ok() {
        SYS_CLK_HZ
    } else {
        XOSC_HZ
    });

    match clocks_up {
        Ok(_) => fluxor::platform::rp_uart::write_str("[fluxor] clocks up\r\n"),
        Err(_e) => {
            // Continuing on an unconfigured clock tree would run every
            // timer, baud rate and transfer at the wrong speed.
            fluxor::platform::rp_uart::write_str("[fluxor] clock bring-up FAILED\r\n");
            fluxor::platform::rp_uart::flush();
            loop {
                fluxor::arch::cortex_m::nop();
            }
        }
    }

    // Everything else out of reset, now the clock tree that feeds it is up.
    //
    // SPI, PIO, DMA, the GPIO banks and the timers are all held in reset out of
    // power-on; a driver configuring one before this writes into a
    // peripheral that keeps its reset values and reports nothing wrong.
    if !fluxor::platform::rp_clocks::bringup::release_peripherals() {
        fluxor::platform::rp_uart::write_str("[fluxor] peripherals stuck in reset\r\n");
        fluxor::platform::rp_uart::flush();
        loop {
            fluxor::arch::cortex_m::nop();
        }
    }

    // The bootloader may have left the watchdog running and nothing here
    // feeds it.
    // SAFETY: a fixed MMIO register whose address is generated from the
    // silicon TOML; single boot-thread writer.
    unsafe {
        fluxor::platform::rp_regs::write32(fluxor::platform::chip::WATCHDOG_CTRL as usize, 0);
    }

    fluxor::platform::rp_timer::init_scheduler_alarm();
    init_logger();
    fluxor::platform::rp_clocks::verify();

    // The device stack, before the graph: a host that enumerates early gets
    // the boot logs, and a failure here is reported over the UART rather
    // than inferred from silence.
    fluxor::platform::rp_uart::write_str("[fluxor] usb: bringing up\r\n");
    if fluxor::platform::rp_usb_device::init() {
        fluxor::platform::rp_usb_device::attach();
        fluxor::platform::rp_uart::write_str("[fluxor] usb: attached\r\n");
    } else {
        fluxor::platform::rp_uart::write_str(
            "[fluxor] usb: controller never left reset\r\n",
        );
    }

    let Some((hw, _plan)) = rp_boot_hardware() else {
        park_reporting("[fluxor] boot: resource plan unsatisfiable\r\n");
    };

    let config = RunnerConfig {
        spi_bus: hw.spi_bus(),
        cs_pin: hw.cs_pin(),
    };
    if !setup(&config) {
        park_reporting("[fluxor] boot: runner setup failed\r\n");
    }

    // Build, run, rebuild. The loop returns when the reconfigure module
    // asks for a rebuild; the graph is then set up again from the staged
    // configuration.
    loop {
        fluxor::platform::rp_uart::write_str("[fluxor] boot: building graph\r\n");
        let module_count = rp_setup_graph();
        if module_count < 0 {
            park_reporting("[fluxor] boot: graph setup failed\r\n");
        }
        log::info!("[boot] ready modules={module_count}");
        scheduler::log_arena_summary();
        // Tier 1b admission: hand any Tier 1b-domain modules to the ISR-tier
        // dispatcher. The step loop polls `isr_tier::poll_tier1b` each
        // iteration, so registration here is the platform's only ISR setup.
        let isr_registered = scheduler::register_isr_tier_modules_from_graph();
        if isr_registered > 0 {
            log::info!("[isr] Tier 1b admitted {isr_registered} module(s)");
        }
        match rp_run_main_loop(module_count as usize) {
            Some(_rebuild) => {
                log::info!("[reconfigure] main loop yielded, rebuilding graph");
                scheduler::set_reconfigure_phase(scheduler::ReconfigurePhase::Running);
            }
            None => park_reporting("[fluxor] graph halted\r\n"),
        }
    }
}

/// Step the graph until either a rebuild is requested (returns `Some((ptr,
/// len))`) or the graph halts (returns `None`).
///
/// One thread, one loop: the graph is stepped, the USB device stack is
/// pumped, the console is drained, and the core idles in `WFE` until the
/// earlier of the pacer's deadline and the device stack's. Nothing here can
/// wait on anything else, which is what keeps the USB pump serviced under
/// every module's behaviour.
fn rp_run_main_loop(module_count: usize) -> Option<(*const u8, usize)> {
    use fluxor::kernel::exec::bare_metal::wait_for_wake;

    // SAFETY: `sched_modules` returns a shared global; this is the only
    // thread, and the scheduler runs serially within it.
    let modules = unsafe { scheduler::sched_modules() };
    let tick_period_us = scheduler::tick_us() as u64;

    log::info!("[sched] running modules={module_count} tick_us={tick_period_us}");

    loop {
        fluxor::platform::rp_io::gpio::poll_gpio_edges();

        match scheduler::step_modules(modules, module_count) {
            StepResult::Continue => {}
            StepResult::Done => {
                log::warn!("[sched] all modules done");
                return None;
            }
            StepResult::Error(i) => {
                log::error!("[sched] step error module={i}");
                return None;
            }
        }

        fluxor::kernel::exec::isr_tier::poll_tier1b();

        // The USB device stack, as a bounded step rather than a task. This
        // is what makes idling below safe.
        let usb_service_us = rp_usb_step();

        // The scheduler's peak step time, once every few seconds. It is the
        // number that decides whether the tick can be shortened: a peak
        // over the tick is a step the guard will abort.
        {
            static mut NEXT_WORST_MS: u32 = 0;
            let now_ms = (fluxor::platform::rp_timer::now_us() / 1000) as u32;
            // SAFETY: single-threaded runtime; this loop is the only user.
            let due = unsafe { NEXT_WORST_MS } <= now_ms;
            if due {
                // SAFETY: as above.
                unsafe { NEXT_WORST_MS = now_ms.saturating_add(5000) };
                log::info!(
                    "[sched] worst_us={} tick_us={}",
                    scheduler::domain_worst_step_us(0),
                    scheduler::tick_us()
                );
            }
        }

        debug_drain_poll();

        if let Some(req) = scheduler::take_rebuild_request() {
            return Some(req);
        }

        let wake = fluxor::kernel::ipc::event::take_wake_pending();
        if !wake.is_empty() {
            scheduler::step_woken_modules(modules, module_count, &wake);
        }

        // The tighter of the two deadlines. The pacer speaks for the graph
        // and the device stack for the bus; idling past either one breaks
        // the thing that owns it.
        let sleep_us = (scheduler::pacer_next_deadline_us(0).min(usb_service_us)) as u64;
        let deadline = fluxor::platform::rp_timer::now_us().saturating_add(sleep_us);

        // Arm the alarm before parking, and disarm after.
        //
        // `WFE` wakes on an *enabled* interrupt, an `SEV`, or a spurious
        // event. Nothing else runs on this core, so
        // there is no `SEV` to come — the alarm is the only thing that can
        // end the sleep. Without it `wait_for_wake` parks on the first
        // iteration and never re-reads the clock, which stops the USB pump
        // below it and takes the board off the bus with every earlier stage
        // of boot having succeeded. `rp_sleep_until` arms the same alarm for
        // the async path, for the same reason.
        fluxor::platform::rp_timer::arm_scheduler_alarm(deadline);

        // Take before sleeping, and the latch is re-checked inside: a wake
        // that lands between the check and the `WFE` leaves the event
        // register set, so the `WFE` returns at once.
        SCHEDULER_WAKE.take();
        wait_for_wake(
            &SCHEDULER_WAKE,
            deadline,
            fluxor::platform::rp_timer::now_us,
            fluxor::arch::cortex_m::wfe,
        );
        fluxor::platform::rp_timer::disarm_scheduler_alarm();

        let wake = fluxor::kernel::ipc::event::take_wake_pending();
        if !wake.is_empty() {
            scheduler::step_woken_modules(modules, module_count, &wake);
        }
    }
}

/// Answer a `GET_DESCRIPTOR`, or `None` for anything this device does not
/// have — which the control layer turns into a STALL.
///
/// Strings are built into a static scratch buffer rather than returned from
/// one, because a string descriptor is encoded on demand. That is sound here
/// for the reason the whole platform is single-threaded: exactly one
/// control transfer is in flight at a time, and the pump finishes streaming
/// the previous one before another SETUP can arrive.
fn descriptor_for(setup: &fluxor::kernel::usb::control::Setup) -> Option<&'static [u8]> {
    use fluxor::kernel::usb::cdc_descriptors as cdc_desc;
    use fluxor::kernel::usb::control::request;
    use fluxor::kernel::usb::descriptor::desc_type;

    if setup.request != request::GET_DESCRIPTOR || !setup.is_device_to_host() {
        return None;
    }

    // `wValue` is the descriptor type in the high byte and the index in the
    // low byte — not two independent fields, which is why they are split
    // here rather than passed around as one.
    let kind = (setup.value >> 8) as u8;
    let index = setup.value as u8;

    match kind {
        desc_type::DEVICE => Some(&cdc_desc::DEVICE),
        desc_type::CONFIGURATION => Some(&cdc_desc::CONFIGURATION),
        desc_type::STRING => {
            static mut STRING_BUF: [u8; cdc_desc::STRING_DESCRIPTOR_MAX] =
                [0; cdc_desc::STRING_DESCRIPTOR_MAX];
            let ptr = &raw mut STRING_BUF;
            // Read once: the ROM call is not free and the ID does not change.
            static mut UNIQUE_ID: Option<u64> = None;
            let id_slot: *mut Option<u64> = &raw mut UNIQUE_ID;
            // SAFETY: single-threaded; this is the only user of the static,
            // and no reference to it outlives this block.
            let id = unsafe {
                if (*id_slot).is_none() {
                    *id_slot = Some(fluxor::platform::rp_bootrom::unique_id().unwrap_or(0));
                }
                (*id_slot).unwrap_or(0)
            };
            // SAFETY: single-threaded, and one control transfer at a time —
            // the pump finishes streaming the previous descriptor before
            // another SETUP can reach this function, so no second borrow of
            // this static can be live.
            let n = unsafe { cdc_desc::string_descriptor(index, id, &mut *ptr)? };
            // SAFETY: `n` bytes were just written through the same pointer,
            // and the static outlives every transfer that streams from it.
            Some(unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), n) })
        }
        _ => None,
    }
}

/// Step the device stack, and report how long the caller may idle before it
/// must be stepped again.
///
/// **The caller's own pacing is not a safe bound for this.** Enumeration is a
/// timed conversation: the host sends SETUP and expects the status stage
/// within milliseconds. This graph's pacer sleeps for its slowest sequence
/// step — half a second in the blink preset — and a device polled that
/// rarely is dropped by the host before it answers anything. Polled from the
/// main loop rather than driven by its interrupt, the stack has to say what
/// it needs.
fn rp_usb_step() -> u32 {
    use fluxor::platform::rp_usb_device as dcd;

    let usb = usb();
    let (pump, controller) = (&mut usb.pump, &mut usb.controller);

    // Give the CDC function's endpoints buffers and enable bits.
    //
    // Idempotent, and called from here rather than once at init because a
    // host may reset the bus and re-enumerate at any point; the allocator
    // skips what it has already handed out, so the steady-state cost is
    // three bit tests. Without this the descriptors describe pipes that do
    // not exist — the device enumerates, the driver binds, and nothing the
    // host writes reaches us.
    controller.configure_cdc_endpoints();

    // Collect events first, then hand them to the pump: the drain
    // acknowledges controller state as it goes, and interleaving that with
    // the pump's register writes would acknowledge events the pump has not
    // seen.
    let mut events = [None; 16];
    let mut n = 0;
    dcd::drain(events.len() as u32, |e| {
        usb_diag_count(&e);
        if n < events.len() {
            // EP0's transferred length is read at drain time, while the
            // buffer-control word still describes the completed transfer,
            // and from whichever direction the event says completed.
            let translated = dcd::translate(e, dcd::ep0_transferred);
            usb_diag_classify(&translated);
            events[n] = translated;
            n += 1;
        }
    });

    let mut i = 0;
    pump.step(
        controller,
        || {
            while i < n {
                let e = events[i].take();
                i += 1;
                if e.is_some() {
                    return e;
                }
            }
            None
        },
        descriptor_for,
    );

    /// Idle budget while the host is still enumerating us.
    ///
    /// USB 2.0 §9.2.6 gives a device 50 ms to return the first data packet
    /// of a control transfer and 5 s to complete `SET_ADDRESS`. A transfer
    /// is several transactions, each of which this stack must be polled to
    /// advance, so the budget is set an order of magnitude inside the
    /// tightest of those bounds rather than at it: one frame, which is also
    /// the rate the host is issuing them at.
    const ENUMERATING_US: u32 = 1_000;
    /// Idle budget once addressed.
    ///
    /// The conversation is over and the endpoints are configured. An IN
    /// endpoint with no buffer armed NAKs in hardware and an OUT endpoint
    /// with none armed does the same, so a host asking either of them is
    /// answered without this stack running at all: it has to be responsive,
    /// not immediate. Eight frames is short enough that a console keystroke
    /// is not perceptibly delayed.
    const ADDRESSED_US: u32 = 8_000;

    // The console has a reader exactly while a host program holds the port
    // open, which is what DTR says. The local log consumer follows it: on
    // open it starts from the oldest line the ring still holds, so a port
    // opened after boot shows the boot; on close it stops, so an unread
    // console does not hold the ring's producer back for nobody.
    {
        static mut PORT_OPEN: bool = false;
        let open = pump.cdc().dtr();
        // SAFETY: single-threaded runtime; this is the only reader/writer.
        let was_open = unsafe { core::ptr::replace(&raw mut PORT_OPEN, open) };
        if open && !was_open {
            fluxor::kernel::sys::log_ring::activate_local_from_backlog();
        } else if !open && was_open {
            fluxor::kernel::sys::log_ring::disable_local();
        }
    }

    // A reboot the host asked for over the reset interface. Taken only
    // after the pump has acknowledged it, so the host's transfer completes
    // before the device disappears — picotool's own source notes that
    // rebooting inside the request makes libusb return unpredictable
    // errors. Both entries return only on failure.
    if let Some(req) = pump.take_reboot_request() {
        use fluxor::kernel::usb::reset_interface::RebootRequest;
        use fluxor::platform::rp_bootrom as bootrom;
        log::info!("[usb] host asked for {req:?}");
        let Err(e) = match req {
            RebootRequest::Bootsel { disable_msd } => bootrom::enter_bootsel(disable_msd),
            RebootRequest::Flash => bootrom::reboot_to_flash(),
        };
        log::error!("[usb] reboot refused: {e:?}");
    }

    // Start the transmit chain if it is not already running: a completion
    // event can only continue it, never begin it.
    pump.service_cdc_tx(controller);

    usb_diag_report(pump);

    if pump.address() == 0 {
        ENUMERATING_US
    } else {
        ADDRESSED_US
    }
}

/// Park, but keep the device stack running.
///
/// A bare `loop { wfe() }` would not do: the USB pull-up is enabled before
/// the graph is built, so the host begins enumerating a device that has
/// stopped answering, and gives up. No port appears, which is
/// indistinguishable from a board that never powered on, whichever stage
/// actually failed.
///
/// The UART message these paths write is only readable with an adapter on
/// the header. Servicing the pump here means the same explanation arrives
/// over the console being brought up, which is the one a person actually
/// has.
fn park_reporting(reason: &str) -> ! {
    fluxor::platform::rp_uart::write_str(reason);
    fluxor::platform::rp_uart::flush();
    log::error!("{}", reason.trim_end());
    // Poll, never sleep. `wfe` returns only for an interrupt or event, and
    // nothing is armed here — the main loop arms the scheduler alarm before
    // each one, and this is not the main loop. A park that sleeps on the
    // first pass runs the pump exactly once, and the host never sees a
    // device answer.
    loop {
        rp_usb_step();
        debug_drain_poll();
        fluxor::arch::cortex_m::nop();
    }
}

/// Where a fault ends up: reported, then parked with the device stack still
/// running.
///
/// Called from the fault trampoline in `boot.rs` with the stacked return
/// address and the fault status registers. The report goes out three ways
/// — UART, log ring, and straight into the CDC pipe — because a fault is
/// the one message that must reach whichever console exists. The pump is
/// polled, so it runs from a fault handler as well as from anywhere else:
/// it needs no interrupt and never waits.
#[unsafe(no_mangle)]
pub extern "C" fn fluxor_fault_park(pc: u32, lr: u32, cfsr: u32, hfsr: u32, bfar: u32) -> ! {
    use core::fmt::Write as _;
    let mut w = FixedWriter {
        buf: [0; 192],
        len: 0,
    };
    let _ = write!(
        &mut w,
        "[fault] pc={pc:08x} lr={lr:08x} cfsr={cfsr:08x} hfsr={hfsr:08x} bfar={bfar:08x}\r\n"
    );
    let (buf, len) = (w.buf, w.len);
    for b in &buf[..len] {
        fluxor::platform::rp_uart::write_byte(*b);
    }
    if let Ok(text) = core::str::from_utf8(&buf[..len]) {
        log::error!("{}", text.trim_end());
    }
    usb().pump.cdc().write(&buf[..len]);
    // As `park_reporting`: poll, never `wfe` with nothing armed.
    loop {
        rp_usb_step();
        debug_drain_poll();
        fluxor::arch::cortex_m::nop();
    }
}

/// The device stack's state, as one object rather than two statics — they
/// are always used together and a single owner is one fewer thing that can
/// be taken separately.
struct Usb {
    pump: fluxor::kernel::usb::device::DevicePump,
    controller: fluxor::platform::rp_usb_device::RpDeviceController,
}

// Not a lock: this is the only thread.
static mut USB: Usb = Usb {
    pump: fluxor::kernel::usb::device::DevicePump::new(),
    controller: fluxor::platform::rp_usb_device::RpDeviceController::new(),
};

/// Borrow the device stack.
///
/// SAFETY: the platform is single-threaded, and the two callers — the
/// USB step and the console sink — run one after the other in that loop,
/// never nested. The sink writes into the CDC ring and does not log, so it
/// cannot re-enter through the logger.
#[allow(static_mut_refs, reason = "single-threaded runtime; see above")]
fn usb() -> &'static mut Usb {
    let p: *mut Usb = &raw mut USB;
    // SAFETY: single-threaded runtime, and the two callers run one after the
    // other in that loop, never nested — see above. No other reference to
    // the static exists while this one is live.
    unsafe { &mut *p }
}

/// What the bus has done to us since boot.
///
/// Counted rather than logged as it happens: at full speed the host issues
/// a transaction every frame, and a line per event would outrun any sink
/// this board has.
#[derive(Default)]
struct UsbDiag {
    bus_resets: u32,
    setups: u32,
    buffers: u32,
    suspends: u32,
    resumes: u32,
    last_setup: [u8; 8],
    /// The last few buffer-completion bitmaps, newest last, and how many
    /// have been seen. Which endpoint-directions complete together is the
    /// thing a register snapshot cannot show: by the time anything reads
    /// `BUFF_STATUS` the drain has already cleared it.
    last_masks: [u32; 6],
    mask_count: u32,
    /// How each EP0 completion was interpreted.
    ep0_data: u32,
    ep0_status: u32,
    /// What was last reported: address, configured, stalled, bus resets.
    last_reported: (u8, bool, bool, u32),
}

static mut USB_DIAG: UsbDiag = UsbDiag {
    bus_resets: 0,
    setups: 0,
    buffers: 0,
    suspends: 0,
    resumes: 0,
    last_setup: [0; 8],
    last_masks: [0; 6],
    mask_count: 0,
    ep0_data: 0,
    ep0_status: 0,
    last_reported: (0, false, false, 0),
};

/// Borrow the diagnostic counters.
///
/// SAFETY: the platform is single-threaded and both callers run from
/// the same step, so no second `&mut` can exist while this one is live.
#[allow(static_mut_refs, reason = "single-threaded runtime; see above")]
fn usb_diag() -> &'static mut UsbDiag {
    let p: *mut UsbDiag = &raw mut USB_DIAG;
    // SAFETY: single-threaded runtime; both callers run from the same step,
    // sequentially, so no second `&mut` exists while this one is live.
    unsafe { &mut *p }
}

/// Record one controller event.
fn usb_diag_count(event: &fluxor::platform::rp_usb_device::Event) {
    use fluxor::platform::rp_usb_device::Event;
    let d = usb_diag();
    match event {
        Event::BusReset => d.bus_resets += 1,
        Event::Setup(s) => {
            d.setups += 1;
            d.last_setup = [
                s.request_type,
                s.request,
                s.value as u8,
                (s.value >> 8) as u8,
                s.index as u8,
                (s.index >> 8) as u8,
                s.length as u8,
                (s.length >> 8) as u8,
            ];
        }
        Event::BuffersComplete(mask) => {
            d.buffers += 1;
            let slot = (d.mask_count as usize) % d.last_masks.len();
            d.last_masks[slot] = *mask;
            d.mask_count += 1;
        }
        Event::Suspended => d.suspends += 1,
        Event::Resumed => d.resumes += 1,
    }
}

/// A fixed buffer that can be `write!`-ed into, for text that must not go
/// through the log ring.
///
/// The ring has one consumer. When `log_net` is in the graph it drains every
/// line before the platform sink sees one, so anything written with `log::`
/// reaches the netconsole *or* the CDC console and never both. A message
/// that has to appear on the CDC pipe regardless is written straight into
/// the endpoint's ring instead.
struct FixedWriter {
    buf: [u8; 192],
    len: usize,
}

impl core::fmt::Write for FixedWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.as_bytes() {
            if self.len == self.buf.len() {
                // Truncate rather than fail: a clipped diagnostic is worth
                // more than none.
                break;
            }
            self.buf[self.len] = *b;
            self.len += 1;
        }
        Ok(())
    }
}

/// Record how an EP0 completion was interpreted.
fn usb_diag_classify(event: &Option<fluxor::kernel::usb::device::DeviceEvent>) {
    use fluxor::kernel::usb::device::DeviceEvent;
    let d = usb_diag();
    match event {
        Some(DeviceEvent::Ep0Data(_)) => d.ep0_data += 1,
        Some(DeviceEvent::Ep0Status) => d.ep0_status += 1,
        _ => {}
    }
}

/// Report the device stack's state when it changes.
///
/// One line per transition — address, configuration, a stall, a bus reset
/// — and the controller's registers only when the transition is a
/// regression, because that is when the two views disagree: a pump that
/// believes it is configured while `ADDR_ENDP` reads zero, or endpoint
/// control words left empty behind a configuration the host selected.
/// Enumeration that succeeds says so in two lines and is then silent.
fn usb_diag_report(pump: &fluxor::kernel::usb::device::DevicePump) {
    use fluxor::kernel::usb::control::Stage;

    let d = usb_diag();
    let stalled = pump.stage() == Stage::Stalled;
    let now = (pump.address(), pump.is_configured(), stalled, d.bus_resets);
    if now == d.last_reported {
        return;
    }
    // A stall is a regression unless it is the answer to a descriptor the
    // device does not have — a host probes for the device qualifier and
    // other optional descriptors and expects the STALL — so those are not
    // worth a register dump.
    let probe = d.last_setup[0] == 0x80
        && d.last_setup[1] == fluxor::kernel::usb::control::request::GET_DESCRIPTOR;
    let regressed = (stalled && !probe) || d.bus_resets != d.last_reported.3;
    d.last_reported = now;

    let s = d.last_setup;
    log::info!(
        "[usb] img={} addr={} cfg={} stage={:?} rst={} setup={} buf={} last={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        option_env!("FLUXOR_IMAGE_TAG").unwrap_or("dev"),
        pump.address(),
        u8::from(pump.is_configured()),
        pump.stage(),
        d.bus_resets,
        d.setups,
        d.buffers,
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    );
    if !regressed {
        return;
    }
    let r = fluxor::platform::rp_usb_device::registers();
    log::info!(
        "[usb] sie_st={:08x} sie_ct={:08x} addr_ep={:08x} buffst={:08x} stall={:08x} ints={:08x} masks={:02x},{:02x},{:02x},{:02x},{:02x},{:02x}",
        r.sie_status, r.sie_ctrl, r.addr_endp, r.buff_status, r.stall_nak, r.ints,
        d.last_masks[0], d.last_masks[1], d.last_masks[2],
        d.last_masks[3], d.last_masks[4], d.last_masks[5],
    );
    log::info!(
        "[usb] epctl={:08x},{:08x},{:08x},{:08x} bufctl={:08x},{:08x},{:08x},{:08x},{:08x},{:08x}",
        r.ep_control[0], r.ep_control[1], r.ep_control[2], r.ep_control[3],
        r.buf_control[0], r.buf_control[1], r.buf_control[2],
        r.buf_control[3], r.buf_control[4], r.buf_control[5],
    );
}


// Platform: RP family (RP2040, RP2350A/B) — Cortex-M, embassy async runtime

use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::dma::InterruptHandler as DmaInterruptHandler;
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, DMA_CH6, PIO0, USB};
use embassy_rp::pio::InterruptHandler as PioInterruptHandler;
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};

use fluxor::platform::rp_io::pio as pio_util;

use fluxor::platform::planner::Hardware;
use fluxor::platform::planner::{self, PioRole};
use fluxor::kernel::exec::scheduler::{self, setup, RunnerConfig, StepResult, MAX_MODULES};
use fluxor::kernel::module::syscalls;

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => PioInterruptHandler<PIO0>;
    DMA_IRQ_0 => DmaInterruptHandler<DMA_CH0>, DmaInterruptHandler<DMA_CH1>, DmaInterruptHandler<DMA_CH6>;
    USBCTRL_IRQ => UsbInterruptHandler<USB>;
});

// ============================================================================
// HardFault handler — captures crash context to .uninit RAM (survives reset)
// ============================================================================

#[cortex_m_rt::exception]
unsafe fn HardFault(ef: &cortex_m_rt::ExceptionFrame) -> ! {
    use fluxor::kernel::exec::scheduler::{CRASH_DATA, CRASH_MAGIC, DBG_STEP_MODULE, DBG_TICK};

    let crash = (&raw mut CRASH_DATA) as *mut u32;
    core::ptr::write_volatile(crash, CRASH_MAGIC);
    core::ptr::write_volatile(crash.add(1), ef.pc());
    core::ptr::write_volatile(crash.add(2), ef.lr());
    core::ptr::write_volatile(
        crash.add(3),
        core::ptr::read_volatile(&raw const DBG_STEP_MODULE) as u32,
    );
    core::ptr::write_volatile(crash.add(4), core::ptr::read_volatile(&raw const DBG_TICK));
    core::ptr::write_volatile(crash.add(5), ef.r0());
    // CFSR: Configurable Fault Status Register — tells us the fault type
    let cfsr = core::ptr::read_volatile(0xE000_ED28 as *const u32);
    core::ptr::write_volatile(crash.add(6), cfsr);
    // BFAR: Bus Fault Address Register — exact address that caused the fault
    let bfar = core::ptr::read_volatile(0xE000_ED38 as *const u32);
    core::ptr::write_volatile(crash.add(7), bfar);

    // Trigger system reset via AIRCR
    let aircr = 0xE000_ED0C as *mut u32;
    core::ptr::write_volatile(aircr, 0x05FA_0004); // VECTKEY | SYSRESETREQ
    loop {
        cortex_m::asm::nop();
    }
}

// ============================================================================
// Tier 2 (IRQ-owned) dispatch — RP single-core path
// ============================================================================
//
// RP is single-core, so Tier 2 is not "a dedicated core owns the IRQ" (that is
// the bcm2712 multicore model) but "a module is bound to a real NVIC IRQ and
// dispatched preemptively from interrupt context." `register_tier2_module`
// (platform-agnostic, called from `register_isr_tier_modules_from_graph` at
// boot) records the module against its IRQ number and calls `hal::irq_bind`;
// on RP that hook (`rp_irq_bind`) unmasks the NVIC line. Any line not claimed
// by an embassy `bind_interrupts!` handler falls through to this
// `DefaultHandler`, which routes it to the Tier 2 trampoline by IRQ number.
//
// `isr_tier2_trampoline` returns -1 when no Tier 2 module owns the IRQ; that
// would otherwise re-fire forever (the pending bit is still set), so the
// unowned line is masked to prevent an interrupt storm. A genuine Tier 2
// module is responsible for clearing its own peripheral interrupt source
// inside `module_isr_entry`, exactly as it would for any IRQ it owns.
#[cortex_m_rt::exception]
unsafe fn DefaultHandler(irqn: i16) {
    if irqn >= 0 {
        let irq = irqn as u16;
        if fluxor::kernel::exec::isr_tier::isr_tier2_trampoline(irq) < 0 {
            // No Tier 2 module owns this IRQ — mask it so it cannot storm.
            cortex_m::peripheral::NVIC::mask(RawIrq(irq));
        }
    }
    // irqn < 0 is a system exception we do not handle here; returning resumes
    // the faulting context, matching cortex-m-rt's default behaviour.
}

/// Newtype wrapping a raw IRQ number so the cortex-m NVIC API (which is
/// generic over `InterruptNumber`) can enable/mask a line chosen at runtime
/// from config, rather than a statically-named `embassy_rp::interrupt` variant.
#[derive(Clone, Copy)]
struct RawIrq(u16);
// SAFETY: the contract is that `number()` returns a valid device IRQ number;
// the value originates from the module manifest's `irq` field, range-checked
// by the build-time ISR-tier validator before it reaches the binding path.
unsafe impl cortex_m::interrupt::InterruptNumber for RawIrq {
    fn number(self) -> u16 {
        self.0
    }
}

/// HAL `irq_bind` for RP: enable the NVIC line for a Tier 2 module's IRQ so it
/// dispatches through `DefaultHandler` → `isr_tier2_trampoline`. The
/// `event_handle` / `trampoline` parameters are unused on RP (the
/// `DefaultHandler` dispatches by IRQ number directly). Returns 0.
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
    // SAFETY: unmasking an NVIC line is sound; the line only fires once its
    // peripheral asserts, and an unowned fire is masked by `DefaultHandler`.
    unsafe {
        cortex_m::peripheral::NVIC::unmask(RawIrq(irq as u16));
    }
    0
}

// ============================================================================
// Log backend — formats log records into the kernel log ring.
// ============================================================================
//
// Replaces embassy_usb_logger on RP platforms. Every log crate record
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

// ============================================================================
// USB CDC-ACM bridge — shared pipe drained by an embassy task.
// ============================================================================
//
// The platform debug drain (`RpUsbSink` below) enqueues bytes into
// `USB_TX_PIPE`. The CDC task drains the pipe and writes packet-sized
// chunks to the CDC endpoint. Pipe is lock-free on the producer side
// via `try_write` and async on the consumer side — exactly the shape
// we need for sync-drain → async-USB.

use embassy_futures::join::join;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::pipe::Pipe;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcState};
use embassy_usb::{Builder, Config as UsbConfig};
use static_cell::StaticCell;

const USB_TX_PIPE_SIZE: usize = 4096;

static USB_TX_PIPE: Pipe<CriticalSectionRawMutex, USB_TX_PIPE_SIZE> = Pipe::new();

// --- Platform debug drain (local USB CDC) ---
//
// Normal-runtime path for kernel log output. Drains `log_ring` into
// USB_TX_PIPE (the Embassy CDC task reads it and writes packets to
// the endpoint). Called once per tick from `rp_run_main_loop`. Single-
// task Embassy executor, so no cross-core coordination is needed.
// HardFault / panic handlers do not use this path; emergency output
// goes through panic_probe (RTT) and the uninit-RAM crash area.
struct RpUsbSink;

impl fluxor::platform::debug::DebugTx for RpUsbSink {
    fn write(&mut self, bytes: &[u8]) -> usize {
        USB_TX_PIPE.try_write(bytes).unwrap_or_default()
    }
}

static mut DEBUG_DRAIN: fluxor::platform::debug::DebugDrain<256> =
    fluxor::platform::debug::DebugDrain::new();
static mut DEBUG_SINK: RpUsbSink = RpUsbSink;

/// Drain queued log bytes into the USB CDC pipe. Embassy main task only.
#[inline]
fn debug_drain_poll() {
    // SAFETY: single consumer of `log_ring`; the Embassy main task is
    // the only caller (no other tasks or ISRs touch DEBUG_DRAIN).
    unsafe {
        let drain_p = &raw mut DEBUG_DRAIN;
        let sink_p = &raw mut DEBUG_SINK;
        let drain = &mut *drain_p;
        let sink = &mut *sink_p;
        drain.poll(sink);
    }
}

#[embassy_executor::task]
async fn usb_cdc_task(driver: Driver<'static, USB>) {
    // Descriptor and state buffers live for the lifetime of the task.
    // StaticCell ensures single initialization without unsafe statics.
    static CONFIG_DESC: StaticCell<[u8; 128]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 16]> = StaticCell::new();
    static MSOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static CDC_STATE: StaticCell<CdcState<'_>> = StaticCell::new();

    let mut config = UsbConfig::new(0xc0de, 0xcafe);
    config.manufacturer = Some("Fluxor");
    config.product = Some("Fluxor USB CDC");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESC.init([0; 128]),
        BOS_DESC.init([0; 16]),
        MSOS_DESC.init([0; 256]),
        CONTROL_BUF.init([0; 64]),
    );

    let class = CdcAcmClass::new(&mut builder, CDC_STATE.init(CdcState::new()), 64);
    let (mut sender, _receiver) = class.split();
    let mut device = builder.build();

    let run_fut = device.run();
    let tx_fut = async {
        let mut buf = [0u8; 64];
        loop {
            sender.wait_connection().await;
            // Host is attached; the local log-ring consumer is free to
            // flow without stalling the producer.
            fluxor::kernel::sys::log_ring::activate_local();
            loop {
                let n = USB_TX_PIPE.read(&mut buf).await;
                if sender.write_packet(&buf[..n]).await.is_err() {
                    break;
                }
                // A full 64-byte packet needs a zero-length packet to
                // terminate the CDC transfer (CDC framing rule).
                if n == 64 && sender.write_packet(&[]).await.is_err() {
                    break;
                }
            }
            // Host disconnected. Stop the local consumer, drop any
            // bytes staged between the ring and the USB endpoint, and
            // flush the CDC pipe so the next attach sees "now"-bytes
            // instead of pre-detach backlog.
            fluxor::kernel::sys::log_ring::disable_local();
            USB_TX_PIPE.clear();
            // SAFETY: the Embassy main task is the only caller that
            // touches DEBUG_DRAIN; this branch runs inside that task.
            unsafe {
                let drain_p = &raw mut DEBUG_DRAIN;
                let drain = &mut *drain_p;
                drain.reset();
            }
        }
    };
    join(run_fut, tx_fut).await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    #[cfg(feature = "chip-rp2040")]
    let p = embassy_rp::init(embassy_rp::config::Config::default());
    #[cfg(not(feature = "chip-rp2040"))]
    let p = embassy_rp::init(embassy_rp::config::Config::new(
        embassy_rp::clocks::ClockConfig::system_freq(240_000_000).unwrap(),
    ));

    // Disable watchdog — bootloader may have enabled it, and we don't feed it.
    // SAFETY: WATCHDOG_CTRL is a fixed MMIO register on the RP2xxx peripheral
    // bus; single boot-thread writer.
    unsafe {
        core::ptr::write_volatile(fluxor::platform::chip::WATCHDOG_CTRL as *mut u32, 0);
    }

    // Install the ring-backed log backend. Records go into kernel::sys::log_ring
    // and are consumed by PIC modules (e.g. log_net for UDP netconsole).
    init_logger();

    // Spawn the USB CDC drain task. The platform debug drain
    // (`RpUsbSink`) feeds bytes into `USB_TX_PIPE`; the task reads
    // packet-sized chunks and writes them to the CDC endpoint. With no
    // host connected the task sits in `wait_connection`/`read.await`
    // and the pipe acts as a small buffer.
    let usb_driver = Driver::new(p.USB, Irqs);
    spawner.spawn(usb_cdc_task(usb_driver).unwrap());

    log::info!("[fluxor] starting");

    // --- Resolve resource plan (max_gpio from config target) ---
    let hw = Hardware::new();
    let max_gpio = hw.raw_config().max_gpio;
    fluxor::platform::rp_io::gpio::set_runtime_max_gpio(max_gpio);
    let plan = match planner::resolve(hw.raw_config(), max_gpio) {
        Ok(p) => p,
        Err(e) => {
            log::error!("[boot] resource conflict: {e:?}");
            loop {
                Timer::after(Duration::from_millis(1000)).await;
            }
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

    // --- Setup runner ---
    let config = RunnerConfig {
        spi_bus: hw.spi_bus(),
        cs_pin: hw.cs_pin(),
    };

    if !setup(&config) {
        log::error!("[boot] setup failed");
        loop {
            Timer::after(Duration::from_millis(1000)).await;
        }
    }

    // Setup / run / rebuild loop. `rp_run_main_loop` returns when the
    // reconfigure module calls RECONFIGURE_TRIGGER_REBUILD; we then reset
    // the phase and re-run setup against STATIC_CONFIG.
    loop {
        let module_count = rp_setup_graph_async().await;
        if module_count < 0 {
            log::error!("[boot] graph setup failed");
            loop {
                Timer::after(Duration::from_millis(1000)).await;
            }
        }

        log::info!("[boot] ready modules={module_count}");
        scheduler::log_arena_summary();

        // Tier 1b admission: hand any Tier 1b-domain modules to the
        // ISR-tier dispatcher and arm the timer-poll. RP's single
        // async executor calls `isr_tier::poll_tier1b` from
        // `rp_run_main_loop` each iteration, so registration
        // here is the platform's only ISR setup. See
        // `.context/rfc_isr_tier_surface.md` §D5+§D6.
        let isr_registered = scheduler::register_isr_tier_modules_from_graph();
        if isr_registered > 0 {
            log::info!("[isr] Tier 1b admitted {isr_registered} module(s)");
        }

        match rp_run_main_loop(module_count as usize).await {
            Some(_rebuild) => {
                log::info!("[reconfigure] main loop yielded, rebuilding graph");
                scheduler::set_reconfigure_phase(scheduler::ReconfigurePhase::Running);
                continue;
            }
            None => {
                log::info!("[sched] stopped");
                loop {
                    Timer::after(Duration::from_millis(1000)).await;
                }
            }
        }
    }
}

// ============================================================================
// RP HAL Ops — function pointer table for all platform-specific operations
// ============================================================================

use embassy_sync::signal::Signal;
use fluxor::kernel::sys::hal::HalOps;

/// Scheduler wake signal — Embassy-safe, used by HAL wake_scheduler.
pub static SCHEDULER_WAKE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

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
    SCHEDULER_WAKE.signal(());
}

fn rp_now_millis() -> u64 {
    embassy_time::Instant::now().as_millis()
}

fn rp_now_micros() -> u64 {
    embassy_time::Instant::now().as_micros()
}

fn rp_tick_count() -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}

/// Portable `sleep_until` (RFC adaptive_tick §5.5 Option B). The Embassy
/// thread-mode executor idles on WFE woken by SEV (via `SCHEDULER_WAKE` →
/// `__pender`); a channel write or alarm raises SEV. This synchronous entry
/// waits for the next such event with a bare WFE — the real rp idle path is
/// the async `select(Timer::after, SCHEDULER_WAKE.wait())` in
/// `rp_run_main_loop`, which a `fn`-pointer cannot await. Returns UNKNOWN: WFE
/// cannot report its wake source, so the caller re-checks its work state.
fn rp_sleep_until(_deadline_us: u64) -> u32 {
    cortex_m::asm::wfe();
    fluxor::kernel::sys::hal::WOKEN_UNKNOWN
}

// Flash bounds come from linker symbols declared in
// `memory-rp2350.x` / `memory-rp2040.x` (`__flash_start__` /
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
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    let primask = cortex_m::register::primask::read();
    if !primask.is_active() {
        // SAFETY: counter increment + interrupt re-enable; we only enable
        // when PRIMASK shows IRQs were already enabled (mirroring caller state).
        unsafe {
            fluxor::kernel::module::loader::increment_irq_disabled_count();
            cortex_m::interrupt::enable();
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
    unsafe { fluxor::platform::rp_flash::store::merge_runtime_overrides(module_id as u8, buf, len, max) }
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
    disable_interrupts: rp_disable_interrupts,
    restore_interrupts: rp_restore_interrupts,
    wake_scheduler: rp_wake_scheduler,
    now_millis: rp_now_millis,
    now_unix_millis: || 0, // no RTC on this platform
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
    // Binary-safe write into the USB-CDC TX pipe the debug drain forwards.
    serial_write: |b| USB_TX_PIPE.try_write(b).unwrap_or_default(),
};

/// Fill buffer with random bytes from the ROSC RANDOMBIT register.
///
/// RP2040/RP2350 both have a ring oscillator with a RANDOMBIT register that
/// provides one random bit per read from oscillator jitter. We accumulate
/// 8 bits per output byte. This is genuine hardware entropy suitable for
/// seeding cryptographic keys.
fn rp_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    // SAFETY: caller is `hal::csprng_fill` which guarantees `buf` is valid
    // for `len` bytes. `i` is bounded by `len`, so `buf.add(i)` stays
    // within the caller's buffer.
    unsafe {
        use embassy_rp::pac;
        let mut i = 0usize;
        while i < len {
            let mut byte: u8 = 0;
            let mut bit = 0u32;
            while bit < 8 {
                byte = (byte << 1) | (pac::ROSC.randombit().read().randombit() as u8);
                bit += 1;
            }
            core::ptr::write_volatile(buf.add(i), byte);
            i += 1;
        }
    }
    len as i32
}

// ============================================================================
// Async graph setup and main loop (moved from scheduler.rs)
// ============================================================================

async fn rp_setup_graph_async() -> i32 {
    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(e) => return e,
    };

    // SAFETY: `static_loader` and `sched_mut` return shared globals;
    // this function runs on the single async executor task, serial
    // with all other scheduler-state mutators.
    let loader = unsafe { scheduler::static_loader() };
    // SAFETY: as above.
    let sched = unsafe { scheduler::sched_mut() };
    let result = rp_instantiate_all_modules_async(
        loader,
        &module_list,
        module_count,
        &mut sched.edges,
        &mut sched.modules,
        &mut sched.ports,
    )
    .await;

    if result < 0 {
        log::error!("[graph] instantiation failed");
        return -1;
    }

    scheduler::compute_downstream_latency(sched, module_count);
    result
}

#[inline(never)]
async fn rp_instantiate_all_modules_async(
    loader: &fluxor::kernel::module::loader::ModuleLoader,
    module_list: &[Option<fluxor::kernel::boot::config::ModuleEntry>; MAX_MODULES],
    module_count: usize,
    edges: &mut [scheduler::Edge; scheduler::MAX_CHANNELS],
    modules: &mut [scheduler::ModuleSlot; MAX_MODULES],
    module_ports: &mut [scheduler::ModulePorts; MAX_MODULES],
) -> i32 {
    let mut instantiated = 0;

    for (module_idx, entry_opt) in module_list.iter().take(module_count).enumerate() {
        let entry = match entry_opt {
            Some(entry) => entry,
            None => continue,
        };

        scheduler::set_current_module(instantiated);
        match scheduler::instantiate_one_module(
            loader,
            entry,
            module_idx,
            instantiated,
            edges,
            modules,
            module_ports,
        ) {
            scheduler::InstantiateResult::Done => {}
            scheduler::InstantiateResult::Pending(mut pending) => loop {
                Timer::after(Duration::from_millis(1)).await;
                // SAFETY: `pending` is owned here and not aliased; the loader
                // documents `try_complete` as callable from any task as long
                // as no other task holds the same `Pending` instance.
                match unsafe { pending.try_complete() } {
                    Ok(Some(dynamic)) => {
                        modules[instantiated] = scheduler::ModuleSlot::Dynamic(dynamic);
                        break;
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        e.log("scheduler");
                        return -1;
                    }
                }
            },
            scheduler::InstantiateResult::Error(e) => {
                log::error!("[inst] failed module={module_idx} error={e}");
                return e;
            }
        }

        fluxor::platform::rp_io::gpio::grant_pending_pins(instantiated as u8);
        instantiated += 1;
        Timer::after(Duration::from_millis(1)).await;
    }

    instantiated as i32
}

/// Step the graph until either a rebuild is requested (returns `Some((ptr, len))`)
/// or the graph halts (returns `None`).
async fn rp_run_main_loop(module_count: usize) -> Option<(*const u8, usize)> {
    // SAFETY: `sched_modules` returns a shared global; runs on the single
    // async executor task, serial with the scheduler.
    let modules = unsafe { scheduler::sched_modules() };
    let tick_period_us = scheduler::tick_us() as u64;

    log::info!(
        "[sched] running modules={module_count} tick_us={tick_period_us}"
    );

    loop {
        fluxor::platform::rp_io::gpio::poll_gpio_edges();

        let result = scheduler::step_modules(modules, module_count);
        match result {
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

        // Poll the Tier 1b timer — fires `isr_tier1b_handler` if the
        // configured period elapsed since the last poll. On RP this
        // is the only path that invokes the ISR dispatcher; without
        // this call, registered Tier 1b modules never run.
        fluxor::kernel::exec::isr_tier::poll_tier1b();

        debug_drain_poll();

        if let Some(req) = scheduler::take_rebuild_request() {
            return Some(req);
        }

        let wake = fluxor::kernel::ipc::event::take_wake_pending();
        if !wake.is_empty() {
            scheduler::step_woken_modules(modules, module_count, &wake);
        }

        // Adaptive-tick pacer (RFC adaptive_tick §5.1): choose this iteration's
        // deadline from the just-finished pass + its pre-sleep wake drain. With
        // no adaptive flag set it returns the nominal tick, so the timer arm is
        // byte-identical to the fixed-tick loop. With mechanism (a) idle it
        // widens to `tick_max_us`; the `SCHEDULER_WAKE` signal still breaks the
        // select immediately on a channel-write wake (Embassy thread executor
        // idles on WFE, woken by SEV — the favourable pairing, §10), so
        // first-request-after-idle latency is unaffected. rp2350 is
        // single-domain → domain 0; the pacer adds one integer calc, no new
        // alarm (Option A, AC4).
        let sleep_us = scheduler::pacer_next_deadline_us(0) as u64;
        SCHEDULER_WAKE.reset();
        embassy_futures::select::select(
            Timer::after(Duration::from_micros(sleep_us)),
            SCHEDULER_WAKE.wait(),
        )
        .await;

        let wake = fluxor::kernel::ipc::event::take_wake_pending();
        if !wake.is_empty() {
            scheduler::step_woken_modules(modules, module_count, &wake);
        }
    }
}

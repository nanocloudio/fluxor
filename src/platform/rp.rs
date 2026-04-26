// Platform: RP family (RP2040, RP2350A/B) — Cortex-M, embassy async runtime

use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::dma::InterruptHandler as DmaInterruptHandler;
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, DMA_CH6, PIO0, USB};
use embassy_rp::pio::InterruptHandler as PioInterruptHandler;
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};

use fluxor::kernel::pio_util;

use fluxor::kernel::config::Hardware;
use fluxor::kernel::hal;
use fluxor::kernel::planner::{self, PioRole};
use fluxor::kernel::scheduler::{self, setup, RunnerConfig, StepResult, MAX_MODULES};
use fluxor::kernel::syscalls;

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
    use fluxor::kernel::scheduler::{CRASH_DATA, CRASH_MAGIC, DBG_STEP_MODULE, DBG_TICK};

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
// Log backend — formats log records into the kernel log ring.
// ============================================================================
//
// Replaces embassy_usb_logger on RP platforms. Every log crate record
// becomes plain UTF-8 bytes in `kernel::log_ring`, which is the canonical
// log bus across all boards. A transport overlay (`log_net`, `log_usb`,
// `log_uart`) drains the ring and forwards the bytes on its wire; if no
// overlay is loaded, log output stays in the ring until it overflows and
// drops.

struct RingLogger;

impl log::Log for RingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
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
        fluxor::kernel::log_ring::push_bytes(&buf[..written]);
    }
    fn flush(&self) {}
}

static RING_LOGGER: RingLogger = RingLogger;

fn init_logger() {
    // Safe: called exactly once, before any task spawns.
    // set_max_level_racy (vs set_max_level) works on Cortex-M0+ too,
    // which lacks target_has_atomic = "ptr".
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
    static CDC_STATE: StaticCell<CdcState> = StaticCell::new();

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
            fluxor::kernel::log_ring::activate_local();
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
            fluxor::kernel::log_ring::disable_local();
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
    unsafe {
        core::ptr::write_volatile(fluxor::kernel::chip::WATCHDOG_CTRL as *mut u32, 0);
    }

    // Install the ring-backed log backend. Records go into kernel::log_ring
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
    fluxor::kernel::gpio::set_runtime_max_gpio(max_gpio);
    let plan = match planner::resolve(hw.raw_config(), max_gpio) {
        Ok(p) => p,
        Err(e) => {
            log::error!("[boot] resource conflict: {:?}", e);
            loop {
                Timer::after(Duration::from_millis(1000)).await;
            }
        }
    };
    planner::log_plan(&plan);

    // Initialize HAL with RP platform ops
    hal::init(&RP_HAL_OPS);

    // Initialize syscall table and providers (before any bus init)
    syscalls::init_syscall_table();
    syscalls::init_providers();

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

        log::info!("[boot] ready modules={}", module_count);

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
use fluxor::kernel::hal::HalOps;

/// Scheduler wake signal — Embassy-safe, used by HAL wake_scheduler.
pub static SCHEDULER_WAKE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

fn rp_disable_interrupts() -> u32 {
    let primask: u32;
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

const FLASH_BASE: usize = 0x10000000;
const FLASH_END: usize = 0x11000000;

fn rp_flash_base() -> usize {
    FLASH_BASE
}
fn rp_flash_end() -> usize {
    FLASH_END
}
fn rp_apply_code_bit(addr: usize) -> usize {
    addr | 1
}

fn rp_validate_fn_addr(addr: usize) -> bool {
    if addr & 1 == 0 {
        return false;
    }
    let instr_addr = addr & !1;
    (FLASH_BASE..FLASH_END).contains(&instr_addr)
}

fn rp_validate_module_base(addr: usize) -> bool {
    (FLASH_BASE..FLASH_END).contains(&addr)
}

fn rp_validate_fn_in_code(addr: usize, code_base: usize, code_size: u32) -> bool {
    let fn_addr = addr & !1;
    let code_end = code_base.wrapping_add(code_size as usize);
    fn_addr >= code_base && fn_addr < code_end
}

fn rp_verify_integrity(computed: &[u8], expected: &[u8]) -> bool {
    computed == expected
}

fn rp_pic_barrier() {
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    let primask = cortex_m::register::primask::read();
    if !primask.is_active() {
        unsafe {
            fluxor::kernel::loader::increment_irq_disabled_count();
            cortex_m::interrupt::enable();
        }
    }
}

use fluxor::kernel::rp_step_guard as step_guard_backend;

fn rp_step_guard_post_check() {
    // No-op on Cortex-M
}

fn rp_read_cycle_count() -> u32 {
    unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
}

fn rp_isr_tier_init() {
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
    fluxor::kernel::rp_providers::init();
}

fn rp_release_module_handles(module_idx: u8) {
    fluxor::kernel::rp_providers::release_handles(module_idx);
}

fn rp_boot_scan() {
    fluxor::kernel::flash_store::boot_scan();
}

fn rp_merge_runtime_overrides(module_id: u16, buf: *mut u8, len: usize, max: usize) -> usize {
    unsafe { fluxor::kernel::flash_store::merge_runtime_overrides(module_id as u8, buf, len, max) }
}

static RP_HAL_OPS: HalOps = HalOps {
    disable_interrupts: rp_disable_interrupts,
    restore_interrupts: rp_restore_interrupts,
    wake_scheduler: rp_wake_scheduler,
    now_millis: rp_now_millis,
    now_micros: rp_now_micros,
    tick_count: rp_tick_count,
    flash_base: rp_flash_base,
    flash_end: rp_flash_end,
    apply_code_bit: rp_apply_code_bit,
    validate_fn_addr: rp_validate_fn_addr,
    validate_module_base: rp_validate_module_base,
    validate_fn_in_code: rp_validate_fn_in_code,
    verify_integrity: rp_verify_integrity,
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
    init_gpio: |gpio| fluxor::kernel::gpio::init_all_from_config(gpio),
    csprng_fill: rp_csprng_fill,
    core_id: || 0,
    irq_bind: |_, _, _| fluxor::kernel::errno::ENOSYS,
};

/// Fill buffer with random bytes from the ROSC RANDOMBIT register.
///
/// RP2040/RP2350 both have a ring oscillator with a RANDOMBIT register that
/// provides one random bit per read from oscillator jitter. We accumulate
/// 8 bits per output byte. This is genuine hardware entropy suitable for
/// seeding cryptographic keys.
fn rp_csprng_fill(buf: *mut u8, len: usize) -> i32 {
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

    let loader = unsafe { scheduler::static_loader() };
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

    if !scheduler::validate_buffer_groups(&sched.edges) {
        log::error!("[graph] buffer group validation failed");
        return -1;
    }

    scheduler::compute_downstream_latency(sched, module_count);
    result
}

#[inline(never)]
async fn rp_instantiate_all_modules_async(
    loader: &fluxor::kernel::loader::ModuleLoader,
    module_list: &[Option<fluxor::kernel::config::ModuleEntry>; MAX_MODULES],
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
                log::error!("[inst] failed module={} error={}", module_idx, e);
                return e;
            }
        }

        fluxor::kernel::gpio::grant_pending_pins(instantiated as u8);
        instantiated += 1;
        Timer::after(Duration::from_millis(1)).await;
    }

    instantiated as i32
}

/// Step the graph until either a rebuild is requested (returns `Some((ptr, len))`)
/// or the graph halts (returns `None`).
async fn rp_run_main_loop(module_count: usize) -> Option<(*const u8, usize)> {
    let modules = unsafe { scheduler::sched_modules() };
    let tick_period_us = scheduler::tick_us() as u64;

    log::info!(
        "[sched] running modules={} tick_us={}",
        module_count,
        tick_period_us
    );

    loop {
        fluxor::kernel::gpio::poll_gpio_edges();

        let result = scheduler::step_modules(modules, module_count);
        match result {
            StepResult::Continue => {}
            StepResult::Done => {
                log::warn!("[sched] all modules done");
                return None;
            }
            StepResult::Error(i) => {
                log::error!("[sched] step error module={}", i);
                return None;
            }
        }

        debug_drain_poll();

        if let Some(req) = scheduler::take_rebuild_request() {
            return Some(req);
        }

        let wake = fluxor::kernel::event::take_wake_pending();
        if wake != 0 {
            scheduler::step_woken_modules(modules, module_count, wake);
        }

        SCHEDULER_WAKE.reset();
        embassy_futures::select::select(
            Timer::after(Duration::from_micros(tick_period_us)),
            SCHEDULER_WAKE.wait(),
        )
        .await;

        let wake = fluxor::kernel::event::take_wake_pending();
        if wake != 0 {
            scheduler::step_woken_modules(modules, module_count, wake);
        }
    }
}

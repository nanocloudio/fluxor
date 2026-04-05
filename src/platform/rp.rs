// Platform: RP family (RP2040, RP2350A/B) — Cortex-M, embassy async runtime

use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, DMA_CH6, PIO0, USB};
use embassy_rp::dma::InterruptHandler as DmaInterruptHandler;
use embassy_rp::pio::InterruptHandler as PioInterruptHandler;
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};

use fluxor::kernel::pio_util;

use fluxor::kernel::syscalls;
use fluxor::kernel::scheduler::{self, setup, RunnerConfig, StepResult, MAX_MODULES};
use fluxor::kernel::config::Hardware;
use fluxor::kernel::hal;
use fluxor::kernel::planner::{self, PioRole};

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
    core::ptr::write_volatile(crash.add(3),
        core::ptr::read_volatile(&raw const DBG_STEP_MODULE) as u32);
    core::ptr::write_volatile(crash.add(4),
        core::ptr::read_volatile(&raw const DBG_TICK));
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
    loop { cortex_m::asm::nop(); }
}

#[embassy_executor::task]
async fn logger_task(driver: Driver<'static, USB>) {
    embassy_usb_logger::run!(4096, log::LevelFilter::Info, driver);
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
    unsafe { core::ptr::write_volatile(fluxor::kernel::chip::WATCHDOG_CTRL as *mut u32, 0); }

    // Spawn USB logger and wait for enumeration
    let usb_driver = Driver::new(p.USB, Irqs);
    spawner.spawn(logger_task(usb_driver).unwrap());
    Timer::after(Duration::from_secs(1)).await;

    log::info!("[fluxor] starting");

    // --- Resolve resource plan (max_gpio from config target) ---
    let hw = Hardware::new();
    let max_gpio = hw.raw_config().max_gpio;
    fluxor::kernel::gpio::set_runtime_max_gpio(max_gpio);
    let plan = match planner::resolve(hw.raw_config(), max_gpio) {
        Ok(p) => p,
        Err(e) => {
            log::error!("[boot] resource conflict: {:?}", e);
            loop { Timer::after(Duration::from_millis(1000)).await; }
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
        log::info!("[boot] i2c{} sda={} scl={}", i2c_cfg.bus, i2c_cfg.sda, i2c_cfg.scl);
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
        log::info!("[boot] pio{} {:?} data={} clk={} extra={}",
            entry.pio_idx, entry.role, entry.data_pin, entry.clk_pin, entry.extra_pin);
    }

    // PIO blocks are accessed via raw PAC through the PIO register bridge
    // (dev_system 0x0C70-0x0C7B). PIC pio_stream module manages SM/DMA at runtime.

    // --- Setup runner ---
    let config = RunnerConfig {
        spi_bus: hw.spi_bus(),
        cs_pin: hw.cs_pin(),
    };

    if !setup(&config) {
        log::error!("[boot] setup failed");
        loop { Timer::after(Duration::from_millis(1000)).await; }
    }

    // Load modules (may do async init like SPI DMA)
    let module_count = rp_setup_graph_async().await;
    if module_count < 0 {
        log::error!("[boot] graph setup failed");
        loop { Timer::after(Duration::from_millis(1000)).await; }
    }

    log::info!("[boot] ready modules={}", module_count);

    // Run the main loop
    rp_run_main_loop(module_count as usize).await;
}

// ============================================================================
// RP HAL Ops — function pointer table for all platform-specific operations
// ============================================================================

use fluxor::kernel::hal::HalOps;
use embassy_sync::signal::Signal;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

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

fn rp_flash_base() -> usize { FLASH_BASE }
fn rp_flash_end() -> usize { FLASH_END }
fn rp_apply_code_bit(addr: usize) -> usize { addr | 1 }

fn rp_validate_fn_addr(addr: usize) -> bool {
    if addr & 1 == 0 { return false; }
    let instr_addr = addr & !1;
    instr_addr >= FLASH_BASE && instr_addr < FLASH_END
}

fn rp_validate_module_base(addr: usize) -> bool {
    addr >= FLASH_BASE && addr < FLASH_END
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

// rp_step_guard_init/arm/disarm are defined in the included rp_step_guard.rs

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
    rp_isr_backend_start(period_us);
}

fn rp_isr_tier_stop() {
    rp_isr_backend_stop();
}

fn rp_isr_tier_poll() {
    // No-op on Cortex-M
}

fn rp_init_providers() {
    fluxor::kernel::rp_ext::init();
}

fn rp_release_module_handles(module_idx: u8) {
    fluxor::kernel::rp_ext::release_handles(module_idx);
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
    step_guard_init: rp_step_guard_init,
    step_guard_arm: rp_step_guard_arm,
    step_guard_disarm: rp_step_guard_disarm,
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
    core_id: || 0, // Single-core on RP2350/RP2040
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
// Step guard platform backends (RP2350 / RP2040)
// ============================================================================

include!("rp_step_guard.rs");

// ============================================================================
// ISR tier platform backends (RP2350 / RP2040)
// ============================================================================

include!("rp_isr_tier.rs");

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
        loader, &module_list, module_count,
        &mut sched.edges, &mut sched.modules, &mut sched.ports,
    ).await;

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

    for module_idx in 0..module_count {
        let entry = match &module_list[module_idx] {
            Some(entry) => entry,
            None => continue,
        };

        scheduler::set_current_module(instantiated);
        match scheduler::instantiate_one_module(
            loader, entry, module_idx, instantiated, edges, modules, module_ports,
        ) {
            scheduler::InstantiateResult::Done => {}
            scheduler::InstantiateResult::Pending(mut pending) => {
                loop {
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
                }
            }
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

async fn rp_run_main_loop(module_count: usize) -> ! {
    let modules = unsafe { scheduler::sched_modules() };
    let tick_period_us = scheduler::tick_us() as u64;

    log::info!("[sched] running modules={} tick_us={}", module_count, tick_period_us);

    loop {
        fluxor::kernel::gpio::poll_gpio_edges();

        let result = scheduler::step_modules(modules, module_count);
        match result {
            StepResult::Continue => {}
            StepResult::Done => {
                log::warn!("[sched] all modules done");
                break;
            }
            StepResult::Error(i) => {
                log::error!("[sched] step error module={}", i);
                break;
            }
        }

        let wake = fluxor::kernel::event::take_wake_pending();
        if wake != 0 {
            scheduler::step_woken_modules(modules, module_count, wake);
        }

        SCHEDULER_WAKE.reset();
        embassy_futures::select::select(
            Timer::after(Duration::from_micros(tick_period_us)),
            SCHEDULER_WAKE.wait(),
        ).await;

        let wake = fluxor::kernel::event::take_wake_pending();
        if wake != 0 {
            scheduler::step_woken_modules(modules, module_count, wake);
        }
    }

    log::info!("[sched] stopped");
    loop { Timer::after(Duration::from_millis(1000)).await; }
}

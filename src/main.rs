//! Fluxor - Config-driven pipeline runtime for Pico 2 W
//!
//! Reads pipeline configuration from flash and executes it.
//! Supports SD card sources, audio processing, I2S output, and more.

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::{DMA_CH0, DMA_CH1, DMA_CH6, I2C0, I2C1, PIO0, PIO1, UART0, UART1, USB};
#[cfg(not(feature = "chip-rp2040"))]
use embassy_rp::peripherals::PIO2;
use embassy_rp::adc::{self as embassy_adc, InterruptHandler as AdcInterruptHandler};
use embassy_rp::i2c::{I2c, InterruptHandler as I2cInterruptHandler};
use embassy_rp::pio::{InterruptHandler as PioInterruptHandler, Pio};
use embassy_rp::spi::{Config as SpiCfg, Phase, Polarity, Spi};
use embassy_rp::uart::{BufferedUart, BufferedInterruptHandler};
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};

use fluxor::io::adc::AdcBus;
use fluxor::io::i2c::I2cBus;
use fluxor::io::spi::SpiBus;
use fluxor::io::uart::UartBus;
use fluxor::io::pio;
use fluxor::io::{PioStreamRunner, PioCmdRunner, PioRxStreamRunner};

use fluxor::kernel::syscalls;
use fluxor::kernel::scheduler::{setup, setup_graph_async, run_main_loop, RunnerConfig};
use fluxor::kernel::config::Hardware;
use fluxor::kernel::planner::{self, PioRole};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => PioInterruptHandler<PIO0>;
    USBCTRL_IRQ => UsbInterruptHandler<USB>;
});

bind_interrupts!(struct Pio1Irqs {
    PIO1_IRQ_0 => PioInterruptHandler<PIO1>;
});

#[cfg(not(feature = "chip-rp2040"))]
bind_interrupts!(struct Pio2Irqs {
    PIO2_IRQ_0 => PioInterruptHandler<PIO2>;
});

bind_interrupts!(struct I2c0Irqs {
    I2C0_IRQ => I2cInterruptHandler<I2C0>;
});

bind_interrupts!(struct I2c1Irqs {
    I2C1_IRQ => I2cInterruptHandler<I2C1>;
});

bind_interrupts!(struct AdcIrqs {
    ADC_IRQ_FIFO => AdcInterruptHandler;
});

bind_interrupts!(struct Uart0Irqs {
    UART0_IRQ => BufferedInterruptHandler<UART0>;
});

bind_interrupts!(struct Uart1Irqs {
    UART1_IRQ => BufferedInterruptHandler<UART1>;
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

/// PIO command runner task — PIO1 (default)
#[embassy_executor::task]
async fn pio_cmd_runner_task(
    mut runner: PioCmdRunner<'static, PIO1, 0, DMA_CH0>,
) -> ! {
    runner.run().await
}

/// PIO command runner task — PIO0 (swapped config)
#[embassy_executor::task]
async fn pio_cmd_runner_task_pio0(
    mut runner: PioCmdRunner<'static, PIO0, 0, DMA_CH0>,
) -> ! {
    runner.run().await
}

/// PIO stream runner task — PIO0 (default)
#[embassy_executor::task]
async fn pio_stream_runner_task(
    mut runner: PioStreamRunner<'static, PIO0, 0, DMA_CH1>,
) -> ! {
    runner.run().await
}

/// PIO stream runner task — PIO1 (swapped config)
#[embassy_executor::task]
async fn pio_stream_runner_task_pio1(
    mut runner: PioStreamRunner<'static, PIO1, 0, DMA_CH1>,
) -> ! {
    runner.run().await
}

/// PIO RX stream runner task — PIO0 (default)
#[embassy_executor::task]
async fn pio_rx_stream_runner_task(
    mut runner: PioRxStreamRunner<'static, PIO0, 1, DMA_CH6>,
) -> ! {
    runner.run().await
}

/// PIO RX stream runner task — PIO1 (swapped config)
#[embassy_executor::task]
async fn pio_rx_stream_runner_task_pio1(
    mut runner: PioRxStreamRunner<'static, PIO1, 1, DMA_CH6>,
) -> ! {
    runner.run().await
}

/// PIO command runner task — PIO2 (RP2350B only)
#[cfg(not(feature = "chip-rp2040"))]
#[embassy_executor::task]
async fn pio_cmd_runner_task_pio2(
    mut runner: PioCmdRunner<'static, PIO2, 0, DMA_CH0>,
) -> ! {
    runner.run().await
}

/// PIO stream runner task — PIO2 (RP2350B only)
#[cfg(not(feature = "chip-rp2040"))]
#[embassy_executor::task]
async fn pio_stream_runner_task_pio2(
    mut runner: PioStreamRunner<'static, PIO2, 0, DMA_CH1>,
) -> ! {
    runner.run().await
}

/// PIO RX stream runner task — PIO2 (RP2350B only)
#[cfg(not(feature = "chip-rp2040"))]
#[embassy_executor::task]
async fn pio_rx_stream_runner_task_pio2(
    mut runner: PioRxStreamRunner<'static, PIO2, 1, DMA_CH6>,
) -> ! {
    runner.run().await
}

/// Create Embassy SPI configuration with given frequency
fn make_spi_config(freq: u32) -> SpiCfg {
    let mut cfg = SpiCfg::default();
    cfg.frequency = freq;
    cfg.phase = Phase::CaptureOnFirstTransition;
    cfg.polarity = Polarity::IdleLow;
    cfg
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
    spawner.spawn(logger_task(usb_driver)).unwrap();
    Timer::after(Duration::from_secs(1)).await;

    log::info!("[fluxor] starting");

    // --- Resolve resource plan (max_gpio from config target) ---
    let hw = Hardware::new();
    let max_gpio = hw.raw_config().max_gpio;
    fluxor::io::gpio::set_runtime_max_gpio(max_gpio);
    let plan = match planner::resolve(hw.raw_config(), max_gpio) {
        Ok(p) => p,
        Err(e) => {
            log::error!("[boot] resource conflict: {:?}", e);
            loop { Timer::after(Duration::from_millis(1000)).await; }
        }
    };
    planner::log_plan(&plan);

    // Initialize syscall table and providers (before any bus init)
    syscalls::init_syscall_table();
    syscalls::init_providers();

    // --- SPI bus 0 ---
    // Find SPI0 config from either plan slot
    static SPI_BUS_0: static_cell::StaticCell<SpiBus> = static_cell::StaticCell::new();
    let spi0_cfg = plan.spi.iter().flatten().find(|s| s.bus == 0).copied();
    if let Some(spi) = spi0_cfg {
        let cfg = make_spi_config(spi.freq_hz);
        let bus = match (spi.miso, spi.mosi, spi.sck) {
            (0, 3, 2) => {
                let s = Spi::new(p.SPI0, p.PIN_2, p.PIN_3, p.PIN_0, p.DMA_CH2, p.DMA_CH3, cfg);
                SPI_BUS_0.init(SpiBus::new_spi0(s))
            }
            (4, 7, 6) => {
                let s = Spi::new(p.SPI0, p.PIN_6, p.PIN_7, p.PIN_4, p.DMA_CH2, p.DMA_CH3, cfg);
                SPI_BUS_0.init(SpiBus::new_spi0(s))
            }
            (16, 19, 18) => {
                let s = Spi::new(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_16, p.DMA_CH2, p.DMA_CH3, cfg);
                SPI_BUS_0.init(SpiBus::new_spi0(s))
            }
            (20, 23, 22) => {
                let s = Spi::new(p.SPI0, p.PIN_22, p.PIN_23, p.PIN_20, p.DMA_CH2, p.DMA_CH3, cfg);
                SPI_BUS_0.init(SpiBus::new_spi0(s))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (32, 35, 34) => {
                let s = Spi::new(p.SPI0, p.PIN_34, p.PIN_35, p.PIN_32, p.DMA_CH2, p.DMA_CH3, cfg);
                SPI_BUS_0.init(SpiBus::new_spi0(s))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (36, 39, 38) => {
                let s = Spi::new(p.SPI0, p.PIN_38, p.PIN_39, p.PIN_36, p.DMA_CH2, p.DMA_CH3, cfg);
                SPI_BUS_0.init(SpiBus::new_spi0(s))
            }
            _ => {
                log::error!("[boot] spi0 unsupported pins miso={} mosi={} sck={}", spi.miso, spi.mosi, spi.sck);
                loop { Timer::after(Duration::from_millis(1000)).await; }
            }
        };
        syscalls::set_spi_bus(0, bus);
        syscalls::mark_spi_initialized(0);
    }

    // --- SPI bus 1 ---
    // Find SPI1 config from either plan slot
    static SPI_BUS_1: static_cell::StaticCell<SpiBus> = static_cell::StaticCell::new();
    let spi1_cfg = plan.spi.iter().flatten().find(|s| s.bus == 1).copied();
    if let Some(spi) = spi1_cfg {
        let cfg = make_spi_config(spi.freq_hz);
        let bus = match (spi.miso, spi.mosi, spi.sck) {
            (8, 11, 10) => {
                let s = Spi::new(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_8, p.DMA_CH4, p.DMA_CH5, cfg);
                SPI_BUS_1.init(SpiBus::new_spi1(s))
            }
            (12, 11, 10) => {
                let s = Spi::new(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, p.DMA_CH4, p.DMA_CH5, cfg);
                SPI_BUS_1.init(SpiBus::new_spi1(s))
            }
            (12, 15, 14) => {
                let s = Spi::new(p.SPI1, p.PIN_14, p.PIN_15, p.PIN_12, p.DMA_CH4, p.DMA_CH5, cfg);
                SPI_BUS_1.init(SpiBus::new_spi1(s))
            }
            (24, 27, 26) => {
                let s = Spi::new(p.SPI1, p.PIN_26, p.PIN_27, p.PIN_24, p.DMA_CH4, p.DMA_CH5, cfg);
                SPI_BUS_1.init(SpiBus::new_spi1(s))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (28, 31, 30) => {
                let s = Spi::new(p.SPI1, p.PIN_30, p.PIN_31, p.PIN_28, p.DMA_CH4, p.DMA_CH5, cfg);
                SPI_BUS_1.init(SpiBus::new_spi1(s))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (40, 43, 42) => {
                let s = Spi::new(p.SPI1, p.PIN_42, p.PIN_43, p.PIN_40, p.DMA_CH4, p.DMA_CH5, cfg);
                SPI_BUS_1.init(SpiBus::new_spi1(s))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (44, 47, 46) => {
                let s = Spi::new(p.SPI1, p.PIN_46, p.PIN_47, p.PIN_44, p.DMA_CH4, p.DMA_CH5, cfg);
                SPI_BUS_1.init(SpiBus::new_spi1(s))
            }
            _ => {
                log::error!("[boot] spi1 unsupported pins miso={} mosi={} sck={}", spi.miso, spi.mosi, spi.sck);
                loop { Timer::after(Duration::from_millis(1000)).await; }
            }
        };
        syscalls::set_spi_bus(1, bus);
        syscalls::mark_spi_initialized(1);
    }

    // Spawn SPI async task (single task routes to correct bus per handle)
    spawner.spawn(syscalls::spi_async_task()).unwrap();

    // --- I2C buses ---
    // Safety: Pin peripherals are ZST markers. Planner enforces pin uniqueness across
    // all peripherals, so a pin consumed by an SPI match arm above is never also consumed
    // by an I2C arm at runtime. We create fresh Peri wrappers since the originals may have
    // been moved into SPI constructors.
    macro_rules! steal_pin {
        ($pin_ty:ident) => {
            #[allow(unused_unsafe)]
            unsafe { embassy_rp::peripherals::$pin_ty::steal() }
        }
    }

    static I2C_BUS_0: static_cell::StaticCell<I2cBus> = static_cell::StaticCell::new();
    let i2c0_cfg = plan.i2c.iter().flatten().find(|c| c.bus == 0).copied();
    let i2c_cfg = fluxor::io::i2c::default_config();
    if let Some(i2c) = i2c0_cfg {
        let bus = match (i2c.sda, i2c.scl) {
            (0, 1) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_1), steal_pin!(PIN_0), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            (4, 5) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_5), steal_pin!(PIN_4), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            (8, 9) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_9), steal_pin!(PIN_8), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            (12, 13) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_13), steal_pin!(PIN_12), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            (16, 17) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_17), steal_pin!(PIN_16), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            (20, 21) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_21), steal_pin!(PIN_20), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            (24, 25) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_25), steal_pin!(PIN_24), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            (28, 29) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_29), steal_pin!(PIN_28), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (32, 33) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_33), steal_pin!(PIN_32), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (36, 37) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_37), steal_pin!(PIN_36), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (40, 41) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_41), steal_pin!(PIN_40), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (44, 45) => {
                let dev = I2c::new_async(p.I2C0, steal_pin!(PIN_45), steal_pin!(PIN_44), I2c0Irqs, i2c_cfg);
                I2C_BUS_0.init(I2cBus::new_i2c0(dev))
            }
            _ => {
                log::error!("[boot] i2c0 unsupported pins sda={} scl={}", i2c.sda, i2c.scl);
                loop { Timer::after(Duration::from_millis(1000)).await; }
            }
        };
        syscalls::set_i2c_bus(0, bus);
        syscalls::mark_i2c_initialized(0);
        log::info!("[boot] i2c0 sda={} scl={}", i2c.sda, i2c.scl);
    }

    // --- I2C bus 1 ---
    static I2C_BUS_1: static_cell::StaticCell<I2cBus> = static_cell::StaticCell::new();
    let i2c1_cfg = plan.i2c.iter().flatten().find(|c| c.bus == 1).copied();
    if let Some(i2c) = i2c1_cfg {
        let bus = match (i2c.sda, i2c.scl) {
            (2, 3) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_3), steal_pin!(PIN_2), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            (6, 7) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_7), steal_pin!(PIN_6), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            (10, 11) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_11), steal_pin!(PIN_10), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            (14, 15) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_15), steal_pin!(PIN_14), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            (18, 19) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_19), steal_pin!(PIN_18), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            (22, 23) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_23), steal_pin!(PIN_22), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            (26, 27) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_27), steal_pin!(PIN_26), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (30, 31) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_31), steal_pin!(PIN_30), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (34, 35) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_35), steal_pin!(PIN_34), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (38, 39) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_39), steal_pin!(PIN_38), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (42, 43) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_43), steal_pin!(PIN_42), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            #[cfg(not(feature = "chip-rp2040"))]
            (46, 47) => {
                let dev = I2c::new_async(p.I2C1, steal_pin!(PIN_47), steal_pin!(PIN_46), I2c1Irqs, i2c_cfg);
                I2C_BUS_1.init(I2cBus::new_i2c1(dev))
            }
            _ => {
                log::error!("[boot] i2c1 unsupported pins sda={} scl={}", i2c.sda, i2c.scl);
                loop { Timer::after(Duration::from_millis(1000)).await; }
            }
        };
        syscalls::set_i2c_bus(1, bus);
        syscalls::mark_i2c_initialized(1);
        log::info!("[boot] i2c1 sda={} scl={}", i2c.sda, i2c.scl);
    }

    // Spawn I2C async task (single task routes to correct bus per handle)
    spawner.spawn(syscalls::i2c_async_task()).unwrap();

    // --- UART bus 0 ---
    static UART_BUS_0: static_cell::StaticCell<UartBus> = static_cell::StaticCell::new();
    static mut UART0_TX_BUF: [u8; 2048] = [0; 2048];
    static mut UART0_RX_BUF: [u8; 2048] = [0; 2048];
    let uart0_cfg = hw.raw_config().uart.iter().flatten().find(|u| u.bus == 0).copied();
    if let Some(uart) = uart0_cfg {
        let config = fluxor::io::uart::make_config(uart.baudrate);
        let bus = match (uart.tx_pin, uart.rx_pin) {
            (0, 1) => {
                let u = unsafe { BufferedUart::new(steal_pin!(UART0), steal_pin!(PIN_0), steal_pin!(PIN_1), Uart0Irqs, &mut *(&raw mut UART0_TX_BUF), &mut *(&raw mut UART0_RX_BUF), config) };
                let (tx, rx) = u.split();
                UART_BUS_0.init(UartBus::new(tx, rx))
            }
            (12, 13) => {
                let u = unsafe { BufferedUart::new(steal_pin!(UART0), steal_pin!(PIN_12), steal_pin!(PIN_13), Uart0Irqs, &mut *(&raw mut UART0_TX_BUF), &mut *(&raw mut UART0_RX_BUF), config) };
                let (tx, rx) = u.split();
                UART_BUS_0.init(UartBus::new(tx, rx))
            }
            (16, 17) => {
                let u = unsafe { BufferedUart::new(steal_pin!(UART0), steal_pin!(PIN_16), steal_pin!(PIN_17), Uart0Irqs, &mut *(&raw mut UART0_TX_BUF), &mut *(&raw mut UART0_RX_BUF), config) };
                let (tx, rx) = u.split();
                UART_BUS_0.init(UartBus::new(tx, rx))
            }
            (28, 29) => {
                let u = unsafe { BufferedUart::new(steal_pin!(UART0), steal_pin!(PIN_28), steal_pin!(PIN_29), Uart0Irqs, &mut *(&raw mut UART0_TX_BUF), &mut *(&raw mut UART0_RX_BUF), config) };
                let (tx, rx) = u.split();
                UART_BUS_0.init(UartBus::new(tx, rx))
            }
            _ => {
                log::error!("[boot] uart0 unsupported pins tx={} rx={}", uart.tx_pin, uart.rx_pin);
                loop { Timer::after(Duration::from_millis(1000)).await; }
            }
        };
        syscalls::set_uart_bus(0, bus);
        syscalls::mark_uart_initialized(0);
        log::info!("[boot] uart0 tx={} rx={} baud={}", uart.tx_pin, uart.rx_pin, uart.baudrate);
    }

    // --- UART bus 1 ---
    static UART_BUS_1: static_cell::StaticCell<UartBus> = static_cell::StaticCell::new();
    static mut UART1_TX_BUF: [u8; 2048] = [0; 2048];
    static mut UART1_RX_BUF: [u8; 2048] = [0; 2048];
    let uart1_cfg = hw.raw_config().uart.iter().flatten().find(|u| u.bus == 1).copied();
    if let Some(uart) = uart1_cfg {
        let config = fluxor::io::uart::make_config(uart.baudrate);
        let bus = match (uart.tx_pin, uart.rx_pin) {
            (4, 5) => {
                let u = unsafe { BufferedUart::new(steal_pin!(UART1), steal_pin!(PIN_4), steal_pin!(PIN_5), Uart1Irqs, &mut *(&raw mut UART1_TX_BUF), &mut *(&raw mut UART1_RX_BUF), config) };
                let (tx, rx) = u.split();
                UART_BUS_1.init(UartBus::new(tx, rx))
            }
            (8, 9) => {
                let u = unsafe { BufferedUart::new(steal_pin!(UART1), steal_pin!(PIN_8), steal_pin!(PIN_9), Uart1Irqs, &mut *(&raw mut UART1_TX_BUF), &mut *(&raw mut UART1_RX_BUF), config) };
                let (tx, rx) = u.split();
                UART_BUS_1.init(UartBus::new(tx, rx))
            }
            (20, 21) => {
                let u = unsafe { BufferedUart::new(steal_pin!(UART1), steal_pin!(PIN_20), steal_pin!(PIN_21), Uart1Irqs, &mut *(&raw mut UART1_TX_BUF), &mut *(&raw mut UART1_RX_BUF), config) };
                let (tx, rx) = u.split();
                UART_BUS_1.init(UartBus::new(tx, rx))
            }
            (24, 25) => {
                let u = unsafe { BufferedUart::new(steal_pin!(UART1), steal_pin!(PIN_24), steal_pin!(PIN_25), Uart1Irqs, &mut *(&raw mut UART1_TX_BUF), &mut *(&raw mut UART1_RX_BUF), config) };
                let (tx, rx) = u.split();
                UART_BUS_1.init(UartBus::new(tx, rx))
            }
            _ => {
                log::error!("[boot] uart1 unsupported pins tx={} rx={}", uart.tx_pin, uart.rx_pin);
                loop { Timer::after(Duration::from_millis(1000)).await; }
            }
        };
        syscalls::set_uart_bus(1, bus);
        syscalls::mark_uart_initialized(1);
        log::info!("[boot] uart1 tx={} rx={} baud={}", uart.tx_pin, uart.rx_pin, uart.baudrate);
    }

    // Spawn UART async task
    spawner.spawn(syscalls::uart_async_task()).unwrap();

    // --- ADC ---
    {
        static ADC_BUS: static_cell::StaticCell<AdcBus> = static_cell::StaticCell::new();
        let adc_dev = embassy_adc::Adc::new(p.ADC, AdcIrqs, embassy_adc::Config::default());
        let temp_ch = embassy_adc::Channel::new_temp_sensor(p.ADC_TEMP_SENSOR);
        let adc_bus = ADC_BUS.init(AdcBus::new(adc_dev, temp_ch));
        syscalls::set_adc_bus(adc_bus);
        spawner.spawn(syscalls::adc_async_task()).unwrap();
        syscalls::mark_adc_initialized();
    }

    // --- GPIO ---
    hw.init_gpio();

    // --- PIO init from plan (grouped by PIO instance to avoid singleton double-move) ---
    // Pre-lookup: what role (Cmd/Stream) is assigned to each PIO instance?
    let pio0_role = plan.pio.iter().flatten().find(|e| e.pio_idx == 0 && e.role != PioRole::RxStream).copied();
    let pio1_role = plan.pio.iter().flatten().find(|e| e.pio_idx == 1 && e.role != PioRole::RxStream).copied();
    #[cfg(not(feature = "chip-rp2040"))]
    let pio2_role = plan.pio.iter().flatten().find(|e| e.pio_idx == 2 && e.role != PioRole::RxStream).copied();
    // Per-PIO RxStream lookup (at most one per PIO block)
    let rx_on_pio0 = plan.pio.iter().flatten().find(|e| e.role == PioRole::RxStream && e.pio_idx == 0).copied();
    let rx_on_pio1 = plan.pio.iter().flatten().find(|e| e.role == PioRole::RxStream && e.pio_idx == 1).copied();
    #[cfg(not(feature = "chip-rp2040"))]
    let rx_on_pio2 = plan.pio.iter().flatten().find(|e| e.role == PioRole::RxStream && e.pio_idx == 2).copied();

    // --- DMA channels for PIO (clone for all branches; planner guarantees one Cmd, one Stream) ---
    // Safety: DMA channel peripherals are ZST markers. Planner enforces at most one Cmd
    // and one Stream role, so each DMA channel is consumed by exactly one runner at runtime.
    let dma_ch0_pio0 = unsafe { p.DMA_CH0.clone_unchecked() };
    let dma_ch0_pio1 = unsafe { p.DMA_CH0.clone_unchecked() };
    #[cfg(not(feature = "chip-rp2040"))]
    let dma_ch0_pio2 = p.DMA_CH0;
    let dma_ch1_pio0 = unsafe { p.DMA_CH1.clone_unchecked() };
    let dma_ch1_pio1 = unsafe { p.DMA_CH1.clone_unchecked() };
    #[cfg(not(feature = "chip-rp2040"))]
    let dma_ch1_pio2 = p.DMA_CH1;
    let dma_ch6_pio0 = unsafe { p.DMA_CH6.clone_unchecked() };
    let dma_ch6_pio1 = unsafe { p.DMA_CH6.clone_unchecked() };
    #[cfg(not(feature = "chip-rp2040"))]
    let dma_ch6_pio2 = p.DMA_CH6;

    // --- PIO0 init (consume p.PIO0 once) ---
    if let Some(entry) = pio0_role {
        let pio0 = Pio::new(p.PIO0, Irqs);
        match entry.role {
            PioRole::Cmd => {
                pio::setup_pio_pin(entry.data_pin, entry.pio_idx, pio::PioPull::None);
                pio::setup_pio_pin(entry.clk_pin, entry.pio_idx, pio::PioPull::None);
                let cmd_runner = PioCmdRunner::new_with_clk(
                    pio0.sm0, dma_ch0_pio0,
                    entry.data_pin, entry.clk_pin,
                    0, entry.pio_idx,
                );
                spawner.spawn(pio_cmd_runner_task_pio0(cmd_runner)).unwrap();
                core::mem::forget(pio0.sm1);
                log::info!("[boot] pio0 cmd dio={} clk={}", entry.data_pin, entry.clk_pin);
            }
            PioRole::Stream => {
                pio::setup_pio_pin(entry.data_pin, entry.pio_idx, pio::PioPull::PullUp);
                pio::setup_pio_pin(entry.clk_pin, entry.pio_idx, pio::PioPull::PullUp);
                if entry.extra_pin != 0xFF {
                    pio::setup_pio_pin(entry.extra_pin, entry.pio_idx, pio::PioPull::PullUp);
                }
                let runner = PioStreamRunner::new_with_sideset(
                    pio0.sm0, dma_ch1_pio0,
                    entry.data_pin, entry.clk_pin, entry.extra_pin,
                    0, entry.pio_idx,
                );
                spawner.spawn(pio_stream_runner_task(runner)).unwrap();
                // RxStream on same PIO block (SM1) — from plan entry if present
                if let Some(rx) = rx_on_pio0 {
                    pio::setup_pio_pin(rx.data_pin, rx.pio_idx, pio::PioPull::PullUp);
                    if rx.clk_pin != 0xFF {
                        pio::setup_pio_pin(rx.clk_pin, rx.pio_idx, pio::PioPull::PullUp);
                    }
                    if rx.extra_pin != 0xFF {
                        pio::setup_pio_pin(rx.extra_pin, rx.pio_idx, pio::PioPull::PullUp);
                    }
                    let rx_runner = PioRxStreamRunner::new_with_sideset(
                        pio0.sm1, dma_ch6_pio0,
                        rx.data_pin, rx.clk_pin, rx.extra_pin,
                        0, rx.pio_idx,
                    );
                    spawner.spawn(pio_rx_stream_runner_task(rx_runner)).unwrap();
                    log::info!("[boot] pio0 rx data={} clk={} extra={}",
                        rx.data_pin, rx.clk_pin, rx.extra_pin);
                } else {
                    core::mem::forget(pio0.sm1);
                }
                log::info!("[boot] pio0 stream data={} bclk={} lrclk={}",
                    entry.data_pin, entry.clk_pin, entry.extra_pin);
            }
            PioRole::RxStream => {} // RxStream is always co-spawned with Stream
        }
        core::mem::forget(pio0.common);
        core::mem::forget(pio0.sm2);
        core::mem::forget(pio0.sm3);
    }

    // --- PIO1 init (consume p.PIO1 once) ---
    if let Some(entry) = pio1_role {
        let pio1 = Pio::new(p.PIO1, Pio1Irqs);
        match entry.role {
            PioRole::Cmd => {
                pio::setup_pio_pin(entry.data_pin, entry.pio_idx, pio::PioPull::None);
                pio::setup_pio_pin(entry.clk_pin, entry.pio_idx, pio::PioPull::None);
                let cmd_runner = PioCmdRunner::new_with_clk(
                    pio1.sm0, dma_ch0_pio1,
                    entry.data_pin, entry.clk_pin,
                    0, entry.pio_idx,
                );
                spawner.spawn(pio_cmd_runner_task(cmd_runner)).unwrap();
                core::mem::forget(pio1.sm1);
                log::info!("[boot] pio1 cmd dio={} clk={}", entry.data_pin, entry.clk_pin);
            }
            PioRole::Stream => {
                pio::setup_pio_pin(entry.data_pin, entry.pio_idx, pio::PioPull::PullUp);
                pio::setup_pio_pin(entry.clk_pin, entry.pio_idx, pio::PioPull::PullUp);
                if entry.extra_pin != 0xFF {
                    pio::setup_pio_pin(entry.extra_pin, entry.pio_idx, pio::PioPull::PullUp);
                }
                let runner = PioStreamRunner::new_with_sideset(
                    pio1.sm0, dma_ch1_pio1,
                    entry.data_pin, entry.clk_pin, entry.extra_pin,
                    0, entry.pio_idx,
                );
                spawner.spawn(pio_stream_runner_task_pio1(runner)).unwrap();
                // RxStream on same PIO block (SM1) — from plan entry if present
                if let Some(rx) = rx_on_pio1 {
                    pio::setup_pio_pin(rx.data_pin, rx.pio_idx, pio::PioPull::PullUp);
                    if rx.clk_pin != 0xFF {
                        pio::setup_pio_pin(rx.clk_pin, rx.pio_idx, pio::PioPull::PullUp);
                    }
                    if rx.extra_pin != 0xFF {
                        pio::setup_pio_pin(rx.extra_pin, rx.pio_idx, pio::PioPull::PullUp);
                    }
                    let rx_runner = PioRxStreamRunner::new_with_sideset(
                        pio1.sm1, dma_ch6_pio1,
                        rx.data_pin, rx.clk_pin, rx.extra_pin,
                        0, rx.pio_idx,
                    );
                    spawner.spawn(pio_rx_stream_runner_task_pio1(rx_runner)).unwrap();
                    log::info!("[boot] pio1 rx data={} clk={} extra={}",
                        rx.data_pin, rx.clk_pin, rx.extra_pin);
                } else {
                    core::mem::forget(pio1.sm1);
                }
                log::info!("[boot] pio1 stream data={} bclk={} lrclk={}",
                    entry.data_pin, entry.clk_pin, entry.extra_pin);
            }
            PioRole::RxStream => {} // RxStream is always co-spawned with Stream
        }
        core::mem::forget(pio1.common);
        core::mem::forget(pio1.sm2);
        core::mem::forget(pio1.sm3);
    }

    // --- PIO2 init (consume p.PIO2 once — RP2350B only, planner rejects on A) ---
    #[cfg(not(feature = "chip-rp2040"))]
    if let Some(entry) = pio2_role {
        let pio2 = Pio::new(p.PIO2, Pio2Irqs);
        match entry.role {
            PioRole::Cmd => {
                pio::setup_pio_pin(entry.data_pin, entry.pio_idx, pio::PioPull::None);
                pio::setup_pio_pin(entry.clk_pin, entry.pio_idx, pio::PioPull::None);
                let cmd_runner = PioCmdRunner::new_with_clk(
                    pio2.sm0, dma_ch0_pio2,
                    entry.data_pin, entry.clk_pin,
                    0, entry.pio_idx,
                );
                spawner.spawn(pio_cmd_runner_task_pio2(cmd_runner)).unwrap();
                core::mem::forget(pio2.sm1);
                log::info!("[boot] pio2 cmd dio={} clk={}", entry.data_pin, entry.clk_pin);
            }
            PioRole::Stream => {
                pio::setup_pio_pin(entry.data_pin, entry.pio_idx, pio::PioPull::PullUp);
                pio::setup_pio_pin(entry.clk_pin, entry.pio_idx, pio::PioPull::PullUp);
                if entry.extra_pin != 0xFF {
                    pio::setup_pio_pin(entry.extra_pin, entry.pio_idx, pio::PioPull::PullUp);
                }
                let runner = PioStreamRunner::new_with_sideset(
                    pio2.sm0, dma_ch1_pio2,
                    entry.data_pin, entry.clk_pin, entry.extra_pin,
                    0, entry.pio_idx,
                );
                spawner.spawn(pio_stream_runner_task_pio2(runner)).unwrap();
                // RxStream on same PIO block (SM1) — from plan entry if present
                if let Some(rx) = rx_on_pio2 {
                    pio::setup_pio_pin(rx.data_pin, rx.pio_idx, pio::PioPull::PullUp);
                    if rx.clk_pin != 0xFF {
                        pio::setup_pio_pin(rx.clk_pin, rx.pio_idx, pio::PioPull::PullUp);
                    }
                    if rx.extra_pin != 0xFF {
                        pio::setup_pio_pin(rx.extra_pin, rx.pio_idx, pio::PioPull::PullUp);
                    }
                    let rx_runner = PioRxStreamRunner::new_with_sideset(
                        pio2.sm1, dma_ch6_pio2,
                        rx.data_pin, rx.clk_pin, rx.extra_pin,
                        0, rx.pio_idx,
                    );
                    spawner.spawn(pio_rx_stream_runner_task_pio2(rx_runner)).unwrap();
                    log::info!("[boot] pio2 rx data={} clk={} extra={}",
                        rx.data_pin, rx.clk_pin, rx.extra_pin);
                } else {
                    core::mem::forget(pio2.sm1);
                }
                log::info!("[boot] pio2 stream data={} bclk={} lrclk={}",
                    entry.data_pin, entry.clk_pin, entry.extra_pin);
            }
            PioRole::RxStream => {} // RxStream is always co-spawned with Stream
        }
        core::mem::forget(pio2.common);
        core::mem::forget(pio2.sm2);
        core::mem::forget(pio2.sm3);
    }

    // PIO blocks not assigned to runners are accessed via raw PAC
    // through the PIO register bridge (dev_system 0x0C70-0x0C7B).

    // --- Setup runner ---
    let config = RunnerConfig {
        spi_bus: hw.spi_bus(),
        cs_pin: hw.cs_pin(),
    };

    // Yield to executor: let spawned async tasks (PIO runners, SPI, I2C, ADC)
    // reach their first await point before modules begin using them.
    Timer::after(Duration::from_millis(1)).await;

    if !setup(&config) {
        log::error!("[boot] setup failed");
        loop { Timer::after(Duration::from_millis(1000)).await; }
    }

    // Load modules (may do async init like SPI DMA)
    let module_count = setup_graph_async().await;
    if module_count < 0 {
        log::error!("[boot] graph setup failed");
        loop { Timer::after(Duration::from_millis(1000)).await; }
    }

    log::info!("[boot] ready modules={}", module_count);

    // Run the main loop
    run_main_loop(module_count as usize).await;
}

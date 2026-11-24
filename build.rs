//! Build script for fluxor
//!
//! Stages the target-specific linker script from `linker/` and generates
//! chip_generated.rs from the silicon TOML [kernel] section.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The domain-to-core map's rules, shared with the kernel and the graph
/// builder.
use fluxor_contracts::core_map;

/// The RP timer ownership rules, shared with the kernel's host tests.
#[path = "src/platform/rp/timer_ledger.rs"]
#[allow(
    dead_code,
    reason = "the kernel's file, mounted whole; only an RP build's ledger reaches every item"
)]
mod timer_ledger;

// ============================================================================
// TOML schema (only the [kernel] section)
// ============================================================================

#[derive(Deserialize)]
struct SiliconToml {
    kernel: Option<KernelConfig>,
    peripherals: Option<PeripheralConfig>,
    memory: Option<MemoryToml>,
    isolation: Option<IsolationToml>,
}

/// `[smp]`: the cores that run a domain loop and the core of each domain.
#[derive(Deserialize)]
struct SmpToml {
    cores: u8,
    domain_cores: Vec<u8>,
    secondary_stack: Option<SecondaryStackToml>,
}

/// The second core's stack: its base, its size and the kernel's share of it
/// under a module.
#[derive(Deserialize)]
struct SecondaryStackToml {
    size_kb: u32,
    reserve_kb: u32,
}

/// Only `[smp]`, for the targets whose other sections the kernel build does
/// not read.
#[derive(Deserialize)]
struct SmpOnly {
    smp: Option<SmpToml>,
}

/// The `[isolation]` facts the RP protection backend compiles against. The
/// tools parse the whole section; the kernel needs only how regions are
/// drawn and how many there are, and checks the count against `MPU_TYPE`.
#[derive(Deserialize)]
struct IsolationToml {
    region_model: Option<String>,
    regions: Option<u8>,
    device_ranges: Option<Vec<DeviceRangeToml>>,
    peripheral_gate: Option<PeripheralGateToml>,
}

/// ACCESSCTRL: the peripheral registers the kernel makes privileged-only.
#[derive(Deserialize)]
struct PeripheralGateToml {
    base: String,
    first: String,
    last: String,
}

/// A peripheral block a gated driver's device window may lie in.
#[derive(Deserialize)]
struct DeviceRangeToml {
    base: String,
    size: String,
    gate: Option<String>,
}

#[derive(Deserialize)]
struct MemoryToml {
    ram_size: String,
    flash_base: Option<String>,
    flash_size: Option<String>,
    /// Flash the kernel keeps for itself at the bottom, which the graph-slot
    /// partition (`flash_layout::graph_flash`) leaves it.
    kernel_flash_reserve: Option<String>,
    /// The flash's erase unit and program page: the partition aligns every
    /// region to the first, and `flash_rp`'s data store serves blocks of it.
    flash_erase_size: Option<String>,
    flash_program_size: Option<String>,
}

// Board TOML — the board facts this script generates.
#[derive(Deserialize)]
struct BoardToml {
    platform: Option<BoardPlatform>,
    hardware: Option<BoardHardware>,
    kernel: Option<BoardKernel>,
}

/// `[kernel]` in a board TOML: kernel behaviour the board fixes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoardKernel {
    tick: Option<BoardTick>,
}

/// `[kernel.tick]`: the bcm2712 tick's optional wake mechanisms, both off
/// unless the board turns them on.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BoardTick {
    /// A wake also raises the doorbell SGI, so a core parked in WFI wakes
    /// at once rather than at its next tick.
    #[serde(default)]
    wake_doorbell: bool,
    /// The per-core timer re-arms to an absolute `cval` deadline rather
    /// than a relative `tval`.
    #[serde(default)]
    absolute_rearm: bool,
}

#[derive(Deserialize)]
struct BoardHardware {
    xosc: Option<BoardXosc>,
    console_uart: Option<BoardConsoleUart>,
    flash: Option<BoardFlash>,
}

/// The flash a board fits: the die has none of its own, and boards over one
/// silicon differ (a Pico W 2 MB, a Pico 2 W 4 MB, larger boards 16 MB).
#[derive(Deserialize)]
struct BoardFlash {
    size: String,
    /// The board's flash part, where it differs from the silicon's default.
    erase_size: Option<String>,
    program_size: Option<String>,
}

#[derive(Deserialize)]
struct BoardConsoleUart {
    tx_pin: u8,
    rx_pin: u8,
    baud: u32,
}

#[derive(Deserialize)]
struct BoardXosc {
    hz: u32,
}

#[derive(Deserialize)]
struct BoardPlatform {
    pcie: Option<BoardPcie>,
}

#[derive(Deserialize)]
struct BoardPcie {
    #[serde(default)]
    aliases: Vec<PcieAliasEntry>,
}

#[derive(Deserialize)]
struct PcieAliasEntry {
    name: String,
    root: String,
    bus: u8,
    dev: u8,
    func: u8,
}

/// Per-silicon resource counts. Generated
/// so a driver bounds itself by a declared number rather than a literal that
/// happens to suit one die.
#[derive(Deserialize, Default)]
struct PeripheralConfig {
    dma_channels: Option<u8>,
    dma_ctrl_trig: Option<std::collections::BTreeMap<String, Vec<u32>>>,
    dma_chan_abort_offset: Option<String>,
    pio_count: Option<u8>,
    spi_bases: Option<Vec<String>>,
    spi_dreq: Option<Vec<Vec<u8>>>,
    i2c_bases: Option<Vec<String>>,
    i2c_dreq: Option<Vec<Vec<u8>>>,
    uart_bases: Option<Vec<String>>,
    uart_dreq: Option<Vec<Vec<u8>>>,
    adc_base: Option<String>,
    pio0_base: Option<String>,
    uart0_base: Option<String>,
    resets_uart0_bit: Option<u32>,
    resets_io_bank0_bit: Option<u32>,
    resets_pads_bank0_bit: Option<u32>,
    resets_base: Option<String>,
    resets_usbctrl_bit: Option<u32>,
    irq_count: Option<u32>,
    resets_release_mask: Option<String>,
    resets_required_mask: Option<String>,
    resets_pll_sys_bit: Option<u32>,
    resets_pll_usb_bit: Option<u32>,
    rosc_base: Option<String>,
    rosc_randombit_offset: Option<String>,
    trng_base: Option<String>,
    pwm_slices: Option<u8>,
    pwm_base: Option<String>,
    xosc_base: Option<String>,
    pll_sys_base: Option<String>,
    pll_usb_base: Option<String>,
    clocks_clk_usb_ctrl_offset: Option<String>,
    clocks_base: Option<String>,
    clocks_fc0_offset: Option<String>,
    io_bank0_base: Option<String>,
    pads_bank0_base: Option<String>,
    sio_gpio_out_base: Option<String>,
    sio_gpio_oe_base: Option<String>,
    sio_reg_stride: Option<String>,
    sio_bank_stride: Option<String>,
    dma_trans_count_mode: Option<Vec<u32>>,
    dma_base: Option<String>,
    xip_ctrl_base: Option<String>,
}

#[derive(Deserialize)]
struct KernelConfig {
    watchdog_ctrl: String,
    psm_wdsel: String,
    psm_wdsel_mask: String,
    boot2_src: String,
    kernel_pool_kb: u32,
    state_arena_kb: u32,
    buffer_arena_kb: u32,
    config_buffer_kb: u32,
    log_ring_kb: u32,
    telemetry_ring_kb: u32,
    ram_static_max_kb: u32,
    kernel_stack_reserve_kb: u32,
    sys_hz: u32,
    overclock_sys_hz: Option<u32>,
    usb_hz: u32,
    timers: TimerLedger,
    flash_erase_block_size: String,
    flash_erase_cmd: String,
    bootsel: BootselConfig,
    /// RP2040 only: its unique ID lives in the flash device.
    flash_unique_id: Option<FlashUniqueIdConfig>,
}

/// One alarm and its single named owner.
#[derive(Deserialize)]
struct TimerAlarm {
    index: u8,
    owner: String,
    irq: u16,
}

/// Per-silicon timer ownership. Every alarm on the monotonic instance has
/// exactly one owner; the build rejects overlap rather than leaving it to a
/// comment that can go stale — as a prose claim about which alarms are free
/// in `step_guard.rs` did, which measurement showed reserved only alarm 0.
#[derive(Deserialize)]
struct TimerLedger {
    monotonic: String,
    monotonic_base: String,
    ticks_base: Option<String>,
    timer_intr_offset: String,
    timer_inte_offset: String,
    alarms: Vec<TimerAlarm>,
    provider_alarms: Vec<u8>,
    foreign_instance: String,
    foreign_alarms: Vec<u8>,
    /// A second core's own instance, where the die runs a domain on one.
    secondary: Option<String>,
    secondary_base: Option<String>,
    secondary_alarms: Option<Vec<TimerAlarm>>,
}

#[derive(Deserialize)]
struct BootselConfig {
    qspi_ss_bit: u8,
    flash_release_addr: String,
    flash_release_value: String,
    pad_addr: String,
    pad_value: String,
    ctrl_addr: String,
    ctrl_value: String,
    status_addr: String,
    gpio_hi_addr: String,
}

/// Reading the flash device's unique ID over XIP_SSI (RP2040).
#[derive(Deserialize)]
struct FlashUniqueIdConfig {
    ssi_dr0_addr: String,
    ssi_sr_addr: String,
    ssi_sr_rfne_bit: u8,
    ss_ctrl_addr: String,
    ss_outover_mask: String,
    ss_outover_low: String,
    ss_outover_high: String,
    cmd: String,
    dummy_bytes: u8,
}

// ============================================================================
// Hex parsing
// ============================================================================

fn parse_hex(s: &str) -> u32 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).expect(s)
    } else {
        s.parse::<u32>().expect(s)
    }
}

// ============================================================================
// Code generation
// ============================================================================

/// The `LENGTH` of the `RAM` region in a linker memory map, in bytes.
fn linker_ram_bytes(script: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(script).ok()?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("RAM ") || l.starts_with("RAM:"))?;
    let len = line
        .split("LENGTH")
        .nth(1)?
        .trim_start_matches([' ', '='])
        .trim();
    let (digits, scale) = match len.strip_suffix('K') {
        Some(d) => (d, 1024),
        None => match len.strip_suffix('M') {
            Some(d) => (d, 1024 * 1024),
            None => (len, 1),
        },
    };
    digits.trim().parse::<u32>().ok().map(|n| n * scale)
}

fn emit_const(gen: &mut String, name: &str, ty: &str, val: &str) {
    gen.push_str(&format!("pub const {name}: {ty} = {val};\n"));
}

/// `DEVICE_RANGES`: the peripheral blocks a device window may lie in. The
/// kernel refuses a window outside them even when the composer admitted it.
fn emit_device_ranges(gen: &mut String, isolation: Option<&IsolationToml>) {
    let hex64 = |s: &str| {
        let h = s
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .replace('_', "");
        u64::from_str_radix(&h, 16).unwrap_or_else(|_| panic!("device_ranges: '{s}' is not hex"))
    };
    let ranges: Vec<String> = isolation
        .and_then(|i| i.device_ranges.as_ref())
        .into_iter()
        .flatten()
        .map(|r| format!("(0x{:x}, 0x{:x})", hex64(&r.base), hex64(&r.size)))
        .collect();
    emit_const(
        gen,
        "DEVICE_RANGES",
        "&[(u64, u64)]",
        &format!("&[{}]", ranges.join(", ")),
    );
}

fn emit_hex_const(gen: &mut String, name: &str, hex_str: &str) {
    let v = parse_hex(hex_str);
    gen.push_str(&format!("pub const {name}: u32 = {v:#010X};\n"));
}

fn generate_chip_rs(
    k: &KernelConfig,
    is_rp2040: bool,
    p: &PeripheralConfig,
    ram_bytes: u32,
) -> String {
    let dma_channels = p.dma_channels.expect("dma_channels");
    let mut g = String::from("// Auto-generated by build.rs from silicon TOML — do not edit\n\n");

    emit_hex_const(&mut g, "WATCHDOG_CTRL", &k.watchdog_ctrl);
    emit_hex_const(&mut g, "PSM_WDSEL", &k.psm_wdsel);
    emit_hex_const(&mut g, "PSM_WDSEL_MASK", &k.psm_wdsel_mask);
    emit_hex_const(&mut g, "BOOT2_SRC", &k.boot2_src);
    g.push('\n');

    // The kernel's one static pool: each graph's plan splits it between the
    // kernel tables, the buffer arena and the state arena. A pool that cannot
    // hold the default arenas beside each other plans no graph the composer
    // admits; one past the static-RAM ceiling could never link inside it.
    assert!(
        k.kernel_pool_kb >= k.state_arena_kb + k.buffer_arena_kb,
        "kernel_pool_kb ({}) cannot hold state_arena_kb + buffer_arena_kb ({})",
        k.kernel_pool_kb,
        k.state_arena_kb + k.buffer_arena_kb
    );
    assert!(
        k.kernel_pool_kb < k.ram_static_max_kb,
        "kernel_pool_kb ({}) leaves the kernel no static RAM under ram_static_max_kb ({})",
        k.kernel_pool_kb,
        k.ram_static_max_kb
    );
    emit_const(
        &mut g,
        "KERNEL_POOL_SIZE",
        "usize",
        &format!("{}", k.kernel_pool_kb * 1024),
    );
    emit_const(
        &mut g,
        "STATE_ARENA_SIZE",
        "usize",
        &format!("{}", k.state_arena_kb * 1024),
    );
    emit_const(
        &mut g,
        "BUFFER_ARENA_SIZE",
        "usize",
        &format!("{}", k.buffer_arena_kb * 1024),
    );
    emit_const(
        &mut g,
        "MAX_MODULE_CONFIG_SIZE",
        "usize",
        &format!("{}", k.config_buffer_kb * 1024),
    );
    emit_const(
        &mut g,
        "LOG_RING_CAPACITY",
        "usize",
        &format!("{}", k.log_ring_kb * 1024),
    );
    emit_const(
        &mut g,
        "TELEMETRY_RING_CAPACITY",
        "usize",
        &format!("{}", k.telemetry_ring_kb * 1024),
    );

    // The kernel stack: what the RAM region leaves above the static-RAM
    // ceiling, and the part of it the kernel keeps for its own frames at a
    // module call. The composer admits the deepest module against the
    // difference; the scheduler fences each step at it.
    let stack_budget = ram_bytes
        .checked_sub(k.ram_static_max_kb * 1024)
        .expect("ram_static_max_kb exceeds the RAM region");
    let reserve = k.kernel_stack_reserve_kb * 1024;
    assert!(
        reserve < stack_budget,
        "kernel_stack_reserve_kb leaves no stack for a module"
    );
    emit_const(
        &mut g,
        "KERNEL_STACK_BUDGET",
        "usize",
        &format!("{stack_budget}"),
    );
    emit_const(
        &mut g,
        "KERNEL_STACK_RESERVE",
        "usize",
        &format!("{reserve}"),
    );

    // Clock profile. SYS_CLK_HZ is the production system clock; the
    // `rp-overclock` feature substitutes the silicon's declared
    // non-production profile, and a silicon that declares none cannot
    // be overclocked by a feature flag alone.
    // Build scripts see features through CARGO_FEATURE_*, never `cfg!`
    // — `cfg!` here would report the build script's own cfg and silently
    // evaluate false for every consumer.
    let overclock = std::env::var_os("CARGO_FEATURE_RP_OVERCLOCK").is_some();
    let sys_hz = if overclock {
        k.overclock_sys_hz.unwrap_or_else(|| {
            panic!(
                "rp-overclock is enabled but this silicon declares no \
                 overclock_sys_hz — an overclock has to be a published \
                 fact, not an implied one"
            )
        })
    } else {
        k.sys_hz
    };

    // Range checks: a clock fact that is out of range should fail the
    // build that declared it, not the silicon that runs it.
    assert!(
        (1_000_000..=400_000_000).contains(&sys_hz),
        "sys clock {sys_hz} Hz is outside any plausible RP range"
    );
    assert_eq!(
        k.usb_hz, 48_000_000,
        "USB requires exactly 48 MHz; this silicon declares {} Hz",
        k.usb_hz
    );
    if let Some(oc) = k.overclock_sys_hz {
        assert!(
            oc > k.sys_hz,
            "overclock_sys_hz ({oc}) must exceed the production sys_hz ({})",
            k.sys_hz
        );
    }

    emit_const(&mut g, "SYS_CLK_HZ", "u32", &format!("{sys_hz}"));
    emit_const(&mut g, "USB_CLK_HZ", "u32", &format!("{}", k.usb_hz));

    // ── Timer ownership ledger ───────────────────────────────────────
    // The build rejects overlap. An alarm with two owners is a fault that
    // shows up as one subsystem's deadline silently cancelling another's,
    // which is close to undiagnosable on hardware and trivial to catch here.
    let t = &k.timers;
    let mut claimed: std::collections::BTreeMap<u8, String> = Default::default();
    for a in &t.alarms {
        assert!(
            a.index < 4,
            "{} alarm {} is out of range: RP timers have 4 alarms (0-3)",
            t.monotonic,
            a.index
        );
        if let Some(prev) = claimed.insert(a.index, a.owner.clone()) {
            panic!(
                "{} alarm {} is claimed by both '{}' and '{}'",
                t.monotonic, a.index, prev, a.owner
            );
        }
    }
    for idx in &t.provider_alarms {
        assert!(
            *idx < 4,
            "{} provider alarm {idx} is out of range (0-3)",
            t.monotonic
        );
        if let Some(prev) = claimed.insert(*idx, "timer provider".to_string()) {
            panic!(
                "{} alarm {idx} is offered to the timer provider but already owned by '{prev}'",
                t.monotonic
            );
        }
    }
    // The external time driver's reservation only collides when it is on the
    // same instance — which on RP2040 it is, there being only one.
    if t.foreign_instance == t.monotonic {
        for idx in &t.foreign_alarms {
            if let Some(prev) = claimed.get(idx) {
                panic!(
                    "{} alarm {idx} is reserved by the external time driver but also owned by '{prev}'",
                    t.monotonic
                );
            }
        }
    }
    // IRQ lines must be distinct: two owners on one line cannot tell whose
    // deadline fired.
    let mut irqs: std::collections::BTreeMap<u16, String> = Default::default();
    for a in &t.alarms {
        if let Some(prev) = irqs.insert(a.irq, a.owner.clone()) {
            panic!(
                "IRQ {} is shared by '{}' and '{}'; each alarm owner needs its own line",
                a.irq, prev, a.owner
            );
        }
    }

    // A second core's instance joins the same ledger: its alarms are checked
    // with the monotonic instance's as one set, so an alarm, a reserved
    // alarm or an NVIC line claimed on both sides is refused here.
    let secondary_alarms = t.secondary_alarms.as_deref().unwrap_or(&[]);
    if let Some(secondary) = &t.secondary {
        assert!(
            *secondary != t.monotonic,
            "[kernel.timers] secondary is the monotonic instance {secondary}; a second core \
             needs a timer of its own"
        );
        assert!(
            t.secondary_base.is_some() && !secondary_alarms.is_empty(),
            "[kernel.timers] secondary = {secondary} needs secondary_base and secondary_alarms"
        );
    } else {
        assert!(
            t.secondary_base.is_none() && secondary_alarms.is_empty(),
            "[kernel.timers] secondary_base and secondary_alarms need `secondary`"
        );
    }
    // Instance numbers for the shared rules: 0 the monotonic instance, 1 the
    // secondary, 2 a foreign instance that is neither.
    let instance_of = |name: &str| -> u8 {
        if name == t.monotonic {
            0
        } else if t.secondary.as_deref() == Some(name) {
            1
        } else {
            2
        }
    };
    let claims: Vec<(timer_ledger::Claim, String)> = t
        .alarms
        .iter()
        .map(|a| (0u8, t.monotonic.as_str(), a))
        .chain(
            secondary_alarms
                .iter()
                .map(|a| (1u8, t.secondary.as_deref().unwrap_or(""), a)),
        )
        .map(|(instance, name, a)| {
            (
                timer_ledger::Claim {
                    instance,
                    alarm: a.index,
                    irq: a.irq,
                },
                format!("{name} alarm {} ('{}', IRQ {})", a.index, a.owner, a.irq),
            )
        })
        .collect();
    let reserved: Vec<timer_ledger::Reserved> = t
        .foreign_alarms
        .iter()
        .map(|&alarm| timer_ledger::Reserved {
            instance: instance_of(&t.foreign_instance),
            alarm,
        })
        .chain(
            t.provider_alarms
                .iter()
                .map(|&alarm| timer_ledger::Reserved { instance: 0, alarm }),
        )
        .collect();
    let only: Vec<timer_ledger::Claim> = claims.iter().map(|(c, _)| *c).collect();
    if let Err(e) = timer_ledger::check(&only, &reserved) {
        use timer_ledger::LedgerError as E;
        match e {
            E::AlarmOutOfRange { claim } => {
                panic!(
                    "{} is out of range: RP timers have 4 alarms (0-3)",
                    claims[claim].1
                )
            }
            E::AlarmClaimedTwice { first, second } => panic!(
                "{} and {} claim one alarm",
                claims[first].1, claims[second].1
            ),
            E::AlarmReserved { claim } => panic!(
                "{} is reserved: the external time driver's or the timer provider's",
                claims[claim].1
            ),
            E::IrqShared { first, second } => panic!(
                "{} and {} share an NVIC line; each alarm owner needs its own",
                claims[first].1, claims[second].1
            ),
        }
    }

    emit_const(
        &mut g,
        "TIMER_MONOTONIC",
        "&str",
        &format!("{:?}", t.monotonic),
    );
    // Resource count, not a literal: RP2350 has 16 DMA channels and RP2040
    // has 12, and a mask that assumes the larger hands out channels the
    // smaller die does not implement.
    assert!(
        dma_channels > 0 && dma_channels <= 16,
        "dma_channels {dma_channels} is outside the RP range"
    );
    emit_const(&mut g, "DMA_CHANNELS", "u8", &format!("{dma_channels}"));

    // The CTRL_TRIG field layout is silicon data, not a constant. RP2350
    // inserted INCR_READ_REV and INCR_WRITE_REV at bits 5 and 7, moving every
    // field above bit 4 up by two. A field written at the other chip's
    // position does not fault — it lands in a neighbour, so the transfer is
    // configured wrongly and simply never completes.
    let ctrl = p
        .dma_ctrl_trig
        .as_ref()
        .unwrap_or_else(|| panic!("[peripherals.dma_ctrl_trig] is required"));
    // A transcription error that overlaps two fields is the one that costs
    // days on hardware, so it fails the build instead.
    let mut occupied: u32 = 0;
    for (name, spec) in ctrl {
        assert_eq!(
            spec.len(),
            2,
            "dma_ctrl_trig.{name} must be [lsb, width], got {spec:?}"
        );
        let (lsb, width) = (spec[0], spec[1]);
        assert!(
            width >= 1 && lsb + width <= 32,
            "dma_ctrl_trig.{name} = [{lsb}, {width}] does not fit in 32 bits"
        );
        let mask = (((1u64 << width) - 1) << lsb) as u32;
        assert!(
            occupied & mask == 0,
            "dma_ctrl_trig.{name} = [{lsb}, {width}] overlaps a field already claimed"
        );
        occupied |= mask;
        let up = name.to_uppercase();
        emit_const(
            &mut g,
            &format!("DMA_CTRL_{up}_LSB"),
            "u32",
            &format!("{lsb}"),
        );
        emit_const(
            &mut g,
            &format!("DMA_CTRL_{up}_WIDTH"),
            "u32",
            &format!("{width}"),
        );
    }
    assert!(
        ctrl.contains_key("busy"),
        "dma_ctrl_trig must declare `busy`; the flash quiesce polls it"
    );

    // SIO lays its two GPIO banks out differently on the two chips — RP2040
    // contiguous per bank, RP2350 interleaved — so both strides are silicon
    // data. A wrong stride addresses a real register, just not the intended
    // one: the pin in the other bank, or OE where OUT was meant.
    for (name, value) in [
        ("PIO0_BASE", &p.pio0_base),
        ("RESETS_BASE", &p.resets_base),
        ("UART0_BASE", &p.uart0_base),
        ("ROSC_BASE", &p.rosc_base),
        ("ROSC_RANDOMBIT_OFFSET", &p.rosc_randombit_offset),
        ("PWM_BASE", &p.pwm_base),
        ("CLOCKS_BASE", &p.clocks_base),
        ("XOSC_BASE", &p.xosc_base),
        ("PLL_SYS_BASE", &p.pll_sys_base),
        ("PLL_USB_BASE", &p.pll_usb_base),
        ("CLOCKS_CLK_USB_CTRL_OFFSET", &p.clocks_clk_usb_ctrl_offset),
        ("CLOCKS_FC0_OFFSET", &p.clocks_fc0_offset),
        ("IO_BANK0_BASE", &p.io_bank0_base),
        ("PADS_BANK0_BASE", &p.pads_bank0_base),
        ("SIO_GPIO_OUT_BASE", &p.sio_gpio_out_base),
        ("SIO_GPIO_OE_BASE", &p.sio_gpio_oe_base),
        ("SIO_REG_STRIDE", &p.sio_reg_stride),
        ("SIO_BANK_STRIDE", &p.sio_bank_stride),
    ] {
        emit_hex_const(
            &mut g,
            name,
            value
                .as_deref()
                .unwrap_or_else(|| panic!("[peripherals] {name} is required")),
        );
    }

    // The crystal is a BOARD fact: the die takes whatever crystal the board
    // fits, and two boards over one silicon can differ. Resolved from the
    // active board TOML when one is named.
    //
    // Absent a board (a plain `cargo build`, or clippy), this falls back to
    // the 12 MHz every RP board in this tree fits. That is a convenience for
    // tooling, not a silicon fact — a firmware build always names its board,
    // because tools/firmware.sh exports it.
    const FALLBACK_XOSC_HZ: u32 = 12_000_000;
    let xosc_hz = std::env::var("FLUXOR_BOARD")
        .ok()
        .and_then(|board| {
            let path = format!("targets/boards/{board}.toml");
            println!("cargo:rerun-if-changed={path}");
            let text = fs::read_to_string(&path).ok()?;
            let parsed: BoardToml = toml::from_str(&text).ok()?;
            parsed.hardware?.xosc.map(|x| x.hz)
        })
        .unwrap_or(FALLBACK_XOSC_HZ);
    assert!(
        (1_000_000..=50_000_000).contains(&xosc_hz),
        "xosc {xosc_hz} Hz is not a plausible RP crystal"
    );
    emit_const(&mut g, "XOSC_HZ", "u32", &format!("{xosc_hz}"));

    // Which header pins carry the fallback console is board wiring, not
    // silicon. Absent when a board has no such header, so a build for one
    // cannot quietly drive two arbitrary pins.
    let console = std::env::var("FLUXOR_BOARD").ok().and_then(|board| {
        let text = fs::read_to_string(format!("targets/boards/{board}.toml")).ok()?;
        toml::from_str::<BoardToml>(&text)
            .ok()?
            .hardware?
            .console_uart
    });
    if let Some(c) = console {
        emit_const(
            &mut g,
            "CONSOLE_UART_TX_PIN",
            "u8",
            &format!("{}", c.tx_pin),
        );
        emit_const(
            &mut g,
            "CONSOLE_UART_RX_PIN",
            "u8",
            &format!("{}", c.rx_pin),
        );
        assert!(
            (300..=4_000_000).contains(&c.baud),
            "console baud {} is outside any plausible range",
            c.baud
        );
        emit_const(&mut g, "CONSOLE_UART_BAUD", "u32", &format!("{}", c.baud));
        // The consts above exist only on this path, so the code that reads
        // them must be gated on the same condition rather than on the RP
        // feature — a silicon-level build has no board and no header.
        println!("cargo:rustc-cfg=console_uart");
    }
    println!("cargo:rerun-if-env-changed=FLUXOR_BOARD");
    // A label for the built image, surfaced by the RP runtime's USB
    // report. Flashing is manual; without it, a drag-and-drop that did not
    // take is indistinguishable from a change that did not work.
    println!("cargo:rerun-if-env-changed=FLUXOR_IMAGE_TAG");

    let uart_reset = p
        .resets_uart0_bit
        .unwrap_or_else(|| panic!("[peripherals] resets_uart0_bit is required"));
    assert!(
        uart_reset < 32,
        "resets_uart0_bit {uart_reset} is not a bit"
    );
    emit_const(&mut g, "RESETS_UART0_BIT", "u32", &format!("{uart_reset}"));

    for (key, value, name) in [
        (
            "resets_io_bank0_bit",
            p.resets_io_bank0_bit,
            "RESETS_IO_BANK0_BIT",
        ),
        (
            "resets_pads_bank0_bit",
            p.resets_pads_bank0_bit,
            "RESETS_PADS_BANK0_BIT",
        ),
    ] {
        let bit = value.unwrap_or_else(|| panic!("[peripherals] {key} is required"));
        assert!(bit < 32, "{key} {bit} is not a bit");
        emit_const(&mut g, name, "u32", &format!("{bit}"));
    }

    let usb_reset = p
        .resets_usbctrl_bit
        .unwrap_or_else(|| panic!("[peripherals] resets_usbctrl_bit is required"));
    assert!(
        usb_reset < 32,
        "resets_usbctrl_bit {usb_reset} is not a bit"
    );
    emit_const(&mut g, "RESETS_USBCTRL_BIT", "u32", &format!("{usb_reset}"));

    let irqs = p
        .irq_count
        .unwrap_or_else(|| panic!("[peripherals] irq_count is required"));
    // Armv6-M fixes the NVIC at 32 external interrupts; Armv7-M and Armv8-M
    // architect up to 240. Checking against the wider bound alone would let
    // an RP2040-class TOML declare a table longer than its NVIC can index,
    // which is space wasted rather than a fault, but the number is also what
    // the vector table is built from and it should mean something.
    let target = std::env::var("TARGET").unwrap_or_default();
    let architected_max = if target.starts_with("thumbv6m") {
        32
    } else {
        240
    };
    assert!(
        (1..=architected_max).contains(&irqs),
        "irq_count {irqs} is outside the NVIC range architected for {target}"
    );
    emit_const(&mut g, "IRQ_COUNT", "usize", &format!("{irqs}"));

    let release = p
        .resets_release_mask
        .as_deref()
        .unwrap_or_else(|| panic!("[peripherals] resets_release_mask is required"));
    let release_bits = u32::from_str_radix(release.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("resets_release_mask {release} is not hex"));
    assert!(
        release_bits != 0,
        "resets_release_mask is empty: no peripheral would ever leave reset"
    );
    emit_const(
        &mut g,
        "RESETS_RELEASE_MASK",
        "u32",
        &format!("0x{release_bits:08x}"),
    );

    let required = p
        .resets_required_mask
        .as_deref()
        .unwrap_or_else(|| panic!("[peripherals] resets_required_mask is required"));
    let required_bits = u32::from_str_radix(required.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("resets_required_mask {required} is not hex"));
    assert!(
        required_bits & !release_bits == 0,
        "resets_required_mask names bits the release mask never clears"
    );
    emit_const(
        &mut g,
        "RESETS_REQUIRED_MASK",
        "u32",
        &format!("0x{required_bits:08x}"),
    );

    // Both PLLs' reset bits. Required, not optional: a PLL left in reset
    // accepts every configuration write and locks to none of them, so a
    // build that cannot name these has no way to bring the clock tree up.
    for (field, value, name) in [
        (
            "resets_pll_sys_bit",
            p.resets_pll_sys_bit,
            "RESETS_PLL_SYS_BIT",
        ),
        (
            "resets_pll_usb_bit",
            p.resets_pll_usb_bit,
            "RESETS_PLL_USB_BIT",
        ),
    ] {
        let bit = value.unwrap_or_else(|| panic!("[peripherals] {field} is required"));
        assert!(bit < 32, "{field} {bit} is not a bit");
        emit_const(&mut g, name, "u32", &format!("{bit}"));
    }

    // Present only where the hardware is. RP2040 has no TRNG, so naming one
    // must fail to build rather than silently fall back to the ring
    // oscillator and keep calling the result a hardware CSPRNG.
    if let Some(trng) = &p.trng_base {
        emit_hex_const(&mut g, "TRNG_BASE", trng);
    }

    // RP2040 has two PIO instances and RP2350 has three. The syscall bridge
    // accepted index 2 on both, and the RP2040 index mapping sent it to PIO0
    // rather than refusing — so a request for a PIO that is not there
    // reconfigured the one already driving something else.
    let pio_count = p
        .pio_count
        .unwrap_or_else(|| panic!("[peripherals] pio_count is required"));
    assert!(
        (2..=3).contains(&pio_count),
        "pio_count {pio_count} is outside the RP range"
    );
    emit_const(&mut g, "PIO_COUNT", "u8", &format!("{pio_count}"));

    // The buses the raw bridges drive: each bus's register block and the
    // [tx, rx] DREQs that pace DMA from it, by bus number. A bus the die
    // does not have is `None`, so no index reaches another block.
    for (what, bases, dreq) in [
        ("SPI", &p.spi_bases, &p.spi_dreq),
        ("I2C", &p.i2c_bases, &p.i2c_dreq),
        ("UART", &p.uart_bases, &p.uart_dreq),
    ] {
        let lower = what.to_ascii_lowercase();
        let bases = bases
            .as_ref()
            .unwrap_or_else(|| panic!("[peripherals] {lower}_bases is required"));
        let dreq = dreq
            .as_ref()
            .unwrap_or_else(|| panic!("[peripherals] {lower}_dreq is required"));
        assert_eq!(
            bases.len(),
            dreq.len(),
            "{lower}_bases and {lower}_dreq differ in length"
        );
        emit_const(
            &mut g,
            &format!("{what}_COUNT"),
            "u8",
            &format!("{}", bases.len()),
        );
        g.push_str(&format!(
            "/// The register block of {what} bus `bus`.\npub const fn {lower}_base(bus: u8) -> Option<usize> {{\n    match bus {{\n"
        ));
        for (i, b) in bases.iter().enumerate() {
            g.push_str(&format!("        {i} => Some({:#010X}),\n", parse_hex(b)));
        }
        g.push_str("        _ => None,\n    }\n}\n");
        g.push_str(&format!(
            "/// The DMA DREQs of {what} bus `bus`, as (tx, rx).\npub const fn {lower}_dreq(bus: u8) -> Option<(u8, u8)> {{\n    match bus {{\n"
        ));
        for (i, d) in dreq.iter().enumerate() {
            assert_eq!(d.len(), 2, "{lower}_dreq entries are [tx, rx]");
            g.push_str(&format!("        {i} => Some(({}, {})),\n", d[0], d[1]));
        }
        g.push_str("        _ => None,\n    }\n}\n");
    }
    emit_hex_const(
        &mut g,
        "ADC_BASE",
        p.adc_base
            .as_deref()
            .unwrap_or_else(|| panic!("[peripherals] adc_base is required")),
    );

    // RP2040 has 8 PWM slices and RP2350 has 12. The bound is per silicon
    // rather than the wider of the two: a slice index the die does not
    // implement is a write into nothing, accepted and lost.
    let pwm_slices = p
        .pwm_slices
        .unwrap_or_else(|| panic!("[peripherals] pwm_slices is required"));
    assert!(
        pwm_slices > 0 && pwm_slices <= 12,
        "pwm_slices {pwm_slices} is outside the RP range"
    );
    emit_const(&mut g, "PWM_SLICES", "u8", &format!("{pwm_slices}"));

    // Not the same on both chips: RP2040 0x444, RP2350 0x464. Aborting the
    // wrong register does nothing visible until the channel that should have
    // stopped keeps writing.
    emit_hex_const(
        &mut g,
        "DMA_CHAN_ABORT_OFFSET",
        p.dma_chan_abort_offset
            .as_deref()
            .unwrap_or_else(|| panic!("[peripherals] dma_chan_abort_offset is required")),
    );
    // Present only where the register actually has the field, so a build for
    // the chip without it cannot silently write into the top of the count.
    if let Some(m) = &p.dma_trans_count_mode {
        assert_eq!(m.len(), 2, "dma_trans_count_mode must be [lsb, width]");
        emit_const(
            &mut g,
            "DMA_TRANS_COUNT_MODE_LSB",
            "u32",
            &format!("{}", m[0]),
        );
        emit_const(
            &mut g,
            "DMA_TRANS_COUNT_MODE_WIDTH",
            "u32",
            &format!("{}", m[1]),
        );
    }
    emit_hex_const(
        &mut g,
        "DMA_BASE",
        p.dma_base
            .as_deref()
            .unwrap_or_else(|| panic!("[peripherals] dma_base is required")),
    );
    emit_hex_const(
        &mut g,
        "XIP_CTRL_BASE",
        p.xip_ctrl_base
            .as_deref()
            .unwrap_or_else(|| panic!("[peripherals] xip_ctrl_base is required")),
    );

    emit_hex_const(&mut g, "MONOTONIC_BASE", &t.monotonic_base);
    emit_hex_const(&mut g, "TIMER_INTR_OFFSET", &t.timer_intr_offset);
    emit_hex_const(&mut g, "TIMER_INTE_OFFSET", &t.timer_inte_offset);
    // RP2040 has no TICKS block; its timer runs off the watchdog's own tick.
    // Absent rather than zero, so a caller cannot accidentally poke address 0.
    if let Some(ticks) = &t.ticks_base {
        emit_hex_const(&mut g, "TICKS_BASE", ticks);
    }
    for a in &t.alarms {
        let up = a.owner.to_uppercase();
        emit_const(
            &mut g,
            &format!("TIMER_ALARM_{up}"),
            "u8",
            &format!("{}", a.index),
        );
        emit_const(
            &mut g,
            &format!("TIMER_IRQ_{up}"),
            "u16",
            &format!("{}", a.irq),
        );
    }
    if let (Some(secondary), Some(base)) = (&t.secondary, &t.secondary_base) {
        emit_const(&mut g, "SECONDARY_TIMER", "&str", &format!("{secondary:?}"));
        emit_hex_const(&mut g, "SECONDARY_TIMER_BASE", base);
        for a in secondary_alarms {
            let up = a.owner.to_uppercase();
            emit_const(
                &mut g,
                &format!("SECONDARY_TIMER_ALARM_{up}"),
                "u8",
                &format!("{}", a.index),
            );
            emit_const(
                &mut g,
                &format!("SECONDARY_TIMER_IRQ_{up}"),
                "u16",
                &format!("{}", a.irq),
            );
        }
        for owner in ["step_guard", "scheduler", "module_timer"] {
            assert!(
                secondary_alarms.iter().any(|a| a.owner == owner),
                "[kernel.timers] secondary_alarms names no '{owner}' alarm"
            );
        }
    }
    g.push('\n');

    emit_hex_const(&mut g, "FLASH_ERASE_BLOCK_SIZE", &k.flash_erase_block_size);
    let cmd = parse_hex(&k.flash_erase_cmd) as u8;
    emit_const(&mut g, "FLASH_ERASE_CMD", "u8", &format!("{cmd:#04X}"));
    g.push('\n');

    let b = &k.bootsel;
    emit_const(
        &mut g,
        "BOOTSEL_QSPI_SS_BIT",
        "u32",
        &format!("{}", b.qspi_ss_bit),
    );
    emit_hex_const(&mut g, "BOOTSEL_FLASH_RELEASE_ADDR", &b.flash_release_addr);
    emit_hex_const(
        &mut g,
        "BOOTSEL_FLASH_RELEASE_VALUE",
        &b.flash_release_value,
    );
    emit_hex_const(&mut g, "BOOTSEL_PAD_ADDR", &b.pad_addr);
    emit_hex_const(&mut g, "BOOTSEL_PAD_VALUE", &b.pad_value);
    emit_hex_const(&mut g, "BOOTSEL_CTRL_ADDR", &b.ctrl_addr);
    emit_hex_const(&mut g, "BOOTSEL_CTRL_VALUE", &b.ctrl_value);
    emit_hex_const(&mut g, "BOOTSEL_STATUS_ADDR", &b.status_addr);
    emit_hex_const(&mut g, "BOOTSEL_GPIO_HI_ADDR", &b.gpio_hi_addr);
    g.push('\n');

    if let Some(u) = &k.flash_unique_id {
        emit_hex_const(&mut g, "FLASH_UID_SSI_DR0_ADDR", &u.ssi_dr0_addr);
        emit_hex_const(&mut g, "FLASH_UID_SSI_SR_ADDR", &u.ssi_sr_addr);
        emit_const(
            &mut g,
            "FLASH_UID_SSI_SR_RFNE_BIT",
            "u32",
            &format!("{}", u.ssi_sr_rfne_bit),
        );
        emit_hex_const(&mut g, "FLASH_UID_SS_CTRL_ADDR", &u.ss_ctrl_addr);
        emit_hex_const(&mut g, "FLASH_UID_SS_OUTOVER_MASK", &u.ss_outover_mask);
        emit_hex_const(&mut g, "FLASH_UID_SS_OUTOVER_LOW", &u.ss_outover_low);
        emit_hex_const(&mut g, "FLASH_UID_SS_OUTOVER_HIGH", &u.ss_outover_high);
        let cmd = parse_hex(&u.cmd) as u8;
        emit_const(&mut g, "FLASH_UID_CMD", "u8", &format!("{cmd:#04X}"));
        emit_const(
            &mut g,
            "FLASH_UID_DUMMY_BYTES",
            "usize",
            &format!("{}", u.dummy_bytes),
        );
        g.push('\n');
    }

    emit_const(
        &mut g,
        "IS_RP2040",
        "bool",
        if is_rp2040 { "true" } else { "false" },
    );

    g
}

// ============================================================================
// Main
// ============================================================================

/// Exactly one supported target family per build invocation. Resolved from
/// cargo feature flags. Anything that doesn't match maps to a clear error so
/// silent fall-through (e.g. wasm builds picking up RP linker artifacts) can't
/// occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    HostLinux,
    HostWasm,
    HostUefi,
    Bcm2712,
    Rp2040,
    Rp2350,
}

fn detect_platform() -> Platform {
    let rp2040 = env::var("CARGO_FEATURE_CHIP_RP2040").is_ok();
    let rp2350b = env::var("CARGO_FEATURE_CHIP_RP2350B").is_ok();
    let bcm = env::var("CARGO_FEATURE_CHIP_BCM2712").is_ok();
    let host_linux = env::var("CARGO_FEATURE_HOST_LINUX").is_ok();
    let host_wasm = env::var("CARGO_FEATURE_HOST_WASM").is_ok();
    let host_uefi = env::var("CARGO_FEATURE_HOST_UEFI").is_ok();

    let active: Vec<&str> = [
        ("chip-rp2040", rp2040),
        ("chip-rp2350b", rp2350b),
        ("chip-bcm2712", bcm),
        ("host-linux", host_linux),
        ("host-wasm", host_wasm),
        ("host-uefi", host_uefi),
    ]
    .iter()
    .filter_map(|(n, on)| if *on { Some(*n) } else { None })
    .collect();

    match active.as_slice() {
        ["chip-rp2040"] => Platform::Rp2040,
        ["chip-rp2350b"] => Platform::Rp2350,
        ["chip-bcm2712"] => Platform::Bcm2712,
        ["host-linux"] => Platform::HostLinux,
        ["host-wasm"] => Platform::HostWasm,
        ["host-uefi"] => Platform::HostUefi,
        // Zero active features means the workspace default kicked in.
        // The default in Cargo.toml is `chip-rp2350b`, but emitting a
        // deterministic error here is friendlier than a Cortex-M linker
        // arg surprising a host build.
        [] => panic!(
            "build.rs: no platform feature selected. Pass exactly one of \
             chip-rp2040 / chip-rp2350b / chip-bcm2712 / host-linux / host-wasm / host-uefi \
             with --no-default-features --features <name>. See `make targets`."
        ),
        _ => panic!(
            "build.rs: multiple conflicting platform features active: {active:?}. \
             Pass exactly one.",
        ),
    }
}

fn main() {
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let platform = detect_platform();
    // Always emit the rerun guard so changing build.rs itself re-triggers.
    println!("cargo:rerun-if-changed=build.rs");
    // Re-run if any platform feature toggles, so a feature change forces
    // re-detection rather than picking up a stale artifact.
    // The RP link script (`linker/link-rp.x`). Its MEMORY block comes from
    // the per-silicon `linker/memory-rp*.x` that `emit_rp` stages as
    // `memory.x` in the same directory; aarch64 has its own script below and
    // does not use this one.
    if env::var_os("CARGO_FEATURE_RP").is_some() {
        File::create(out.join("link-rp.x"))
            .unwrap()
            .write_all(include_bytes!("linker/link-rp.x"))
            .unwrap();
        println!("cargo:rustc-link-arg=-T{}/link-rp.x", out.display());
        println!("cargo:rerun-if-changed=linker/link-rp.x");
    }

    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CHIP_RP2040");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CHIP_RP2350B");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CHIP_BCM2712");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_HOST_LINUX");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_HOST_WASM");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_HOST_UEFI");
    // Downstream Rust code can match on this cfg to assert platform identity
    // (e.g. a `#[cfg(fluxor_platform = "wasm")]` block that statically rejects
    // a stray RP-only `include!` ever reaching the wasm crate graph).
    let platform_str = match platform {
        Platform::HostLinux => "host-linux",
        Platform::HostWasm => "host-wasm",
        Platform::HostUefi => "host-uefi",
        Platform::Bcm2712 => "bcm2712",
        Platform::Rp2040 => "rp2040",
        Platform::Rp2350 => "rp2350",
    };
    println!("cargo:rustc-check-cfg=cfg(fluxor_platform, values(\"host-linux\", \"host-wasm\", \"host-uefi\", \"bcm2712\", \"rp2040\", \"rp2350\"))");
    println!("cargo:rustc-cfg=fluxor_platform=\"{platform_str}\"");

    // The module ABI, under the name the module build uses.
    //
    // `crates/fluxor-abi/src/config.rs` is mounted by BOTH the kernel and every PIC
    // module, and its `profile_embedded` block picks connection ceilings and
    // `TARGET_CLASS` by `fluxor_abi`: the RP parts differ by 3.75x and
    // `target_arch` cannot tell thumbv6m from thumbv8m. The kernel's own
    // `kernel::config::profile_rp` reads it too, for the per-die code-size
    // ceiling, so the kernel build must set the same value the module build
    // does; leaving the name undeclared would also make every use of it an
    // unexpected-cfg error under `-D warnings`.
    //
    // A separate name from `fluxor_platform` because the value sets differ:
    // `fluxor_platform` names the kernel's platform, this the module ABI
    // (`tools/src/runtime_abi.rs`). The hosted platforms set no value — their
    // profiles are selected by `target_arch` and never read this — but the
    // accepted-value list is declared for every build so the name is known.
    println!(
        "cargo:rustc-check-cfg=cfg(fluxor_abi, values(\"thumbv6m\", \"thumbv8m\", \"aarch64\", \"x86_64\", \"wasm32\", \"xtensa-lx6\"))"
    );
    let module_abi = match platform {
        Platform::Bcm2712 | Platform::HostUefi => Some("aarch64"),
        Platform::Rp2040 => Some("thumbv6m"),
        Platform::Rp2350 => Some("thumbv8m"),
        _ => None,
    };
    if let Some(abi) = module_abi {
        println!("cargo:rustc-cfg=fluxor_abi=\"{abi}\"");
    }

    // M-profile variant. Rust has no built-in cfg distinguishing ARMv6-M
    // (Cortex-M0+, RP2040) from ARMv8-M (Cortex-M33, RP2350), and the
    // difference is load-bearing in `arch::cortex_m` — ARMv6-M has exactly
    // one NVIC ISER/ICER pair where ARMv8-M has up to sixteen. Emitting it
    // here keeps that fact with the build that knows the target, instead of
    // inferring it from a chip feature at each use.
    println!("cargo:rustc-check-cfg=cfg(armv6m)");
    // Whether this build has a board that declares a console header. Set in
    // `emit_rp` where the board TOML is read; declared here so every platform
    // — including the hosted ones, which never set it — knows the name.
    println!("cargo:rustc-check-cfg=cfg(console_uart)");
    if matches!(platform, Platform::Rp2040) {
        println!("cargo:rustc-cfg=armv6m");
    }

    match platform {
        // Hosted targets: kernel capacity comes from `kernel::config` (per
        // platform, selected by the platform feature). No linker script, no
        // chip_generated.rs.
        Platform::HostLinux => {
            emit_smp(out, "targets/host/linux.toml");
        }
        Platform::HostWasm => {
            emit_smp(out, "targets/host/wasm.toml");
        }
        Platform::HostUefi => {
            emit_smp(out, "targets/host/uefi.toml");
            emit_uefi(out)
        }
        Platform::Bcm2712 => {
            emit_smp(out, "targets/silicon/bcm2712.toml");
            emit_bcm2712(out)
        }
        Platform::Rp2040 => emit_rp(out, Rp::Rp2040),
        Platform::Rp2350 => emit_rp(out, Rp::Rp2350),
    }
}

/// `[smp]` of `toml_path` as `smp_generated.rs`: the cores that run a domain
/// loop and the core of each domain, checked against the map's rules. Every
/// platform's `chip` includes it. Returns the section for a caller that
/// reads more of it.
fn emit_smp(out: &Path, toml_path: &str) -> SmpToml {
    let text = fs::read_to_string(toml_path).unwrap_or_else(|e| panic!("{toml_path}: {e}"));
    let smp = toml::from_str::<SmpOnly>(&text)
        .unwrap_or_else(|e| panic!("{toml_path}: {e}"))
        .smp
        .unwrap_or_else(|| panic!("{toml_path} has no [smp] section"));
    if let Err(e) = core_map::validate(&smp.domain_cores, smp.cores) {
        use core_map::MapError as E;
        let why = match e {
            E::Length => format!(
                "names {} domains; a map covers exactly {}",
                smp.domain_cores.len(),
                core_map::DOMAINS
            ),
            E::NoCores => "runs no core".to_owned(),
            E::PrimaryNotOnBootCore => "puts domain 0 off core 0, the core that boots".to_owned(),
            E::CoreOutOfRange { domain } => format!(
                "puts domain {domain} on core {}, but the target runs {} core(s)",
                smp.domain_cores[domain], smp.cores
            ),
            E::SecondaryShared { core } => format!(
                "gives core {core} more than one domain; a core other than 0 runs one domain's loop"
            ),
        };
        panic!(
            "{toml_path}: [smp] domain_cores {:?} {why}",
            smp.domain_cores
        );
    }
    let g = format!(
        "// Auto-generated by build.rs from {toml_path} [smp] — do not edit.\n\
         /// Cores that run a domain loop.\n\
         pub const SMP_CORES: usize = {};\n\
         /// The core that runs each execution domain.\n\
         pub const DOMAIN_CORES: [u8; {}] = {:?};\n",
        smp.cores,
        core_map::DOMAINS,
        smp.domain_cores
    );
    fs::write(out.join("smp_generated.rs"), g).unwrap();
    println!("cargo:rerun-if-changed={toml_path}");
    println!("cargo:rerun-if-changed=contracts/src/core_map.rs");
    smp
}

fn emit_uefi(out: &Path) {
    // The image's link address and span are the target's (`[memory]` in
    // `targets/host/uefi.toml`): the loader reads them back out of the
    // image's header and reserves exactly that span from the firmware.
    #[derive(Deserialize)]
    struct MemoryOnly {
        memory: UefiMemory,
    }
    #[derive(Deserialize)]
    struct UefiMemory {
        ram_base: String,
        ram_size: String,
    }
    let path = "targets/host/uefi.toml";
    let host: MemoryOnly =
        toml::from_str(&fs::read_to_string(path).expect("targets/host/uefi.toml"))
            .expect("targets/host/uefi.toml parses");
    File::create(out.join("memory-uefi.x"))
        .unwrap()
        .write_all(include_bytes!("linker/memory-uefi.x"))
        .unwrap();
    println!("cargo:rustc-link-arg=-T{}/memory-uefi.x", out.display());
    println!(
        "cargo:rustc-link-arg=--defsym=RAM_ORIGIN={}",
        host.memory.ram_base
    );
    println!(
        "cargo:rustc-link-arg=--defsym=RAM_LENGTH={}",
        host.memory.ram_size
    );
    println!("cargo:rerun-if-changed=linker/memory-uefi.x");
    println!("cargo:rerun-if-changed={path}");

    // `arch::aarch64::isolation` compiles against the blocks a device window
    // may be granted in. This runtime isolates no module and ACPI names the
    // machine only at boot, so the target declares none.
    let mut generated = String::new();
    emit_device_ranges(&mut generated, None);
    fs::write(out.join("isolation_generated.rs"), generated).unwrap();
}

fn emit_bcm2712(out: &Path) {
    // BCM2712: single linker script with board-dependent RAM origin —
    // real Pi 5 (board-pi5) vs QEMU virt — via --defsym. Kernel capacity
    // comes from `kernel::config::profile_bcm2712`;
    // `targets/silicon/bcm2712.toml` restates the state arena for the graph
    // builder and otherwise carries non-capacity metadata.
    let is_pi5 = env::var("CARGO_FEATURE_BOARD_PI5").is_ok();
    let ram_origin = if is_pi5 { "0x80000" } else { "0x40080000" };
    File::create(out.join("memory-bcm2712.x"))
        .unwrap()
        .write_all(include_bytes!("linker/memory-bcm2712.x"))
        .unwrap();
    println!("cargo:rustc-link-arg=-T{}/memory-bcm2712.x", out.display());
    println!("cargo:rustc-link-arg=--defsym=RAM_ORIGIN={ram_origin}");
    // Where the kernel's own RAM (image, .bss, stack) must end — asserted by
    // the linker script. On the Pi 5 the firmware places the DTB and
    // initramfs near 0x2E00_0000, and a boot that writes over them never
    // comes up; on QEMU virt the DRAM zone the tables and the state arena
    // share starts at 2 GB (`platform/bcm2712/memmap.rs`).
    let ram_ceiling = if is_pi5 { "0x2E000000" } else { "0x80000000" };
    println!("cargo:rustc-link-arg=--defsym=RAM_CEILING={ram_ceiling}");
    println!("cargo:rerun-if-changed=linker/memory-bcm2712.x");
    println!("cargo:rerun-if-changed=targets/silicon/bcm2712.toml");

    // PCIe device topology is a board fact: generate the alias table from the
    // active board TOML (Pi 5 has the NVMe/RP1 topology; QEMU virt declares
    // none). `src/platform/bcm2712/pcie_aliases.rs` includes the result.
    // The board is the one the firmware build names (`FLUXOR_BOARD`), when
    // it is a bcm2712 board; a build that names none is the Pi 5 or QEMU
    // virt by its cargo feature.
    let named = env::var("FLUXOR_BOARD")
        .ok()
        .map(|b| format!("targets/boards/{b}.toml"))
        .filter(|path| {
            fs::read_to_string(path)
                .ok()
                .and_then(|t| toml::from_str::<toml::Value>(&t).ok())
                .and_then(|v| v.get("board")?.get("silicon")?.as_str().map(str::to_owned))
                .is_some_and(|s| s == "bcm2712")
        });
    let board_toml = named.unwrap_or_else(|| {
        if is_pi5 {
            "targets/boards/pi5.toml".to_owned()
        } else {
            "targets/boards/qemu-virt.toml".to_owned()
        }
    });
    let board_toml = board_toml.as_str();
    emit_board_pcie_aliases(out, board_toml);
    emit_board_tick(out, board_toml);
    println!("cargo:rerun-if-changed={board_toml}");
    println!("cargo:rerun-if-env-changed=FLUXOR_BOARD");

    // The isolation facts the MMU backend compiles against: the blocks a
    // device window may be granted in. `src/arch/aarch64/isolation.rs`
    // includes the result.
    #[derive(Deserialize)]
    struct IsolationOnly {
        isolation: Option<IsolationToml>,
    }
    let silicon: IsolationOnly = toml::from_str(
        &fs::read_to_string("targets/silicon/bcm2712.toml").expect("targets/silicon/bcm2712.toml"),
    )
    .expect("targets/silicon/bcm2712.toml parses");
    let mut generated = String::new();
    emit_device_ranges(&mut generated, silicon.isolation.as_ref());
    fs::write(out.join("isolation_generated.rs"), generated).unwrap();
}

/// `[kernel.tick]` of the board TOML as consts the bcm2712 boot applies.
fn emit_board_tick(out: &Path, board_toml: &str) {
    let text = fs::read_to_string(board_toml).unwrap_or_else(|e| panic!("{board_toml}: {e}"));
    let board: BoardToml = toml::from_str(&text).unwrap_or_else(|e| panic!("{board_toml}: {e}"));
    let tick = board.kernel.and_then(|k| k.tick).unwrap_or_default();
    let g = format!(
        "// Auto-generated by build.rs from the active board TOML [kernel.tick] — do not edit.\n\
         pub const WAKE_DOORBELL: bool = {};\n\
         pub const ABSOLUTE_REARM: bool = {};\n",
        tick.wake_doorbell, tick.absolute_rearm
    );
    fs::write(out.join("board_tick.rs"), g).unwrap();
}

fn emit_board_pcie_aliases(out: &Path, board_toml: &str) {
    let aliases = fs::read_to_string(board_toml)
        .ok()
        .and_then(|c| toml::from_str::<BoardToml>(&c).ok())
        .and_then(|b| b.platform)
        .and_then(|p| p.pcie)
        .map(|p| p.aliases)
        .unwrap_or_default();

    let mut g = String::from(
        "// Auto-generated by build.rs from the active board TOML [platform.pcie] — do not edit.\n\
         pub const ALIASES: &[PcieAlias] = &[\n",
    );
    for a in &aliases {
        let root = match a.root.as_str() {
            "pcie1" => "PcieRoot::Pcie1",
            "pcie2" => "PcieRoot::Pcie2",
            other => {
                panic!("{board_toml}: unknown pcie alias root {other:?} (expected pcie1|pcie2)")
            }
        };
        g.push_str(&format!(
            "    PcieAlias {{ name: {:?}, root: {root}, bus: {}, dev: {}, func: {} }},\n",
            a.name, a.bus, a.dev, a.func
        ));
    }
    g.push_str("];\n");
    File::create(out.join("board_pcie_aliases.rs"))
        .unwrap()
        .write_all(g.as_bytes())
        .unwrap();
}

enum Rp {
    Rp2040,
    Rp2350,
}

fn emit_rp(out: &Path, family: Rp) {
    let is_rp2040 = matches!(family, Rp::Rp2040);
    let linker_script = if is_rp2040 {
        include_bytes!("linker/memory-rp2040.x") as &[u8]
    } else {
        include_bytes!("linker/memory-rp2350.x") as &[u8]
    };
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(linker_script)
        .unwrap();

    let toml_path = if is_rp2040 {
        "targets/silicon/rp2040.toml"
    } else {
        "targets/silicon/rp2350.toml"
    };
    let content =
        fs::read_to_string(toml_path).unwrap_or_else(|e| panic!("Failed to read {toml_path}: {e}"));
    let silicon: SiliconToml =
        toml::from_str(&content).unwrap_or_else(|e| panic!("Failed to parse {toml_path}: {e}"));
    let kernel = silicon
        .kernel
        .unwrap_or_else(|| panic!("{toml_path} missing [kernel] section"));

    let peripherals = silicon.peripherals.unwrap_or_default();
    assert!(
        peripherals.dma_channels.is_some(),
        "{toml_path} missing [peripherals] dma_channels"
    );
    // The stack is what the linker's RAM region leaves above the statics, so
    // the TOML's RAM size must be that region, not the die's total SRAM.
    let ram_bytes = linker_ram_bytes(linker_script)
        .unwrap_or_else(|| panic!("no RAM region in the {toml_path} linker memory map"));
    let toml_ram = silicon
        .memory
        .as_ref()
        .map(|m| parse_hex(&m.ram_size))
        .unwrap_or_else(|| panic!("{toml_path} missing [memory] ram_size"));
    assert!(
        toml_ram == ram_bytes,
        "{toml_path}: [memory] ram_size {toml_ram:#x} is not the linker's RAM region \
         ({ram_bytes:#x}), which is where the kernel's statics and stack live"
    );
    let mut generated = generate_chip_rs(&kernel, is_rp2040, &peripherals, ram_bytes);
    // The domain-to-core map, and the second core's stack and timer where
    // the map runs a domain there.
    let smp = emit_smp(out, toml_path);
    let runs_secondary = smp.domain_cores.iter().any(|&c| c != 0);
    assert!(
        runs_secondary == smp.secondary_stack.is_some(),
        "{toml_path}: [smp] secondary_stack is declared exactly when domain_cores runs a \
         domain off core 0"
    );
    assert!(
        runs_secondary == kernel.timers.secondary.is_some(),
        "{toml_path}: [kernel.timers] secondary is declared exactly when [smp] domain_cores \
         runs a domain off core 0"
    );
    // Core 1's stack is a static the kernel links (`rp_core1`), sized here.
    if let Some(stack) = &smp.secondary_stack {
        let size = stack.size_kb * 1024;
        let reserve = stack.reserve_kb * 1024;
        assert!(
            reserve < size,
            "{toml_path}: [smp] secondary_stack reserve_kb leaves no stack for a module"
        );
        emit_const(
            &mut generated,
            "SECONDARY_STACK_SIZE",
            "usize",
            &format!("{size}"),
        );
        emit_const(
            &mut generated,
            "SECONDARY_STACK_RESERVE",
            "usize",
            &format!("{reserve}"),
        );
    }
    // Isolation facts. A silicon with no [isolation] section compiles no
    // backend in, so these default to "no protection unit".
    let (model, regions) = match &silicon.isolation {
        Some(i) => (
            i.region_model.clone().unwrap_or_else(|| "none".into()),
            i.regions.unwrap_or(0),
        ),
        None => ("none".into(), 0),
    };
    assert!(
        matches!(model.as_str(), "none" | "pmsav7" | "pmsav8"),
        "{toml_path}: [isolation] region_model '{model}' is not an MPU model"
    );
    emit_const(
        &mut generated,
        "ISOLATION_PMSAV8",
        "bool",
        if model == "pmsav8" { "true" } else { "false" },
    );
    emit_const(
        &mut generated,
        "ISOLATION_PMSAV7",
        "bool",
        if model == "pmsav7" { "true" } else { "false" },
    );
    emit_const(
        &mut generated,
        "ISOLATION_REGIONS",
        "u8",
        &format!("{regions}"),
    );
    emit_device_ranges(&mut generated, silicon.isolation.as_ref());
    // The peripheral gate, and each grantable block's register in it (0 for
    // a block with none), parallel to `DEVICE_RANGES`.
    let iso = silicon.isolation.as_ref();
    let gates: Vec<String> = iso
        .and_then(|i| i.device_ranges.as_ref())
        .into_iter()
        .flatten()
        .map(|r| format!("0x{:x}", r.gate.as_deref().map(parse_hex).unwrap_or(0)))
        .collect();
    emit_const(
        &mut generated,
        "DEVICE_RANGE_GATES",
        "&[u32]",
        &format!("&[{}]", gates.join(", ")),
    );
    let gate = match iso.and_then(|i| i.peripheral_gate.as_ref()) {
        Some(g) => format!(
            "Some((0x{:08x}, 0x{:x}, 0x{:x}))",
            parse_hex(&g.base),
            parse_hex(&g.first),
            parse_hex(&g.last)
        ),
        None => "None".into(),
    };
    emit_const(
        &mut generated,
        "PERIPHERAL_GATE",
        "Option<(u32, u32, u32)>",
        &gate,
    );
    // The whole XIP flash, which a contained module may read and execute,
    // and which the graph slots and the parameter store are partitioned from.
    // Its size is the board's when the build names one: the silicon's figure
    // is only the default a board without a `[hardware.flash]` keeps.
    if let Some(m) = &silicon.memory {
        if let (Some(b), Some(z)) = (&m.flash_base, &m.flash_size) {
            let board_flash = std::env::var("FLUXOR_BOARD").ok().and_then(|board| {
                let path = format!("targets/boards/{board}.toml");
                println!("cargo:rerun-if-changed={path}");
                let text = fs::read_to_string(&path).ok()?;
                toml::from_str::<BoardToml>(&text).ok()?.hardware?.flash
            });
            emit_hex_const(&mut generated, "FLASH_BASE", b);
            match &board_flash {
                Some(f) => emit_hex_const(&mut generated, "FLASH_SIZE", &f.size),
                None => emit_hex_const(&mut generated, "FLASH_SIZE", z),
            }
            if let Some(r) = &m.kernel_flash_reserve {
                emit_hex_const(&mut generated, "KERNEL_FLASH_RESERVE", r);
            }
            // The flash part's geometry: the board's when it names one, else
            // the silicon's. Not guessed: the partition and the data store
            // are cut to it.
            let erase = board_flash
                .as_ref()
                .and_then(|f| f.erase_size.clone())
                .or_else(|| m.flash_erase_size.clone())
                .expect("[memory] flash_erase_size: the flash part's erase unit");
            let program = board_flash
                .as_ref()
                .and_then(|f| f.program_size.clone())
                .or_else(|| m.flash_program_size.clone())
                .expect("[memory] flash_program_size: the flash part's program page");
            emit_hex_const(&mut generated, "FLASH_ERASE_SIZE", &erase);
            emit_hex_const(&mut generated, "FLASH_PROGRAM_SIZE", &program);
        }
    }
    File::create(out.join("chip_generated.rs"))
        .unwrap()
        .write_all(generated.as_bytes())
        .unwrap();

    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=linker/memory-rp2350.x");
    println!("cargo:rerun-if-changed=linker/memory-rp2040.x");
    println!("cargo:rerun-if-changed=targets/silicon/rp2040.toml");
    println!("cargo:rerun-if-changed=targets/silicon/rp2350.toml");
}

//! Build script for fluxor
//!
//! Provides the target-specific memory.x linker script and generates
//! chip_generated.rs from the silicon TOML [kernel] section.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;

// ============================================================================
// TOML schema (only the [kernel] section)
// ============================================================================

#[derive(Deserialize)]
struct SiliconToml {
    kernel: Option<KernelConfig>,
    peripherals: Option<PeripheralConfig>,
}

// Board TOML — only the [platform.pcie] topology this script generates.
#[derive(Deserialize)]
struct BoardToml {
    platform: Option<BoardPlatform>,
    hardware: Option<BoardHardware>,
}

#[derive(Deserialize)]
struct BoardHardware {
    xosc: Option<BoardXosc>,
    console_uart: Option<BoardConsoleUart>,
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
    state_arena_kb: u32,
    buffer_arena_kb: u32,
    config_buffer_kb: u32,
    config_arena_kb: u32,
    log_ring_kb: u32,
    sys_hz: u32,
    overclock_sys_hz: Option<u32>,
    usb_hz: u32,
    timers: TimerLedger,
    flash_erase_block_size: String,
    flash_erase_cmd: String,
    bootsel: BootselConfig,
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

fn emit_const(gen: &mut String, name: &str, ty: &str, val: &str) {
    gen.push_str(&format!("pub const {name}: {ty} = {val};\n"));
}

fn emit_hex_const(gen: &mut String, name: &str, hex_str: &str) {
    let v = parse_hex(hex_str);
    gen.push_str(&format!("pub const {name}: u32 = {v:#010X};\n"));
}

fn generate_chip_rs(k: &KernelConfig, is_rp2040: bool, p: &PeripheralConfig) -> String {
    let dma_channels = p.dma_channels.expect("dma_channels");
    let mut g = String::from("// Auto-generated by build.rs from silicon TOML — do not edit\n\n");

    emit_hex_const(&mut g, "WATCHDOG_CTRL", &k.watchdog_ctrl);
    emit_hex_const(&mut g, "PSM_WDSEL", &k.psm_wdsel);
    emit_hex_const(&mut g, "PSM_WDSEL_MASK", &k.psm_wdsel_mask);
    emit_hex_const(&mut g, "BOOT2_SRC", &k.boot2_src);
    g.push('\n');

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
        "CONFIG_ARENA_SIZE",
        "usize",
        &format!("{}", k.config_arena_kb * 1024),
    );
    emit_const(
        &mut g,
        "LOG_RING_CAPACITY",
        "usize",
        &format!("{}", k.log_ring_kb * 1024),
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
    // RP2040 has no TICKS block; its timer runs off the watchdog tick, which
    // the clock init already enables. Absent rather than zero, so a caller
    // cannot accidentally poke address 0.
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

    let active: Vec<&str> = [
        ("chip-rp2040", rp2040),
        ("chip-rp2350b", rp2350b),
        ("chip-bcm2712", bcm),
        ("host-linux", host_linux),
        ("host-wasm", host_wasm),
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
        // Zero active features means the workspace default kicked in.
        // The default in Cargo.toml is `chip-rp2350b`, but emitting a
        // deterministic error here is friendlier than a Cortex-M linker
        // arg surprising a host build.
        [] => panic!(
            "build.rs: no platform feature selected. Pass exactly one of \
             chip-rp2040 / chip-rp2350b / chip-bcm2712 / host-linux / host-wasm \
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
    // The RP link script. The MEMORY block comes from the per-silicon
    // `memory-rp*.x` this script emits as `memory.x`; aarch64 has its own
    // script below and does not use this one.
    if env::var_os("CARGO_FEATURE_RP").is_some() {
        println!("cargo:rustc-link-arg=-Tlink-rp.x");
        println!("cargo:rerun-if-changed=link-rp.x");
    }

    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CHIP_RP2040");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CHIP_RP2350B");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CHIP_BCM2712");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_HOST_LINUX");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_HOST_WASM");
    // Downstream Rust code can match on this cfg to assert platform identity
    // (e.g. a `#[cfg(fluxor_platform = "wasm")]` block that statically rejects
    // a stray RP-only `include!` ever reaching the wasm crate graph).
    let platform_str = match platform {
        Platform::HostLinux => "host-linux",
        Platform::HostWasm => "host-wasm",
        Platform::Bcm2712 => "bcm2712",
        Platform::Rp2040 => "rp2040",
        Platform::Rp2350 => "rp2350",
    };
    println!("cargo:rustc-check-cfg=cfg(fluxor_platform, values(\"host-linux\", \"host-wasm\", \"bcm2712\", \"rp2040\", \"rp2350\"))");
    println!("cargo:rustc-cfg=fluxor_platform=\"{platform_str}\"");

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
        Platform::HostLinux => {
            // Hosted targets: capacity tunables come from
            // `abi::config::kernel` (per-profile, selected at compile
            // time via `cfg(target_arch)` in `modules/sdk/config.rs`).
            // No linker script, no chip_generated.rs.
            emit_builtin_param_tags(out, "modules/platform/linux");
        }
        Platform::HostWasm => emit_builtin_param_tags(out, "modules/platform/wasm"),
        Platform::Bcm2712 => emit_bcm2712(out),
        Platform::Rp2040 => emit_rp(out, Rp::Rp2040),
        Platform::Rp2350 => emit_rp(out, Rp::Rp2350),
    }
}

// ============================================================================
// Built-in parameter tags
// ============================================================================

/// A built-in `manifest.toml`, reduced to the `[[params]]` tag table.
#[derive(Deserialize)]
struct BuiltinManifestToml {
    #[serde(default)]
    builtin: bool,
    #[serde(default)]
    params: Vec<BuiltinParamToml>,
}

#[derive(Deserialize)]
struct BuiltinParamToml {
    name: String,
    tag: u8,
}

/// Generate the platform-side TLV tag constants from the built-in manifests
/// under `dir`, one `pub mod <module_name>` per manifest.
///
/// The manifest is the single source of truth for a built-in's wire layout.
/// Generating the constants the platform matches on means a hand-typed number
/// cannot disagree with the declared tag: there is only one number.
fn emit_builtin_param_tags(out: &Path, dir: &str) {
    println!("cargo:rerun-if-changed={dir}");

    let mut modules: Vec<(String, Vec<BuiltinParamToml>)> = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        // The manifest tree is absent in a consumer checkout that vendors only
        // the crate; emit an empty table rather than failing the build.
        Err(_) => {
            fs::write(out.join("builtin_param_tags.rs"), "").unwrap();
            return;
        }
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    paths.sort();

    for p in paths {
        let manifest_path = p.join("manifest.toml");
        if !manifest_path.exists() {
            continue;
        }
        println!("cargo:rerun-if-changed={}", manifest_path.display());
        let content = fs::read_to_string(&manifest_path).unwrap();
        let parsed: BuiltinManifestToml = toml::from_str(&content).unwrap_or_else(|e| {
            panic!(
                "{}: cannot read [[params]] tags: {e}",
                manifest_path.display()
            )
        });
        if !parsed.builtin || parsed.params.is_empty() {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        modules.push((name, parsed.params));
    }

    let mut g = String::from(
        "// Auto-generated by build.rs from the built-in manifest [[params]] tables — do not edit.\n",
    );
    for (module, params) in &modules {
        g.push_str(&format!("pub mod {module} {{\n"));
        for param in params {
            g.push_str(&format!(
                "    pub const TAG_{}: u8 = {};\n",
                param.name.to_uppercase(),
                param.tag,
            ));
        }
        g.push_str("}\n");
    }
    fs::write(out.join("builtin_param_tags.rs"), g).unwrap();
}

fn emit_bcm2712(out: &Path) {
    // BCM2712: single linker script with board-dependent RAM origin —
    // real Pi 5 (board-pi5) vs QEMU virt — via --defsym. Capacity constants
    // come from the centralised `abi::config::kernel::profile_host`;
    // `targets/silicon/bcm2712.toml` carries non-capacity metadata only.
    let is_pi5 = env::var("CARGO_FEATURE_BOARD_PI5").is_ok();
    let ram_origin = if is_pi5 { "0x80000" } else { "0x40080000" };
    File::create(out.join("memory-bcm2712.x"))
        .unwrap()
        .write_all(include_bytes!("memory-bcm2712.x"))
        .unwrap();
    println!("cargo:rustc-link-arg=-T{}/memory-bcm2712.x", out.display());
    println!("cargo:rustc-link-arg=--defsym=RAM_ORIGIN={ram_origin}");
    println!("cargo:rerun-if-changed=memory-bcm2712.x");
    println!("cargo:rerun-if-changed=targets/silicon/bcm2712.toml");

    // PCIe device topology is a board fact: generate the alias table from the
    // active board TOML (Pi 5 has the NVMe/RP1 topology; QEMU virt declares
    // none). `src/platform/bcm2712/pcie_aliases.rs` includes the result.
    let board_toml = if is_pi5 {
        "targets/boards/pi5.toml"
    } else {
        "targets/boards/qemu-virt.toml"
    };
    emit_board_pcie_aliases(out, board_toml);
    println!("cargo:rerun-if-changed={board_toml}");
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
        include_bytes!("memory-rp2040.x") as &[u8]
    } else {
        include_bytes!("memory-rp2350.x") as &[u8]
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
    let generated = generate_chip_rs(&kernel, is_rp2040, &peripherals);
    File::create(out.join("chip_generated.rs"))
        .unwrap()
        .write_all(generated.as_bytes())
        .unwrap();

    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory-rp2350.x");
    println!("cargo:rerun-if-changed=memory-rp2040.x");
    println!("cargo:rerun-if-changed=targets/silicon/rp2040.toml");
    println!("cargo:rerun-if-changed=targets/silicon/rp2350.toml");
}

//! CYW43 WiFi Driver PIC Module
//!
//! Hardware driver for the CYW43439 WiFi chip (Pico W).
//! Implements gSPI communication as a sync state machine driven by `module_step()`.
//!
//! # State Machine
//!
//! ```text
//! Init → PowerOn → GspiInit → LoadFW → LoadCLM → WaitReady
//!                                                      ↓
//!                                            InitWifi → RegisterNetif → Running
//! ```
//!
//! Each phase may span many `module_step()` calls. gSPI transactions within a phase
//! use substep tracking (start transfer, poll, process result).
//!
//! # Channels
//!
//! - `out_chan`: Received ethernet frames → IP stack module
//! - `in_chan`:  Transmit ethernet frames ← IP stack module
//!
//! # Firmware
//!
//! The ~230KB firmware blob is `include_bytes!` in .rodata (flash XIP, no RAM cost).
//!
//! # Config Parameters
//!
//! | Tag | Name    | Type | Default | Description           |
//! |-----|---------|------|---------|-----------------------|
//! | 1   | pio_idx | u8   | 1       | PIO instance (0-2)    |
//! | 2   | dio_pin | u8   | 24      | gSPI data pin         |
//! | 3   | clk_pin | u8   | 29      | gSPI clock pin        |
//! | 4   | cs_pin  | u8   | 25      | Chip select pin       |
//! | 5   | pwr_pin | u8   | 23      | Power control pin     |

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

#[allow(dead_code)]
mod constants;
#[allow(dead_code)]
mod gspi;
#[allow(dead_code)]
mod wifi_ops;

use constants::*;

use abi::contracts::hal::{gpio as dev_gpio, pio as dev_pio};

// Provider contract ids (mirror kernel::provider::contract::*).
const HAL_GPIO_CONTRACT: u32 = 0x0001;
const HAL_PIO_CONTRACT:  u32 = 0x0004;

// ============================================================================
// Firmware Blobs (in .rodata, read from flash XIP)
// ============================================================================

/// CYW43439 main firmware (~230KB)
static FIRMWARE: &[u8] = include_bytes!("../../../firmware/43439A0.bin");
/// CYW43439 CLM blob (~1KB)
static CLM: &[u8] = include_bytes!("../../../firmware/43439A0_clm.bin");

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
pub struct Cyw43State {
    // Core module fields
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pub ctrl_chan: i32,

    // Hardware handles
    pub pio_handle: i32,
    pub cs_handle: i32,
    pub pwr_handle: i32,

    // State machine
    pub phase: Cyw43Phase,
    pub substep: u8,
    pub wifi_substep: u8,
    _pad0: u8,
    pub last_time_ms: u64,

    // Config parameters
    pub pio_idx: u8,
    pub dio_pin: u8,
    pub clk_pin: u8,
    pub cs_pin: u8,
    pub pwr_pin: u8,
    _pad1: [u8; 3],

    // gSPI transaction state
    pub txn_step: gspi::TxnStep,
    pub txn_rx_skip_words: u8, // response words to skip in RX (1=bus/wlan, 2=backplane)
    pub txn_len: u16,
    pub txn_rx_payload_len: u16,
    _pad2: [u8; 2],
    /// TX buffer for gSPI commands (tx_words + cmd + data + rx_words).
    /// Must hold MAX_FRAME_SIZE + 12 bytes overhead for WLAN writes.
    pub txn_buf: [u8; 1600],
    /// RX buffer for gSPI responses (must fit largest ESCAN result frame)
    pub rxn_buf: [u8; 1600],

    // Backplane window tracking
    pub bp_window: u32,
    pub bp_window_target: u32,

    // Firmware upload tracking
    pub fw_offset: u32,

    // SDPCM state
    pub sdpcm_seq: u8,
    pub sdpcm_rx_seq: u8,
    _pad3: [u8; 2],

    // WiFi credentials (from netif ioctl or config)
    pub ssid: [u8; MAX_SSID_LEN],
    pub ssid_len: u8,
    pub password: [u8; MAX_PASS_LEN],
    pub pass_len: u8,
    pub security: u8, // 0=WPA2, 1=WPA3
    pub mac_retries: u8,   // MAC read + ctrl frame retries (limit 50/30)
    pub assoc_retries: u8, // WiFi association retries (limit 3)

    /// WiFi connection state
    pub wifi_state: Cyw43WifiState,
    pub pending_wifi_op: wifi_ops::WifiOp,
    pub mac_addr: [u8; 6],
    pub delay_start: u64,

    // Ioctl synchronization: count sent vs firmware-acknowledged
    pub ioctl_send_count: u8,
    pub ioctl_recv_count: u8,
    pub ioctl_error_seen: bool, // CDC error flag seen during connect

    // Association Comeback: AP sent Timeout Interval IE (0x38 type 3)
    // Value in ms (or TUs, ~1ms each). 0 = no comeback requested.
    pub comeback_ms: u32,

    // Netif state output channel (out[5]) — emits MSG_NETIF_STATE frames
    // on state transitions. Consumers (wifi, ip) read from their wired
    // input port.
    pub netif_state_chan: i32,

    // Frame I/O buffer (shared between RX and TX operations)
    pub frame_buf: [u8; MAX_FRAME_SIZE],
    pub frame_len: u16,
    pub frame_pending_tx: bool,
    pub frame_pending_rx: bool,
    pub out_stalled: bool,

    // Status register cache
    pub last_status: u32,

    // Params buffer
    pub params: [u8; 16],
    pub params_len: u16,
    _pad5: [u8; 2],

    // Scan state
    pub scan_active: bool,
    pub scan_count: u8,
    pub scan_sync_id: u16,
    pub scan_out_chan: i32,       // out[1]: scan results (text)
    pub scan_bin_chan: i32,       // out[2]: scan results (binary, 36B records)
    pub status_chan: i32,         // out[3]: status events

    // LED control
    pub led_chan: i32,           // in[1]: LED FMP commands
    pub led_state: u8,          // cached LED level (0=off, 1=on)
    pub led_gpio_ready: bool,   // CYW43 GPIO0 configured as output
    pub wifi_active: bool,      // true when WiFi output is wired
    pub led_op: u8,             // LED state machine: 0=idle, 1-6=init, 7=send

    pub led_brightness: u8,     // target brightness 0-255 (software PWM)
    pub poll_turn: u8,          // alternating F2/F3 priority (0 or 1)
    pub led_pwm_counter: u8,    // PWM cycle position
    pub led_pwm_period: u8,     // PWM period in steps (default 20 = 50Hz)

    // BT transport (groundwork — not yet active)
    pub bt_in_chan: i32,         // in[2]: HCI commands from host
    pub bt_out_chan: i32,        // out[4]: HCI events/data to host
    pub frame_pending_bt_rx: bool, // F3 read in progress
    _pad7: [u8; 3],

    // Ioctl response tracking
    pub pending_ioctl_id: u16,     // CDC id of last sent ioctl
    pub pending_ioctl_status: i16, // CDC status from response (-1 = no response yet)

}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::*;

    define_params! {
        Cyw43State;

        1, pio_idx, u8, 1, enum { pio0=0, pio1=1, pio2=2 }
            => |s, d, len| { s.pio_idx = p_u8(d, len, 0, 1); };

        2, dio_pin, u8, 24
            => |s, d, len| { s.dio_pin = p_u8(d, len, 0, 24); };

        3, clk_pin, u8, 29
            => |s, d, len| { s.clk_pin = p_u8(d, len, 0, 29); };

        4, cs_pin, u8, 25
            => |s, d, len| { s.cs_pin = p_u8(d, len, 0, 25); };

        5, pwr_pin, u8, 23
            => |s, d, len| { s.pwr_pin = p_u8(d, len, 0, 23); };
    }
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn log_error(s: &Cyw43State, msg: &[u8]) {
    let sys = &*s.syscalls;
    dev_log(sys, 1, msg.as_ptr(), msg.len());
}

unsafe fn log_info(s: &Cyw43State, msg: &[u8]) {
    let sys = &*s.syscalls;
    dev_log(sys, 3, msg.as_ptr(), msg.len());
}

/// Format u32 as "0xHHHHHHHH" (10 chars). Returns bytes written.
unsafe fn fmt_hex32(dst: *mut u8, val: u32) -> usize {
    *dst = b'0';
    *dst.add(1) = b'x';
    let hex = b"0123456789ABCDEF";
    let mut i = 0usize;
    while i < 8 {
        let nib = ((val >> (28 - i * 4)) & 0xF) as usize;
        *dst.add(2 + i) = hex[nib];
        i += 1;
    }
    10
}

// LED state machine steps — direct backplane GPIO register access.
// Uses CHIPCOMMON_GPIO_* registers (0x18000064/68/6C) via gSPI backplane
// function, bypassing firmware ioctls entirely. No WLC_UP, no SDPCM, no
// CDC response needed. Each step is one gSPI transaction.
//
// Init: WINDOW → CONTROL → OUTEN → OUT → ready (4 steps)
// Runtime: WINDOW (if needed) → READ → WRITE (read-modify-write, 1-3 steps)
const LED_OP_IDLE: u8 = 0;
const LED_OP_INIT_WINDOW: u8 = 1;   // Set backplane window to CHIPCOMMON_BASE
const LED_OP_INIT_CONTROL: u8 = 2;  // Clear GPIO_CONTROL bit 0 (GPIO mode, not peripheral)
const LED_OP_INIT_OUTEN: u8 = 3;    // Set GPIO_OUTPUT_EN bit 0 (output enable)
const LED_OP_INIT_OUT: u8 = 4;      // Clear GPIO_OUTPUT bit 0 (LED off)
const LED_OP_SEND_WINDOW: u8 = 5;   // Set backplane window (if needed)
const LED_OP_SEND_WRITE: u8 = 6;    // Write GPIO_OUTPUT bit 0

/// Maximum firmware chunks per step() call. At 64B/chunk and ~50µs/chunk,
/// 32 chunks ≈ 1.6ms per step, completing 230KB FW upload in ~115 steps.
const FW_CHUNKS_PER_STEP: u32 = 32;

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<Cyw43State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<Cyw43State>() {
            return -2;
        }

        // State memory is already zeroed by kernel's alloc_state()
        let s = &mut *(state as *mut Cyw43State);

        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // WiFi mode requires primary output; LED-only mode does not
        s.wifi_active = out_chan >= 0;

        // Discover secondary input/output ports
        s.led_chan = dev_channel_port(&*s.syscalls, 0, 1); // in[1]: LED control
        if s.led_chan >= 0 {
            log_info(s, b"[cyw43] led_chan wired");
        }
        s.led_pwm_period = 20; // 50Hz software PWM at 1ms step rate
        s.bt_in_chan = dev_channel_port(&*s.syscalls, 0, 2);  // in[2]: BT HCI commands

        // Discover secondary output ports
        s.scan_out_chan = dev_channel_port(&*s.syscalls, 1, 1); // out[1]: scan text
        s.scan_bin_chan = dev_channel_port(&*s.syscalls, 1, 2); // out[2]: scan binary
        s.status_chan = dev_channel_port(&*s.syscalls, 1, 3);   // out[3]: status events
        s.bt_out_chan = dev_channel_port(&*s.syscalls, 1, 4);   // out[4]: BT HCI events
        s.netif_state_chan = dev_channel_port(&*s.syscalls, 1, 5); // out[5]: netif state

        // Parse TLV params (sets defaults from schema if not in config)
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        } else {
            // Apply schema defaults when no params provided
            s.pio_idx = 1;
            s.dio_pin = 24;
            s.clk_pin = 29;
            s.cs_pin = 25;
            s.pwr_pin = 23;
        }
        s.pending_ioctl_status = -1;
        s.phase = Cyw43Phase::Init;
        s.substep = 0;

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut Cyw43State);
        if s.syscalls.is_null() {
            return -1;
        }

        // ════════════════════════════════════════════════════════════════
        // CYW43 Phase Transitions (CYW43439 gSPI init sequence)
        // ════════════════════════════════════════════════════════════════
        //
        // Phase          | Trigger                  | Next            | Notes
        // ───────────────|──────────────────────────|─────────────────|──────────────────
        // Init           | always                   | PowerOn         | claim PIO + GPIO
        // PowerOn        | power-on delay elapsed   | GspiInit        | WL_REG_ON high, 150ms
        // GspiInit       | gSPI test pattern ok     | ChipPrep        | bus config + ALP clk
        // ChipPrep       | cores reset, RAM cleared | LoadFw          | multi-substep
        // LoadFw         | firmware uploaded         | LoadNvram       | 64B backplane chunks
        // LoadNvram      | NVRAM uploaded            | WaitReady       | + NVRAM length token
        // WaitReady      | HT clock available       | InitWifi        | poll HT_AVAILABLE
        // InitWifi       | ioctl sequence complete  | RegisterNetif   | multi-substep
        // RegisterNetif  | netif + events created   | Running         |
        // Running        | (steady state)           | —               | event/frame loop
        // Error          | (terminal)               | —               | returns -1
        //
        // All phases → Error on any failed substep (r < 0).
        // substep: u8 counter within each phase (sequential, not named states).
        //
        match s.phase {
            Cyw43Phase::Init => step_init(s),
            Cyw43Phase::PowerOn => step_power_on(s),
            Cyw43Phase::GspiInit => step_gspi_init(s),
            Cyw43Phase::ChipPrep => step_chip_prep(s),
            Cyw43Phase::LoadFw => step_load_fw(s),
            Cyw43Phase::LoadNvram => step_load_nvram(s),
            Cyw43Phase::WaitReady => step_wait_ready(s),
            Cyw43Phase::LoadClm => step_load_clm(s),
            Cyw43Phase::InitWifi => step_init_wifi(s),
            Cyw43Phase::RegisterNetif => step_register_netif(s),
            Cyw43Phase::Running => step_running(s),
            Cyw43Phase::Error => -1,
            _ => {
                s.phase = Cyw43Phase::Error;
                -1
            }
        }
    }
}

// ============================================================================
// Phase Implementations
// ============================================================================

/// Phase 0: Initialize hardware handles
unsafe fn step_init(s: &mut Cyw43State) -> i32 {
    let sys = &*s.syscalls;

    match s.substep {
        0 => {
            // Claim power pin (output, initially low = off)
            let mut pwr_arg = [s.pwr_pin];
            let h = (sys.provider_open)(HAL_GPIO_CONTRACT, dev_gpio::SET_OUTPUT, pwr_arg.as_mut_ptr(), 1);
            if h < 0 {
                log_error(s, b"[cyw43] pwr pin fail");
                s.phase = Cyw43Phase::Error;
                return -1;
            }
            s.pwr_handle = h;
            let mut lvl = [0u8];
            (sys.provider_call)(h, dev_gpio::SET_LEVEL, lvl.as_mut_ptr(), 1);

            // Claim CS pin (output, initially high = deasserted)
            let mut cs_arg = [s.cs_pin];
            let h = (sys.provider_open)(HAL_GPIO_CONTRACT, dev_gpio::SET_OUTPUT, cs_arg.as_mut_ptr(), 1);
            if h < 0 {
                log_error(s, b"[cyw43] cs pin fail");
                s.phase = Cyw43Phase::Error;
                return -1;
            }
            s.cs_handle = h;
            let mut lvl = [1u8];
            (sys.provider_call)(h, dev_gpio::SET_LEVEL, lvl.as_mut_ptr(), 1);

            // Allocate PIO command slot — tracked against HAL_PIO.
            let mut alloc_arg = [s.pio_idx, 0u8];
            let h = (sys.provider_open)(HAL_PIO_CONTRACT, dev_pio::CMD_ALLOC, alloc_arg.as_mut_ptr(), 2);
            if h < 0 {
                log_error(s, b"[cyw43] pio alloc fail");
                s.phase = Cyw43Phase::Error;
                return -1;
            }
            s.pio_handle = h;

            s.substep = 1;
            0
        }
        1 => {
            // Load gSPI PIO program
            let load_args = abi::contracts::hal::pio::LoadProgramArgs {
                program: GSPI_PIO_PROGRAM.as_ptr(),
                program_len: GSPI_PIO_PROGRAM.len() as u32,
                wrap_target: GSPI_PIO_WRAP_TARGET,
                wrap: GSPI_PIO_WRAP,
                sideset_bits: GSPI_PIO_SIDESET_BITS,
                options: 0,
            };
            let r = (sys.provider_call)(
                s.pio_handle,
                dev_pio::CMD_LOAD_PROGRAM,
                &load_args as *const _ as *mut u8,
                core::mem::size_of::<abi::contracts::hal::pio::LoadProgramArgs>(),
            );
            if r < 0 {
                log_error(s, b"[cyw43] pio prog fail");
                s.phase = Cyw43Phase::Error;
                return -1;
            }

            // Configure PIO pins
            let cfg_args = abi::contracts::hal::pio::CmdConfigureArgs {
                data_pin: s.dio_pin,
                clk_pin: s.clk_pin,
                _pad: [0; 2],
                clock_div: DEFAULT_CLOCK_DIV,
            };
            let r = (sys.provider_call)(
                s.pio_handle,
                dev_pio::CMD_CONFIGURE,
                &cfg_args as *const _ as *mut u8,
                core::mem::size_of::<abi::contracts::hal::pio::CmdConfigureArgs>(),
            );
            if r < 0 {
                log_error(s, b"[cyw43] pio cfg fail");
                s.phase = Cyw43Phase::Error;
                return -1;
            }

            log_info(s, b"[cyw43] pio ok, powering on");
            s.phase = Cyw43Phase::PowerOn;
            s.substep = 0;
            s.last_time_ms = dev_millis(sys);
            0
        }
        _ => {
            s.substep = 0;
            0
        }
    }
}

/// Phase 1: Power on the chip and wait for startup
unsafe fn step_power_on(s: &mut Cyw43State) -> i32 {
    let sys = &*s.syscalls;

    match s.substep {
        0 => {
            // Assert power (high)
            let mut lvl = [1u8];
            (sys.provider_call)(s.pwr_handle, dev_gpio::SET_LEVEL, lvl.as_mut_ptr(), 1);
            s.last_time_ms = dev_millis(sys);
            s.substep = 1;
            0
        }
        1 => {
            // Wait for power-on delay
            let now = dev_millis(sys);
            if now - s.last_time_ms >= POWER_ON_DELAY_MS {
                log_info(s, b"[cyw43] pwr delay done, gspi init");
                s.phase = Cyw43Phase::GspiInit;
                s.substep = 0;
            }
            0
        }
        _ => {
            s.substep = 0;
            0
        }
    }
}

/// Phase 2: Initialize gSPI bus and verify communication
///
/// Sequence (matching Embassy cyw43-pio init_bus):
///   0-1: Read TEST_RO with swap16 until FEEDBEAD (chip ready, still in 16-bit mode)
///   2-3: Write combined bus config (BUS_CONFIG_INIT) with swap16 (sets 32-bit mode)
///   4-5: Write F1 response delay = 4 (now in 32-bit mode, normal write)
///   6-7: Read TEST_RO normal to verify 32-bit mode works
///   8+:  ALP clock, interrupts, etc.
unsafe fn step_gspi_init(s: &mut Cyw43State) -> i32 {
    let sys = &*s.syscalls;

    match s.substep {
        // ---- Step 0-1: Poll TEST_RO in 16-bit swapped mode ----
        0 => {
            s.last_time_ms = dev_millis(sys);
            s.substep = 1;
            0
        }
        1 => {
            // Read TEST_RO with swap16 (chip still in 16-bit word mode)
            let r = gspi::bus_read32_swapped_start(s, REG_BUS_TEST_RO);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 2;
            0
        }
        2 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

            let test_val = gspi::rxn_u32_swapped(s);
            if test_val == TEST_PATTERN {
                log_info(s, b"[cyw43] test_ro ok");
                s.substep = 3;
                return 0;
            }

            // Retry until timeout
            let elapsed = dev_millis(sys) - s.last_time_ms;
            if elapsed < 1000 {
                s.substep = 1; // retry
                return 0;
            }

            log_error(s, b"[cyw43] test reg fail");
            s.phase = Cyw43Phase::Error;
            -1
        }

        // ---- Step 3-4: Write combined bus config with swap16 ----
        3 => {
            // Write BUS_CONFIG_INIT (ctrl + resp_delay + status_en) as 32-bit swapped
            let r = gspi::bus_write32_swapped_start(s, REG_BUS_CTRL, BUS_CONFIG_INIT);
            if r < 0 {
                log_error(s, b"[cyw43] bus cfg fail");
                s.phase = Cyw43Phase::Error;
                return -1;
            }
            s.substep = 4;
            0
        }
        4 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 5;
            0
        }

        // ---- Step 5-6: Write F1 response delay (now in 32-bit mode) ----
        5 => {
            // Chip is now in 32-bit word mode; use normal (unswapped) writes
            let r = gspi::bus_write8_start(s, REG_BUS_RESP_DELAY_F1, GSPI_RESPONSE_DELAY as u8);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 6;
            0
        }
        6 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 7;
            0
        }

        // ---- Step 7-8: Verify TEST_RO in normal 32-bit mode ----
        7 => {
            let r = gspi::bus_read32_start(s, REG_BUS_TEST_RO);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 8;
            0
        }
        8 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

            let test_val = gspi::rxn_u32(s);
            if test_val != TEST_PATTERN {
                log_error(s, b"[cyw43] 32bit verify fail");
                s.phase = Cyw43Phase::Error;
                return -1;
            }
            s.substep = 9;
            0
        }

        // ---- Step 9+: ALP clock, interrupts (same as before, renumbered) ----
        9 => {
            // Enable ALP clock
            let r = gspi::wrapper_write8_start(s, REG_BP_CHIP_CLOCK_CSR, BP_CLK_ALP_REQUEST as u8);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 10;
            0
        }
        10 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.last_time_ms = dev_millis(sys);
            s.substep = 11;
            0
        }
        11 => {
            // Poll for ALP clock available
            let r = gspi::wrapper_read8_start(s, REG_BP_CHIP_CLOCK_CSR);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 12;
            0
        }
        12 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

            let clk = gspi::rxn_u8(s) as u32;
            if clk & BP_CLK_ALP_AVAILABLE != 0 {
                s.substep = 13;
            } else {
                let now = dev_millis(sys);
                if now - s.last_time_ms > ALP_TIMEOUT_MS {
                    log_error(s, b"[cyw43] alp timeout");
                    s.phase = Cyw43Phase::Error;
                    return -1;
                }
                s.substep = 11; // Poll again
            }
            0
        }
        13 => {
            // Clear ALP request, force ALP (required before backplane access)
            let r = gspi::wrapper_write8_start(s, REG_BP_CHIP_CLOCK_CSR, BP_CLK_FORCE_ALP as u8);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 14;
            0
        }
        14 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 15;
            0
        }
        15 => {
            // Enable F2 packet available interrupt
            let irq_en = IRQ_F2_PACKET_AVAILABLE | IRQ_DATA_UNAVAILABLE;
            let r = gspi::bus_write32_start(s, REG_BUS_INTERRUPT_ENABLE, irq_en);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 16;
            0
        }
        16 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

            // Always proceed to ChipPrep → firmware loading.
            // CYW43 GPIO needs firmware + HT clock to drive physical pins.
            log_info(s, b"[cyw43] gspi ok, chip prep");
            s.phase = Cyw43Phase::ChipPrep;
            s.substep = 0;
            0
        }

        _ => { s.substep = 0; 0 }
    }
}

/// Phase 3: Chip preparation — disable WLAN core, reset SOCSRAM, configure remap.
///
/// Matches Embassy's init sequence before firmware upload:
///   core_disable(WLAN)      — ensure ARM core is stopped
///   core_disable(SOCSRAM)   — stop SOCSRAM
///   core_reset(SOCSRAM)     — bring SOCSRAM out of reset with clocks
///   SOCSRAM remap disable   — write bankx registers for 4343x
///
/// Each backplane operation uses 2 substeps (start + poll), plus window
/// changes (2 substeps) and 1ms delays where required by the chip.
unsafe fn step_chip_prep(s: &mut Cyw43State) -> i32 {
    let sys = &*s.syscalls;

    match s.substep {
        // ================================================================
        // core_disable(WLAN): wrapper base = 0x18103000
        //   IOCTRL   = 0x18103408
        //   RESETCTRL = 0x18103800
        //   Both in window 0x18100000
        // ================================================================

        // Set window for WLAN wrapper registers
        0 => {
            let r = gspi::bp_set_window(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            if r > 0 { s.substep = 1; return 0; }
            s.substep = 2; 0
        }
        1 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            gspi::bp_window_done(s);
            s.substep = 2; 0
        }
        // Dummy read of RESETCTRL
        2 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 3; 0
        }
        3 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 4; 0
        }
        // Read RESETCTRL — check if already in reset
        4 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 5; 0
        }
        5 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            let val = gspi::rxn_u8(s);
            if val & AI_RESETCTRL_BIT_RESET != 0 {
                // Already in reset — skip to core_disable(SOCSRAM)
                s.substep = 16; return 0;
            }
            s.substep = 6; 0
        }
        // Write 0 to IOCTRL (disable clocks)
        6 => {
            let r = gspi::bp_write8_start(s, WLAN_WRAPPER_BASE + AI_IOCTRL_OFFSET, 0);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 7; 0
        }
        7 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 8; 0
        }
        // Readback IOCTRL
        8 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_IOCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 9; 0
        }
        9 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            // 1ms delay
            s.last_time_ms = dev_millis(sys);
            s.substep = 10; 0
        }
        10 => {
            if dev_millis(sys) - s.last_time_ms < 1 { return 0; }
            s.substep = 11; 0
        }
        // Assert reset
        11 => {
            let r = gspi::bp_write8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET, AI_RESETCTRL_BIT_RESET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 12; 0
        }
        12 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 13; 0
        }
        // Readback RESETCTRL
        13 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 14; 0
        }
        14 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 16; 0 // Skip 15, fall through to SOCSRAM
        }

        // ================================================================
        // core_disable(SOCSRAM): wrapper base = 0x18104000
        //   IOCTRL    = 0x18104408
        //   RESETCTRL = 0x18104800
        //   Window = 0x18104000
        // ================================================================

        // Set window for SOCSRAM wrapper registers
        16 => {
            let r = gspi::bp_set_window(s, SOCSRAM_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            if r > 0 { s.substep = 17; return 0; }
            s.substep = 18; 0
        }
        17 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            gspi::bp_window_done(s);
            s.substep = 18; 0
        }
        // Dummy read RESETCTRL
        18 => {
            let r = gspi::bp_read8_start(s, SOCSRAM_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 19; 0
        }
        19 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 20; 0
        }
        // Read RESETCTRL — check if already in reset
        20 => {
            let r = gspi::bp_read8_start(s, SOCSRAM_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 21; 0
        }
        21 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            let val = gspi::rxn_u8(s);
            if val & AI_RESETCTRL_BIT_RESET != 0 {
                // Already in reset — skip to core_reset enable part
                s.substep = 32; return 0;
            }
            s.substep = 22; 0
        }
        // Write 0 to IOCTRL
        22 => {
            let r = gspi::bp_write8_start(s, SOCSRAM_WRAPPER_BASE + AI_IOCTRL_OFFSET, 0);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 23; 0
        }
        23 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 24; 0
        }
        // Readback IOCTRL
        24 => {
            let r = gspi::bp_read8_start(s, SOCSRAM_WRAPPER_BASE + AI_IOCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 25; 0
        }
        25 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.last_time_ms = dev_millis(sys);
            s.substep = 26; 0
        }
        26 => {
            if dev_millis(sys) - s.last_time_ms < 1 { return 0; }
            s.substep = 27; 0
        }
        // Assert reset
        27 => {
            let r = gspi::bp_write8_start(s, SOCSRAM_WRAPPER_BASE + AI_RESETCTRL_OFFSET, AI_RESETCTRL_BIT_RESET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 28; 0
        }
        28 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 29; 0
        }
        // Readback RESETCTRL
        29 => {
            let r = gspi::bp_read8_start(s, SOCSRAM_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 30; 0
        }
        30 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 32; 0 // Skip 31, fall through to core_reset enable
        }

        // ================================================================
        // core_reset(SOCSRAM) part 2: bring out of reset
        // Still in SOCSRAM wrapper window
        // ================================================================

        // Write FGC | CLOCK_EN to IOCTRL
        32 => {
            let r = gspi::bp_write8_start(s, SOCSRAM_WRAPPER_BASE + AI_IOCTRL_OFFSET,
                AI_IOCTRL_BIT_FGC | AI_IOCTRL_BIT_CLOCK_EN);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 33; 0
        }
        33 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 34; 0
        }
        // Readback IOCTRL
        34 => {
            let r = gspi::bp_read8_start(s, SOCSRAM_WRAPPER_BASE + AI_IOCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 35; 0
        }
        35 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 36; 0
        }
        // Deassert reset
        36 => {
            let r = gspi::bp_write8_start(s, SOCSRAM_WRAPPER_BASE + AI_RESETCTRL_OFFSET, 0);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 37; 0
        }
        37 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            // 1ms delay
            s.last_time_ms = dev_millis(sys);
            s.substep = 38; 0
        }
        38 => {
            if dev_millis(sys) - s.last_time_ms < 1 { return 0; }
            s.substep = 39; 0
        }
        // Remove force-clock, keep clock-enable
        39 => {
            let r = gspi::bp_write8_start(s, SOCSRAM_WRAPPER_BASE + AI_IOCTRL_OFFSET,
                AI_IOCTRL_BIT_CLOCK_EN);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 40; 0
        }
        40 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 41; 0
        }
        // Readback IOCTRL
        41 => {
            let r = gspi::bp_read8_start(s, SOCSRAM_WRAPPER_BASE + AI_IOCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 42; 0
        }
        42 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            // 1ms delay
            s.last_time_ms = dev_millis(sys);
            s.substep = 43; 0
        }
        43 => {
            if dev_millis(sys) - s.last_time_ms < 1 { return 0; }
            s.substep = 44; 0
        }

        // ================================================================
        // SOCSRAM remap: disable SRAM_3 remap (4343x specific)
        //   bp_write32(SOCSRAM_BASE + 0x10, 3)
        //   bp_write32(SOCSRAM_BASE + 0x44, 0)
        //   Window = 0x18000000
        // ================================================================

        // Set window for SOCSRAM core registers
        44 => {
            let r = gspi::bp_set_window(s, SOCSRAM_BASE + SOCSRAM_BANKX_INDEX);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            if r > 0 { s.substep = 45; return 0; }
            s.substep = 46; 0
        }
        45 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            gspi::bp_window_done(s);
            s.substep = 46; 0
        }
        // Write BANKX_INDEX = 3
        46 => {
            let r = gspi::bp_write32_start(s, SOCSRAM_BASE + SOCSRAM_BANKX_INDEX, 3);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 47; 0
        }
        47 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 48; 0
        }
        // Write BANKX_PDA = 0
        48 => {
            let r = gspi::bp_write32_start(s, SOCSRAM_BASE + SOCSRAM_BANKX_PDA, 0);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 49; 0
        }
        49 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

            log_info(s, b"[cyw43] chip prep done, loading fw");
            s.phase = Cyw43Phase::LoadFw;
            s.substep = 0;
            s.fw_offset = 0;
            0
        }
        _ => { s.substep = 0; 0 }
    }
}

/// Phase 4: Upload firmware to chip ATCM RAM
unsafe fn step_load_fw(s: &mut Cyw43State) -> i32 {
    let fw = FIRMWARE;
    let fw_len = fw.len() as u32;

    // Upload FW_CHUNKS_PER_STEP chunks per step() call, yielding to the
    // scheduler between batches. This prevents the ~180ms blocking stall
    // that would starve all other modules during firmware upload.
    let mut chunks_done = 0u32;
    while s.fw_offset < fw_len && chunks_done < FW_CHUNKS_PER_STEP {
        let addr = ATCM_RAM_BASE + s.fw_offset;
        let remaining = fw_len - s.fw_offset;
        let chunk = if remaining > FW_CHUNK_SIZE as u32 {
            FW_CHUNK_SIZE
        } else {
            remaining as usize
        };
        let fw_ptr = fw.as_ptr().add(s.fw_offset as usize);
        let r = gspi::bp_write_block_sync(s, addr, fw_ptr, chunk);
        if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
        s.fw_offset += chunk as u32;
        chunks_done += 1;
    }

    if s.fw_offset >= fw_len {
        log_info(s, b"[cyw43] fw loaded, nvram next");
        s.phase = Cyw43Phase::LoadNvram;
        s.substep = 0;
        s.fw_offset = 0;
    }
    0
}

/// Phase 5: Upload NVRAM data to end of chip RAM + write length magic word.
/// Same loop-optimized state machine as step_load_fw.
unsafe fn step_load_nvram(s: &mut Cyw43State) -> i32 {
    let nvram = NVRAM;
    let nvram_len_aligned = ((nvram.len() + 3) & !3) as u32;
    let nvram_base_addr = ATCM_RAM_BASE + CHIP_RAM_SIZE - 4 - nvram_len_aligned;

    // Upload NVRAM data chunks (chunked like FW upload for consistency)
    let mut chunks_done = 0u32;
    while s.fw_offset < nvram_len_aligned && chunks_done < FW_CHUNKS_PER_STEP {
        let addr = nvram_base_addr + s.fw_offset;
        let remaining = nvram_len_aligned - s.fw_offset;
        let chunk = if remaining > FW_CHUNK_SIZE as u32 {
            FW_CHUNK_SIZE
        } else {
            remaining as usize
        };
        let actual_chunk = chunk.min(nvram.len().saturating_sub(s.fw_offset as usize));
        let r = if actual_chunk > 0 {
            let nvram_ptr = nvram.as_ptr().add(s.fw_offset as usize);
            gspi::bp_write_block_sync(s, addr, nvram_ptr, actual_chunk)
        } else {
            let zeros = [0u8; 4];
            gspi::bp_write_block_sync(s, addr, zeros.as_ptr(), chunk)
        };
        if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
        s.fw_offset += chunk as u32;
        chunks_done += 1;
    }

    if s.fw_offset < nvram_len_aligned {
        return 0; // More chunks to upload next step
    }

    // Write NVRAM length magic word (sync)
    let magic_addr = ATCM_RAM_BASE + CHIP_RAM_SIZE - 4;
    let nvram_len_words = nvram_len_aligned / 4;
    let magic = (!nvram_len_words << 16) | nvram_len_words;

    let r = gspi::bp_set_window_sync(s, magic_addr);
    if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

    let magic_data = magic.to_le_bytes();
    let r = gspi::txn_write_sync(s, FUNC_BACKPLANE, magic_addr & BP_WIN_MASK, &magic_data);
    if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

    log_info(s, b"[cyw43] nvram done, wait ready");
    s.phase = Cyw43Phase::WaitReady;
    s.substep = 0;
    s.fw_offset = 0;
    0
}

/// Phase 7: Upload CLM blob via iovar
unsafe fn step_load_clm(s: &mut Cyw43State) -> i32 {
    let clm = CLM;
    let clm_len = clm.len() as u32;

    match s.substep {
        0 => {
            if s.fw_offset >= clm_len {
                s.phase = Cyw43Phase::InitWifi;
                s.substep = 0;
                s.fw_offset = 0;
                let sys = &*s.syscalls;
                s.last_time_ms = dev_millis(sys);
                return 0;
            }

            // Build clm_load iovar: "clmload\0" + header + chunk
            let remaining = clm_len - s.fw_offset;
            let chunk = if remaining > CLM_CHUNK_SIZE as u32 {
                CLM_CHUNK_SIZE
            } else {
                remaining as usize
            };

            // CLM download header (12 bytes): flag(u16), type(u16), len(u32), crc(u32)
            // Embassy: flag always includes DOWNLOAD_FLAG_HANDLER_VER (0x1000)
            let mut flag: u16 = 0x1000; // HANDLER_VER
            if s.fw_offset == 0 { flag |= 0x0002; } // DL_BEGIN
            if s.fw_offset + chunk as u32 >= clm_len { flag |= 0x0004; } // DL_END

            let iovar_name = b"clmload\0";
            let hdr_len = iovar_name.len() + 12 + chunk;

            // Build SDPCM + CDC header
            let sdpcm_len = gspi::build_ioctl_header(
                &mut s.frame_buf,
                SDPCM_CHAN_CONTROL,
                s.sdpcm_seq,
                WLC_SET_VAR,
                0,
                hdr_len,
            );

            // Copy iovar name (pointer-based to avoid bounds checks)
            let fb = s.frame_buf.as_mut_ptr();
            let mut i = 0;
            let base = sdpcm_len;
            while i < iovar_name.len() {
                *fb.add(base + i) = iovar_name[i];
                i += 1;
            }

            // CLM download header (12 bytes): flag(u16) + type(u16) + len(u32) + crc(u32)
            let hdr_base = base + iovar_name.len();
            *fb.add(hdr_base) = (flag & 0xFF) as u8;
            *fb.add(hdr_base + 1) = ((flag >> 8) & 0xFF) as u8;
            *fb.add(hdr_base + 2) = 0x02; // type = DOWNLOAD_TYPE_CLM
            *fb.add(hdr_base + 3) = 0x00;
            let len_bytes = (chunk as u32).to_le_bytes();
            *fb.add(hdr_base + 4) = len_bytes[0];
            *fb.add(hdr_base + 5) = len_bytes[1];
            *fb.add(hdr_base + 6) = len_bytes[2];
            *fb.add(hdr_base + 7) = len_bytes[3];
            // crc = 0
            *fb.add(hdr_base + 8) = 0;
            *fb.add(hdr_base + 9) = 0;
            *fb.add(hdr_base + 10) = 0;
            *fb.add(hdr_base + 11) = 0;

            // Copy CLM data
            let data_base = hdr_base + 12;
            let clm_ptr = clm.as_ptr().add(s.fw_offset as usize);
            i = 0;
            while i < chunk {
                *fb.add(data_base + i) = *clm_ptr.add(i);
                i += 1;
            }

            let total = sdpcm_len + hdr_len;
            s.sdpcm_seq = s.sdpcm_seq.wrapping_add(1);

            let r = gspi::wlan_write_start(s, s.frame_buf.as_ptr(), total);
            if r < 0 {
                s.phase = Cyw43Phase::Error;
                return -1;
            }
            s.substep = 1;
            0
        }
        1 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

            let remaining = clm_len - s.fw_offset;
            let chunk = if remaining > CLM_CHUNK_SIZE as u32 {
                CLM_CHUNK_SIZE as u32
            } else {
                remaining
            };
            s.fw_offset += chunk;
            s.substep = 0;
            0
        }
        _ => { s.substep = 0; 0 }
    }
}

/// Phase 6: core_reset(WLAN) + wait for HT clock + F2 ready.
///
/// Matches Embassy's sequence exactly:
///   1. core_disable(WLAN) via wrapper registers at 0x18103000
///   2. Enable WLAN core (FGC|CLOCK_EN → deassert reset → 1ms → CLOCK_EN → 1ms)
///   3. Poll HT_AVAILABLE in chip clock CSR (firmware brings this up, ~29ms)
///   4. Poll F2_RX_READY in bus status
unsafe fn step_wait_ready(s: &mut Cyw43State) -> i32 {
    let sys = &*s.syscalls;

    match s.substep {
        // ================================================================
        // core_disable(WLAN) — same pattern as chip_prep but repeated
        // because core_reset always starts with core_disable.
        // WLAN wrapper: IOCTRL=0x18103408, RESETCTRL=0x18103800
        // ================================================================

        // Set window for WLAN wrapper
        0 => {
            let r = gspi::bp_set_window(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            if r > 0 { s.substep = 1; return 0; }
            s.substep = 2; 0
        }
        1 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            gspi::bp_window_done(s);
            s.substep = 2; 0
        }
        // Dummy read RESETCTRL
        2 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 3; 0
        }
        3 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 4; 0
        }
        // Read RESETCTRL — check if already in reset
        4 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 5; 0
        }
        5 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            let val = gspi::rxn_u8(s);
            if val & AI_RESETCTRL_BIT_RESET != 0 {
                // Already in reset — skip to core_reset enable part
                s.substep = 16; return 0;
            }
            s.substep = 6; 0
        }
        // Write 0 to IOCTRL (disable clocks)
        6 => {
            let r = gspi::bp_write8_start(s, WLAN_WRAPPER_BASE + AI_IOCTRL_OFFSET, 0);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 7; 0
        }
        7 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 8; 0
        }
        // Readback IOCTRL
        8 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_IOCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 9; 0
        }
        9 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.last_time_ms = dev_millis(sys);
            s.substep = 10; 0
        }
        10 => {
            if dev_millis(sys) - s.last_time_ms < 1 { return 0; }
            s.substep = 11; 0
        }
        // Assert reset
        11 => {
            let r = gspi::bp_write8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET, AI_RESETCTRL_BIT_RESET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 12; 0
        }
        12 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 13; 0
        }
        // Readback RESETCTRL
        13 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 14; 0
        }
        14 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 16; 0 // Fall through to enable
        }

        // ================================================================
        // core_reset(WLAN) part 2: bring out of reset
        // Still in WLAN wrapper window
        // ================================================================

        // Write FGC | CLOCK_EN to IOCTRL
        16 => {
            let r = gspi::bp_write8_start(s, WLAN_WRAPPER_BASE + AI_IOCTRL_OFFSET,
                AI_IOCTRL_BIT_FGC | AI_IOCTRL_BIT_CLOCK_EN);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 17; 0
        }
        17 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 18; 0
        }
        // Readback IOCTRL
        18 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_IOCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 19; 0
        }
        19 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 20; 0
        }
        // Deassert reset
        20 => {
            let r = gspi::bp_write8_start(s, WLAN_WRAPPER_BASE + AI_RESETCTRL_OFFSET, 0);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 21; 0
        }
        21 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            // 1ms delay
            s.last_time_ms = dev_millis(sys);
            s.substep = 22; 0
        }
        22 => {
            if dev_millis(sys) - s.last_time_ms < 1 { return 0; }
            s.substep = 23; 0
        }
        // Remove force-clock, keep clock-enable
        23 => {
            let r = gspi::bp_write8_start(s, WLAN_WRAPPER_BASE + AI_IOCTRL_OFFSET,
                AI_IOCTRL_BIT_CLOCK_EN);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 24; 0
        }
        24 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 25; 0
        }
        // Readback IOCTRL
        25 => {
            let r = gspi::bp_read8_start(s, WLAN_WRAPPER_BASE + AI_IOCTRL_OFFSET);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 26; 0
        }
        26 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            // 1ms delay
            s.last_time_ms = dev_millis(sys);
            s.substep = 27; 0
        }
        27 => {
            if dev_millis(sys) - s.last_time_ms < 1 { return 0; }
            s.substep = 28; 0
        }

        // ================================================================
        // Poll HT clock available (firmware brings this up, ~29ms)
        // ================================================================
        28 => {
            s.last_time_ms = dev_millis(sys);
            s.substep = 29; 0
        }
        29 => {
            let r = gspi::wrapper_read8_start(s, REG_BP_CHIP_CLOCK_CSR);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 30; 0
        }
        30 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

            let clk = gspi::rxn_u8(s) as u32;
            if clk & BP_CLK_HT_AVAILABLE != 0 {
                s.substep = 31;
            } else {
                let now = dev_millis(sys);
                if now - s.last_time_ms > HT_TIMEOUT_MS {
                    log_error(s, b"[cyw43] ht timeout");
                    s.phase = Cyw43Phase::Error;
                    return -1;
                }
                s.substep = 29; // Poll again
            }
            0
        }

        // ================================================================
        // Poll F2 ready
        // ================================================================
        31 => {
            s.last_time_ms = dev_millis(sys);
            s.substep = 32; 0
        }
        32 => {
            let r = gspi::bus_read32_start(s, REG_BUS_STATUS);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 33; 0
        }
        33 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }

            let status = gspi::rxn_u32(s);
            if status & STATUS_F2_RX_READY != 0 {
                if s.wifi_active {
                    s.phase = Cyw43Phase::LoadClm;
                    s.substep = 0;
                    s.fw_offset = 0;
                } else {
                    // LED-only mode: firmware running, skip WiFi setup
                    log_info(s, b"[cyw43] fw ready, led-only mode");
                    s.phase = Cyw43Phase::Running;
                    s.substep = 0;
                    return 3; // StepOutcome::Ready
                }
            } else {
                let now = dev_millis(sys);
                if now - s.last_time_ms > FW_READY_TIMEOUT_MS {
                    log_error(s, b"[cyw43] fw timeout");
                    s.phase = Cyw43Phase::Error;
                    return -1;
                }
                s.substep = 32; // Poll again
            }
            0
        }
        _ => { s.substep = 0; 0 }
    }
}

/// Phase 6: Initialize WiFi subsystem
///
/// Matches Embassy cyw43 init sequence:
///   bus:txglom=0 → country → ampdu_ba_wsize=8 → ampdu_mpdu=4
///   → event_msgs → WLC_UP → PM=0 → GMode=1
unsafe fn step_init_wifi(s: &mut Cyw43State) -> i32 {
    match s.substep {
        // ── bus:txglom=0 (disable TX glomming) ──────────────────
        0 => {
            let r = wifi_ops::ioctl_set_var(s, IOVAR_BUS_TXGLOM, &0u32.to_le_bytes());
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 1;
            0
        }
        1 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 2;
            0
        }
        // ── country=XX ──────────────────────────────────────────
        2 => {
            let country = [
                b'X', b'X', 0, 0,        // country_abbrev
                b'X', b'X', 0, 0,        // country_code
                0xFF, 0xFF, 0xFF, 0xFF,   // rev = -1 (i32 LE)
            ];
            let r = wifi_ops::ioctl_set_var(s, IOVAR_COUNTRY, &country);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 3;
            0
        }
        3 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 4;
            0
        }
        // ── ampdu_ba_wsize=8 (AMPDU block-ack window) ───────────
        4 => {
            let r = wifi_ops::ioctl_set_var(s, IOVAR_AMPDU_BA_WSIZE, &8u32.to_le_bytes());
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 5;
            0
        }
        5 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 6;
            0
        }
        // ── ampdu_mpdu=4 (max MPDUs per AMPDU) ──────────────────
        6 => {
            let r = wifi_ops::ioctl_set_var(s, IOVAR_AMPDU_MPDU, &4u32.to_le_bytes());
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 7;
            0
        }
        7 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 8;
            0
        }
        // ── event_msgs ──────────────────────────────────────────
        8 => {
            // Enable all events except spammy ones.
            // Format: { iface: u32 LE = 0, events: [u8; 24] = bitmap }
            let mut evtmask = [0u8; 28];
            let mut i = 4usize;
            while i < 28 {
                evtmask[i] = 0xFF;
                i += 1;
            }
            evtmask[4 + 19/8] &= !(1u8 << (19 % 8)); // ROAM
            evtmask[4 + 40/8] &= !(1u8 << (40 % 8)); // RADIO
            evtmask[4 + 44/8] &= !(1u8 << (44 % 8)); // PROBREQ_MSG
            evtmask[4 + 54/8] &= !(1u8 << (54 % 8)); // IF
            evtmask[4 + 71/8] &= !(1u8 << (71 % 8)); // PROBRESP_MSG
            evtmask[4 + 137/8] &= !(1u8 << (137 % 8)); // PROBREQ_MSG_RX
            let r = wifi_ops::ioctl_set_var(s, IOVAR_EVT_MASK, &evtmask);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 9;
            0
        }
        9 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 10;
            0
        }
        // ── WLC_UP ──────────────────────────────────────────────
        10 => {
            let r = wifi_ops::ioctl_set_u32(s, WLC_UP, 0);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 11;
            0
        }
        11 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 12;
            0
        }
        // ── sup_wpa=1 (enable supplicant early so it's ready for SAE) ─
        12 => {
            let mut val = [0u8; 8];
            val[4] = 1; // iface_idx=0, value=1 (enable)
            let r = wifi_ops::ioctl_set_var(s, IOVAR_BSSCFG_SUP_WPA, &val);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 13;
            0
        }
        13 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 14;
            0
        }
        // ── sup_wpa2_eapver=-1 (accept any EAP version) ─────────
        14 => {
            let mut val = [0u8; 8];
            val[4] = 0xFF; val[5] = 0xFF; val[6] = 0xFF; val[7] = 0xFF;
            let r = wifi_ops::ioctl_set_var(s, IOVAR_BSSCFG_SUP_WPA2_EAPVER, &val);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 15;
            0
        }
        15 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 16;
            0
        }
        // ── sup_wpa_tmo=2500 (WPA handshake timeout) ────────────
        16 => {
            let mut val = [0u8; 8];
            val[4] = 0xC4; val[5] = 0x09; // iface_idx=0, value=2500
            let r = wifi_ops::ioctl_set_var(s, IOVAR_BSSCFG_SUP_WPA_TMO, &val);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 17;
            0
        }
        17 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 18;
            0
        }
        // ── PM=0 (disable power management) ─────────────────────
        18 => {
            let r = wifi_ops::ioctl_set_u32(s, WLC_SET_PM, 0);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 19;
            0
        }
        19 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 20;
            0
        }
        // ── GMode=1 (auto) ──────────────────────────────────────
        20 => {
            let r = wifi_ops::ioctl_set_u32(s, WLC_SET_GMODE, 1);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 21;
            0
        }
        21 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 22;
            0
        }
        // ── arp_ol=0 (disable ARP offloading) ────────────────────
        22 => {
            let r = wifi_ops::ioctl_set_var(s, IOVAR_ARP_OL, &0u32.to_le_bytes());
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 23;
            0
        }
        23 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 24;
            0
        }
        // ── arp_version=0 ────────────────────────────────────────
        24 => {
            let r = wifi_ops::ioctl_set_var(s, IOVAR_ARP_VERSION, &0u32.to_le_bytes());
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 25;
            0
        }
        25 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 26;
            0
        }
        // ── allmulti=1 (receive all multicast/broadcast frames) ──
        26 => {
            let r = wifi_ops::ioctl_set_var(s, IOVAR_ALLMULTI, &1u32.to_le_bytes());
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 27;
            0
        }
        27 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 28;
            0
        }
        // ── Read MAC from chip via GET_VAR("cur_etheraddr") ─────
        28 => {
            let name = b"cur_etheraddr\0";
            let r = wifi_ops::ioctl_get_var(s, name, 6);
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.substep = 29;
            0
        }
        29 => {
            let r = gspi::txn_poll(s);
            if r == 0 { return 0; }
            if r < 0 { s.phase = Cyw43Phase::Error; return -1; }
            s.mac_retries = 0;
            s.substep = 30;
            0
        }
        // Poll for ioctl response containing MAC
        30 => {
            // Read bus status
            let r = gspi::bus_read32_start(s, REG_BUS_STATUS);
            if r < 0 { return 0; }
            let r = gspi::txn_poll(s);
            if r <= 0 { return 0; }
            let status = gspi::rxn_u32(s);
            if status & STATUS_F2_PKT_AVAILABLE == 0 {
                // No packet yet — check retry limit
                s.mac_retries += 1;
                if s.mac_retries > 50 {
                    // Give up, continue with zeroed MAC
                    s.phase = Cyw43Phase::RegisterNetif;
                    s.substep = 0;
                    s.wifi_state = Cyw43WifiState::Ready;
                }
                return 0;
            }
            let pkt_len = ((status >> STATUS_F2_PKT_LEN_SHIFT)
                & STATUS_F2_PKT_LEN_MASK) as usize;
            if pkt_len == 0 || pkt_len > 1500 {
                return 0;
            }
            // Read the frame
            let r = gspi::wlan_read_start(s, pkt_len);
            if r < 0 { return 0; }
            let r = gspi::txn_poll(s);
            if r <= 0 { return 0; }

            // Parse SDPCM header
            let payload = gspi::rxn_payload_ptr(s);
            let (channel, data_offset, data_len) =
                gspi::parse_sdpcm_header(payload, pkt_len);
            if channel != SDPCM_CHAN_CONTROL as i8 || data_len < CDC_HEADER_LEN + 6 {
                // Not a control response or too small — discard and retry
                s.mac_retries += 1;
                if s.mac_retries > 30 {
                    s.phase = Cyw43Phase::RegisterNetif;
                    s.substep = 0;
                    s.wifi_state = Cyw43WifiState::Ready;
                }
                return 0;
            }
            let cdc = payload.add(data_offset);
            // Check CDC cmd — skip stale SET_VAR responses from earlier init ioctls
            let cmd = u32::from_le_bytes([*cdc, *cdc.add(1), *cdc.add(2), *cdc.add(3)]);
            if cmd != WLC_GET_VAR {
                // Stale ioctl response (SET_VAR etc.) — discard and retry
                s.mac_retries += 1;
                if s.mac_retries > 30 {
                    s.phase = Cyw43Phase::RegisterNetif;
                    s.substep = 0;
                    s.wifi_state = Cyw43WifiState::Ready;
                }
                return 0;
            }
            // This is our GET_VAR response — check error flag
            let flags = (*cdc.add(8) as u16) | ((*cdc.add(9) as u16) << 8);
            if flags & 0x01 == 0 {
                // Success — firmware overwrites var name with value at CDC payload start
                let mac_ptr = cdc.add(CDC_HEADER_LEN);
                let mut m = 0;
                while m < 6 {
                    s.mac_addr[m] = *mac_ptr.add(m);
                    m += 1;
                }
                // Log the MAC
                let sys = &*s.syscalls;
                let mut buf = [0u8; 36];
                let prefix = b"[cyw43] mac=";
                let mut p = 0usize;
                while p < prefix.len() { buf[p] = prefix[p]; p += 1; }
                let hex = b"0123456789abcdef";
                m = 0;
                while m < 6 {
                    buf[p] = hex[(s.mac_addr[m] >> 4) as usize];
                    buf[p + 1] = hex[(s.mac_addr[m] & 0x0F) as usize];
                    p += 2;
                    if m < 5 { buf[p] = b':'; p += 1; }
                    m += 1;
                }
                dev_log(sys, 1, buf.as_ptr(), p);
            }
            s.ioctl_recv_count = s.ioctl_recv_count.wrapping_add(1);
            s.phase = Cyw43Phase::RegisterNetif;
            s.substep = 0;
            s.wifi_state = Cyw43WifiState::Ready;
            0
        }
        _ => { s.substep = 0; 0 }
    }
}

/// Phase 7: Signal radio-ready state and transition to Running.
unsafe fn step_register_netif(s: &mut Cyw43State) -> i32 {
    let sys = &*s.syscalls;

    match s.substep {
        0 => {
            // Emit "radio ready, not connected" so wifi module can proceed.
            emit_netif_state(s, NETIF_STATE_NO_LINK);

            s.phase = Cyw43Phase::Running;
            s.substep = 0;
            // Startup metric: radio ready
            {
                let ms = dev_millis(sys);
                let mut buf = [0u8; 30];
                let bp = buf.as_mut_ptr();
                let prefix = b"[cyw43] ready t+";
                let mut p = 0;
                while p < prefix.len() { *bp.add(p) = *prefix.as_ptr().add(p); p += 1; }
                p += fmt_u32_raw(buf.as_mut_ptr().add(p), ms as u32);
                *bp.add(p) = b'm'; p += 1;
                *bp.add(p) = b's'; p += 1;
                dev_log(sys, 1, bp, p);
            }
            emit_status_event(s, MSG_RADIO_READY, &[]);
            3 // StepOutcome::Ready
        }
        _ => { s.substep = 0; 0 }
    }
}

/// Phase 8: Running — poll for events, handle frame I/O, service WiFi ops.
///
/// Architecture: Each section performs at most one gSPI transaction per step()
/// call. F2 polling runs unconditionally (needed for ioctl responses even in
/// LED-only mode). LED operations are a state machine interleaved with WiFi I/O.
///
/// frame_buf contention (Issue #4): frame_buf is a staging buffer for building
/// SDPCM frames. txn_write() copies data into txn_buf before the synchronous
/// PIO DMA transfer, so frame_buf is immediately reusable. No actual contention
/// exists between TX frames and ioctl commands.
///
/// CDC id matching (Issue #5): Ioctl responses are counted via ioctl_recv_count
/// in process_rx_frame. Since only one ioctl is in flight at a time (enforced by
/// txn_step == Idle gating), sequential count matching is sufficient. CDC id
/// field matching can be added when concurrent ioctl support (Issue #13) is needed.
/// Poll chip status, start F2/F3 reads, handle read completions.
unsafe fn step_rx(s: &mut Cyw43State) {
    // Poll chip status for incoming frames (only when no txn in progress)
    if s.txn_step == gspi::TxnStep::Idle && !s.frame_pending_rx && s.substep == 0 {
        let r = gspi::bus_read32_start(s, REG_BUS_STATUS);
        if r >= 0 {
            s.frame_pending_rx = true;
        }
    }

    // Check for status read completion — start F2 or F3 read
    if s.frame_pending_rx {
        let r = gspi::txn_poll(s);
        if r > 0 {
            s.frame_pending_rx = false;
            let status = gspi::rxn_u32(s);
            s.last_status = status;

            let f2_avail = status & STATUS_F2_PKT_AVAILABLE != 0;
            let f3_avail = status & STATUS_F3_PKT_AVAILABLE != 0;

            // Round-robin: even turns → F2 first, odd → F3 first
            let try_f2_first = s.poll_turn & 1 == 0;
            let mut started = false;

            if try_f2_first {
                if f2_avail && !started {
                    started = try_start_f2_read(s, status);
                }
                if f3_avail && !started {
                    started = try_start_f3_read(s, status);
                }
            } else {
                if f3_avail && !started {
                    started = try_start_f3_read(s, status);
                }
                if f2_avail && !started {
                    started = try_start_f2_read(s, status);
                }
            }

            if started {
                s.poll_turn = s.poll_turn.wrapping_add(1);
            }
        } else if r < 0 {
            s.frame_pending_rx = false;
        }
    }

    // Handle F2 (WiFi) frame read completion
    if s.substep == 10 {
        let r = gspi::txn_poll(s);
        if r > 0 {
            s.substep = 0;
            process_rx_frame(s);
        } else if r < 0 {
            s.substep = 0;
        }
    }

    // Handle F3 (BT) frame read completion — stub: log and discard
    if s.substep == 11 {
        let r = gspi::txn_poll(s);
        if r > 0 {
            s.substep = 0;
        } else if r < 0 {
            s.substep = 0;
        }
    }
}

/// Poll ctrl channel and drive pending WiFi operations.
unsafe fn step_wifi_ops(s: &mut Cyw43State) {
    let sys = &*s.syscalls;

    // Check for pending WiFi operations from ctrl channel
    if s.ctrl_chan >= 0
        && s.pending_wifi_op == wifi_ops::WifiOp::None
        && s.txn_step == gspi::TxnStep::Idle
    {
        let poll = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
        if poll > 0 && (poll as u32 & POLL_IN) != 0 {
            let mut cmd_buf = [0u8; 128];
            let (ty, len) = msg_read(sys, s.ctrl_chan, cmd_buf.as_mut_ptr(), cmd_buf.len());
            if ty != 0 {
                process_wifi_command(s, ty, cmd_buf.as_ptr(), len as usize);
            }
        }
    }

    // Drive pending WiFi operation
    if s.pending_wifi_op != wifi_ops::WifiOp::None {
        let result = match s.pending_wifi_op {
            wifi_ops::WifiOp::Connect => wifi_ops::step_connect(s),
            wifi_ops::WifiOp::Disconnect => wifi_ops::step_disconnect(s),
            wifi_ops::WifiOp::Scan => wifi_ops::step_scan(s),
            _ => 1,
        };

        let completed_op = s.pending_wifi_op;
        if result > 0 {
            s.pending_wifi_op = wifi_ops::WifiOp::None;
            s.wifi_substep = 0;
            if completed_op == wifi_ops::WifiOp::Disconnect {
                emit_netif_state(s, NETIF_STATE_DOWN);
            }
            if completed_op == wifi_ops::WifiOp::Scan && s.scan_out_chan >= 0 {
                let sys = &*s.syscalls;
                let msg = b"--- scan done ---\n";
                (sys.channel_write)(s.scan_out_chan, msg.as_ptr(), msg.len());
            }
            if completed_op == wifi_ops::WifiOp::Connect {
                s.wifi_state = Cyw43WifiState::Connecting;
                log_info(s, b"[cyw43] assoc started");
            } else if completed_op == wifi_ops::WifiOp::Disconnect {
                s.wifi_state = Cyw43WifiState::Ready;
                emit_status_event(s, MSG_DISCONNECTED, &[0]);
            } else if completed_op == wifi_ops::WifiOp::Scan {
                emit_status_event(s, MSG_SCAN_DONE, &[s.scan_count]);
            }
        } else if result < 0 {
            log_error(s, b"[cyw43] wifi op fail");
            s.pending_wifi_op = wifi_ops::WifiOp::None;
            s.wifi_substep = 0;
        }
    }
}

/// Read TX frames from in_chan, build SDPCM headers, send via gSPI.
unsafe fn step_tx(s: &mut Cyw43State) {
    let sys = &*s.syscalls;

    // TX fairness: defer TX when F2/F3 RX packets are pending.
    if s.in_chan >= 0
        && s.txn_step == gspi::TxnStep::Idle
        && !s.frame_pending_tx
        && s.substep == 0
        && (s.last_status & (STATUS_F2_PKT_AVAILABLE | STATUS_F3_PKT_AVAILABLE)) == 0
    {
        let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
        if poll > 0 && (poll as u32 & POLL_IN) != 0 {
            let r = (sys.channel_read)(
                s.in_chan,
                s.frame_buf.as_mut_ptr(),
                MAX_FRAME_SIZE,
            );
            if r > 0 {
                let eth_len = r as usize;
                let hdr_len = SDPCM_HEADER_LEN + BDC_HEADER_LEN;
                let fb = s.frame_buf.as_mut_ptr();
                let mut i = eth_len;
                while i > 0 {
                    i -= 1;
                    *fb.add(hdr_len + i) = *fb.add(i);
                }
                gspi::build_data_header(&mut s.frame_buf, s.sdpcm_seq, eth_len);
                s.sdpcm_seq = s.sdpcm_seq.wrapping_add(1);
                let total = hdr_len + eth_len;
                let r = gspi::wlan_write_start(s, s.frame_buf.as_ptr(), total);
                if r >= 0 {
                    s.frame_pending_tx = true;
                }
            }
        }
    }

    // Check TX completion
    if s.frame_pending_tx {
        let r = gspi::txn_poll(s);
        if r != 0 {
            s.frame_pending_tx = false;
        }
    }
}

/// LED state machine (backplane GPIO) + software PWM + LED channel input.
///
/// Software PWM: at each step, advance a counter modulo `led_pwm_period`.
/// Compare counter to duty threshold derived from `led_brightness` (0-255).
/// Only issue gSPI transactions when the physical LED state needs to change.
/// Default period = 20 steps = 50Hz at 1ms step rate (above flicker threshold).
unsafe fn step_led(s: &mut Cyw43State) {
    if s.led_chan < 0 || s.substep != 0 {
        return;
    }

    // --- gSPI state machine for LED GPIO control ---
    match s.led_op {
        LED_OP_IDLE => {
            if !s.led_gpio_ready {
                s.led_op = LED_OP_INIT_WINDOW;
            }
        }
        LED_OP_INIT_WINDOW => {
            if s.txn_step == gspi::TxnStep::Idle {
                let r = gspi::bp_set_window(s, CHIPCOMMON_GPIO_CONTROL);
                if r > 0 {
                    gspi::txn_poll(s);
                    gspi::bp_window_done(s);
                    s.led_op = LED_OP_INIT_CONTROL;
                } else if r == 0 {
                    s.led_op = LED_OP_INIT_CONTROL;
                } else {
                    s.led_op = LED_OP_IDLE;
                }
            }
        }
        LED_OP_INIT_CONTROL => {
            if s.txn_step == gspi::TxnStep::Idle {
                let r = gspi::bp_write32_start(s, CHIPCOMMON_GPIO_CONTROL, 0);
                if r >= 0 {
                    gspi::txn_poll(s);
                    s.led_op = LED_OP_INIT_OUTEN;
                } else {
                    s.led_op = LED_OP_IDLE;
                }
            }
        }
        LED_OP_INIT_OUTEN => {
            if s.txn_step == gspi::TxnStep::Idle {
                let r = gspi::bp_write32_start(s, CHIPCOMMON_GPIO_OUTPUT_EN, 1);
                if r >= 0 {
                    gspi::txn_poll(s);
                    s.led_op = LED_OP_INIT_OUT;
                } else {
                    s.led_op = LED_OP_IDLE;
                }
            }
        }
        LED_OP_INIT_OUT => {
            if s.txn_step == gspi::TxnStep::Idle {
                let r = gspi::bp_write32_start(s, CHIPCOMMON_GPIO_OUTPUT, 0);
                if r >= 0 {
                    gspi::txn_poll(s);
                    s.led_gpio_ready = true;
                    s.led_state = 0;
                    s.led_pwm_counter = 0;
                    if s.led_pwm_period == 0 { s.led_pwm_period = 20; }
                    log_info(s, b"[cyw43] led bp ready");
                }
                s.led_op = LED_OP_IDLE;
            }
        }
        LED_OP_SEND_WINDOW => {
            if s.txn_step == gspi::TxnStep::Idle {
                let r = gspi::bp_set_window(s, CHIPCOMMON_GPIO_OUTPUT);
                if r > 0 {
                    gspi::txn_poll(s);
                    gspi::bp_window_done(s);
                    s.led_op = LED_OP_SEND_WRITE;
                } else if r == 0 {
                    s.led_op = LED_OP_SEND_WRITE;
                } else {
                    s.led_op = LED_OP_IDLE;
                }
            }
        }
        LED_OP_SEND_WRITE => {
            if s.txn_step == gspi::TxnStep::Idle {
                // Compute target from current PWM state
                let period = s.led_pwm_period as u16;
                let duty_steps = ((s.led_brightness as u16 * period) + 127) / 255;
                let target_on = s.led_pwm_counter < duty_steps as u8;
                let val: u32 = if target_on { 1 } else { 0 };
                let r = gspi::bp_write32_start(s, CHIPCOMMON_GPIO_OUTPUT, val);
                if r >= 0 {
                    gspi::txn_poll(s);
                    s.led_state = val as u8;
                }
                s.led_op = LED_OP_IDLE;
            }
        }
        _ => { s.led_op = LED_OP_IDLE; }
    }

    // --- Read LED channel input ---
    if s.led_gpio_ready && s.led_op == LED_OP_IDLE {
        let sys = &*s.syscalls;
        let poll = (sys.channel_poll)(s.led_chan, POLL_IN);
        if poll > 0 && (poll as u32 & POLL_IN) != 0 {
            let mut led_buf = [0u8; 8];
            let r = (sys.channel_read)(s.led_chan, led_buf.as_mut_ptr(), 8);
            if r > 0 {
                let len = r as usize;
                let mut handled = false;
                if len >= 6 {
                    let ty = u32::from_le_bytes([led_buf[0], led_buf[1], led_buf[2], led_buf[3]]);
                    match ty {
                        MSG_ON => {
                            s.led_brightness = 255; handled = true;
                        }
                        MSG_OFF => {
                            s.led_brightness = 0; handled = true;
                        }
                        MSG_TOGGLE => {
                            s.led_brightness = if s.led_brightness > 0 { 0 } else { 255 };
                            handled = true;
                        }
                        _ => {}
                    }
                }
                if !handled {
                    // Raw brightness byte: single byte or payload byte
                    s.led_brightness = if len >= 6 {
                        led_buf[4] | led_buf[5]
                    } else {
                        led_buf[0]
                    };
                }
            }
        }
    }

    // --- Software PWM cycle ---
    if s.led_gpio_ready && s.led_op == LED_OP_IDLE {
        let period = s.led_pwm_period;
        if period > 0 {
            s.led_pwm_counter = s.led_pwm_counter.wrapping_add(1);
            if s.led_pwm_counter >= period {
                s.led_pwm_counter = 0;
            }

            let duty_steps = ((s.led_brightness as u16 * period as u16) + 127) / 255;
            let target_on: bool = s.led_pwm_counter < duty_steps as u8;
            let current_on = s.led_state != 0;

            if target_on != current_on {
                s.led_op = LED_OP_SEND_WINDOW;
            }
        }
    }
}

unsafe fn step_running(s: &mut Cyw43State) -> i32 {
    s.out_stalled = false;

    step_rx(s);

    if s.wifi_active {
        step_wifi_ops(s);
        step_tx(s);
    }

    step_led(s);

    // Burst: if more F2/F3 packets available, re-step immediately.
    // But if the output channel is full, yield so downstream (ip) can drain.
    if !s.out_stalled
        && s.last_status & (STATUS_F2_PKT_AVAILABLE | STATUS_F3_PKT_AVAILABLE) != 0
    {
        return 2;
    }
    0
}

// ============================================================================
// F2/F3 Read Helpers
// ============================================================================

/// Try to start an F2 (WiFi) frame read. Returns true if read was started.
unsafe fn try_start_f2_read(s: &mut Cyw43State, status: u32) -> bool {
    let pkt_len = ((status >> STATUS_F2_PKT_LEN_SHIFT)
        & STATUS_F2_PKT_LEN_MASK) as usize;
    if pkt_len > 0 && pkt_len <= 1500 {
        let r = gspi::wlan_read_start(s, pkt_len);
        if r >= 0 {
            s.frame_len = pkt_len as u16;
            s.substep = 10; // F2 frame read in progress
            return true;
        }
    }
    false
}

/// Try to start an F3 (BT) frame read. Returns true if read was started.
unsafe fn try_start_f3_read(s: &mut Cyw43State, status: u32) -> bool {
    let pkt_len = ((status >> STATUS_F3_PKT_LEN_SHIFT)
        & STATUS_F3_PKT_LEN_MASK) as usize;
    if pkt_len > 0 && pkt_len <= 1500 {
        let r = gspi::bt_read_start(s, pkt_len);
        if r >= 0 {
            s.frame_len = pkt_len as u16;
            s.substep = 11; // F3 frame read in progress
            return true;
        }
    }
    false
}

// ============================================================================
// Scan Result Formatting
// ============================================================================

/// Format a scan result as a text line and write to scan_out_chan.
/// Output: "SSID_NAME                        ch:NN rssi:-NN\n"
unsafe fn format_scan_result(
    s: &mut Cyw43State,
    ssid_ptr: *const u8,
    ssid_len: usize,
    channel: u16,
    rssi: i16,
) {
    if s.scan_out_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;

    let mut line = [b' '; 64];
    let mut pos = 0usize;

    // Copy SSID
    let slen = ssid_len.min(32);
    let mut i = 0;
    while i < slen {
        let b = *ssid_ptr.add(i);
        if b == 0 {
            break;
        }
        line[pos] = b;
        pos += 1;
        i += 1;
    }

    // Pad to column 33
    while pos < 33 {
        pos += 1;
    }

    // "ch:"
    line[pos] = b'c';
    pos += 1;
    line[pos] = b'h';
    pos += 1;
    line[pos] = b':';
    pos += 1;

    // Channel (2 digits)
    let ch = channel.min(99);
    line[pos] = b'0' + ((ch / 10) % 10) as u8;
    pos += 1;
    line[pos] = b'0' + (ch % 10) as u8;
    pos += 1;
    line[pos] = b' ';
    pos += 1;

    // "rssi:"
    line[pos] = b'r';
    pos += 1;
    line[pos] = b's';
    pos += 1;
    line[pos] = b's';
    pos += 1;
    line[pos] = b'i';
    pos += 1;
    line[pos] = b':';
    pos += 1;

    // RSSI value (typically negative)
    if rssi < 0 {
        line[pos] = b'-';
        pos += 1;
    }
    let abs_rssi = if rssi < 0 { (-rssi) as u16 } else { rssi as u16 };
    if abs_rssi >= 100 {
        line[pos] = b'0' + ((abs_rssi / 100) % 10) as u8;
        pos += 1;
    }
    line[pos] = b'0' + ((abs_rssi / 10) % 10) as u8;
    pos += 1;
    line[pos] = b'0' + (abs_rssi % 10) as u8;
    pos += 1;

    line[pos] = b'\n';
    pos += 1;

    (sys.channel_write)(s.scan_out_chan, line.as_ptr(), pos);
}

/// Emit a structured binary scan result as FMP message on scan_bin_chan (out[2]).
///
/// Payload (36 bytes):
///   [0]     ssid_len: u8
///   [1..33] ssid: [u8; 32]  (zero-padded)
///   [33]    channel: u8
///   [34]    rssi: i8
///   [35]    security: u8
unsafe fn emit_scan_result_binary(
    s: &mut Cyw43State,
    ssid_ptr: *const u8,
    ssid_len: usize,
    channel: u16,
    rssi: i16,
    chanspec: u16,
) {
    if s.scan_bin_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;

    let poll = (sys.channel_poll)(s.scan_bin_chan, POLL_OUT);
    if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
        return;
    }

    let mut rec = [0u8; SCAN_RESULT_SIZE];
    let slen = ssid_len.min(32);
    rec[0] = slen as u8;

    // Copy SSID
    let mut i = 0;
    while i < slen {
        let b = *ssid_ptr.add(i);
        if b == 0 { break; }
        rec[1 + i] = b;
        i += 1;
    }

    rec[33] = (channel & 0xFF) as u8;
    rec[34] = rssi as i8 as u8;

    // Security: derive from chanspec privacy bit is unreliable;
    // mark as 0 (open) — the wifi module can refine this later
    rec[35] = 0;

    msg_write(sys, s.scan_bin_chan, MSG_SCAN_RESULT, rec.as_ptr(), SCAN_RESULT_SIZE as u16);
}

/// Emit an FMP status event on status_chan (out[3]).
unsafe fn emit_status_event(s: &mut Cyw43State, msg_type: u32, payload: &[u8]) {
    if s.status_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;

    let poll = (sys.channel_poll)(s.status_chan, POLL_OUT);
    if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
        return;
    }

    msg_write(sys, s.status_chan, msg_type, payload.as_ptr(), payload.len() as u16);
}

/// Emit an MSG_NETIF_STATE frame on netif_state_chan (out[5]).
/// Drops silently if the port is unwired or the ring is full; consumers
/// poll for the next transition.
unsafe fn emit_netif_state(s: &Cyw43State, state: u8) {
    if s.netif_state_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.netif_state_chan, POLL_OUT);
    if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
        return;
    }
    let payload = [state];
    msg_write(sys, s.netif_state_chan, MSG_NETIF_STATE, payload.as_ptr(), 1);
}


// ============================================================================
// Frame Processing
// ============================================================================

/// Process a received WLAN frame from the chip.
unsafe fn process_rx_frame(s: &mut Cyw43State) {
    let frame_len = s.frame_len as usize;

    // RX payload is in rxn_buf after response/pad words
    if frame_len < SDPCM_HEADER_LEN {
        return;
    }

    let payload = gspi::rxn_payload_ptr(s);

    // Parse SDPCM header
    let (channel, data_offset, data_len) = gspi::parse_sdpcm_header(
        payload,
        frame_len,
    );
    if channel < 0 {
        return;
    }
    let channel = channel as u8;

    match channel {
        SDPCM_CHAN_CONTROL => {
            // Ioctl response — count for synchronization barrier
            s.ioctl_recv_count = s.ioctl_recv_count.wrapping_add(1);
            // CDC header at data_offset: cmd(4) + len(4) + flags(2) + id(2) + status(4)
            if data_len >= CDC_HEADER_LEN {
                let cdc = payload.add(data_offset);
                let flags = (*cdc.add(8) as u16) | ((*cdc.add(9) as u16) << 8);

                // CDC id matching (Issue #13b): verify response matches request
                let resp_id = (*cdc.add(10) as u16) | ((*cdc.add(11) as u16) << 8);
                if resp_id == s.pending_ioctl_id {
                    // Matched: store status (0 = success, or error code)
                    if flags & 0x01 != 0 {
                        let st = (*cdc.add(12) as i16) | ((*cdc.add(13) as i16) << 8);
                        s.pending_ioctl_status = if st == 0 { -2 } else { st };
                    } else {
                        s.pending_ioctl_status = 0; // success
                    }
                }

                if flags & 0x01 != 0 {
                    // CDCF_IOC_ERROR — firmware rejected the ioctl
                    s.ioctl_error_seen = true;
                    let status = (*cdc.add(12) as u32) | ((*cdc.add(13) as u32) << 8)
                        | ((*cdc.add(14) as u32) << 16) | ((*cdc.add(15) as u32) << 24);
                    let cmd = (*cdc as u32) | ((*cdc.add(1) as u32) << 8)
                        | ((*cdc.add(2) as u32) << 16) | ((*cdc.add(3) as u32) << 24);
                    // Log: "ioctl err C=cmd S=status"
                    let sys = &*s.syscalls;
                    let mut buf = [0u8; 50];
                    let p = buf.as_mut_ptr();
                    let prefix = b"[cyw43] ioctl err cmd=";
                    let mut i = 0;
                    while i < prefix.len() { *p.add(i) = *prefix.as_ptr().add(i); i += 1; }
                    let mut pos = prefix.len();
                    pos += fmt_u32_raw(buf.as_mut_ptr().add(pos), cmd);
                    let mid = b" S=";
                    i = 0;
                    while i < mid.len() { *p.add(pos + i) = *mid.as_ptr().add(i); i += 1; }
                    pos += mid.len();
                    pos += fmt_u32_raw(buf.as_mut_ptr().add(pos), status);
                    dev_log(sys, 1, buf.as_ptr(), pos);
                }
            }
        }
        SDPCM_CHAN_EVENT => {
            // BDC header at SDPCM data_offset
            // Embassy uses data_offset directly (no version check):
            //   packet_start = 4 * bdc_header.data_offset
            let bdc_start = payload.add(data_offset);
            let bdc_data_off = *bdc_start.add(3) as usize;
            let bdc_total = BDC_HEADER_LEN + bdc_data_off * 4;

            // Verify this is a Broadcom event frame (ethertype 0x886C)
            // Some firmware delivers non-event frames on channel 1 (e.g. during SAE)
            if data_len >= bdc_total + EVT_ETH_HDR_LEN {
                let eth = payload.add(data_offset + bdc_total);
                let etype = ((*eth.add(12) as u16) << 8) | (*eth.add(13) as u16);
                if etype != 0x886C {
                    // Not a Broadcom event — skip
                    return;
                }
            }

            // Event structure: BDC(bdc_total) + ETH(14) + EventHdr(10) + EventMsg(48)
            let min_evt_len = bdc_total + EVT_ETH_HDR_LEN + EVT_MSG_PREAMBLE + EVT_MSG_MIN_LEN;
            if data_len >= min_evt_len {
                // Event message starts after BDC + ethernet header + BCMILCP preamble
                let evt = payload.add(data_offset + bdc_total + EVT_ETH_HDR_LEN);
                // EventMessage layout after preamble(10): version(u16) + flags(u16) + event_type(u32 BE) + status(u32 BE)
                let et = evt.add(EVT_MSG_PREAMBLE + 4); // skip version(2) + flags(2)
                let event_type = ((*et as u32) << 24)
                    | ((*et.add(1) as u32) << 16)
                    | ((*et.add(2) as u32) << 8)
                    | (*et.add(3) as u32);
                let st = evt.add(EVT_MSG_PREAMBLE + 8); // skip version(2) + flags(2) + event_type(4)
                let status = ((*st as u32) << 24)
                    | ((*st.add(1) as u32) << 16)
                    | ((*st.add(2) as u32) << 8)
                    | (*st.add(3) as u32);
                // Parse reason code (at offset +12 after preamble: version(2)+flags(2)+event_type(4)+status(4))
                let rp = evt.add(EVT_MSG_PREAMBLE + 12);
                let reason = ((*rp as u32) << 24)
                    | ((*rp.add(1) as u32) << 16)
                    | ((*rp.add(2) as u32) << 8)
                    | (*rp.add(3) as u32);

                // Parse IE88 (ASSOC_RESP_IE) for Timeout Interval IE (tag 0x38)
                // When AP sends Association Comeback (type 3), extract the backoff time.
                if event_type == 88 {
                    let dl = evt.add(EVT_MSG_PREAMBLE + 20);
                    let datalen = ((*dl as u32) << 24)
                        | ((*dl.add(1) as u32) << 16)
                        | ((*dl.add(2) as u32) << 8)
                        | (*dl.add(3) as u32);
                    let evt_data = evt.add(EVT_MSG_PREAMBLE + EVT_MSG_MIN_LEN);
                    let avail = if data_len > bdc_total + EVT_ETH_HDR_LEN + EVT_MSG_PREAMBLE + EVT_MSG_MIN_LEN {
                        data_len - bdc_total - EVT_ETH_HDR_LEN - EVT_MSG_PREAMBLE - EVT_MSG_MIN_LEN
                    } else { 0 };
                    let ie_len = (datalen as usize).min(avail);
                    // Walk IE TLVs: tag(1) + len(1) + data(len)
                    let mut off = 0usize;
                    while off + 2 <= ie_len {
                        let tag = *evt_data.add(off);
                        let tlen = *evt_data.add(off + 1) as usize;
                        if off + 2 + tlen > ie_len { break; }
                        // Timeout Interval IE: tag=0x38 (56), len=5, type(1)+value(4)
                        if tag == 0x38 && tlen == 5 {
                            let tie_type = *evt_data.add(off + 2);
                            // Only act on FIRST comeback (comeback_ms==0)
                            if tie_type == 3 && s.comeback_ms == 0 {
                                let v = (*evt_data.add(off + 3) as u32)
                                    | ((*evt_data.add(off + 4) as u32) << 8)
                                    | ((*evt_data.add(off + 5) as u32) << 16)
                                    | ((*evt_data.add(off + 6) as u32) << 24);
                                s.comeback_ms = v;
                                log_info(s, b"[cyw43] comeback abort");
                                // Immediately abort: arm WaitComeback to send DISASSOC + backoff
                                if s.wifi_state == Cyw43WifiState::Connecting
                                    && s.pending_wifi_op == wifi_ops::WifiOp::None
                                {
                                    s.assoc_retries += 1;
                                    s.wifi_state = Cyw43WifiState::Retrying;
                                    s.pending_wifi_op = wifi_ops::WifiOp::Connect;
                                    s.wifi_substep = wifi_ops::ConnectStep::WaitComeback as u8;
                                    s.delay_start = 0;
                                }
                            }
                        }
                        off += 2 + tlen;
                    }
                }

                match event_type {
                    WLC_E_SET_SSID => {
                        if status != WLC_E_STATUS_SUCCESS
                            && (s.wifi_state == Cyw43WifiState::Connecting || s.wifi_state == Cyw43WifiState::Retrying)
                            && s.assoc_retries < 3
                        {
                            s.assoc_retries += 1;
                            s.wifi_state = Cyw43WifiState::Retrying;
                            s.pending_wifi_op = wifi_ops::WifiOp::Connect;
                            if s.comeback_ms > 0 {
                                // AP sent comeback timer — backoff then retry
                                s.wifi_substep = wifi_ops::ConnectStep::WaitComeback as u8;
                                log_info(s, b"[cyw43] comeback wait");
                            } else {
                                s.wifi_substep = 0;
                                log_info(s, b"[cyw43] join retry");
                            }
                        }
                    }
                    WLC_E_LINK => {
                        if status == WLC_E_STATUS_SUCCESS {
                            s.wifi_state = Cyw43WifiState::Connected;
                            s.assoc_retries = 0;
                            let sys = &*s.syscalls;
                            emit_netif_state(s, NETIF_STATE_NO_ADDRESS);
                            log_info(s, b"[cyw43] link up");

                            // Send MAC to IP module via out_chan as a special frame:
                            // 14-byte Ethernet header with EtherType=0x0000 (MAC announcement)
                            // dst=our MAC, src=our MAC, type=0x0000
                            if s.out_chan >= 0 && s.mac_addr[0] != 0 {
                                let mut mac_frame = [0u8; 14];
                                let mut m = 0;
                                while m < 6 {
                                    mac_frame[m] = s.mac_addr[m];     // dst = our MAC
                                    mac_frame[6 + m] = s.mac_addr[m]; // src = our MAC
                                    m += 1;
                                }
                                // EtherType 0x0000 = MAC announcement (not a real EtherType)
                                mac_frame[12] = 0;
                                mac_frame[13] = 0;
                                let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
                                if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
                                    (sys.channel_write)(
                                        s.out_chan,
                                        mac_frame.as_ptr(),
                                        14,
                                    );
                                }
                            }

                            emit_status_event(s, MSG_CONNECTED, &[]);
                        }
                    }
                    WLC_E_DEAUTH | WLC_E_DEAUTH_IND
                    | WLC_E_DISASSOC | WLC_E_DISASSOC_IND => {
                        if s.wifi_state == Cyw43WifiState::Retrying {
                            // Stale deauth from previous attempt — ignore
                        } else if s.wifi_state == Cyw43WifiState::Connecting && s.assoc_retries < 3 {
                            s.assoc_retries += 1;
                            s.wifi_state = Cyw43WifiState::Retrying;
                            s.pending_wifi_op = wifi_ops::WifiOp::Connect;
                            if s.comeback_ms > 0 {
                                s.wifi_substep = wifi_ops::ConnectStep::WaitComeback as u8;
                                log_info(s, b"[cyw43] comeback wait");
                            } else {
                                s.wifi_substep = 0;
                                log_info(s, b"[cyw43] join retry");
                            }
                        } else {
                            emit_netif_state(s, NETIF_STATE_DOWN);
                            s.wifi_state = Cyw43WifiState::Ready;
                            log_error(s, b"[cyw43] link lost");
                            emit_status_event(s, MSG_DISCONNECTED, &[1]); // reason=1 (deauth)
                        }
                    }
                    WLC_E_ESCAN_RESULT => {
                        if s.scan_active {
                            if status == WLC_E_STATUS_PARTIAL {
                                // Parse BSS info from escan result
                                // Event msg fixed fields: preamble(10) + event_type(4) + flags(2) + status(4) + reason(4) + addr(6) + datalen(4) = 34
                                let evt_data_start = data_offset + bdc_total + EVT_ETH_HDR_LEN + EVT_MSG_PREAMBLE + EVT_MSG_MIN_LEN;
                                let remaining = if frame_len > evt_data_start { frame_len - evt_data_start } else { 0 };

                                if remaining >= ESCAN_RESULT_HDR_LEN + BSS_RSSI_OFF + 2 {
                                    let erp = payload.add(evt_data_start);
                                    let bss_count = (*erp.add(8) as u16) | ((*erp.add(9) as u16) << 8);

                                    if bss_count > 0 {
                                        let bss = erp.add(ESCAN_RESULT_HDR_LEN);
                                        let ssid_len = (*bss.add(BSS_SSID_LEN_OFF) as usize).min(32);

                                        let rssi = (*bss.add(BSS_RSSI_OFF) as i16)
                                            | ((*bss.add(BSS_RSSI_OFF + 1) as i16) << 8);

                                        let chanspec = (*bss.add(BSS_CHANSPEC_OFF) as u16)
                                            | ((*bss.add(BSS_CHANSPEC_OFF + 1) as u16) << 8);
                                        let channel = chanspec & 0xFF;

                                        format_scan_result(s, bss.add(BSS_SSID_OFF), ssid_len, channel, rssi);
                                        emit_scan_result_binary(s, bss.add(BSS_SSID_OFF), ssid_len, channel, rssi, chanspec);
                                        s.scan_count += 1;
                                    }
                                }
                            } else {
                                // status == 0 or other: scan complete
                                s.scan_active = false;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        SDPCM_CHAN_DATA => {
            // Data frame — strip BDC header (+ padding) and forward to out_chan
            let bdc_start = payload.add(data_offset);
            let bdc_data_off = *bdc_start.add(3) as usize;
            let bdc_total = BDC_HEADER_LEN + bdc_data_off * 4;
            if data_len > bdc_total {
                let eth_start = data_offset + bdc_total;
                let eth_len = data_len - bdc_total;

                // Check EtherType (bytes 12-13 of ethernet header, big-endian)
                // EAPOL = 0x888E
                if eth_len >= 14 {
                    let eth = payload.add(eth_start);
                    let etype = ((*eth.add(12) as u16) << 8) | (*eth.add(13) as u16);
                    if etype == 0x888E {
                        let sys = &*s.syscalls;
                        let mut buf = [0u8; 36];
                        let p = buf.as_mut_ptr();
                        let prefix = b"[cyw43] eapol rx len=";
                        let mut i = 0;
                        while i < prefix.len() { *p.add(i) = *prefix.as_ptr().add(i); i += 1; }
                        let pos = prefix.len() + fmt_u32_raw(buf.as_mut_ptr().add(prefix.len()), eth_len as u32);
                        dev_log(sys, 1, buf.as_ptr(), pos);
                    }
                }

                if s.out_chan >= 0 {
                    let sys = &*s.syscalls;
                    let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
                    if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
                            (sys.channel_write)(
                            s.out_chan,
                            payload.add(eth_start),
                            eth_len,
                        );
                    } else {
                        // Channel full — stop bursting so downstream can drain
                        s.out_stalled = true;
                    }
                }
            }
        }
        _ => {}
    }
}

/// Process an FMP WiFi command from the ctrl channel.
///
/// # Safety
/// `payload` must point to at least `len` valid bytes.
unsafe fn process_wifi_command(s: &mut Cyw43State, msg_type: u32, payload: *const u8, len: usize) {
    match msg_type {
        // Connect: payload = [ssid_len, pass_len, security, ssid..., password...]
        MSG_CONNECT => {
            if len < 3 {
                return;
            }
            let ssid_len = (*payload as usize).min(MAX_SSID_LEN);
            let pass_len = (*payload.add(1) as usize).min(MAX_PASS_LEN);
            s.security = *payload.add(2);

            if len < 3 + ssid_len + pass_len {
                return;
            }

            s.ssid_len = ssid_len as u8;
            let mut i = 0;
            while i < ssid_len {
                s.ssid[i] = *payload.add(3 + i);
                i += 1;
            }

            s.pass_len = pass_len as u8;
            i = 0;
            while i < pass_len {
                s.password[i] = *payload.add(3 + ssid_len + i);
                i += 1;
            }

            s.pending_wifi_op = wifi_ops::WifiOp::Connect;
            s.wifi_substep = 0;
            s.assoc_retries = 0;
        }
        // Disconnect (no payload)
        MSG_DISCONNECT => {
            s.pending_wifi_op = wifi_ops::WifiOp::Disconnect;
            s.wifi_substep = 0;
        }
        // Scan (no payload)
        MSG_SCAN => {
            s.pending_wifi_op = wifi_ops::WifiOp::Scan;
            s.wifi_substep = 0;
            s.scan_active = false;
            s.scan_count = 0;
        }
        _ => {}
    }
}

// ============================================================================
// Panic Handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");

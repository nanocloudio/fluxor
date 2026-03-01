//! CYW43 chip constants — registers, gSPI protocol, SDPCM framing.
//!
//! References:
//!   - CYW43439 datasheet (Infineon)
//!   - gSPI Application Note (AN214654)
//!   - cyw43 crate (embassy-rs) for register map


// ============================================================================
// gSPI Command Word
// ============================================================================

/// gSPI command word bit positions
pub const GSPI_CMD_WRITE: u32 = 1 << 31;
pub const GSPI_CMD_INCR: u32 = 1 << 30;
/// Function field shift (bits 29:28)
pub const GSPI_CMD_FUNC_SHIFT: u32 = 28;
/// Address field shift (bits 27:11)
pub const GSPI_CMD_ADDR_SHIFT: u32 = 11;
/// Size field (bits 10:0)
pub const GSPI_CMD_SIZE_MASK: u32 = 0x7FF;

/// gSPI functions
pub const FUNC_BUS: u32 = 0;
pub const FUNC_BACKPLANE: u32 = 1;
pub const FUNC_WLAN: u32 = 2;
pub const FUNC_BT: u32 = 3;

// ============================================================================
// gSPI Bus Registers (Function 0)
// ============================================================================

/// SPI Bus Control — setup/data delay, word length, etc.
pub const REG_BUS_CTRL: u32 = 0x0000;
/// SPI Response delay (read turnaround cycles)
pub const REG_BUS_RESPONSE_DELAY: u32 = 0x0001;
/// SPI Status Enable
pub const REG_BUS_STATUS_ENABLE: u32 = 0x0002;
/// SPI Reset
pub const REG_BUS_RESET: u32 = 0x0003;
/// SPI Interrupt Register
pub const REG_BUS_INTERRUPT: u32 = 0x0004;
/// SPI Interrupt Enable
pub const REG_BUS_INTERRUPT_ENABLE: u32 = 0x0006;
/// SPI Status Register
pub const REG_BUS_STATUS: u32 = 0x0008;
/// SPI Test Read
pub const REG_BUS_TEST_RO: u32 = 0x0014;
/// SPI Test Read/Write
pub const REG_BUS_TEST_RW: u32 = 0x0018;
/// SPI Response Delay Extra
pub const REG_BUS_RESP_DELAY_F1: u32 = 0x001C;
/// SPI Response Delay Extra (F2)
pub const REG_BUS_RESP_DELAY_F2: u32 = 0x001D;

/// Test register expected value (for verifying gSPI communication)
pub const TEST_PATTERN: u32 = 0xFEEDBEAD;

/// Bus control register bits
pub const BUS_CTRL_WORD_LENGTH_32: u32 = 0x01;
pub const BUS_CTRL_BIG_ENDIAN: u32 = 0x02;
pub const BUS_CTRL_STATUS_ENABLE: u32 = 0x04;
pub const BUS_CTRL_INTR_WITH_STATUS: u32 = 0x08;
pub const BUS_CTRL_HIGH_SPEED: u32 = 0x10;
pub const BUS_CTRL_INT_POLARITY_HIGH: u32 = 0x20;
pub const BUS_CTRL_WAKE_UP: u32 = 0x80;

/// Combined bus config for init (written as 32-bit to addr 0 in 16-bit swapped mode).
/// byte0 = CTRL (0xB1: 32bit + HS + int_polarity_high + wake)
/// byte1 = RESPONSE_DELAY (0x04)
/// byte2 = STATUS_ENABLE (0x03 = status_enable + intr_with_status) — matches Embassy exactly
/// byte3 = 0x00
pub const BUS_CONFIG_INIT: u32 = 0x000304B1;

/// Interrupt register bits
pub const IRQ_DATA_UNAVAILABLE: u32 = 0x0001;
pub const IRQ_F2_F3_FIFO_RD_UNDERFLOW: u32 = 0x0002;
pub const IRQ_F2_F3_FIFO_WR_OVERFLOW: u32 = 0x0004;
pub const IRQ_COMMAND_ERROR: u32 = 0x0008;
pub const IRQ_DATA_ERROR: u32 = 0x0010;
pub const IRQ_F2_PACKET_AVAILABLE: u32 = 0x0020;
pub const IRQ_F1_OVERFLOW: u32 = 0x0080;
pub const IRQ_F1_INTR: u32 = 0x2000;

/// Status register bits
pub const STATUS_DATA_NOT_AVAILABLE: u32 = 0x00000001;
pub const STATUS_UNDERFLOW: u32 = 0x00000002;
pub const STATUS_OVERFLOW: u32 = 0x00000004;
pub const STATUS_F2_INTR: u32 = 0x00000008;
pub const STATUS_F3_INTR: u32 = 0x00000010;
pub const STATUS_F2_RX_READY: u32 = 0x00000020;
pub const STATUS_F3_RX_READY: u32 = 0x00000040;
pub const STATUS_HOST_CMD_DATA_ERR: u32 = 0x00000080;
pub const STATUS_F2_PKT_AVAILABLE: u32 = 0x00000100;
pub const STATUS_F2_PKT_LEN_SHIFT: u32 = 9;
pub const STATUS_F2_PKT_LEN_MASK: u32 = 0x7FF;

/// F3 (BT) packet status — mirrors F2 layout in upper half of status register
pub const STATUS_F3_PKT_AVAILABLE: u32 = 0x00100000; // bit 20
pub const STATUS_F3_PKT_LEN_SHIFT: u32 = 21;         // bits [31:21]
pub const STATUS_F3_PKT_LEN_MASK: u32 = 0x7FF;

// ============================================================================
// Backplane Registers (Function 1)
// ============================================================================

/// Backplane window address register
pub const REG_BP_WIN: u32 = 0x1000A;
/// Backplane window mask (windows are 32KB aligned)
pub const BP_WIN_MASK: u32 = 0x7FFF;
pub const BP_WIN_SIZE: u32 = 0x8000;
/// Flag OR'd into backplane address for 32-bit reads (Embassy: BACKPLANE_32BIT_FLAG)
pub const BP_32BIT_FLAG: u32 = 0x8000;

/// ALP (Active Low Power) clock enable
pub const REG_BP_CHIP_CLOCK_CSR: u32 = 0x1000E;
/// Pullup enable
pub const REG_BP_PULLUP: u32 = 0x1000F;
/// SDIO Wakeup control
pub const REG_BP_WAKEUP_CTRL: u32 = 0x1001E;
/// Sleep CSR
pub const REG_BP_SLEEP_CSR: u32 = 0x1001F;

/// Chip Clock CSR bits
pub const BP_CLK_ALP_REQUEST: u32 = 0x08;
pub const BP_CLK_ALP_AVAILABLE: u32 = 0x40;
pub const BP_CLK_HT_REQUEST: u32 = 0x10;
pub const BP_CLK_HT_AVAILABLE: u32 = 0x80;
pub const BP_CLK_FORCE_ALP: u32 = 0x01;
pub const BP_CLK_FORCE_HT: u32 = 0x02;
pub const BP_CLK_FORCE_ILP: u32 = 0x04;

/// Chip core base addresses (backplane, NOT wrapper)
pub const CHIPCOMMON_BASE: u32 = 0x18000000;
pub const SOCSRAM_BASE: u32 = 0x18004000;
pub const ARMCM3_BASE: u32 = 0x18003000;

/// Chip common registers (relative to CHIPCOMMON_BASE)
pub const CC_CHIPID: u32 = 0x000;
pub const CC_CAPABILITIES: u32 = 0x004;

/// CYW43 GPIO registers (CHIPCOMMON_BASE + offset)
pub const CHIPCOMMON_GPIO_CONTROL: u32 = CHIPCOMMON_BASE + 0x6C;
pub const CHIPCOMMON_GPIO_OUTPUT: u32 = CHIPCOMMON_BASE + 0x64;
pub const CHIPCOMMON_GPIO_OUTPUT_EN: u32 = CHIPCOMMON_BASE + 0x68;
pub const CC_WATCHDOG: u32 = 0x080;

/// SOCSRAM registers (relative to SOCSRAM_BASE)
pub const SOCSRAM_BANKX_INDEX: u32 = 0x10;
pub const SOCSRAM_BANKX_PDA: u32 = 0x44;

/// CYW43439 chip ID
pub const CYW43439_CHIP_ID: u32 = 43439;

/// Chip RAM size (CYW43439 = 512KB)
pub const CHIP_RAM_SIZE: u32 = 512 * 1024; // 0x80000

// ============================================================================
// AI (Address Interconnect) Wrapper Registers
// ============================================================================

/// Offset from core base to wrapper registers
pub const WRAPPER_REGISTER_OFFSET: u32 = 0x100000;

/// AI register offsets (from wrapper base)
pub const AI_IOCTRL_OFFSET: u32 = 0x408;
pub const AI_RESETCTRL_OFFSET: u32 = 0x800;

/// AI IOCTRL register bits
pub const AI_IOCTRL_BIT_CLOCK_EN: u8 = 0x01;
pub const AI_IOCTRL_BIT_FGC: u8 = 0x02;      // Force Gated Clocks

/// AI RESETCTRL register bits
pub const AI_RESETCTRL_BIT_RESET: u8 = 0x01;

/// Wrapper base addresses (core base + WRAPPER_REGISTER_OFFSET)
/// These are what Embassy uses for core_disable / core_reset operations.
pub const WLAN_WRAPPER_BASE: u32 = ARMCM3_BASE + WRAPPER_REGISTER_OFFSET; // 0x18103000
pub const SOCSRAM_WRAPPER_BASE: u32 = SOCSRAM_BASE + WRAPPER_REGISTER_OFFSET; // 0x18104000

// ============================================================================
// SDPCM (Software Data Path Control Message) Header
// ============================================================================

/// SDPCM header size
pub const SDPCM_HEADER_LEN: usize = 12;

/// SDPCM channel IDs
pub const SDPCM_CHAN_CONTROL: u8 = 0;
pub const SDPCM_CHAN_EVENT: u8 = 1;
pub const SDPCM_CHAN_DATA: u8 = 2;
pub const SDPCM_CHAN_HCI: u8 = 3; // BT HCI over SDPCM

/// CDC (Common Driver Core) header size
pub const CDC_HEADER_LEN: usize = 16;

/// BDC (Broadcast Data Channel) header size
pub const BDC_HEADER_LEN: usize = 4;

/// IOCTL commands
pub const WLC_SET_SSID: u32 = 26;
pub const WLC_SET_CHANNEL: u32 = 30;
pub const WLC_DISASSOC: u32 = 52;
pub const WLC_SET_ANTDIV: u32 = 64;
pub const WLC_UP: u32 = 2;
pub const WLC_DOWN: u32 = 3;
pub const WLC_SET_INFRA: u32 = 20;
pub const WLC_SET_AUTH: u32 = 22;
pub const WLC_SET_WSEC: u32 = 134;
pub const WLC_SET_WPA_AUTH: u32 = 165;
pub const WLC_SET_WSEC_PMK: u32 = 268;
pub const WLC_SET_PASSIVE_SCAN: u32 = 49;
pub const WLC_SCAN: u32 = 50;
pub const WLC_SCAN_RESULTS: u32 = 51;
pub const WLC_SET_PM: u32 = 86;
pub const WLC_SET_GMODE: u32 = 110;
pub const WLC_SET_PROBRESP_TIMEOUT: u32 = 272;
pub const WLC_SET_COUNTRY: u32 = 84;
pub const WLC_SET_VAR: u32 = 263;
pub const WLC_GET_VAR: u32 = 262;

/// Security modes
pub const WSEC_NONE: u32 = 0;
pub const WSEC_WEP: u32 = 1;
pub const WSEC_TKIP: u32 = 2;
pub const WSEC_AES: u32 = 4;

/// WPA auth modes
pub const WPA_AUTH_DISABLED: u32 = 0x0000;
pub const WPA_AUTH_PSK: u32 = 0x0004;
pub const WPA2_AUTH_PSK: u32 = 0x0080;
pub const WPA3_AUTH_SAE: u32 = 0x40000;

/// 802.11 authentication algorithm numbers (for WLC_SET_AUTH)
pub const AUTH_OPEN: u32 = 0;
pub const AUTH_SAE: u32 = 3;

/// Management Frame Protection (MFP / PMF)
pub const MFP_NONE: u32 = 0;
pub const MFP_CAPABLE: u32 = 1;
pub const MFP_REQUIRED: u32 = 2;

/// Security mode byte (wifi→cyw43 command protocol)
pub const SECURITY_WPA2: u8 = 0;
pub const SECURITY_WPA3: u8 = 1;
pub const SECURITY_OPEN: u8 = 2;

/// Infrastructure mode
pub const INFRA_STA: u32 = 1;

// ============================================================================
// IOVAR (IO Variable) Names
// ============================================================================

/// Well-known iovar names
pub const IOVAR_COUNTRY: &[u8] = b"country\0";
pub const IOVAR_MFP: &[u8] = b"mfp\0";
pub const IOVAR_WPA_AUTH: &[u8] = b"wpa_auth\0";
pub const IOVAR_SAE_PASSWORD: &[u8] = b"sae_password\0";
pub const IOVAR_BSSCFG_SUP_WPA: &[u8] = b"bsscfg:sup_wpa\0";
pub const IOVAR_BSSCFG_SUP_WPA2_EAPVER: &[u8] = b"bsscfg:sup_wpa2_eapver\0";
pub const IOVAR_BSSCFG_SUP_WPA_TMO: &[u8] = b"bsscfg:sup_wpa_tmo\0";
pub const IOVAR_EVT_MASK: &[u8] = b"bsscfg:event_msgs\0";
pub const IOVAR_BSS: &[u8] = b"bss\0";
pub const IOVAR_PM2_SLEEP_RET: &[u8] = b"pm2_sleep_ret\0";
pub const IOVAR_BCNLI_DTM: &[u8] = b"bcn_li_dtim\0";
pub const IOVAR_ASSOC_RETRY_MAX: &[u8] = b"assoc_retry_max\0";
pub const IOVAR_ESCAN: &[u8] = b"escan\0";
pub const IOVAR_AMPDU_BA_WSIZE: &[u8] = b"ampdu_ba_wsize\0";
pub const IOVAR_AMPDU_MPDU: &[u8] = b"ampdu_mpdu\0";
pub const IOVAR_BUS_TXGLOM: &[u8] = b"bus:txglom\0";
pub const IOVAR_ARP_OL: &[u8] = b"arp_ol\0";
pub const IOVAR_ARP_VERSION: &[u8] = b"arp_version\0";
pub const IOVAR_ALLMULTI: &[u8] = b"allmulti\0";

// ============================================================================
// WiFi Scan Constants
// ============================================================================

pub const WL_SCAN_ACTION_START: u16 = 1;
pub const DOT11_BSSTYPE_ANY: u8 = 2;

// ============================================================================
// Structured Scan Result (out[2] binary format, FMP-wrapped)
// ============================================================================

/// Binary scan result payload size (fixed 36 bytes per AP)
pub const SCAN_RESULT_SIZE: usize = 36;

// Offsets within a SCAN_RESULT_SIZE payload:
//   [0]     ssid_len: u8
//   [1..33] ssid: [u8; 32]
//   [33]    channel: u8
//   [34]    rssi: i8 (signed)
//   [35]    security: u8 (0=open, 1=WEP, 2=WPA, 3=WPA2)

/// ESCAN result offsets (from start of event data payload)
/// wl_escan_result_t: buflen(4) + version(4) + sync_id(2) + bss_count(2) = 12
pub const ESCAN_RESULT_HDR_LEN: usize = 12;

/// wl_bss_info_t field offsets (from start of bss_info, after escan header)
/// Layout matches Embassy BssInfo (#[repr(C, packed(2))]):
///   version(u32)=0, length(u32)=4, bssid([u8;6])=8, beacon_period(u16)=14,
///   capability(u16)=16, ssid_len(u8)=18, ssid([u8;32])=19, reserved1(1)=51,
///   rateset_count(u32)=52, rates([u8;16])=56, chanspec(u16)=72,
///   atim_window(u16)=74, dtim_period(u8)=76, reserved2(1)=77, rssi(i16)=78
pub const BSS_SSID_LEN_OFF: usize = 18;   // u8
pub const BSS_SSID_OFF: usize = 19;       // [u8; 32]
pub const BSS_CHANSPEC_OFF: usize = 72;   // u16 LE (channel = lower byte)
pub const BSS_RSSI_OFF: usize = 78;       // i16 LE

// ============================================================================
// Firmware Constants
// ============================================================================

/// Firmware upload chunk size (backplane FIFO limit = 64 bytes).
/// The CYW43439 backplane interface has a 64-byte FIFO — larger writes corrupt data.
/// Throughput is achieved by busy-polling PIO transfers in step_load_fw/step_load_nvram
/// rather than yielding to the scheduler between each chunk.
pub const FW_CHUNK_SIZE: usize = 64;

/// Firmware chip RAM address start
pub const ATCM_RAM_BASE: u32 = 0;

/// CLM blob download
pub const CLM_CHUNK_SIZE: usize = 256;
pub const CLM_CHUNK_LEN_MAX: usize = 1400;

// ============================================================================
// PIO gSPI Program
// ============================================================================

/// PIO program for CYW43 gSPI half-duplex communication.
///
/// Bit-level TX then bit-level RX, matching Embassy's cyw43-pio low-speed
/// program exactly. The host controls each transfer via forced instructions:
///   - set_x(write_bits): total TX bits - 1
///   - set_y(read_bits): total RX bits - 1
///   - set_pindir(1): DIO as output
///   - exec_jmp(wrap_target): start program
///
/// The PIO program does NOT manage word counts or idle polling — that's all
/// handled by the kernel's process_transfer via forced instructions + DMA.
///
/// TX: out 1 bit at a time, CLK low then high (MSB first via shift-left).
/// Turnaround: set DIO to input, 1 cycle delay.
/// RX: sample 1 bit at a time, CLK high then low (MSB first via shift-left).
/// After RX: wait for CYW43 event pin, then signal host via PIO IRQ 0.
///
/// Autopull=true, autopush=true, shift-left (MSB first), threshold 32.
///
/// Sideset: 1 bit on CLK pin (active high).
/// DIO pin: out_base, in_base, set_base (for pindirs).
pub const GSPI_PIO_PROGRAM: [u16; 8] = [
    // .wrap_target
    //  0: out pins, 1    side 0       ; shift out 1 TX bit, CLK low
    0x6001,
    //  1: jmp x-- 0      side 1       ; CLK high, loop X+1 times
    0x1040,
    //  2: set pindirs, 0 side 0       ; turnaround — DIO input
    0xE080,
    //  3: nop            side 0       ; turnaround delay
    0xA042,
    //  4: in pins, 1     side 1       ; sample 1 RX bit, CLK high
    0x5001,
    //  5: jmp y-- 4      side 0       ; CLK low, loop Y+1 times
    0x0084,
    //  6: wait 1 pin 0   side 0       ; wait for CYW43 event on DIO
    0x2080,
    //  7: irq 0          side 0       ; signal host
    0xC000,
    // .wrap
];

pub const GSPI_PIO_WRAP_TARGET: u8 = 0;
pub const GSPI_PIO_WRAP: u8 = 7;
pub const GSPI_PIO_SIDESET_BITS: u8 = 1;
pub const GSPI_PIO_SIDESET_OPTIONAL: bool = false;
pub const GSPI_PIO_SIDESET_PINDIRS: bool = false;

// ============================================================================
// Module State Machine Phases
// ============================================================================

/// CYW43 driver initialization and runtime phases.
///
/// Ref: CYW43439 datasheet + gSPI Application Note (AN214654).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum Cyw43Phase {
    Init = 0,
    PowerOn = 1,
    GspiInit = 2,
    ChipPrep = 3,
    LoadFw = 4,
    LoadNvram = 5,
    WaitReady = 6,
    LoadClm = 7,
    InitWifi = 8,
    RegisterNetif = 9,
    Running = 10,
    Error = 255,
}

/// WiFi connection sub-states (within Running phase).
///
/// Idle → Ready → Connecting → Connected
///                    ↓↑
///                  Retrying (SAE/WPA3 comeback)
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum Cyw43WifiState {
    Idle = 0,
    Ready = 1,
    Connecting = 2,
    Connected = 3,
    Retrying = 4,
}

/// Startup delay after power-on (ms)
/// CYW43439 datasheet: 150-250ms after WL_REG_ON before gSPI is ready.
pub const POWER_ON_DELAY_MS: u64 = 150;
/// Delay after gSPI init (ms)
pub const GSPI_INIT_DELAY_MS: u64 = 5;
/// Timeout waiting for ALP clock (ms)
pub const ALP_TIMEOUT_MS: u64 = 500;
/// Timeout waiting for HT clock (ms)
pub const HT_TIMEOUT_MS: u64 = 1000;
/// Timeout waiting for firmware ready (ms)
pub const FW_READY_TIMEOUT_MS: u64 = 2000;

// ============================================================================
// CYW43 Firmware Event Types (from SDPCM_CHAN_EVENT frames)
// ============================================================================

pub const WLC_E_SET_SSID: u32 = 0;
pub const WLC_E_AUTH: u32 = 3;
pub const WLC_E_DEAUTH: u32 = 5;
pub const WLC_E_DEAUTH_IND: u32 = 6;
pub const WLC_E_DISASSOC: u32 = 11;
pub const WLC_E_DISASSOC_IND: u32 = 12;
pub const WLC_E_LINK: u32 = 16;

pub const WLC_E_STATUS_SUCCESS: u32 = 0;
pub const WLC_E_STATUS_PARTIAL: u32 = 8;
pub const WLC_E_ESCAN_RESULT: u32 = 69;

/// Event message offsets within event payload (after BDC header + ETH header).
/// ETH header is 14 bytes (dst_mac[6] + src_mac[6] + ethertype[2]).
/// Event structure: subtype(2 BE) + length(2 BE) + version(1) + oui(3) + usr_subtype(2 BE)
///                  + event_type(4 BE) + flags(2 BE) + status(4 BE) + reason(4 BE)
pub const EVT_ETH_HDR_LEN: usize = 14;
pub const EVT_MSG_PREAMBLE: usize = 10; // bytes before event_type field
pub const EVT_MSG_MIN_LEN: usize = 48;  // full EventMessage struct

// ============================================================================
// Netif Constants
// ============================================================================

/// Max SSID / password lengths
pub const MAX_SSID_LEN: usize = 32;
pub const MAX_PASS_LEN: usize = 64;

// POLL_IN, POLL_OUT, POLL_HUP are defined in pic_runtime.rs (included by mod.rs)

/// gSPI response delay in bytes (written to SPI_RESPONSE_DELAY register).
/// pico-sdk uses 4 for high-speed mode. With 0, the chip's behavior is undefined
/// in high-speed mode and captured data is garbage (response-delay period noise).
/// The PIO program has no delay loop — this register tells the chip how many
/// padding bytes to insert before valid data, which we skip via GSPI_SKIP_WORDS_BUS.
pub const GSPI_RESPONSE_DELAY: u32 = 4;

/// Response skip words for RX parsing.
/// After RESPONSE_DELAY=4 is configured, F0 (bus) reads have 1 padding word.
/// Backplane (F1) has 1 padding word (from REG_BUS_RESP_DELAY_F1).
/// WLAN (F2) has no padding word.
pub const GSPI_SKIP_WORDS_BUS: usize = 1;
pub const GSPI_SKIP_WORDS_WLAN: usize = 0;

/// Extra status word appended after payload (always 1, matching Embassy).
pub const GSPI_STATUS_WORDS: usize = 1;

/// Maximum frame size
pub const MAX_FRAME_SIZE: usize = 1536;

/// Clock divider for 25MHz gSPI (system clock 150MHz / 3 = 50MHz PIO, 2 PIO cycles/bit)
/// 8.8 fixed-point format: 3.0 = 0x0300
/// Matches Embassy's RM2_CLOCK_DIVIDER.
/// PIO infrastructure shifts left 8 to build register value.
pub const DEFAULT_CLOCK_DIV: u32 = 0x0300;

// ============================================================================
// NVRAM Data (board configuration for CYW43439)
// ============================================================================

/// NVRAM key=value pairs for the CYW43439 firmware.
/// Null-separated entries, double-null terminated.
/// Matches Embassy's cyw43/src/nvram.rs exactly.
pub static NVRAM: &[u8] = b"\
NVRAMRev=$Rev$\x00\
manfid=0x2d0\x00\
prodid=0x0727\x00\
vendid=0x14e4\x00\
devid=0x43e2\x00\
boardtype=0x0887\x00\
boardrev=0x1100\x00\
boardnum=22\x00\
macaddr=00:A0:50:b5:59:5e\x00\
sromrev=11\x00\
boardflags=0x00404001\x00\
boardflags3=0x04000000\x00\
xtalfreq=37400\x00\
nocrc=1\x00\
ag0=255\x00\
aa2g=1\x00\
ccode=ALL\x00\
pa0itssit=0x20\x00\
extpagain2g=0\x00\
pa2ga0=-168,6649,-778\x00\
AvVmid_c0=0x0,0xc8\x00\
cckpwroffset0=5\x00\
maxp2ga0=84\x00\
txpwrbckof=6\x00\
cckbw202gpo=0\x00\
legofdmbw202gpo=0x66111111\x00\
mcsbw202gpo=0x77711111\x00\
propbw202gpo=0xdd\x00\
ofdmdigfilttype=18\x00\
ofdmdigfilttypebe=18\x00\
papdmode=1\x00\
papdvalidtest=1\x00\
pacalidx2g=45\x00\
papdepsoffset=-30\x00\
papdendidx=58\x00\
ltecxmux=0\x00\
ltecxpadnum=0x0102\x00\
ltecxfnsel=0x44\x00\
ltecxgcigpio=0x01\x00\
il0macaddr=00:90:4c:c5:12:38\x00\
wl0id=0x431b\x00\
deadman_to=0xffffffff\x00\
muxenab=0x100\x00\
spurconfig=0x3\x00\
glitch_based_crsmin=1\x00\
btc_mode=1\x00\
\x00";

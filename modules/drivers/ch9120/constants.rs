//! CH9120 UART-to-Ethernet driver constants.
//!
//! Ref: CH9120 datasheet (WCH/Nanjing Qinheng)

// ============================================================================
// CH9120 Serial Command Protocol
// ============================================================================

/// All configuration commands start with this 2-byte prefix.
pub const CMD_PREFIX: [u8; 2] = [0x57, 0xAB];

// Configuration command codes (sent after CMD_PREFIX)
pub const CMD_GET_VERSION: u8 = 0x01;
pub const CMD_RESET: u8 = 0x02;
pub const CMD_SET_MODE: u8 = 0x10;       // arg: 1 byte (0-3)
pub const CMD_SET_LOCAL_IP: u8 = 0x11;    // arg: 4 bytes
pub const CMD_SET_SUBNET: u8 = 0x12;      // arg: 4 bytes
pub const CMD_SET_GATEWAY: u8 = 0x13;     // arg: 4 bytes
pub const CMD_SET_LOCAL_PORT: u8 = 0x14;  // arg: 2 bytes LE
pub const CMD_SET_DEST_IP: u8 = 0x15;     // arg: 4 bytes
pub const CMD_SET_DEST_PORT: u8 = 0x16;   // arg: 2 bytes LE
pub const CMD_SET_BAUD: u8 = 0x21;        // arg: 4 bytes LE
pub const CMD_SET_DHCP: u8 = 0x33;        // arg: 1 byte (0=off, 1=on)
pub const CMD_SAVE: u8 = 0x0D;            // Save params to EEPROM
pub const CMD_EXEC: u8 = 0x0E;            // Execute config and soft-reset

// ============================================================================
// Network Mode Values
// ============================================================================

pub const MODE_TCP_SERVER: u8 = 0;
pub const MODE_TCP_CLIENT: u8 = 1;
pub const MODE_UDP_SERVER: u8 = 2;
pub const MODE_UDP_CLIENT: u8 = 3;

// ============================================================================
// HAL_UART contract opcodes
// ============================================================================

// GPIO
pub const DEV_GPIO_CLAIM: u32 = 0x0100;
pub const DEV_GPIO_SET_MODE: u32 = 0x0102;
pub const DEV_GPIO_SET_LEVEL: u32 = 0x0104;

// UART
pub const DEV_UART_OPEN: u32 = 0x0D00;
pub const DEV_UART_CLOSE: u32 = 0x0D01;
pub const DEV_UART_WRITE: u32 = 0x0D02;
pub const DEV_UART_READ: u32 = 0x0D03;
pub const DEV_UART_POLL: u32 = 0x0D04;

// ============================================================================
// Timing
// ============================================================================

/// Reset pin held low for this many ms.
pub const RESET_PULSE_MS: u64 = 50;
/// Wait after releasing reset before entering config mode.
pub const RESET_SETTLE_MS: u64 = 200;
/// Configuration mode baud rate (fixed by CH9120 datasheet).
pub const CONFIG_BAUD: u32 = 9600;

// ============================================================================
// Buffer Sizes
// ============================================================================

/// Max config command size (prefix + cmd + 4-byte arg).
pub const CMD_BUF_SIZE: usize = 16;
/// Max config response size.
pub const RESP_BUF_SIZE: usize = 16;
/// UART data bridge buffer (RX and TX).
pub const DATA_BUF_SIZE: usize = 512;

/// Number of configuration commands to send.
pub const NUM_CONFIG_CMDS: u8 = 8;

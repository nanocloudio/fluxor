//! ENC28J60 module constants.

/// Maximum Ethernet frame size (without FCS)
pub const MTU: usize = 1514;

/// ENC28J60 SPI opcodes
pub const ENC_READ_CTRL_REG: u8 = 0x00;
pub const ENC_READ_BUF_MEM: u8 = 0x3A;
pub const ENC_WRITE_CTRL_REG: u8 = 0x40;
pub const ENC_WRITE_BUF_MEM: u8 = 0x7A;
pub const ENC_BIT_FIELD_SET: u8 = 0x80;
pub const ENC_BIT_FIELD_CLR: u8 = 0xA0;
pub const ENC_SOFT_RESET: u8 = 0xFF;

/// dev_call opcodes
pub const DEV_GPIO_CLAIM: u32 = 0x0100;
pub const DEV_GPIO_SET_MODE: u32 = 0x0102;
pub const DEV_GPIO_SET_LEVEL: u32 = 0x0104;
pub const DEV_SPI_OPEN: u32 = 0x0200;
pub const DEV_SPI_TRANSFER_START: u32 = 0x0207;
pub const DEV_SPI_TRANSFER_POLL: u32 = 0x0208;
pub const DEV_SPI_POLL_BYTE: u32 = 0x0209;

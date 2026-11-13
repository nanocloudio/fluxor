//! ENC28J60 module constants.

/// Maximum Ethernet frame size (without FCS)
pub const MTU: usize = 1514;

pub const ENC_SOFT_RESET: u8 = 0xFF;

/// HAL contract opcodes
pub const DEV_GPIO_CLAIM: u32 = super::abi::registry::gpio::CLAIM;
pub const DEV_GPIO_SET_MODE: u32 = super::abi::registry::gpio::SET_MODE;
pub const DEV_GPIO_SET_LEVEL: u32 = super::abi::registry::gpio::SET_LEVEL;
pub const DEV_SPI_OPEN: u32 = super::abi::registry::spi::OPEN;
pub const DEV_SPI_TRANSFER_START: u32 = super::abi::registry::spi::TRANSFER_START;
pub const DEV_SPI_TRANSFER_POLL: u32 = super::abi::registry::spi::TRANSFER_POLL;

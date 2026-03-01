//! I2C bus abstraction for async transfers.
//!
//! This module wraps Embassy's I2C peripheral with a simpler interface used
//! by the syscall layer. Supports both I2C0 and I2C1 via an enum wrapper.

use embassy_rp::i2c::{self, Async, Config, I2c};
use embassy_rp::peripherals::{I2C0, I2C1};

/// I2C error type preserving detail from the Embassy driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cError {
    /// Device did not acknowledge (not present or busy).
    Nack,
    /// Bus arbitration lost.
    ArbitrationLoss,
    /// Invalid buffer length or address.
    InvalidArg,
    /// Other / unspecified hardware error.
    Other,
}

impl From<i2c::Error> for I2cError {
    fn from(e: i2c::Error) -> Self {
        match e {
            i2c::Error::Abort(i2c::AbortReason::NoAcknowledge) => I2cError::Nack,
            i2c::Error::Abort(i2c::AbortReason::ArbitrationLoss) => I2cError::ArbitrationLoss,
            i2c::Error::InvalidReadBufferLength
            | i2c::Error::InvalidWriteBufferLength
            | i2c::Error::AddressOutOfRange(_) => I2cError::InvalidArg,
            _ => I2cError::Other,
        }
    }
}

/// I2C bus wrapper with async support.
///
/// Wraps either I2C0 or I2C1 (one bus at a time).
pub enum I2cBus {
    I2c0(I2c<'static, I2C0, Async>),
    I2c1(I2c<'static, I2C1, Async>),
}

impl I2cBus {
    /// Create a new I2C0 bus wrapper.
    pub fn new_i2c0(i2c: I2c<'static, I2C0, Async>) -> Self {
        Self::I2c0(i2c)
    }

    /// Create a new I2C1 bus wrapper.
    pub fn new_i2c1(i2c: I2c<'static, I2C1, Async>) -> Self {
        Self::I2c1(i2c)
    }

    /// Write data to an I2C device.
    pub async fn write(&mut self, addr: u8, data: &[u8]) -> Result<(), I2cError> {
        match self {
            Self::I2c0(i2c) => i2c.write_async(addr, data.iter().copied()).await.map_err(I2cError::from),
            Self::I2c1(i2c) => i2c.write_async(addr, data.iter().copied()).await.map_err(I2cError::from),
        }
    }

    /// Read data from an I2C device.
    pub async fn read(&mut self, addr: u8, buf: &mut [u8]) -> Result<(), I2cError> {
        match self {
            Self::I2c0(i2c) => i2c.read_async(addr, buf).await.map_err(I2cError::from),
            Self::I2c1(i2c) => i2c.read_async(addr, buf).await.map_err(I2cError::from),
        }
    }

    /// Write then read (common for register-based devices).
    pub async fn write_read(&mut self, addr: u8, tx: &[u8], rx: &mut [u8]) -> Result<(), I2cError> {
        match self {
            Self::I2c0(i2c) => i2c.write_read_async(addr, tx.iter().copied(), rx).await.map_err(I2cError::from),
            Self::I2c1(i2c) => i2c.write_read_async(addr, tx.iter().copied(), rx).await.map_err(I2cError::from),
        }
    }
}

/// Create default I2C configuration.
pub fn default_config() -> Config {
    let mut config = Config::default();
    config.frequency = 400_000; // 400 kHz (Fast mode)
    config
}

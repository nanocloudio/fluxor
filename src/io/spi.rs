//! SPI bus abstraction for async DMA transfers.
//!
//! This module wraps Embassy's SPI peripheral with a simpler interface used
//! by the syscall layer. All transfers use DMA for efficient background
//! operation.
//!
//! Supports both SPI0 and SPI1 via an enum wrapper (one bus at a time).
//!
//! # SPI Modes
//!
//! | Mode | CPOL | CPHA | Description                          |
//! |------|------|------|--------------------------------------|
//! | 0    | 0    | 0    | Idle low, capture on rising edge     |
//! | 1    | 0    | 1    | Idle low, capture on falling edge    |
//! | 2    | 1    | 0    | Idle high, capture on falling edge   |
//! | 3    | 1    | 1    | Idle high, capture on rising edge    |

use embassy_rp::peripherals::{SPI0, SPI1};
use embassy_rp::spi::{Async, Config, Phase, Polarity, Spi};

/// SPI error type.
///
/// Note: Embassy's RP2350 SPI driver currently defines no error variants,
/// so bus transfer errors cannot occur at the driver level. This enum
/// exists for API consistency and forward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiError {
    /// Invalid configuration (e.g. mode > 3).
    InvalidConfig,
    /// Bus transfer error (reserved for future Embassy error variants).
    Bus,
}

/// SPI bus wrapper with async DMA support.
///
/// Wraps either SPI0 or SPI1 (one bus at a time). Chip select is
/// managed separately via GPIO syscalls.
pub enum SpiBus {
    Spi0(Spi<'static, SPI0, Async>),
    Spi1(Spi<'static, SPI1, Async>),
}

impl SpiBus {
    /// Create a new SPI bus wrapper for SPI0.
    pub fn new_spi0(spi: Spi<'static, SPI0, Async>) -> Self {
        Self::Spi0(spi)
    }

    /// Create a new SPI bus wrapper for SPI1.
    pub fn new_spi1(spi: Spi<'static, SPI1, Async>) -> Self {
        Self::Spi1(spi)
    }

    /// Write data to SPI (transmit only, discard received bytes).
    pub async fn write(&mut self, data: &[u8]) -> Result<(), SpiError> {
        match self {
            Self::Spi0(spi) => spi.write(data).await.map_err(|_| SpiError::Bus),
            Self::Spi1(spi) => spi.write(data).await.map_err(|_| SpiError::Bus),
        }
    }

    /// Transfer data in-place (buffer is both TX and RX).
    ///
    /// On entry, `data` contains bytes to transmit. On exit, `data` contains
    /// received bytes.
    pub async fn transfer_in_place(&mut self, data: &mut [u8]) -> Result<(), SpiError> {
        match self {
            Self::Spi0(spi) => spi.transfer_in_place(data).await.map_err(|_| SpiError::Bus),
            Self::Spi1(spi) => spi.transfer_in_place(data).await.map_err(|_| SpiError::Bus),
        }
    }

    /// Full-duplex transfer with separate TX and RX buffers.
    ///
    /// Both buffers must be the same length.
    pub async fn transfer(&mut self, rx: &mut [u8], tx: &[u8]) -> Result<(), SpiError> {
        match self {
            Self::Spi0(spi) => spi.transfer(rx, tx).await.map_err(|_| SpiError::Bus),
            Self::Spi1(spi) => spi.transfer(rx, tx).await.map_err(|_| SpiError::Bus),
        }
    }

    /// Set clock frequency (Hz).
    pub fn set_frequency(&mut self, freq: u32) {
        match self {
            Self::Spi0(spi) => spi.set_frequency(freq),
            Self::Spi1(spi) => spi.set_frequency(freq),
        }
    }

    /// Configure frequency and mode atomically.
    ///
    /// Returns `Err(InvalidConfig)` if mode > 3.
    pub fn set_config(&mut self, freq: u32, mode: u8) -> Result<(), SpiError> {
        let (polarity, phase) = match mode {
            0 => (Polarity::IdleLow, Phase::CaptureOnFirstTransition),
            1 => (Polarity::IdleLow, Phase::CaptureOnSecondTransition),
            2 => (Polarity::IdleHigh, Phase::CaptureOnFirstTransition),
            3 => (Polarity::IdleHigh, Phase::CaptureOnSecondTransition),
            _ => return Err(SpiError::InvalidConfig),
        };
        let mut config = Config::default();
        config.frequency = freq;
        config.polarity = polarity;
        config.phase = phase;
        match self {
            Self::Spi0(spi) => spi.set_config(&config),
            Self::Spi1(spi) => spi.set_config(&config),
        }
        Ok(())
    }
}

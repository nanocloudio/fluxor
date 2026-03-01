//! ADC (analog-to-digital converter) abstraction for async conversions.
//!
//! This module wraps Embassy's ADC peripheral. The RP2350 has a 12-bit
//! SAR ADC with 5 input channels (GPIO26-29 + internal temperature sensor).
//!
//! Currently supports channel 4 (temperature sensor). GPIO pin channels
//! (0-3) will return InvalidChannel until pin management is integrated.

use embassy_rp::adc::{Adc, Async, Channel};

/// ADC error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdcError {
    /// Invalid channel number.
    InvalidChannel,
    /// Conversion error.
    Other,
}

/// ADC bus wrapper with async support.
pub struct AdcBus {
    adc: Adc<'static, Async>,
    temp_channel: Channel<'static>,
}

impl AdcBus {
    /// Create a new ADC bus wrapper with temperature sensor channel.
    pub fn new(adc: Adc<'static, Async>, temp_channel: Channel<'static>) -> Self {
        Self { adc, temp_channel }
    }

    /// Read a 12-bit value from the given ADC channel.
    ///
    /// Currently only channel 4 (temperature sensor) is supported.
    /// Returns raw 12-bit value (0-4095) on success.
    pub async fn read_channel(&mut self, ch: u8) -> Result<u16, AdcError> {
        match ch {
            4 => self.adc.read(&mut self.temp_channel).await.map_err(|_| AdcError::Other),
            _ => Err(AdcError::InvalidChannel),
        }
    }
}

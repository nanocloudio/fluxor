//! I/O subsystems: SPI, I2C, GPIO, PIO, UART, ADC.

pub mod spi;
pub mod pio;
pub mod gpio;
pub mod i2c;
pub mod uart;
pub mod adc;

pub use pio::{PioStreamRunner, PioStreamService, PioCmdRunner, PioCmdService, PioRxStreamRunner, PioRxStreamService};

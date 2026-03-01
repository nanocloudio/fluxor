//! UART bus abstraction for buffered async transfers.
//!
//! Uses Embassy's `BufferedUart` which is interrupt-driven with ring buffers.
//! Split into separate TX and RX halves for full-duplex operation.

use embassy_rp::uart::{BufferedUartRx, BufferedUartTx, Config};

/// UART error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UartError {
    Framing,
    Parity,
    Overrun,
    Break,
    Other,
}

impl From<embassy_rp::uart::Error> for UartError {
    fn from(e: embassy_rp::uart::Error) -> Self {
        match e {
            embassy_rp::uart::Error::Framing => UartError::Framing,
            embassy_rp::uart::Error::Parity => UartError::Parity,
            embassy_rp::uart::Error::Overrun => UartError::Overrun,
            embassy_rp::uart::Error::Break => UartError::Break,
            _ => UartError::Other,
        }
    }
}

/// Split UART bus — TX and RX halves for full-duplex.
pub struct UartBus {
    tx: BufferedUartTx,
    rx: BufferedUartRx,
}

impl UartBus {
    /// Create from pre-split TX and RX halves.
    pub fn new(tx: BufferedUartTx, rx: BufferedUartRx) -> Self {
        Self { tx, rx }
    }

    /// Write data to UART TX. Returns bytes written.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, UartError> {
        embedded_io_async::Write::write(&mut self.tx, data).await.map_err(|_| UartError::Other)
    }

    /// Read available data from UART RX. Returns bytes read (may be partial).
    /// Waits for at least 1 byte, then returns whatever is available.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, UartError> {
        embedded_io_async::Read::read(&mut self.rx, buf).await.map_err(|_| UartError::Other)
    }
}

/// Default UART configuration: 115200 baud, 8N1.
pub fn default_config() -> Config {
    let mut config = Config::default();
    config.baudrate = 115200;
    config
}

/// UART configuration with specified baud rate, 8N1.
pub fn make_config(baudrate: u32) -> Config {
    let mut config = Config::default();
    config.baudrate = baudrate;
    config
}

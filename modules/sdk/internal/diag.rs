// Internal: diagnostics and log transport.
//
// Layer: internal (unstable, kernel-private).
//
// Consumed by log_ring / log_uart / log_usb overlay modules. Kernel
// emergency writes (panic handler) use separate internal paths not
// exposed here.

/// Drain bytes from the kernel log ring.
/// handle=-1, arg=output buffer, arg_len=capacity.
/// Returns bytes copied (0 if empty, never negative). The low 16 bits
/// of the return value are the payload length; the high 16 bits carry
/// the overflow-dropped byte count since the last drain (saturating).
pub const LOG_RING_DRAIN: u32 = 0x0C64;

/// Write raw bytes to the platform's primary UART synchronously.
/// handle=-1, arg=input buffer, arg_len=byte count.
/// Returns bytes written (== arg_len) on success, or ENOSYS if the
/// platform has no UART, EINVAL on bad args. Blocking: the call does
/// not return until all bytes have been flushed to the FIFO.
pub const UART_WRITE_RAW: u32 = 0x0C65;

/// Enqueue bytes for transmission on the platform's USB CDC endpoint.
/// handle=-1, arg=input buffer, arg_len=byte count.
/// Returns bytes enqueued (may be < arg_len if the internal TX pipe is
/// backpressured), or ENOSYS if the platform has no USB. Non-blocking:
/// the call does not wait for USB frames to go on the wire.
pub const USB_WRITE_RAW: u32 = 0x0C66;

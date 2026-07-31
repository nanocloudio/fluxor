// Internal: diagnostics and log transport.
//
// Layer: internal (unstable, kernel-private).
//
// Local debug transports (UART, USB CDC) are owned by the platform
// runtime's `platform::debug` module — they do not have module-facing
// opcodes. This module retains only the log-ring drain surface used by
// graph-time log forwarders such as `log_net`.

/// Drain bytes from the kernel log ring.
/// handle=-1, arg=output buffer, arg_len=capacity.
/// Returns bytes copied (0 if empty, never negative). The low 16 bits
/// of the return value are the payload length; the next 15 bits are
/// the overflow-dropped byte count since the last drain (saturating at
/// 0x7FFF). The top bit is always 0.
pub const LOG_RING_DRAIN: u32 = 0x0C64;

/// Snapshot fan-out / fan-in pump counters as ASCII into a caller buffer.
/// Returns bytes written. Read-only — no permission required.
/// handle=-1, arg=output buffer, arg_len=capacity.
pub const FAN_DIAG_SNAPSHOT: u32 = 0x0C65;

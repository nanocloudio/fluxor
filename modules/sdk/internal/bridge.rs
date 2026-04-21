// Internal: bridge channels (cross-domain ring bridges).
//
// Layer: internal (unstable, kernel-private).

/// Write data to a bridge channel.
/// handle=bridge_fd, arg=data bytes. Returns 0 on success, -EAGAIN if ring full.
pub const WRITE: u32 = 0x0CE0;
/// Read data from a bridge channel.
/// handle=bridge_fd, arg=output buffer. Returns bytes read, -EAGAIN if empty/no new.
pub const READ: u32 = 0x0CE1;
/// Poll bridge readiness. handle=bridge_fd. Returns 1 if readable, 0 if not.
pub const POLL: u32 = 0x0CE2;
/// Get bridge info. handle=bridge_fd, arg=12-byte output buffer.
/// Returns: [type:u8, from:u8, to:u8, _:u8, drops:u32 LE, seq:u32 LE]
pub const INFO: u32 = 0x0CE3;

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

/// Enumerate the *calling* module's own bridge endpoints. handle is ignored
/// (pass -1); `arg` is an output buffer of at least `SELF_BRIDGES_BUF_LEN`
/// bytes. On success the buffer is filled as:
///   [0]    = in_count  (u8)
///   [1]    = out_count (u8)
///   [2..4] = reserved (0)
///   [4..]  = `in_count` input bridge fds (i32 LE), then `out_count` output
///            bridge fds (i32 LE)
/// Each returned fd is a tagged bridge handle usable directly with
/// `WRITE` / `READ` / `POLL` / `INFO`. Returns the number of bytes written, or
/// a negative errno (`-EINVAL` if the buffer is too small, `-ENODEV` if the
/// caller is not an ISR-tier module with wired bridges).
///
/// This is the module-facing half of the ISR-tier I/O contract: an ISR-tier
/// module (Tier 1b / Tier 2) discovers its bridge endpoints here, then moves
/// data through them with the bridge ops above — all of which are exempt from
/// the §D7 ISR-context syscall deny because the underlying ring operations are
/// lock-free and allocation-free. Lives in the kernel-primitive opcode range
/// (not 0x0CExx) because it is a "self" query like `SELF_INDEX`, not a
/// per-handle bridge operation.
pub const SELF_BRIDGES: u32 = 0x0C44;

/// Maximum bridge endpoints per ISR-tier module (matches the kernel's
/// `isr_tier::MODULE_MAX_BRIDGES`); sizes the `SELF_BRIDGES` output buffer.
pub const MAX_BRIDGES_PER_MODULE: usize = 4;

/// Minimum `SELF_BRIDGES` output buffer length: 4-byte header + up to
/// `MAX_BRIDGES_PER_MODULE` input + output fds (4 bytes each).
pub const SELF_BRIDGES_BUF_LEN: usize = 4 + (MAX_BRIDGES_PER_MODULE * 2) * 4;

/// True for the bridge ops an ISR-tier module may call from interrupt context
/// (the §D7 syscall deny exempts these). The underlying `RingBridge`
/// push/pop/peek and the `SELF_BRIDGES` enumeration are lock-free and
/// allocation-free, so they are safe to invoke from `module_isr_entry`.
pub const fn is_isr_safe(op: u32) -> bool {
    matches!(op, WRITE | READ | POLL | INFO | SELF_BRIDGES)
}

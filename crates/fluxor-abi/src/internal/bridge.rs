// Internal: bridge channels (cross-domain ring bridges).
//
// Layer: internal (unstable, kernel-private).

/// Get bridge info. handle=the bridge, arg=16-byte output buffer.
/// Returns: [type:u8, 0:u8, from:u16 LE, to:u16 LE, 0:u16, drops:u32 LE,
/// seq:u32 LE]
pub use super::super::registry::bridge::INFO;
/// Poll bridge readiness. handle=the bridge. Returns 1 if readable, 0 if not.
pub use super::super::registry::bridge::POLL;
/// Read data from a bridge channel.
/// handle=the bridge, `data` = the output buffer. Returns bytes read, -EAGAIN if empty/no new.
pub use super::super::registry::bridge::READ;
/// Write data to a bridge channel.
/// handle=the bridge, `data` = the bytes to write. Returns 0 on success, -EAGAIN if ring full.
pub use super::super::registry::bridge::WRITE;

/// One of the *calling* module's own bridge endpoints, as a handle.
/// `handle = -1`, `arg` = `[dir u8][index u8]` ([`SELF_BRIDGE_ARG_LEN`]):
/// `dir` [`DIR_IN`] or [`DIR_OUT`], `index` the endpoint's position among the
/// module's bridges of that direction. Returns the bridge's handle, usable
/// with `WRITE` / `READ` / `POLL` / `INFO` and `HANDLE_POLL`; `ENOENT` past
/// the module's last bridge of `dir`, `ENODEV` when the caller is not an
/// ISR-tier module with wired bridges.
///
/// This is the module-facing half of the ISR-tier I/O contract: an ISR-tier
/// module (Tier 1b / Tier 2) takes its bridge handles in `module_new`, then
/// moves data through them with the bridge ops above — exempt from the §D7
/// ISR-context syscall deny because the underlying ring operations are
/// lock-free and allocation-free. Taking a handle mints a kernel route, which
/// is scheduler work: call it from `module_new`, never from the ISR entry.
pub use super::super::registry::bridge::SELF_BRIDGE;

/// [`SELF_BRIDGE`]'s argument length.
pub const SELF_BRIDGE_ARG_LEN: usize = 2;
/// [`SELF_BRIDGE`] `dir`: a bridge the module reads.
pub const DIR_IN: u8 = 0;
/// [`SELF_BRIDGE`] `dir`: a bridge the module writes.
pub const DIR_OUT: u8 = 1;

/// Maximum bridge endpoints per ISR-tier module and direction (matches the
/// kernel's `isr_tier::MODULE_MAX_BRIDGES`).
pub const MAX_BRIDGES_PER_MODULE: usize = 4;

/// True for the bridge ops an ISR-tier module may call (the §D7 syscall deny
/// exempts these). The underlying `RingBridge` push/pop/peek are lock-free
/// and allocation-free, so the data ops are safe to invoke from
/// `module_isr_entry`.
pub const fn is_isr_safe(op: u32) -> bool {
    matches!(op, WRITE | READ | POLL | INFO | SELF_BRIDGE)
}

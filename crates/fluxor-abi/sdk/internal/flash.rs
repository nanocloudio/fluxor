// Internal: raw flash bridge for the runtime parameter store.
//
// Layer: internal (unstable, kernel-private).
//
// Only the flash_rp / flash_store PIC module consumes these. They are
// gated to the runtime-store sector bounds inside the kernel.

/// Raw flash erase: erase 4KB sector (restricted to runtime store bounds).
/// handle=-1, arg=[offset:u32 LE] (4 bytes). Returns 0 or negative errno.
pub const RAW_ERASE: u32 = 0x0C38;
/// Raw flash program: program 256B page (restricted to runtime store bounds).
/// handle=-1, arg=[offset:u32 LE, data:256 bytes] (260 bytes). Returns 0 or negative errno.
pub const RAW_PROGRAM: u32 = 0x0C39;
/// Flash sideband operation (internally acquires FLASH_XIP).
/// handle=-1, arg[0]=operation kind. Returns result or EAGAIN.
pub const SIDEBAND: u32 = 0x0C10;

/// Flash sideband operation kinds.
pub mod sideband_op {
    /// Read QSPI CS pin level (BOOTSEL button). Returns 0 or 1.
    pub const READ_CS: u8 = 0;
    /// Read flash via XIP. arg=[offset:u32 LE], kernel writes data at arg[4..].
    /// Returns bytes copied or negative error.
    pub const XIP_READ: u8 = 1;
}

// Platform: BCM2712 PCIE_DEVICE contract — handle-scoped PCIe device
// binding.
//
// Layer: platform/bcm2712 (chip-specific, unstable).
//
// The PCIE_DEVICE contract (id 0x0012) lets a driver open a handle to
// a specific PCIe device by selector — either a board-local alias
// (`m2_primary`, `rp1`) or a `@class=<name>` match that must resolve
// uniquely. The handle carries the device context for config-space
// access, BAR mapping, and MSI-X vector allocation; drivers never
// name a root complex or positional index directly.
//
// Driver manifest declaration:
//   permissions = ["platform_raw"]
//
//   [[resources]]
//   requires_contract = "pcie_device"
//
// Typical flow (NVMe):
//   handle = provider_open(PCIE_DEVICE, BIND, b"m2_primary", 10)
//   provider_call(handle, BAR_MAP, [0u8], 10) -> writes virt_addr:u64 to arg[2..10]
//   provider_call(handle, CFG_READ32, [offset_lo, offset_hi, ...], ...) -> reads u32
//   provider_call(handle, MSI_ALLOC, [event_handle:i32, ...], ...) -> vec/addr/data
//   provider_close(handle)
//
// Other chips ship their own vtable for contract id 0x0012 with the
// same opcode semantics; only the alias table in each platform's
// `pcie_aliases.rs` varies.

/// Open-style op (issued via `provider_open`). Payload is a UTF-8
/// selector string:
///   - plain name      → board alias lookup (e.g. "m2_primary")
///   - "@class=<name>" → PCI-class match, must resolve to exactly
///     one device (e.g. "@class=nvme")
///
/// Returns a non-negative device handle on success or a negative errno
/// (ENODEV if unresolved, EAGAIN if the link hasn't trained yet,
/// EBUSY if a class selector matches more than one device).
pub const BIND: u32 = 0x0CA0;

/// Release the handle. Default close op invoked by `provider_close`.
/// `handle = dev_handle`, arg = empty.
pub const CLOSE: u32 = 0x0CA1;

/// Read a 32-bit word from the device's PCI configuration space.
/// `handle = dev_handle`, arg = [offset:u16 LE] at bytes 0..2;
/// writes value:u32 LE to arg[4..8] on success. Returns 0 or -errno.
/// Caller must pass at least 8 bytes so the output slot exists.
pub const CFG_READ32: u32 = 0x0CA2;

/// Write a 32-bit word to the device's PCI configuration space.
/// `handle = dev_handle`, arg = [offset:u16 LE, _pad:u16, value:u32 LE]
/// (8 bytes). Returns 0 or -errno.
pub const CFG_WRITE32: u32 = 0x0CA3;

/// Map the device's BARn into kernel virtual address space.
/// `handle = dev_handle`, arg = [bar_idx:u8] at byte 0. Writes the
/// resulting 64-bit virt address (LE) to arg[2..10]. Returns 0 or
/// -errno. Caller must pass at least 10 bytes.
pub const BAR_MAP: u32 = 0x0CA4;

/// Allocate an MSI-X vector for the device, registering `event_handle`
/// as the kernel-side fd that fires when the vector asserts. The kernel
/// brings up the root complex's MSI controller on first call.
/// `handle = dev_handle`, arg = [event_handle:i32 LE] at bytes 0..4.
/// Writes [vec:u8, _pad:u8×3, target_addr:u64 LE, data:u32 LE] to
/// arg[4..20]. Returns 0 or -errno. Caller must pass at least 20 bytes.
pub const MSI_ALLOC: u32 = 0x0CA5;

/// Read back device introspection. `handle = dev_handle`, arg is a
/// 32-byte output buffer. Writes:
///   [ vendor_id:u16 LE, device_id:u16 LE, class:u32 LE,
///     bus:u8, dev:u8, func:u8, _pad:u8,
///     alias:[u8; 20] null-terminated (empty if bound by class) ]
/// Returns 32 on success or -errno.
pub const INFO: u32 = 0x0CA6;

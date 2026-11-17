// Contract: pcie_device — handle-scoped PCIe device binding.
//
// Layer: contracts/hal (portable, stable). The operations here are generic
// PCIe concepts — bind/discover a device, read/write configuration space, map
// a BAR, allocate an interrupt, obtain device info — so a driver (NVMe, RP1,
// a NIC) depends on PCIe CAPABILITY, never on a silicon family.
// Root-complex mechanics (outbound windows, MSI controller programming)
// are platform implementation; PCIe topology/aliases (`m2_primary`, `rp1`)
// are board facts (see docs/architecture/hal_architecture.md
// D-HW-TAXONOMY).
//
// The PCIE_DEVICE contract (id 0x0012) lets a driver open a handle to
// a specific PCIe device by selector — either a board-local alias
// (`m2_primary`, `rp1`) or a `@class=<name>` match that must resolve
// uniquely. The handle carries the device context for config-space
// access, BAR mapping, and MSI-X vector allocation; drivers never
// name a root complex or positional index directly.
//
// Driver manifest declaration:
//
//   [[resources]]
//   requires_contract = "pcie_device"
//
// Typical flow (NVMe):
//   handle = provider_open(PCIE_DEVICE, BIND, b"m2_primary", 10)
//   provider_call(handle, BAR_MAP, [0u8; 12]) -> writes [addr:u64][len:u32] to arg[0..12]
//   provider_call(handle, CFG_READ32, [offset_lo, offset_hi, ...], ...) -> reads u32
//   msi = provider_call(handle, MSI_ALLOC, [0u8; 20]) -> [addr][len][data][vec]; HANDLE_POLL(msi)
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
pub use super::super::super::registry::pcie_device::BIND;

/// Release the handle. Default close op invoked by `provider_close`.
/// `handle = dev_handle`, arg = empty.
pub use super::super::super::registry::pcie_device::CLOSE;

/// Read a 32-bit word from the device's PCI configuration space.
/// `handle = dev_handle`, arg = [offset:u16 LE] at bytes 0..2;
/// writes value:u32 LE to arg[4..8] on success. Returns 0 or -errno.
/// Caller must pass at least 8 bytes so the output slot exists.
pub use super::super::super::registry::pcie_device::CFG_READ32;

/// Write a 32-bit word to the device's PCI configuration space.
/// `handle = dev_handle`, arg = [offset:u16 LE, _pad:u16, value:u32 LE]
/// (8 bytes). Returns 0 or -errno.
pub use super::super::super::registry::pcie_device::CFG_WRITE32;

/// Map the device's BAR `bar_idx` and answer where it lies: an address
/// answer. `handle = dev_handle`, arg in = `[bar_idx:u8]`, arg out =
/// `[addr:u64 LE][len:u32 LE]` (12 bytes; `len` is the BAR's size). Mapping
/// a BAR already mapped answers the same window. Returns 0 or -errno:
/// `ENODEV` for a BAR the device does not implement, `ERANGE` for one of
/// 4 GiB or more, which the answer cannot state.
pub use super::super::super::registry::pcie_device::BAR_MAP;

/// Allocate an MSI-X vector for the device. The kernel brings up the root
/// complex's MSI controller on first call. `handle = dev_handle`, arg out =
/// [`msi::ARG_LEN`] bytes: `[target_addr:u64 LE][len:u32 LE][data:u32 LE]
/// [vec:u8][0:u8×3]` — an address answer: the doorbell address the device
/// writes `data` to, and the window's length. Returns the vector's handle: a
/// signalling handle that polls `POLL_IN` once per interrupt (`HANDLE_POLL`)
/// and wakes the driver. Closing it frees the vector.
pub use super::super::super::registry::pcie_device::MSI_ALLOC;

/// [`MSI_ALLOC`]'s answer layout.
pub mod msi {
    /// Exact `arg` length.
    pub const ARG_LEN: usize = 20;
    /// `u64` LE — the address the device writes to raise the vector.
    pub const ADDR: usize = 0;
    /// `u32` LE — the length of the doorbell window at `ADDR`.
    pub const LEN: usize = 8;
    /// `u32` LE — the value the device writes.
    pub const DATA: usize = 12;
    /// `u8` — the MSI-X table entry the vector is.
    pub const VEC: usize = 16;
}

/// Read back device introspection. `handle = dev_handle`, arg is a
/// 32-byte output buffer. Writes:
///   [ vendor_id:u16 LE, device_id:u16 LE, class:u32 LE,
///     bus:u8, dev:u8, func:u8, _pad:u8,
///     alias:[u8; 20] null-terminated (empty if bound by class) ]
/// Returns 32 on success or -errno.
pub use super::super::super::registry::pcie_device::INFO;

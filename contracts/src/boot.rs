//! What a boot loader hands the kernel, and what the kernel image tells the
//! loader. Shared by the UEFI loader (`crates/fluxor-uefi-loader`) and the
//! kernel's `uefi` platform, so the two sides cannot disagree about a
//! layout; plain `#[repr(C)]` data.
//!
//! The loader runs while the firmware's boot services exist: it gathers what
//! only they can answer — the memory map, the ACPI root, the console UART,
//! entropy, the wall clock — loads the kernel image at the address the image
//! asks for, leaves boot services, and jumps to the image with
//! x0 = `&BootInfo`. After that the kernel uses no firmware service and knows
//! nothing of UEFI: any loader that fills a `BootInfo` (a BIOS loader on a
//! machine without UEFI) boots the same kernel.

/// `BootInfo::magic`.
pub const BOOT_INFO_MAGIC: u64 = u64::from_le_bytes(*b"FLXBOOT1");

/// `KernelHeader::magic`.
pub const KERNEL_HEADER_MAGIC: u64 = u64::from_le_bytes(*b"FLXUEFI1");

/// The first bytes of a kernel image built for the `uefi` runtime.
///
/// The image is not relocatable: it runs at `load_base`. The loader places
/// the whole image file there — the kernel binary followed by the payload
/// the packer appends — and reserves `[load_base, ram_end)` for it, the
/// RAM the kernel uses beyond its file (BSS, stacks, the relocated payload).
/// A busy page in that span is refused, never worked around.
///
/// Offset 0 is a branch over the header, so the image's first instruction is
/// still its entry: the loader jumps to `load_base`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelHeader {
    /// `b` past this header.
    pub branch: u32,
    pub reserved0: u32,
    /// [`KERNEL_HEADER_MAGIC`].
    pub magic: u64,
    /// The image's link address.
    pub load_base: u64,
    /// The end of the RAM the kernel uses from `load_base` on.
    pub ram_end: u64,
    /// The kernel binary's own length; the payload follows it in the file.
    pub kernel_bytes: u64,
}

/// What a region of the machine's memory is, once the firmware is gone.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemKind {
    /// Free RAM: conventional memory and what boot services used.
    Usable = 1,
    /// Firmware runtime code and data, and anything the firmware reserved.
    Reserved = 2,
    /// ACPI tables; usable once the kernel has read them.
    AcpiReclaim = 3,
    /// ACPI non-volatile storage; never usable.
    AcpiNvs = 4,
    /// Memory-mapped I/O the firmware described.
    Mmio = 5,
    /// What the loader allocated: this `BootInfo`, the region list, the
    /// loader itself. Usable once the kernel has copied what it needs.
    Loader = 6,
    /// The kernel's own span, `[load_base, ram_end)`.
    Kernel = 7,
}

/// One region of the memory map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemRegion {
    pub base: u64,
    pub len: u64,
    pub kind: MemKind,
    pub reserved: u32,
}

/// A `[base, base + len)` span.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Range {
    pub base: u64,
    pub len: u64,
}

/// `BootInfo::console_type` when the firmware described no console UART.
pub const CONSOLE_NONE: u32 = u32::MAX;
/// ACPI SPCR interface types the kernel's earliest console writes to.
pub const CONSOLE_16550: u32 = 0x0000;
pub const CONSOLE_PL011: u32 = 0x0003;
pub const CONSOLE_SBSA: u32 = 0x000E;
pub const CONSOLE_16550_GAS: u32 = 0x0012;

/// Handed to the kernel in x0.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    /// [`BOOT_INFO_MAGIC`].
    pub magic: u64,
    /// `regions` points at `region_count` [`MemRegion`]s, sorted by base.
    pub regions: u64,
    pub region_count: u64,
    /// The ACPI 2.0 RSDP's physical address; `0` if the firmware has none.
    pub rsdp: u64,
    /// The image file as loaded (the kernel finds its payload through the
    /// image's own trailer).
    pub image: Range,
    /// `[load_base, ram_end)`, reserved by the loader.
    pub kernel_ram: Range,
    /// Entropy from the firmware, `entropy_len` bytes of it.
    pub entropy: [u8; 64],
    pub entropy_len: u32,
    /// The exception level the kernel was entered at: 1, or 2 on bare metal.
    pub entry_el: u32,
    /// Wall clock at handoff; `0` unknown.
    pub unix_millis_at_handoff: u64,
    /// The boot core's MPIDR.
    pub boot_cpu_id: u64,
    /// The console UART as the firmware's ACPI SPCR table describes it, so
    /// the kernel can print from its first instruction, before it has read
    /// any ACPI of its own: the SPCR interface type (`CONSOLE_*`), the
    /// register width in bytes (`0` unspecified), the register block's
    /// physical address.
    pub console_type: u32,
    pub console_access_bytes: u32,
    pub console_base: u64,
}

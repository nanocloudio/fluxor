//! What a boot loader hands the kernel, and what the kernel image tells the
//! loader. Shared by the UEFI loader (`crates/fluxor-uefi-loader`) and the
//! kernel's `uefi` platform, so the two sides cannot disagree about a
//! layout: plain `#[repr(C)]` data, its offsets pinned below, and the
//! allocation-free builder the loader fills the memory map with.
//!
//! The loader runs while the firmware's boot services exist: it gathers what
//! only they can answer — the memory map, the ACPI root, the console UART,
//! entropy, the wall clock — loads the kernel image at the address the image
//! asks for, leaves boot services, and jumps to the image with
//! x0 = `&BootInfo`. After that the kernel uses no firmware service and knows
//! nothing of UEFI: the `BootInfo` is the whole interface, so any loader that
//! fills one boots the same kernel.
//!
//! The entry state, at `KernelHeader::load_base`: the MMU and data cache off
//! at the current exception level (EL1 or EL2), every interrupt masked, the
//! image file, the `BootInfo` and its region array cleaned to the point of
//! coherency, x0 = `&BootInfo`.

/// `BootInfo::magic`.
pub const BOOT_INFO_MAGIC: u64 = u64::from_le_bytes(*b"FLXBOOT1");

/// `KernelHeader::magic`.
pub const KERNEL_HEADER_MAGIC: u64 = u64::from_le_bytes(*b"FLXUEFI1");

/// The first bytes of a kernel image built for the `uefi` runtime.
///
/// The image is not relocatable: it runs at `load_base`. The loader places
/// the whole image file there — the kernel binary followed by the payload
/// the packer appends — and reserves `[load_base, ram_end)` for it: the file
/// plus the RAM the kernel uses beyond it (BSS, the boot stack). A busy page
/// in that span is refused, never worked around.
///
/// Offset 0 is a branch over the header, so the image's first instruction is
/// still its entry: the loader jumps to `load_base`. `_start` in
/// `src/platform/uefi.rs` emits this layout field for field.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemRegion {
    pub base: u64,
    pub len: u64,
    pub kind: MemKind,
    pub reserved: u32,
}

/// A `[base, base + len)` span.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    pub base: u64,
    pub len: u64,
}

impl Range {
    pub const fn end(&self) -> u64 {
        self.base + self.len
    }
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
    /// `regions` points at `region_count` [`MemRegion`]s, sorted by base,
    /// disjoint, with no two adjacent regions of one kind (a [`RegionList`]).
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
    /// The exception level the kernel was entered at: 1 in a virtual
    /// machine, 2 on bare metal that implements EL2.
    pub entry_el: u32,
    /// Wall clock at handoff; `0` unknown.
    pub unix_millis_at_handoff: u64,
    /// The boot core's MPIDR.
    pub boot_cpu_id: u64,
    /// The console UART as the firmware's ACPI SPCR table describes it, so
    /// the kernel can print from its first instruction, before it has read
    /// any ACPI of its own: the SPCR interface type (`CONSOLE_*`), the
    /// register access width in bytes (`0` unspecified), the register
    /// block's physical address.
    pub console_type: u32,
    pub console_access_bytes: u32,
    pub console_base: u64,
}

// The layouts both sides compile against; `_start` emits the header's by
// hand, so a field moved here without it fails the build, not the boot.
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<KernelHeader>() == 40);
    assert!(offset_of!(KernelHeader, magic) == 8);
    assert!(offset_of!(KernelHeader, load_base) == 16);
    assert!(offset_of!(KernelHeader, ram_end) == 24);
    assert!(offset_of!(KernelHeader, kernel_bytes) == 32);
    assert!(size_of::<MemRegion>() == 24);
    assert!(offset_of!(BootInfo, image) == 32);
    assert!(offset_of!(BootInfo, entropy) == 64);
    assert!(offset_of!(BootInfo, entropy_len) == 128);
    assert!(offset_of!(BootInfo, unix_millis_at_handoff) == 136);
    assert!(offset_of!(BootInfo, console_type) == 152);
    assert!(offset_of!(BootInfo, console_base) == 160);
    assert!(size_of::<BootInfo>() == 168);
};

/// The memory map a `BootInfo` carries, built in caller-owned storage with
/// no allocation: the loader fills it after leaving boot services.
///
/// The firmware's descriptors arrive in no promised order and may run
/// across the kernel's span. Each one added is cut at the span's edges (the
/// part inside becomes [`MemKind::Kernel`]), placed in base order, and
/// merged with a neighbour of its kind that it touches. A region that would
/// need a slot past the storage's end is counted in [`dropped`](Self::dropped)
/// instead.
pub struct RegionList<'a> {
    slots: &'a mut [MemRegion],
    len: usize,
    dropped: usize,
    kernel: Range,
}

impl<'a> RegionList<'a> {
    pub fn new(slots: &'a mut [MemRegion], kernel: Range) -> Self {
        RegionList {
            slots,
            len: 0,
            dropped: 0,
            kernel,
        }
    }

    /// Add `[base, base + len)` of `kind`.
    pub fn add(&mut self, base: u64, len: u64, kind: MemKind) {
        let end = base.saturating_add(len);
        let (k0, k1) = (self.kernel.base, self.kernel.end());
        if self.kernel.len == 0 || end <= k0 || base >= k1 {
            self.place(base, end, kind);
            return;
        }
        self.place(base, k0.max(base), kind);
        self.place(base.max(k0), end.min(k1), MemKind::Kernel);
        self.place(k1.min(end), end, kind);
    }

    fn place(&mut self, base: u64, end: u64, kind: MemKind) {
        if end <= base {
            return;
        }
        let at = self.slots[..self.len].partition_point(|r| r.base < base);
        let joins_prev = at > 0 && {
            let p = &self.slots[at - 1];
            p.kind == kind && p.base + p.len == base
        };
        let joins_next = at < self.len && {
            let n = &self.slots[at];
            n.kind == kind && n.base == end
        };
        match (joins_prev, joins_next) {
            (true, true) => {
                let next_len = self.slots[at].len;
                self.slots[at - 1].len += (end - base) + next_len;
                self.slots.copy_within(at + 1..self.len, at);
                self.len -= 1;
            }
            (true, false) => self.slots[at - 1].len += end - base,
            (false, true) => {
                let n = &mut self.slots[at];
                n.len += n.base - base;
                n.base = base;
            }
            (false, false) => {
                if self.len == self.slots.len() {
                    self.dropped += 1;
                    return;
                }
                self.slots.copy_within(at..self.len, at + 1);
                self.slots[at] = MemRegion {
                    base,
                    len: end - base,
                    kind,
                    reserved: 0,
                };
                self.len += 1;
            }
        }
    }

    /// The regions so far, sorted by base.
    pub fn regions(&self) -> &[MemRegion] {
        &self.slots[..self.len]
    }

    /// Regions that found no free slot.
    pub fn dropped(&self) -> usize {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: MemRegion = MemRegion {
        base: 0,
        len: 0,
        kind: MemKind::Reserved,
        reserved: 0,
    };

    fn r(base: u64, len: u64, kind: MemKind) -> MemRegion {
        MemRegion {
            base,
            len,
            kind,
            reserved: 0,
        }
    }

    #[test]
    fn unordered_descriptors_come_out_sorted_and_merged() {
        let mut slots = [EMPTY; 8];
        let mut l = RegionList::new(&mut slots, Range::default());
        l.add(0x3000, 0x1000, MemKind::Usable);
        l.add(0x0000, 0x1000, MemKind::Usable);
        l.add(0x5000, 0x1000, MemKind::Mmio);
        // Bridges the two usable runs into one.
        l.add(0x1000, 0x2000, MemKind::Usable);
        l.add(0x4000, 0x1000, MemKind::Reserved);
        assert_eq!(
            l.regions(),
            &[
                r(0x0000, 0x4000, MemKind::Usable),
                r(0x4000, 0x1000, MemKind::Reserved),
                r(0x5000, 0x1000, MemKind::Mmio),
            ]
        );
        assert_eq!(l.dropped(), 0);
    }

    #[test]
    fn a_descriptor_across_the_kernel_span_is_cut_at_its_edges() {
        let mut slots = [EMPTY; 8];
        let kernel = Range {
            base: 0x10_000,
            len: 0x4_000,
        };
        let mut l = RegionList::new(&mut slots, kernel);
        // The firmware merged the loader's own LoaderCode pages with the
        // kernel's into one descriptor.
        l.add(0xE_000, 0x8_000, MemKind::Loader);
        assert_eq!(
            l.regions(),
            &[
                r(0xE_000, 0x2_000, MemKind::Loader),
                r(0x10_000, 0x4_000, MemKind::Kernel),
                r(0x14_000, 0x2_000, MemKind::Loader),
            ]
        );
    }

    #[test]
    fn a_descriptor_inside_the_kernel_span_becomes_kernel() {
        let mut slots = [EMPTY; 4];
        let kernel = Range {
            base: 0x10_000,
            len: 0x4_000,
        };
        let mut l = RegionList::new(&mut slots, kernel);
        l.add(0x12_000, 0x2_000, MemKind::Loader);
        l.add(0x10_000, 0x2_000, MemKind::Loader);
        assert_eq!(l.regions(), &[r(0x10_000, 0x4_000, MemKind::Kernel)]);
    }

    #[test]
    fn a_region_with_no_slot_is_counted_not_written() {
        let mut slots = [EMPTY; 2];
        let mut l = RegionList::new(&mut slots, Range::default());
        l.add(0x0000, 0x1000, MemKind::Usable);
        l.add(0x2000, 0x1000, MemKind::Usable);
        l.add(0x4000, 0x1000, MemKind::Usable);
        // Still merges into a full list.
        l.add(0x1000, 0x1000, MemKind::Usable);
        assert_eq!(l.regions(), &[r(0x0000, 0x3000, MemKind::Usable)]);
        assert_eq!(l.dropped(), 1);
        l.add(0x0, 0, MemKind::Mmio);
        assert_eq!(l.regions().len(), 1, "an empty descriptor adds nothing");
    }
}

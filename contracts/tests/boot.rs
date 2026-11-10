//! `fluxor_contracts::boot::RegionList`: firmware memory descriptors come out
//! sorted, merged and cut at the kernel image's edges.

use fluxor_contracts::boot::*;

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

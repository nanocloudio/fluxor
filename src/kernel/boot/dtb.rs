//! Flattened Device Tree (FDT) reader.
//!
//! The DTB pointer handed to the kernel by firmware is stashed in
//! `_boot_dtb_ptr`; this module walks the blob to answer property queries.
//! Minimal: no heap, no materialised tree — a streaming walker over the FDT
//! structure block, every read bounds-checked against the blob, so a
//! malformed tree answers `None` and never faults.
//!
//! Two questions are asked of it:
//! - the board's Ethernet MAC ([`read_ethernet_mac`]);
//! - the board's memory ([`memory_facts`]): the `/memory` nodes, the
//!   `/reserved-memory` children and the header's memory-reservation block,
//!   the initramfs `/chosen` names, the blob's own bytes, and the DMA windows
//!   the buses' `dma-ranges` describe. The bcm2712 kernel builds its memory
//!   map from it (`platform/bcm2712/memmap.rs`), and it runs before the MMU
//!   is on — so it reads only through slices, which the bare-metal target
//!   compiles to aligned or byte accesses.
//!
//! Reference: devicetree.org/specifications (section 5 "Flattened Device
//! Tree (DTB) Format", section 3.4-3.5 "/memory", "/reserved-memory").

const FDT_MAGIC: u32 = 0xD00DFEED;
const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32 = 0x0000_0002;
const FDT_PROP: u32 = 0x0000_0003;
const FDT_NOP: u32 = 0x0000_0004;
const FDT_END: u32 = 0x0000_0009;
/// Header bytes: ten big-endian u32 fields.
const HEADER_LEN: usize = 40;
/// Largest blob the reader accepts. A board's tree is ~80 KiB (the Pi 5's) and
/// QEMU's ~1 MiB at most; a header claiming more is corrupt, and the reader
/// would otherwise walk whatever memory follows.
pub const MAX_BLOB: usize = 2 * 1024 * 1024;
/// Node nesting the walker tracks. The Pi 5's tree nests 6 deep; the
/// specification sets no bound, so a deeper tree is refused rather than
/// mis-read.
pub const MAX_DEPTH: usize = 16;
/// `/memory` ranges kept. A board states one to a few (the Pi 5 two); past
/// this the facts are marked incomplete and the platform keeps its fixed map.
pub const MAX_MEMORY_RANGES: usize = 16;
/// Reserved ranges kept: `/reserved-memory` children, the reservation block,
/// the initramfs and the blob itself. The Pi 5 states about six; past this
/// the facts are marked incomplete, because a reservation dropped is memory
/// the kernel would write over.
pub const MAX_RESERVED_RANGES: usize = 32;

extern "C" {
    static _boot_dtb_ptr: u64;
}

/// One physical range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub base: u64,
    pub size: u64,
}

impl Range {
    pub const EMPTY: Range = Range { base: 0, size: 0 };

    /// One past the range's last byte, saturating.
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }
}

/// What the tree says about the board's memory.
#[derive(Clone, Copy, Debug)]
pub struct MemoryFacts {
    /// `/memory` `reg` ranges, in tree order.
    pub memory: [Range; MAX_MEMORY_RANGES],
    pub memory_count: usize,
    /// Ranges nothing of the kernel's may be placed in.
    pub reserved: [Range; MAX_RESERVED_RANGES],
    pub reserved_count: usize,
    /// The lowest end of any bus's `dma-ranges` window, in the parent bus's
    /// address space: memory a device can reach lies below it. `None` when no
    /// bus restricts DMA.
    pub dma_ceiling: Option<u64>,
    /// A table above overflowed, or a value the placement rests on could not
    /// be read: the facts are incomplete and must not be used to place
    /// memory.
    pub truncated: bool,
    /// Why the facts are incomplete: the `INCOMPLETE_*` bits that apply.
    pub incomplete: u8,
}

/// More `/memory` ranges than [`MAX_MEMORY_RANGES`].
pub const INCOMPLETE_MEMORY_TABLE: u8 = 1 << 0;
/// More reserved ranges than [`MAX_RESERVED_RANGES`].
pub const INCOMPLETE_RESERVED_TABLE: u8 = 1 << 1;
/// A `/memory` `reg` the reader cannot stride.
pub const INCOMPLETE_MEMORY_REG: u8 = 1 << 2;
/// A `/reserved-memory` child `reg` the reader cannot stride.
pub const INCOMPLETE_RESERVED_REG: u8 = 1 << 3;
/// A `/chosen` `linux,initrd-start` / `linux,initrd-end` that cannot be read
/// (wider than [`MAX_CELLS`], a non-zero cell above 64 bits, a length that is
/// no whole number of cells), only one of the pair, or an end below its start.
pub const INCOMPLETE_INITRD: u8 = 1 << 4;

impl MemoryFacts {
    pub const fn empty() -> Self {
        Self {
            memory: [Range::EMPTY; MAX_MEMORY_RANGES],
            memory_count: 0,
            reserved: [Range::EMPTY; MAX_RESERVED_RANGES],
            reserved_count: 0,
            dma_ceiling: None,
            truncated: false,
            incomplete: 0,
        }
    }

    /// The `/memory` ranges stated.
    pub fn memory(&self) -> &[Range] {
        self.memory.get(..self.memory_count).unwrap_or(&[])
    }

    /// The reserved ranges stated.
    pub fn reserved(&self) -> &[Range] {
        self.reserved.get(..self.reserved_count).unwrap_or(&[])
    }

    /// Total bytes of memory stated.
    pub fn memory_bytes(&self) -> u64 {
        self.memory()
            .iter()
            .fold(0u64, |a, r| a.saturating_add(r.size))
    }

    /// Mark the facts incomplete for `why` (an `INCOMPLETE_*` bit).
    fn mark_incomplete(&mut self, why: u8) {
        self.truncated = true;
        self.incomplete |= why;
    }

    fn push_memory(&mut self, r: Range) {
        if r.size == 0 {
            return;
        }
        match self.memory.get_mut(self.memory_count) {
            Some(slot) => {
                *slot = r;
                self.memory_count += 1;
            }
            None => self.mark_incomplete(INCOMPLETE_MEMORY_TABLE),
        }
    }

    fn push_reserved(&mut self, r: Range) {
        if r.size == 0 {
            return;
        }
        match self.reserved.get_mut(self.reserved_count) {
            Some(slot) => {
                *slot = r;
                self.reserved_count += 1;
            }
            None => self.mark_incomplete(INCOMPLETE_RESERVED_TABLE),
        }
    }
}

#[inline]
fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn be64(b: &[u8], off: usize) -> Option<u64> {
    Some((u64::from(be32(b, off)?) << 32) | u64::from(be32(b, off + 4)?))
}

/// Widest `#address-cells` / `#size-cells` the reader accepts. PCI buses state
/// three address cells; a value past this is a malformed tree, and reading it
/// would stride through the property with a nonsensical width.
const MAX_CELLS: u32 = 4;

/// A `cells`-wide big-endian number (0 reads as 0; at most [`MAX_CELLS`]).
fn cells_value(b: &[u8], off: usize, cells: u32) -> Option<u64> {
    match cells {
        0 => Some(0),
        1 => be32(b, off).map(u64::from),
        2 => be64(b, off),
        // Wider than 64 bits: only the low two cells can address anything
        // this kernel maps; the high ones must be zero.
        n if n <= MAX_CELLS => {
            let hi = (n as usize - 2) * 4;
            for i in 0..n as usize - 2 {
                if be32(b, off + i * 4)? != 0 {
                    return None;
                }
            }
            be64(b, off + hi)
        }
        _ => None,
    }
}

/// A `/chosen` initramfs bound: as many cells as the property holds, or
/// `None` when that is no whole number of cells, none, or wider than
/// [`MAX_CELLS`].
fn initrd_cell(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return None;
    }
    let cells = u32::try_from(value.len() / 4).ok()?;
    if cells > MAX_CELLS {
        return None;
    }
    cells_value(value, 0, cells)
}

/// The blob at `ptr`: its header checked (magic, size bound) and the slice
/// covering exactly `totalsize` bytes.
///
/// # Safety
/// `ptr` is null or points at readable memory for at least the header, and
/// for `totalsize` bytes when the header is a valid FDT header.
pub unsafe fn blob_at(ptr: *const u8) -> Option<&'static [u8]> {
    if ptr.is_null() || (ptr as usize) & 7 != 0 {
        return None;
    }
    // SAFETY: the caller's contract covers the header.
    let head = unsafe { core::slice::from_raw_parts(ptr, HEADER_LEN) };
    if be32(head, 0)? != FDT_MAGIC {
        return None;
    }
    let total = be32(head, 4)? as usize;
    if !(HEADER_LEN..=MAX_BLOB).contains(&total) {
        return None;
    }
    // SAFETY: a valid header; the caller's contract covers `totalsize`.
    Some(unsafe { core::slice::from_raw_parts(ptr, total) })
}

/// The structure and strings blocks of `blob`, bounds-checked.
fn blocks(blob: &[u8]) -> Option<(&[u8], &[u8], usize)> {
    if be32(blob, 0)? != FDT_MAGIC {
        return None;
    }
    let total = (be32(blob, 4)? as usize).min(blob.len());
    let off_struct = be32(blob, 8)? as usize;
    let off_strings = be32(blob, 12)? as usize;
    let off_rsvmap = be32(blob, 16)? as usize;
    let size_strings = be32(blob, 32)? as usize;
    let size_struct = be32(blob, 36)? as usize;
    let structs = blob.get(off_struct..off_struct.checked_add(size_struct)?.min(total))?;
    let strings = blob.get(off_strings..off_strings.checked_add(size_strings)?.min(total))?;
    Some((structs, strings, off_rsvmap))
}

/// The NUL-terminated string at `off` in `strings`.
fn string_at(strings: &[u8], off: usize) -> &[u8] {
    let s = strings.get(off..).unwrap_or(&[]);
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    s.get(..end).unwrap_or(&[])
}

/// One structure-block event.
enum Event<'a> {
    Begin(&'a [u8]),
    End,
    Prop(&'a [u8], &'a [u8]),
}

/// Walk the structure block, calling `f` per event. `false` when the block is
/// malformed (the walk stops there).
fn walk<'a>(structs: &'a [u8], strings: &'a [u8], mut f: impl FnMut(Event<'a>) -> bool) -> bool {
    let mut i = 0usize;
    loop {
        let Some(tok) = be32(structs, i) else {
            return false;
        };
        i += 4;
        match tok {
            FDT_BEGIN_NODE => {
                let rest = structs.get(i..).unwrap_or(&[]);
                let Some(len) = rest.iter().position(|&b| b == 0) else {
                    return false;
                };
                let name = rest.get(..len).unwrap_or(&[]);
                i = (i + len + 1 + 3) & !3;
                if !f(Event::Begin(name)) {
                    return true;
                }
            }
            FDT_END_NODE => {
                if !f(Event::End) {
                    return true;
                }
            }
            FDT_NOP => {}
            FDT_PROP => {
                let (Some(len), Some(nameoff)) = (be32(structs, i), be32(structs, i + 4)) else {
                    return false;
                };
                i += 8;
                let len = len as usize;
                let Some(value) = structs.get(i..i.saturating_add(len)) else {
                    return false;
                };
                if !f(Event::Prop(string_at(strings, nameoff as usize), value)) {
                    return true;
                }
                i = (i + len + 3) & !3;
            }
            FDT_END => return true,
            _ => return false,
        }
    }
}

/// Return the DTB base pointer, or None if no DTB was captured at boot or
/// the magic bytes don't match.
fn boot_blob() -> Option<&'static [u8]> {
    // SAFETY: `_boot_dtb_ptr` is written once at boot, before any reader.
    let p = unsafe { core::ptr::read_volatile(&raw const _boot_dtb_ptr) };
    if p == 0 || p == u64::MAX {
        return None;
    }
    // SAFETY: the boot path recorded the pointer the firmware handed over,
    // which lies in mapped DRAM.
    unsafe { blob_at(p as usize as *const u8) }
}

/// Return the ethernet MAC address from the DTB, if present.
///
/// Walks the structure block looking for any node carrying a
/// `local-mac-address` property of exactly 6 bytes, and returns the first
/// match. Returns None if no such property is found or no DTB is attached.
pub fn read_ethernet_mac() -> Option<[u8; 6]> {
    mac_in(boot_blob()?)
}

/// [`read_ethernet_mac`] over a given blob.
pub fn mac_in(blob: &[u8]) -> Option<[u8; 6]> {
    let (structs, strings, _) = blocks(blob)?;
    let mut mac = None;
    walk(structs, strings, |ev| {
        if let Event::Prop(name, value) = ev {
            if name == b"local-mac-address" && value.len() == 6 {
                let mut m = [0u8; 6];
                for (d, s) in m.iter_mut().zip(value) {
                    *d = *s;
                }
                mac = Some(m);
                return false;
            }
        }
        true
    });
    mac
}

/// Per-node walk state.
#[derive(Clone, Copy)]
struct Frame {
    /// `#address-cells` / `#size-cells` this node states for its children.
    addr_cells: u32,
    size_cells: u32,
    /// The node is `/memory` (by name at the top level, or `device_type`).
    memory: bool,
    /// The node is `/reserved-memory`.
    reserved_parent: bool,
    /// The node is `/chosen`.
    chosen: bool,
    /// `reg` and `dma-ranges` seen in this node, resolved at its end (the
    /// cells they are read with may be stated after them).
    reg: (usize, usize),
    dma: (usize, usize),
    has_dma: bool,
}

const FRAME: Frame = Frame {
    addr_cells: 2,
    size_cells: 1,
    memory: false,
    reserved_parent: false,
    chosen: false,
    reg: (0, 0),
    dma: (0, 0),
    has_dma: false,
};

/// Offset of `value` inside `structs` (both borrow the same blob).
fn offset_in(structs: &[u8], value: &[u8]) -> usize {
    (value.as_ptr() as usize).wrapping_sub(structs.as_ptr() as usize)
}

/// `(base, size)` pairs of a `reg`-shaped value with the given cells. `false`
/// when the value cannot be read with them (a cell count past [`MAX_CELLS`],
/// a zero-width pair, or an address too wide for 64 bits): the caller cannot
/// know what ranges it states.
fn for_each_pair(
    b: &[u8],
    (off, len): (usize, usize),
    ac: u32,
    sc: u32,
    mut f: impl FnMut(u64, u64),
) -> bool {
    if ac > MAX_CELLS || sc > MAX_CELLS || ac + sc == 0 {
        return false;
    }
    let stride = (ac + sc) as usize * 4;
    let mut p = off;
    while p + stride <= off + len {
        match (
            cells_value(b, p, ac),
            cells_value(b, p + ac as usize * 4, sc),
        ) {
            (Some(base), Some(size)) => f(base, size),
            _ => return false,
        }
        p += stride;
    }
    true
}

/// What `blob` says about the board's memory, or `None` when it is no FDT or
/// its structure block is malformed.
pub fn memory_facts(blob: &[u8]) -> Option<MemoryFacts> {
    let (structs, strings, off_rsvmap) = blocks(blob)?;
    let mut facts = MemoryFacts::empty();
    // The blob itself: read after boot (the MAC), so never overwritten.
    facts.push_reserved(Range {
        base: blob.as_ptr() as usize as u64,
        size: blob.len() as u64,
    });
    // The header's memory-reservation block: (address, size) u64 pairs ending
    // in a zero pair.
    let mut p = off_rsvmap;
    while let (Some(base), Some(size)) = (be64(blob, p), be64(blob, p + 8)) {
        if base == 0 && size == 0 {
            break;
        }
        facts.push_reserved(Range { base, size });
        p += 16;
    }

    let mut stack = [FRAME; MAX_DEPTH];
    let mut depth = 0usize; // frames in use; stack[depth - 1] is the open node
    let mut ok = true;
    // Each half of the initramfs pair: absent, or present and read (`None`
    // when its cells cannot be read).
    let mut initrd = (None::<Option<u64>>, None::<Option<u64>>);
    let complete = walk(structs, strings, |ev| match ev {
        Event::Begin(name) => {
            if depth >= MAX_DEPTH {
                ok = false;
                return false;
            }
            let mut fr = FRAME;
            // Top-level node names: the root is depth 0, its children 1.
            if depth == 1 {
                let base = name.split(|&c| c == b'@').next().unwrap_or(&[]);
                fr.memory = base == b"memory";
                fr.reserved_parent = base == b"reserved-memory";
                fr.chosen = base == b"chosen";
            }
            stack[depth] = fr;
            depth += 1;
            true
        }
        Event::Prop(name, value) => {
            let Some(fr) = depth.checked_sub(1).and_then(|d| stack.get_mut(d)) else {
                return true;
            };
            match name {
                b"#address-cells" => {
                    if let Some(v) = be32(value, 0) {
                        fr.addr_cells = v;
                    }
                }
                b"#size-cells" => {
                    if let Some(v) = be32(value, 0) {
                        fr.size_cells = v;
                    }
                }
                b"device_type" if value.starts_with(b"memory\0") || value == b"memory" => {
                    fr.memory = true;
                }
                b"reg" => fr.reg = (offset_in(structs, value), value.len()),
                b"dma-ranges" => {
                    fr.dma = (offset_in(structs, value), value.len());
                    fr.has_dma = true;
                }
                b"linux,initrd-start" if fr.chosen => initrd.0 = Some(initrd_cell(value)),
                b"linux,initrd-end" if fr.chosen => initrd.1 = Some(initrd_cell(value)),
                _ => {}
            }
            true
        }
        Event::End => {
            let Some(d) = depth.checked_sub(1) else {
                ok = false;
                return false;
            };
            let fr = stack[d];
            depth = d;
            // The cells this node's own `reg` is read with are its parent's.
            let parent = d.checked_sub(1).map(|i| stack[i]).unwrap_or(FRAME);
            let grand_reserved = parent.reserved_parent && d == 2;
            // A `reg` that cannot be read leaves the facts incomplete: an
            // unread memory range is memory unaccounted for, an unread
            // reservation memory the kernel would write over.
            if fr.memory
                && fr.reg.1 > 0
                && !for_each_pair(
                    structs,
                    fr.reg,
                    parent.addr_cells,
                    parent.size_cells,
                    |base, size| facts.push_memory(Range { base, size }),
                )
            {
                facts.mark_incomplete(INCOMPLETE_MEMORY_REG);
            }
            if grand_reserved
                && fr.reg.1 > 0
                && !for_each_pair(
                    structs,
                    fr.reg,
                    parent.addr_cells,
                    parent.size_cells,
                    |base, size| facts.push_reserved(Range { base, size }),
                )
            {
                facts.mark_incomplete(INCOMPLETE_RESERVED_REG);
            }
            // `dma-ranges`: (child address in this node's cells, parent
            // address in the parent's, size in this node's). An empty one is
            // an identity mapping of everything and restricts nothing.
            // A window whose cells cannot be read restricts nothing the
            // reader can state, and the facts' placement does not rest on it.
            let (ca, pa, sc) = (fr.addr_cells, parent.addr_cells, fr.size_cells);
            if fr.has_dma && fr.dma.1 > 0 && ca <= MAX_CELLS && pa <= MAX_CELLS && sc <= MAX_CELLS {
                let stride = (ca + pa + sc) as usize * 4;
                let (off, len) = fr.dma;
                let mut p = off;
                let mut node_top = None::<u64>;
                while stride > 0 && p + stride <= off + len {
                    if let (Some(pbase), Some(size)) = (
                        cells_value(structs, p + ca as usize * 4, pa),
                        cells_value(structs, p + (ca + pa) as usize * 4, sc),
                    ) {
                        let top = pbase.saturating_add(size);
                        node_top = Some(node_top.map_or(top, |t: u64| t.max(top)));
                    }
                    p += stride;
                }
                if let Some(top) = node_top {
                    facts.dma_ceiling = Some(facts.dma_ceiling.map_or(top, |c| c.min(top)));
                }
            }
            true
        }
    });
    if !complete || !ok {
        return None;
    }
    // A stated initramfs that cannot be placed is a reservation the kernel
    // would write over, so it leaves the facts incomplete like an unread
    // reservation `reg`.
    match initrd {
        (None, None) => {}
        (Some(Some(s)), Some(Some(e))) if e >= s => facts.push_reserved(Range {
            base: s,
            size: e - s,
        }),
        _ => facts.mark_incomplete(INCOMPLETE_INITRD),
    }
    Some(facts)
}

/// [`memory_facts`] of the blob the firmware handed over at `ptr`.
///
/// # Safety
/// As [`blob_at`].
pub unsafe fn memory_facts_at(ptr: *const u8) -> Option<MemoryFacts> {
    // SAFETY: the caller's contract.
    memory_facts(unsafe { blob_at(ptr) }?)
}

// The machine as its ACPI tables describe it: tables only, no AML.
//
// A parser over byte slices. `Memory` is how it reaches a physical address, so
// the kernel reads through its identity map and a host test reads a fixture.
// Every length comes from the tables themselves, so every read is bounded and
// every table is checksummed before anything in it is believed.

/// Physical memory, as the parser sees it.
pub trait Memory {
    /// `len` bytes at physical `addr`; `None` where the machine has none.
    fn bytes(&self, addr: u64, len: usize) -> Option<&[u8]>;
}

/// Why the tables could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoRsdp,
    BadRsdp,
    /// The ACPI revision has no XSDT.
    NoXsdt,
    BadXsdt,
}

pub const MAX_TABLES: usize = 32;
pub const MAX_CPUS: usize = 64;
pub const MAX_RID_MAPS: usize = 8;

/// One processor the MADT says can run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cpu {
    pub mpidr: u64,
    /// GICv2 CPU interface.
    pub gicc_base: u64,
    /// GICv3 redistributor, when the MADT names one per CPU.
    pub gicr_base: u64,
}

/// What the kernel needs from the tables.
#[derive(Clone, Copy, Debug)]
pub struct Machine {
    /// Signature of every table the XSDT lists whose checksum holds.
    pub tables: [[u8; 4]; MAX_TABLES],
    pub table_count: usize,
    /// XSDT entries refused: unreadable, or a bad length or checksum.
    pub bad_tables: usize,
    pub cpus: [Cpu; MAX_CPUS],
    pub cpu_count: usize,
    /// CPUs beyond [`MAX_CPUS`].
    pub cpus_dropped: usize,
    pub gicd_base: u64,
    /// MADT GIC version: 0 unstated, else 1 to 4.
    pub gic_version: u8,
    /// First GICv3 redistributor discovery range; 0 if none.
    pub gicr_range_base: u64,
    pub its_count: usize,
    pub its_base: u64,
    pub v2m_count: usize,
    pub v2m_base: u64,
    /// GTDT interrupts.
    pub timer_virt_gsiv: u32,
    pub timer_phys_gsiv: u32,
    /// SPCR interface type and register block; `u32::MAX`/0 when absent.
    pub console_type: u32,
    pub console_base: u64,
    /// MCFG's ECAM window for PCI segment 0, as the address bus 0 would have
    /// (the table's convention whatever its first bus); 0 when it names none.
    /// The buses it decodes are `ecam_bus_start..=ecam_bus_end`.
    pub ecam_base: u64,
    pub ecam_bus_start: u8,
    pub ecam_bus_end: u8,
    /// IORT: how segment 0's requester IDs become ITS device IDs, as
    /// `(first RID, last RID - first RID, first device ID)` (the table states
    /// a range by its count less one); empty when the table is absent.
    pub rid_maps: [(u32, u32, u32); MAX_RID_MAPS],
    pub rid_map_count: usize,
    /// FADT `ARM_BOOT_ARCH`: PSCI implemented, and by HVC rather than SMC.
    pub psci: bool,
    pub psci_hvc: bool,
    pub hw_reduced: bool,
}

impl Machine {
    const fn empty() -> Self {
        Machine {
            tables: [[0; 4]; MAX_TABLES],
            table_count: 0,
            bad_tables: 0,
            cpus: [Cpu {
                mpidr: 0,
                gicc_base: 0,
                gicr_base: 0,
            }; MAX_CPUS],
            cpu_count: 0,
            cpus_dropped: 0,
            gicd_base: 0,
            gic_version: 0,
            gicr_range_base: 0,
            its_count: 0,
            its_base: 0,
            v2m_count: 0,
            v2m_base: 0,
            timer_virt_gsiv: 0,
            timer_phys_gsiv: 0,
            console_type: u32::MAX,
            console_base: 0,
            ecam_base: 0,
            ecam_bus_start: 0,
            ecam_bus_end: 0,
            rid_maps: [(0, 0, 0); MAX_RID_MAPS],
            rid_map_count: 0,
            psci: false,
            psci_hvc: false,
            hw_reduced: false,
        }
    }

    #[allow(
        dead_code,
        reason = "the host tests ask for a table by name; the kernel reads the parsed fields"
    )]
    pub fn has_table(&self, signature: &[u8; 4]) -> bool {
        self.tables[..self.table_count]
            .iter()
            .any(|t| t == signature)
    }
}

const HEADER: usize = 36;
const RSDP_V1: usize = 20;
const RSDP_V2: usize = 36;
/// A table bigger than this is corrupt, whatever its length field says.
const MAX_TABLE: usize = 1 << 24;

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |sum, x| sum.wrapping_add(*x)) == 0
}

/// A table with a plausible length and a good checksum.
fn table<M: Memory>(mem: &M, addr: u64) -> Option<&[u8]> {
    let header = mem.bytes(addr, HEADER)?;
    let len = u32_at(header, 4)? as usize;
    if !(HEADER..=MAX_TABLE).contains(&len) {
        return None;
    }
    let body = mem.bytes(addr, len)?;
    checksum_ok(body).then_some(body)
}

/// Read the tables the RSDP at `rsdp` leads to.
pub fn parse<M: Memory>(mem: &M, rsdp: u64) -> Result<Machine, Error> {
    if rsdp == 0 {
        return Err(Error::NoRsdp);
    }
    let head = mem.bytes(rsdp, RSDP_V1).ok_or(Error::NoRsdp)?;
    if &head[..8] != b"RSD PTR " || !checksum_ok(head) {
        return Err(Error::BadRsdp);
    }
    if head[15] < 2 {
        return Err(Error::NoXsdt);
    }
    let full = mem.bytes(rsdp, RSDP_V2).ok_or(Error::BadRsdp)?;
    if !checksum_ok(full) {
        return Err(Error::BadRsdp);
    }
    let xsdt_addr = u64_at(full, 24).ok_or(Error::BadRsdp)?;
    let xsdt = table(mem, xsdt_addr).ok_or(Error::BadXsdt)?;
    if &xsdt[..4] != b"XSDT" {
        return Err(Error::BadXsdt);
    }
    let mut machine = Machine::empty();
    let mut at = HEADER;
    while let Some(addr) = u64_at(xsdt, at) {
        at += 8;
        match table(mem, addr) {
            Some(body) => read_table(body, &mut machine),
            None => machine.bad_tables += 1,
        }
    }
    Ok(machine)
}

fn read_table(body: &[u8], m: &mut Machine) {
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&body[..4]);
    if m.table_count < MAX_TABLES {
        m.tables[m.table_count] = signature;
        m.table_count += 1;
    }
    // A table too short for a field leaves that field at its empty value.
    let _ = match &signature {
        b"APIC" => read_madt(body, m),
        b"GTDT" => read_gtdt(body, m),
        b"SPCR" => read_spcr(body, m),
        b"MCFG" => read_mcfg(body, m),
        b"FACP" => read_fadt(body, m),
        b"IORT" => read_iort(body, m),
        _ => Some(()),
    };
}

fn read_madt(b: &[u8], m: &mut Machine) -> Option<()> {
    // Local interrupt controller address + flags precede the entries.
    let mut at = HEADER + 8;
    while at + 2 <= b.len() {
        let kind = b[at];
        let len = b[at + 1] as usize;
        if len < 2 || at + len > b.len() {
            break;
        }
        let e = &b[at..at + len];
        match kind {
            // GICC: flags bit 0 enabled, bit 3 online capable.
            0x0B if len >= 76 => {
                let flags = u32_at(e, 12)?;
                if flags & 0b1001 != 0 {
                    if m.cpu_count < MAX_CPUS {
                        m.cpus[m.cpu_count] = Cpu {
                            mpidr: u64_at(e, 68)?,
                            gicc_base: u64_at(e, 32)?,
                            gicr_base: u64_at(e, 60)?,
                        };
                        m.cpu_count += 1;
                    } else {
                        m.cpus_dropped += 1;
                    }
                }
            }
            // GICD.
            0x0C if len >= 21 => {
                m.gicd_base = u64_at(e, 8)?;
                m.gic_version = e[20];
            }
            // GIC MSI frame (GICv2m).
            0x0D if len >= 16 => {
                if m.v2m_count == 0 {
                    m.v2m_base = u64_at(e, 8)?;
                }
                m.v2m_count += 1;
            }
            // GICR discovery range.
            0x0E if len >= 16 => {
                if m.gicr_range_base == 0 {
                    m.gicr_range_base = u64_at(e, 4)?;
                }
            }
            // GIC ITS.
            0x0F if len >= 16 => {
                if m.its_count == 0 {
                    m.its_base = u64_at(e, 8)?;
                }
                m.its_count += 1;
            }
            _ => {}
        }
        at += len;
    }
    Some(())
}

fn read_gtdt(b: &[u8], m: &mut Machine) -> Option<()> {
    // CntControlBase, reserved, then GSIV and flags pairs: secure EL1,
    // non-secure EL1, virtual.
    m.timer_phys_gsiv = u32_at(b, HEADER + 20)?;
    m.timer_virt_gsiv = u32_at(b, HEADER + 28)?;
    Some(())
}

fn read_spcr(b: &[u8], m: &mut Machine) -> Option<()> {
    // Interface type and 3 reserved bytes, then the register block as a
    // generic address: space, width, offset and access size, then the address.
    m.console_type = u32::from(*b.get(HEADER)?);
    m.console_base = u64_at(b, HEADER + 8)?;
    Some(())
}

/// The root complex of PCI segment 0 and its ID mappings to an ITS group. A
/// mapping through an SMMU is left out: this kernel does not program one, and a
/// device behind it would need the SMMU's own mapping.
fn read_iort(b: &[u8], m: &mut Machine) -> Option<()> {
    const ITS_GROUP: u8 = 0;
    const ROOT_COMPLEX: u8 = 2;
    let count = u32_at(b, HEADER)? as usize;
    let mut node = u32_at(b, HEADER + 4)? as usize;
    for _ in 0..count.min(64) {
        let kind = *b.get(node)?;
        let len = usize::from(u16_at(b, node + 1)?);
        if len == 0 {
            return None;
        }
        if kind == ROOT_COMPLEX && u32_at(b, node + 28)? == 0 {
            let maps = u32_at(b, node + 8)? as usize;
            let first = u32_at(b, node + 12)? as usize;
            for i in 0..maps.min(MAX_RID_MAPS) {
                let at = node + first + i * 20;
                let target = u32_at(b, at + 12)? as usize;
                if *b.get(target)? != ITS_GROUP || m.rid_map_count == MAX_RID_MAPS {
                    continue;
                }
                m.rid_maps[m.rid_map_count] =
                    (u32_at(b, at)?, u32_at(b, at + 4)?, u32_at(b, at + 8)?);
                m.rid_map_count += 1;
            }
        }
        node += len;
    }
    Some(())
}

/// The ITS device ID of PCI requester `rid` under `maps` (`Machine::rid_maps`);
/// `rid` itself when they map nothing (QEMU's identity mapping states it, a
/// missing table states nothing at all).
pub fn device_id(maps: &[(u32, u32, u32)], rid: u32) -> u32 {
    maps.iter()
        .find(|&&(base, span, _)| rid >= base && rid - base <= span)
        .map_or(rid, |&(base, _, out)| out + (rid - base))
}

/// Segment 0's entry: the segment the IORT mappings and requester IDs name.
fn read_mcfg(b: &[u8], m: &mut Machine) -> Option<()> {
    // 8 reserved bytes, then 16-byte entries: base address, segment, first
    // and last bus, 4 reserved.
    let mut e = HEADER + 8;
    while e + 16 <= b.len() {
        if u16_at(b, e + 8)? == 0 {
            m.ecam_base = u64_at(b, e)?;
            m.ecam_bus_start = *b.get(e + 10)?;
            m.ecam_bus_end = *b.get(e + 11)?;
            break;
        }
        e += 16;
    }
    Some(())
}

fn read_fadt(b: &[u8], m: &mut Machine) -> Option<()> {
    m.hw_reduced = u32_at(b, 112)? & (1 << 20) != 0;
    let arm = u16_at(b, 129)?;
    m.psci = arm & 1 != 0;
    m.psci_hvc = arm & 2 != 0;
    Some(())
}

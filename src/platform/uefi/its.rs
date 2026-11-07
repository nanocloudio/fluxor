// The GICv3 Interrupt Translation Service: how a PCI device's MSI becomes an
// LPI on this core. A device writes its event number to the ITS's translation
// register; the ITS looks the device up (its ID from the IORT), finds the event
// in that device's table, and raises the LPI the table names.
//
// The tables are the kernel's, carved at boot and never moved: the command
// queue, the device and collection tables the ITS asks for, one interrupt
// translation table per device, and the redistributor's LPI configuration and
// pending tables. Each is written, then cleaned to the point of coherency, so it
// is right whether or not the ITS snoops the CPU's caches.

use fluxor::arch::aarch64::{gic, mmio};
use fluxor::kernel::mem::carve;

use super::acpi;

const GITS_CTLR: usize = 0x0000;
const GITS_TYPER: usize = 0x0008;
const GITS_CBASER: usize = 0x0080;
const GITS_CWRITER: usize = 0x0088;
const GITS_CREADR: usize = 0x0090;
const GITS_BASER: usize = 0x0100;
const GITS_TRANSLATER: u64 = 0x1_0040;
const CTLR_ENABLED: u32 = 1;
const CTLR_QUIESCENT: u32 = 1 << 31;

const GICR_CTLR: usize = 0x0000;
const GICR_TYPER: usize = 0x0008;
const GICR_PROPBASER: usize = 0x0070;
const GICR_PENDBASER: usize = 0x0078;
const GICR_ENABLE_LPIS: u32 = 1;
const GICR_TYPER_PLPIS: u64 = 1;

/// Inner write-back read/write-allocate, inner shareable: the attributes every
/// table is offered with; an ITS or redistributor that cannot snoop says so by
/// reading back non-shareable, and the cleaning below covers it either way.
/// `GITS_CBASER` and `GITS_BASER<n>` hold InnerCache in [61:59];
/// `GICR_PROPBASER` and `GICR_PENDBASER` in [9:7]. Shareability is [11:10] in
/// all four.
const ITS_CACHE_WB: u64 = 0b111 << 59;
const RD_CACHE_WB: u64 = 0b111 << 7;
const SHARE_INNER: u64 = 1 << 10;
const VALID: u64 = 1 << 63;
/// `GITS_BASER<n>.Page_Size`, [9:8]: 4, 16 or 64 KiB.
const PAGE_SIZE_SHIFT: u64 = 8;

const SZ_4K: usize = 4 * 1024;
const SZ_16K: usize = 16 * 1024;
const SZ_64K: usize = 64 * 1024;
const COMMANDS: usize = SZ_64K;
/// LPI INTIDs 8192..16384: what the property table covers.
const LPI_ID_BITS: u64 = 14;
const LPI_COUNT: usize = (1 << LPI_ID_BITS) - gic::FIRST_LPI as usize;
/// An LPI configuration byte: priority in [7:2], bit 1 RES1, bit 0 enabled.
const LPI_PRIORITY_ENABLED: u8 = 0xA0 | (1 << 1) | 1;
/// Events per device: an ITT of 32 entries.
const EVENT_BITS: u64 = 5;
const MAX_DEVICES: usize = 8;
const COMMAND_SPINS: u32 = 10_000_000;

struct Its {
    base: usize,
    commands: usize,
    write_at: usize,
    properties: usize,
    target: u64,
    itt_entry: usize,
    /// Device IDs the device table covers: what MAPD may name.
    device_ids: u64,
    next_lpi: u32,
    devices: [(u32, u32); MAX_DEVICES],
    device_count: usize,
}

static mut ITS: Option<Its> = None;

/// Clean `[addr, addr + len)` to the point of coherency, by the smallest data
/// cache line `CTR_EL0.DminLine` reports.
fn clean(addr: usize, len: usize) {
    let ctr: u64;
    // SAFETY: reads a system register.
    unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let step = 4usize << ((ctr >> 16) & 0xF);
    let mut line = addr & !(step - 1);
    while line < addr + len {
        // SAFETY: cache maintenance by address on memory this module carved.
        unsafe { core::arch::asm!("dc cvac, {}", in(reg) line, options(nostack)) };
        line += step;
    }
    // SAFETY: a barrier.
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
}

fn carve_aligned(bytes: usize, align: usize) -> Option<usize> {
    carve::carve(bytes, align).map(|p| p as usize)
}

/// The bytes of one page of a `GITS_BASER<n>` value.
fn page_bytes(baser: u64) -> usize {
    match (baser >> PAGE_SIZE_SHIFT) & 3 {
        0 => SZ_4K,
        1 => SZ_16K,
        _ => SZ_64K,
    }
}

/// `GITS_BASER<n>.Page_Size` for a page of `bytes`.
fn page_field(bytes: usize) -> u64 {
    match bytes {
        SZ_4K => 0,
        SZ_16K => 1,
        _ => 2,
    }
}

impl Its {
    /// Queue one command and wait until the ITS has read it.
    fn command(&mut self, words: [u64; 4]) -> Result<(), &'static str> {
        let slot = self.commands + self.write_at;
        for (i, w) in words.iter().enumerate() {
            // SAFETY: inside the command queue this module carved.
            unsafe { core::ptr::write_volatile((slot + i * 8) as *mut u64, *w) };
        }
        clean(slot, 32);
        self.write_at = (self.write_at + 32) % COMMANDS;
        // SAFETY: the ITS frame the MADT described, mapped Device.
        unsafe { mmio::write64(self.base + GITS_CWRITER, self.write_at as u64) };
        for _ in 0..COMMAND_SPINS {
            // SAFETY: as above.
            let read = unsafe { mmio::read64(self.base + GITS_CREADR) };
            if read & 1 != 0 {
                return Err("its_command_stalled");
            }
            if (read & 0xF_FFE0) as usize == self.write_at {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("its_command_timeout")
    }

    fn sync(&mut self) -> Result<(), &'static str> {
        let target = self.target;
        self.command([0x05, 0, target, 0])
    }

    /// The device's translation table, mapping it on first use.
    fn device(&mut self, device_id: u32) -> Result<(), &'static str> {
        if self.devices[..self.device_count]
            .iter()
            .any(|&(d, _)| d == device_id)
        {
            return Ok(());
        }
        if u64::from(device_id) >= self.device_ids {
            return Err("its_device_id_out_of_range");
        }
        if self.device_count == MAX_DEVICES {
            return Err("its_devices_exhausted");
        }
        let bytes = (self.itt_entry << EVENT_BITS).max(256);
        let itt = carve_aligned(bytes, 256).ok_or("its_itt_alloc")?;
        clean(itt, bytes);
        self.command([
            0x08 | (u64::from(device_id) << 32),
            EVENT_BITS - 1,
            VALID | (itt as u64 & 0x000F_FFFF_FFFF_FF00),
            0,
        ])?;
        self.devices[self.device_count] = (device_id, 0);
        self.device_count += 1;
        Ok(())
    }

    /// One MSI for `device_id`, delivered as a new LPI bound to `event`.
    fn allocate(&mut self, device_id: u32, event: i32) -> Result<(u64, u32), &'static str> {
        self.device(device_id)?;
        let slot = self.devices[..self.device_count]
            .iter()
            .position(|&(d, _)| d == device_id)
            .ok_or("its_device_lost")?;
        let event_id = self.devices[slot].1;
        if event_id >= 1 << EVENT_BITS {
            return Err("its_events_exhausted");
        }
        if self.next_lpi as usize >= gic::FIRST_LPI as usize + LPI_COUNT {
            return Err("its_lpis_exhausted");
        }
        let lpi = self.next_lpi;
        let property = self.properties + (lpi - gic::FIRST_LPI) as usize;
        // SAFETY: inside the property table this module carved.
        unsafe { core::ptr::write_volatile(property as *mut u8, LPI_PRIORITY_ENABLED) };
        clean(property, 1);
        if gic::bind_lpi(lpi, event) != 0 {
            return Err("its_binding_table_full");
        }
        self.command([
            0x0A | (u64::from(device_id) << 32),
            u64::from(event_id) | (u64::from(lpi) << 32),
            0,
            0,
        ])?;
        self.command([
            0x0C | (u64::from(device_id) << 32),
            u64::from(event_id),
            0,
            0,
        ])?;
        self.sync()?;
        self.next_lpi += 1;
        self.devices[slot].1 += 1;
        Ok((self.base as u64 + GITS_TRANSLATER, event_id))
    }
}

/// Program the ITS's tables, give this core's redistributor its LPI tables, and
/// map collection 0 to this core.
///
/// # Safety
/// Once, on the boot core, with the MMU on, after the GICv3 is up.
pub unsafe fn init(machine: &acpi::Machine, redistributor: usize) -> Result<(), &'static str> {
    let base = machine.its_base as usize;
    if mmio::read64(redistributor + GICR_TYPER) & GICR_TYPER_PLPIS == 0 {
        return Err("lpis_unsupported");
    }
    if mmio::read32(redistributor + GICR_CTLR) & GICR_ENABLE_LPIS != 0 {
        // Once on, LPIs cannot be pointed at new tables.
        return Err("lpis_already_enabled");
    }
    mmio::write32(base + GITS_CTLR, 0);
    let mut spins = 0u32;
    while mmio::read32(base + GITS_CTLR) & CTLR_QUIESCENT == 0 {
        spins += 1;
        if spins == COMMAND_SPINS {
            return Err("its_not_quiescent");
        }
    }
    let typer = mmio::read64(base + GITS_TYPER);
    let itt_entry = (((typer >> 4) & 0xF) + 1) as usize;
    let device_bits = ((typer >> 13) & 0x1F) + 1;
    let physical_targets = (typer >> 19) & 1 != 0;

    let commands = carve_aligned(COMMANDS, SZ_64K).ok_or("its_queue_alloc")?;
    clean(commands, COMMANDS);
    mmio::write64(
        base + GITS_CBASER,
        VALID | ITS_CACHE_WB | SHARE_INNER | commands as u64 | (COMMANDS / SZ_4K - 1) as u64,
    );
    mmio::write64(base + GITS_CWRITER, 0);

    // Flat tables of at most 256 pages, the most `Size` can count. MAPD may
    // name only the device IDs the device table's pages cover.
    let mut device_ids = 1u64 << device_bits;
    for n in 0..8usize {
        let at = base + GITS_BASER + n * 8;
        let current = mmio::read64(at);
        let kind = (current >> 56) & 7;
        if kind == 0 {
            continue;
        }
        let entry = (((current >> 48) & 0x1F) + 1) as usize;
        // Devices: one entry per device ID; collections: this kernel uses one.
        let entries = if kind == 1 {
            1usize << device_bits.min(16)
        } else {
            64
        };
        let bytes = (entries * entry).next_multiple_of(SZ_64K).min(256 * SZ_64K);
        let table = carve_aligned(bytes, SZ_64K).ok_or("its_table_alloc")?;
        clean(table, bytes);
        let value = VALID
            | ITS_CACHE_WB
            | SHARE_INNER
            | table as u64
            | (current & (0x1F << 48))
            | (kind << 56);
        let program = |page: usize| {
            let pages = (bytes / page).min(256) as u64;
            mmio::write64(
                at,
                value | (page_field(page) << PAGE_SIZE_SHIFT) | (pages - 1),
            );
            mmio::read64(at)
        };
        // 64 KiB pages where the ITS takes them; otherwise the size it reads
        // back as supporting, with the table counted in that size's pages.
        let mut granted = program(SZ_64K);
        if page_bytes(granted) != SZ_64K {
            granted = program(page_bytes(granted));
        }
        if kind == 1 {
            let covered = ((granted & 0xFF) as usize + 1) * page_bytes(granted) / entry;
            device_ids = device_ids.min(covered as u64);
        }
    }

    let properties = carve_aligned(LPI_COUNT, SZ_64K).ok_or("its_properties_alloc")?;
    clean(properties, LPI_COUNT);
    let pending = carve_aligned(SZ_64K, SZ_64K).ok_or("its_pending_alloc")?;
    clean(pending, SZ_64K);
    mmio::write64(
        redistributor + GICR_PROPBASER,
        RD_CACHE_WB | SHARE_INNER | properties as u64 | (LPI_ID_BITS - 1),
    );
    mmio::write64(
        redistributor + GICR_PENDBASER,
        RD_CACHE_WB | SHARE_INNER | pending as u64,
    );
    mmio::write32(
        redistributor + GICR_CTLR,
        mmio::read32(redistributor + GICR_CTLR) | GICR_ENABLE_LPIS,
    );
    mmio::write32(base + GITS_CTLR, CTLR_ENABLED);

    let target = if physical_targets {
        redistributor as u64 & 0x000F_FFFF_FFFF_0000
    } else {
        ((mmio::read64(redistributor + GICR_TYPER) >> 8) & 0xFFFF) << 16
    };
    let mut its = Its {
        base,
        commands,
        write_at: 0,
        properties,
        target,
        itt_entry,
        device_ids,
        next_lpi: gic::FIRST_LPI,
        devices: [(0, 0); MAX_DEVICES],
        device_count: 0,
    };
    its.command([0x09, 0, VALID | target, 0])?;
    its.command([0x0D, 0, 0, 0])?;
    its.sync()?;
    log::info!(
        "[its] ready base={base:#x} device_bits={device_bits} device_ids={device_ids} itt_entry={itt_entry} pta={}",
        u8::from(physical_targets)
    );
    // SAFETY: the boot core, before any driver can ask for an MSI.
    ITS = Some(its);
    Ok(())
}

/// An MSI for the device with ITS device ID `device_id` (its requester ID
/// through the IORT), signalling `event`: the address and data its MSI-X table
/// entry takes. `None` with no ITS.
pub fn allocate(device_id: u32, event: i32) -> Option<Result<(u64, u32), &'static str>> {
    // SAFETY: this runtime steps on one core; set once at boot.
    let its = unsafe { (*core::ptr::addr_of_mut!(ITS)).as_mut()? };
    Some(its.allocate(device_id, event))
}

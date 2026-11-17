// PCI on a machine ACPI describes: MCFG's ECAM window, with the BARs the firmware
// assigned. The `pcie_device` contract's handle and selector live here, and the
// drivers above it cannot tell this machine from a Pi 5.
//
// Selectors: `@class=nvme` and `@class=ethernet` (exactly one match, as on any
// board), `@bdf=BB:DD.F`, and the two names a graph on a cloud or virtual machine
// uses: `boot_nvme`, the first NVMe controller, and `scratch_nvme`, the second,
// which a test may write to without touching the disk it booted from.

use fluxor::arch::aarch64::mmio;
use fluxor::kernel::sys::errno;

const MAX_DEVICES: usize = 32;
const MAX_BUSES: usize = 16;
const ECAM_FN_BYTES: usize = 1 << 12;
const NVME_CLASS: u32 = 0x01_08_02;
const ETHERNET_CLASS: u32 = 0x02_00_00;

const CFG_ID: usize = 0x00;
const CFG_COMMAND: usize = 0x04;
const CFG_CLASS: usize = 0x08;
const CFG_HEADER: usize = 0x0C;
const CFG_BAR0: usize = 0x10;
const CFG_BUSES: usize = 0x18;
const CFG_CAP_PTR: usize = 0x34;
const CMD_MEMORY: u32 = 1 << 1;
const CMD_BUS_MASTER: u32 = 1 << 2;
const CAP_MSIX: u8 = 0x11;

#[derive(Clone, Copy)]
pub struct Device {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    pub msix: u16,
    bound: bool,
    is_bridge: bool,
}

impl Device {
    const EMPTY: Self = Device {
        bus: 0,
        dev: 0,
        func: 0,
        vendor: 0,
        device: 0,
        class: 0,
        msix: 0,
        bound: false,
        is_bridge: false,
    };
}

struct Bus {
    ecam: usize,
    first_bus: u8,
    last_bus: u8,
    devices: [Device; MAX_DEVICES],
    /// Each device's BAR sizes, probed the first time a BAR is mapped; 0
    /// until then.
    bar_sizes: [[u64; 6]; MAX_DEVICES],
    count: usize,
}

static mut BUS: Bus = Bus {
    ecam: 0,
    first_bus: 0,
    last_bus: 0,
    devices: [Device::EMPTY; MAX_DEVICES],
    bar_sizes: [[0; 6]; MAX_DEVICES],
    count: 0,
};

fn bus() -> &'static mut Bus {
    // SAFETY: this runtime steps on one core, and `pcie_device` calls arrive on it.
    unsafe { &mut *core::ptr::addr_of_mut!(BUS) }
}

fn config(b: &Bus, bus: u8, dev: u8, func: u8, reg: usize) -> Option<usize> {
    if bus < b.first_bus || bus > b.last_bus || dev >= 32 || func >= 8 || reg >= ECAM_FN_BYTES {
        return None;
    }
    // MCFG states the window's base as bus 0's, whichever bus it starts at.
    let function = (usize::from(bus) << 8) | (usize::from(dev) << 3) | usize::from(func);
    Some(b.ecam + function * ECAM_FN_BYTES + (reg & !3))
}

fn read(b: &Bus, bus: u8, dev: u8, func: u8, reg: usize) -> u32 {
    match config(b, bus, dev, func, reg) {
        // SAFETY: inside the ECAM window MCFG described, mapped Device.
        Some(addr) => unsafe { mmio::read32(addr) },
        None => u32::MAX,
    }
}

fn write(b: &Bus, bus: u8, dev: u8, func: u8, reg: usize, value: u32) -> bool {
    match config(b, bus, dev, func, reg) {
        Some(addr) => {
            // SAFETY: as in `read`.
            unsafe { mmio::write32(addr, value) };
            true
        }
        None => false,
    }
}

/// The MSI-X table size the device's capability states; 0 without one.
fn msix_vectors(b: &Bus, bus: u8, dev: u8, func: u8) -> u16 {
    const CAP_LIST: u32 = 1 << 20;
    if read(b, bus, dev, func, CFG_COMMAND) & CAP_LIST == 0 {
        return 0;
    }
    let mut at = (read(b, bus, dev, func, CFG_CAP_PTR) & 0xFC) as usize;
    for _ in 0..48 {
        if at == 0 {
            return 0;
        }
        let head = read(b, bus, dev, func, at);
        if head as u8 == CAP_MSIX {
            return (((head >> 16) & 0x7FF) + 1) as u16;
        }
        at = ((head >> 8) & 0xFC) as usize;
    }
    0
}

/// Read what is on the bus. Bridges add the buses the firmware numbered behind
/// them; nothing is reassigned. Returns the number of devices found.
pub fn enumerate(ecam: u64, first_bus: u8, last_bus: u8) -> usize {
    let b = bus();
    b.ecam = ecam as usize;
    b.first_bus = first_bus;
    b.last_bus = last_bus;
    b.count = 0;
    b.bar_sizes = [[0; 6]; MAX_DEVICES];
    let mut pending = [first_bus; MAX_BUSES];
    let (mut head, mut tail) = (0usize, 1usize);
    while head < tail {
        let on = pending[head];
        head += 1;
        for dev in 0..32u8 {
            let mut functions = 1u8;
            let mut func = 0u8;
            while func < functions {
                let id = read(b, on, dev, func, CFG_ID);
                if id & 0xFFFF == 0xFFFF {
                    func += 1;
                    continue;
                }
                let header = read(b, on, dev, func, CFG_HEADER) >> 16;
                if func == 0 && header & 0x80 != 0 {
                    functions = 8;
                }
                let is_bridge = header & 0x7F == 1;
                if is_bridge && tail < MAX_BUSES {
                    let secondary = (read(b, on, dev, func, CFG_BUSES) >> 8) as u8;
                    if secondary > on {
                        pending[tail] = secondary;
                        tail += 1;
                    }
                }
                if b.count < MAX_DEVICES {
                    let msix = msix_vectors(b, on, dev, func);
                    let class = read(b, on, dev, func, CFG_CLASS) >> 8;
                    b.devices[b.count] = Device {
                        bus: on,
                        dev,
                        func,
                        vendor: id as u16,
                        device: (id >> 16) as u16,
                        class,
                        msix,
                        bound: false,
                        is_bridge,
                    };
                    b.count += 1;
                }
                func += 1;
            }
        }
    }
    b.count
}

pub fn devices() -> &'static [Device] {
    let b = bus();
    &b.devices[..b.count]
}

fn nth_of_class(class: u32, nth: usize) -> Option<usize> {
    devices()
        .iter()
        .enumerate()
        .filter(|(_, d)| d.class == class && !d.is_bridge)
        .nth(nth)
        .map(|(i, _)| i)
}

fn parse_hex(text: &str) -> Option<u8> {
    u8::from_str_radix(text, 16).ok()
}

/// `BB:DD.F`, in hexadecimal as `lspci` prints it.
fn parse_bdf(text: &str) -> Option<(u8, u8, u8)> {
    let (bus, rest) = text.split_once(':')?;
    let (dev, func) = rest.split_once('.')?;
    Some((parse_hex(bus)?, parse_hex(dev)?, parse_hex(func)?))
}

fn resolve(selector: &str) -> Result<usize, i32> {
    if let Some(name) = selector.strip_prefix("@class=") {
        let class = match name {
            "nvme" => NVME_CLASS,
            "ethernet" => ETHERNET_CLASS,
            _ => return Err(errno::EINVAL),
        };
        let found = nth_of_class(class, 0).ok_or(errno::ENODEV)?;
        return match nth_of_class(class, 1) {
            Some(_) => Err(errno::EBUSY),
            None => Ok(found),
        };
    }
    if let Some(text) = selector.strip_prefix("@bdf=") {
        let (bus, dev, func) = parse_bdf(text).ok_or(errno::EINVAL)?;
        return devices()
            .iter()
            .position(|d| d.bus == bus && d.dev == dev && d.func == func)
            .ok_or(errno::ENODEV);
    }
    match selector {
        "boot_nvme" => nth_of_class(NVME_CLASS, 0).ok_or(errno::ENODEV),
        "scratch_nvme" => nth_of_class(NVME_CLASS, 1).ok_or(errno::ENODEV),
        _ => Err(errno::ENODEV),
    }
}

/// Bind the device `selector` names; the bound handle.
pub fn bind(selector: &[u8]) -> i32 {
    let Ok(text) = core::str::from_utf8(selector) else {
        return errno::EINVAL;
    };
    let selector = text.trim_end_matches('\0').trim();
    let index = match resolve(selector) {
        Ok(index) => index,
        Err(e) => return e,
    };
    let b = bus();
    let d = b.devices[index];
    b.devices[index].bound = true;
    // The firmware may have left a device it did not boot from switched off.
    let command = read(b, d.bus, d.dev, d.func, CFG_COMMAND) & 0xFFFF;
    write(
        b,
        d.bus,
        d.dev,
        d.func,
        CFG_COMMAND,
        command | CMD_MEMORY | CMD_BUS_MASTER,
    );
    log::info!(
        "[pcie_device] bound '{selector}' {:02x}:{:02x}.{:x} vid={:04x} did={:04x}",
        d.bus,
        d.dev,
        d.func,
        d.vendor,
        d.device
    );
    index as i32
}

/// The device index a bound handle's index names.
fn bound(handle: i32) -> Option<usize> {
    let index = usize::try_from(handle).ok()?;
    devices().get(index).filter(|d| d.bound).map(|_| index)
}

/// Device-register aperture `index`, `(address, len)`: the memory BARs of
/// the enumerated devices, in device then BAR order, where the kernel reaches
/// them. Never RAM, never the interrupt controller. `None` past the last, and
/// for a BAR of 4 GiB or more, which an aperture answer cannot state.
pub fn aperture(index: u8) -> Option<(u64, u64)> {
    let mut left = usize::from(index);
    for (i, d) in devices().iter().enumerate() {
        let bars = if d.is_bridge { 2 } else { 6 };
        for n in 0..bars {
            let Some(address) = bar_address(d, n) else {
                continue;
            };
            if left > 0 {
                left -= 1;
                continue;
            }
            let size = bar_size(i, n)?;
            u32::try_from(size).ok()?;
            return Some((reachable(address, size)?, size));
        }
    }
    None
}

/// Handles the PCI table hands out at once: one per device.
pub const HANDLE_SLOTS: usize = MAX_DEVICES;

/// The requester ID of the device a handle is bound to: bus, device, function.
pub fn requester_id(handle: i32) -> Option<u32> {
    let d = devices()[bound(handle)?];
    Some((u32::from(d.bus) << 8) | (u32::from(d.dev) << 3) | u32::from(d.func))
}

pub fn close(handle: i32) -> i32 {
    match bound(handle) {
        Some(index) => {
            bus().devices[index].bound = false;
            0
        }
        None => errno::EINVAL,
    }
}

/// `CFG_READ32`: arg = `[offset u16][0 u16]`, the word written to arg[4..8].
pub fn cfg_read(handle: i32, arg: &mut [u8]) -> i32 {
    let Some(index) = bound(handle).filter(|_| arg.len() >= 8) else {
        return errno::EINVAL;
    };
    let offset = u16::from_le_bytes([arg[0], arg[1]]) as usize;
    let d = bus().devices[index];
    let Some(addr) = config(bus(), d.bus, d.dev, d.func, offset) else {
        return errno::EINVAL;
    };
    // SAFETY: inside the ECAM window MCFG described, mapped Device.
    let value = unsafe { mmio::read32(addr) };
    arg[4..8].copy_from_slice(&value.to_le_bytes());
    0
}

/// `CFG_WRITE32`: arg = `[offset u16][0 u16][value u32]`.
pub fn cfg_write(handle: i32, arg: &[u8]) -> i32 {
    let Some(index) = bound(handle).filter(|_| arg.len() >= 8) else {
        return errno::EINVAL;
    };
    let offset = u16::from_le_bytes([arg[0], arg[1]]) as usize;
    let value = u32::from_le_bytes([arg[4], arg[5], arg[6], arg[7]]);
    let d = bus().devices[index];
    if write(bus(), d.bus, d.dev, d.func, offset, value) {
        0
    } else {
        errno::EINVAL
    }
}

/// Where the kernel reaches the `len` bytes at physical `address`. Every
/// address the identity map covers and RAM does not hold is Device from boot.
/// Above it, the top gigabytes of the map serve as aliases, one per physical
/// gigabyte asked for, so a span there must lie inside one gigabyte.
fn reachable(address: u64, len: u64) -> Option<u64> {
    const GIB: u64 = 1 << 30;
    const IDENTITY_END: u64 = 512 * GIB;
    /// What `TCR_VALUE`'s output size can name.
    const PA_END: u64 = 1 << 40;
    const ALIASES: usize = 8;
    static mut ALIASED: [u64; ALIASES] = [u64::MAX; ALIASES];
    let end = address.checked_add(len)?;
    if end <= IDENTITY_END {
        return Some(address);
    }
    if address < IDENTITY_END || end > PA_END || address % GIB + len > GIB {
        return None;
    }
    let gb = address / GIB;
    // SAFETY: this runtime steps on one core. The alias slots are the top eight
    // gigabytes below 512 GB, which hold neither RAM nor a device on the
    // machines this runs on, so nothing reaches them except through an alias.
    unsafe {
        let aliased = &mut *core::ptr::addr_of_mut!(ALIASED);
        let slot = match aliased.iter().position(|&g| g == gb) {
            Some(slot) => slot,
            None => {
                let slot = aliased.iter().position(|&g| g == u64::MAX)?;
                aliased[slot] = gb;
                fluxor::arch::aarch64::boot_mmu::alias_gb(
                    511 - slot,
                    gb,
                    fluxor::arch::aarch64::boot_mmu::Kind::Device,
                );
                slot
            }
        };
        Some(((511 - slot) as u64) * GIB + address % GIB)
    }
}

/// The memory address the firmware assigned to BAR `n`: six BARs in a type 0
/// header, two in a bridge's. A 64-bit BAR takes the next slot for its high
/// half, so it cannot be the last.
fn bar_address(d: &Device, n: usize) -> Option<u64> {
    let bars = if d.is_bridge { 2 } else { 6 };
    if n >= bars {
        return None;
    }
    let b = bus();
    let low = read(b, d.bus, d.dev, d.func, CFG_BAR0 + n * 4);
    if low & 1 != 0 {
        return None;
    }
    let is_64 = (low >> 1) & 3 == 2;
    if is_64 && n + 1 >= bars {
        return None;
    }
    let high = if is_64 {
        u64::from(read(b, d.bus, d.dev, d.func, CFG_BAR0 + (n + 1) * 4))
    } else {
        0
    };
    match (high << 32) | u64::from(low & !0xF) {
        0 => None,
        address => Some(address),
    }
}

/// The size of BAR `n` of device `index`, by the standard probe: all ones
/// written, and the bits that read back set are the address bits the BAR
/// decodes. Memory decode is off meanwhile, so the device answers nothing at
/// a half-written address. Probed once and kept; `None` for a BAR that
/// decodes nothing.
fn bar_size(index: usize, n: usize) -> Option<u64> {
    let b = bus();
    if b.bar_sizes[index][n] != 0 {
        return Some(b.bar_sizes[index][n]);
    }
    let d = b.devices[index];
    let reg = CFG_BAR0 + n * 4;
    let probe = |reg: usize| {
        let kept = read(b, d.bus, d.dev, d.func, reg);
        write(b, d.bus, d.dev, d.func, reg, u32::MAX);
        let mask = read(b, d.bus, d.dev, d.func, reg);
        write(b, d.bus, d.dev, d.func, reg, kept);
        (kept, mask)
    };
    let command = read(b, d.bus, d.dev, d.func, CFG_COMMAND) & 0xFFFF;
    write(b, d.bus, d.dev, d.func, CFG_COMMAND, command & !CMD_MEMORY);
    let (low, mask_low) = probe(reg);
    let mask_high = if (low >> 1) & 3 == 2 {
        probe(reg + 4).1
    } else {
        u32::MAX
    };
    write(b, d.bus, d.dev, d.func, CFG_COMMAND, command);
    let mask = (u64::from(mask_high) << 32) | u64::from(mask_low & !0xF);
    let size = (!mask).wrapping_add(1);
    (size != 0).then(|| {
        b.bar_sizes[index][n] = size;
        size
    })
}

/// `BAR_MAP`: in `[bar u8]`, out `[addr u64][len u32]`.
pub fn bar_map(handle: i32, arg: &mut [u8]) -> i32 {
    let Some(index) = bound(handle).filter(|_| arg.len() >= 12) else {
        return errno::EINVAL;
    };
    let d = bus().devices[index];
    let n = usize::from(arg[0]);
    let Some((address, size)) = bar_address(&d, n).and_then(|a| Some((a, bar_size(index, n)?)))
    else {
        return errno::ENODEV;
    };
    let Ok(len) = u32::try_from(size) else {
        return errno::ERANGE;
    };
    let Some(address) = reachable(address, size) else {
        return errno::ENODEV;
    };
    arg[0..8].copy_from_slice(&address.to_le_bytes());
    arg[8..12].copy_from_slice(&len.to_le_bytes());
    0
}

/// `INFO`: the 32-byte record `[vendor u16][device u16][class u32][bus u8]
/// [dev u8][func u8][0; 21]`.
pub fn info(handle: i32, arg: &mut [u8]) -> i32 {
    let Some(index) = bound(handle).filter(|_| arg.len() >= 32) else {
        return errno::EINVAL;
    };
    let d = bus().devices[index];
    let out = &mut arg[..32];
    out.fill(0);
    out[0..2].copy_from_slice(&d.vendor.to_le_bytes());
    out[2..4].copy_from_slice(&d.device.to_le_bytes());
    out[4..8].copy_from_slice(&d.class.to_le_bytes());
    out[8] = d.bus;
    out[9] = d.dev;
    out[10] = d.func;
    32
}

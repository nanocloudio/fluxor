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
    count: usize,
}

static mut BUS: Bus = Bus {
    ecam: 0,
    first_bus: 0,
    last_bus: 0,
    devices: [Device::EMPTY; MAX_DEVICES],
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

/// # Safety
/// `arg`/`arg_len` describe a caller-owned selector.
pub unsafe fn bind(arg: *const u8, arg_len: usize) -> i32 {
    let bytes = core::slice::from_raw_parts(arg, arg_len);
    let Ok(text) = core::str::from_utf8(bytes) else {
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
    fluxor::kernel::ipc::fd::tag_fd(fluxor::kernel::ipc::fd::FD_TAG_PCIE_DEVICE, index as i32)
}

fn bound(handle: i32) -> Option<usize> {
    if handle < 0 {
        return None;
    }
    let (tag, slot) = fluxor::kernel::ipc::fd::untag_fd(handle);
    if tag != fluxor::kernel::ipc::fd::FD_TAG_PCIE_DEVICE {
        return None;
    }
    devices()
        .get(slot as usize)
        .filter(|d| d.bound)
        .map(|_| slot as usize)
}

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

/// # Safety
/// `arg` holds `arg_len` caller-owned bytes.
pub unsafe fn cfg_read(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(index) = bound(handle).filter(|_| !arg.is_null() && arg_len >= 8) else {
        return errno::EINVAL;
    };
    let offset = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
    let d = bus().devices[index];
    let Some(addr) = config(bus(), d.bus, d.dev, d.func, offset) else {
        return errno::EINVAL;
    };
    // SAFETY: inside the ECAM window MCFG described, mapped Device.
    let value = mmio::read32(addr).to_le_bytes();
    core::ptr::copy_nonoverlapping(value.as_ptr(), arg.add(4), 4);
    0
}

/// # Safety
/// `arg` holds `arg_len` caller-owned bytes.
pub unsafe fn cfg_write(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(index) = bound(handle).filter(|_| !arg.is_null() && arg_len >= 8) else {
        return errno::EINVAL;
    };
    let offset = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
    let value = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
    let d = bus().devices[index];
    if write(bus(), d.bus, d.dev, d.func, offset, value) {
        0
    } else {
        errno::EINVAL
    }
}

/// Where the kernel reaches physical `address`. Every address the identity map
/// covers and RAM does not hold is Device from boot. Above it, the top gigabytes
/// of the map serve as aliases, one per physical gigabyte asked for.
fn reachable(address: u64) -> Option<u64> {
    const GIB: u64 = 1 << 30;
    const IDENTITY_END: u64 = 512 * GIB;
    /// What `TCR_VALUE`'s output size can name.
    const PA_END: u64 = 1 << 40;
    const ALIASES: usize = 8;
    static mut ALIASED: [u64; ALIASES] = [u64::MAX; ALIASES];
    if address < IDENTITY_END {
        return Some(address);
    }
    if address >= PA_END {
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

/// # Safety
/// `arg` holds `arg_len` caller-owned bytes.
pub unsafe fn bar_map(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(index) = bound(handle).filter(|_| !arg.is_null() && arg_len >= 10) else {
        return errno::EINVAL;
    };
    let d = bus().devices[index];
    let Some(address) = bar_address(&d, usize::from(*arg)).and_then(reachable) else {
        return errno::ENODEV;
    };
    let bytes = address.to_le_bytes();
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg.add(2), 8);
    0
}

/// # Safety
/// `arg` holds `arg_len` caller-owned bytes.
pub unsafe fn info(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(index) = bound(handle).filter(|_| !arg.is_null() && arg_len >= 32) else {
        return errno::EINVAL;
    };
    let d = bus().devices[index];
    core::ptr::write_bytes(arg, 0, 32);
    core::ptr::copy_nonoverlapping(d.vendor.to_le_bytes().as_ptr(), arg, 2);
    core::ptr::copy_nonoverlapping(d.device.to_le_bytes().as_ptr(), arg.add(2), 2);
    core::ptr::copy_nonoverlapping(d.class.to_le_bytes().as_ptr(), arg.add(4), 4);
    *arg.add(8) = d.bus;
    *arg.add(9) = d.dev;
    *arg.add(10) = d.func;
    32
}

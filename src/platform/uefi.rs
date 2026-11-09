// Platform: UEFI-booted bare metal — aarch64.
//
// Entered from the UEFI loader (`crates/fluxor-uefi-loader`) at the image's
// link address with x0 = `&BootInfo`, the MMU and data cache off, at EL1 (a
// virtual machine) or EL2 (bare metal). The loader has already left the
// firmware's boot services: from here the kernel knows the machine only
// through `BootInfo` — the memory map, the ACPI root and the console UART the
// firmware described — and calls no firmware service.
//
// `_start` opens with the image's `KernelHeader`, which the loader reads to
// place the image and reserve its RAM, then drops to EL1, installs the vectors,
// sets up FP/SIMD, the boot stack and BSS and calls `uefi_main`. That checks the
// handoff, maps the machine from the firmware's memory map, reads its ACPI
// tables, brings up the interrupt controller and the timer and proves each
// with a self-test, wakes the other cores, enumerates PCI, instantiates the
// graph and runs it on the boot core. Each stage is reported on the console
// UART as it is reached.
//
// With the MMU off every data access is Device memory, where an unaligned
// access faults. The target (`aarch64-unknown-none`) compiles with
// `strict-align`, and the handoff is read field by field at each field's
// own width.

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use fluxor::arch::aarch64::boot_mmu::{self, Kind};
use fluxor::arch::aarch64::{cpu, exception, gic, mmio, psci, timer};
use fluxor::boot::{
    BootInfo, MemKind, MemRegion, BOOT_INFO_MAGIC, CONSOLE_16550, CONSOLE_16550_GAS, CONSOLE_PL011,
    CONSOLE_SBSA,
};
use fluxor::kernel::exec::domains;

#[path = "uefi/acpi.rs"]
mod acpi;
#[path = "uefi/devices.rs"]
mod devices;
#[path = "uefi/hal.rs"]
mod hal;
#[path = "uefi/its.rs"]
mod its;
#[path = "uefi/pci.rs"]
mod pci;
#[path = "uefi/smp.rs"]
mod smp;

extern "C" {
    static __kernel_load_base: u8;
    static __end_block_addr: u8;
    static __end_data_addr: u8;
    static __stack_guard: u8;
    static __stack_start: u8;
    static __stack_end: u8;
}

global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    ".type _start, @function",
    "_start:",
    // The header (`KernelHeader`): a branch over it, then its fields.
    "    b 1f",
    "    .word 0",
    "    .ascii \"FLXUEFI1\"",
    "    .quad __kernel_load_base",
    "    .quad __kernel_ram_end",
    "    .quad __kernel_bytes",
    "1:",
    // Interrupts masked until the kernel has vectors of its own. The
    // handoff contract masks them already; masking here means nothing
    // depends on the loader having done so.
    "    msr daifset, #0xf",
    "    mov x19, x0",
    // FP/SIMD on: CPACR_EL1.FPEN = 0b11; at EL2, CPTR_EL2.TFP (bit 10 with
    // HCR_EL2.E2H clear) cleared as well.
    "    mrs x9, CurrentEL",
    "    cmp x9, #(2 << 2)",
    "    b.ne 6f",
    "    mrs x9, cptr_el2",
    "    bic x9, x9, #(1 << 10)",
    "    msr cptr_el2, x9",
    "6:",
    // The kernel runs at EL1, wherever the firmware handed it over.
    fluxor::drop_to_el1!("x9", "x10", "2f"),
    "2:",
    "    adr x9, exception_vectors",
    "    msr vbar_el1, x9",
    "    mov x9, #(3 << 20)",
    "    msr cpacr_el1, x9",
    "    isb",
    "    msr SPSel, #1",
    "    isb",
    "    ldr x9, =__stack_end",
    "    mov sp, x9",
    "    ldr x0, =__bss_start",
    "    ldr x1, =__bss_end",
    "3:  cmp x0, x1",
    "    b.hs 4f",
    "    str xzr, [x0], #8",
    "    b 3b",
    "4:  mov x0, x19",
    "    bl uefi_main",
    "5:  wfi",
    "    b 5b",
);

/// The console UART the loader found in the firmware's SPCR table.
#[derive(Clone, Copy)]
struct Console {
    kind: u32,
    base: usize,
    /// Register spacing for a 16550: the SPCR access width, 1 if unstated.
    stride: usize,
}

impl Console {
    fn from_boot(info: &BootInfo) -> Option<Self> {
        let stride = match info.console_access_bytes {
            0 => 1,
            n => n as usize,
        };
        match info.console_type {
            CONSOLE_PL011 | CONSOLE_SBSA | CONSOLE_16550 | CONSOLE_16550_GAS
                if info.console_base != 0 =>
            {
                Some(Console {
                    kind: info.console_type,
                    base: info.console_base as usize,
                    stride,
                })
            }
            _ => None,
        }
    }

    fn putc(&self, c: u8) {
        // SAFETY: the register block the firmware described as this machine's
        // console; with the MMU off it is Device memory, accessed at the width
        // its interface defines.
        unsafe {
            match self.kind {
                CONSOLE_PL011 | CONSOLE_SBSA => {
                    // FR.TXFF (bit 5) set while the transmit FIFO is full.
                    while mmio::read32(self.base + 0x18) & (1 << 5) != 0 {}
                    mmio::write32(self.base, u32::from(c));
                }
                _ => {
                    // LSR.THRE (bit 5) set when the holding register is empty.
                    let lsr = self.base + 5 * self.stride;
                    if self.stride >= 4 {
                        while mmio::read32(lsr) & (1 << 5) == 0 {}
                        mmio::write32(self.base, u32::from(c));
                    } else {
                        while mmio::read8(lsr) & (1 << 5) == 0 {}
                        mmio::write8(self.base, c);
                    }
                }
            }
        }
    }

    /// One byte if the transmitter has room, without waiting.
    fn try_putc(&self, c: u8) -> bool {
        // SAFETY: as `putc`, polling the same status bits once.
        unsafe {
            match self.kind {
                CONSOLE_PL011 | CONSOLE_SBSA => {
                    if mmio::read32(self.base + 0x18) & (1 << 5) != 0 {
                        return false;
                    }
                    mmio::write32(self.base, u32::from(c));
                }
                _ => {
                    let lsr = self.base + 5 * self.stride;
                    let status = if self.stride >= 4 {
                        mmio::read32(lsr)
                    } else {
                        u32::from(mmio::read8(lsr))
                    };
                    if status & (1 << 5) == 0 {
                        return false;
                    }
                    if self.stride >= 4 {
                        mmio::write32(self.base, u32::from(c));
                    } else {
                        mmio::write8(self.base, c);
                    }
                }
            }
        }
        true
    }

    fn puts(&self, s: &str) {
        let p = s.as_ptr();
        for i in 0..s.len() {
            // SAFETY: within `s`.
            let c = unsafe { byte_at(p, i) };
            if c == b'\n' {
                self.putc(b'\r');
            }
            self.putc(c);
        }
    }

    fn hex(&self, v: u64) {
        self.puts("0x");
        let mut started = false;
        for shift in (0..16).rev() {
            let d = ((v >> (shift * 4)) & 0xF) as u8;
            if d != 0 || started || shift == 0 {
                started = true;
                self.putc(if d < 10 { b'0' + d } else { b'a' + d - 10 });
            }
        }
    }

    fn dec(&self, mut v: u64) {
        let mut div = 1u64;
        while v / div >= 10 {
            div *= 10;
        }
        loop {
            self.putc(b'0' + (v / div) as u8);
            v %= div;
            if div == 1 {
                break;
            }
            div /= 10;
        }
    }
}

/// One byte of a string, read as one byte: with the MMU off every access is to
/// Device memory, where the wider load the compiler might merge it into faults.
///
/// # Safety
/// `p + i` is inside a live allocation.
unsafe fn byte_at(p: *const u8, i: usize) -> u8 {
    core::ptr::read_volatile(p.add(i))
}

/// Bytes of usable RAM in the loader's memory map.
fn usable_bytes(info: &BootInfo) -> u64 {
    let regions = info.regions as *const MemRegion;
    let mut total = 0u64;
    for i in 0..info.region_count as usize {
        // SAFETY: the loader's region array, `region_count` entries, each
        // naturally aligned; read field by field so no access is wider than
        // the field.
        let (len, kind) = unsafe {
            let r = regions.add(i);
            (
                core::ptr::read_volatile(core::ptr::addr_of!((*r).len)),
                core::ptr::read_volatile(core::ptr::addr_of!((*r).kind)),
            )
        };
        if kind == MemKind::Usable {
            total += len;
        }
    }
    total
}

/// The console, for the exception path, which has only a function pointer.
static mut CONSOLE: Option<Console> = None;

fn console_sink(bytes: &[u8]) {
    // SAFETY: written once by the boot core before the sink is installed.
    if let Some(con) = unsafe { core::ptr::addr_of!(CONSOLE).read() } {
        for &b in bytes {
            con.putc(b);
        }
    }
}

/// As many bytes as the console takes now: the kernel's binary-safe serial path
/// and the log drain's sink, neither of which may wait.
pub fn serial_write(bytes: &[u8]) -> usize {
    // SAFETY: written once by the boot core before anything calls this.
    let Some(con) = (unsafe { core::ptr::addr_of!(CONSOLE).read() }) else {
        return bytes.len();
    };
    bytes.iter().take_while(|&&b| con.try_putc(b)).count()
}

struct ConsoleTx;

impl fluxor::platform::debug::DebugTx for ConsoleTx {
    fn write(&mut self, bytes: &[u8]) -> usize {
        serial_write(bytes)
    }
}

static mut DRAIN: fluxor::platform::debug::DebugDrain<1024> =
    fluxor::platform::debug::DebugDrain::new();

/// Move queued log bytes to the console. The run loop only.
fn drain_log() {
    exception::report_core_faults();
    // SAFETY: the log ring's one local consumer, on the one core stepping.
    unsafe { (*core::ptr::addr_of_mut!(DRAIN)).poll(&mut ConsoleTx) };
}

struct RingLogger;

impl log::Log for RingLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        use core::fmt::Write;
        struct Line {
            buf: [u8; 256],
            at: usize,
        }
        impl Write for Line {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let take = s.len().min(self.buf.len() - 2 - self.at);
                self.buf[self.at..self.at + take].copy_from_slice(&s.as_bytes()[..take]);
                self.at += take;
                Ok(())
            }
        }
        let mut line = Line {
            buf: [0; 256],
            at: 0,
        };
        let _ = core::fmt::write(&mut line, *record.args());
        line.buf[line.at] = b'\r';
        line.buf[line.at + 1] = b'\n';
        fluxor::kernel::sys::log_ring::push_record(&line.buf[..line.at + 2]);
    }
    fn flush(&self) {}
}

/// The counter's frequency and its value at entry, for `t_us`.
struct Clock {
    freq: u64,
    start: u64,
}

impl Clock {
    fn now() -> u64 {
        let v: u64;
        // SAFETY: reads the counter, which EL1 may always read.
        unsafe { core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nostack)) };
        v
    }

    fn start() -> Self {
        let freq: u64;
        // SAFETY: reads a system register.
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack)) };
        Clock {
            freq: freq.max(1),
            start: Self::now(),
        }
    }

    fn elapsed_us(&self) -> u64 {
        // Scaled in 128 bits: dividing by `freq / 1_000_000` would truncate a
        // frequency that is not a whole number of megahertz.
        (u128::from(Self::now() - self.start) * 1_000_000 / u128::from(self.freq)) as u64
    }

    fn elapsed_s(&self) -> u64 {
        (Self::now() - self.start) / self.freq
    }
}

/// One memory-map region, read at the widths of its fields.
fn region(info: &BootInfo, i: usize) -> (u64, u64, MemKind) {
    let r = (info.regions as *const MemRegion).wrapping_add(i);
    // SAFETY: `i` is below `region_count`; the loader's array, naturally
    // aligned, read field by field so no access is wider than the field.
    unsafe {
        (
            core::ptr::read_volatile(core::ptr::addr_of!((*r).base)),
            core::ptr::read_volatile(core::ptr::addr_of!((*r).len)),
            core::ptr::read_volatile(core::ptr::addr_of!((*r).kind)),
        )
    }
}

/// Whether the map says `[lo, hi)` holds memory the kernel may cache: anything
/// the firmware described except its MMIO.
fn holds_ram(info: &BootInfo, lo: u64, hi: u64) -> bool {
    (0..info.region_count as usize).any(|i| {
        let (base, len, kind) = region(info, i);
        kind != MemKind::Mmio && base < hi && base + len > lo
    })
}

/// The map of this boot, for a check made after the handoff was read.
static mut BOOT_INFO: *const BootInfo = core::ptr::null();

/// Whether the firmware's map says `addr` is memory.
pub fn is_ram(addr: u64) -> bool {
    // SAFETY: written once by the boot core before any driver can ask.
    let info = unsafe { BOOT_INFO };
    // SAFETY: the loader's handoff, which lives for the whole boot.
    !info.is_null() && holds_ram(unsafe { &*info }, addr, addr.saturating_add(1))
}

const GIB: u64 = 1 << 30;
const BLOCK_2M: u64 = 2 << 20;

/// The identity map of this machine, from the firmware's memory map: what holds
/// RAM is cacheable, every other address is Device and never executed, so
/// whatever the machine has there is reachable once ACPI says where.
///
/// # Safety
/// Boot core, MMU off, once.
unsafe fn build_map(info: &BootInfo) {
    let kernel = core::ptr::addr_of!(__kernel_load_base) as u64;
    let kernel_gb = (kernel / GIB) as usize;
    for gb in 0..512usize {
        let lo = (gb as u64) * GIB;
        if holds_ram(info, lo, lo + GIB) {
            boot_mmu::map_gb(gb, Kind::Dram);
        } else {
            boot_mmu::map_gb(gb, Kind::Device);
        }
    }
    // The kernel's gigabyte block by block, so that its stack guard can be
    // unmapped and an address with nothing behind it stays Device.
    boot_mmu::split_gb(kernel_gb, Kind::Device);
    for i in 0..512usize {
        let lo = (kernel_gb as u64) * GIB + (i as u64) * BLOCK_2M;
        if holds_ram(info, lo, lo + BLOCK_2M) {
            boot_mmu::map_2mb(i, Kind::Dram);
        }
    }
    let secondary = smp::guards();
    boot_mmu::unmap_stack_guards(&[
        core::ptr::addr_of!(__stack_guard) as u64,
        secondary[0],
        secondary[1],
        secondary[2],
    ]);
}

/// Physical memory for the ACPI parser, through the identity map: only what the
/// firmware's map describes as memory, so a corrupt pointer in a table reads
/// nothing rather than faulting.
struct Physical<'a>(&'a BootInfo);

impl acpi::Memory for Physical<'_> {
    fn bytes(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let end = addr.checked_add(len as u64)?;
        (0..self.0.region_count as usize)
            .map(|i| region(self.0, i))
            .any(|(base, size, kind)| {
                kind != MemKind::Mmio
                    && kind != MemKind::Usable
                    && addr >= base
                    && end <= base + size
            })
            // SAFETY: inside a mapped region that is the firmware's, not free.
            .then(|| unsafe { core::slice::from_raw_parts(addr as *const u8, len) })
    }
}

/// Hand the carve allocator and the state arena the largest free stretch of the
/// firmware's map. The kernel's span is `Kernel` in the map and what the loader
/// allocated `Loader`, so neither can be chosen. Nothing there is zeroed here:
/// each carve zeroes itself and the arena zeroes from a frontier.
///
/// # Safety
/// Once, on the boot core, MMU on, before anything allocates.
unsafe fn install_zone(info: &BootInfo) -> (u64, u64) {
    const ALIGN: u64 = 0x1_0000;
    let mut best = (0u64, 0u64);
    for i in 0..info.region_count as usize {
        let (base, len, kind) = region(info, i);
        if kind != MemKind::Usable {
            continue;
        }
        let lo = base.next_multiple_of(ALIGN);
        let hi = (base + len) & !(ALIGN - 1);
        if hi > lo && hi - lo > best.1 - best.0 {
            best = (lo, hi);
        }
    }
    if best.1 > best.0 {
        fluxor::kernel::mem::carve::install(best.0 as usize, best.1 as usize);
        fluxor::kernel::module::loader::install_arena(best.0 as usize, (best.1 - best.0) as usize);
    }
    best
}

/// The MPIDR affinity field that numbers this machine's cores: the lowest level
/// at which the cores the MADT lists differ. A hypervisor commonly numbers its
/// vCPUs in Aff0; a part that sets `MPIDR_EL1.MT` keeps Aff0 for threads and
/// numbers its cores in Aff1. Aff0 with one core.
fn core_id_shift(machine: &acpi::Machine) -> u32 {
    let cpus = &machine.cpus[..machine.cpu_count];
    let Some(first) = cpus.first() else {
        return 0;
    };
    [0u32, 8, 16, 32]
        .into_iter()
        .find(|&shift| {
            cpus.iter()
                .any(|c| (c.mpidr >> shift) & 0xFF != (first.mpidr >> shift) & 0xFF)
        })
        .unwrap_or(0)
}

/// This core's redistributor: its `GICR_TYPER` names it by affinity. The MADT
/// gives either a frame per CPU or a range to walk.
fn find_redistributor(machine: &acpi::Machine) -> Option<usize> {
    let mpidr: u64;
    // SAFETY: reads a system register.
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)) };
    redistributor_of(machine, mpidr)
}

/// The redistributor of the core with `mpidr`.
fn redistributor_of(machine: &acpi::Machine, mpidr: u64) -> Option<usize> {
    const TYPER: usize = 0x08;
    const TYPER_VLPIS: u64 = 1 << 1;
    const TYPER_LAST: u64 = 1 << 4;
    let affinity = ((mpidr >> 32) & 0xFF) << 24 | (mpidr & 0xFF_FFFF);
    let matches = |frame: usize| {
        // SAFETY: a redistributor frame the MADT described, mapped Device.
        let typer = unsafe { mmio::read64(frame + TYPER) };
        (typer >> 32 == affinity, typer)
    };
    let this = machine.cpus[..machine.cpu_count]
        .iter()
        .find(|c| c.gicr_base != 0 && c.mpidr & 0xFF_00FF_FFFF == mpidr & 0xFF_00FF_FFFF);
    if let Some(cpu) = this {
        return Some(cpu.gicr_base as usize);
    }
    let mut frame = machine.gicr_range_base as usize;
    if frame == 0 {
        return None;
    }
    for _ in 0..acpi::MAX_CPUS {
        let (hit, typer) = matches(frame);
        if hit {
            return Some(frame);
        }
        if typer & TYPER_LAST != 0 {
            return None;
        }
        frame += if typer & TYPER_VLPIS != 0 {
            0x4_0000
        } else {
            0x2_0000
        };
    }
    None
}

/// Name the interrupt controller and the timer from the tables, and turn them
/// on. `None` if the tables name no controller this kernel can drive.
///
/// # Safety
/// Once, on the boot core, with the MMU on and the vectors installed.
unsafe fn start_interrupts(machine: &acpi::Machine, info: &BootInfo) -> Option<&'static str> {
    // Under a hypervisor the physical timer traps, so the guest's is the virtual
    // one; a kernel the firmware entered at EL2 owns the machine.
    let (counter, ppi) = if info.entry_el == 2 {
        (timer::Counter::Physical, machine.timer_phys_gsiv)
    } else {
        (timer::Counter::Virtual, machine.timer_virt_gsiv)
    };
    timer::configure(counter);
    let name = if machine.gic_version >= 3 {
        let redistributor = find_redistributor(machine)?;
        gic::configure_v3(machine.gicd_base as usize, redistributor, ppi);
        // SAFETY: the boot core, once.
        unsafe { REDISTRIBUTOR = redistributor };
        "gicv3"
    } else {
        let cpu = machine.cpus[..machine.cpu_count]
            .iter()
            .find(|c| c.gicc_base != 0)?;
        gic::configure(machine.gicd_base as usize, cpu.gicc_base as usize, ppi);
        "gicv2"
    };
    gic::init();
    Some(name)
}

/// This core's GICv3 redistributor, once found; 0 on a GICv2.
static mut REDISTRIBUTOR: usize = 0;

const SELF_TEST_WAIT_US: u64 = 1_000_000;

/// An SGI sent to this core and taken, so the whole path is known to work: GIC,
/// vector, handler, EOI.
fn sgi_self_test(clock: &Clock) -> bool {
    let before = exception::SGI_RECEIVED.load(Ordering::Relaxed);
    // SAFETY: the controller is configured; interrupts are unmasked by the
    // caller.
    unsafe { gic::send_sgi_self(gic::WAKE_SGI) };
    let deadline = clock.elapsed_us() + SELF_TEST_WAIT_US;
    while clock.elapsed_us() < deadline {
        if exception::SGI_RECEIVED.load(Ordering::Relaxed) != before {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// A deadline set and landed: ten ticks of 10 ms take 100 ms within 10 %.
fn timer_self_test(clock: &Clock) -> Option<u64> {
    const PERIOD_US: u64 = 10_000;
    const TICKS: u32 = 10;
    let core = cpu::current_core_id() as usize;
    let period = (PERIOD_US * timer::timer_freq() / 1_000_000) as u32;
    exception::NEXT_DEADLINE_TICKS[core].store(period, Ordering::Relaxed);
    let first = exception::CORE_TICKS[core].load(Ordering::Relaxed);
    // SAFETY: this core's timer, armed for this test and re-armed by the run loop.
    unsafe { timer::timer_set(period) };
    let start = clock.elapsed_us();
    let deadline = start + SELF_TEST_WAIT_US;
    while exception::CORE_TICKS[core]
        .load(Ordering::Relaxed)
        .wrapping_sub(first)
        < TICKS
    {
        if clock.elapsed_us() >= deadline {
            return None;
        }
        core::hint::spin_loop();
    }
    let took = clock.elapsed_us() - start;
    let want = PERIOD_US * u64::from(TICKS);
    (took * 10 >= want * 9 && took * 10 <= want * 11).then_some(took)
}

/// A step made to overrun its deadline must be caught.
fn step_guard_self_test(clock: &Clock) -> bool {
    use fluxor::kernel::exec::step_guard;
    (hal::HAL_OPS.step_guard_arm)(1000);
    let until = clock.elapsed_us() + 2000;
    while clock.elapsed_us() < until {
        core::hint::spin_loop();
    }
    (hal::HAL_OPS.step_guard_post_check)();
    let caught = step_guard::is_timed_out();
    step_guard::clear_timed_out();
    caught
}

fn report_entry(con: &Console, info: &BootInfo) {
    con.puts("[boot] stage=kernel_entry el=");
    con.dec(u64::from(info.entry_el));
    con.puts(" cpu=");
    con.hex(info.boot_cpu_id);
    con.puts(" regions=");
    con.dec(info.region_count);
    con.puts(" usable_mib=");
    con.dec(usable_bytes(info) >> 20);
    con.puts(" rsdp=");
    con.hex(info.rsdp);
    con.puts(" image=");
    con.hex(info.image.base);
    con.puts("+");
    con.hex(info.image.len);
    con.puts("\n");
}

fn report_acpi(con: &Console, m: &acpi::Machine, clock: &Clock) {
    con.puts("[boot] stage=acpi tables=");
    for (i, signature) in m.tables[..m.table_count].iter().enumerate() {
        if i != 0 {
            con.putc(b',');
        }
        for &b in signature {
            con.putc(b);
        }
    }
    con.puts(" bad=");
    con.dec(m.bad_tables as u64);
    con.puts(" cpus=");
    con.dec(m.cpu_count as u64);
    con.puts(" gic=v");
    con.dec(u64::from(m.gic_version));
    con.puts(" gicd=");
    con.hex(m.gicd_base);
    con.puts(" its=");
    con.dec(m.its_count as u64);
    con.puts(" v2m=");
    con.dec(m.v2m_count as u64);
    con.puts(" vtimer=");
    con.dec(u64::from(m.timer_virt_gsiv));
    con.puts(if m.psci_hvc { " psci=hvc" } else { " psci=smc" });
    con.puts(" ecam=");
    con.hex(m.ecam_base);
    con.puts(" t_us=");
    con.dec(clock.elapsed_us());
    con.puts("\n");
}

fn report_stages(con: &Console, reached: &str, clock: &Clock) {
    con.puts("[boot] stages=");
    con.puts(reached);
    con.puts(" total_us=");
    con.dec(clock.elapsed_us());
    con.puts("\n");
}

/// The graph's `boot:` map, from the image's config blob; all defaults if it
/// has none or the blob does not parse.
struct BootParams {
    fault_probe: bool,
    lockup_probe: bool,
    summary_every_s: u64,
    summary_for_s: u64,
    max_uptime_s: u64,
}

fn boot_params() -> BootParams {
    static mut CONFIG: core::mem::MaybeUninit<fluxor::kernel::boot::config::Config> =
        core::mem::MaybeUninit::uninit();
    // SAFETY: the boot core, once, before anything else reads the config.
    let raw = unsafe {
        let slot = &raw mut CONFIG;
        let config = (*slot).write(fluxor::kernel::boot::config::Config::empty());
        if fluxor::kernel::boot::config::read_config_into(config) {
            config.boot_params
        } else {
            [0; fluxor::kernel::boot::config::BOOT_PARAMS_BYTES]
        }
    };
    let word = |at: usize| {
        u64::from(u32::from_le_bytes([
            raw[at],
            raw[at + 1],
            raw[at + 2],
            raw[at + 3],
        ]))
    };
    BootParams {
        fault_probe: raw[1] != 0,
        lockup_probe: raw[2] != 0,
        summary_every_s: match word(4) {
            0 => 10,
            n => n,
        },
        summary_for_s: word(8),
        max_uptime_s: word(12),
    }
}

/// Fault on purpose: a store into the boot stack's unmapped guard page.
fn fault_probe() -> ! {
    let guard = core::ptr::addr_of!(__stack_guard) as *mut u64;
    // SAFETY: not safe, on purpose: `build_map` left this page unmapped, so the
    // store faults and the exception path reports it.
    unsafe { core::ptr::write_volatile(guard, 0) };
    park()
}

fn stack_guard_probe(addr: u64) -> Option<usize> {
    let guard = core::ptr::addr_of!(__stack_guard) as u64;
    if addr >= guard && addr < guard + 4096 {
        return Some(0);
    }
    smp::guard_core(addr)
}

#[no_mangle]
extern "C" fn uefi_main(info: *const BootInfo) -> ! {
    let clock = Clock::start();
    // SAFETY: the loader's handoff, cleaned to the point of coherency before
    // the jump; read only after its magic is checked.
    let info = unsafe {
        if info.is_null()
            || core::ptr::read_volatile(core::ptr::addr_of!((*info).magic)) != BOOT_INFO_MAGIC
        {
            park();
        }
        &*info
    };
    let Some(con) = Console::from_boot(info) else {
        // Nothing can be said on a machine with no console; the firmware
        // reports the machine as up and the rig times out.
        park()
    };
    // SAFETY: the boot core, before the sink that reads it is installed.
    unsafe {
        CONSOLE = Some(con);
        BOOT_INFO = info;
    }

    report_entry(&con, info);

    // Which MPIDR field numbers the cores is the MADT's to say
    // (`core_id_shift`, once the tables are read); until then the boot core is
    // the only one running, so any field serves.
    cpu::configure_core_id(0);
    exception::set_dump_sink(console_sink);
    exception::set_stack_guard_probe(stack_guard_probe);
    let (stack_start, stack_end, image_start, image_end) = (
        core::ptr::addr_of!(__stack_start) as usize,
        core::ptr::addr_of!(__stack_end) as usize,
        core::ptr::addr_of!(__kernel_load_base) as usize,
        core::ptr::addr_of!(__end_block_addr) as usize,
    );
    exception::set_frame_bounds(
        stack_start,
        stack_end,
        image_start,
        core::ptr::addr_of!(__end_data_addr) as usize,
    );

    // SAFETY: the boot core, once, MMU off, at EL1. Everything written since
    // entry lies in the kernel's span, so that span is what is invalidated.
    unsafe {
        build_map(info);
        boot_mmu::enable(&[(image_start, image_end)]);
    }
    con.puts("[boot] stage=mmu t_us=");
    con.dec(clock.elapsed_us());
    con.puts("\n");

    let machine = match acpi::parse(&Physical(info), info.rsdp) {
        Ok(machine) => machine,
        Err(why) => {
            con.puts("[boot] error acpi ");
            con.puts(match why {
                acpi::Error::NoRsdp => "no_rsdp",
                acpi::Error::BadRsdp => "bad_rsdp",
                acpi::Error::NoXsdt => "no_xsdt",
                acpi::Error::BadXsdt => "bad_xsdt",
            });
            con.puts("\n");
            park()
        }
    };
    report_acpi(&con, &machine, &clock);
    psci::configure(if machine.psci_hvc {
        psci::Conduit::Hvc
    } else {
        psci::Conduit::Smc
    });
    // Before the timer and the controller: the tick's per-core slots and the
    // fault stacks are indexed by this field from the first interrupt on.
    cpu::configure_core_id(core_id_shift(&machine));

    let params = boot_params();
    if params.fault_probe {
        report_stages(&con, "kernel_entry,mmu,acpi", &clock);
        fault_probe();
    }

    let mut reached = Reached::new();
    for stage in ["kernel_entry", "mmu", "acpi"] {
        reached.push(stage);
    }
    // SAFETY: the boot core, once; MMU on, vectors installed.
    let zone = unsafe { install_zone(info) };
    // SAFETY: as above; the tables were checksummed by the parser.
    let controller = unsafe { start_interrupts(&machine, info) };
    let Some(controller) = controller else {
        con.puts("[boot] error irq no_controller\n");
        idle(&con, info, &machine, reached.as_str(), &params, &clock)
    };
    // SAFETY: vectors and controller are ready for the first interrupt.
    unsafe { core::arch::asm!("msr daifclr, #2") };

    if !sgi_self_test(&clock) {
        con.puts("[boot] error irq sgi_not_received\n");
        idle(&con, info, &machine, reached.as_str(), &params, &clock)
    }
    reached.push("irq");
    con.puts("[boot] stage=irq ctrl=");
    con.puts(controller);
    con.puts(" its=");
    con.dec(machine.its_count as u64);
    con.puts(" t_us=");
    con.dec(clock.elapsed_us());
    con.puts("\n");

    let Some(took_us) = timer_self_test(&clock) else {
        con.puts("[boot] error timer deadline_missed\n");
        idle(&con, info, &machine, reached.as_str(), &params, &clock)
    };
    reached.push("timer");
    con.puts("[boot] stage=timer src=");
    con.puts(if info.entry_el == 2 { "cntp" } else { "cntv" });
    con.puts(" freq=");
    con.dec(timer::timer_freq());
    con.puts(" took_us=");
    con.dec(took_us);
    con.puts(" t_us=");
    con.dec(clock.elapsed_us());
    con.puts("\n");

    fluxor::kernel::sys::log_ring::activate_local();
    static LOGGER: RingLogger = RingLogger;
    // SAFETY: the one boot-time caller, before any other logger user.
    unsafe { log::set_logger_racy(&LOGGER).ok() };
    log::set_max_level(log::LevelFilter::Info);

    fluxor::kernel::boot(&hal::HAL_OPS);
    fluxor::kernel::exec::step_guard::init();
    if !step_guard_self_test(&clock) {
        con.puts("[boot] error step_guard not_caught\n");
        idle(&con, info, &machine, reached.as_str(), &params, &clock)
    }
    reached.push("step_guard");
    con.puts("[boot] stage=step_guard self_test=ok\n");

    // SAFETY: written once by `start_interrupts`, above.
    let redistributor = unsafe { REDISTRIBUTOR };
    if machine.its_count != 0 && redistributor != 0 {
        // SAFETY: the boot core, once; the GICv3 is up and the zone installed.
        if let Err(why) = unsafe { its::init(&machine, redistributor) } {
            con.puts("[boot] error its ");
            con.puts(why);
            con.puts("\n");
        }
    }

    let period = (1000 * timer::timer_freq() / 1_000_000) as u32;
    // SAFETY: the boot core, once; MMU, GIC and timer up.
    let (cpus, running) = unsafe {
        smp::start(
            &machine,
            |mpidr| redistributor_of(&machine, mpidr),
            period,
            params.lockup_probe,
            || clock.elapsed_us(),
        )
    };
    reached.push("smp");
    con.puts("[boot] stage=smp cpus=");
    con.dec(cpus as u64);
    con.puts(" used=");
    con.dec(running as u64);
    con.puts(" t_us=");
    con.dec(clock.elapsed_us());
    con.puts("\n");

    // SAFETY: the firmware's seed, cleaned to PoC with the handoff.
    let seed = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(info.entropy) as *const u8,
            (info.entropy_len as usize).min(info.entropy.len()),
        )
    };
    let (firmware, hardware) = hal::seed_entropy(seed);
    con.puts("[rng] sources=");
    con.puts(match (firmware, hardware) {
        (true, true) => "firmware,rndr",
        (true, false) => "firmware",
        (false, true) => "rndr",
        (false, false) => "none",
    });
    con.puts("\n");

    // The ECAM window MCFG described, mapped Device from boot.
    let found = pci::enumerate(
        machine.ecam_base,
        machine.ecam_bus_start,
        machine.ecam_bus_end,
    );
    for d in pci::devices() {
        con.puts("[pcie] dev bdf=");
        con.hex(u64::from(d.bus));
        con.puts(":");
        con.hex(u64::from(d.dev));
        con.puts(".");
        con.dec(u64::from(d.func));
        con.puts(" vid=");
        con.hex(u64::from(d.vendor));
        con.puts(" did=");
        con.hex(u64::from(d.device));
        con.puts(" class=");
        con.hex(u64::from(d.class));
        con.puts(" msix=");
        con.dec(u64::from(d.msix));
        con.puts("\n");
    }
    reached.push("pcie");
    con.puts("[boot] stage=pcie devices=");
    con.dec(found as u64);
    con.puts(" t_us=");
    con.dec(clock.elapsed_us());
    con.puts("\n");
    devices::configure(&machine, zone);

    // A graph with no modules is an image that only proves the boot: nothing is
    // left to run, so the summary repeats until the uptime limit.
    if !graph_has_modules() {
        idle(&con, info, &machine, reached.as_str(), &params, &clock)
    }
    let modules = match start_graph() {
        Ok(modules) => modules,
        Err(why) => {
            for _ in 0..64 {
                drain_log();
                let until = clock.elapsed_us() + 1000;
                while clock.elapsed_us() < until {
                    core::hint::spin_loop();
                }
            }
            con.puts("[boot] error graph ");
            con.puts(why);
            con.puts("\n");
            idle(&con, info, &machine, reached.as_str(), &params, &clock)
        }
    };
    reached.push("graph");
    con.puts("[boot] stage=graph modules=");
    con.dec(modules as u64);
    con.puts(" zone=");
    con.hex(zone.0);
    con.puts("-");
    con.hex(zone.1);
    con.puts(" t_us=");
    con.dec(clock.elapsed_us());
    con.puts("\n");
    report_stages(&con, reached.as_str(), &clock);

    run(con, reached, params, clock)
}

/// The stages reached, for the summary line.
struct Reached {
    text: [u8; 96],
    len: usize,
}

impl Reached {
    const fn new() -> Self {
        Reached {
            text: [0; 96],
            len: 0,
        }
    }

    fn push(&mut self, stage: &str) {
        if self.len != 0 {
            self.text[self.len] = b',';
            self.len += 1;
        }
        self.text[self.len..self.len + stage.len()].copy_from_slice(stage.as_bytes());
        self.len += stage.len();
    }

    fn as_str(&self) -> &str {
        // SAFETY: only ever appended whole `&str`s and commas.
        unsafe { core::str::from_utf8_unchecked(&self.text[..self.len]) }
    }
}

fn graph_has_modules() -> bool {
    use fluxor::kernel::exec::scheduler;
    // SAFETY: the boot core, before the run loop exists.
    let cfg_ref = unsafe { scheduler::static_config_mut() };
    fluxor::kernel::boot::config::read_config_into(cfg_ref) && cfg_ref.module_count != 0
}

/// Parse the image's graph, instantiate it and start the tick from its period.
fn start_graph() -> Result<usize, &'static str> {
    use fluxor::kernel::exec::scheduler;
    use fluxor::kernel::module::loader;
    loader::reset_state_arena();
    // SAFETY: the boot core, before the run loop exists.
    let loader_ref = unsafe { scheduler::static_loader_mut() };
    if loader_ref.init().is_err() {
        return Err("no_module_table");
    }
    // SAFETY: as above.
    let cfg = unsafe { scheduler::static_config() };
    let tick_us = match cfg.header.tick_us {
        0 => 1000,
        t => u64::from(t),
    };
    let period = (tick_us * timer::timer_freq() / 1_000_000) as u32;
    let core = cpu::current_core_id() as usize;
    exception::NEXT_DEADLINE_TICKS[core].store(period, Ordering::Relaxed);
    // SAFETY: this core's timer.
    unsafe { timer::timer_set(period) };

    let (list, count) = scheduler::prepare_graph().map_err(|_| "prepare_failed")?;
    if let Err(why) = domains::cross::bridge_edges() {
        log::error!("[graph] {why}");
        return Err("bridge_failed");
    }
    let loaded = match domains::instantiate(&list, count) {
        Ok(loaded) => loaded,
        Err(domains::InstantiateError::OwnerPlan(_)) => return Err("owner_plan_invalid"),
        Err(domains::InstantiateError::Modules(_)) => return Err("module_failed"),
    };
    scheduler::finalize_instantiation_accounting();
    scheduler::admit_resident_workloads_from_config();
    // Domain `n` runs on secondary `n`: a domain with modules and no core
    // would hold its modules unstepped, so the graph is refused instead.
    if let Some(d) = domains::coreless_domain(&PLATFORM) {
        log::error!("[graph] domain {d} has modules but this machine started no core for it");
        return Err("domain_without_core");
    }
    Ok(loaded)
}

/// What each bound interrupt has done: a device asked for one and is getting it.
fn report_interrupts() {
    // SAFETY: a read of the binding table the scheduler thread grows.
    let count = unsafe { gic::IRQ_BINDING_COUNT };
    for i in 0..count {
        // SAFETY: `i` is below the count.
        let irq = unsafe { (*core::ptr::addr_of!(gic::IRQ_BINDINGS))[i].irq };
        let fires = gic::BINDING_FIRES[i].load(Ordering::Relaxed);
        log::info!("[irq] binding={i} irq={irq} fires={fires}");
    }
}

/// How often the boot core looks at the other cores' tick counts.
const WATCH_EVERY_US: u64 = 500_000;

/// What both loops do between passes: move the log to the console, watch the
/// other cores for a lockup, power the machine off at the uptime limit, and
/// say when the summary is due. Nothing here waits on an interrupt, so it holds
/// with interrupts masked.
struct Upkeep {
    watch: smp::Watch,
    watch_at_us: u64,
    summary_at_s: u64,
}

impl Upkeep {
    fn new(params: &BootParams, clock: &Clock) -> Self {
        Upkeep {
            watch: smp::Watch::new(),
            watch_at_us: 0,
            summary_at_s: clock.elapsed_s() + params.summary_every_s,
        }
    }

    /// One round. True when the summary is due, which it is every
    /// `summary_every_s` for the first `summary_for_s` (always, if 0).
    fn poll(&mut self, con: &Console, params: &BootParams, clock: &Clock) -> bool {
        let now_us = clock.elapsed_us();
        if now_us >= self.watch_at_us {
            self.watch.check(now_us);
            self.watch_at_us = now_us + WATCH_EVERY_US;
        }
        drain_log();
        let now = clock.elapsed_s();
        if params.max_uptime_s != 0 && now >= params.max_uptime_s {
            con.puts("[power] max_uptime reached\n");
            psci::system_off();
            park();
        }
        if now < self.summary_at_s || (params.summary_for_s != 0 && now > params.summary_for_s) {
            return false;
        }
        self.summary_at_s = now + params.summary_every_s;
        true
    }
}

/// What the boot core's loop reports and watches between passes.
struct Running {
    con: Console,
    params: BootParams,
    clock: Clock,
    reached: Reached,
    upkeep: Upkeep,
    cpu: CpuMeter,
}

/// How often the boot core reports each domain core's busy share.
const CPU_EVERY_US: u64 = 5_000_000;

/// Each active domain's busy share since the last report: the counter ticks
/// its core spent in passes (`domains::busy_ticks`) over the ticks elapsed.
/// What tells a saturated core from one waiting on its tick.
struct CpuMeter {
    at_us: u64,
    at_ticks: u64,
    busy: [u64; fluxor::kernel::exec::scheduler::MAX_DOMAINS],
}

impl CpuMeter {
    fn new() -> Self {
        CpuMeter {
            at_us: 0,
            at_ticks: timer::read_timer_count_64(),
            busy: core::array::from_fn(domains::busy_ticks),
        }
    }

    fn poll(&mut self, now_us: u64) {
        if now_us < self.at_us + CPU_EVERY_US {
            return;
        }
        let now = timer::read_timer_count_64();
        let span = now.wrapping_sub(self.at_ticks).max(1);
        let mut pct = [0u64; fluxor::kernel::exec::scheduler::MAX_DOMAINS];
        for (d, last) in self.busy.iter_mut().enumerate() {
            let busy = domains::busy_ticks(d);
            pct[d] = busy.wrapping_sub(*last) * 100 / span;
            *last = busy;
        }
        self.at_ticks = now;
        self.at_us = now_us;
        let shown = domains::domains_needed();
        log::info!(
            "[cpu] busy_pct={:?} span_ms={}",
            &pct[..shown],
            span * 1000 / timer::timer_freq().max(1)
        );
    }
}

static mut RUNNING: Option<Running> = None;

/// What this platform does around the shared domain loop.
static PLATFORM: domains::Platform = domains::Platform {
    has_core: smp::online,
    after_pass,
    after_step,
};

/// After each pass of domain 0: the boot core's upkeep, and the summary when
/// it is due.
fn after_pass(domain_id: usize, _core_id: usize, _tier: domains::Tier) {
    if domain_id != 0 {
        return;
    }
    // SAFETY: set before the boot core entered domain 0's loop, which only
    // the boot core runs.
    let Some(running) = (unsafe { (*core::ptr::addr_of_mut!(RUNNING)).as_mut() }) else {
        return;
    };
    running.cpu.poll(running.clock.elapsed_us());
    if running
        .upkeep
        .poll(&running.con, &running.params, &running.clock)
    {
        log::info!(
            "[boot] stages={} total_us={}",
            running.reached.as_str(),
            running.clock.elapsed_us()
        );
        report_interrupts();
    }
}

fn after_step(_domain_id: usize) {}

/// Release the graph to the other cores and run domain 0 on this one. The
/// summary keeps repeating, because a cloud console joins late.
fn run(con: Console, reached: Reached, params: BootParams, clock: Clock) -> ! {
    let upkeep = Upkeep::new(&params, &clock);
    // SAFETY: the boot core, once, before the loop that reads it.
    unsafe {
        RUNNING = Some(Running {
            con,
            params,
            clock,
            reached,
            upkeep,
            cpu: CpuMeter::new(),
        });
    }
    domains::release();
    domains::run(0, &PLATFORM)
}

/// Where the kernel stops when it has no graph to run, or a stage failed: what
/// it found and how far it got repeat, because a cloud console may join after
/// the boot has finished, until the uptime limit powers the machine off.
fn idle(
    con: &Console,
    info: &BootInfo,
    machine: &acpi::Machine,
    reached: &str,
    params: &BootParams,
    clock: &Clock,
) -> ! {
    report_stages(con, reached, clock);
    let mut upkeep = Upkeep::new(params, clock);
    loop {
        if upkeep.poll(con, params, clock) {
            report_entry(con, info);
            report_acpi(con, machine, clock);
            report_stages(con, reached, clock);
        }
        core::hint::spin_loop();
    }
}

fn park() -> ! {
    loop {
        // SAFETY: wait-for-interrupt has no memory effects.
        unsafe { core::arch::asm!("wfi") };
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    park()
}

/// This kernel has no heap: its tables are carved at boot. The contracts crate
/// links `alloc`, so one must be named, and it refuses every request.
struct NoHeap;

// SAFETY: `alloc` returns null, which the contract allows; nothing is ever
// handed out for `dealloc` to receive.
unsafe impl core::alloc::GlobalAlloc for NoHeap {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

#[global_allocator]
static NO_HEAP: NoHeap = NoHeap;

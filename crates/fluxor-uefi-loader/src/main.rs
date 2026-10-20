//! The UEFI loader: the firmware runs this, and it runs the kernel.
//!
//! While boot services exist it gathers what only they can answer — the
//! memory map, the ACPI root, the console UART, entropy, the wall clock —
//! and reads the kernel image `\fluxor\fluxor.img` from the volume it was
//! itself loaded from. The image says where it must run and how much RAM it
//! uses (`KernelHeader`); the loader reserves exactly that span and refuses a
//! busy page rather than placing the kernel anywhere else. Then it leaves
//! boot services and enters the image in the state `fluxor_contracts::boot`
//! defines: MMU and data cache off, interrupts masked, x0 = `&BootInfo`. The
//! kernel never learns it was booted by UEFI.
//!
//! Every step says what it did on the firmware console as one
//! `[loader] …` line, so a machine that stops early says where.
//!
//! An ESP with no kernel image (or an image without the header) leaves the
//! loader nothing to hand over: it says why on the console and powers the
//! machine off.
//!
//! The few processor reads it makes (`CurrentEL`, `MPIDR`, cache
//! maintenance) are its own: it runs as a firmware application, on another
//! target than the kernel's `src/arch`.

#![no_std]
#![no_main]
#![allow(
    unsafe_code,
    reason = "a firmware application: every call it makes is through a table of foreign function pointers the firmware hands it"
)]

mod efi;

use core::ffi::c_void;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use efi::*;
use fluxor_contracts::boot::{
    BootInfo, KernelHeader, MemKind, MemRegion, Range, RegionList, BOOT_INFO_MAGIC, CONSOLE_NONE,
    KERNEL_HEADER_MAGIC,
};

/// The most memory-map regions the loader hands over, after merging adjacent
/// regions of one kind. Regions past this are counted and reported on the
/// console before boot services end.
const MAX_REGIONS: usize = 256;

const IMAGE_PATH: &str = "\\fluxor\\fluxor.img";

static mut SYSTEM_TABLE: *mut SystemTable = core::ptr::null_mut();

/// Cleared just before the first ExitBootServices call: from then on the
/// console, a boot service, is not called, and anything said (a panic) is
/// dropped.
static CONSOLE_LIVE: AtomicBool = AtomicBool::new(true);

// ── console ──────────────────────────────────────────────────────────────────

/// The firmware console: each write converted to UCS-2 and sent in chunks of
/// up to 128 code units. Usable only while boot services exist.
struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if !CONSOLE_LIVE.load(Ordering::Relaxed) {
            return Ok(());
        }
        // SAFETY: SYSTEM_TABLE is set before the first write, and
        // CONSOLE_LIVE holds only while boot services exist.
        let out = unsafe { (*SYSTEM_TABLE).con_out };
        if out.is_null() {
            return Ok(());
        }
        let mut buf = [0u16; 128];
        let mut n = 0;
        let flush = |buf: &mut [u16; 128], n: &mut usize| {
            buf[*n] = 0;
            // SAFETY: a NUL-terminated UCS-2 string in our own buffer.
            unsafe { ((*out).output_string)(out, buf.as_ptr()) };
            *n = 0;
        };
        for c in s.chars() {
            if c == '\n' {
                buf[n] = '\r' as u16;
                n += 1;
            }
            buf[n] = if (c as u32) < 0x1_0000 {
                c as u16
            } else {
                '?' as u16
            };
            n += 1;
            if n >= buf.len() - 3 {
                flush(&mut buf, &mut n);
            }
        }
        if n > 0 {
            flush(&mut buf, &mut n);
        }
        Ok(())
    }
}

macro_rules! say {
    ($($arg:tt)*) => {{
        let _ = writeln!(Console, $($arg)*);
    }};
}

// ── firmware helpers ─────────────────────────────────────────────────────────

fn bs() -> &'static BootServices {
    // SAFETY: valid for the life of boot services, which every caller is in.
    unsafe { &*(*SYSTEM_TABLE).boot_services }
}

fn rt() -> &'static RuntimeServices {
    // SAFETY: the runtime services table outlives boot services.
    unsafe { &*(*SYSTEM_TABLE).runtime_services }
}

fn ucs2<const N: usize>(s: &str) -> [u16; N] {
    let mut out = [0u16; N];
    for (i, c) in s.chars().take(N - 1).enumerate() {
        out[i] = c as u16;
    }
    out
}

/// Say why on the console while it is live, then power the machine off
/// through the runtime services, which outlive ExitBootServices.
fn shutdown(why: &str) -> ! {
    say!("[loader] shutdown: {why}");
    // SAFETY: a runtime service, callable before and after ExitBootServices.
    unsafe { (rt().reset_system)(RESET_SHUTDOWN, SUCCESS, 0, core::ptr::null()) }
}

fn firmware_vendor(buf: &mut [u8; 48]) -> &str {
    // SAFETY: the vendor string is NUL-terminated UCS-2 owned by the firmware.
    let p = unsafe { (*SYSTEM_TABLE).firmware_vendor };
    let mut n = 0;
    if !p.is_null() {
        while n < buf.len() {
            // SAFETY: read up to the NUL or our buffer's end.
            let c = unsafe { *p.add(n) };
            if c == 0 {
                break;
            }
            buf[n] = if c < 0x80 { c as u8 } else { b'?' };
            n += 1;
        }
    }
    core::str::from_utf8(&buf[..n]).unwrap_or("?")
}

fn find_rsdp() -> u64 {
    // SAFETY: the configuration table holds `number_of_table_entries` entries.
    unsafe {
        let st = &*SYSTEM_TABLE;
        for i in 0..st.number_of_table_entries {
            let e = &*st.configuration_table.add(i);
            if e.vendor_guid == ACPI_20_TABLE_GUID {
                return e.vendor_table as u64;
            }
        }
    }
    0
}

/// The console UART from ACPI's SPCR table: (interface type, register access
/// width in bytes, base address). RSDP → XSDT → the table signed `SPCR`;
/// every table checked for its signature and a sane length, none trusted
/// further. A register block outside system memory is no console here.
fn find_spcr(rsdp: u64) -> (u32, u32, u64) {
    let none = (CONSOLE_NONE, 0, 0);
    if rsdp == 0 {
        return none;
    }
    // SAFETY: ACPI tables are firmware memory the identity map covers; each
    // read is bounded by a length the table itself states and is checked.
    unsafe {
        let p = rsdp as *const u8;
        if core::slice::from_raw_parts(p, 8) != b"RSD PTR " || *p.add(15) < 2 {
            return none;
        }
        let xsdt = core::ptr::read_unaligned(p.add(24) as *const u64) as *const u8;
        if xsdt.is_null() || core::slice::from_raw_parts(xsdt, 4) != b"XSDT" {
            return none;
        }
        let len = core::ptr::read_unaligned(xsdt.add(4) as *const u32) as usize;
        if !(36..=36 + 8 * 1024).contains(&len) {
            return none;
        }
        for i in 0..(len - 36) / 8 {
            let t = core::ptr::read_unaligned(xsdt.add(36 + 8 * i) as *const u64) as *const u8;
            if t.is_null() || core::slice::from_raw_parts(t, 4) != b"SPCR" {
                continue;
            }
            let tlen = core::ptr::read_unaligned(t.add(4) as *const u32) as usize;
            if tlen < 52 {
                return none;
            }
            // Interface type at 36; the base-address GAS at 40: space id
            // (0 = system memory), bit width, bit offset, access size
            // (1..4 = 1, 2, 4, 8 bytes), then the 64-bit address.
            if *t.add(40) != 0 {
                return none;
            }
            let kind = *t.add(36) as u32;
            let access = match *t.add(43) {
                n @ 1..=4 => 1u32 << (n - 1),
                _ => 0,
            };
            let base = core::ptr::read_unaligned(t.add(44) as *const u64);
            return (kind, access, base);
        }
    }
    none
}

fn entropy(out: &mut [u8; 64]) -> u32 {
    let mut p: *mut c_void = core::ptr::null_mut();
    // SAFETY: boot service with valid out-pointer.
    let st = unsafe { (bs().locate_protocol)(&RNG_PROTOCOL_GUID, core::ptr::null_mut(), &mut p) };
    if st != SUCCESS || p.is_null() {
        return 0;
    }
    let rng = p as *mut RngProtocol;
    // SAFETY: the protocol's own GetRNG, default algorithm, into our buffer.
    let st = unsafe { ((*rng).get_rng)(rng, core::ptr::null(), out.len(), out.as_mut_ptr()) };
    if st == SUCCESS {
        out.len() as u32
    } else {
        0
    }
}

/// Days from 1970-01-01 to `y-m-d` (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn unix_millis() -> u64 {
    let mut t = Time::default();
    // SAFETY: runtime service with a valid out-pointer.
    let st = unsafe { (rt().get_time)(&mut t, core::ptr::null_mut()) };
    if st != SUCCESS || t.year < 1970 {
        return 0;
    }
    let days = days_from_civil(t.year as i64, t.month as i64, t.day as i64);
    let secs = days * 86_400 + t.hour as i64 * 3600 + t.minute as i64 * 60 + t.second as i64;
    // `time_zone` is the offset from UTC in minutes; 2047
    // (`EFI_UNSPECIFIED_TIMEZONE`) gives none, and the clock is taken as UTC.
    let tz = if t.time_zone == 2047 {
        0
    } else {
        t.time_zone as i64
    };
    let secs = secs - tz * 60;
    if secs < 0 {
        return 0;
    }
    secs as u64 * 1000 + (t.nanosecond / 1_000_000) as u64
}

// ── the kernel image ─────────────────────────────────────────────────────────

/// The image file, open.
struct ImageFile(*mut File);

/// Where the firmware loaded this loader. The code that turns the MMU off
/// keeps executing as translation stops, under different memory attributes
/// than the firmware's mapping gave it, and the firmware made the image
/// coherent only to the point of unification; cleaned to the point of
/// coherency, it reads the same whichever path the fetch takes.
fn own_image(image_handle: Handle) -> Range {
    let mut li: *mut c_void = core::ptr::null_mut();
    // SAFETY: boot service with a valid out-pointer.
    unsafe {
        if (bs().handle_protocol)(image_handle, &LOADED_IMAGE_PROTOCOL_GUID, &mut li) != SUCCESS {
            shutdown("no loaded-image protocol");
        }
        let li = &*(li as *const LoadedImage);
        Range {
            base: li.image_base as u64,
            len: li.image_size,
        }
    }
}

fn open_image(image_handle: Handle) -> Result<ImageFile, &'static str> {
    let mut li: *mut c_void = core::ptr::null_mut();
    // SAFETY: boot services with valid out-pointers throughout.
    unsafe {
        if (bs().handle_protocol)(image_handle, &LOADED_IMAGE_PROTOCOL_GUID, &mut li) != SUCCESS {
            return Err("no loaded-image protocol");
        }
        let device = (*(li as *mut LoadedImage)).device_handle;
        let mut fs: *mut c_void = core::ptr::null_mut();
        if (bs().handle_protocol)(device, &SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, &mut fs) != SUCCESS {
            return Err("the loader's volume has no file system");
        }
        let fs = fs as *mut SimpleFileSystem;
        let mut root: *mut File = core::ptr::null_mut();
        if ((*fs).open_volume)(fs, &mut root) != SUCCESS {
            return Err("cannot open the loader's volume");
        }
        let name: [u16; 32] = ucs2(IMAGE_PATH);
        let mut file: *mut File = core::ptr::null_mut();
        let st = ((*root).open)(root, &mut file, name.as_ptr(), FILE_MODE_READ, 0);
        ((*root).close)(root);
        if st != SUCCESS {
            return Err("no \\fluxor\\fluxor.img on the loader's volume");
        }
        Ok(ImageFile(file))
    }
}

impl ImageFile {
    fn size(&self) -> u64 {
        let mut end = 0u64;
        // SAFETY: the file's own position calls.
        unsafe {
            ((*self.0).set_position)(self.0, u64::MAX);
            ((*self.0).get_position)(self.0, &mut end);
            ((*self.0).set_position)(self.0, 0);
        }
        end
    }

    fn read_at(&self, offset: u64, dst: *mut u8, len: usize) -> bool {
        let mut n = len;
        // SAFETY: `dst` holds `len` bytes the caller owns.
        unsafe {
            ((*self.0).set_position)(self.0, offset);
            ((*self.0).read)(self.0, &mut n, dst as *mut c_void) == SUCCESS && n == len
        }
    }
}

impl Drop for ImageFile {
    fn drop(&mut self) {
        // SAFETY: closes the handle `open` returned.
        unsafe { ((*self.0).close)(self.0) };
    }
}

// ── the memory map ───────────────────────────────────────────────────────────

fn kind_of(efi_type: u32) -> MemKind {
    match efi_type {
        CONVENTIONAL_MEMORY | BOOT_SERVICES_CODE | BOOT_SERVICES_DATA => MemKind::Usable,
        LOADER_CODE | LOADER_DATA => MemKind::Loader,
        ACPI_RECLAIM_MEMORY => MemKind::AcpiReclaim,
        ACPI_MEMORY_NVS => MemKind::AcpiNvs,
        MEMORY_MAPPED_IO | MEMORY_MAPPED_IO_PORT_SPACE => MemKind::Mmio,
        RUNTIME_SERVICES_CODE | RUNTIME_SERVICES_DATA => MemKind::Reserved,
        _ => MemKind::Reserved,
    }
}

/// The firmware's memory map, read into a buffer allocated beforehand so
/// that reading it allocates nothing (an allocation would change the map
/// and invalidate the key `ExitBootServices` needs).
struct MapBuf {
    buf: *mut MemoryDescriptor,
    cap: usize,
    size: usize,
    key: usize,
    desc_size: usize,
}

impl MapBuf {
    fn new() -> Self {
        let (mut size, mut key, mut desc_size, mut ver) = (0usize, 0usize, 0usize, 0u32);
        // SAFETY: a size query: null buffer, valid out-pointers.
        unsafe {
            (bs().get_memory_map)(
                &mut size,
                core::ptr::null_mut(),
                &mut key,
                &mut desc_size,
                &mut ver,
            );
        }
        // Room for the allocations still to come to add descriptors.
        let cap = size + 16 * desc_size.max(48);
        let mut p: *mut c_void = core::ptr::null_mut();
        // SAFETY: boot-service pool allocation.
        if unsafe { (bs().allocate_pool)(LOADER_DATA, cap, &mut p) } != SUCCESS {
            shutdown("cannot allocate the memory-map buffer");
        }
        MapBuf {
            buf: p as *mut MemoryDescriptor,
            cap,
            size: 0,
            key: 0,
            desc_size: 0,
        }
    }

    fn read(&mut self) -> Status {
        let mut ver = 0u32;
        self.size = self.cap;
        // SAFETY: our buffer of `cap` bytes.
        unsafe {
            (bs().get_memory_map)(
                &mut self.size,
                self.buf,
                &mut self.key,
                &mut self.desc_size,
                &mut ver,
            )
        }
    }

    fn descriptors(&self) -> impl Iterator<Item = &MemoryDescriptor> {
        let n = if self.desc_size == 0 {
            0
        } else {
            self.size / self.desc_size
        };
        let base = self.buf as *const u8;
        let step = self.desc_size;
        // SAFETY: `n` descriptors of `desc_size` bytes each, just written.
        (0..n).map(move |i| unsafe { &*(base.add(i * step) as *const MemoryDescriptor) })
    }

    /// Translate into `out`: sorted, merged, the kernel's span cut out as
    /// [`MemKind::Kernel`]. Allocates nothing. Returns the region count and
    /// how many found no slot.
    fn translate(&self, out: &mut [MemRegion; MAX_REGIONS], kernel: Range) -> (usize, usize) {
        let mut list = RegionList::new(out, kernel);
        for d in self.descriptors() {
            list.add(d.physical_start, d.number_of_pages * 4096, kind_of(d.kind));
        }
        (list.regions().len(), list.dropped())
    }
}

// ── handoff ──────────────────────────────────────────────────────────────────

/// Clean `[base, base + len)` to the point of coherency, so it is in memory
/// when the kernel reads it with the data cache off.
fn clean_to_poc(base: u64, len: u64) {
    let mut ctr: u64;
    // SAFETY: CTR_EL0 is readable at EL1/EL2.
    unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr) };
    let line = 4u64 << ((ctr >> 16) & 0xF);
    let mut a = base & !(line - 1);
    while a < base + len {
        // SAFETY: a data-cache maintenance op by VA over memory we own.
        unsafe { core::arch::asm!("dc cvac, {}", in(reg) a) };
        a += line;
    }
    // SAFETY: an architectural barrier.
    unsafe { core::arch::asm!("dsb sy") };
}

fn current_el() -> u32 {
    let el: u64;
    // SAFETY: CurrentEL is readable at every EL above 0.
    unsafe { core::arch::asm!("mrs {}, CurrentEL", out(reg) el) };
    ((el >> 2) & 3) as u32
}

fn mpidr() -> u64 {
    let v: u64;
    // SAFETY: MPIDR_EL1 is readable at EL1 and EL2.
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) v) };
    v
}

/// Mask every interrupt, turn the MMU and data cache off at the current EL
/// and jump to `entry` with x0 = `boot_info`: the entry state
/// `fluxor_contracts::boot` defines. The firmware's map is the identity, so
/// the code keeps running at the same address as translation stops. Masking
/// comes first: an interrupt the firmware left pending would be taken
/// through its vector table, in memory it no longer owns.
///
/// # Safety
/// After ExitBootServices, with everything the kernel will read cleaned to
/// the point of coherency.
unsafe fn jump(entry: u64, boot_info: u64) -> ! {
    core::arch::asm!(
        "msr daifset, #0xf",
        "ic iallu",
        "dsb sy",
        "isb",
        "mrs x9, CurrentEL",
        "cmp x9, #(2 << 2)",
        "b.ne 1f",
        "mrs x9, sctlr_el2",
        "bic x9, x9, #(1 << 0)",  // M
        "bic x9, x9, #(1 << 2)",  // C
        "msr sctlr_el2, x9",
        "b 2f",
        "1:",
        "mrs x9, sctlr_el1",
        "bic x9, x9, #(1 << 0)",  // M
        "bic x9, x9, #(1 << 2)",  // C
        "msr sctlr_el1, x9",
        "2:",
        "isb",
        "br x10",
        in("x0") boot_info,
        in("x10") entry,
        options(noreturn),
    )
}

// ── main ─────────────────────────────────────────────────────────────────────

#[no_mangle]
extern "efiapi" fn efi_main(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    // SAFETY: the firmware hands a valid system table and keeps it alive.
    unsafe { SYSTEM_TABLE = system_table };
    // The watchdog would reset a machine whose kernel is slow to come up.
    // SAFETY: boot service, disabling the timer (0 seconds).
    unsafe { (bs().set_watchdog_timer)(0, 0, 0, core::ptr::null()) };

    let mut vendor = [0u8; 48];
    // SAFETY: plain read of a system-table field.
    let fw_rev = unsafe { (*SYSTEM_TABLE).firmware_revision };
    say!(
        "[loader] fluxor uefi loader fw={} rev=0x{:x} el={}",
        firmware_vendor(&mut vendor),
        fw_rev,
        current_el()
    );

    let rsdp = find_rsdp();
    say!("[loader] acpi rsdp=0x{rsdp:x}");
    let (console_type, console_access, console_base) = find_spcr(rsdp);
    say!(
        "[loader] console spcr_type=0x{console_type:x} base=0x{console_base:x} access={console_access}"
    );
    let mut seed = [0u8; 64];
    let seed_len = entropy(&mut seed);
    say!("[loader] rng bytes={seed_len}");
    let now_ms = unix_millis();
    say!("[loader] time unix_ms={now_ms}");

    let loader = own_image(image_handle);

    // The kernel image and the span it asks for.
    let file = match open_image(image_handle) {
        Ok(f) => f,
        Err(why) => shutdown(why),
    };
    let size = file.size();
    let mut header = core::mem::MaybeUninit::<KernelHeader>::uninit();
    if size < core::mem::size_of::<KernelHeader>() as u64
        || !file.read_at(
            0,
            header.as_mut_ptr() as *mut u8,
            core::mem::size_of::<KernelHeader>(),
        )
    {
        shutdown("fluxor.img is too short to hold a kernel header");
    }
    // SAFETY: fully read above.
    let header = unsafe { header.assume_init() };
    if header.magic != KERNEL_HEADER_MAGIC {
        say!("[loader] image bytes={size} has no uefi kernel header");
        shutdown("fluxor.img is not a uefi kernel image");
    }
    let kernel = Range {
        base: header.load_base,
        len: header.ram_end.saturating_sub(header.load_base),
    };
    // The whole file goes at `load_base`: the kernel binary, then the
    // payload the packer appended.
    if header.kernel_bytes > size || size > kernel.len || kernel.base & 0xFFF != 0 {
        shutdown("fluxor.img's header is inconsistent with the file");
    }
    let pages = kernel.len.div_ceil(4096) as usize;
    let mut at = kernel.base;
    // SAFETY: boot service; asks for exactly the kernel's span.
    if unsafe { (bs().allocate_pages)(ALLOCATE_ADDRESS, LOADER_CODE, pages, &mut at) } != SUCCESS {
        say!(
            "[loader] kernel range busy base=0x{:x} len=0x{:x}",
            kernel.base,
            kernel.len
        );
        // Name what holds the span, so the fix — a different `[memory]
        // ram_base` for the target — is chosen from the firmware's own map.
        let mut map = MapBuf::new();
        if map.read() == SUCCESS {
            for d in map.descriptors() {
                let end = d.physical_start + d.number_of_pages * 4096;
                if d.kind != CONVENTIONAL_MEMORY
                    && d.physical_start < kernel.base + kernel.len
                    && end > kernel.base
                {
                    say!(
                        "[loader] kernel range busy: efi_type={} 0x{:x}+0x{:x}",
                        d.kind,
                        d.physical_start,
                        end - d.physical_start
                    );
                }
            }
            for d in map.descriptors() {
                if d.kind == CONVENTIONAL_MEMORY && d.number_of_pages >= (kernel.len >> 12) {
                    say!(
                        "[loader] free span: 0x{:x}+0x{:x}",
                        d.physical_start,
                        d.number_of_pages * 4096
                    );
                }
            }
        }
        shutdown("the kernel's RAM span is not free");
    }
    if !file.read_at(0, kernel.base as *mut u8, size as usize) {
        shutdown("reading fluxor.img failed");
    }
    drop(file);
    say!(
        "[loader] image bytes={size} kernel_bytes={} at=0x{:x} kernel_ram=0x{:x}+0x{:x}",
        header.kernel_bytes,
        kernel.base,
        kernel.base,
        kernel.len
    );

    // Everything handed over, allocated before the final map read.
    let mut p: *mut c_void = core::ptr::null_mut();
    let regions_bytes =
        core::mem::size_of::<[MemRegion; MAX_REGIONS]>() + core::mem::size_of::<BootInfo>();
    // SAFETY: boot-service pool allocation.
    if unsafe { (bs().allocate_pool)(LOADER_DATA, regions_bytes, &mut p) } != SUCCESS {
        shutdown("cannot allocate the handoff");
    }
    let regions = p as *mut [MemRegion; MAX_REGIONS];
    // SAFETY: the BootInfo follows the region array in the same allocation.
    let boot_info = unsafe { (p as *mut u8).add(core::mem::size_of::<[MemRegion; MAX_REGIONS]>()) }
        as *mut BootInfo;
    let mut map = MapBuf::new();

    // The last console output: the map summary, from a read that is then
    // repeated, unchanged, for the exit.
    if map.read() != SUCCESS {
        shutdown("GetMemoryMap failed");
    }
    // SAFETY: our allocation, sized for MAX_REGIONS.
    let (n, dropped) = map.translate(unsafe { &mut *regions }, kernel);
    let mut usable = 0u64;
    let mut largest = Range::default();
    // SAFETY: our allocation; `translate` filled `n` entries.
    for r in unsafe { &(&*regions)[..n] } {
        if r.kind == MemKind::Usable {
            usable += r.len;
            if r.len > largest.len {
                largest = Range {
                    base: r.base,
                    len: r.len,
                };
            }
        }
    }
    say!(
        "[loader] memmap regions={n} dropped={dropped} usable_mib={} largest=0x{:x}+0x{:x}",
        usable >> 20,
        largest.base,
        largest.len
    );
    say!("[loader] exit_boot_services");

    // From here no console: a console write can allocate inside the
    // firmware and so change the map key. Read the map, exit; on a stale key
    // (`EFI_INVALID_PARAMETER`) read it again and retry. After the first
    // attempt the firmware may have shut boot services down in part, and
    // only the memory-allocation services (GetMemoryMap among them) and
    // ExitBootServices may be called: the console goes quiet before it, and
    // a failure after it powers off without saying why.
    let mut tries = 0;
    loop {
        if map.read() != SUCCESS {
            shutdown("GetMemoryMap failed at exit");
        }
        CONSOLE_LIVE.store(false, Ordering::Relaxed);
        // SAFETY: the key from the read just made.
        let st = unsafe { (bs().exit_boot_services)(image_handle, map.key) };
        if st == SUCCESS {
            break;
        }
        tries += 1;
        if st != INVALID_PARAMETER || tries > 4 {
            shutdown("ExitBootServices refused");
        }
    }

    // Boot services are gone. Fill the handoff from the final map.
    // SAFETY: our allocation, still ours: the firmware no longer runs.
    let (n, _) = map.translate(unsafe { &mut *regions }, kernel);
    // SAFETY: as above.
    unsafe {
        boot_info.write(BootInfo {
            magic: BOOT_INFO_MAGIC,
            regions: regions as u64,
            region_count: n as u64,
            rsdp,
            image: Range {
                base: kernel.base,
                len: size,
            },
            kernel_ram: kernel,
            entropy: seed,
            entropy_len: seed_len,
            entry_el: current_el(),
            unix_millis_at_handoff: now_ms,
            boot_cpu_id: mpidr(),
            console_type,
            console_access_bytes: console_access,
            console_base,
        });
    }
    clean_to_poc(kernel.base, size);
    clean_to_poc(p as u64, regions_bytes as u64);
    clean_to_poc(loader.base, loader.len);
    // SAFETY: after ExitBootServices, everything the kernel reads is at PoC.
    unsafe { jump(kernel.base, boot_info as u64) }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    say!("[loader] panic: {}", info.message());
    loop {
        // SAFETY: wait-for-interrupt has no memory effects.
        unsafe { core::arch::asm!("wfi") };
    }
}

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
// place the image and reserve its RAM, then sets up FP/SIMD, the boot stack
// and BSS and calls `uefi_main`, which checks the handoff, reports it on the
// console UART in one `[boot] stage=kernel_entry` line and parks the core.
//
// With the MMU off every data access is Device memory, where an unaligned
// access faults. The target (`aarch64-unknown-none`) compiles with
// `strict-align`, and the handoff is read field by field at each field's
// own width.

use core::arch::global_asm;
use core::panic::PanicInfo;

use fluxor_contracts::boot::{
    BootInfo, MemKind, MemRegion, BOOT_INFO_MAGIC, CONSOLE_16550, CONSOLE_16550_GAS,
    CONSOLE_PL011, CONSOLE_SBSA,
};

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
    "    b.ne 2f",
    "    mrs x9, cptr_el2",
    "    bic x9, x9, #(1 << 10)",
    "    msr cptr_el2, x9",
    "2:",
    "    mov x9, #(3 << 20)",
    "    msr cpacr_el1, x9",
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
                    while core::ptr::read_volatile((self.base + 0x18) as *const u32) & (1 << 5) != 0 {}
                    core::ptr::write_volatile(self.base as *mut u32, u32::from(c));
                }
                _ => {
                    // LSR.THRE (bit 5) set when the holding register is empty.
                    let lsr = self.base + 5 * self.stride;
                    if self.stride >= 4 {
                        while core::ptr::read_volatile(lsr as *const u32) & (1 << 5) == 0 {}
                        core::ptr::write_volatile(self.base as *mut u32, u32::from(c));
                    } else {
                        while core::ptr::read_volatile(lsr as *const u8) & (1 << 5) == 0 {}
                        core::ptr::write_volatile(self.base as *mut u8, c);
                    }
                }
            }
        }
    }

    fn puts(&self, s: &str) {
        let p = s.as_ptr();
        for i in 0..s.len() {
            // SAFETY: within `s`; one byte at a time, so never unaligned.
            let c = unsafe { core::ptr::read_volatile(p.add(i)) };
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

#[no_mangle]
extern "C" fn uefi_main(info: *const BootInfo) -> ! {
    // SAFETY: the loader's handoff, cleaned to the point of coherency before
    // the jump; read only after its magic is checked.
    let info = unsafe {
        if info.is_null() || core::ptr::read_volatile(core::ptr::addr_of!((*info).magic)) != BOOT_INFO_MAGIC {
            park();
        }
        &*info
    };
    if let Some(con) = Console::from_boot(info) {
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
    park()
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

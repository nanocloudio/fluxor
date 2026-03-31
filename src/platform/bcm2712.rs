// Platform: BCM2712 (Raspberry Pi 5 / CM5) — Cortex-A76, aarch64 bare-metal
//
// QEMU virt: PL011 UART at 0x0900_0000, GICv2 at 0x0800_0000/0x0801_0000,
// ARM Generic Timer PPI 30 for 1ms scheduler tick.
//
// Fully config-driven: YAML → config.bin + modules.bin embedded at compile time.
// The kernel just boots hardware, loads config, wires channels, and runs the graph.

use core::panic::PanicInfo;
use core::arch::global_asm;

use fluxor::kernel::scheduler;
use fluxor::kernel::loader;

// Embedded module table + config — built by `make vm`
#[repr(C, align(4096))]
struct PageAligned([u8; include_bytes!("../../target/bcm2712/modules.bin").len()]);
static MODULE_BLOB: PageAligned = PageAligned(*include_bytes!("../../target/bcm2712/modules.bin"));
static MODULE_TABLE: &[u8] = &MODULE_BLOB.0;

#[repr(C, align(4))]
struct ConfigAligned([u8; include_bytes!("../../target/bcm2712/config.bin").len()]);
static CONFIG_BLOB: ConfigAligned = ConfigAligned(*include_bytes!("../../target/bcm2712/config.bin"));
static CONFIG_DATA: &[u8] = &CONFIG_BLOB.0;

// ============================================================================
// UART (PL011 on QEMU virt)
// ============================================================================

const UART_BASE: *mut u8 = 0x0900_0000 as *mut u8;

fn uart_putc(c: u8) {
    unsafe { core::ptr::write_volatile(UART_BASE, c) };
}

fn uart_puts(s: &[u8]) {
    let mut i = 0;
    while i < s.len() { uart_putc(s[i]); i += 1; }
}

fn uart_put_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    if n == 0 { uart_putc(b'0'); return; }
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; uart_putc(buf[i]); }
}

fn uart_put_hex64(val: u64) {
    let hex = b"0123456789abcdef";
    let mut i = 60i32;
    while i >= 0 {
        uart_putc(hex[((val >> i as u64) & 0xf) as usize]);
        i -= 4;
    }
}

// ============================================================================
// GICv2
// ============================================================================

const GICD_BASE: usize = 0x0800_0000;
const GICC_BASE: usize = 0x0801_0000;
const GICC_IAR: *mut u32 = (GICC_BASE + 0x00C) as *mut u32;
const GICC_EOIR: *mut u32 = (GICC_BASE + 0x010) as *mut u32;
const TIMER_PPI: u32 = 30;

unsafe fn gic_init() {
    core::ptr::write_volatile(GICD_BASE as *mut u32, 1); // GICD_CTLR
    core::ptr::write_volatile((GICD_BASE + 0x100) as *mut u32, 1u32 << TIMER_PPI); // ISENABLER0
    core::ptr::write_volatile((GICD_BASE + 0x400 + TIMER_PPI as usize) as *mut u8, 0); // priority
    core::ptr::write_volatile((GICC_BASE + 0x004) as *mut u32, 0xFF); // PMR
    core::ptr::write_volatile(GICC_BASE as *mut u32, 1); // GICC_CTLR
}

// ============================================================================
// ARM Generic Timer
// ============================================================================

fn timer_freq() -> u64 {
    let freq: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    freq
}

unsafe fn timer_set(ticks: u32) {
    core::arch::asm!(
        "msr cntp_tval_el0, {val}",
        "mov {ctl}, #1",
        "msr cntp_ctl_el0, {ctl}",
        val = in(reg) ticks as u64,
        ctl = out(reg) _,
    );
}

// ============================================================================
// Exception vectors
// ============================================================================

global_asm!(
    ".section .text",
    ".balign 2048",
    "exception_vectors:",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    // IRQ handler — save all caller-saved registers
    ".balign 128",
    "sub sp, sp, #256",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x29, x30, [sp, #160]",
    "bl irq_handler",
    "ldp x0,  x1,  [sp, #0]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x29, x30, [sp, #160]",
    "add sp, sp, #256",
    "eret",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    // Lower EL (8 entries)
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    "unhandled_exception:",
    "stp x29, x30, [sp, #-16]!",
    "stp x0, x1, [sp, #-16]!",
    "mrs x0, elr_el1",
    "mrs x1, esr_el1",
    "mrs x2, far_el1",
    "bl exception_dump",
    "ldp x0, x1, [sp], #16",
    "ldp x29, x30, [sp], #16",
    "1: wfe",
    "b 1b",
);

#[no_mangle]
unsafe extern "C" fn exception_dump(elr: u64, esr: u64, far: u64) {
    uart_puts(b"\r\n!!! EXCEPTION\r\n");
    uart_puts(b"  ELR=0x"); uart_put_hex64(elr);
    uart_puts(b"\r\n  ESR=0x"); uart_put_hex64(esr);
    uart_puts(b"\r\n  FAR=0x"); uart_put_hex64(far);
    uart_puts(b"\r\n");
}

static mut TICKS_PER_MS: u32 = 0;

#[no_mangle]
unsafe extern "C" fn irq_handler() {
    let iar = core::ptr::read_volatile(GICC_IAR);
    let int_id = iar & 0x3FF;
    if int_id == TIMER_PPI {
        timer_set(TICKS_PER_MS);
        scheduler::DBG_TICK += 1;
    }
    core::ptr::write_volatile(GICC_EOIR, iar);
}

// ============================================================================
// Entry point
// ============================================================================

global_asm!(
    ".section .text._start",
    ".global _start",
    ".type _start, @function",
    "_start:",
    "    mov x0, #(3 << 20)",
    "    msr cpacr_el1, x0",
    "    isb",
    "    adr x0, __bss_start",
    "    adr x1, __bss_end",
    "0:  cmp x0, x1",
    "    b.ge 1f",
    "    str xzr, [x0], #8",
    "    b 0b",
    "1:",
    "    ldr x30, =__stack_end",
    "    mov sp, x30",
    "    bl main",
    "2:  wfe",
    "    b 2b",
);

#[no_mangle]
pub extern "C" fn main() -> ! {
    uart_puts(b"[fluxor] bcm2712 boot\r\n");

    static LOGGER: UartLogger = UartLogger;
    unsafe { log::set_logger_racy(&LOGGER).ok() };
    log::set_max_level(log::LevelFilter::Info);

    // Exception vectors + GIC + timer
    unsafe {
        core::arch::asm!("adr {tmp}, exception_vectors", "msr vbar_el1, {tmp}", tmp = out(reg) _);
        gic_init();
        let freq = timer_freq();
        TICKS_PER_MS = if freq > 0 { (freq / 1000) as u32 } else { 62500 };
        timer_set(TICKS_PER_MS);
        core::arch::asm!("msr daifclr, #2"); // enable IRQs
    }

    // Initialize syscall table and provider registry
    fluxor::kernel::syscalls::init_syscall_table();
    fluxor::kernel::syscalls::init_providers();

    // --- Config-driven module graph ---
    use fluxor::kernel::channel;
    use fluxor::kernel::config::{self, MAX_MODULES};

    // Parse config
    let mut cfg = config::Config::empty();
    if !config::read_config_from_ptr(CONFIG_DATA.as_ptr(), &mut cfg) {
        uart_puts(b"[config] parse failed\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }
    let n_modules = cfg.module_count as usize;
    let n_edges = cfg.edge_count as usize;
    uart_puts(b"[config] ");
    uart_put_u32(n_modules as u32);
    uart_puts(b" modules, ");
    uart_put_u32(n_edges as u32);
    uart_puts(b" edges\r\n");

    // Load module table
    loader::reset_state_arena();
    let mut ldr = loader::ModuleLoader::new();
    if ldr.init_from_blob(MODULE_TABLE.as_ptr()).is_err() {
        uart_puts(b"[loader] no modules\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }

    // Create channels from graph edges
    // Per-module channel assignment: first in-edge → in_chan, first out-edge → out_chan
    let mut mod_in: [i32; MAX_MODULES] = [-1; MAX_MODULES];
    let mut mod_out: [i32; MAX_MODULES] = [-1; MAX_MODULES];
    let mut mod_ctrl: [i32; MAX_MODULES] = [-1; MAX_MODULES];

    let mut e = 0usize;
    while e < n_edges {
        if let Some(ref edge) = cfg.graph_edges[e] {
            let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
            if ch >= 0 {
                let from = edge.from_id as usize;
                let to = edge.to_id as usize;
                // Source module: this channel is an output
                if from < MAX_MODULES && mod_out[from] < 0 {
                    mod_out[from] = ch;
                }
                // Dest module: this channel is an input (or ctrl)
                if to < MAX_MODULES {
                    if edge.to_port == 0 && mod_in[to] < 0 {
                        mod_in[to] = ch;
                    } else if edge.to_port == 1 && mod_ctrl[to] < 0 {
                        mod_ctrl[to] = ch;
                    }
                }
            }
        }
        e += 1;
    }

    // Mask IRQs during module instantiation
    let _inst_guard = fluxor::kernel::guard::KernelGuard::acquire();

    let syscalls = fluxor::kernel::syscalls::get_table_for_module_type(0);

    const MAX_MODS: usize = 8;
    let mut modules: [Option<loader::DynamicModule>; MAX_MODS] = [const { None }; MAX_MODS];
    let mut mod_count = 0usize;

    let mut i = 0usize;
    while i < n_modules && i < MAX_MODS {
        if let Some(ref entry) = cfg.modules[i] {
            if let Ok(m) = ldr.find_by_name_hash(entry.name_hash) {
                // Set current module index so heap init and syscalls work
                fluxor::kernel::scheduler::set_current_module(mod_count);
                let result = unsafe {
                    loader::DynamicModule::start_new(
                        &m, syscalls,
                        mod_in[i], mod_out[i], mod_ctrl[i],
                        entry.params_ptr, entry.params_len, "",
                    )
                };
                match result {
                    Ok(loader::StartNewResult::Ready(dm)) => {
                        modules[mod_count] = Some(dm);
                        mod_count += 1;
                    }
                    Ok(loader::StartNewResult::Pending(mut pending)) => {
                        for _ in 0..100 {
                            for _ in 0..10000 { unsafe { core::arch::asm!("nop") }; }
                            match unsafe { pending.try_complete() } {
                                Ok(Some(dm)) => {
                                    modules[mod_count] = Some(dm);
                                    mod_count += 1;
                                    break;
                                }
                                Ok(None) => {}
                                Err(e) => { e.log("module"); break; }
                            }
                        }
                    }
                    Err(e) => e.log("module"),
                }
            }
        }
        i += 1;
    }

    // Re-enable IRQs
    drop(_inst_guard);

    uart_puts(b"[inst] ");
    uart_put_u32(mod_count as u32);
    uart_puts(b" modules loaded\r\n");

    uart_puts(b"[sched] starting\r\n");

    // Main loop — step all modules, that's it
    use fluxor::modules::Module;
    loop {
        unsafe { core::arch::asm!("wfi") };
        unsafe { scheduler::DBG_TICK += 1; }
        let tick = unsafe { scheduler::DBG_TICK };

        let mut j = 0;
        while j < mod_count {
            if let Some(ref mut m) = modules[j] { let _ = m.step(); }
            j += 1;
        }

        if tick % 10000 == 0 {
            log::info!("[sched] alive t={}", tick);
        }
    }
}

// ============================================================================
// log crate backend
// ============================================================================

struct UartLogger;

impl log::Log for UartLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool { true }
    fn log(&self, record: &log::Record) {
        use core::fmt::Write;
        struct UartWriter;
        impl Write for UartWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                for b in s.bytes() { uart_putc(b); }
                Ok(())
            }
        }
        let _ = core::fmt::write(&mut UartWriter, *record.args());
        uart_puts(b"\r\n");
    }
    fn flush(&self) {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uart_puts(b"[fluxor] PANIC\r\n");
    loop { unsafe { core::arch::asm!("wfi") }; }
}

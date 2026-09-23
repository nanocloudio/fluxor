// Platform: BCM2712 (Raspberry Pi 5) — Cortex-A76, aarch64 bare-metal
//
// Two board configurations (selected at compile time):
//   - QEMU virt (default): PL011 at 0x0900_0000, GICv2 at 0x0800_0000, RAM at 0x4008_0000
//   - Pi 5 (feature "board-pi5"): PL011 at 0xFE20_1000, GIC-400 at 0xFF84_1000, RAM at 0x8_0000
//
// Features:
//   - Secondary core parking (Pi 5 boots all 4 cores; cores 1-3 wait in WFE)
//   - Early MMU init with identity-mapped page tables (cacheable DRAM, device MMIO)
//   - RP1 peripheral access via PCIe BAR (GPIO, SPI, I2C register bridges)
//   - Multi-domain execution with config-driven domain assignment and core wakeup
//
// Fully config-driven: the boot image carries trailer, modules.bin, and config.bin
// after the fixed kernel binary, discovered at runtime via the layout trailer.

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use fluxor::kernel::boot::config::EdgeClass;
use fluxor::kernel::module::loader;
use fluxor::platform::multicore;
use fluxor::platform::{mmu, mpu};
use fluxor::kernel::exec::scheduler;

// ── Boot-time submodules (binary-private; not exposed via fluxor::kernel) ──
//
// Boot-only support code (UART driver, GIC distributor, ARM Generic
// Timer, RP1 HAL, exception vectors, boot-time MMU page tables,
// kernel `log` backend) is factored into focused submodules under
// `src/platform/bcm2712/` and consumed by `main()`, the domain
// loops, and the BCM HAL ops table.
//
// Submodules that hold shared kernel state (PCIe enumeration,
// runtime MMU isolation, cross-domain channels, NIC DMA arena, paged
// memory) are declared in `src/kernel/mod.rs` and reachable as
// `fluxor::kernel::{pcie, mmu, multicore, nic_ring, …}`. They are
// **not** redeclared here — a loaded module's kernel-facing surface
// is the `fluxor::kernel` namespace, never `src/platform/*`.
#[path = "bcm2712/boot_mmu.rs"]
mod boot_mmu;
#[path = "bcm2712/exception.rs"]
mod exception;
#[path = "bcm2712/gic.rs"]
mod gic;
#[path = "bcm2712/logger.rs"]
mod logger;
#[path = "bcm2712/rp1.rs"]
mod rp1;
#[path = "bcm2712/timer.rs"]
mod timer;
#[path = "bcm2712/uart.rs"]
mod uart;

// Bring UART + GIC + exception names into the binary's namespace so
// existing callsites (`uart_puts(b"…")`, `irq_bind(…)`, `GICD_BASE`,
// `IRQ_BINDING_COUNT`, `NEXT_DEADLINE_TICKS`, `CORE_TICKS`,
// `current_core_id()`, …) stay unchanged. The submodules own the MMIO
// registers, log-ring drain, debug-tx sink, GIC distributor + CPU
// interface init, IRQ binding state, exception vectors, and the IRQ
// dispatch path.
use exception::*;
use gic::*;
use logger::RingLogger;
use uart::*;

// ============================================================================
// Platform address constants (compile-time board selection)
// ============================================================================

// UART (PL011) — see `bcm2712/uart.rs` for the driver. The `use uart::*`
// in the submodule block above brings UART_BASE/UART_DR/UART_FR/etc.
// into this file's namespace alongside the read/write functions.

// GIC base addresses, IAR/EOIR pointers, and TIMER_PPI live in
// `bcm2712/gic.rs` (brought in via `use gic::*` near the top of this
// file). The constants stay name-identical so existing references in
// the boot path resolve through the glob import unchanged.
#[cfg(not(feature = "board-pi5"))]
const QEMU_CONFIG_BLOB_ADDR: usize = 0x6100_0000;
#[cfg(not(feature = "board-pi5"))]
const QEMU_MODULES_BLOB_ADDR: usize = 0x6200_0000;

global_asm!(
    ".section .layout_header,\"a\"",
    ".global __package_header_start",
    ".global __package_source_start",
    "__package_header_start:",
    "    .word 0x4B505846", // PACKAGE_HEADER_MAGIC
    "    .byte 1, 0, 0, 0", // version + reserved
    // runtime_end: end of file-backed sections (must NOT include BSS
    // or stack). The kernel resolves the trailer via this same symbol
    // through `config::get_trailer_addr()`. `_start`'s relocator copies
    // `package_size` bytes here only when package_size != 0; RAM-loaded
    // aarch64 images leave it at 0 and skip the copy.
    "    .word __end_data_addr",
    "    .word 0", // package_size (RP/XIP post-BSS relocation only)
    "__package_source_start:",
);

// PL011 UART registers + driver moved to `bcm2712/uart.rs`.

// ============================================================================
// BCM2712 PCIe Root Complex
// ============================================================================
//
// RP1 is connected via PCIe x4. VPU firmware (with enable_rp1_uart=1 and
// pciex4_reset=0 in config.txt) brings up the link and maps RP1 at
// 0x1c_0000_0000 before kernel handoff. We only need to disable ASPM
// for reliable infrequent-access patterns (per RP1 datasheet §3.3.1.3).
// PCIe root complex (onboard) MMIO base — used by rp1_pcie_disable_aspm.
#[cfg(feature = "board-pi5")]
const PCIE_RC_BASE: usize = 0x10_0012_0000;
#[cfg(feature = "board-pi5")]
const PCIE_MISC_HARD_PCIE_HARD_DEBUG: usize = 0x4304;
#[cfg(feature = "board-pi5")]
const PCIE_MISC_UBUS_CTRL: usize = 0x40a4;

#[cfg(feature = "board-pi5")]
#[inline(always)]
unsafe fn pcie_read(off: usize) -> u32 {
    core::ptr::read_volatile((PCIE_RC_BASE + off) as *const u32)
}

#[cfg(feature = "board-pi5")]
#[inline(always)]
unsafe fn pcie_write(off: usize, val: u32) {
    core::ptr::write_volatile((PCIE_RC_BASE + off) as *mut u32, val);
}

/// Disable ASPM on the PCIe RC so that
/// writes from infrequent access patterns (ours) don't get stalled or
/// dropped by L1 wake latency. Per RP1 datasheet §3.3.1.3.
///
/// Does NOT toggle PCIe resets or touch the outbound window — VPU firmware
/// already brought the link up at kernel handoff.
#[cfg(feature = "board-pi5")]
unsafe fn rp1_pcie_disable_aspm() {
    // HARD_PCIE_HARD_DEBUG (+0x4304 on Pi 5 RC).
    //  bit 1  = CLKREQ_DEBUG_ENABLE
    //  bit 16 = REFCLK_OVRD_ENABLE
    //  bit 20 = REFCLK_OVRD_OUT
    //  bit 21 = L1SS_ENABLE
    // Clearing these matches `brcm_pcie_start_link` phase 1 in pcie-brcmstb.c.
    let mut tmp = pcie_read(PCIE_MISC_HARD_PCIE_HARD_DEBUG);
    tmp &= !0x0032_0002;
    pcie_write(PCIE_MISC_HARD_PCIE_HARD_DEBUG, tmp);

    // UBUS error suppression — without REPLY_ERR_DIS, a read to an unmapped
    // PCIe address raises an AXI external abort. Set it so UART writes
    // (which target legitimate addresses) aren't ambient-affected by stray
    // reads elsewhere in the kernel.
    let mut tmp = pcie_read(PCIE_MISC_UBUS_CTRL);
    tmp |= (1 << 13) | (1 << 19);
    pcie_write(PCIE_MISC_UBUS_CTRL, tmp);
}

// ============================================================================
// RP1 Ethernet (Cadence GEM_GXL 1p09) — register map
// ============================================================================
//
// Two MMIO regions:
//   eth     @ 0x1c_0010_0000 (16 kB)   Cadence GEM core
//   eth_cfg @ 0x1c_0010_4000 (16 kB)   RP1 wrapper (clkgen, TSU, irq mux)
//   pads_eth@ 0x1c_000f_c000           RGMII pad config
//
// Core offsets from Linux drivers/net/ethernet/cadence/macb.h (MACB + GEM
// classic register indices) cross-referenced with RP1 datasheet §7.
//
// VPU firmware leaves the GEM powered, clocked, and out of reset at kernel
// handoff — ethernet works under Linux with no clock/reset setup in the
// macb driver path. We rely on that state for initial bring-up.

#[cfg(feature = "board-pi5")]
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod eth {
    pub const GEM_BASE: usize = 0x1c_0010_0000;
    pub const ETH_CFG_BASE: usize = 0x1c_0010_4000;

    // --- Cadence GEM core register offsets ---
    pub const NCR: usize = 0x000; // Network Control
    pub const NCFGR: usize = 0x004; // Network Config
    pub const NSR: usize = 0x008; // Network Status (MDIO idle etc)
    pub const TSR: usize = 0x014; // Transmit Status
    pub const RBQP: usize = 0x018; // classic MACB RX Queue Ptr
    pub const TBQP: usize = 0x01c; // classic MACB TX Queue Ptr
    pub const RSR: usize = 0x020; // Receive Status
    pub const ISR: usize = 0x024;
    pub const IER: usize = 0x028;
    pub const IDR: usize = 0x02c;
    pub const IMR: usize = 0x030;
    pub const MAN: usize = 0x034; // PHY Maintenance (MDIO)
    pub const HRB: usize = 0x090; // Hash Bottom
    pub const HRT: usize = 0x094; // Hash Top
    pub const SA1B: usize = 0x098; // Specific address 1 Bottom (MAC lo)
    pub const SA1T: usize = 0x09c; // Specific address 1 Top    (MAC hi)
    pub const USRIO: usize = 0x0c0; // User IO
    pub const WOL: usize = 0x0c4;
    pub const MID: usize = 0x0fc; // Module ID (RO) — Pi 5 = 0x00070109

    pub const DMACFG: usize = 0x010; // GEM DMA Config
    pub const GEM_TBQP_0: usize = 0x440; // GEM queue-0 TX BD ptr
    pub const GEM_RBQP_0: usize = 0x480; // GEM queue-0 RX BD ptr

    // --- NCR bits ---
    pub const NCR_LB: u32 = 1 << 0; // loopback
    pub const NCR_LLB: u32 = 1 << 1; // local loopback
    pub const NCR_RE: u32 = 1 << 2; // RX enable
    pub const NCR_TE: u32 = 1 << 3; // TX enable
    pub const NCR_MPE: u32 = 1 << 4; // Management port enable (MDIO)
    pub const NCR_CLRSTAT: u32 = 1 << 5;
    pub const NCR_INCSTAT: u32 = 1 << 6;
    pub const NCR_WESTAT: u32 = 1 << 7;
    pub const NCR_BP: u32 = 1 << 8;
    pub const NCR_TSTART: u32 = 1 << 9; // Start transmission
    pub const NCR_THALT: u32 = 1 << 10;

    // --- MID expected value (verified via Linux /dev/mem on DUT) ---
    pub const EXPECTED_MID: u32 = 0x0007_0109;

    // --- eth_cfg wrapper offsets (RP1 datasheet §7.1) ---
    pub const CFG_CONTROL: usize = 0x00;
    pub const CFG_STATUS: usize = 0x04; // RGMII_LINK/SPEED/DUPLEX
    pub const CFG_TSU_CNT0: usize = 0x08;
    pub const CFG_TSU_CNT1: usize = 0x0c;
    pub const CFG_TSU_CNT2: usize = 0x10;
    pub const CFG_CLKGEN: usize = 0x14; // TXCLKDELEN, ENABLE, SPEED_OVERRIDE
    pub const CFG_CLK2FC: usize = 0x18;
    pub const CFG_INTR: usize = 0x1c; // bit 0 = ETHERNET top-level irq
    pub const CFG_INTE: usize = 0x20;
    pub const CFG_INTF: usize = 0x24;
    pub const CFG_INTS: usize = 0x28;

    #[inline(always)]
    pub unsafe fn read(off: usize) -> u32 {
        core::ptr::read_volatile((GEM_BASE + off) as *const u32)
    }

    #[inline(always)]
    pub unsafe fn write(off: usize, val: u32) {
        core::ptr::write_volatile((GEM_BASE + off) as *mut u32, val);
    }

    #[inline(always)]
    pub unsafe fn cfg_read(off: usize) -> u32 {
        core::ptr::read_volatile((ETH_CFG_BASE + off) as *const u32)
    }

    #[inline(always)]
    pub unsafe fn cfg_write(off: usize, val: u32) {
        core::ptr::write_volatile((ETH_CFG_BASE + off) as *mut u32, val);
    }
}

// Timer driver lives in `src/platform/bcm2712/timer.rs` — see
// the `#[path = "bcm2712/timer.rs"] mod timer;` declaration at the
// top of this file. Public surface: `timer::{timer_freq,
// read_timer_count, timer_set}`.

// ============================================================================
// Multi-core init signaling
// ============================================================================

/// Set by core 0 once graph compilation and module instantiation have
/// finished. Cores 1..3 spin on this in `secondary_core_main` before
/// entering their domain pump.
static INIT_COMPLETE: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Entry point with secondary core parking
// ============================================================================
//
// Pi 5 GPU firmware boots all 4 Cortex-A76 cores. The _start code checks
// MPIDR_EL1.Aff0 to identify the core. Core 0 proceeds to main, cores 1-3
// park in a WFE loop.
//
// On QEMU virt with -smp 1 (default), MPIDR_EL1.Aff0 = 0, so the check
// is harmless. With -smp 4, secondary cores will park correctly.

// DTB pointer handed to us by the firmware. `main` records it once the
// MMU is up; `kernel::boot::dtb::read_ethernet_mac` consults it. Placed in
// `.data` with a non-zero sentinel to keep it out of `.bss` (which the
// boot code zeros).
#[no_mangle]
#[link_section = ".data"]
pub static mut _boot_dtb_ptr: u64 = 0xFFFF_FFFF_FFFF_FFFF;

global_asm!(
    ".section .text._start",
    ".global _start",
    ".type _start, @function",
    "_start:",
    // aarch64 Linux boot protocol: x0 = DTB physical address. Stash it in
    // x19 (callee-saved) so we can hand it to `main` after the MMU comes
    // up — storing to a symbol here would use the virtual link address,
    // which does not map anywhere real with the MMU off.
    "    mov x19, x0",
    // Core 0 proceeds; 1-3 park. Pi 5 encodes core at Aff1[15:8].
    "    mrs x0, mpidr_el1",
    "    ubfx x0, x0, #8, #8",
    "    cbnz x0, .Lpark_core",
    // ---- Primary core (core 0) continues ----
    // Pi 5 firmware hands off at EL2. Our kernel runs as EL1, so we must
    // drop down. If we're already at EL1 this short-circuits.
    "    mrs x0, CurrentEL",
    "    cmp x0, #(2 << 2)", // currently at EL2?
    "    b.ne 2f",           // no → skip EL drop
    // At EL2: disable EL2 MMU/caches and prepare an eret to EL1h.
    "    mrs x0, sctlr_el2",
    "    bic x0, x0, #(1 << 0)",  // M
    "    bic x0, x0, #(1 << 2)",  // C
    "    bic x0, x0, #(1 << 12)", // I
    "    msr sctlr_el2, x0",
    "    isb",
    // HCR_EL2.RW = 1 → EL1 is aarch64
    "    mrs x0, hcr_el2",
    "    mov x1, #(1 << 31)",
    "    orr x0, x0, x1",
    "    msr hcr_el2, x0",
    // CNTHCTL_EL2: allow EL1 physical timer / counter access
    "    mrs x0, cnthctl_el2",
    "    orr x0, x0, #(1 << 0)", // EL1PCTEN
    "    orr x0, x0, #(1 << 1)", // EL1PCEN
    "    msr cnthctl_el2, x0",
    "    msr cntvoff_el2, xzr",
    // Fake EL1h return state: DAIF all masked, SP_EL1 selected
    "    mov x0, #0x3c5", // (D|A|I|F)<<6 | 0b0101 = EL1h
    "    msr spsr_el2, x0",
    "    adr x0, 2f",
    "    msr elr_el2, x0",
    "    eret",
    "2:",
    // Now at EL1 (either originally or via eret).
    // Install exception vectors for EL1.
    "    adr x1, exception_vectors",
    "    msr vbar_el1, x1",
    "    isb",
    // Make sure EL1 MMU/caches are off. We enable them ourselves in
    // boot_mmu::enable() after setting up page tables; any residual VPU state
    // needs to be cleared so our setup actually takes effect.
    "    mrs x0, sctlr_el1",
    "    bic x0, x0, #(1 << 0)",  // M
    "    bic x0, x0, #(1 << 2)",  // C
    "    bic x0, x0, #(1 << 12)", // I
    "    msr sctlr_el1, x0",
    "    isb",
    "    ic iallu",
    "    tlbi vmalle1",
    "    dsb sy",
    "    isb",
    // Enable NEON/FP (CPACR_EL1.FPEN = 0b11)
    "    mov x0, #(3 << 20)",
    "    msr cpacr_el1, x0",
    "    isb",
    // Use SP_EL1 for kernel execution so IRQs take the EL1h/SP_ELx vector slot.
    "    msr SPSel, #1",
    "    isb",
    // Set up stack before relocating the packaged payload.
    "    ldr x30, =__stack_end",
    "    mov sp, x30",
    // If a packaged payload is appended after the image, relocate it above the
    // runtime-reserved RAM region before zeroing .bss.
    "    ldr x2, =__package_header_start",
    "    ldr w3, [x2]",
    "    movz w4, #0x5846",
    "    movk w4, #0x4B50, lsl #16",
    "    cmp w3, w4",
    "    b.ne 9f",
    "    ldr w5, [x2, #12]", // package_size
    "    cbz w5, 9f",
    "    add x6, x2, #16",  // source: bytes appended after the header
    "    ldr w7, [x2, #8]", // destination base (__end_block_addr, aligned by packer)
    // Fast 8-byte copy loop (both src and dst are 256-byte aligned by packer)
    "    bic x10, x5, #7", // x10 = size rounded down to 8-byte multiple
    "    mov x8, xzr",
    "8:  cmp x8, x10",
    "    b.ge 7f",
    "    ldr x9, [x6, x8]",
    "    str x9, [x7, x8]",
    "    add x8, x8, #8",
    "    b 8b",
    // Copy remaining 0-7 tail bytes
    "7:  cmp x8, x5",
    "    b.ge 9f",
    "    ldrb w9, [x6, x8]",
    "    strb w9, [x7, x8]",
    "    add x8, x8, #1",
    "    b 7b",
    "9:",
    // Zero BSS
    "    ldr x0, =__bss_start",
    "    ldr x1, =__bss_end",
    "0:  cmp x0, x1",
    "    b.ge 1f",
    "    str xzr, [x0], #8",
    "    b 0b",
    "1:",
    // Jump to Rust main — pass DTB pointer (firmware-provided) as first arg.
    "    mov x0, x19",
    "    bl main",
    // Should never return
    "2:  b 2b",
    // Secondary-core fallback park. On Pi 5, ATF holds cores 1-3 in
    // its own PSCI-managed state and never dispatches them into
    // `_start`; `wake_secondary_cores` brings them up through PSCI
    // CPU_ON, which jumps straight into `secondary_core_trampoline`.
    // This label only matters for firmware variants that hand cores
    // 1-3 to the kernel image at boot.
    ".Lpark_core:",
    "    wfi",
    "    b .Lpark_core",
);

// ============================================================================
// Graph instantiation + activation
// ============================================================================

/// Instantiate every module in a compiled graph and activate per-domain
/// scheduler state. Shared by first boot and live rebuild: both call
/// `prepare_graph()` then this. Returns the count of modules loaded.
///
/// `module_list`/`module_count` come from `scheduler::prepare_graph()`. IRQs are
/// masked for the duration via the kernel guard. Caller owns cross-domain edge
/// bridging (boot does it inline before this; single-domain rebuild needs none).
fn instantiate_and_activate(
    module_list: &[Option<fluxor::kernel::boot::config::ModuleEntry>],
    module_count: usize,
) -> Result<usize, usize> {
    // Mask IRQs during module instantiation
    let _inst_guard = fluxor::kernel::sys::guard::KernelGuard::acquire();

    // Ownership must be live before any provider handle is opened. See `kernel::exec::bare_metal` for why the
    // ordering is load-bearing and why this fails closed.
    if let Err(e) = fluxor::kernel::exec::bare_metal::apply_owner_plan() {
        panic!("[owner] staged plan invalid ({e:?}); refusing to run the graph with ownership isolation disabled");
    }

    // SAFETY: boot-time read.
    let loader_ref = unsafe { scheduler::static_loader() };
    // SAFETY: scheduler-thread mutable access during graph instantiation.
    let sched = unsafe { scheduler::sched_mut() };
    let mut total_mods = 0usize;
    let mut failed = 0usize;
    for (module_idx, slot) in module_list.iter().enumerate().take(module_count) {
        let entry = match slot {
            Some(e) => e,
            None => continue,
        };
        if entry.domain_id as usize >= multicore::MAX_DOMAINS {
            uart_puts(b"[inst] invalid domain_id for module ");
            uart_put_u32(module_idx as u32);
            uart_puts(b"\r\n");
            continue;
        }
        scheduler::set_current_module(module_idx);
        let result = scheduler::instantiate_one_module(
            loader_ref,
            entry,
            module_idx,
            module_idx,
            &mut sched.edges,
            &mut sched.modules,
            &mut sched.ports,
        );
        match result {
            scheduler::InstantiateResult::Done => {
                total_mods += 1;
            }
            scheduler::InstantiateResult::Pending(mut pending) => {
                let mut loaded = false;
                for _ in 0..100 {
                    for _ in 0..10000 {
                        // SAFETY: NOP is a hint; safe spin delay.
                        unsafe { core::arch::asm!("nop") };
                    }
                    // SAFETY: `pending` was allocated by instantiate_one_module
                    // and lives across these poll iterations.
                    match unsafe { pending.try_complete() } {
                        Ok(Some(dm)) => {
                            scheduler::store_dynamic_module(module_idx, dm);
                            total_mods += 1;
                            loaded = true;
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            e.log("module");
                            loaded = true;
                            break;
                        }
                    }
                }
                if !loaded {
                    uart_puts(b"[inst] module ");
                    uart_put_u32(module_idx as u32);
                    uart_puts(b" pending timeout\r\n");
                    failed += 1;
                }
            }
            scheduler::InstantiateResult::Error(e) => {
                // Was an empty arm: a module could fail to load and leave no
                // trace. See `bare_metal::instantiation_is_fail_closed`.
                uart_puts(b"[inst] module ");
                uart_put_u32(module_idx as u32);
                uart_puts(b" failed rc=");
                uart_put_u32(e as u32);
                uart_puts(b"\r\n");
                failed += 1;
            }
        }
    }

    // Activate the compiled graph and log per-domain composition.
    // BCM doesn't populate `sched.edges`, so DMA-owned edges are
    // logged by walking the config's edge slice directly via
    // `log_dma_owned_edges_from_config`.
    scheduler::set_active_module_count(module_count);
    // SAFETY: scheduler-thread read of the installed static config.
    let cfg = unsafe { scheduler::static_config() };
    fluxor::kernel::exec::scheduler::log_dma_owned_edges_from_config(&cfg.graph_edges);

    // Tier 1b admission: hand every module in a Tier 1b domain to
    // the ISR-tier dispatcher. The helper picks the appropriate
    // (step_fn, state_ptr) pair from each slot and arms the
    // platform's polled-timer ISR (`bcm_isr_tier_poll`). Cooperative
    // domains are untouched; the cooperative scheduler already
    // skips ISR-tier modules via `step_one_module`.
    let isr_registered = scheduler::register_isr_tier_modules_from_graph();
    if isr_registered > 0 {
        uart_puts(b"[isr] Tier 1b admitted ");
        uart_put_u32(isr_registered as u32);
        uart_puts(b" module(s)\r\n");
    }

    let mut d = 0usize;
    while d < multicore::MAX_DOMAINS {
        let mod_count = scheduler::domain_module_count(d);
        if mod_count > 0 {
            // SAFETY: per-domain state init; on boot the domain is not yet
            // running, on rebuild its core is quiesced/parked.
            unsafe {
                let ds = multicore::domain_state(d);
                ds.core_id = d as u8; // Domain N runs on core N
                ds.module_count = mod_count as u8;
                ds.active = true;
            }
            uart_puts(b"[domain] ");
            uart_put_u32(d as u32);
            uart_puts(b": ");
            uart_put_u32(mod_count as u32);
            uart_puts(b" modules (core ");
            uart_put_u32(d as u32);
            uart_puts(b") order: ");
            let mut k = 0usize;
            while k < mod_count {
                if k > 0 {
                    uart_puts(b"->");
                }
                if let Some(g) = scheduler::domain_exec_order_at(d, k) {
                    uart_put_u32(g as u32);
                }
                k += 1;
            }
            uart_puts(b"\r\n");
        }
        d += 1;
    }

    drop(_inst_guard);
    // Fail closed: a module that did not instantiate leaves its ports
    // unwired, so the graph that would run is not the graph that was asked
    // for. `Err` carries the failure count; the caller decides how loudly to
    // refuse. See `bare_metal::instantiation_is_fail_closed`.
    if failed > 0 && fluxor::kernel::exec::bare_metal::instantiation_is_fail_closed() {
        return Err(failed);
    }
    Ok(total_mods)
}

/// Number of domains that have at least one module in the compiled graph.
fn active_domain_count() -> usize {
    (0..multicore::MAX_DOMAINS)
        .filter(|&d| scheduler::domain_module_count(d) > 0)
        .count()
}

/// Bridge every cross-domain edge of the freshly compiled graph: split each
/// edge whose endpoints live in different domains into producer-side /
/// consumer-side channels joined by a `multicore::CrossDomainChannel` SPSC
/// pump. Shared by first boot and live rebuild — a rebuild first calls
/// `multicore::reset_cross_state()` under quiesce so this re-registers from a
/// clean table, exactly like boot.
///
/// The walk reads `sched.edges` (not `cfg.graph_edges`) so an edge that is
/// part of both a fan group and a cross-domain hop is seen through its
/// rewritten endpoints. For each cross edge: open a fresh consumer-side
/// channel `W2`, register the SPSC bridge `edge.channel → W2`, and set
/// `edge.consumer_channel = W2` (`collect_input_channels` honours it, so
/// `populate_ports` lifts `W2` into the consumer's in_chans).
///
/// Returns the number of bridges established, or a diagnostic on reservation
/// shortfall. On `Err` no partial rewiring is left visible to consumers: the
/// failing edge's `consumer_channel` is untouched, and the caller decides the
/// posture (boot halts; rebuild leaves the graph idle / fail-safe).
fn bridge_cross_domain_edges() -> Result<usize, &'static str> {
    use fluxor::kernel::ipc::channel;

    // SAFETY: scheduler-thread access during graph prep (boot) or under
    // full quiesce (rebuild) — sole mutator of scheduler state either way.
    let sched = unsafe { scheduler::sched_mut() };
    let n_compiled_edges = sched.edge_count;
    let mut bridged = 0usize;
    let mut e = 0usize;
    while e < n_compiled_edges {
        let edge_snapshot = sched.edges[e];
        if edge_snapshot.channel < 0 {
            e += 1;
            continue;
        }

        let from = edge_snapshot.from_module;
        let to = edge_snapshot.to_module;
        let from_domain = scheduler::module_domain_id(from);
        let to_domain = scheduler::module_domain_id(to);
        let is_cross =
            from_domain != to_domain || edge_snapshot.edge_class == EdgeClass::CrossCore;
        if !is_cross {
            e += 1;
            continue;
        }

        // Reserve the SPSC ring, the consumer-side channel, and the
        // edge-table slot before touching `consumer_channel`, so a failure
        // never leaves a consumer rebound to a handle no pump fills.
        let cross_ch_idx = match multicore::alloc_cross_channel() {
            Some(i) => i,
            None => return Err("cross-domain SPSC rings exhausted; cannot bridge edge"),
        };

        let in_ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
        if in_ch < 0 {
            return Err("consumer-side channel alloc failed for cross-domain edge");
        }

        // Mirror the producer-side channel's mailbox flag onto the
        // consumer-side bridge channel. Without this, typed-envelope
        // edges (WsFrame, FmpMessage, etc.) shred their framing at
        // this seam: the pump writes back-to-back atomic frames into
        // a FIFO ring, the consumer's next `channel_read` returns
        // multiple envelopes coalesced, and only the first parses
        // cleanly. POLL_IN also stays latched on the leftover bytes,
        // driving the consumer module to spin on phantom reads.
        // `tests/ws.rs::cross_domain_pump_*` covers this seam on
        // the host.
        if channel::channel_is_mailbox(edge_snapshot.channel) {
            channel::channel_set_mailbox(in_ch);
        }

        let to_port_marker: u8 = if edge_snapshot.is_ctrl() { 1 } else { 0 };
        // SAFETY: cross-edge registration runs during graph prep (boot) or
        // under full quiesce (rebuild); multicore module owns the registry.
        let registered = unsafe {
            multicore::register_cross_edge(multicore::CrossDomainEdge {
                from_domain,
                from_module: from as u8,
                from_port: edge_snapshot.from_port_index,
                to_domain,
                to_module: to as u8,
                to_port: to_port_marker,
                channel_idx: cross_ch_idx as u8,
                local_out_handle: edge_snapshot.channel,
                local_in_handle: in_ch,
                pending_aux: core::sync::atomic::AtomicU32::new(u32::MAX),
            })
        };
        if registered.is_none() {
            return Err("cross-domain edge table full; cannot bridge edge");
        }

        sched.edges[e].consumer_channel = in_ch;
        // Delivery-side wake: for a `wake: true` cross-domain edge, bind
        // the CONSUMER-local channel — the consumer-side pump delivers
        // into it via `channel_write`, so the existing wake hook fires at
        // the first moment the consumer could actually read the bytes.
        // The producer-side channel is left unbound (a write-time wake is
        // guaranteed-spurious: the consumer's domain steps before it
        // pumps inbound). Wake service latency is bounded by the consumer
        // domain's tick — cutting WFI mid-sleep needs the targeted SGI
        // doorbell, gated on the WFI-wake mitigation.
        if edge_snapshot.wake_on_write {
            fluxor::kernel::ipc::channel::channel_set_wake_module(
                in_ch,
                edge_snapshot.to_module as i32,
            );
            log::info!(
                "[wake] cross-domain edge {}→{} consumer chan={} delivery-wake bound",
                edge_snapshot.from_module,
                edge_snapshot.to_module,
                in_ch
            );
        }
        bridged += 1;
        e += 1;
    }
    Ok(bridged)
}

/// Poll the live-rebuild bridge on the primary domain. Called from every
/// per-domain pump loop (cooperative / Tier 1a / Tier 1b) so the rebuild runs
/// regardless of the primary domain's tier. No-op off domain 0.
///
/// On a pending request: quiesce non-primary domains (race-free global mutation),
/// reload STATIC_CONFIG, and rebuild the graph in place — mirroring the RP loop.
/// `prepare_graph` does the destructive reset and is fail-safe on error.
/// Single-domain only: multi-domain needs cross-domain SPSC bridges
/// re-established (boot does that inline), so it is refused and left idle.
/// Full rollback to the prior generation needs the previous config retained.
fn poll_rebuild_bridge(domain_id: usize) {
    if domain_id != 0 {
        return;
    }

    // Test hook (feature `test-plan`): once, well after netconsole bring-up,
    // report the owner-table occupancy. The boot `apply_staged()` installs the
    // embedded plan's owner before the net is up (so its own log predates the
    // netconsole); this late report makes that boot-applied ownership observable
    // over the netconsole. Expect "active workloads = 1".
    #[cfg(feature = "test-plan")]
    {
        use core::sync::atomic::{AtomicBool, Ordering as TestOrd};
        static REPORTED: AtomicBool = AtomicBool::new(false);
        let t = CORE_TICKS[0].load(TestOrd::Relaxed);
        if t >= 180_000 && !REPORTED.swap(true, TestOrd::Relaxed) {
            let n = scheduler::owners().active_workload_count();
            log::info!("[test] owner table active workloads = {n}");
        }
    }

    // Test hook (feature `test-rebuild`): one-shot rebuild after a fixed number
    // of polls so the bridge can be observed on hardware. Absent from normal builds.
    #[cfg(feature = "test-rebuild")]
    {
        use core::sync::atomic::{AtomicBool, Ordering as TestOrd};
        static FIRED: AtomicBool = AtomicBool::new(false);
        // Use the wall-clock-ish CORE_TICKS counter (advanced by the timer ISR,
        // ~9.5k/s) rather than loop iterations — the cooperative pump `wfi`s, so
        // iteration count accrues far slower than ticks. 450k ticks ≈ 47 s of
        // scheduler time: long past DHCP/netconsole bring-up, so the rebuild is
        // observable over the netconsole.
        let t = CORE_TICKS[0].load(TestOrd::Relaxed);
        if t >= 450_000 && !FIRED.swap(true, TestOrd::Relaxed) {
            log::warn!("[test] one-shot rebuild trigger at tick {t}");
            // SAFETY: null/0 = reload current STATIC_CONFIG sentinel.
            unsafe { scheduler::request_rebuild(core::ptr::null(), 0) };
        }
    }

    if scheduler::take_rebuild_request().is_none() {
        return;
    }
    let expected = multicore::non_primary_active_count();
    multicore::request_quiesce();
    multicore::wait_parked(expected);
    log::warn!("[reconfigure] quiesced {expected} domains; rebuilding");
    // All non-primary domains are parked: safe to reset the cross-domain
    // bridge state so `bridge_cross_domain_edges` re-registers from a clean
    // table exactly like boot. (prepare_graph below also resets channel and
    // buffer slots, so the consumer-side bridge channels are reopened fresh.)
    // SAFETY: quiesce established above — parked pumps neither walk the edge
    // table nor touch the SPSC rings.
    unsafe { multicore::reset_cross_state() };
    match scheduler::prepare_graph() {
        Ok((module_list, module_count)) => {
            // Re-establish cross-domain bridges for the new graph, then
            // instantiate. Domain topology (exec modes / core assignment) must
            // match the running generation: parked pumps resume inside their
            // tier loop and re-read module tables per tick, but not their
            // exec mode — changing tiers needs a reboot-class system update.
            match bridge_cross_domain_edges() {
                Ok(bridges) => {
                    match instantiate_and_activate(&module_list, module_count) {
                        Ok(n) => {
                            let domains = active_domain_count();
                            log::warn!(
                                "[reconfigure] rebuilt graph: {n} modules, {domains} domain(s), \
                                 {bridges} cross-domain bridge(s)"
                            );
                        }
                        // A rebuild that cannot instantiate is refused, not
                        // run partially. The node stays up with the graph it
                        // has rather than silently becoming a different one.
                        Err(failed) => log::error!(
                            "[reconfigure] rebuild refused: {failed} module(s) failed to \
                             instantiate; the graph would run with unwired ports"
                        ),
                    }
                }
                Err(msg) => {
                    log::error!("[reconfigure] {msg}; graph left idle");
                }
            }
        }
        Err(_) => {
            log::error!("[reconfigure] prepare_graph failed; graph left idle");
        }
    }
    scheduler::set_reconfigure_phase(scheduler::ReconfigurePhase::Running);
    multicore::release_quiesce();
}

// ============================================================================
// Main entry point
// ============================================================================

#[no_mangle]
pub extern "C" fn main(dtb_phys: u64) -> ! {
    // Pi 5 bring-up sequence:
    //   1. MMU enable — DRAM cacheable, RP1 MMIO as Device-nGnRE at 0x1c.
    //   2. rp1_pcie_disable_aspm() — surgical ASPM disable on PCIe RC.
    //      VPU firmware (with enable_rp1_uart=1 + pciex4_reset=0) has
    //      already brought up the PCIe link, enabled RP1 endpoint
    //      PCI_COMMAND, and configured GPIO14/15 + PL011 for UART.
    //   3. uart_init() — reprogram PL011 to be sure (VPU may have left
    //      it configured, but we set our own baud/params).
    // SAFETY: Single boot-thread; MMU init runs once before any module
    // observes virtual addresses. RP1 ASPM disable touches MMIO mapped
    // by init_page_tables one line earlier.
    #[cfg(feature = "board-pi5")]
    unsafe {
        boot_mmu::init_page_tables();
        boot_mmu::enable();
        rp1_pcie_disable_aspm();
    }

    // SAFETY: uart_init configures the PL011 MMIO pre-driver; single-threaded boot.
    unsafe { uart_init() };
    UART_READY.store(1, Ordering::Release);
    // UART FIFO is always drained by hardware, so the local log-ring
    // consumer can activate immediately.
    fluxor::kernel::sys::log_ring::activate_local();

    // Record the DTB pointer now that the MMU is on; later DTB reads
    // dereference `_boot_dtb_ptr`.
    // SAFETY: `_boot_dtb_ptr` is a static usize; single boot-time writer.
    unsafe {
        core::ptr::write_volatile(&raw mut _boot_dtb_ptr, dtb_phys);
    }

    #[cfg(feature = "board-pi5")]
    uart_puts(b"[fluxor] bcm2712 boot (Pi 5)\r\n");
    #[cfg(not(feature = "board-pi5"))]
    uart_puts(b"[fluxor] bcm2712 boot (QEMU virt)\r\n");

    // QEMU virt: MMU init happens here (Pi 5 did it earlier, before PCIe).
    // SAFETY: MMU init runs once at boot before any module observes virt addrs.
    #[cfg(not(feature = "board-pi5"))]
    unsafe {
        boot_mmu::init_page_tables();
        boot_mmu::enable();
    }

    // Probe RP1 early on Pi 5 to confirm the PCIe BAR mapping is alive.
    rp1::report(uart_puts, uart_put_hex32);

    // Keep the GEM module-ID probe pre-logger because it only feeds
    // UART diagnostics. Full PCIe enumeration runs below so its
    // log::info! lines reach the ring (and therefore log_net -> UDP).
    #[cfg(feature = "board-pi5")]
    {
        // SAFETY: GEM_BASE + MID is the documented module-ID register at the
        // GEM MMIO base; aligned u32 read.
        let mid =
            unsafe { core::ptr::read_volatile(eth::GEM_BASE.wrapping_add(eth::MID) as *const u32) };
        uart_puts(b"[gem] MID=0x");
        uart_put_hex32(mid);
        if mid == eth::EXPECTED_MID {
            uart_puts(b" (OK)\r\n");
        } else {
            uart_puts(b" (UNEXPECTED - expected 0x00070109)\r\n");
        }
    }

    static LOGGER: RingLogger = RingLogger;
    // SAFETY: set_logger_racy is documented as "single-threaded only"; boot
    // is the only call site and runs before any module exists.
    unsafe { log::set_logger_racy(&LOGGER).ok() };
    log::set_max_level(log::LevelFilter::Info);

    // Force the active cooler to full so sustained-load rig runs aren't
    // confounded by thermal throttling. Drives the RP1 PWM channel the boot
    // firmware uses for the Pi 5 fan; the readback is logged so the rig can
    // confirm the writes took. No-op on QEMU. Placed after logger init so the
    // report reaches the UDP telemetry stream.
    rp1::cooling_full_on();

    // PCIe1 bring-up: stages 1 + 2a + 2b (reset/RESCAL + RC-wide regs
    // + MDIO tuning). Stage 2c onwards (SerDes/PERST#/link) is not driven
    // from here.
    {
        let n = fluxor::platform::pcie::enumerate();
        log::info!("[pcie] bus1 devices={n}");
    }

    // Report timer frequency
    let freq = timer::timer_freq();
    uart_puts(b"[timer] freq=");
    uart_put_u32(freq as u32);
    uart_puts(b" Hz\r\n");

    // Exception vectors + GIC + timer
    // Timer tick period will be recalculated after config is parsed (tick_us).
    // Start with 1ms default so the system runs during init.
    let default_ticks = if freq > 0 {
        (freq / 1000) as u32
    } else {
        62500
    };
    // Seed every per-core deadline slot with the 1 ms default so any core
    // that takes a timer IRQ before its domain-specific re-seed reloads a
    // sane value. Cores 1-3 overwrite their own slot in `secondary_core_main`
    // and core 0 re-seeds from config.tick_us below.
    for slot in &NEXT_DEADLINE_TICKS {
        slot.store(default_ticks, Ordering::Relaxed);
    }
    // SAFETY: GIC + generic timer init touch system control regs that the
    // boot path is the sole writer of; DAIFCLR enables IRQs after vectors
    // and step_guard are wired.
    unsafe {
        gic_init();
        timer::timer_set(default_ticks);
        core::arch::asm!("msr daifclr, #2"); // enable IRQs
    }

    uart_puts(b"[gic] initialized, IRQs enabled\r\n");

    // HAL ops, syscall table, providers, then the BCM2712
    // generic-timer-backed step guard.
    fluxor::kernel::boot(&BCM2712_HAL_OPS);
    fluxor::kernel::exec::step_guard::init();

    // --- Config-driven module graph ---
    //
    // `scheduler::prepare_graph` compiles the graph (edge decode, fan
    // module insertion, channel allocation, port-table population). This
    // platform layers the multi-core concerns on top: cross-domain
    // edges are bridged with `multicore::register_cross_edge`, and each
    // core's run loop drives `scheduler::step_domain_modules` (or
    // `step_domain_modules_poll` for Tier 3) through the shared
    // `step_one_module` body.
    use fluxor::kernel::boot::config;

    // Parse config + loader into the kernel's static state. Pi 5 scans
    // flash via the trailer; QEMU side-loads a packed blob at a fixed
    // address. `prepare_graph` reads STATIC_CONFIG / STATIC_LOADER from
    // there.
    loader::reset_state_arena();
    let static_state_ok = {
        #[cfg(not(feature = "board-pi5"))]
        {
            // SAFETY: QEMU virt's fluxor.ld places the config blob and
            // modules blob at known phys addresses; mappings established
            // by `boot_mmu::init_page_tables()` above.
            let blob_magic =
                unsafe { core::ptr::read_volatile(QEMU_CONFIG_BLOB_ADDR as *const u32) };
            // SAFETY: as above.
            let modules_blob_magic =
                unsafe { core::ptr::read_volatile(QEMU_MODULES_BLOB_ADDR as *const u32) };
            if blob_magic == config::MAGIC_CONFIG
                && modules_blob_magic == loader::MODULE_TABLE_MAGIC
            {
                // SAFETY: caller upholds `# Safety` invariant — blobs at
                // the QEMU known addresses remain mapped for the whole boot.
                unsafe {
                    // Cap the declared length to MAX_CONFIG_SIZE so the
                    // parser slice doesn't span the full 16 MB gap
                    // between QEMU_CONFIG_BLOB_ADDR and the modules
                    // blob; the parser will reject any header that
                    // declares more.
                    scheduler::populate_static_state(
                        QEMU_CONFIG_BLOB_ADDR as *const u8,
                        config::MAX_CONFIG_SIZE,
                        QEMU_MODULES_BLOB_ADDR as *const u8,
                    )
                }
                .is_ok()
            } else {
                // SAFETY: boot-time single-thread init.
                let loader_ref = unsafe { scheduler::static_loader_mut() };
                // SAFETY: as above.
                let cfg_ref = unsafe { scheduler::static_config_mut() };
                let l_ok = loader_ref.init().is_ok();
                let c_ok = config::read_config_into(cfg_ref);
                l_ok && c_ok
            }
        }
        #[cfg(feature = "board-pi5")]
        {
            // Flash-trailer path: the loader scans the packed image for
            // the module table; the config sits in the same trailer.
            // SAFETY: boot-time single-thread init.
            let loader_ref = unsafe { scheduler::static_loader_mut() };
            // SAFETY: as above.
            let cfg_ref = unsafe { scheduler::static_config_mut() };
            let l_ok = loader_ref.init().is_ok();
            let c_ok = config::read_config_into(cfg_ref);
            l_ok && c_ok
        }
    };
    if !static_state_ok {
        uart_puts(b"[config] parse / loader failed\r\n");
        loop {
            // SAFETY: WFI is a hint to halt the core; safe as a fault path.
            unsafe { core::arch::asm!("wfi") };
        }
    }
    // SAFETY: scheduler-thread boot-time read.
    let cfg = unsafe { scheduler::static_config() };
    let n_modules = cfg.module_count as usize;
    let n_edges = cfg.edge_count as usize;

    // Reconfigure the timer tick from config.tick_us.
    let tick_us = if cfg.header.tick_us > 0 {
        cfg.header.tick_us as u32
    } else {
        1000
    };
    // freq is in Hz, so ticks_per_us = freq / 1_000_000
    // ticks = tick_us * (freq / 1_000_000) = tick_us * freq / 1_000_000
    let core0_ticks = if freq > 0 {
        ((tick_us as u64) * freq / 1_000_000) as u32
    } else {
        62500 * tick_us / 1000
    };
    // Core 0 runs the default domain (domain 0); its Tier-0 cadence is the
    // global tick. Seed core 0's per-core deadline slot and arm the timer.
    // Cores 1-3 re-seed their own slots from `domain_tick_us` in
    // `secondary_core_main`; the per-core slot is what survives the IRQ
    // handler's reload, so each domain keeps its own rate.
    let core0 = (current_core_id() as usize).min(NEXT_DEADLINE_TICKS.len() - 1);
    NEXT_DEADLINE_TICKS[core0].store(core0_ticks, Ordering::Relaxed);
    // SAFETY: generic-timer regs are per-CPU; the boot core is the sole writer.
    unsafe {
        timer::timer_set(core0_ticks);
    }
    uart_puts(b"[timer] tick_us=");
    uart_put_u32(tick_us);
    uart_puts(b"\r\n");

    // Measured-option opt-in: the SGI wake doorbell and absolute `cntp_cval`
    // re-arm ship OFF by default and stay off in production. This build-time
    // feature flips them on at boot so the rig can validate them on silicon
    // without disturbing the default path.
    #[cfg(feature = "adaptive_deferred_rig")]
    {
        set_wake_doorbell(true);
        set_absolute_rearm(true);
        log::info!("[adaptive] deferred mechanisms ON (wake_doorbell + absolute_rearm) — rig validation build");
    }

    uart_puts(b"[config] ");
    uart_put_u32(n_modules as u32);
    uart_puts(b" modules, ");
    uart_put_u32(n_edges as u32);
    uart_puts(b" edges\r\n");

    // Test hook (feature `test-plan`): stage an embedded owner plan so the boot
    // `apply_staged()` exercises the live-ownership path on hardware. The blob
    // (one workload in slot 1 owning module 0) is generated by
    // `cargo run -p fluxor-tools --example emit_plan`. test-only, never shipped.
    #[cfg(feature = "test-plan")]
    {
        // One workload (slot 1, gen 2) owning module index 100 — deliberately beyond
        // any real graph module, so the stamp is observable yet harmless (it
        // does not re-own the live net-stack modules and break the netconsole).
        static TEST_PLAN: [u8; 90] = [
            0x46, 0x4c, 0x58, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xaa, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x64, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x97,
            0x01, 0x60, 0x9a, 0xb6, 0xd0, 0xd4, 0x07, 0x20, 0x5f, 0x44, 0x14, 0x8b,
            0xed, 0x5e, 0x42, 0xa9, 0x63, 0x47, 0x6b, 0x72, 0x4d, 0xc6, 0xc8, 0x58,
            0xf7, 0x14, 0x6e, 0x50, 0x2c, 0x35,
        ];
        // SAFETY: TEST_PLAN is 'static; the pointer stays valid for the run.
        unsafe {
            fluxor::kernel::workload::owner_plan::set_staged_plan(TEST_PLAN.as_ptr(), TEST_PLAN.len());
        }
        uart_puts(b"[test] staged embedded owner plan\r\n");
    }

    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(_) => {
            uart_puts(b"[graph] prepare_graph failed\r\n");
            loop {
                // SAFETY: WFI is a hint; safe as a fault path.
                unsafe { core::arch::asm!("wfi") };
            }
        }
    };

    // Cross-domain post-process: split every edge whose endpoints live
    // in different domains into producer-side / consumer-side channels
    // bridged by a `multicore::CrossDomainChannel` SPSC pump.
    //
    // The walk reads `sched.edges` (not `cfg.graph_edges`) so an edge
    // that is part of both a fan group and a cross-domain hop is seen
    // through its rewritten endpoints — the bridge lands on the actual
    // producer/consumer hop, not the original config one.
    //
    // For each cross edge, open a fresh consumer-side channel `W2`,
    // register the SPSC bridge `edge.channel → W2`, and set
    // `edge.consumer_channel = W2`. `collect_input_channels` honours
    // `consumer_channel`, so `populate_ports` lifts `W2` into the
    // consumer's in_chans.
    if let Err(msg) = bridge_cross_domain_edges() {
        // Boot posture: a reservation shortfall halts — rebinding a consumer
        // to a handle no pump fills would strand every byte the producer
        // writes, and there is no earlier generation to fall back to.
        uart_puts(b"[graph] ");
        uart_puts(msg.as_bytes());
        uart_puts(b"\r\n");
        loop {
            // SAFETY: WFI is a hint; safe as a fault path.
            unsafe { core::arch::asm!("wfi") };
        }
    }

    // Instantiate + activate the compiled graph (shared with live rebuild).
    let total_mods = match instantiate_and_activate(&module_list, module_count) {
        Ok(n) => n,
        Err(failed) => {
            // Fail closed at boot. Running a graph whose modules did not all
            // load converts a loud, local failure into a silent one that
            // surfaces later as missing data, far from the cause.
            uart_puts(b"[inst] REFUSING GRAPH: ");
            uart_put_u32(failed as u32);
            uart_puts(b" module(s) failed to instantiate\r\n");
            loop {
                // SAFETY: WFI is a hint to halt the core; the same fail-stop
                // this file already uses for a failed config parse.
                unsafe { core::arch::asm!("wfi") };
            }
        }
    };

    uart_puts(b"[inst] ");
    uart_put_u32(total_mods as u32);
    uart_puts(b" modules loaded total\r\n");

    fluxor::kernel::exec::scheduler::finalize_instantiation_accounting();

    // Admit resident workloads declared in the config's `[FXPD]` section
    // (`workloads:` / `combine <two-graph.yaml>`) as workload owners via
    // `apply_add` + finalize. Boot-time, before the run loops start. No-op
    // without a workload section; the multi-graph runner multiplexes the
    // workloads with the base graph on the shared cooperative runner.
    fluxor::kernel::exec::scheduler::admit_resident_workloads_from_config();

    // Signal init complete — secondary cores can start
    INIT_COMPLETE.store(1, Ordering::Release);

    // Log cross-domain channel status
    uart_puts(b"[cross] channels=");
    uart_put_u32(multicore::cross_edge_count() as u32);
    uart_puts(b" dma_arena_used=");
    uart_put_u32(multicore::dma_arena_used() as u32);
    uart_puts(b"\r\n");

    // Wake secondary cores that have non-empty domains assigned
    wake_secondary_cores();

    // Every counted non-primary domain is now on its way into `run_domain_loop`
    // (where it honours `park_if_requested`), so a runtime peer-core quiesce can
    // make progress. This gates the live-splice's quiesce
    // (`scheduler::live::apply_add`/`free_owner`): before this point the splice
    // runs single-threaded (boot admission), after it under a real quiesce.
    multicore::mark_smp_online();

    uart_puts(b"[sched] starting domain 0 on core 0\r\n");

    // Flush buffered early-boot log bytes to the UART before we enter
    // the tick loop. Each poll moves up to the staging size (1 KB),
    // so a short burst covers typical boot chatter; anything left
    // over flushes during the first few ticks.
    for _ in 0..8 {
        debug_drain_poll_core0();
    }

    // Main loop — domain 0 on core 0
    run_domain_loop(0)
}


// ============================================================================
// Domain execution loop
// ============================================================================

/// Run the main loop for a domain. Steps all modules assigned to that domain.
///
/// This function never returns. On core 0 it is called directly from main().
/// On secondary cores it is called from the secondary_core_main() entry point.
/// Per-domain execution metrics.
struct DomainMetrics {
    /// Total ticks processed.
    tick_count: u32,
    /// Ticks where step work exceeded 50% of tick budget.
    busy_ticks: u32,
    /// Tier 3 only: total step calls.
    poll_steps: u32,
    /// Tier 3 only: steps where all modules returned Continue (idle).
    poll_idle: u32,
    /// Tier 3 only: WFE count.
    wfe_count: u32,
    /// Worst-case step duration in timer ticks (for deadline margin).
    worst_step_ticks: u32,
}

impl DomainMetrics {
    const fn new() -> Self {
        Self {
            tick_count: 0,
            busy_ticks: 0,
            poll_steps: 0,
            poll_idle: 0,
            wfe_count: 0,
            worst_step_ticks: 0,
        }
    }
}

static mut DOMAIN_METRICS: [DomainMetrics; multicore::MAX_DOMAINS] =
    [const { DomainMetrics::new() }; multicore::MAX_DOMAINS];

/// Arm this core's next Tier-0 deadline from the pass just finished. The
/// kernel pacer chooses the next-pass
/// period (µs) from the domain's busy/idle + worst-step signals; we convert to
/// generic-timer ticks and write this core's `NEXT_DEADLINE_TICKS` slot, which
/// the `TIMER_PPI` handler reloads on the next fire. The IRQ-driven reload means
/// the chosen period takes effect on the following timer period (a one-period
/// propagation lag, acceptable for a cadence pacer).
///
/// A fixed domain (`adaptive_flags == 0`) gets the fixed `domain_tick_us` from
/// the pacer, so the slot keeps its boot-seeded value and cadence is
/// byte-identical to the non-adaptive kernel. Variable cadence (mechanisms
/// (a)/(b)) becomes active only when a domain sets adaptive flags; on bcm2712
/// multicore it also relies on the SEV/WFI wake bound described below and the
/// per-domain wake mask.
///
/// SEV-vs-WFI bound: the Tier-0 loop idles on `WFI`, broken only by an IRQ.
/// IRQ-backed wakes (device interrupts) break it immediately, but a
/// cross-domain / software wake only sets `EVENT_WAKE_PENDING` — it does NOT
/// raise an IRQ, so it cannot cut short a widened idle `WFI`; that wake is
/// serviced when the timer next fires. We therefore clamp the adaptive
/// idle/relaxed deadline so the worst-case software-wake latency is bounded (no
/// hot-path cost, no extra hardware; an SGI doorbell that interrupts `WFI`
/// directly is the measured alternative). The clamp only bites when the pacer
/// relaxes past it (idle (a) → tick_max, or (b) near tick_max); busy passes
/// return ≤ the nominal tick, far below it, so steady-state and the
/// non-adaptive default are untouched. Rig-tunable: it trades idle wakeups
/// against worst-case software-wake latency.
const BCM_IDLE_DEADLINE_CLAMP_US: u32 = 4_000;

/// Most-relaxed deadline (µs) core 0's pacer chose since the last `[therm]`
/// emit. The `[therm]` pass itself is busy (it drains the log ring → UDP), so a
/// point-sampled `dl0_us` reads low even when the domain relaxes BETWEEN emits.
/// This interval-max captures whether (a)/(b) actually reached the relaxed
/// cadence — a sampling-robust idle witness. Reset each emit.
static DL0_MAX_US: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Per-domain next-deadline (µs) produced by the most recent `domain_step_all`
/// (the resident-graph runner / single-graph pacer). `arm_next_deadline` reads
/// it instead of re-querying the pacer, so a multi-graph domain arms the
/// merged deadline rather than the per-domain single-graph one. Always written
/// by `domain_step_all` before `arm_next_deadline` runs in the same loop body.
static DOMAIN_RUNNER_DEADLINE_US: [core::sync::atomic::AtomicU32; multicore::MAX_DOMAINS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; multicore::MAX_DOMAINS];

#[inline]
fn arm_next_deadline(domain_id: usize, core_id: usize) {
    // The runner already chose this domain's next deadline during the preceding
    // `domain_step_all` (the resident-graph merge, or the single-graph pacer).
    let raw_us = if domain_id < multicore::MAX_DOMAINS {
        DOMAIN_RUNNER_DEADLINE_US[domain_id].load(Ordering::Relaxed)
    } else {
        scheduler::pacer_next_deadline_us(domain_id)
    };
    // The software-wake latency clamp applies ONLY to an adaptive relaxed
    // deadline. A fixed domain (adaptive_flags == 0) gets `domain_tick_us`
    // verbatim from the pacer and must keep it — clamping a 10 ms fixed tick to
    // 4 ms would silently re-pace it and break the byte-identical non-adaptive
    // cadence guarantee. Only mechanisms (a)/(b) can relax past the clamp.
    let next_us = if scheduler::domain_adaptive_flags(domain_id) != 0 {
        // The clamp must NOT undercut the pacer's floor: the pacer never
        // returns below `floor = max(tick_min_us, worst_step × MARGIN)`; arming
        // below it (e.g. tick_min_us > 4 ms, or a live worst-step floor > 4 ms) would run
        // the domain faster than its worst-step budget admits — a budget/floor
        // contract break. Cap relaxation at `max(CLAMP, floor)`: the clamp still
        // bounds software-wake latency when the floor is under it; a domain that
        // genuinely needs a longer minimum period gets it (its own step cadence
        // already bounds responsiveness, so no extra latency is added).
        let floor = scheduler::pacer_domain_floor_us(domain_id);
        raw_us.min(BCM_IDLE_DEADLINE_CLAMP_US.max(floor))
    } else {
        raw_us
    };
    if core_id == 0 {
        DL0_MAX_US.fetch_max(next_us, Ordering::Relaxed);
    }
    let freq = timer::timer_freq();
    let ticks = if freq > 0 {
        ((next_us as u64) * freq / 1_000_000) as u32
    } else {
        // freq read failed — same ~1 ms @ 62.5 MHz fallback the seed paths use.
        62_500
    };
    let slot = core_id.min(NEXT_DEADLINE_TICKS.len() - 1);
    NEXT_DEADLINE_TICKS[slot].store(ticks, Ordering::Relaxed);
}

fn run_domain_loop(domain_id: usize) -> ! {
    let exec_mode = scheduler::domain_exec_mode(domain_id);
    let core_id = current_core_id() as usize;

    match exec_mode {
        // ── Tier 1a: High-rate periodic (1-10 kHz) ──
        // Same as Tier 0 but with per-domain timer tick rate.
        // Timer IRQ fires at domain_tick_us; full module ABI retained.
        1 => {
            log::info!(
                "[domain] {} core={} tier=1a tick_us={}",
                domain_id,
                core_id,
                scheduler::domain_tick_us(domain_id)
            );
            loop {
                // SAFETY: WFI halts the core until next interrupt; hint-only.
                unsafe { core::arch::asm!("wfi") };
                multicore::park_if_requested(domain_id);
                let t0 = timer::read_timer_count();
                domain_step_all(domain_id);
                pump_cross_domain(domain_id);
                if core_id == 0 {
                    debug_drain_poll_core0();
                }
                let elapsed = timer::read_timer_count().wrapping_sub(t0);
                // SAFETY: DOMAIN_METRICS[d] is exclusively touched by domain `d`'s
                // pump thread; bounded by MAX_DOMAINS.
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                maybe_emit_soc_temp(core_id);
                // live-rebuild bridge (Tier 1a primary).
                poll_rebuild_bridge(domain_id);
                if elapsed > metrics.worst_step_ticks {
                    metrics.worst_step_ticks = elapsed;
                }
                // Track busy ticks (step work exceeded 50% of tick budget)
                let freq = timer::timer_freq() as u32;
                let budget_ticks = if freq > 0 {
                    (scheduler::domain_tick_us(domain_id) as u64 * freq as u64 / 1_000_000) as u32
                } else {
                    62500
                };
                if elapsed > budget_ticks / 2 {
                    metrics.busy_ticks += 1;
                }
                // Report every ~10s (at domain tick rate)
                let report_interval = 10_000_000 / scheduler::domain_tick_us(domain_id);
                if metrics.tick_count % report_interval == 0 && metrics.tick_count > 0 {
                    log::info!(
                        "[tier1a] d={} ticks={} worst={}cyc",
                        domain_id,
                        metrics.tick_count,
                        metrics.worst_step_ticks
                    );
                }
                // Cross-domain bridge health — domain 0 only (core 0 owns the
                // UDP debug drain), emitted frequently (~0.5 s at tick_us=100)
                // so the multi-lane cross-domain wedge is visible over telemetry
                // without UART. drops = SPSC ring rejected a frame; bp =
                // backpressure (ring full / consumer not ready); depth[d] =
                // pending frames queued toward domain d.
                if domain_id == 0 && xdom_due() {
                    let (drops, bp, _sb) = multicore::cross_domain_stats();
                    let depth = multicore::cross_domain_queue_depths();
                    // Per-domain liveness: tick_count (tier 0/1a) and poll_steps
                    // (tier 3). A frozen count for a lane domain means that core
                    // isn't stepping (timer/wake), distinct from a module that
                    // isn't consuming its input. SAFETY: relaxed reads of other
                    // domains' metrics for diagnostics only.
                    let (d1t, d1p, d2t, d2p) = unsafe {
                        (
                            DOMAIN_METRICS[1].tick_count,
                            DOMAIN_METRICS[1].poll_steps,
                            DOMAIN_METRICS[2].tick_count,
                            DOMAIN_METRICS[2].poll_steps,
                        )
                    };
                    // Secondary-core fault latch — a frozen lane tick_count with
                    // a nonzero fault count + ESR identifies a core that took an
                    // exception (the UART dump being invisible on this bench).
                    let f1 = exception::CORE_FAULT_COUNT[1].load(Ordering::Relaxed);
                    let f2 = exception::CORE_FAULT_COUNT[2].load(Ordering::Relaxed);
                    let e1 = exception::CORE_FAULT_ESR[1].load(Ordering::Relaxed);
                    let e2 = exception::CORE_FAULT_ESR[2].load(Ordering::Relaxed);
                    // Which module each lane core is currently stepping — if a
                    // lane's tick is frozen, this names the module it hung in.
                    let m1 = scheduler::module_index_on_core(1);
                    // HW timer-IRQ count per core (climbs even while the loop is
                    // stuck) + the last interrupted PC (the spin location).
                    let ct1 = exception::CORE_TICKS[1].load(Ordering::Relaxed);
                    // Programmed deadline for the lane core (freeze-detector
                    // aid): under variable cadence an idle core's CORE_TICKS
                    // climbs slowly *by design* — surfacing its deadline lets a
                    // reader tell "idle (widened deadline, tick_count still
                    // advancing)" from "wedged (tick_count frozen)". The frozen
                    // tick_count remains the cadence-invariant freeze signal.
                    let dl1 = exception::NEXT_DEADLINE_TICKS[1].load(Ordering::Relaxed);
                    let elr1 = exception::CORE_LAST_ELR[1].load(Ordering::Relaxed);
                    let far1 = exception::CORE_FAULT_FAR[1].load(Ordering::Relaxed);
                    let sp1 = exception::CORE_FAULT_SPSR[1].load(Ordering::Relaxed);
                    let fe1 = exception::CORE_FAULT_ELR[1].load(Ordering::Relaxed);
                    // Cross-domain flow into/out of the consensus core (d2),
                    // reported on the periodic [xdom] line. p = frames pushed
                    // to the SPSC ring, c = frames delivered to the consumer
                    // channel.
                    let xp = |a: usize, b: usize| XPUMP_PROD[a * 4 + b].load(Ordering::Relaxed);
                    let xc = |a: usize, b: usize| XPUMP_CONS[a * 4 + b].load(Ordering::Relaxed);
                    log::info!(
                        "[xdom] drops={} bp={} depth=[{},{},{},{}] d2t={} xf 1>2:{}/{} 3>2:{}/{} 2>1:{}/{} 2>3:{}/{} 2>0:{}/{}",
                        drops, bp,
                        depth[0], depth[1], depth[2], depth[3], d2t,
                        xp(1,2), xc(1,2), xp(3,2), xc(3,2),
                        xp(2,1), xc(2,1), xp(2,3), xc(2,3), xp(2,0), xc(2,0),
                    );
                    let _ = (d1p, d2p, f2, e2, d1t, ct1, dl1, m1, elr1, f1, e1, far1, sp1, fe1);
                    // If any core latched a panic, broadcast the site over UDP.
                    let pc = PANIC_CORE.load(Ordering::Relaxed);
                    if pc != 0xFFFF_FFFF {
                        let line = PANIC_LINE.load(Ordering::Relaxed);
                        let fptr = PANIC_FILE_PTR.load(Ordering::Relaxed);
                        let flen = PANIC_FILE_LEN.load(Ordering::Relaxed) as usize;
                        let file = if fptr != 0 && flen > 0 && flen < 256 {
                            // SAFETY: file ptr/len come from a `&'static str` in
                            // the shared address space; bounded length (<256),
                            // read-only.
                            let bytes =
                                unsafe { core::slice::from_raw_parts(fptr as *const u8, flen) };
                            core::str::from_utf8(bytes).unwrap_or("?")
                        } else {
                            "?"
                        };
                        log::info!("[PANIC] core={pc} at {file}:{line}");
                    }
                }
                // Arm-after-step for Tier 1a too (the pacer governs Tier 0 AND
                // Tier 1a). A Tier-1a domain with adaptive_flags advances its
                // cadence here; byte-identical when adaptive_flags==0 (the
                // pacer returns the fixed domain tick).
                arm_next_deadline(domain_id, core_id);
            }
        }
        // ── Tier 3: Poll-mode (continuous stepping) ──
        // Continuous stepping through the shared scheduler body. The
        // pass runs every module in the domain once via
        // `step_domain_modules_poll`, which is identical to
        // `step_domain_modules` except it also reports whether any
        // module returned `StepOutcome::Burst` during the pass. When
        // no module bursted (and there's no other pending work) the
        // core WFEs.
        3 => {
            log::info!("[domain] {domain_id} core={core_id} tier=3 poll-mode");
            loop {
                multicore::park_if_requested(domain_id);
                // SAFETY: scheduler-thread per-domain access; bounded.
                let sched = unsafe { scheduler::sched_mut() };
                let (_result, any_burst) =
                    scheduler::step_domain_modules_poll(&mut sched.modules, domain_id);
                pump_cross_domain(domain_id);
                if core_id == 0 {
                    debug_drain_poll_core0();
                }

                // SAFETY: DOMAIN_METRICS[d] is exclusively touched by domain `d`'s
                // pump thread; bounded by MAX_DOMAINS.
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.poll_steps += 1;
                if !any_burst {
                    metrics.poll_idle += 1;
                    metrics.wfe_count += 1;
                    // SAFETY: WFE halts the core until an event; hint-only.
                    unsafe { core::arch::asm!("wfe") };
                }
                // Report every ~1M poll steps
                if metrics.poll_steps & 0xFFFFF == 0 && metrics.poll_steps > 0 {
                    let idle_pct = if metrics.poll_steps > 0 {
                        metrics.poll_idle * 100 / metrics.poll_steps
                    } else {
                        0
                    };
                    log::info!(
                        "[tier3] d={} polls={} idle={}% wfe={}",
                        domain_id,
                        metrics.poll_steps,
                        idle_pct,
                        metrics.wfe_count
                    );
                }
            }
        }
        // ── Tier 1b: Polled-timer ISR ──
        // Modules in this domain are *not* iterated via
        // `domain_step_all` — they were handed to the ISR-tier
        // dispatcher at graph setup. The pump just calls
        // `isr_tier::poll_tier1b` each loop iteration; that helper
        // fires `isr_tier1b_handler` when the configured period has
        // elapsed (bcm_isr_tier_poll software-polls the architected
        // counter on aarch64, since the cooperative scheduler shares
        // the core). Cross-domain pumps still run so a Tier 0
        // sibling can deliver work into the Tier 1b domain.
        2 => {
            log::info!(
                "[domain] {} core={} tier=1b period_us={}",
                domain_id,
                core_id,
                scheduler::domain_tick_us(domain_id)
            );
            loop {
                multicore::park_if_requested(domain_id);
                fluxor::kernel::exec::isr_tier::poll_tier1b();
                pump_cross_domain(domain_id);
                if core_id == 0 {
                    debug_drain_poll_core0();
                }
                // SAFETY: WFE halts the core until an event arrives;
                // the poll above is non-blocking, so spinning into WFE
                // is the correct idle posture.
                unsafe { core::arch::asm!("wfe") };
                // SAFETY: DOMAIN_METRICS[d] is exclusively touched by
                // domain `d`'s pump thread; bounded by MAX_DOMAINS.
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                // live-rebuild bridge (Tier 1b primary).
                poll_rebuild_bridge(domain_id);
                if metrics.tick_count.is_multiple_of(1_000_000) {
                    log::info!(
                        "[tier1b] d={} polls={} ticks={}",
                        domain_id,
                        metrics.tick_count,
                        fluxor::kernel::exec::isr_tier::tier1b_ticks(),
                    );
                }
            }
        }
        // ── Tier 2: IRQ-owned, dedicated core ──
        // Modules in this domain are NOT iterated cooperatively — each is
        // bound to a hardware IRQ at graph setup (`register_tier2_module` +
        // `hal::irq_bind` → `isr_tier2_trampoline`), and the GIC dispatches
        // straight into `module_isr_entry` from interrupt context. This core's
        // job is therefore to (a) stay parked in WFI so it is available to take
        // its owned IRQ with minimal latency, and (b) still service the
        // cooperative housekeeping that every domain core owes: cross-domain
        // SPSC pumping (so a sibling can hand work toward a Tier-2 module's
        // bridge), the live-rebuild bridge, and park-on-reconfigure. Without
        // this arm an `exec_mode == 4` domain fell through to the Tier-0
        // default and spun a cooperative pump that does no useful work for its
        // (skipped) ISR-tier modules.
        4 => {
            log::info!("[domain] {domain_id} core={core_id} tier=2 irq-owned");
            loop {
                // SAFETY: WFI halts the core until its owned IRQ (or any other
                // unmasked interrupt) fires; the trampoline runs in ISR context.
                unsafe { core::arch::asm!("wfi") };
                multicore::park_if_requested(domain_id);
                pump_cross_domain(domain_id);
                if core_id == 0 {
                    debug_drain_poll_core0();
                }
                // SAFETY: DOMAIN_METRICS[d] is exclusively touched by domain
                // `d`'s pump thread; bounded by MAX_DOMAINS.
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                // live-rebuild bridge (so a Tier-2 domain can be reconfigured).
                poll_rebuild_bridge(domain_id);
                if metrics.tick_count.is_multiple_of(1_000_000) {
                    log::info!(
                        "[tier2] d={domain_id} wakes={} irqs={}",
                        metrics.tick_count,
                        fluxor::kernel::exec::isr_tier::tier2_dispatch_count(),
                    );
                }
            }
        }
        // ── Tier 0: Cooperative (default, 1ms tick) ──
        _ => {
            loop {
                // SAFETY: WFI halts the core until next interrupt; hint-only.
                unsafe { core::arch::asm!("wfi") };
                multicore::park_if_requested(domain_id);
                let tick = CORE_TICKS[core_id].load(Ordering::Relaxed);
                // Tier-2 silicon-validation trigger: from core 0, periodically
                // send SGI 15 to core 1 (the Tier-2 dedicated core), which is
                // the hardware IRQ its Tier-2 module owns. Drives
                // `module_isr_entry` so the dispatch path is exercised on real
                // silicon. Build-flag only; never in production.
                #[cfg(feature = "test_tier2_sgi")]
                if core_id == 0 && tick.is_multiple_of(2000) {
                    // SAFETY: single MMIO write to the boot-mapped GIC distributor.
                    unsafe { gic::send_sgi(1, 15) };
                }
                domain_step_all(domain_id);
                pump_cross_domain(domain_id);
                // Poll the Tier 1b timer here too — on configurations
                // with no dedicated Tier 1b core, the cooperative pump
                // is the only path to fire the ISR handler.
                fluxor::kernel::exec::isr_tier::poll_tier1b();
                if core_id == 0 {
                    debug_drain_poll_core0();
                }
                // SAFETY: DOMAIN_METRICS[d] is exclusively touched by domain `d`'s
                // pump thread; bounded by MAX_DOMAINS.
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                scheduler::maybe_emit_alive(tick as u64, Some(domain_id));
                maybe_emit_soc_temp(core_id);
                // live-rebuild bridge (cooperative / Tier 0 primary).
                poll_rebuild_bridge(domain_id);
                // Arm-after-step: pick the next deadline from this pass and
                // write the per-core slot before looping back to WFI.
                // Byte-identical when adaptive_flags==0.
                arm_next_deadline(domain_id, core_id);
            }
        }
    }
}

/// Step every module in `domain_id` via the shared per-domain
/// scheduler path. Routes through `scheduler::step_domain_modules`
/// (same `step_one_module` body single-domain platforms use), so
/// every BCM-domain step honours period gating, upstream-ready
/// gating, `Done` finalisation, the fault state machine, and the
/// `Burst` loop identically to RP/Linux/WASM.
fn domain_step_all(domain_id: usize) {
    // SAFETY: per-domain pump runs on the domain's owning core.
    let sched = unsafe { scheduler::sched_mut() };
    // Multi-graph runtime: with more than one resident graph in this domain,
    // steps each owner independently, skips idle owners, and returns the
    // merged deadline. Byte-identical to `step_domain_modules` +
    // `pacer_next_deadline_us(domain)` with one resident graph. The deadline
    // is stashed for the arm-after-step write below.
    let (_result, deadline_us) =
        scheduler::step_resident_graphs_domain(&mut sched.modules, domain_id);
    if domain_id < multicore::MAX_DOMAINS {
        DOMAIN_RUNNER_DEADLINE_US[domain_id].store(deadline_us, Ordering::Relaxed);
    }
}

/// Move one slot per edge in each direction between local pipe channels
/// and their cross-domain SPSC ring. Called from `run_domain_loop` on
/// every tick; producer and consumer sides of each edge each fire on
/// the tick of their owning domain.
///
/// On the consumer side, the local pipe FIFO is peeked via `POLL_OUT`
/// before consuming from the SPSC ring — `channel_write` can return a
/// short write when the FIFO is near-full, and SPSC slots are consumed
/// in whole-message units, so pulling from the ring first and then
/// writing to a full FIFO would silently drop the tail.
///
/// `IOCTL_NOTIFY` sideband (seek requests and the like) is bridged via
/// `edge.pending_aux`: the consumer-side pump drains the consumer's
/// local input aux and stores it there; the producer-side pump drains
/// it and replays it onto the producer's local output aux.
/// Max frames a single `pump_cross_domain` pass moves per edge per direction.
/// Sized to a full SPSC ring so a producer can fill (or a consumer drain) the
/// whole ring in one pass instead of one frame per domain tick — the latter
/// throttled cross-domain TLS flights to 1 frame/tick and saturated the ring
/// under load.
const CROSS_PUMP_BURST: u32 = multicore::RING_SLOTS as u32;

// Diagnostic per-domain-pair cross-domain flow matrix (from*4+to). PROD counts
// frames the producer arm pushed into the SPSC ring; CONS counts frames the
// consumer arm delivered into the local consumer channel. A pair where
// PROD>0 but CONS≈0 localises where cross-core delivery stalls.
static XPUMP_PROD: [core::sync::atomic::AtomicU32; 16] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 16];
static XPUMP_CONS: [core::sync::atomic::AtomicU32; 16] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 16];

fn pump_cross_domain(domain_id: usize) {
    let n_cross = multicore::cross_edge_count();
    let mut ei = 0;
    while ei < n_cross {
        let Some(edge) = multicore::get_cross_edge(ei) else {
            ei += 1;
            continue;
        };
        let Some(ch) = multicore::get_cross_channel(edge.channel_idx as usize) else {
            ei += 1;
            continue;
        };

        // Producer side. Check remote SPSC space first — `channel_read`
        // commits the local mailbox frame, so consuming the producer's
        // frame before knowing the SPSC ring has room would be a real
        // drop. If the ring is full we leave the frame in the producer
        // mailbox; the producer module sees back-pressure on its output
        // and the pump retries next tick.
        if edge.from_domain == domain_id as u8 && edge.local_out_handle >= 0 {
            // Drain up to a full ring's worth of frames from the producer
            // mailbox into the SPSC ring this pass. The original one-frame-
            // per-pump shipped at most one frame per domain tick, so a TLS
            // flight (many records) crawled across the seam and the ring
            // saturated under load (observed: depth stuck at RING_SLOTS, the
            // consumer's curl timing out). Stop when the ring is full
            // (back-pressure) or the mailbox is drained.
            let mut moved = 0u32;
            while moved < CROSS_PUMP_BURST {
                if ch.is_full() {
                    multicore::CROSS_DOMAIN_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                let mut buf = [0u8; multicore::SLOT_DATA_SIZE];
                // SAFETY: `buf` is `SLOT_DATA_SIZE` bytes on the stack;
                // channel_read writes ≤ `buf.len()` bytes.
                let n = unsafe {
                    fluxor::kernel::ipc::channel::channel_read(
                        edge.local_out_handle,
                        buf.as_mut_ptr(),
                        buf.len(),
                    )
                };
                if n <= 0 {
                    break; // producer mailbox empty
                }
                // The ring had space when we checked, but a parallel
                // consumer-side close (or an oversized frame, which
                // `ch.send` rejects) can still cause a refusal. Bump the
                // cross-domain drop counter so operator-side telemetry sees it.
                if !ch.send(&buf[..n as usize]) {
                    multicore::CROSS_DOMAIN_DROPS.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                let mi = ((edge.from_domain as usize) * 4 + edge.to_domain as usize) & 15;
                XPUMP_PROD[mi].fetch_add(1, Ordering::Relaxed);
                moved += 1;
            }
            let aux = edge.pending_aux.swap(u32::MAX, Ordering::AcqRel);
            if aux != u32::MAX {
                let mut val = aux;
                let _ = fluxor::kernel::ipc::channel::channel_ioctl(
                    edge.local_out_handle,
                    fluxor::kernel::ipc::channel::IOCTL_NOTIFY,
                    &mut val as *mut u32 as *mut u8,
                );
            }
        }

        // Consumer side.
        if edge.to_domain == domain_id as u8 && edge.local_in_handle >= 0 {
            // Drain up to a full ring's worth of frames from the SPSC ring
            // into the local consumer channel this pass, re-checking POLL_OUT
            // each iteration (the FIFO can fill mid-drain). Matches the
            // multi-frame producer drain above so a burst clears in one pump.
            let mut moved = 0u32;
            while moved < CROSS_PUMP_BURST {
                // Atomic-or-nothing delivery. The local consumer channel is a
                // FIFO whose `channel_write` is partial-OK — writing a slot
                // that doesn't fully fit truncates it, losing the tail and
                // corrupting the consumer's framed byte stream (net_proto:
                // a dropped tail desyncs the [type][len][payload] framing, so
                // the consumer reads a bogus length and SPINS on phantom reads
                // — exactly the lane-core hang). So peek the next slot's length
                // and only consume+write it when the FIFO has room for ALL of
                // it; otherwise leave it queued and back-pressure.
                let Some(slot_len) = ch.try_peek_len() else {
                    break; // ring empty
                };
                if fluxor::kernel::ipc::channel::channel_writable_bytes(edge.local_in_handle) < slot_len
                {
                    multicore::CROSS_DOMAIN_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                let mut buf = [0u8; multicore::SLOT_DATA_SIZE];
                let Some(len) = ch.try_recv(&mut buf) else {
                    break; // ring drained between peek and recv
                };
                // SAFETY: `len == slot_len <= SLOT_DATA_SIZE = buf.len()`, and
                // the FIFO was just confirmed to have room for the whole slot,
                // so this write is complete (no truncation).
                unsafe {
                    fluxor::kernel::ipc::channel::channel_write(edge.local_in_handle, buf.as_ptr(), len);
                }
                let mi = ((edge.from_domain as usize) * 4 + edge.to_domain as usize) & 15;
                XPUMP_CONS[mi].fetch_add(1, Ordering::Relaxed);
                moved += 1;
            }
            let mut val: u32 = 0;
            let rc = fluxor::kernel::ipc::channel::channel_ioctl(
                edge.local_in_handle,
                fluxor::kernel::ipc::channel::IOCTL_POLL_NOTIFY,
                &mut val as *mut u32 as *mut u8,
            );
            if rc == fluxor::kernel::ipc::channel::CHAN_OK && val != u32::MAX {
                // `pending_aux` is single-slot — a fresh notification
                // overwrites any prior one that the producer pump
                // hadn't yet drained. The single-slot design is
                // intentionally coalescing (later writes win); the
                // overwrite counter below makes the rate of coalesced
                // events visible without changing the wire shape.
                let prev = edge.pending_aux.swap(val, Ordering::AcqRel);
                if prev != u32::MAX {
                    multicore::SIDEBAND_AUX_OVERWRITES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        ei += 1;
    }
}

// ============================================================================
// Secondary core entry points
// ============================================================================

/// Entry point for secondary cores after wake.
///
/// Waits for init_complete, sets up its own timer and GIC, then runs its
/// assigned domain loop. If no domain is assigned, parks in WFE.
fn secondary_core_main_1() -> ! {
    secondary_core_main(1)
}

fn secondary_core_main_2() -> ! {
    secondary_core_main(2)
}

fn secondary_core_main_3() -> ! {
    secondary_core_main(3)
}

fn secondary_core_main(domain_id: usize) -> ! {
    // Wait for init to complete on core 0
    while INIT_COMPLETE.load(Ordering::Acquire) == 0 {
        // SAFETY: WFE is a hint to wait until the next event.
        unsafe {
            core::arch::asm!("wfe");
        }
    }

    let core_id = current_core_id();
    uart_puts(b"[core");
    uart_put_u32(core_id as u32);
    uart_puts(b"] started, domain=");
    uart_put_u32(domain_id as u32);
    uart_puts(b"\r\n");
    log::info!("[core{core_id}] started, domain={domain_id}");

    // Set up GIC CPU interface + per-domain timer rate for this core. Tier 1a
    // may run faster than the global tick; a Tier-0 lane domain may run
    // slower. Storing the domain's tick into THIS core's deadline slot is
    // what makes the rate stick: the TIMER_PPI handler reloads from the
    // per-core slot, so the domain's rate survives the first IRQ rather than
    // being taken from a shared global.
    let domain_tick = scheduler::domain_tick_us(domain_id);
    let freq = timer::timer_freq();
    let ticks_for_domain = if freq > 0 {
        ((domain_tick as u64) * freq / 1_000_000) as u32
    } else {
        // freq read failed — fall back to ~1 ms at the assumed 62.5 MHz timer
        // (same constant the boot path uses for the freq==0 error case).
        62_500
    };
    let slot = (core_id as usize).min(NEXT_DEADLINE_TICKS.len() - 1);
    NEXT_DEADLINE_TICKS[slot].store(ticks_for_domain, Ordering::Relaxed);
    // SAFETY: secondary-core init runs once before the domain pump starts;
    // GIC + generic-timer registers are per-CPU.
    unsafe {
        gic_init_secondary();
        timer::timer_set(ticks_for_domain);
        // Enable IRQs (not needed for Tier 3 poll-mode, but harmless)
        core::arch::asm!("msr daifclr, #2");
    }

    // Check if this domain is active
    let ds = multicore::domain_state_ref(domain_id);
    if !ds.active || ds.module_count == 0 {
        uart_puts(b"[core");
        uart_put_u32(core_id as u32);
        uart_puts(b"] no work, parking\r\n");
        loop {
            // SAFETY: WFE halts the core until an event; idle path.
            unsafe {
                core::arch::asm!("wfe");
            }
        }
    }

    // Run the domain loop
    run_domain_loop(domain_id)
}

/// Wake all secondary cores that have domains assigned.
///
/// Called after module instantiation on core 0. Each secondary core
/// gets its own entry function that maps to its domain.
pub fn wake_secondary_cores() {
    let entries: [fn() -> !; 3] = [
        secondary_core_main_1,
        secondary_core_main_2,
        secondary_core_main_3,
    ];

    for core_id in 1u8..=3 {
        let domain_id = core_id as usize;
        let ds = multicore::domain_state_ref(domain_id);
        if ds.active && ds.module_count > 0 {
            uart_puts(b"[wake] core ");
            uart_put_u32(core_id as u32);
            uart_puts(b" for domain ");
            uart_put_u32(domain_id as u32);
            uart_puts(b"\r\n");

            let entry = entries[(core_id - 1) as usize];
            let ok = multicore::wake_core(core_id, entry);
            if !ok {
                uart_puts(b"[wake] FAILED core ");
                uart_put_u32(core_id as u32);
                uart_puts(b"\r\n");
            }
        }
    }
}

// ============================================================================
// BCM2712 HAL Ops
// ============================================================================

use fluxor::kernel::sys::hal::HalOps;

fn bcm_disable_interrupts() -> u32 {
    let daif: u32;
    // SAFETY: reads + writes the DAIF system register; preserves_flags +
    // nomem/nostack mean the asm has no side effects on memory.
    unsafe {
        core::arch::asm!(
            "mrs {0:x}, daif",
            "msr daifset, #2",
            out(reg) daif,
            options(nomem, nostack, preserves_flags),
        );
    }
    daif
}

fn bcm_restore_interrupts(saved: u32) {
    // SAFETY: writes DAIF (interrupt-mask system register); no memory effects.
    unsafe {
        core::arch::asm!(
            "msr daif, {0:x}",
            in(reg) saved,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// WFI wake-doorbell toggle. Default OFF: the wake path emits only `SEV`,
/// paired with the `tick_max_us` idle clamp. When ON, the wake
/// path also broadcasts a GIC SGI so a WFI-parked Tier-0/1a core wakes
/// immediately rather than waiting for the backstop — at the cost of an MMIO
/// write on the hot `event_signal` / cross-domain SPSC-push paths. Enable it
/// only where the clamp's first-request-after-idle latency is measured to be
/// insufficient.
static WAKE_DOORBELL: AtomicBool = AtomicBool::new(false);

/// Enable/disable the SGI wake doorbell at runtime (default off).
pub fn set_wake_doorbell(on: bool) {
    WAKE_DOORBELL.store(on, Ordering::Relaxed);
}

/// Enable/disable the absolute (`cntp_cval`) timer re-arm at runtime
/// (default off — the relative `cntp_tval` path is the default). See
/// `exception::ABSOLUTE_REARM`.
pub fn set_absolute_rearm(on: bool) {
    exception::ABSOLUTE_REARM.store(on, Ordering::Relaxed);
}

/// Broadcast the wake doorbell SGI to all cores, IFF the doorbell is
/// enabled. Called alongside `SEV` on every wake path so a WFI-parked core
/// (which `SEV` cannot break) also wakes. No-op (one relaxed load) when off.
#[inline(always)]
pub fn wake_doorbell() {
    if WAKE_DOORBELL.load(Ordering::Relaxed) {
        #[cfg(target_arch = "aarch64")]
        // SAFETY: single MMIO write to the boot-mapped GIC distributor.
        unsafe {
            gic::send_sgi_all(gic::WAKE_SGI);
        }
    }
}

fn bcm_wake_scheduler() {
    // SAFETY: SEV broadcasts an event to wake WFE-parked cores; hint-only.
    unsafe { core::arch::asm!("sev") };
    // SEV does NOT break WFI (Tier 0/1a idle posture). When the doorbell
    // is enabled, also send an SGI so a WFI-parked core wakes immediately.
    wake_doorbell();
}

/// Portable `sleep_until`. The per-core periodic timer (the idle backstop,
/// ≤ `tick_max_us`) is already armed, and any bound IRQ — plus the wake
/// doorbell SGI — breaks WFI. So a single WFI blocks until the next
/// wake without programming a separate one-shot (which would race the
/// IRQ-handler's per-core deadline reload). Returns UNKNOWN: WFI cannot
/// report its wake source, so the caller must re-check its work/deadline
/// state.
fn bcm_sleep_until(_deadline_us: u64) -> u32 {
    // SAFETY: WFI is a hint that parks the core until an unmasked IRQ.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("wfi")
    };
    fluxor::kernel::sys::hal::WOKEN_UNKNOWN
}

/// Monotonic milliseconds since boot. Reads the ARM generic timer
/// (`CNTPCT_EL0`) and scales by `cntfrq_el0 / 1000`. Backs
/// `dev_millis` / `syscall_millis` for module-side timing such as
/// NVMe arena probe perf measurement and TCP RTT estimation.
fn bcm_now_millis() -> u64 {
    let counter = bcm_read_cntpct();
    let freq = bcm_counter_freq();
    if freq == 0 {
        return 0;
    }
    counter.wrapping_mul(1000) / freq
}

/// Monotonic microseconds since boot. Same source as
/// `bcm_now_millis`, scaled to µs for sub-millisecond profiling.
fn bcm_now_micros() -> u64 {
    let counter = bcm_read_cntpct();
    let freq = bcm_counter_freq();
    if freq == 0 {
        return 0;
    }
    counter.wrapping_mul(1_000_000) / freq
}
fn bcm_tick_count() -> u32 {
    // Back the HAL `tick_count` with wall-clock milliseconds
    // (CNTPCT-derived) instead of `DBG_TICK`. The
    // identity "1 tick == 1 ms" holds only at the fixed 1 ms default; under
    // mechanism (b) the period varies and under mechanism (a)/idle `DBG_TICK`
    // stops advancing, so a `DBG_TICK`-backed `tick_count` returns wrong
    // "ms since boot" under adaptive tick. `bcm_now_millis()` is correct under
    // any pacing — matching rp's `Instant`-based `rp_tick_count` (rp.rs:449).
    // The internal logical tick counter (`scheduler::tick_count()` → DBG_TICK)
    // is unchanged; only this outward HAL op is decoupled.
    bcm_now_millis() as u32
}

// ============================================================================
// BCM2712 SoC thermal sensor (AVS monitor) — read-only
// ============================================================================
//
// The bcm2712 exposes its on-die temperature via the AVS monitor (device-tree
// compatible "brcm,bcm2711-thermal") at SoC peripheral 0x7d542000, which the SoC
// `ranges` map to CPU physical 0x10_7d542000 — inside the aperture boot_mmu
// already maps (table[64]/[65]). The status word at +0x200 is valid only when
// bits 16 and 10 are set; the low 10 bits are the raw code. Per the stock
// device-tree `coefficients = <-550, 450000>`:  T(milli°C) = 450000 − 550·raw.
// Verified on silicon (raw=714 → 57.3 °C, matching the Linux thermal zone).

#[cfg(feature = "board-pi5")]
const AVS_TEMP_STATUS: usize = 0x10_7d54_2200;
#[cfg(feature = "board-pi5")]
const AVS_TEMP_VALID: u32 = (1 << 16) | (1 << 10);

/// SoC die temperature in milli-Celsius, or `None` if the sensor reading is not
/// yet valid. Board-pi5 only (no AVS monitor on the QEMU virt model).
#[cfg(feature = "board-pi5")]
pub fn soc_temp_mc() -> Option<i32> {
    // SAFETY: AVS_TEMP_STATUS is a fixed, side-effect-free MMIO status register
    // in the SoC peripheral aperture mapped by boot_mmu.
    let v = unsafe { core::ptr::read_volatile(AVS_TEMP_STATUS as *const u32) };
    if v & AVS_TEMP_VALID != AVS_TEMP_VALID {
        return None;
    }
    let raw = (v & 0x3ff) as i32;
    Some(450_000 - 550 * raw)
}

#[cfg(not(feature = "board-pi5"))]
pub fn soc_temp_mc() -> Option<i32> {
    None
}

/// Emit the SoC die temperature to the log/telemetry stream on a ~5 s
/// wall-clock cadence (core 0 only). This is the direct signal that the active
/// cooler is working — the DUT should cool under a sustained load instead of
/// throttling — and it is what the thermal floor-decay measurement consumes.
fn maybe_emit_soc_temp(core_id: usize) {
    if core_id != 0 {
        return;
    }
    const TEMP_INTERVAL_MS: u64 = 5_000;
    static LAST_TEMP_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static LAST_CT0: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let now = bcm_now_millis();
    let last = LAST_TEMP_MS.load(Ordering::Relaxed);
    if now.wrapping_sub(last) < TEMP_INTERVAL_MS {
        return;
    }
    LAST_TEMP_MS.store(now, Ordering::Relaxed);
    let ct0 = exception::CORE_TICKS[0].load(Ordering::Relaxed);
    // irq_hz = the actual timer-IRQ (wakeup) RATE over the last interval.
    // With mechanism (a) on an idle domain this falls far below
    // the nominal `1e6/tick_us`. This is the SAMPLING-ROBUST idle signal: unlike
    // the instantaneous dl0_us below, it averages over the whole interval, so it
    // isn't skewed by the fact that the emit pass itself is busy.
    let dt_ms = now.wrapping_sub(last).max(1);
    let last_ct0 = LAST_CT0.swap(ct0, Ordering::Relaxed);
    let irq_hz = (ct0.wrapping_sub(last_ct0) as u64 * 1000 / dt_ms) as u32;
    // dl0_us = core 0's deadline at THIS (busy) emit instant; dl0_max_us = the
    // most-relaxed deadline reached since the last emit (sampling-robust — proves
    // (a)/(b) actually relaxed even though the emit pass reads busy). Reset the
    // interval-max after reading it.
    let freq = timer::timer_freq();
    let to_us = |ticks: u64| -> u32 {
        if freq > 0 {
            (ticks * 1_000_000 / freq) as u32
        } else {
            0
        }
    };
    let dl0_us = to_us(exception::NEXT_DEADLINE_TICKS[0].load(Ordering::Relaxed) as u64);
    let dl0_max_us = DL0_MAX_US.swap(0, Ordering::Relaxed);
    // worst_us = the pacer floor's input (decaying peak-hold step time); ovr =
    // per-domain budget overruns. Together they show whether the domain stays
    // inside budget and whether the floor rises on load and decays on cool-down.
    let worst_us = scheduler::domain_worst_step_us(0);
    let ovr = scheduler::domain_budget_overruns(0);
    // Surface the Tier-2 IRQ-dispatch count on the reliable core-0 cadence so a
    // dedicated-core Tier-2 module's `module_isr_entry` firing is observable
    // over UDP (its own loop logs only every 1M wakes).
    let t2disp = fluxor::kernel::exec::isr_tier::tier2_dispatch_count();
    if let Some(mc) = soc_temp_mc() {
        log::info!(
            "[therm] soc_temp_mC={mc} t_ms={now} ct0={ct0} irq_hz={irq_hz} dl0_us={dl0_us} dl0_max_us={dl0_max_us} worst_us={worst_us} ovr={ovr} t2disp={t2disp}"
        );
    } else {
        log::info!(
            "[therm] soc_temp_mC=na t_ms={now} ct0={ct0} irq_hz={irq_hz} dl0_us={dl0_us} dl0_max_us={dl0_max_us} worst_us={worst_us} ovr={ovr} t2disp={t2disp}"
        );
    }
    // Re-emit the fan PWM register readback on the same cadence. The one-shot
    // boot report is pre-DHCP and never reaches the UDP stream; this recurring
    // copy does, so the rig can confirm the channel stays programmed (DUTY,
    // enable bit) for the whole run.
    rp1::fan_report();
}

/// Wall-clock gate for the `[xdom]` cross-domain freeze/telemetry dump. Gated on
/// a fixed ~0.5 s wall-clock cadence so the telemetry rate is decoupled from
/// domain 0's `tick_count` — which, once domain 0 paces variably (adaptive
/// idle), advances slowly and would otherwise stall the sibling-lane liveness
/// windows. Core 0 / the domain-0 pump is the sole caller.
fn xdom_due() -> bool {
    const XDOM_INTERVAL_MS: u64 = 500;
    static LAST_XDOM_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let now = bcm_now_millis();
    if now.wrapping_sub(LAST_XDOM_MS.load(Ordering::Relaxed)) < XDOM_INTERVAL_MS {
        return false;
    }
    LAST_XDOM_MS.store(now, Ordering::Relaxed);
    true
}

fn bcm_flash_base() -> usize {
    0
}
fn bcm_flash_end() -> usize {
    0
}
fn bcm_apply_code_bit(addr: usize) -> usize {
    addr
}
// BCM address-validation hooks. aarch64 instructions are 4-byte
// aligned and module headers / code bases are also 4-byte aligned on
// bare-metal, so requiring `addr & 0x3 == 0` catches ABI corruption
// and the "manifest claims an offset that lands mid-instruction"
// failure mode before the kernel calls into a bad fn pointer.
fn bcm_validate_fn_addr(addr: usize) -> bool {
    addr != 0 && (addr & 0x3) == 0
}
fn bcm_validate_module_base(addr: usize) -> bool {
    addr != 0 && (addr & 0x3) == 0
}
fn bcm_validate_fn_in_code(addr: usize, code_base: usize, code_size: u32) -> bool {
    // Belt-and-braces check against `[code_base, code_base + code_size)`.
    // `get_export_addr` already rejects manifests claiming offsets past
    // `code_size`, but the platform-side check runs uniformly and
    // mirrors `linux_validate_fn_in_code`.
    if code_base == 0 || code_size == 0 {
        return false;
    }
    let end = code_base.saturating_add(code_size as usize);
    addr >= code_base && addr < end
}
fn bcm_verify_integrity(computed: &[u8], expected: &[u8]) -> bool {
    computed.len() == expected.len() && computed == expected
}

/// OTA staging cache maintenance. EL1 DRAM is mapped RWX by the boot
/// page tables, so no permission flip is needed; what IS needed before
/// executing freshly written module code is coherency between the data
/// cache the writes landed in and the instruction stream: clean D-cache
/// to PoU + invalidate I-cache over the region, then DSB/ISB
/// (ARM DDI 0487, self-modifying-code sequence).
fn bcm_ota_stage_protect(base: *mut u8, len: usize, executable: bool) -> bool {
    if !executable {
        // Region is plain RW DRAM; nothing to undo.
        return true;
    }
    const LINE: usize = 64;
    let start = (base as usize) & !(LINE - 1);
    let end = (base as usize).saturating_add(len);
    let mut p = start;
    while p < end {
        // SAFETY: dc/ic by VA over a valid mapped DRAM region; cache
        // maintenance has no memory effects beyond coherency.
        unsafe {
            core::arch::asm!("dc cvau, {a}", a = in(reg) p);
        }
        p += LINE;
    }
    // SAFETY: barriers + broadcast I-cache invalidate, per the
    // architectural code-modification sequence.
    unsafe {
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb");
    }
    true
}

fn bcm_pic_barrier() {
    // SAFETY: DSB SY + ISB are architectural barriers — no memory effects.
    unsafe { core::arch::asm!("dsb sy", "isb") };
}

// Step guard: software elapsed-time check
static mut BCM_ARM_TIME: u64 = 0;
static mut BCM_DEADLINE_TICKS: u64 = 0;

/// Read the timer counter (physical on Pi 5, virtual on QEMU for KVM compat).
fn bcm_read_cntpct() -> u64 {
    let val: u64;
    // SAFETY: reads CNTPCT_EL0 — generic timer counter, side-effect-free.
    #[cfg(feature = "board-pi5")]
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) val)
    };
    // SAFETY: reads CNTVCT_EL0 — virtual counter under KVM/QEMU.
    #[cfg(not(feature = "board-pi5"))]
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) val)
    };
    val
}

fn bcm_counter_freq() -> u64 {
    let freq: u64;
    // SAFETY: reads CNTFRQ_EL0 — read-only frequency register.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    freq
}

fn bcm_step_guard_init() {}

fn bcm_step_guard_arm(deadline_us: u32) {
    use fluxor::kernel::exec::step_guard;
    step_guard::clear_timed_out();
    step_guard::set_armed(true);
    let freq = bcm_counter_freq();
    let ticks = (deadline_us as u64 * freq) / 1_000_000;
    // SAFETY: per-core step-guard state; written by the same core that
    // armed it. Read back in `bcm_step_guard_post_check` on the same core.
    unsafe {
        BCM_ARM_TIME = bcm_read_cntpct();
        BCM_DEADLINE_TICKS = ticks;
    }
}

fn bcm_step_guard_disarm() {
    fluxor::kernel::exec::step_guard::set_armed(false);
}

fn bcm_step_guard_post_check() {
    use fluxor::kernel::exec::step_guard;
    if !step_guard::is_armed() {
        return;
    }
    let now = bcm_read_cntpct();
    // SAFETY: per-core step-guard read paired with the arming write above.
    let elapsed = now.wrapping_sub(unsafe { BCM_ARM_TIME });
    // SAFETY: as above.
    if elapsed >= unsafe { BCM_DEADLINE_TICKS } {
        step_guard::set_timed_out();
    }
    step_guard::set_armed(false);
}

fn bcm_read_cycle_count() -> u32 {
    bcm_read_cntpct() as u32
}

fn bcm_isr_tier_init() {}

// ISR tier 1b: software poll on aarch64
static mut BCM_ISR_LAST_TICK: u64 = 0;
static mut BCM_ISR_PERIOD_TICKS: u64 = 0;

fn bcm_isr_tier_start(period_us: u32) {
    use fluxor::kernel::exec::isr_tier;
    isr_tier::set_tier1b_period_us(period_us);
    let freq = bcm_counter_freq();
    // SAFETY: ISR-tier statics are set during init before any tier-1b
    // module runs; sole writer on the scheduler thread.
    unsafe {
        BCM_ISR_PERIOD_TICKS = (period_us as u64 * freq) / 1_000_000;
        BCM_ISR_LAST_TICK = bcm_read_cntpct();
    }
    isr_tier::TIER1B_ACTIVE.store(true, core::sync::atomic::Ordering::Release);
}

fn bcm_isr_tier_stop() {
    fluxor::kernel::exec::isr_tier::TIER1B_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
}

fn bcm_isr_tier_poll() {
    use fluxor::kernel::exec::isr_tier;
    if !isr_tier::TIER1B_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    let now = bcm_read_cntpct();
    // SAFETY: ISR poll runs on the scheduler thread; sole reader.
    let elapsed = now.wrapping_sub(unsafe { BCM_ISR_LAST_TICK });
    // SAFETY: as above.
    let period = unsafe { BCM_ISR_PERIOD_TICKS };
    if period > 0 && elapsed >= period {
        // SAFETY: sole writer for the ISR poll counter.
        unsafe {
            BCM_ISR_LAST_TICK = now;
            isr_tier::isr_tier1b_handler();
        }
    }
}

fn bcm_init_providers() {
    // BCM2712 system extension for MMIO and NIC opcodes
    fluxor::kernel::module::syscalls::register_system_extension(bcm_system_extension_dispatch);
    // Metal fmod-graph `workload` (0x1A) backend: stages a workload as an
    // owned module subgraph via `apply_add`/owner/lease. Gated exactly like
    // the Linux install — `requires_contract = "workload"` + `platform_raw` in
    // the caller's manifest. The core logic is kernel-generic
    // (`kernel::workload::workload_graph`); this is the metal registration
    // that installs it.
    use fluxor::kernel::module::provider;
    use fluxor::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::WORKLOAD, bcm_workload_dispatch);
    // The versioned watchable key store: `storage.object` (0x14) +
    // `storage.namespace` (0x13) over a fixed-capacity RAM store. A
    // store-backed graph reaches its state through these two contracts, and a
    // provider that is absent answers ENOSYS: the graph runs and produces
    // nothing, which is the failure that looks like no failure.
    // SAFETY: single-threaded boot, before any provider dispatch.
    unsafe { fluxor::platform::store::init() };
}

/// Metal `workload` (0x1A) provider dispatch — the thin bcm registration hook.
/// Delegates to the kernel-generic backend
/// (`kernel::workload::workload_graph`), which runs on the primary domain /
/// core 0 (the system graph's domain) so the runtime `apply_add`/`free_owner`
/// it drives honor the primary-only quiesce invariant.
///
/// # Safety
/// Scheduler-thread dispatch only; see `workload_graph::workload_dispatch`.
unsafe fn bcm_workload_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    fluxor::kernel::workload::workload_graph::workload_dispatch(handle, opcode, arg, arg_len)
}

/// Platform-specific per-module cleanup for BCM2712.
///
/// **Intentional no-op.** BCM platform resources (NIC rings, PCIe
/// BARs, DMA arena allocations, MSI vectors) do **not** record their
/// owning module index — the `nic_ring`, `pcie`, and
/// `cross_domain_*` tables allocate by sequence, not by owner. A
/// single faulted module cannot release just its slice of these
/// resources because the kernel doesn't know which slice is its.
/// BCM-side resource reclaim relies on the kernel-wide reset that
/// `prepare_graph` performs on every reconfigure
/// (`channel::reset_all` + `provider::reset_handle_tracking` +
/// `buffer_pool::reset_all`). A meaningful per-module release would
/// require adding `owner_module: u8` to each of those tables; until
/// then the empty body is deliberate, not a TODO.
fn bcm_release_module_handles(_module_idx: u8) {
    // See docstring above — intentional no-op pending per-resource
    // ownership tracking in nic_ring / pcie / dma arenas.
}
fn bcm_boot_scan() {}
fn bcm_merge_runtime_overrides(_module_id: u16, _buf: *mut u8, len: usize, _max: usize) -> usize {
    len
}

unsafe fn bcm_system_extension_dispatch(
    _handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    use fluxor::abi::contracts::storage::paged_arena;
    use fluxor::abi::contracts::hal::pcie_device;
    use fluxor::abi::platform::bcm2712::{mmio_dma, msi, nic_ring, pcie_config};
    match opcode {
        mmio_dma::MMIO_READ32 => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let val = core::ptr::read_volatile(addr as *const u32);
            let vb = val.to_le_bytes();
            *arg.add(8) = vb[0];
            *arg.add(9) = vb[1];
            *arg.add(10) = vb[2];
            *arg.add(11) = vb[3];
            0
        }
        mmio_dma::MMIO_WRITE32 => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let val = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            core::ptr::write_volatile(addr as *mut u32, val);
            0
        }
        mmio_dma::CACHE_FLUSH_RANGE => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            // Clean + invalidate data cache by VA range
            let mut ptr = (addr as usize) & !63;
            let end = ((addr as usize) + size as usize + 63) & !63;
            while ptr < end {
                core::arch::asm!("dc civac, {}", in(reg) ptr, options(nostack));
                ptr += 64;
            }
            core::arch::asm!("dsb sy");
            0
        }
        mmio_dma::DMA_ALLOC_CONTIG => {
            if arg.is_null() || arg_len < 16 {
                return -22;
            }
            let size = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let align = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            // Use the PCIe1-reachable arena at AXI 0x1_0000_0000 so
            // device DMA routed through the PCIe1 inbound window lands
            // in real DRAM. See `bcm2712_nic_ring::pcie1_dma_alloc_contig`.
            let phys =
                fluxor::platform::nic_ring::pcie1_dma_alloc_contig(size as usize, align as usize);
            if phys == 0 {
                return -38;
            }
            let pb = (phys as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(pb.as_ptr(), arg.add(8), 8);
            0
        }
        mmio_dma::DMA_ALLOC_STREAMING => {
            if arg.is_null() || arg_len < 16 {
                return -22;
            }
            let size = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let align = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            // Streaming arena stays WB-cacheable. Callers must pair writes
            // with DMA_FLUSH before device-reads and DMA_INVALIDATE before
            // CPU-reads of device-written regions.
            let phys =
                fluxor::platform::nic_ring::pcie1_dma_alloc_streaming(size as usize, align as usize);
            if phys == 0 {
                return -38;
            }
            let pb = (phys as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(pb.as_ptr(), arg.add(8), 8);
            0
        }
        mmio_dma::DMA_FLUSH => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            // Clean (but do not invalidate) by VA range. Caller has just
            // written to a streaming DMA buffer and is about to hand it
            // to the device. `dc cvac` pushes dirty lines to PoC so the
            // device reads the up-to-date data; CPU's copy stays valid.
            let mut ptr = (addr as usize) & !63;
            let end = ((addr as usize) + size as usize + 63) & !63;
            while ptr < end {
                core::arch::asm!("dc cvac, {}", in(reg) ptr, options(nostack));
                ptr += 64;
            }
            core::arch::asm!("dsb sy");
            0
        }
        mmio_dma::DMA_INVALIDATE => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            // Invalidate by VA range. Device has just DMA'd into the
            // region; drop any speculatively-loaded stale CPU lines so
            // the next CPU load returns DMA data. `dc ivac` is the
            // inverse of cvac — it discards without writeback. Use
            // `dc civac` semantics if the caller can't guarantee the
            // buffer was clean (we pick invalidate-only deliberately:
            // streaming DMA buffers are either wholly CPU-owned or
            // wholly device-owned at handoff).
            let mut ptr = (addr as usize) & !63;
            let end = ((addr as usize) + size as usize + 63) & !63;
            while ptr < end {
                core::arch::asm!("dc ivac, {}", in(reg) ptr, options(nostack));
                ptr += 64;
            }
            core::arch::asm!("dsb sy");
            0
        }
        nic_ring::NIC_BAR_MAP => fluxor::platform::pcie::syscall_bar_map(arg, arg_len),
        nic_ring::NIC_BAR_UNMAP => fluxor::platform::pcie::syscall_bar_unmap(arg, arg_len),
        nic_ring::NIC_RING_CREATE => fluxor::platform::nic_ring::syscall_ring_create(arg, arg_len),
        nic_ring::NIC_RING_DESTROY => fluxor::platform::nic_ring::syscall_ring_destroy(arg, arg_len),
        nic_ring::NIC_RING_INFO => {
            fluxor::platform::nic_ring::syscall_ring_info(_handle, arg, arg_len)
        }
        pcie_config::PCIE_RESCAN => {
            let _ = arg;
            let _ = arg_len;
            fluxor::platform::pcie::enumerate() as i32
        }
        pcie_config::PCIE_CFG_READ32 => fluxor::platform::pcie::syscall_cfg_read32(arg, arg_len),
        pcie_config::PCIE_CFG_WRITE32 => fluxor::platform::pcie::syscall_cfg_write32(arg, arg_len),
        msi::PCIE1_MSI_INIT => {
            // arg = [spi_irq: u32 LE]
            if arg.is_null() || arg_len < 4 {
                return -22;
            }
            let spi_irq = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            if !fluxor::platform::pcie::pcie1_msi_init() {
                return fluxor::kernel::sys::errno::ENODEV;
            }
            register_pcie1_msi_spi(spi_irq)
        }
        msi::PCIE1_MSI_ALLOC_VECTOR => {
            if arg.is_null() || arg_len < 20 {
                return -22;
            }
            let event_handle = i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            match fluxor::platform::pcie::pcie1_msi_alloc_vector(event_handle) {
                None => -12, // ENOMEM
                Some((vec, addr, data)) => {
                    *arg.add(4) = vec;
                    *arg.add(5) = 0;
                    *arg.add(6) = 0;
                    *arg.add(7) = 0;
                    let ab = addr.to_le_bytes();
                    for (i, byte) in ab.iter().enumerate() {
                        *arg.add(8 + i) = *byte;
                    }
                    let db = data.to_le_bytes();
                    for (i, byte) in db.iter().enumerate() {
                        *arg.add(16 + i) = *byte;
                    }
                    0
                }
            }
        }
        // ── PCIE_DEVICE contract ──────────────────────────────────
        pcie_device::BIND => {
            if arg.is_null() || arg_len == 0 {
                return -22;
            }
            let sel = core::slice::from_raw_parts(arg, arg_len);
            fluxor::platform::pcie::bind_selector(sel)
        }
        pcie_device::CLOSE => fluxor::platform::pcie::syscall_device_close(_handle),
        pcie_device::CFG_READ32 => {
            fluxor::platform::pcie::syscall_device_cfg_read32(_handle, arg, arg_len)
        }
        pcie_device::CFG_WRITE32 => {
            fluxor::platform::pcie::syscall_device_cfg_write32(_handle, arg, arg_len)
        }
        pcie_device::BAR_MAP => fluxor::platform::pcie::syscall_device_bar_map(_handle, arg, arg_len),
        pcie_device::MSI_ALLOC => {
            if arg.is_null() || arg_len < 20 || _handle < 0 {
                return -22;
            }
            // The bound handle tells us which root complex's MSI mux
            // to use. Only PCIe1 is wired today.
            match fluxor::platform::pcie::bound_device_root(_handle) {
                None => fluxor::kernel::sys::errno::EINVAL,
                Some(root) => {
                    use fluxor::platform::pcie_aliases::PcieRoot;
                    match root {
                        PcieRoot::Pcie1 => {
                            if !fluxor::platform::pcie::pcie1_msi_init() {
                                return fluxor::kernel::sys::errno::ENODEV;
                            }
                            if !PCIE1_MSI_SPI_REGISTERED {
                                let _ = register_pcie1_msi_spi(
                                    fluxor::platform::pcie::BCM2712_PCIE1_MSI_SPI_IRQ,
                                );
                                PCIE1_MSI_SPI_REGISTERED = true;
                            }
                            let event_handle =
                                i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
                            match fluxor::platform::pcie::pcie1_msi_alloc_vector(event_handle) {
                                None => fluxor::kernel::sys::errno::ENOMEM,
                                Some((vec, addr, data)) => {
                                    *arg.add(4) = vec;
                                    *arg.add(5) = 0;
                                    *arg.add(6) = 0;
                                    *arg.add(7) = 0;
                                    let ab = addr.to_le_bytes();
                                    for (i, byte) in ab.iter().enumerate() {
                                        *arg.add(8 + i) = *byte;
                                    }
                                    let db = data.to_le_bytes();
                                    for (i, byte) in db.iter().enumerate() {
                                        *arg.add(16 + i) = *byte;
                                    }
                                    0
                                }
                            }
                        }
                        PcieRoot::Pcie2 => fluxor::kernel::sys::errno::ENOSYS,
                    }
                }
            }
        }
        pcie_device::INFO => fluxor::platform::pcie::syscall_device_info(_handle, arg, arg_len),
        paged_arena::ARENA_REGISTER => {
            if arg.is_null() || arg_len < 10 {
                return -22;
            }
            let vpages = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let rmax = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let bt = match *arg.add(8) {
                0 => fluxor::kernel::backing_store::BackingType::None,
                1 => fluxor::kernel::backing_store::BackingType::RamDisk,
                2 => fluxor::kernel::backing_store::BackingType::External,
                _ => return -22,
            };
            let wb = match *arg.add(9) {
                0 => fluxor::kernel::backing_store::WritebackPolicy::Deferred,
                1 => fluxor::kernel::backing_store::WritebackPolicy::WriteThrough,
                _ => return -22,
            };
            let idx = fluxor::kernel::exec::scheduler::current_module_index() as u8;
            fluxor::kernel::backing_store::backing_register(idx, vpages, rmax, bt, wb)
        }
        paged_arena::ARENA_READ => {
            if arg.is_null() || arg_len < 14 {
                return -22;
            }
            let arena_id = *arg as usize;
            let vpage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let buf = u64::from_le_bytes([
                *arg.add(6),
                *arg.add(7),
                *arg.add(8),
                *arg.add(9),
                *arg.add(10),
                *arg.add(11),
                *arg.add(12),
                *arg.add(13),
            ]) as *mut u8;
            fluxor::kernel::backing_store::backing_read(arena_id, vpage, buf)
        }
        paged_arena::ARENA_WRITE => {
            if arg.is_null() || arg_len < 14 {
                return -22;
            }
            let arena_id = *arg as usize;
            let vpage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let buf = u64::from_le_bytes([
                *arg.add(6),
                *arg.add(7),
                *arg.add(8),
                *arg.add(9),
                *arg.add(10),
                *arg.add(11),
                *arg.add(12),
                *arg.add(13),
            ]) as *const u8;
            fluxor::kernel::backing_store::backing_write(arena_id, vpage, buf)
        }
        paged_arena::ARENA_FLUSH => {
            if arg.is_null() || arg_len < 1 {
                return -22;
            }
            let arena_id = *arg as usize;
            fluxor::kernel::backing_store::backing_flush(arena_id)
        }
        paged_arena::ARENA_BULK => {
            if arg.is_null() || arg_len < 18 {
                return -22;
            }
            let arena_id = *arg as usize;
            let op = *arg.add(1);
            let vpage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let count = u32::from_le_bytes([*arg.add(6), *arg.add(7), *arg.add(8), *arg.add(9)]);
            let buf_u64 = u64::from_le_bytes([
                *arg.add(10),
                *arg.add(11),
                *arg.add(12),
                *arg.add(13),
                *arg.add(14),
                *arg.add(15),
                *arg.add(16),
                *arg.add(17),
            ]);
            match op {
                paged_arena::ARENA_BULK_OP_WRITE => {
                    fluxor::kernel::backing_store::backing_write_pages(
                        arena_id,
                        vpage,
                        count,
                        buf_u64 as *const u8,
                    )
                }
                paged_arena::ARENA_BULK_OP_READ => {
                    fluxor::kernel::backing_store::backing_read_pages(
                        arena_id,
                        vpage,
                        count,
                        buf_u64 as *mut u8,
                    )
                }
                _ => -22,
            }
        }
        _ => -38, // E_NOSYS
    }
}

/// Protection impls (HalOps seam). On BCM2712 module protection is the EL0
/// MMU; the portable MPU facade is a no-op here but is kept in the enable
/// path for exact parity with the pre-seam behavior.
fn bcm_protection_set_enabled(enabled: bool) {
    mpu::set_enabled(enabled);
    mmu::set_enabled(enabled);
}
fn bcm_protection_register_module(
    module_idx: usize,
    code_base: usize,
    code_size: usize,
    state_ptr: *mut u8,
    state_size: usize,
    heap_ptr: *mut u8,
    heap_size: usize,
) {
    mmu::register_module(
        module_idx,
        code_base as u64,
        code_size as u64,
        state_ptr,
        state_size,
        heap_ptr,
        heap_size,
    );
}
/// Channel-region registration with the EL0 page-rounding + fail-closed
/// interleave policy: an isolated module's channel span is mapped EL0-RW as
/// one page-rounded range; if a PEER producer's buffer falls inside that span
/// (possible for a multi-output module whose buffers bracket a peer's),
/// mapping it would grant writable access to the peer's buffer — refuse to
/// register instead (the isolated module's own channel I/O then faults per
/// policy, but no peer buffer is ever exposed).
fn bcm_protection_set_channel_region(i: usize, base: usize, size: usize) {
    mpu::set_channel_region(i, base as u32, size as u32);
    const PAGE: usize = 4096;
    if fluxor::kernel::exec::scheduler::module_is_isolated(i) {
        let pbase = base & !(PAGE - 1);
        let pend = (base + size + PAGE - 1) & !(PAGE - 1);
        if fluxor::kernel::ipc::buffer_pool::any_foreign_buffer_in_range(
            i as u8,
            pbase,
            pend - pbase,
        ) {
            log::error!(
                "[el0] module {i}: channel span 0x{pbase:x}+{} overlaps a peer buffer —                  REFUSING to map channel region (fail closed).",
                pend - pbase,
            );
        } else {
            mmu::set_channel_region(i, pbase as u64, (pend - pbase) as u64);
        }
    } else {
        mmu::set_channel_region(i, base as u64, size as u64);
    }
}
fn bcm_protection_map_page(module_idx: usize, vaddr: usize, phys: usize, writable: bool) {
    mmu::map_4k_page(module_idx, vaddr as u64, phys as u64, writable);
}
fn bcm_protection_unmap_page(module_idx: usize, vaddr: usize) {
    mmu::unmap_4k_page(module_idx, vaddr as u64);
}

/// Park online secondaries for a structural mutation (HalOps seam): no-op
/// before SMP is online; otherwise request + wait for every active peer.
fn bcm_smp_quiesce_peers() -> bool {
    if multicore::smp_online() {
        let expected = multicore::non_primary_active_count();
        multicore::request_quiesce();
        multicore::wait_parked(expected);
        return true;
    }
    false
}

// ── VideoCore property mailbox: the TRANSPORT half ──────────────────────
//
// The MESSAGE half — which tag, how the value region is sized, which
// response codes mean the firmware actually answered — is
// `src/kernel/sys/vc_mailbox.rs`, pure data, host-tested. What lives here
// is only what genuinely cannot run off a board: four register accesses,
// cache maintenance, and a bounded poll.

/// ARM↔VC mailbox block. Device tree `mailbox@7c013880` under
/// `soc@107c000000` (`ranges = <0x00 0x10 0x00 0x80000000>`), so physical
/// 0x10_7c01_3880 — the same identity-mapped Device aperture (GB 65,
/// 0x10_4000_0000..) that already carries RNG200 (0x10_7d20_8000) and the
/// GIC. Mapped Device-nGnRnE by `boot_mmu`, so a wrong OFFSET here is at
/// best a bounded timeout and may be an SError from the fabric (this SoC
/// reports errors on some unbacked reads — see the UBUS REPLY_ERR_DIS note
/// in `pcie.rs`); it is NOT a quiet guarantee, which is why the base is
/// pinned against the DT rather than probed.
const VC_MBOX_BASE: usize = 0x10_7c01_3880;
/// Mailbox 0 (VC→ARM): read register and status.
const VC_MBOX_READ: usize = VC_MBOX_BASE;
const VC_MBOX0_STATUS: usize = VC_MBOX_BASE + 0x18;
/// Mailbox 1 (ARM→VC): write register and status.
const VC_MBOX_WRITE: usize = VC_MBOX_BASE + 0x20;
const VC_MBOX1_STATUS: usize = VC_MBOX_BASE + 0x38;
const VC_MBOX_FULL: u32 = 1 << 31;
const VC_MBOX_EMPTY: u32 = 1 << 30;
/// The property-tags channel (ARM→VC).
const VC_CH_PROPERTY: u32 = 8;
/// Status reads per wait before giving up. Device-memory reads are on the
/// order of 100 ns, so this is roughly a tenth of a second — far past the
/// ~100 µs a property call takes, and it runs on a lazy provider call
/// (`TIER`/`DESCRIBE`), never on the boot path, so the worst case is one
/// slow syscall that answers `false`.
const VC_MBOX_POLL_BOUND: u32 = 1_000_000;

/// The property buffer, and the invariant that makes the cache maintenance
/// below LEGAL rather than merely fast.
///
/// `dc ivac` discards a line without writeback. If this buffer shared a
/// cache line with a neighbouring kernel static, invalidating "our" line
/// would throw away the neighbour's dirty data — silent corruption of an
/// unrelated static — and a neighbour dirtied between our pre-ring clean
/// and the VC's response would write back OVER the response. So the buffer
/// must own its cache lines exclusively: aligned to 128 (CWG-safe on A76;
/// lines are 64) and padded to a whole number of lines. 32 words = 128
/// bytes = exactly its own lines; also headroom for any future tag (the
/// OTP exchange needs 16).
#[repr(C, align(128))]
struct VcMboxBuf([u32; 32]);
static mut VC_MBOX_BUF: VcMboxBuf = VcMboxBuf([0; 32]);

/// One caller at a time; the loser answers `false` (fail-safe) rather than
/// sharing the buffer. Needed because provider syscalls execute on the
/// calling core and this platform runs module domains on secondaries —
/// two cores CAN be in `TIER` at once. `compare_exchange` with
/// Acquire/Release so the winner's buffer writes are ordered against the
/// flag; every exit path below releases it, because in a kernel with no
/// RAII a leaked flag would be a permanent SOFTWARE tier until reboot.
static VC_MBOX_BUSY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Clean+invalidate the buffer's lines to PoC. Same idiom as the
/// `DMA_FLUSH`/`DMA_INVALIDATE` handlers above (the PoC pair) — NOT the
/// OTA-staging sequence, which is the PoU/instruction-coherency idiom.
///
/// # Safety
/// `addr..addr+len` must be valid mapped memory owned by the caller.
unsafe fn vc_cache_civac(addr: usize, len: usize) {
    let mut ptr = addr & !63;
    let end = (addr + len + 63) & !63;
    while ptr < end {
        core::arch::asm!("dc civac, {}", in(reg) ptr, options(nostack));
        ptr += 64;
    }
    core::arch::asm!("dsb sy");
}

/// One property-mailbox exchange over `VC_MBOX_BUF[..words]`.
///
/// `true` means the firmware took our address and answered SOMETHING at it
/// — whether it answered *successfully* is the parser's question, asked on
/// the buffer afterwards. Every failure path answers `false`, which the
/// caller turns into `SealProvenance::None`, which is the tier this part
/// reported before any of this existed.
///
/// # Safety
/// Kernel context; MMIO to the mailbox block; exclusive buffer access is
/// guaranteed by `VC_MBOX_BUSY` (taken by the caller).
unsafe fn vc_property_exchange(words: usize) -> bool {
    // Identity map: VA == PA for kernel DRAM on this platform (boot_mmu maps
    // all of DRAM 1:1), so the buffer's address IS its physical address. The
    // mailbox word is 32-bit — `(phys & !0xF) | channel` — so a buffer that
    // ever ended up above 4 GB is refused rather than truncated into
    // somebody else's memory.
    let addr = core::ptr::addr_of_mut!(VC_MBOX_BUF) as usize;
    if addr > (u32::MAX as usize) - 128 {
        return false;
    }
    let len = words * 4;

    // Push the request to PoC so the VC reads what we wrote, and drop our
    // own lines so the response is read from RAM, not stale cache.
    vc_cache_civac(addr, len);

    // Ring: wait for space, write `[phys | channel]`.
    let mut waited = 0u32;
    while core::ptr::read_volatile(VC_MBOX1_STATUS as *const u32) & VC_MBOX_FULL != 0 {
        waited += 1;
        if waited > VC_MBOX_POLL_BOUND {
            return false;
        }
    }
    core::ptr::write_volatile(
        VC_MBOX_WRITE as *mut u32,
        (addr as u32 & !0xF) | VC_CH_PROPERTY,
    );

    // Await OUR response. Status EMPTY==0 only says "a message is waiting";
    // the read word carries the channel in its low nibble and the address
    // above — anything not ours (another channel, RAZ garbage on a quiet
    // bus) is discarded and the wait continues, inside the same bound.
    waited = 0;
    loop {
        while core::ptr::read_volatile(VC_MBOX0_STATUS as *const u32) & VC_MBOX_EMPTY != 0 {
            waited += 1;
            if waited > VC_MBOX_POLL_BOUND {
                return false;
            }
        }
        let word = core::ptr::read_volatile(VC_MBOX_READ as *const u32);
        if word & 0xF == VC_CH_PROPERTY && word & !0xF == addr as u32 & !0xF {
            break;
        }
        waited += 1;
        if waited > VC_MBOX_POLL_BOUND {
            return false;
        }
    }

    // Drop any line speculatively fetched while the VC owned the memory,
    // so the parse below reads the firmware's bytes and not our stale ones.
    vc_cache_civac(addr, len);
    true
}

/// Read this board's provisioned sealing key: the raw customer-OTP bytes,
/// `[SEAL_KEY_MAGIC][28 key bytes]` per the layout pinned in
/// `vc_mailbox.rs`.
///
/// Build (host-tested core) → exchange (the transport above) → parse
/// (host-tested core) → rows to LE bytes. `true` ONLY when a processed,
/// well-formed firmware reply yielded exactly the eight rows — and even
/// then the caller's rule still checks the magic and per-row degeneracy,
/// so a mis-addressed or partially-provisioned read answers `None`.
///
/// Provisioning is a separate act and is not this function's business:
/// blowing fuses is irreversible and belongs to a deliberate, audited step,
/// not to a boot path. This only ever READS.
fn bcm_read_device_seal_key(out: &mut [u8; 32]) -> bool {
    use fluxor::kernel::sys::hal as k;

    if VC_MBOX_BUSY
        .compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        // A concurrent caller holds the buffer. `false` here is transient
        // and fail-safe — and `bcm_seal_provenance` memoizes SUCCESS, so
        // after the first good read this path is effectively unreachable.
        return false;
    }
    // SAFETY: the CAS above grants exclusive access to `VC_MBOX_BUF`, the
    // exchange's MMIO targets the DT-pinned mailbox block in the mapped
    // Device aperture, and the flag is released on every path below.
    let ok = unsafe {
        let buf = &mut (*core::ptr::addr_of_mut!(VC_MBOX_BUF)).0;
        let result = (|| {
            let words =
                k::build_get_customer_otp(buf, k::CUSTOMER_OTP_FIRST_ROW, k::CUSTOMER_OTP_ROWS)?;
            if !vc_property_exchange(words) {
                return None;
            }
            let rows = k::parse_get_customer_otp(&buf[..words], k::CUSTOMER_OTP_ROWS)?;
            for (i, row) in rows.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&row.to_le_bytes());
            }
            Some(())
        })();
        result.is_some()
    };
    VC_MBOX_BUSY.store(false, core::sync::atomic::Ordering::Release);
    ok
}

/// This board's sealing provenance, memoized on SUCCESS only.
///
/// `key_vault` asks on every `TIER` and every `DESCRIBE`, and each ask is a
/// full cache-maintained mailbox round trip — plus, under concurrency, the
/// busy-flag loser would transiently answer `None`, and a `key_custody`
/// check racing an unrelated `DESCRIBE` would refuse spuriously. A
/// validated `DeviceUnique` read of OTP cannot become truer or falser
/// later, so a confirmed answer is cached forever; a FAILURE is never
/// cached, because "the mailbox was busy" must not become "this board has
/// no device key" for the rest of the boot.
fn bcm_seal_provenance() -> fluxor::kernel::sys::hal::SealProvenance {
    use core::sync::atomic::{AtomicU8, Ordering};
    static CONFIRMED: AtomicU8 = AtomicU8::new(0);
    if CONFIRMED.load(Ordering::Acquire) == 1 {
        return fluxor::kernel::sys::hal::SealProvenance::DeviceUnique;
    }
    let mut blob = [0u8; 32];
    let ok = bcm_read_device_seal_key(&mut blob);
    let p = fluxor::kernel::sys::hal::provenance_from_hardware_key(ok, &blob);
    if matches!(p, fluxor::kernel::sys::hal::SealProvenance::DeviceUnique) {
        CONFIRMED.store(1, Ordering::Release);
    }
    p
}

static BCM2712_HAL_OPS: HalOps = HalOps {
    // No durable home for a sealed blob on this platform yet, and saying so
    // is the point: the vault keeps its in-RAM entry and behaves exactly as
    // before. A platform gains cold-restart persistence by implementing
    // these two and loses nothing by not.
    seal_blob_write: |_, _| false,
    seal_blob_read: |_, _| None,
    disable_interrupts: bcm_disable_interrupts,
    restore_interrupts: bcm_restore_interrupts,
    wake_scheduler: bcm_wake_scheduler,
    now_millis: bcm_now_millis,
    now_unix_millis: || 0, // no RTC on this platform
    // No RTC, so nothing to say about its synchronisation either.
    // `None` rather than `Some((false, _))`: this board cannot tell, which
    // is a different fact from telling us the clock is unsynchronised.
    clock_sync_status: || None,
    // No sealing on this platform yet.
    //
    // `None` rather than a host-readable stand-in: a sealing key stored in
    // flash beside the blob it seals protects nothing and would still read
    // as `HostReadable`, which is a stronger claim than the truth. bcm2712
    // has OTP fuses that could back `DeviceUnique` — claiming it requires
    // actually deriving from them, and a provenance that overstates itself
    // raises a vault's isolation tier and with it what a deployment
    // believes about keys it has not protected.
    seal_provenance: bcm_seal_provenance,
    seal: |_, _| None,
    unseal: |_, _| None,
    now_micros: bcm_now_micros,
    tick_count: bcm_tick_count,
    flash_base: bcm_flash_base,
    flash_end: bcm_flash_end,
    apply_code_bit: bcm_apply_code_bit,
    validate_fn_addr: bcm_validate_fn_addr,
    validate_module_base: bcm_validate_module_base,
    validate_fn_in_code: bcm_validate_fn_in_code,
    verify_integrity: bcm_verify_integrity,
    ota_stage_protect: bcm_ota_stage_protect,
    pic_barrier: bcm_pic_barrier,
    step_guard_init: bcm_step_guard_init,
    step_guard_arm: bcm_step_guard_arm,
    step_guard_disarm: bcm_step_guard_disarm,
    step_guard_post_check: bcm_step_guard_post_check,
    read_cycle_count: bcm_read_cycle_count,
    isr_tier_init: bcm_isr_tier_init,
    isr_tier_start: bcm_isr_tier_start,
    isr_tier_stop: bcm_isr_tier_stop,
    isr_tier_poll: bcm_isr_tier_poll,
    init_providers: bcm_init_providers,
    release_module_handles: bcm_release_module_handles,
    boot_scan: bcm_boot_scan,
    merge_runtime_overrides: bcm_merge_runtime_overrides,
    init_gpio: |_| 0, // no GPIO init on aarch64 (handled by PIC modules)
    csprng_fill: bcm_csprng_fill,
    core_id: || current_core_id() as usize,
    irq_bind,
    sleep_until: bcm_sleep_until,
    smp_quiesce_peers: bcm_smp_quiesce_peers,
    smp_release_peers: multicore::release_quiesce,
    smp_max_domains: || multicore::MAX_DOMAINS,
    protection_set_enabled: bcm_protection_set_enabled,
    protection_reset: mmu::reset_isolation,
    protection_register_module: bcm_protection_register_module,
    protection_set_channel_region: bcm_protection_set_channel_region,
    protection_set_isolated_channels: mmu::set_isolated_channels,
    protected_step: mmu::protected_step,
    protection_map_page: bcm_protection_map_page,
    protection_unmap_page: bcm_protection_unmap_page,
    stack_canary_check: mpu::check_stack_canary,
    stack_canary_reinit: mpu::reinit_stack_canary,
    // Binary-safe debug-UART write (PL011) — the telemetry `transport_buffer` sink.
    serial_write: |b| uart::uart_nonblocking_write(b),
};

// iproc-rng200 registers (BCM2712 / Pi 5). DT: soc@107c000000/rng@7d208000
// with ranges <0x0 0x10_0000_0000 0x8000_0000>. The block's map, as its
// Linux driver (`iproc-rng200`) programs it: control, the two soft resets,
// the interrupt status word, and the output FIFO with its count register.
#[cfg(feature = "board-pi5")]
const RNG200_BASE: usize = 0x10_7d20_8000;
#[cfg(feature = "board-pi5")]
const RNG200_CTRL: *mut u32 = RNG200_BASE as *mut u32;
#[cfg(feature = "board-pi5")]
const RNG200_RNG_SOFT_RESET: *mut u32 = (RNG200_BASE + 0x04) as *mut u32;
#[cfg(feature = "board-pi5")]
const RNG200_RBG_SOFT_RESET: *mut u32 = (RNG200_BASE + 0x08) as *mut u32;
#[cfg(feature = "board-pi5")]
const RNG200_INT_STATUS: *mut u32 = (RNG200_BASE + 0x18) as *mut u32;
#[cfg(feature = "board-pi5")]
const RNG200_FIFO_DATA: *const u32 = (RNG200_BASE + 0x20) as *const u32;
#[cfg(feature = "board-pi5")]
const RNG200_FIFO_COUNT: *const u32 = (RNG200_BASE + 0x24) as *const u32;
/// `RNG_CTRL` generator-enable field.
#[cfg(feature = "board-pi5")]
const RNG200_RBGEN_MASK: u32 = 0x1FFF;
#[cfg(feature = "board-pi5")]
const RNG200_RBGEN_ENABLE: u32 = 0x1;
/// `RNG_INT_STATUS`: the generator locked itself out after a health-test
/// failure and produces nothing until reset.
#[cfg(feature = "board-pi5")]
const RNG200_MASTER_FAIL_LOCKOUT: u32 = 1 << 31;
/// `RNG_FIFO_COUNT`: words waiting in the output FIFO.
#[cfg(feature = "board-pi5")]
const RNG200_FIFO_COUNT_MASK: u32 = 0xFF;

/// Bring the generator to a known-running state: generator off, both
/// soft resets pulsed, interrupt status cleared, generator on.
#[cfg(feature = "board-pi5")]
unsafe fn rng200_restart() {
    let ctrl = core::ptr::read_volatile(RNG200_CTRL) & !RNG200_RBGEN_MASK;
    core::ptr::write_volatile(RNG200_CTRL, ctrl);
    core::ptr::write_volatile(RNG200_RNG_SOFT_RESET, 1);
    core::ptr::write_volatile(RNG200_RNG_SOFT_RESET, 0);
    core::ptr::write_volatile(RNG200_RBG_SOFT_RESET, 1);
    core::ptr::write_volatile(RNG200_RBG_SOFT_RESET, 0);
    let pending = core::ptr::read_volatile(RNG200_INT_STATUS);
    core::ptr::write_volatile(RNG200_INT_STATUS, pending);
    core::ptr::write_volatile(RNG200_CTRL, ctrl | RNG200_RBGEN_ENABLE);
}

/// Fill buffer with hardware random bytes.
///
/// Pi 5 (board-pi5): the iproc-rng200 TRNG at 0x10_7d20_8000. A word is
/// taken only from a running generator's FIFO, and a zero word is never
/// entropy: the source presents zeros while unseeded or locked out, so
/// zeros are discarded, a run of them restarts the block, and a run that
/// outlasts the restart is a dead source, refused rather than handed out.
/// QEMU virt: CNTPCT_EL0 counter jitter with LCG mixing (weak).
///
/// Returns 0 on success, -1 if the hardware failed to produce entropy —
/// the [`HalOps::csprng_fill`] contract. A byte count is not a success
/// value here: callers test the result against 0, so returning `len`
/// reads as a failure for every non-empty fill.
///
/// [`HalOps::csprng_fill`]: crate::kernel::sys::hal::HalOps::csprng_fill
fn bcm_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    // SAFETY: iproc-rng200 MMIO is the documented BCM2712 RNG block;
    // mapped by `boot_mmu::init_page_tables`. `buf`/`len` come from a
    // caller-owned slice via the syscall ABI.
    unsafe {
        #[cfg(feature = "board-pi5")]
        {
            // The waits are time-bounded: the FIFO refills in microseconds,
            // so a wait this long is a hardware fault, not a race.
            const WORD_WAIT_US: u64 = 1_000_000;
            const ZERO_RUN_RESTART: u32 = 64;
            const ZERO_RUN_FATAL: u32 = 4096;
            let status = core::ptr::read_volatile(RNG200_INT_STATUS);
            let ctrl = core::ptr::read_volatile(RNG200_CTRL);
            if status & RNG200_MASTER_FAIL_LOCKOUT != 0
                || ctrl & RNG200_RBGEN_MASK != RNG200_RBGEN_ENABLE
            {
                rng200_restart();
            }
            let mut zero_run = 0u32;
            let mut restarted = false;
            let mut i = 0usize;
            while i < len {
                let deadline = bcm_now_micros() + WORD_WAIT_US;
                while core::ptr::read_volatile(RNG200_FIFO_COUNT) & RNG200_FIFO_COUNT_MASK == 0
                    && bcm_now_micros() < deadline
                {
                    core::hint::spin_loop();
                }
                if core::ptr::read_volatile(RNG200_FIFO_COUNT) & RNG200_FIFO_COUNT_MASK == 0 {
                    uart_puts(b"[rng200] FATAL: entropy timeout\r\n");
                    return -1;
                }
                let word = core::ptr::read_volatile(RNG200_FIFO_DATA);
                if word == 0 {
                    zero_run += 1;
                    if zero_run == ZERO_RUN_RESTART && !restarted {
                        rng200_restart();
                        restarted = true;
                    }
                    if zero_run >= ZERO_RUN_FATAL {
                        uart_puts(b"[rng200] FATAL: only zero words\r\n");
                        return -1;
                    }
                    continue;
                }
                zero_run = 0;
                let bytes = word.to_le_bytes();
                let mut j = 0;
                while j < 4 && i < len {
                    core::ptr::write_volatile(buf.add(i), bytes[j]);
                    i += 1;
                    j += 1;
                }
            }
        }

        #[cfg(not(feature = "board-pi5"))]
        {
            // QEMU virt: no hardware RNG. Use counter jitter + LCG mixing.
            // Adequate for testing only.
            let mut state: u64 = 0;
            let mut i = 0usize;
            while i < len {
                let cnt: u64;
                core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt);
                state ^= cnt;
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                core::ptr::write_volatile(buf.add(i), (state >> 32) as u8);
                i += 1;
            }
        }
    }
    0
}

/// Panic latch — a panic on a secondary core prints to the (possibly unwired)
/// UART then halts. These atomics let core 0, which owns the live UDP debug
/// drain, surface the panic site over network telemetry. file ptr+len point
/// into 'static rodata (kernel or PIC module — shared address space), so core 0
/// can reconstruct the `&str`.
pub static PANIC_CORE: portable_atomic::AtomicU32 = portable_atomic::AtomicU32::new(0xFFFF_FFFF);
pub static PANIC_LINE: portable_atomic::AtomicU32 = portable_atomic::AtomicU32::new(0);
pub static PANIC_FILE_PTR: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);
pub static PANIC_FILE_LEN: portable_atomic::AtomicU32 = portable_atomic::AtomicU32::new(0);

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // Latch the panic site so core 0 can broadcast it over UDP (the UART
    // dump below is invisible on benches without a wired debug UART). Done
    // first, with plain atomic stores only — no formatting/alloc in here.
    if let Some(loc) = info.location() {
        PANIC_LINE.store(loc.line(), Ordering::Relaxed);
        PANIC_FILE_PTR.store(loc.file().as_ptr() as u64, Ordering::Relaxed);
        PANIC_FILE_LEN.store(loc.file().len() as u32, Ordering::Relaxed);
    }
    PANIC_CORE.store(current_core_id() as u32, Ordering::Relaxed);
    // Emergency sink: platform-owned, separate from the normal
    // DebugTx drain. Writes directly to the UART hardware because
    // the scheduler is dead and the debug drain won't run again.
    // Gated on UART_READY so we don't poke the peripheral before
    // `uart_init` has run.
    if UART_READY.load(Ordering::Relaxed) != 0 {
        uart_raw_puts(b"\r\n!!! PANIC on core ");
        uart_raw_put_u32(current_core_id() as u32);
        uart_raw_puts(b"\r\n");
        if let Some(loc) = info.location() {
            uart_raw_puts(b"  at ");
            uart_raw_puts(loc.file().as_bytes());
            uart_raw_putc(b':');
            uart_raw_put_u32(loc.line());
            uart_raw_puts(b"\r\n");
        }
        let mut buf = [0u8; 1024];
        let n = fluxor::kernel::sys::log_ring::read_tail(&mut buf);
        if n > 0 {
            uart_raw_puts(b"--- log tail (");
            uart_raw_put_u32(n as u32);
            uart_raw_puts(b" bytes) ---\r\n");
            uart_raw_puts(&buf[..n]);
            uart_raw_puts(b"\r\n--- end ---\r\n");
        }
    }
    loop {
        // SAFETY: WFI is a hint; halts the core until next interrupt.
        unsafe { core::arch::asm!("wfi") };
    }
}

//! Module protection on the RP family: gated modules run unprivileged, on
//! their own process stack, inside MPU regions the shared planner draws, and
//! reach the kernel only through the gateway.
//!
//! One implementation serves both dies. What differs — how a region is
//! drawn (PMSAv8 base/limit against PMSAv7 power-of-two with subregions),
//! whether a limit register bounds the process stack, and which fault
//! vectors exist — is a target fact (`chip::ISOLATION_*`) or an
//! architectural `cfg`, never a chip-name branch.
//!
//! # The round trip
//!
//! - **Entry** ([`protected_call`], privileged thread on MSP): program the
//!   module's regions (and `PSPLIM` on ARMv8-M), build the module's first
//!   exception frame on its own stack below its params — arguments, the
//!   return veneer as `lr`, the entry point as `pc` — save the kernel's
//!   callee-saved registers and MSP in this core's control block, and issue
//!   the launch SVC.
//! - **Launch and resume** (the trap, handler mode, from a kernel SVC while
//!   an entry is live): restore the module's callee-saved registers, put MSP
//!   back where the kernel left it, mark thread mode unprivileged and
//!   exception-return onto the module's PSP frame. Privilege is dropped only
//!   by that return, never in thread mode, so no kernel instruction runs
//!   unprivileged and nothing the module can reach needs to.
//! - **Trap** (`fluxor_rp_trap`, handler mode): an SVC from a veneer, a fault,
//!   or PendSV pended by the step guard, taken while this core's gated module
//!   runs, saves the module's callee-saved registers and PSP frame, regains
//!   privilege, and exception-returns to thread mode on MSP in
//!   `fluxor_rp_trap_thread` — so everything the kernel then does runs in
//!   privileged thread mode, exactly as a non-gated module's calls do.
//! - **Serve** ([`fluxor_rp_serve`]): a gateway op is authorised and served,
//!   the result is written into the module's frame, and the resume SVC puts
//!   the module back at its veneer's `bx lr`; the return veneer, a fault or a
//!   missed deadline returns to the kernel from `protected_call` with the
//!   outcome.
//!
//! A PendSV the step guard pends while the kernel is serving a gateway op
//! arrives on MSP. It is recorded in the control block and honoured at the
//! resume SVC, which then finishes the entry as forced out instead of
//! returning to the module, so a deadline cannot slip past between a check
//! and the privilege drop.
//!
//! Anything else that traps with the core privileged, or on MSP, is the
//! kernel's own fault and parks the node as before.

use portable_atomic::{AtomicU32, Ordering};

use crate::kernel::exec::scheduler::MAX_MODULES;
use crate::kernel::module::gateway;
use crate::platform::chip;
use fluxor_contracts::isolation::{region_plan, Access, RegionModel, Span};

/// How this die draws regions, from the silicon TOML.
pub const MODEL: RegionModel = if chip::ISOLATION_PMSAV8 {
    RegionModel::Pmsav8 {
        regions: chip::ISOLATION_REGIONS,
    }
} else {
    RegionModel::Pmsav7 {
        regions: chip::ISOLATION_REGIONS,
    }
};

/// Bytes an exception frame takes on a gated module's stack: the basic
/// frame and the alignment pad (the FPU is off, so never the extended frame).
pub const EXCEPTION_FRAME_BYTES: usize = 32 + 4;

mod reg {
    pub const ICSR: usize = 0xE000_ED04;
    pub const SHPR2: usize = 0xE000_ED1C;
    pub const SHPR3: usize = 0xE000_ED20;
    pub const SHCSR: usize = 0xE000_ED24;
    pub const CFSR: usize = 0xE000_ED28;
    pub const MMFAR: usize = 0xE000_ED34;
    pub const MPU_TYPE: usize = 0xE000_ED90;
    pub const MPU_CTRL: usize = 0xE000_ED94;
    pub const MPU_RNR: usize = 0xE000_ED98;
    pub const MPU_RBAR: usize = 0xE000_ED9C;
    /// RLAR on PMSAv8, RASR on PMSAv7.
    pub const MPU_RLAR_RASR: usize = 0xE000_EDA0;
    pub const MPU_MAIR0: usize = 0xE000_EDC0;
}

#[inline(always)]
unsafe fn w(addr: usize, v: u32) {
    // SAFETY: fixed System Control Space registers; caller is privileged.
    unsafe { core::ptr::write_volatile(addr as *mut u32, v) }
}

#[inline(always)]
unsafe fn r(addr: usize) -> u32 {
    // SAFETY: as `w`.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

// ── The gateway block ────────────────────────────────────────────────
//
// One 256-byte, 256-aligned block of kernel flash that every gated module
// may read and execute: the veneers (`svc #op; bx lr`, four bytes each, the
// op derived from the trapping address so a module cannot name one with an
// SVC of its own), the return veneer, then the gateway `SyscallTable` in
// `SyscallTable`'s own field order. Nothing else is in it. 256 bytes and
// 256-aligned is one region under both models.
core::arch::global_asm!(
    ".section .text.fluxor_gateway, \"ax\"",
    ".p2align 8",
    // A plain label, not `.thumb_func`: its value is the block's address,
    // the region base; each table entry adds the Thumb bit itself.
    ".global fluxor_rp_gateway",
    "fluxor_rp_gateway:",
    ".irp op, 0,1,2,3,4,5,6,7,8,9,10,11",
    "svc #\\op",
    "bx lr",
    ".endr",
    // The return veneer: entry points return here.
    "svc #12",
    "b .",
    ".p2align 2",
    ".global fluxor_rp_gateway_table",
    "fluxor_rp_gateway_table:",
    ".word {version}",
    ".word fluxor_rp_gateway + 0*4 + 1",  // channel_read
    ".word fluxor_rp_gateway + 1*4 + 1",  // channel_write
    ".word fluxor_rp_gateway + 2*4 + 1",  // channel_poll
    ".word fluxor_rp_gateway + 3*4 + 1",  // heap_alloc
    ".word fluxor_rp_gateway + 4*4 + 1",  // heap_free
    ".word fluxor_rp_gateway + 5*4 + 1",  // heap_realloc
    ".word fluxor_rp_gateway + 6*4 + 1",  // provider_open
    ".word fluxor_rp_gateway + 7*4 + 1",  // provider_call
    ".word fluxor_rp_gateway + 8*4 + 1",  // provider_query
    ".word fluxor_rp_gateway + 9*4 + 1",  // provider_close
    ".word fluxor_rp_gateway + 10*4 + 1", // channel_peek
    // telemetry_enabled: a word the kernel writes cannot be read-only to the
    // module and current at once; the SDK treats null as "ask".
    ".word 0",
    ".word fluxor_rp_gateway + 11*4 + 1", // provider_call_sel
    ".p2align 8",
    version = const crate::abi::ABI_VERSION,
);

unsafe extern "C" {
    static fluxor_rp_gateway: u8;
    static fluxor_rp_gateway_table: u8;
}

const GATEWAY_BLOCK: u32 = 256;
const RETURN_OP: u32 = gateway::op::RETURN;
const _: () = assert!(gateway::op::COUNT == 12 && RETURN_OP == 12);
/// The immediate of the SVC the kernel issues, on MSP, to launch or resume
/// a gated module. A veneer's immediate is its op, which is below
/// `RETURN_OP`; a module has no SVC of its own the trap honours.
const RESUME_SVC: u32 = 0xFF;
const _: () = assert!(RESUME_SVC > RETURN_OP);

fn gateway_base() -> u32 {
    // Only the address of the assembly label is taken.
    core::ptr::addr_of!(fluxor_rp_gateway) as u32
}

const _: () = assert!(
    RESUME_SVC == 0xFF,
    "the launch and resume SVCs above are `svc #0xFF`"
);

/// The gateway `SyscallTable` a gated module is handed.
pub fn gateway_table() -> *const crate::abi::SyscallTable {
    // Only the address of the assembly label is taken.
    core::ptr::addr_of!(fluxor_rp_gateway_table) as *const _
}

// ── Per-module domains ──────────────────────────────────────────────

/// Most regions any gated module needs: code, gateway block, private region
/// and a device window.
const DOMAIN_REGIONS: usize = 4;

/// A module's domain as the MPU is programmed with it: each region's two
/// register values (RBAR, and RLAR on PMSAv8 or RASR on PMSAv7), encoded
/// once at registration so a switch is register writes and nothing else.
#[derive(Clone, Copy)]
struct Domain {
    regs: [(u32, u32); DOMAIN_REGIONS],
    count: u8,
    /// The process stack: `PSP` starts at `stack_top`, `PSPLIM` is
    /// `stack_floor`.
    stack_floor: u32,
    stack_top: u32,
    /// The peripheral-gate register opened for this module's device window,
    /// or 0 for none.
    gate: u32,
}

static mut DOMAINS: [Domain; MAX_MODULES] = [Domain {
    regs: [(0, 0); DOMAIN_REGIONS],
    count: 0,
    stack_floor: 0,
    stack_top: 0,
    gate: 0,
}; MAX_MODULES];

// ── Peripheral gate (ACCESSCTRL) ────────────────────────────────────

/// Written into the top half of every ACCESSCTRL write, or it is ignored.
const GATE_PASSWORD: u32 = 0xacce_0000;
/// Secure unprivileged, Non-secure privileged, Non-secure unprivileged.
const GATE_SU: u32 = 1 << 2;
const GATE_UNPRIVILEGED_AND_NS: u32 = 0b111;

/// Make every peripheral Secure-privileged only: whatever the MPU allows,
/// unprivileged code reaches no peripheral register. The masters' bits
/// (cores, DMA, debugger) and SRAM, ROM and XIP are left as they are.
fn gate_lock_peripherals() {
    let Some((base, first, last)) = chip::PERIPHERAL_GATE else {
        return;
    };
    let mut n = 0;
    let mut off = first;
    while off <= last {
        let a = (base + off) as usize;
        // SAFETY: ACCESSCTRL registers from the silicon TOML; boot, Secure
        // privileged.
        unsafe {
            let v = crate::platform::rp_regs::read32(a) & 0xFF;
            crate::platform::rp_regs::write32(a, GATE_PASSWORD | (v & !GATE_UNPRIVILEGED_AND_NS));
        }
        n += 1;
        off += 4;
    }
    log::info!("[gate] peripherals privileged-only: {n}");
}

/// Open (or close) one block's peripheral-gate register to Secure
/// unprivileged access, for the gated module holding it as its window.
fn gate_set_unprivileged(gate: u32, open: bool) {
    let Some((base, _, _)) = chip::PERIPHERAL_GATE else {
        return;
    };
    let a = (base + gate) as usize;
    // SAFETY: an ACCESSCTRL register the TOML names; setup or teardown path,
    // Secure privileged.
    unsafe {
        let v = crate::platform::rp_regs::read32(a) & 0xFF;
        let v = if open { v | GATE_SU } else { v & !GATE_SU };
        crate::platform::rp_regs::write32(a, GATE_PASSWORD | v);
    }
}

/// Encode one planned region as its (RBAR, RLAR/RASR) pair.
fn encode(rg: &fluxor_contracts::isolation::Region) -> (u32, u32) {
    if chip::ISOLATION_PMSAV8 {
        // RBAR: base | SH=0 | AP | XN;  RLAR: limit | AttrIndx | EN.
        let (ap, xn) = match rg.access {
            Access::ReadExec => (0b11, 0),  // RO, any privilege
            Access::ReadWrite => (0b01, 1), // RW, any privilege
            Access::Device => (0b01, 1),
            Access::Guard => (0b00, 1), // RW privileged only
        };
        let attr = if rg.access == Access::Device { 1 } else { 0 };
        (
            (rg.base as u32 & !0x1F) | (ap << 1) | xn,
            ((rg.base + rg.size - 1) as u32 & !0x1F) | (attr << 1) | 1,
        )
    } else {
        // RBAR: base (RNR selects the region); RASR: XN | AP | TEX/S/C/B |
        // SRD | SIZE | EN.
        let (ap, xn) = match rg.access {
            Access::ReadExec => (0b110, 0),  // RO, any privilege
            Access::ReadWrite => (0b011, 1), // RW, any privilege
            Access::Device => (0b011, 1),
            Access::Guard => (0b001, 1), // RW privileged only
        };
        // TEX:S:C:B — device (000:1:0:1), or normal non-cacheable
        // shareable (001:1:0:0).
        let tcb = if rg.access == Access::Device {
            0b00_0101
        } else {
            0b00_1100
        };
        let size_field = 63 - rg.size.leading_zeros() - 1;
        (
            rg.base as u32 & !0xFF,
            (xn << 28) | (ap << 24) | (tcb << 16) | ((rg.srd as u32) << 8) | (size_field << 1) | 1,
        )
    }
}

/// Build `module`'s domain from what the gateway knows of it: its code, the
/// gateway block, and its private region (stack, state and heap, which the
/// loader allocated as one). `false` fails its load closed.
pub fn register(module: usize) -> bool {
    if module >= MAX_MODULES || !mpu_matches_facts() {
        return false;
    }
    let Some((code, stack, private)) = gateway::regions(module) else {
        return false;
    };
    let Some(whole) = private.iter().find(|r| r.len != 0) else {
        return false;
    };
    // An isolated module reads and executes only its own code, as the span
    // the planner draws for it: its code rounded to the packer's page
    // alignment, which reaches its own image and the pad before the next
    // module's header, never another module's code. A contained module may
    // read and execute all of flash — it is the kernel's memory, not its
    // code, that `contained` protects — which also serves a module whose
    // code is too large for PMSAv7 to draw at its page alignment.
    let contained = crate::kernel::exec::scheduler::module_protection_level(module)
        == crate::kernel::exec::scheduler::protection_level::CONTAINED;
    let (code_base, code_len) = if contained {
        (chip::FLASH_BASE as u64, chip::FLASH_SIZE as u64)
    } else {
        (
            code.base as u64,
            fluxor_contracts::isolation::code_region_len(code.len as u64),
        )
    };
    let code_span = Span {
        base: code_base,
        len: code_len,
        access: Access::ReadExec,
    };
    let private_span = Span {
        base: whole.base as u64,
        len: whole.len as u64,
        access: Access::ReadWrite,
    };
    // All of flash already covers the gateway block for a contained module.
    let gateway_span = Span {
        base: gateway_base() as u64,
        len: GATEWAY_BLOCK as u64,
        access: Access::ReadExec,
    };
    // A device window the graph granted: the peripheral's registers, device
    // memory, reachable directly and nothing beside them. Only inside a block
    // the target lists as grantable, whatever the config says.
    let window = crate::kernel::exec::scheduler::module_device_window(module).map(|(b, z)| Span {
        base: b,
        len: z as u64,
        access: Access::Device,
    });
    let mut gate = 0;
    if let Some(w) = window {
        let block = chip::DEVICE_RANGES
            .iter()
            .position(|&(rb, rz)| w.base >= rb && w.base + w.len <= rb + rz);
        if let Some(i) = block {
            gate = chip::DEVICE_RANGE_GATES[i];
        } else {
            log::error!(
                "[mpu] module {module}: device window 0x{:x}+{} is outside every grantable block",
                w.base,
                w.len
            );
            return false;
        }
    }
    let mut spans_buf = [code_span; DOMAIN_REGIONS];
    let mut n = 0;
    for sp in [
        Some(code_span),
        (!contained).then_some(gateway_span),
        Some(private_span),
        window,
    ]
    .into_iter()
    .flatten()
    {
        spans_buf[n] = sp;
        n += 1;
    }
    let spans: &[Span] = &spans_buf[..n];
    match region_plan(spans, MODEL) {
        Ok(plan) if plan.regions().len() <= DOMAIN_REGIONS => {
            let mut d = Domain {
                regs: [(0, 0); DOMAIN_REGIONS],
                count: plan.regions().len() as u8,
                stack_floor: stack.base as u32,
                stack_top: (stack.base + stack.len) as u32,
                gate,
            };
            for (slot, rg) in d.regs.iter_mut().zip(plan.regions()) {
                *slot = encode(rg);
            }
            // SAFETY: setup path; this module is not running.
            unsafe { DOMAINS[module] = d };
            if let Some(w) = window {
                if gate != 0 {
                    gate_set_unprivileged(gate, true);
                }
                log::info!(
                    "[mpu] module {module} device window 0x{:x}+{} gate=0x{gate:x}",
                    w.base,
                    w.len
                );
            }
            log::info!(
                "[mpu] module {module} {}: {} regions, code=0x{:x}+{} private=0x{:x}+{} stack=0x{:x}..0x{:x}",
                if contained { "contained" } else { "isolated" },
                plan.regions().len(),
                code_base,
                code_len,
                whole.base,
                whole.len,
                stack.base,
                stack.base + stack.len,
            );
            true
        }
        Ok(plan) => {
            log::error!(
                "[mpu] module {module}: its plan needs {} regions — not isolated, not run",
                plan.regions().len()
            );
            false
        }
        Err(e) => {
            log::error!("[mpu] module {module}: no region plan: {e:?} — not isolated, not run");
            false
        }
    }
}

/// Forget `module`'s domain at teardown.
pub fn release(module: usize) {
    if module < MAX_MODULES {
        // SAFETY: the module is no longer stepping.
        unsafe {
            let d = &mut DOMAINS[module];
            if d.gate != 0 {
                gate_set_unprivileged(d.gate, false);
                d.gate = 0;
            }
            d.count = 0;
        }
    }
}

/// Whether the MPU is what the target facts say. Read once at boot and
/// logged; a mismatch refuses every isolation rather than programming
/// regions that do not exist.
fn mpu_matches_facts() -> bool {
    static CHECKED: AtomicU32 = AtomicU32::new(0);
    match CHECKED.load(Ordering::Acquire) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    // SAFETY: a read-only SCS register.
    let dregion = (unsafe { r(reg::MPU_TYPE) } >> 8) & 0xFF;
    let ok = dregion == chip::ISOLATION_REGIONS as u32 && dregion != 0;
    log::info!(
        "[mpu] type dregion={dregion} model={} facts={} {}",
        if chip::ISOLATION_PMSAV8 {
            "pmsav8"
        } else {
            "pmsav7"
        },
        chip::ISOLATION_REGIONS,
        if ok {
            "ok"
        } else {
            "MISMATCH — isolation refused"
        }
    );
    CHECKED.store(if ok { 1 } else { 2 }, Ordering::Release);
    ok
}

// ── Region programming ──────────────────────────────────────────────

/// Program `d` and enable the MPU with the privileged default map, so the
/// kernel keeps its whole address space and the module sees only its regions.
unsafe fn program(d: &Domain) {
    // SAFETY: privileged; interrupts that fire run privileged under
    // PRIVDEFENA, and the regions only ever grant.
    unsafe {
        w(reg::MPU_CTRL, 0);
        crate::arch::cortex_m::dsb();
        for n in 0..chip::ISOLATION_REGIONS as usize {
            w(reg::MPU_RNR, n as u32);
            if n < d.count as usize {
                w(reg::MPU_RBAR, d.regs[n].0);
                w(reg::MPU_RLAR_RASR, d.regs[n].1);
            } else {
                w(reg::MPU_RLAR_RASR, 0);
            }
        }
        // PRIVDEFENA | ENABLE.
        w(reg::MPU_CTRL, 0b101);
        crate::arch::cortex_m::dsb();
        crate::arch::cortex_m::isb();
    }
}

unsafe fn mpu_off() {
    // SAFETY: privileged.
    unsafe {
        w(reg::MPU_CTRL, 0);
        crate::arch::cortex_m::dsb();
        crate::arch::cortex_m::isb();
    }
}

// ── Control blocks ──────────────────────────────────────────────────

/// Per-core round-trip state, addressed from assembly by offset.
#[repr(C, align(64))]
struct Cb {
    kernel_msp: u32,     // 0
    active: u32,         // 4
    frame: u32,          // 8  (PSP at the trap)
    kind: u32,           // 12 (IPSR at the trap)
    module_r4: [u32; 8], // 16..48 (r4-r11)
    result: u32,         // 48
    module: u32,         // 52
    outcome: i32,        // 56
    /// A PendSV the step guard pended reached the kernel path (MSP) while
    /// the entry was live: the module is forced out at its next resume
    /// instead of running on.
    pending: u32, // 60
}

const _: () = {
    assert!(core::mem::size_of::<Cb>() == 64);
    assert!(core::mem::offset_of!(Cb, result) == 48);
    assert!(core::mem::offset_of!(Cb, outcome) == 56);
    assert!(core::mem::offset_of!(Cb, pending) == 60);
};

const CORES: usize = 2;

#[no_mangle]
static mut FLUXOR_RP_GATE_CB: [Cb; CORES] = [const {
    Cb {
        kernel_msp: 0,
        active: 0,
        frame: 0,
        kind: 0,
        module_r4: [0; 8],
        result: 0,
        module: 0,
        outcome: 0,
        pending: 0,
    }
}; CORES];

fn core_id() -> usize {
    // SAFETY: SIO CPUID, a read-only register present on both dies.
    (unsafe { core::ptr::read_volatile(0xD000_0000 as *const u32) } as usize) & 1
}

/// Whether a gated module is running on this core — the step guard's alarm
/// asks, to decide whether to force it out.
pub fn gated_active() -> bool {
    // SAFETY: this core's block, read on this core.
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(FLUXOR_RP_GATE_CB[core_id()].active)) != 0
    }
}

/// Force the gated module running on this core out at the next opportunity:
/// pend PendSV, whose handler, finding unprivileged thread context, turns it
/// into a trap.
pub fn force_out() {
    // SAFETY: ICSR.PENDSVSET.
    unsafe { w(reg::ICSR, 1 << 28) };
}

/// One-time setup: SVC and PendSV at the lowest priority, so every device
/// interrupt still preempts the trap path; the configurable faults enabled
/// where they exist, so a module's MemManage or stack-limit fault is not
/// escalated.
pub fn init() {
    // SAFETY: privileged SCS writes at boot.
    unsafe {
        let v = r(reg::SHPR2) & 0x00FF_FFFF;
        w(reg::SHPR2, v | 0xFF00_0000);
        let v = r(reg::SHPR3) & 0xFF00_FFFF;
        w(reg::SHPR3, v | 0x00FF_0000);
        if chip::ISOLATION_PMSAV8 {
            // MEMFAULTENA | BUSFAULTENA | USGFAULTENA.
            let v = r(reg::SHCSR);
            w(reg::SHCSR, v | (0b111 << 16));
            // Attr0 normal non-cacheable, Attr1 device nGnRE.
            w(reg::MPU_MAIR0, 0x0000_0444);
        }
    }
    let _ = mpu_matches_facts();
    gate_lock_peripherals();
}

// ── Entry ───────────────────────────────────────────────────────────

unsafe extern "C" {
    fn fluxor_rp_enter(cb: *mut Cb, entry: u32, args: *const u32, psp: u32, ret: u32) -> i32;
}

/// Call one entry point of gated module `module` unprivileged (the HAL's
/// `protected_call`). A module with no domain is refused, never run
/// privileged.
///
/// The module's stack starts below its params, then four words for
/// arguments five to eight, then the exception frame the launch returns
/// onto: `args[0..4]` in r0–r3, the return veneer in `lr`, `entry` in `pc`.
///
/// # Safety
/// `entry` is a validated export of `module` taking `args`; the caller runs
/// on the core the module is stepped on.
pub unsafe fn protected_call(
    module: usize,
    entry: usize,
    args: &[usize; 8],
    params: &[u8],
    deadline_us: u32,
) -> i32 {
    if module >= MAX_MODULES {
        return crate::kernel::sys::hal::PROTECTED_CALL_REFUSED;
    }
    // SAFETY: setup-path writes; read on the stepping core.
    let d = unsafe { DOMAINS[module] };
    if d.count == 0 {
        return crate::kernel::sys::hal::PROTECTED_CALL_REFUSED;
    }
    let mut a = [0u32; 8];
    for (o, i) in a.iter_mut().zip(args.iter()) {
        *o = *i as u32;
    }
    // Params at the top of the module's own stack, 8-aligned; below them the
    // four words for arguments five to eight and the launch frame, which the
    // entry sequence places, then the stack proper.
    let mut psp = d.stack_top;
    if !params.is_empty() {
        let len = (params.len() as u32 + 7) & !7;
        if len + 64 > d.stack_top - d.stack_floor {
            return crate::kernel::sys::hal::PROTECTED_CALL_REFUSED;
        }
        psp -= len;
        // SAFETY: inside the module's own stack, which the loader allocated.
        unsafe { core::ptr::copy_nonoverlapping(params.as_ptr(), psp as *mut u8, params.len()) };
        a[3] = psp;
    }
    let core = core_id();
    // SAFETY: this core's block; the module is not running.
    let cb = unsafe { core::ptr::addr_of_mut!(FLUXOR_RP_GATE_CB[core]) };
    // SAFETY: as above — only this core touches its control block.
    unsafe {
        (*cb).module = module as u32;
        (*cb).outcome = 0;
        program(&d);
        // The process stack's limit register, where the architecture has
        // one: ARMv8-M. The ARMv6-M build has no `PSPLIM`, so there the
        // bound is the end of the private region.
        #[cfg(not(feature = "chip-rp2040"))]
        core::arch::asm!("msr PSPLIM, {0}", in(reg) d.stack_floor, options(nomem, nostack));
    }
    // The step guard bounds every entry, not only steps: construction arms it
    // here, a step re-arms what the scheduler armed.
    let armed_here = !crate::kernel::exec::step_guard::is_armed();
    if deadline_us != 0 {
        crate::platform::rp_step_guard::rp_step_guard_arm(deadline_us);
    }
    let ret = gateway_base() + 4 * RETURN_OP + 1;
    // SAFETY: the domain is programmed; the enter/trap assembly restores the
    // kernel's registers and MSP before returning here.
    let rc = unsafe { fluxor_rp_enter(cb, entry as u32 | 1, a.as_ptr(), psp, ret) };
    if armed_here {
        crate::platform::rp_step_guard::rp_step_guard_disarm();
    }
    rc
}

// ── Serve (privileged thread mode) ──────────────────────────────────

/// What `fluxor_rp_trap_thread` does next.
const RESUME: u32 = 0;
const RETURN: u32 = 1;

/// Decide one trap from this core's gated module. Returns [`RESUME`] with
/// `cb.result` set for a served gateway op, or [`RETURN`] with `cb.outcome`
/// set when the entry is over (returned, faulted, or forced out).
#[no_mangle]
unsafe extern "C" fn fluxor_rp_serve(cb: *mut Cb) -> u32 {
    // SAFETY: this core's block, filled by the trap on this core.
    let (kind, frame, module) = unsafe { ((*cb).kind & 0x1FF, (*cb).frame, (*cb).module as usize) };
    let finish = |outcome: i32| -> u32 {
        // SAFETY: as above; the module is suspended for good.
        unsafe {
            (*cb).outcome = outcome;
            (*cb).active = 0;
            mpu_off();
        }
        RETURN
    };
    let stack = gateway::regions(module).map(|(_, s, _)| s);
    let in_stack = |addr: u32, len: u32| match stack {
        Some(s) => s.contains(addr as usize, len as usize),
        None => false,
    };
    match kind {
        // SVC: only from a veneer. The op is where it trapped from.
        11 => {
            if !in_stack(frame, 32) {
                log::error!("[mpu] module {module}: SVC with its stack outside its own memory");
                crate::kernel::exec::step_guard::record_mpu_fault(module);
                return finish(0);
            }
            // SAFETY: the frame lies in the module's stack (checked).
            let f = |i: u32| unsafe { core::ptr::read_volatile((frame + 4 * i) as *const u32) };
            let pc = f(6);
            let off = pc.wrapping_sub(2).wrapping_sub(gateway_base());
            if off % 4 != 0 || off / 4 > RETURN_OP {
                log::error!("[mpu] module {module}: SVC at 0x{pc:08x}, not from a veneer — protection fault");
                crate::kernel::exec::step_guard::record_mpu_fault(module);
                return finish(0);
            }
            let op = off / 4;
            if op == RETURN_OP {
                note_clean(module);
                return finish(f(0) as i32);
            }
            // Arguments five and six sit above the frame (and its pad).
            let pad = if f(7) & (1 << 9) != 0 { 4 } else { 0 };
            let above = frame + 32 + pad;
            let (a4, a5) = if in_stack(above, 8) {
                // SAFETY: inside the module's stack (checked).
                unsafe {
                    (
                        core::ptr::read_volatile(above as *const u32),
                        core::ptr::read_volatile((above + 4) as *const u32),
                    )
                }
            } else {
                (0, 0)
            };
            let args = [
                f(0) as usize,
                f(1) as usize,
                f(2) as usize,
                f(3) as usize,
                a4 as usize,
                a5 as usize,
            ];
            // SAFETY: the module is suspended at its veneer; the gateway
            // validates everything before use.
            let rc = unsafe { gateway::dispatch(module, op, args) };
            // The deadline may have passed while the kernel served the op:
            // the alarm's PendSV then reached the kernel path, and the
            // module is not resumed on borrowed time.
            if crate::kernel::exec::step_guard::is_timed_out() {
                log::error!("[mpu] module {module} forced out: ran past its step deadline");
                crate::kernel::exec::step_guard::record_forced_timeout(module);
                return finish(0);
            }
            // SAFETY: this core's control block; the module is suspended.
            unsafe { (*cb).result = rc as u32 };
            RESUME
        }
        // PendSV: the step guard found the entry past its deadline.
        14 => {
            log::error!("[mpu] module {module} forced out: ran past its step deadline");
            crate::kernel::exec::step_guard::record_forced_timeout(module);
            finish(0)
        }
        // HardFault, MemManage, BusFault, UsageFault (incl. PSPLIM).
        _ => {
            let (cfsr, mmfar) = if chip::ISOLATION_PMSAV8 {
                // SAFETY: fault status registers present on ARMv8-M.
                unsafe {
                    let c = r(reg::CFSR);
                    w(reg::CFSR, c); // write-one-to-clear
                    (c, r(reg::MMFAR))
                }
            } else {
                (0, 0)
            };
            let pc = if in_stack(frame, 32) {
                // SAFETY: inside the module's stack (checked).
                unsafe { core::ptr::read_volatile((frame + 24) as *const u32) }
            } else {
                0
            };
            let what = if cfsr & (1 << 20) != 0 {
                "stack overflow (PSPLIM)"
            } else {
                "protection fault"
            };
            log::error!(
                "[mpu] module {module} {what}: exc={kind} cfsr=0x{cfsr:08x} mmfar=0x{mmfar:08x} pc=0x{pc:08x}"
            );
            crate::kernel::exec::step_guard::record_mpu_fault(module);
            finish(0)
        }
    }
}

/// The first few clean round trips per module, and a periodic one, so a rig
/// sees positive evidence of unprivileged execution.
fn note_clean(module: usize) {
    static COUNT: [AtomicU32; MAX_MODULES] = [const { AtomicU32::new(0) }; MAX_MODULES];
    let n = COUNT[module].fetch_add(1, Ordering::Relaxed);
    if n < 4 || n.is_multiple_of(4096) {
        log::info!("[mpu] module {module} unprivileged step ok step={n}");
    }
}

// ── Assembly: enter, trap, trap-thread ──────────────────────────────
//
// ARMv6-M instructions only, so one copy serves both cores. Offsets are the
// `Cb` layout above.
core::arch::global_asm!(
    ".section .text.fluxor_rp_protection, \"ax\"",
    // fluxor_rp_enter(cb=r0, entry=r1, args=r2, psp=r3, [sp]=ret) -> i32
    //
    // Saves the kernel's callee-saved registers and MSP, builds the module's
    // launch frame on its stack, and issues the launch SVC. Returns — from
    // the trap's return path, onto the frame pushed here — with the outcome.
    ".global fluxor_rp_enter",
    ".thumb_func",
    "fluxor_rp_enter:",
    "push {{r4-r7, lr}}",
    "mov r4, r8",
    "mov r5, r9",
    "mov r6, r10",
    "mov r7, r11",
    "push {{r4-r7}}",
    "ldr r6, [sp, #36]", // ret veneer (fifth argument, above nine pushed words)
    "mov r4, sp",
    "str r4, [r0, #0]", // kernel_msp
    // Arguments five to eight onto the module's stack.
    "subs r3, #16",
    "ldr r4, [r2, #16]",
    "str r4, [r3, #0]",
    "ldr r4, [r2, #20]",
    "str r4, [r3, #4]",
    "ldr r4, [r2, #24]",
    "str r4, [r3, #8]",
    "ldr r4, [r2, #28]",
    "str r4, [r3, #12]",
    // The launch frame below them: r0-r3 = arguments, r12 = 0, lr = the
    // return veneer, pc = the entry (bit 0 clear), xPSR = Thumb.
    "subs r3, #32",
    "ldr r4, [r2, #0]",
    "str r4, [r3, #0]",
    "ldr r4, [r2, #4]",
    "str r4, [r3, #4]",
    "ldr r4, [r2, #8]",
    "str r4, [r3, #8]",
    "ldr r4, [r2, #12]",
    "str r4, [r3, #12]",
    "movs r4, #0",
    "str r4, [r3, #16]",
    "str r6, [r3, #20]",
    "movs r4, #1",
    "bics r1, r4",
    "str r1, [r3, #24]",
    "ldr r4, =0x01000000",
    "str r4, [r3, #28]",
    "msr psp, r3",
    // Nothing of the kernel's reaches the module: its r4-r11 start at zero.
    "movs r4, #0",
    "str r4, [r0, #16]",
    "str r4, [r0, #20]",
    "str r4, [r0, #24]",
    "str r4, [r0, #28]",
    "str r4, [r0, #32]",
    "str r4, [r0, #36]",
    "str r4, [r0, #40]",
    "str r4, [r0, #44]",
    "str r4, [r0, #60]", // pending = 0
    "movs r4, #1",
    "str r4, [r0, #4]", // active = 1
    "svc #0xFF",
    "b .",
    // ---- fluxor_rp_trap: SVCall, PendSV, HardFault, MemManage, BusFault, UsageFault
    ".global fluxor_rp_trap",
    ".thumb_func",
    "fluxor_rp_trap:",
    "mov r0, lr",
    "movs r1, #4",
    "tst r0, r1",
    "beq 9f", // taken on MSP: the kernel's own
    "mrs r1, CONTROL",
    "movs r2, #1",
    "tst r1, r2",
    "beq 9f", // privileged thread on PSP: not a module
    "ldr r2, =0xD0000000",
    "ldr r2, [r2]",
    "movs r1, #1",
    "ands r2, r1",
    "lsls r2, r2, #6",
    "ldr r3, =FLUXOR_RP_GATE_CB",
    "adds r3, r3, r2", // r3 = this core's block
    "ldr r2, [r3, #4]",
    "cmp r2, #0",
    "beq 9f", // no gated entry live
    "str r4, [r3, #16]",
    "str r5, [r3, #20]",
    "str r6, [r3, #24]",
    "str r7, [r3, #28]",
    "mov r4, r8",
    "str r4, [r3, #32]",
    "mov r4, r9",
    "str r4, [r3, #36]",
    "mov r4, r10",
    "str r4, [r3, #40]",
    "mov r4, r11",
    "str r4, [r3, #44]",
    "mrs r2, psp",
    "str r2, [r3, #8]",
    "mrs r2, ipsr",
    "str r2, [r3, #12]",
    // Privileged again (thread mode, on return).
    "movs r2, #0",
    "msr CONTROL, r2",
    "isb",
    // A frame on MSP that returns to thread mode in fluxor_rp_trap_thread(cb).
    "7:",
    "ldr r2, [r3, #0]",
    "subs r2, #32",
    "lsrs r2, r2, #3",
    "lsls r2, r2, #3",
    "mov sp, r2",
    "str r3, [r2, #0]",
    "movs r1, #0",
    "str r1, [r2, #4]",
    "str r1, [r2, #8]",
    "str r1, [r2, #12]",
    "str r1, [r2, #16]",
    "str r1, [r2, #20]",
    "ldr r1, =fluxor_rp_trap_thread",
    "movs r0, #1",
    "bics r1, r0",
    "str r1, [r2, #24]",
    "ldr r1, =0x01000000",
    "str r1, [r2, #28]",
    "ldr r0, =0xFFFFFFF9",
    "bx r0",
    // The kernel's own, on MSP: faults to the report; PendSV and SVC while
    // a gated entry is live are the guard's force-out and the launch/resume
    // SVC; any other SVC or PendSV is ignored.
    "9:",
    "ldr r2, =0xD0000000",
    "ldr r2, [r2]",
    "movs r1, #1",
    "ands r2, r1",
    "lsls r2, r2, #6",
    "ldr r3, =FLUXOR_RP_GATE_CB",
    "adds r3, r3, r2", // r3 = this core's block
    "mrs r0, ipsr",
    "cmp r0, #11",
    "beq 5f",
    "cmp r0, #14",
    "beq 6f",
    "ldr r1, =FaultTrampoline",
    "bx r1",
    // PendSV while the kernel serves a live entry: remembered for the resume.
    "6:",
    "ldr r2, [r3, #4]",
    "cmp r2, #0",
    "beq 8f",
    "movs r2, #1",
    "str r2, [r3, #60]", // pending = 1
    "8:",
    "bx lr",
    // SVC: the launch/resume request, if an entry is live and the immediate
    // is RESUME_SVC (read from the instruction the stacked pc follows).
    "5:",
    "ldr r2, [r3, #4]",
    "cmp r2, #0",
    "beq 8b",
    "mrs r2, msp",
    "ldr r1, [r2, #24]",
    "subs r1, #2",
    "ldrb r1, [r1]",
    "cmp r1, #0xFF",
    "bne 8b",
    "ldr r1, [r3, #60]",
    "cmp r1, #0",
    "bne 4f",
    // Resume: the module's r4-r11, MSP back to the kernel's, thread mode
    // unprivileged, and an exception return onto the frame on PSP.
    "ldr r4, [r3, #16]",
    "ldr r5, [r3, #20]",
    "ldr r6, [r3, #24]",
    "ldr r7, [r3, #28]",
    "ldr r0, [r3, #32]",
    "mov r8, r0",
    "ldr r0, [r3, #36]",
    "mov r9, r0",
    "ldr r0, [r3, #40]",
    "mov r10, r0",
    "ldr r0, [r3, #44]",
    "mov r11, r0",
    "ldr r0, [r3, #0]",
    "msr msp, r0",
    "movs r0, #1",
    "msr CONTROL, r0",
    "isb",
    "ldr r0, =0xFFFFFFFD",
    "bx r0",
    // Forced out before it could resume: served as the PendSV it was.
    "4:",
    "movs r1, #0",
    "str r1, [r3, #60]",
    "movs r1, #14",
    "str r1, [r3, #12]", // kind = PendSV
    "b 7b",
    // ---- fluxor_rp_trap_thread(cb=r0): privileged thread mode on MSP.
    ".global fluxor_rp_trap_thread",
    ".thumb_func",
    "fluxor_rp_trap_thread:",
    "mov r4, r0",
    "bl fluxor_rp_serve",
    "cmp r0, #0",
    "bne 1f",
    // Resume the module at its veneer's `bx lr`: the op's result goes into
    // its frame's r0, and the resume SVC returns onto that frame.
    "ldr r0, [r4, #8]",  // frame
    "ldr r1, [r4, #48]", // result
    "str r1, [r0, #0]",
    "svc #0xFF",
    "b .",
    // The entry is over: back to protected_call with the outcome.
    "1:",
    "ldr r0, [r4, #56]",
    "ldr r1, [r4, #0]",
    "mov sp, r1",
    "pop {{r4-r7}}",
    "mov r8, r4",
    "mov r9, r5",
    "mov r10, r6",
    "mov r11, r7",
    "pop {{r4-r7, pc}}",
    ".ltorg",
);

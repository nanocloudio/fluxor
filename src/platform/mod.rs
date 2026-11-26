//! Platform-runtime modules shared across board entry points.
//!
//! Each board's entry point (`src/platform/<board>.rs`) is included
//! directly by `src/main.rs` via `include!` and owns its own boot
//! sequence. Code that is shared across boards — and belongs in the
//! platform layer, not the kernel — lives here as ordinary modules and
//! is reached from the platform files via `fluxor::platform::...`.

pub mod debug;

// Linux host-platform provider modules (host-process isolation backend, the
// `workload` provider, and the platform providers they compose). Library
// modules (not part of the `fluxor-linux` binary's flat `include!` namespace)
// so the host test harness can reach them. Explicit
// `#[path]` so this resolves to `linux/mod.rs`, never the binary entry point at
// `src/platform/linux.rs`.
#[cfg(feature = "host-linux")]
#[path = "linux/mod.rs"]
pub mod linux;

// Linux external-process executor for external-hosted (OCI-backed) graph nodes.
// Hosted-only: spawns real processes, so it exists only when the platform has
// std.
#[cfg(feature = "host-linux")]
#[path = "linux/proc_executor.rs"]
pub mod proc_executor;

// ── Chip-selected platform backends ──────────────────────────────────────────
//
// The per-chip platform modules, selected by `#[cfg]`. The chip selection lives
// here in the platform layer; the kernel reaches them via `crate::platform::<name>`.

/// The memory map from the device tree: what the boot tables map as DRAM and
/// the zone the kernel's tables and the state arena share (bcm2712).
#[cfg(feature = "chip-bcm2712")]
#[path = "bcm2712/memmap.rs"]
pub mod memmap;
/// Secondary-core bring-up + RP1/DMA40 (bcm2712).
#[cfg(feature = "chip-bcm2712")]
#[path = "bcm2712/multicore.rs"]
pub mod multicore;
/// NIC ring / GEM DMA descriptors (bcm2712 net).
#[cfg(feature = "chip-bcm2712")]
#[path = "bcm2712/net.rs"]
pub mod nic_ring;
/// PCIe1 root-complex bring-up, enumeration and device access (bcm2712).
#[cfg(feature = "chip-bcm2712")]
#[path = "bcm2712/pcie.rs"]
pub mod pcie;
/// PCIe BAR/window alias tables (bcm2712).
#[cfg(feature = "chip-bcm2712")]
#[path = "bcm2712/pcie_aliases.rs"]
pub mod pcie_aliases;

/// Chip backend — the per-target chip services (clocks, arenas, boot glue),
/// selected by `#[cfg]`. Every target has exactly one.
#[cfg(feature = "rp")]
#[path = "rp/chip.rs"]
pub mod chip;
#[cfg(feature = "chip-bcm2712")]
#[path = "bcm2712/chip.rs"]
pub mod chip;
#[cfg(feature = "host-uefi")]
#[path = "uefi/chip.rs"]
pub mod chip;
#[cfg(feature = "host-linux")]
#[path = "linux/chip.rs"]
pub mod chip;
#[cfg(feature = "host-wasm")]
#[path = "wasm/chip.rs"]
pub mod chip;

/// Boot/config planner (rp flash-resident config staging).
#[cfg(feature = "rp")]
#[path = "rp/config.rs"]
pub mod planner;
/// The reset vector and vector table.
#[cfg(feature = "rp")]
#[path = "rp/boot.rs"]
pub mod rp_boot;
/// RP bootrom function lookup. Declared unconditionally so the table-code
/// packing is host-testable; the lookup itself is `rp`-gated.
#[path = "rp/bootrom.rs"]
pub mod rp_bootrom;
/// RP clock measurement (FC0 frequency counter). Declared unconditionally so
/// the result decoding is host-testable; the register reads are `rp`-gated.
#[path = "rp/clocks.rs"]
pub mod rp_clocks;
/// RP2350 core 1 as the core of an execution domain: its launch, its RAM
/// park, its own interrupt lines and timer.
#[cfg(all(feature = "rp", feature = "smp"))]
#[path = "rp/core1.rs"]
pub mod rp_core1;
/// RP cycle and execute-in-place cache counters. Declared unconditionally so
/// the cycle arithmetic is host-testable; the register access is `rp`-gated.
#[path = "rp/counters.rs"]
pub mod rp_counters;
/// RP DMA channel registers. Declared unconditionally so the channel address
/// arithmetic is host-testable; the register reads are `rp`-gated.
#[path = "rp/dma.rs"]
pub mod rp_dma;
/// The RP DMA scan list: its control-block table, arming rules and position
/// accounting. Declared unconditionally so a host test runs it against a
/// model of the channels; the registers are in `rp_providers`.
#[path = "rp/dma_list.rs"]
pub mod rp_dma_list;
/// RP entropy sources and their conditioning. Declared unconditionally so
/// the register offsets and quality grades are host-testable.
#[path = "rp/entropy.rs"]
pub mod rp_entropy;
/// RP flash store + XIP lock. Kernel re-exports `flash_store`/`resource`.
#[cfg(feature = "rp")]
#[path = "rp/flash.rs"]
pub mod rp_flash;
/// RP GPIO registers (IO_BANK0/PADS_BANK0/SIO). Declared unconditionally so
/// the bank-stride arithmetic is host-testable; the writes are `rp`-gated.
#[path = "rp/gpio_regs.rs"]
pub mod rp_gpio_regs;
/// The RP2350 IMAGE_DEF block the bootrom requires. Declared unconditionally
/// so the bitfield packing is host-testable.
#[path = "rp/image_def.rs"]
pub mod rp_image_def;
/// RP GPIO + PIO helpers. Kernel re-exports `gpio`/`pio_util`.
#[cfg(feature = "rp")]
#[path = "rp/io.rs"]
pub mod rp_io;
/// RP2350 OTP seal key: the vault's sealing key, held in an OTP page the
/// bootloader cannot read. Declared unconditionally so the key decision and
/// the row layout are host-testable; the OTP access itself is `rp`-gated.
#[path = "rp/otp_seal.rs"]
pub mod rp_otp_seal;
/// RP PIO registers. Declared unconditionally so the instance and state
/// machine addressing is host-testable; the register access is `rp`-gated.
#[path = "rp/pio_regs.rs"]
pub mod rp_pio_regs;
/// RP module protection: unprivileged gated modules behind the gateway.
#[cfg(all(feature = "rp", feature = "kernel-mpu"))]
#[path = "rp/protection.rs"]
pub mod rp_protection;
/// RP platform provider registrations.
#[cfg(feature = "rp")]
#[path = "rp/providers.rs"]
pub mod rp_providers;
/// RP typed MMIO primitives. Declared unconditionally so the
/// field-encoding arithmetic is host-testable; the volatile accessors are
/// unsafe and address-checked by their callers.
#[path = "rp/regs.rs"]
pub mod rp_regs;
/// What a step on an RP core is charged: deadlines moved past time the
/// kernel held the core, and the allowance for a cache refilled after a
/// flash write. Declared unconditionally so the accounting is host-testable.
#[path = "rp/step_charge.rs"]
pub mod rp_step_charge;
/// RP step-guard (watchdog-backed step budget).
#[cfg(feature = "rp")]
#[path = "rp/step_guard.rs"]
pub mod rp_step_guard;
/// RP 64-bit monotonic time — the single source every `HalOps` time entry
/// reads. Declared unconditionally so the wrap arithmetic is
/// host-testable; the register reads inside are `rp`-gated.
#[path = "rp/timer.rs"]
pub mod rp_timer;
/// RP timer ownership rules, which the build script applies to the silicon
/// TOML. Declared unconditionally so a host test drives the same rules.
#[path = "rp/timer_ledger.rs"]
pub mod rp_timer_ledger;
/// RP fallback UART console — the log path that survives a USB stack that
/// will not enumerate.
#[cfg(feature = "rp")]
#[path = "rp/uart.rs"]
pub mod rp_uart;
/// RP USB device controller bring-up and event drain.
#[cfg(feature = "rp")]
#[path = "rp/usb_device.rs"]
pub mod rp_usb_device;
/// RP USB controller registers and DPRAM allocation. Declared unconditionally
/// so the allocator and word encodings are host-testable.
#[path = "rp/usb_dpram.rs"]
pub mod rp_usb_dpram;
/// RP USB controller events and their interpretation. Declared
/// unconditionally so the bitmap and buffer-direction rules are host-testable.
#[path = "rp/usb_events.rs"]
pub mod rp_usb_events;
/// RP2 USB host-mode DPRAM layout. Declared unconditionally so the layout
/// arithmetic is host-testable; role-exclusive from the device backend.
#[path = "rp/usb_host.rs"]
pub mod rp_usb_host;
/// RP liveness watchdog: a wedged board falls back to BOOTSEL.
#[cfg(feature = "rp")]
#[path = "rp/watchdog.rs"]
pub mod rp_watchdog;

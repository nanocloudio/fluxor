//! Board-local PCIe device aliases for BCM2712 (CM5 / Pi 5).
//!
//! The alias table is the seam between board topology and a stable,
//! user-facing name. Drivers and user YAML configs reference these
//! names (`m2_primary`, `rp1`); the `pcie_device` contract's binder
//! resolves them by matching the expected PCI (bus, dev, func) on a
//! named root complex. Scan order does not affect which device an
//! alias binds — a bridge or a reorder changes the enumeration index
//! but not the BDF.
//!
//! | Alias         | Root  | BDF   | Notes                                   |
//! |---------------|-------|-------|-----------------------------------------|
//! | `m2_primary`  | PCIe1 | 1:0.0 | External x1 slot (NVMe HAT+, M.2 HAT).  |
//! | `rp1`         | PCIe2 | 1:0.0 | Internal x4 link to RP1 (GEM, UART/…). |
//!
//! Only PCIe1 is brought up by the bare-metal kernel; binding to
//! `rp1` returns ENODEV.
//!
//! Current entries name the endpoint directly on bus 1 of each root.
//! A card that interposes a PCIe switch (endpoint appears on bus 2+)
//! needs either an updated BDF or a deeper-walking binder — the
//! alias explicitly fails to bind rather than silently picking
//! whichever device enumerates first.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcieRoot {
    /// External x1 slot (NVMe HAT+).
    Pcie1,
    /// Internal x4 link to RP1.
    Pcie2,
}

pub struct PcieAlias {
    pub name: &'static str,
    pub root: PcieRoot,
    /// Expected PCI (bus, dev, func) of the device on `root`. The
    /// binder scans the enumeration table for a device with this
    /// exact triple; stable across enumeration reorders.
    pub bus:  u8,
    pub dev:  u8,
    pub func: u8,
}

pub const ALIASES: &[PcieAlias] = &[
    PcieAlias { name: "m2_primary", root: PcieRoot::Pcie1, bus: 1, dev: 0, func: 0 },
    PcieAlias { name: "rp1",        root: PcieRoot::Pcie2, bus: 1, dev: 0, func: 0 },
];

/// Look up an alias by name. Case-sensitive — aliases are
/// ASCII-lowercase identifiers.
pub fn resolve(name: &str) -> Option<&'static PcieAlias> {
    ALIASES.iter().find(|a| a.name == name)
}

/// PCI class name → class code (bits 23:0 of the 32-bit class
/// register; low byte is PI, middle byte is subclass, high byte is
/// base class).
///
/// Only well-defined classes we bind drivers to are listed; unknown
/// names return `None` so `@class=…` selectors surface as configuration
/// errors rather than silently matching nothing.
pub fn class_code(name: &str) -> Option<u32> {
    match name {
        "nvme"     => Some(0x01_08_02), // storage / NVM / NVMe
        "ethernet" => Some(0x02_00_00), // network / ethernet
        _ => None,
    }
}

//! PCIe ownership: what a driver must claim before it may touch a device
//!.
//!
//! Pure bookkeeping, with no register access — the config-space and aperture
//! mechanics belong to a platform. What lives here is the part that decides
//! whether a driver is entitled to an address at all, which is the same
//! question on every platform and is easier to get right where it can be
//! tested.

pub mod bar;
pub mod msix;

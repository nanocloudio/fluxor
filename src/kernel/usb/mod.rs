//! The common USB semantic core.
//!
//! One set of rules for descriptors, transfer identity and completion,
//! shared by every controller backend. Backends own register rings, DPRAM
//! and IRQ acknowledgement; nothing above this layer learns whether a
//! transfer used RP2 DPRAM or an xHCI TRB.
//!
//! Everything here is pure logic over owned state, with no register access
//! and no hardware dependency — which is deliberate. The hostile-descriptor
//! and completion-race cases this core exists to survive are the ones that
//! are hardest to provoke on real hardware and easiest to drive from a test.

pub mod cdc;
pub mod cdc_descriptors;
pub mod control;
pub mod descriptor;
pub mod device;
pub mod hid_report;
pub mod identity;
pub mod midi;
pub mod msc_bot;
pub mod recovery;
/// The reset interface picotool drives, and its request codes.
pub mod reset_interface;
pub mod transfer;
pub mod xhci_ring;
pub mod xhci_topology;

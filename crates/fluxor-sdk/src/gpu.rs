//! The GPU device model every backend shares: the program-pack validator,
//! the device, the provider pump, the producer-side client and the
//! deterministic replay backend. One namespace, as the contract is one: the
//! pack validator reads the envelope's target and arithmetic facts, the
//! device reads the pack's bindings, and the pump drives the device.
//! The wire it runs is `fluxor_abi::contracts::gpu`, re-exported here.

pub(crate) use crate::crypto::sha256::{sha256, Sha256};
pub use fluxor_abi::contracts::gpu::*;

mod client;
mod device;
mod pack;
mod pump;
mod replay;

pub use client::*;
pub use device::*;
pub use pack::*;
pub use pump::*;
pub use replay::*;

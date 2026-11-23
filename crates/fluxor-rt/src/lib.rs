//! The module runtime: the syscall wrappers, the state, stack and arena
//! declarations, the params TLV reader, the PIC compiler intrinsics and the
//! panic handler every `.fmod` links. Modules link it; the kernel never
//! does.
//!
//! A module imports it whole (`use fluxor_rt::*;`) and calls its macros by
//! path (`fluxor_rt::define_params!`), which resolves from any module scope.
//!
//! # Safety
//!
//! Every `unsafe fn` here has one contract: `sys` is the syscall table the
//! kernel handed the module, and each pointer is valid for the length
//! passed beside it (for writes, writable for it) for the duration of the
//! call. Nothing is retained past the call unless the function says so.

#![no_std]
#![allow(
    unsafe_code,
    reason = "the runtime is the module side of the syscall table: raw pointers in, raw pointers out"
)]
#![allow(
    clippy::missing_safety_doc,
    reason = "every unsafe fn shares the one contract stated in the crate docs' Safety section"
)]

pub use fluxor_abi as abi;
pub use fluxor_abi::wire::*;
pub(crate) use fluxor_abi::SyscallTable;

/// The digest of the ABI this runtime was compiled against, embedded so
/// `fluxor modules pack` can verify compilation provenance: it reads this
/// value from the ELF and requires it to equal the packer's own surface
/// digest, so a module built against other ABI numbers than the kernel's is
/// refused rather than shipped.
///
/// Every module link names it (`--undefined=FLUXOR_ABI_SURFACE`), which keeps
/// it, and with it this crate's object, past `--gc-sections`; `pack` finds it
/// by name. One definition, as there is one runtime crate however many
/// modules a host binary links.
#[used]
#[no_mangle]
pub static FLUXOR_ABI_SURFACE: [u8; 32] = abi::abi_surface::ABI_SURFACE_DIGEST;

mod bank_stream;
mod block;
mod bridge;
mod consts;
mod device_access;
mod exchange;
mod fmp;
mod format;
mod heap;
mod intrinsics;
mod names;
mod net;
mod params;
mod provider;
mod state;
mod step;
mod storage;
mod telemetry;
mod utf8;
mod wasm;
mod wasm_entry;

pub use block::*;
pub use bridge::*;
pub use consts::*;
pub use device_access::*;
pub use exchange::*;
pub use fmp::*;
pub use format::*;
pub use heap::*;
#[cfg(any(target_os = "none", target_arch = "wasm32"))]
pub use intrinsics::*;
pub use names::*;
pub use net::*;
pub use params::*;
pub use provider::*;
pub use step::StepReturn;
pub use storage::*;
pub use telemetry::*;
pub use utf8::*;
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

/// A datagram endpoint bound by name, over the `datagram` contract.
pub mod datagram_endpoint;

/// The cycle and instruction-cache counters, over the `counters` contract.
pub mod counters;

/// A module's assets: a program read in place or streamed, or a file.
pub mod asset;

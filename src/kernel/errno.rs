//! Centralised POSIX-style error codes for all kernel subsystems.
//!
//! The canonical definitions live in `crate::abi::errno` (part of the stable
//! module ABI). This module re-exports them so kernel code can continue to
//! use `crate::kernel::errno::*` unchanged.

pub use crate::abi::errno::*;

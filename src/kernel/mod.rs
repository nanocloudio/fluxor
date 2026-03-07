//! Kernel syscall surfaces (minimal).

pub mod syscalls;
pub mod channel;
pub mod config;
pub mod scheduler;
pub mod loader;
pub mod net;
pub mod socket;
pub mod buffer_pool;
pub mod errno;
pub mod event;
pub mod resource;
pub mod ringbuf;
pub mod fd;
pub mod provider;
pub mod planner;
pub mod flash_store;
pub mod chip;

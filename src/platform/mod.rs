//! Platform-runtime modules shared across board entry points.
//!
//! Each board's entry point (`src/platform/<board>.rs`) is included
//! directly by `src/main.rs` via `include!` and owns its own boot
//! sequence. Code that is shared across boards — and belongs in the
//! platform layer, not the kernel — lives here as ordinary modules and
//! is reached from the platform files via `fluxor::platform::...`.

pub mod debug;

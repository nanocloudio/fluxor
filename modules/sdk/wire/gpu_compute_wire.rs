#![allow(
    dead_code,
    reason = "shared producer↔consumer↔backend wire contract; not every constant \
              is used by every includer (the consumer uses only the top-level \
              opcodes; producers and the JS backend use the rest)"
)]
//! Generic GPU-compute wire contract — the ONE definition of the
//! `wasm_browser_compute` command-stream opcodes, shared by every producer and
//! the consumer. A producer that emits the stream (an app, or the driver's own
//! demo) includes this file so the opcodes cannot drift from the consumer
//! (`src/platform/wasm/compute.rs`) or the backend (`host_gpu_compute_*` in
//! host_shims.js). The full per-command byte layout is documented on
//! `compute.rs`; this file holds only the numbers both sides must agree on.
//!
//! The values are pinned by `tests/harness/tests/gpu_compute_wire.rs`, which
//! also checks that the JS backend's literals match (JS cannot include this
//! file).

// Top-level command opcodes (u8), on the driver's input channel.
pub const CMD_CREATE_PIPELINE: u8 = 0x01;
pub const CMD_CREATE_BUFFER: u8 = 0x10;
pub const CMD_UPLOAD_BUFFER: u8 = 0x11;
pub const CMD_SUBMIT: u8 = 0x30;
pub const CMD_PRESENT: u8 = 0x40;
pub const CMD_READBACK: u8 = 0x50;

// SUBMIT sub-command opcodes (u8), within the SUBMIT command list.
pub const SUB_DISPATCH: u8 = 0x01;
pub const SUB_COPY: u8 = 0x02;

// CREATE_BUFFER `usage` bitmask (copy-dst is always implied by the backend).
pub const USAGE_STORAGE: u32 = 1 << 0;
pub const USAGE_UNIFORM: u32 = 1 << 1;
pub const USAGE_COPY_SRC: u32 = 1 << 2;
pub const USAGE_MAP_READ: u32 = 1 << 4;

// CREATE_PIPELINE `shader_fmt`. The browser backend consumes WGSL only; a
// native (Vulkan/bare-metal) backend consumes SPIR-V.
pub const SHADER_FMT_WGSL: u32 = 0;
pub const SHADER_FMT_SPIRV: u32 = 1;

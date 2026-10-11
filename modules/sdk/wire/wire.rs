// Wire-format constants — values that appear on disk (module headers,
// channel-hint blobs, packed manifest tables) or are consumed by
// name-hash lookup at boot. The kernel, the module SDK, and the host
// tools all import this file so every consumer agrees on these bytes
// without manual coordination.
//
// Reach paths:
//
//   - `modules/sdk/abi.rs` exposes it as `abi::wire::*` for the kernel
//     and any non-PIC consumer of the SDK facade.
//   - `modules/sdk/runtime.rs` `include!`'s this file so PIC modules
//     see the constants in their top-level namespace.
//   - `tools/src/main.rs` and `tools/src/lib.rs` `#[path]`-mount this
//     file as `crate::wire` for the host tools.

/// ABI version byte stamped into every module header. The kernel's
/// loader rejects modules whose `header.abi_version` doesn't match
/// this exact value — there is no backwards-compatibility layer.
pub const ABI_VERSION: u8 = 1;

/// Bytes per port-capacity entry in the manifest's flag-bit-5
/// capacity section: `[buffer_size u32 LE][max_record u32 LE]`.
pub const CHANNEL_HINT_WIRE_BYTES: usize = 8;

/// Runtime bits in a module manifest's `hardware_targets` mask (manifest
/// bytes 10..12, u16 LE): the runtimes a module may run under. A loader
/// refuses a module whose mask lacks its own runtime's bit. The tools'
/// runtime table (`tools/src/runtime_abi.rs`) names these same values.
pub mod runtime_bit {
    pub const RP2350: u16 = 0x01;
    pub const RP2040: u16 = 0x02;
    pub const BCM2712: u16 = 0x04;
    pub const WASM: u16 = 0x08;
    pub const LINUX: u16 = 0x10;
    pub const MACOS: u16 = 0x20;
    pub const WINDOWS: u16 = 0x40;
    pub const ESP32: u16 = 0x80;
}

/// FNV-1a 32-bit hash. Identifies modules and exports by name (string
/// → u32 lookup key) at both runtime and compile time. `const fn` so
/// module-name hash constants can be evaluated at build time without
/// a build script.
pub const fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

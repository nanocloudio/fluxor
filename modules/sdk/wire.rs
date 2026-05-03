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

/// Wire size of one `ChannelHint` slot serialised by
/// `write_channel_hints` and decoded by the kernel's
/// `query_channel_hints`. The in-memory `ChannelHint` struct's
/// natural `#[repr(C)]` alignment matches this size.
pub const CHANNEL_HINT_WIRE_BYTES: usize = 8;

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

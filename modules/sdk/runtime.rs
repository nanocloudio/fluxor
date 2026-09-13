// Shared PIC module runtime support.
//
// Provides compiler runtime intrinsics and helper functions required by all
// PIC modules. Each module includes this via `include!("../../sdk/runtime.rs")`.
//
// Compiler Intrinsics: ARM EABI memclr/memcpy for struct init/assignment.
// Param Helpers: Safe(r) little-endian reads from a raw params pointer.

// The digest of the SDK this module is compiled against, embedded so
// `fluxor modules pack` can verify compilation provenance: it reads this value from
// the ELF and requires it to equal the packer's own surface digest before
// packaging, so a module whose hardcoded ABI numbers do not match the
// current kernel is rejected rather than shipped.
//
// `#[used]` keeps it past dead-code elimination; it lands in `.rodata`
// (captured by every module linker script) and `pack` locates it by symbol
// name. The symbol is left mangled (no `#[no_mangle]`): the host test
// harness links several module crates into one binary, where a fixed global
// symbol would collide, so `pack` matches the mangled name by substring.
#[used]
pub static FLUXOR_ABI_SURFACE: [u8; 32] = abi::abi_surface::ABI_SURFACE_DIGEST;

// Wire-format constants (ABI_VERSION, CHANNEL_HINT_WIRE_BYTES,
// fnv1a32). Brought into the PIC module's top-level namespace; the
// kernel reaches the same values via `abi::wire::*`.
include!("wire/wire.rs");

// ── Runtime split into responsibility files (F8) ──
include!("runtime/intrinsics.rs");
include!("runtime/consts.rs");
include!("runtime/format.rs");
include!("runtime/wasm.rs");
include!("runtime/provider.rs");
include!("runtime/net.rs");
include!("runtime/telemetry.rs");
include!("runtime/device_access.rs");
include!("runtime/storage.rs");
include!("runtime/fmp.rs");
include!("runtime/heap.rs");
include!("runtime/bridge.rs");

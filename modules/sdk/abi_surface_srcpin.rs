// GENERATED CONSTANT — regenerate with `fluxor abi-regen`, do not
// hand-edit the value.
//
// sha256 over the canonicalized source of ALL `modules/sdk/**/*.rs`
// except this generated file (sorted relative paths; per file:
// `path \0 canonical-content \0`). Canonicalization is token-based
// (`tools/src/hash.rs::canonicalize_source`): comments, doc comments,
// and formatting are digest-neutral, while every identifier, literal,
// and real attribute is significant. The relative path is folded in,
// so a file rename DOES move the digest.
//
// This folds the contract and platform layers — opcode name-hashes,
// wire structs, request/response layouts — into the ABI-surface digest
// without hand-enumerating thousands of constants, and without a
// build.rs in every consumer: the const is checked in, and
// `tools/src/hash.rs::contracts_platform_srcpin_is_current` recomputes
// it from the sources and fails (printing the replacement) when it
// drifts. Deliberately over-sensitive: a pure refactor of a contract
// file changes the digest and forces a rebuild/restage — the safe
// direction.
pub const CONTRACTS_PLATFORM_SRC_HASH: [u8; 32] = [
    0xfb, 0xe9, 0x44, 0xee, 0x45, 0x0d, 0x86, 0x37, 0xd1, 0x0a, 0xbe, 0x7d, 0xca, 0xa5, 0x2c, 0xd3,
    0x4a, 0xbd, 0x0a, 0x10, 0xe2, 0x80, 0x76, 0x43, 0x36, 0x4e, 0x52, 0x3b, 0x21, 0x67, 0x3f, 0x0a,
];

/// The full ABI-surface digest (sha256 of the canonical surface stream:
/// numeric walk ‖ srcpin ‖ semantic epoch). GENERATED — regenerate via the
/// drift test alongside CONTRACTS_PLATFORM_SRC_HASH. Excluded from the
/// srcpin walk (this file is), so it is not self-referential.
///
/// This is the value the SDK embeds into every compiled module
/// (`runtime.rs` `FLUXOR_ABI_SURFACE`), so packing can verify the module
/// was COMPILED against this surface rather than merely stamped by a
/// current packer — the compile-provenance guarantee.
pub const ABI_SURFACE_DIGEST: [u8; 32] = [
    0xee, 0x4a, 0x2c, 0xed, 0xad, 0x82, 0xe5, 0x85, 0xa3, 0x36, 0xd8, 0xf7, 0x3d, 0x58, 0x60, 0xeb,
    0xf5, 0x10, 0x87, 0xff, 0xbe, 0x3e, 0xcd, 0xab, 0x66, 0x12, 0x4a, 0x73, 0x16, 0xe4, 0x64, 0xb9,
];

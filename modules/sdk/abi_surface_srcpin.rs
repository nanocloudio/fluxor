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
    0xa6, 0x7a, 0x68, 0x72, 0xe2, 0xd0, 0x4a, 0x4c, 0x04, 0x56, 0x9c, 0x48, 0xc6, 0x4c, 0x69,
    0xd0, 0x04, 0x4f, 0x38, 0x1e, 0x2a, 0x72, 0x10, 0x89, 0x6e, 0x93, 0x2f, 0x83, 0x76, 0xbc,
    0x87, 0xa9,
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
    0x77, 0x3b, 0x6d, 0x61, 0xbd, 0xa5, 0xc8, 0x25, 0xb7, 0xad, 0xc8, 0xf6, 0x58, 0x4e, 0xd3,
    0xe0, 0x99, 0x12, 0x9a, 0xd1, 0xa2, 0x26, 0x6b, 0xfc, 0x91, 0xf9, 0xc9, 0x4c, 0x3a, 0xfc,
    0x29, 0x8e,
];

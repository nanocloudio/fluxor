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
    0x87, 0xa8, 0x65, 0x20, 0xd8, 0xc6, 0xd8, 0x95, 0x97, 0xa5, 0x85, 0x5d, 0xdb, 0xf6, 0xbe, 0x22,
    0xfb, 0x89, 0xe7, 0x85, 0x5d, 0x42, 0x6b, 0xb3, 0x8f, 0xac, 0x71, 0xe1, 0xa6, 0x50, 0x09, 0xb6,
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
    0x45, 0xae, 0x7c, 0x0b, 0x66, 0x51, 0x4f, 0x07, 0x3c, 0xa6, 0xce, 0xf6, 0x10, 0xeb, 0xe0, 0x50,
    0x74, 0x73, 0x56, 0x20, 0xdd, 0xe2, 0xab, 0x31, 0x53, 0xeb, 0x29, 0x46, 0x7c, 0x4d, 0x67, 0xfa,
];

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
    0x89, 0x9b, 0xd3, 0x8d, 0x69, 0x75, 0x28, 0x6e, 0xfa, 0x40, 0xdb, 0xc3, 0x6b, 0xe0, 0x23, 0x58,
    0xb3, 0x0c, 0x38, 0x5a, 0xc7, 0xc3, 0xc8, 0x85, 0x44, 0xe3, 0x86, 0xa7, 0xaa, 0x55, 0x2d, 0xfc,
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
    0x54, 0x82, 0x6d, 0x32, 0x53, 0x7a, 0xfa, 0xa3, 0x2b, 0x8e, 0xf2, 0xbe, 0xf9, 0xb2, 0xe8, 0xa6,
    0x35, 0x65, 0xda, 0x32, 0xd6, 0xbb, 0xa5, 0xc0, 0x83, 0x22, 0xd2, 0xf5, 0x36, 0x7a, 0x88, 0x69,
];

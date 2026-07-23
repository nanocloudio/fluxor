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
    0x67, 0x3c, 0xc3, 0x32, 0x2d, 0x2c, 0xff, 0x85, 0x6d, 0xe0, 0x12, 0x3d, 0x4d, 0x32, 0x6f,
    0xb5, 0xa0, 0xca, 0x76, 0xbb, 0x01, 0x0c, 0x05, 0x3c, 0x74, 0x5c, 0xc5, 0x8f, 0x4e, 0x5e,
    0xc6, 0x82,
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
    0x2d, 0x3f, 0xf4, 0x17, 0x6b, 0x2d, 0x22, 0x27, 0x12, 0x4b, 0x90, 0x02, 0xdc, 0x74, 0x09,
    0x3b, 0x10, 0xcf, 0xf7, 0xe2, 0x73, 0x3a, 0x0d, 0x19, 0xd9, 0x97, 0x52, 0x75, 0xb9, 0xa3,
    0x4b, 0xde,
];

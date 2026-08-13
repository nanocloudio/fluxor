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
    0xe1, 0xf3, 0x6d, 0x15, 0xb3, 0x76, 0xc4, 0x62, 0xeb, 0x78, 0x25, 0x0f, 0xaf, 0xc0, 0x17,
    0xf9, 0x83, 0x69, 0x2b, 0x42, 0x82, 0x8e, 0xcc, 0xa2, 0x71, 0x3d, 0xca, 0xa5, 0x06, 0x34,
    0x08, 0xad,
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
    0x49, 0x03, 0x55, 0x93, 0xa9, 0x12, 0xfc, 0xd9, 0x06, 0x96, 0x3c, 0xa6, 0x53, 0x41, 0x57,
    0x8d, 0xb2, 0x63, 0xf0, 0x67, 0x84, 0xf2, 0x49, 0x0c, 0x8e, 0xd3, 0x89, 0xc7, 0x49, 0x8f,
    0x90, 0xe3,
];

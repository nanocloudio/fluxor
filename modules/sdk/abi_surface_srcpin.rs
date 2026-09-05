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
    0x56, 0x43, 0x14, 0xd1, 0xb4, 0xe0, 0x62, 0x98, 0x57, 0x3c, 0x97, 0xdd, 0x4f, 0xc1, 0x82,
    0x61, 0xc6, 0xce, 0xc2, 0x1e, 0xcb, 0x25, 0xc7, 0xce, 0x88, 0x90, 0xc2, 0xa1, 0xe0, 0x45,
    0xf9, 0x1b,
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
    0xc9, 0xa3, 0x0d, 0xf6, 0x85, 0xcb, 0x83, 0x69, 0x69, 0x4c, 0xfc, 0xc7, 0xeb, 0x6a, 0x21,
    0xf1, 0xe3, 0xfa, 0x58, 0x04, 0x82, 0x84, 0x21, 0x4b, 0xc5, 0x31, 0xfc, 0xe5, 0x82, 0x74,
    0x82, 0xfc,
];

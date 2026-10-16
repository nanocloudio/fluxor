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
    0x65, 0x5b, 0xd1, 0x98, 0x98, 0xc6, 0xf5, 0xf3, 0x3a, 0x3c, 0x42, 0x1a, 0x3d, 0x56, 0xac, 0xaf,
    0x7e, 0x88, 0x07, 0xc3, 0xe8, 0x62, 0xb1, 0xfc, 0xa3, 0x5a, 0xd7, 0x51, 0x39, 0x22, 0x21, 0xd1,
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
    0x06, 0x90, 0xc0, 0xd6, 0xca, 0x0b, 0x0a, 0x6d, 0x0b, 0x36, 0xea, 0x6b, 0x2b, 0xdd, 0xa7, 0x7a,
    0x62, 0xbe, 0x9b, 0xeb, 0x38, 0xa7, 0xad, 0x68, 0x7f, 0x32, 0x39, 0x88, 0x2f, 0xea, 0xcf, 0x26,
];

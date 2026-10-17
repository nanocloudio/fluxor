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
    0xf4, 0x13, 0xf0, 0x34, 0xea, 0xbe, 0xdd, 0xc1, 0x77, 0x41, 0x08, 0xfc, 0x39, 0x54, 0x5b, 0x14,
    0x35, 0x03, 0xd1, 0xd2, 0x8e, 0xeb, 0x79, 0x08, 0xe8, 0xf2, 0xa3, 0x89, 0xc2, 0x65, 0x10, 0x7f,
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
    0xed, 0x1c, 0xc7, 0x18, 0x77, 0xdd, 0xf2, 0xe0, 0x2f, 0xe4, 0xa0, 0x49, 0x2c, 0xea, 0x06, 0xa9,
    0xfe, 0x88, 0x1a, 0xd8, 0xbe, 0x71, 0x24, 0x7b, 0xa2, 0xf9, 0x2c, 0x09, 0x4f, 0xcc, 0xb1, 0x32,
];

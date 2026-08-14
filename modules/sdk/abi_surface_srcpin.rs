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
    0x32, 0x12, 0xb0, 0x3b, 0x56, 0x82, 0xad, 0x21, 0x82, 0xe4, 0x26, 0x10, 0x84, 0x08, 0x66,
    0x15, 0x0d, 0x27, 0xe0, 0x31, 0x45, 0xd8, 0xd8, 0x39, 0x3f, 0x3b, 0xf4, 0x59, 0x2e, 0x41,
    0xa0, 0x50,
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
    0x5b, 0xef, 0xd3, 0x63, 0x2c, 0x01, 0x56, 0xd1, 0x2a, 0x6b, 0x7e, 0x08, 0xc4, 0xee, 0xd4,
    0x34, 0xfc, 0xb0, 0xeb, 0x26, 0x14, 0x4a, 0xae, 0xbc, 0xe1, 0x86, 0xa4, 0x35, 0x15, 0x7b,
    0x80, 0x81,
];

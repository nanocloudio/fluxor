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
    0xa4, 0x19, 0xb9, 0x30, 0x24, 0x1a, 0x93, 0x86, 0xcc, 0x52, 0x35, 0x5d, 0xfa, 0x3e, 0xab,
    0x51, 0xa2, 0x7d, 0x30, 0x84, 0x08, 0x99, 0x1a, 0xd8, 0xff, 0x62, 0x92, 0x3b, 0x2a, 0x57,
    0x3a, 0x42,
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
    0x7d, 0x3a, 0xe2, 0xa1, 0x20, 0xab, 0xa2, 0x9b, 0x57, 0x45, 0xb5, 0xc5, 0xd3, 0x5b, 0x2c,
    0x47, 0x99, 0xd6, 0xad, 0xd6, 0xee, 0x8d, 0x80, 0x43, 0x2c, 0x77, 0xaa, 0xfb, 0x48, 0x74,
    0x69, 0x58,
];

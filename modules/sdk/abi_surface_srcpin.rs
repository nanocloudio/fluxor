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
    0xee, 0x7c, 0x34, 0x4b, 0x7b, 0xcf, 0x0e, 0xab, 0x46, 0x61, 0xb8, 0x8b, 0x6f, 0x7e, 0xd0,
    0x76, 0x52, 0xf5, 0x2b, 0xeb, 0x0f, 0x9a, 0x82, 0x66, 0x55, 0xa0, 0x3a, 0x65, 0x81, 0x4e,
    0x4d, 0x74,
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
    0x18, 0xd2, 0xa8, 0x02, 0x14, 0xae, 0x62, 0x93, 0x81, 0x05, 0x08, 0x62, 0x67, 0xf0, 0xf7,
    0xa4, 0x60, 0xd9, 0x66, 0xe6, 0x98, 0x88, 0x6c, 0x38, 0xc1, 0x94, 0xa9, 0x5d, 0xdd, 0x1b,
    0x20, 0x66,
];

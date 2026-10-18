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
    0x98, 0x33, 0x6f, 0x22, 0x9e, 0x89, 0x63, 0x30, 0xd8, 0x26, 0x69, 0x08, 0x0b, 0x07, 0x21, 0x7f,
    0xa0, 0x6d, 0xea, 0xdf, 0x67, 0x59, 0xa1, 0x37, 0x53, 0x86, 0xff, 0x9f, 0xcd, 0x57, 0x9d, 0x30,
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
    0x86, 0x54, 0xe1, 0x56, 0x92, 0x5b, 0x1a, 0x63, 0xac, 0xe2, 0x51, 0x12, 0x9b, 0x51, 0x3a, 0xb8,
    0x61, 0xd6, 0xf8, 0xc7, 0xb2, 0xf8, 0x80, 0x3f, 0xd9, 0xdf, 0x7c, 0x9d, 0x6c, 0x49, 0xff, 0x73,
];

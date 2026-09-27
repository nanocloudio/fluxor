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
    0x4a, 0x39, 0xfc, 0xd4, 0x5d, 0xae, 0x63, 0xf5, 0xc5, 0xd7, 0x5d, 0x75, 0x1a, 0x6e, 0xf4, 0x4e,
    0x11, 0x05, 0xb9, 0xf8, 0x2e, 0xb2, 0xae, 0x33, 0xbd, 0xa1, 0x80, 0x69, 0x2a, 0x25, 0x93, 0x2b,
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
    0x36, 0x4b, 0xf0, 0x65, 0x9e, 0xd0, 0x2b, 0xce, 0xfe, 0x18, 0x93, 0x6d, 0x34, 0xcf, 0x90, 0x73,
    0x01, 0x97, 0xab, 0x07, 0xb7, 0x58, 0x71, 0x1e, 0xe2, 0x19, 0x38, 0x8a, 0x0a, 0x34, 0x9d, 0xc0,
];

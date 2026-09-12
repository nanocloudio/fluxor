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
    0x08, 0xf3, 0x84, 0x9f, 0x9f, 0xd7, 0x22, 0x23, 0x0d, 0x0a, 0x77, 0xfb, 0xf6, 0xe1, 0x19,
    0xd1, 0x47, 0x2c, 0xeb, 0x8b, 0xdb, 0xc8, 0xa6, 0xa0, 0xae, 0x4a, 0x29, 0x70, 0x72, 0x06,
    0x0e, 0x91,
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
    0x06, 0x34, 0x26, 0x4a, 0x5e, 0x54, 0x3a, 0xe8, 0x57, 0x56, 0x24, 0x06, 0x13, 0xeb, 0xbe,
    0x9c, 0x59, 0xe5, 0xd8, 0x5b, 0xa3, 0x49, 0x93, 0x94, 0xbf, 0xc8, 0xf5, 0x5f, 0x68, 0xc1,
    0x0c, 0x10,
];

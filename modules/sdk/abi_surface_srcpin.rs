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
    0x98, 0xd8, 0xbb, 0xf0, 0x40, 0xcb, 0x1e, 0x79, 0x86, 0x96, 0xde, 0x22, 0xcd, 0xb2, 0x13,
    0xe1, 0x72, 0x42, 0xb0, 0x07, 0x62, 0xe5, 0x9e, 0x4e, 0x75, 0xad, 0x33, 0xd2, 0xc3, 0xee,
    0xa8, 0xe6,
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
    0x57, 0xc0, 0xce, 0xa8, 0x97, 0xe5, 0x3d, 0x70, 0x01, 0x89, 0x50, 0x56, 0x25, 0xfc, 0x11,
    0x39, 0x6a, 0x3b, 0x80, 0xec, 0x04, 0xe4, 0x35, 0x6d, 0xa4, 0xa5, 0xab, 0x9e, 0xae, 0x89,
    0xe0, 0x30,
];

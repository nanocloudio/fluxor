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
    0x44, 0x37, 0x82, 0x25, 0x98, 0x5d, 0x99, 0x2d, 0x1b, 0xd0, 0x36, 0xfb, 0xfe, 0x6c, 0x20,
    0xf6, 0x1f, 0x08, 0x23, 0x02, 0x19, 0x06, 0xd2, 0xcc, 0xbf, 0xa6, 0xef, 0xbb, 0x22, 0x9e,
    0x31, 0x19,
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
    0xbe, 0x14, 0xa6, 0x2d, 0x15, 0xd0, 0x66, 0x73, 0xbf, 0x9c, 0x91, 0x80, 0xf6, 0xe9, 0xd6,
    0x74, 0xe7, 0x07, 0x13, 0x55, 0x15, 0x92, 0x47, 0xe5, 0x60, 0xc6, 0x30, 0x9a, 0x29, 0x62,
    0x90, 0x74,
];

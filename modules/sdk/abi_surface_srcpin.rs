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
    0x3a, 0x27, 0xb3, 0x62, 0xe6, 0xd6, 0x21, 0xbb, 0x98, 0x1d, 0xf1, 0x87, 0x33, 0x37, 0xe8, 0xba,
    0x17, 0xc0, 0x77, 0xa2, 0x51, 0x02, 0xf5, 0x82, 0x29, 0x99, 0x1d, 0x7f, 0x0c, 0x70, 0xaf, 0x6b,
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
    0x80, 0xe3, 0xe4, 0xcb, 0xb5, 0x86, 0x8f, 0x90, 0x72, 0xbe, 0x05, 0x78, 0x12, 0x53, 0xe4, 0x3f,
    0xfa, 0xfa, 0x26, 0xc9, 0xa7, 0x71, 0xba, 0x8f, 0x4b, 0x9b, 0xf0, 0xe1, 0xee, 0xc5, 0x89, 0x35,
];

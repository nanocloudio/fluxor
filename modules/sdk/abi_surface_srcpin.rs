// GENERATED CONSTANT — regenerate via the drift test, do not hand-edit
// the value.
//
// sha256 over the canonicalized source of ALL `modules/sdk/**/*.rs`
// except this generated file (sorted relative paths; per file:
// `path \0 canonical-content \0`). Canonicalization drops blank lines and
// whole-line `//` comments and trims trailing whitespace — so `///` doc
// churn is digest-neutral. It does NOT strip block comments, inline
// comments, or indentation, and it includes the path: a rename, reformat,
// or inline comment DOES move the digest (over-sensitive by design).
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
    0xba, 0x18, 0x9c, 0xb5, 0x50, 0x0b, 0x1f, 0x10, 0x0b, 0xa2, 0xfa, 0x0d, 0x8a, 0x1e, 0xb4,
    0x1e, 0xc9, 0x97, 0x0e, 0x33, 0x0d, 0xca, 0x46, 0x96, 0x28, 0xaf, 0x8a, 0x3e, 0x21, 0x8b,
    0x4b, 0xa4,
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
    0x7d, 0xd8, 0xfe, 0x54, 0x2b, 0x62, 0x70, 0x5a, 0x92, 0x64, 0xc7, 0x52, 0x11, 0x6a, 0x60,
    0x5a, 0x7d, 0x53, 0xd2, 0x8b, 0x76, 0xe6, 0x50, 0x29, 0xe3, 0x71, 0x11, 0xf1, 0xbe, 0x96,
    0xbb, 0x74,
];

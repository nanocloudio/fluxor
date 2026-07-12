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
    0xf2, 0x3b, 0xad, 0x6c, 0x29, 0x32, 0x25, 0x15, 0x3e, 0xce, 0xef, 0x6a, 0x8f, 0x17, 0xe6,
    0xf3, 0x1f, 0x8f, 0x5d, 0x60, 0x1e, 0x7a, 0xda, 0x5e, 0x8e, 0x52, 0x29, 0xf8, 0x74, 0xf5,
    0x6f, 0xc3,
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
    0xdf, 0x05, 0x32, 0x0c, 0xf0, 0xa9, 0xb3, 0x9d, 0x62, 0x55, 0xcd, 0x9f, 0xb2, 0xba, 0x06,
    0x69, 0xfc, 0xd7, 0x28, 0xfa, 0xb5, 0xe0, 0x5f, 0x30, 0x84, 0x27, 0xe5, 0xd0, 0x94, 0xfa,
    0x7b, 0xf6,
];

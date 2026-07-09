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
    0x24, 0xa5, 0x58, 0x56, 0x89, 0x4a, 0xb5, 0xe2, 0xf1, 0x81, 0x62, 0x40, 0x08, 0x3c, 0x51,
    0x02, 0x50, 0xeb, 0x01, 0x26, 0xfd, 0x2f, 0xcf, 0x1c, 0x5a, 0xa5, 0x2d, 0x2f, 0xb2, 0x51,
    0x72, 0x22,
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
    0x45, 0xb2, 0x0b, 0x27, 0x93, 0xa1, 0x0c, 0x1a, 0xbd, 0x3e, 0x30, 0xc0, 0x69, 0xbd, 0x0a,
    0xd7, 0x3a, 0x07, 0x33, 0x04, 0xc4, 0xad, 0xc5, 0x64, 0x15, 0xe1, 0x5a, 0x4d, 0x59, 0x1f,
    0x18, 0x74,
];

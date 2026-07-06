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
    0x93, 0xf5, 0x2e, 0x25, 0x95, 0x0a, 0xbb, 0x89, 0xd3, 0x55, 0xc2, 0x35, 0x2e, 0x1c, 0x8d,
    0x46, 0x1e, 0x80, 0x29, 0x31, 0x72, 0x0e, 0xd2, 0x92, 0x1d, 0x73, 0x42, 0x5a, 0x96, 0x6e,
    0xf0, 0x44,
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
    0x78, 0xbe, 0x30, 0xdd, 0xe4, 0x53, 0xbb, 0x6f, 0x9e, 0x77, 0x85, 0x6a, 0x8f, 0x40, 0x75,
    0x39, 0xb7, 0x98, 0x4d, 0x1d, 0x54, 0xa2, 0xdc, 0x96, 0x5d, 0xea, 0x68, 0x07, 0x0f, 0xbe,
    0x70, 0xc6,
];

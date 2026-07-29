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
    0xb4, 0x25, 0xed, 0x47, 0xe4, 0x81, 0x95, 0x57, 0xbc, 0x62, 0xff, 0xc7, 0x12, 0xfd, 0x35,
    0x9e, 0x66, 0x46, 0xf1, 0x50, 0xf4, 0x3d, 0x9b, 0xba, 0x04, 0x66, 0x36, 0x65, 0x59, 0x25,
    0x94, 0x8b,
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
    0x4a, 0x0d, 0x44, 0xf8, 0x21, 0x78, 0x5d, 0xdc, 0x03, 0x9f, 0x6a, 0x42, 0x4c, 0x02, 0xa9,
    0x75, 0x76, 0x69, 0x70, 0x96, 0x46, 0xa1, 0x87, 0x0f, 0xb9, 0x8e, 0x5e, 0xa7, 0xca, 0x03,
    0x82, 0x7b,
];

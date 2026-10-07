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
    0x46, 0x84, 0x15, 0x02, 0xd1, 0x76, 0x90, 0x75, 0xad, 0x53, 0x62, 0xad, 0xe3, 0x2c, 0x2d, 0xc0,
    0xe1, 0xee, 0x3d, 0x51, 0x2b, 0xee, 0x9f, 0x15, 0x26, 0xb6, 0x49, 0xd6, 0xd2, 0x36, 0xb1, 0x44,
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
    0xd7, 0x60, 0xd4, 0x30, 0x49, 0x5c, 0xb0, 0x49, 0x85, 0x1f, 0x3c, 0x80, 0x81, 0x3b, 0x63, 0x10,
    0x80, 0xea, 0x52, 0xab, 0x65, 0x8f, 0x44, 0xfd, 0xaa, 0xd4, 0xc3, 0xbe, 0xb6, 0x99, 0xc6, 0x1b,
];

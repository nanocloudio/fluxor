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
    0x53, 0x7b, 0x4c, 0x1d, 0x68, 0xdc, 0x80, 0x0f, 0xa5, 0x08, 0xe3, 0x24, 0x84, 0xf3, 0xea, 0x04,
    0xa0, 0xf5, 0x28, 0xf5, 0x86, 0xd9, 0x93, 0x62, 0x0b, 0x40, 0xef, 0x1c, 0x54, 0xd8, 0x08, 0x59,
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
    0x8c, 0x44, 0x10, 0x0d, 0x2d, 0xab, 0x32, 0x7e, 0x55, 0xdd, 0x8e, 0x69, 0xc1, 0x4c, 0x60, 0xd5,
    0x4c, 0xab, 0x30, 0xa5, 0xa8, 0x3d, 0xc8, 0xf9, 0x0a, 0x81, 0x02, 0x13, 0x10, 0x94, 0x25, 0x58,
];

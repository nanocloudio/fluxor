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
    0x2c, 0xcc, 0xeb, 0xd0, 0xb3, 0x77, 0xb9, 0x6e, 0x55, 0x8f, 0xa5, 0x03, 0xf9, 0x11, 0x91,
    0xd5, 0x30, 0xff, 0xc2, 0xd3, 0x24, 0xf7, 0x91, 0x7a, 0x82, 0xb4, 0x54, 0x41, 0x4b, 0x52,
    0x79, 0x6d,
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
    0x2b, 0xf7, 0x2c, 0xda, 0xab, 0x45, 0xd5, 0x57, 0x50, 0x15, 0x5a, 0x46, 0x93, 0xab, 0xf9,
    0x24, 0xb5, 0x49, 0xf5, 0xb3, 0x9b, 0xd5, 0xc3, 0xa5, 0x3a, 0x70, 0x8f, 0x96, 0x0a, 0x35,
    0x74, 0xf8,
];

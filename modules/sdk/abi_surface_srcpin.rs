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
    0x4d, 0x1c, 0x8b, 0x7f, 0x71, 0xc1, 0xd2, 0x06, 0x11, 0xed, 0x9c, 0x5d, 0xf0, 0x55, 0xbf,
    0x5d, 0x04, 0x05, 0x79, 0x06, 0x6f, 0x36, 0xfa, 0x6b, 0xfc, 0xa5, 0x98, 0x15, 0x59, 0xba,
    0x0d, 0x3d,
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
    0x60, 0x6a, 0xd1, 0x7a, 0x39, 0xc8, 0x65, 0x1c, 0x31, 0x74, 0x03, 0x9f, 0xb1, 0xa4, 0x07,
    0x49, 0xa5, 0x0f, 0x81, 0x14, 0x11, 0x5e, 0xce, 0x77, 0x8f, 0x21, 0xd0, 0x1c, 0x52, 0x23,
    0xb9, 0x90,
];

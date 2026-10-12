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
    0xa4, 0xd5, 0xd9, 0xe3, 0x1a, 0x13, 0x56, 0x5f, 0xeb, 0x51, 0x91, 0xea, 0xca, 0x2f, 0xb5, 0x3b,
    0xda, 0xd4, 0x45, 0x0e, 0x25, 0xd1, 0x46, 0x43, 0x6d, 0x39, 0x9e, 0x2b, 0x6d, 0x08, 0x6b, 0xa1,
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
    0x09, 0x52, 0x3e, 0x28, 0x81, 0x52, 0xb5, 0x8d, 0x0b, 0xdd, 0x66, 0xcd, 0xda, 0xac, 0x5d, 0xe3,
    0xcb, 0x1c, 0x2f, 0xff, 0x27, 0xd9, 0x75, 0xee, 0x55, 0xa1, 0x18, 0x46, 0x33, 0xeb, 0x85, 0xa1,
];

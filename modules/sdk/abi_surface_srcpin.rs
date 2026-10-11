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
    0x23, 0xef, 0x8c, 0x39, 0xee, 0x51, 0x19, 0xc7, 0x73, 0x22, 0xa3, 0x77, 0x53, 0x74, 0x31, 0x5e,
    0x27, 0x15, 0x91, 0x2a, 0x9b, 0x74, 0x37, 0x47, 0xca, 0x42, 0x82, 0xf4, 0x8e, 0x6d, 0x00, 0x37,
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
    0x9c, 0xcc, 0x63, 0x79, 0x8e, 0x14, 0xe8, 0x70, 0x3c, 0xc5, 0x2a, 0x72, 0x01, 0x08, 0x5e, 0xa6,
    0x06, 0xee, 0xc0, 0x25, 0x51, 0xea, 0x3f, 0x69, 0x19, 0x9d, 0x21, 0x06, 0x56, 0x62, 0xba, 0xfe,
];

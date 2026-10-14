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
    0xab, 0xae, 0xe2, 0x84, 0x51, 0x3b, 0x4d, 0x82, 0xfc, 0xa9, 0x62, 0x18, 0x8d, 0xba, 0xd3, 0x1c,
    0x09, 0xd1, 0xcf, 0x4c, 0xcc, 0xb7, 0x94, 0x02, 0x09, 0x49, 0x5d, 0xeb, 0x13, 0x2f, 0x99, 0x25,
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
    0x3b, 0x9d, 0x95, 0x6d, 0xf3, 0xaa, 0x0e, 0x15, 0xfe, 0x17, 0x5a, 0x99, 0x74, 0x4f, 0x41, 0x81,
    0x91, 0xe4, 0x8d, 0x60, 0xad, 0x89, 0xa9, 0xe7, 0xa7, 0x63, 0x00, 0x8a, 0xce, 0x39, 0x15, 0x01,
];

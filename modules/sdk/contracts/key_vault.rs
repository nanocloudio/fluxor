// Contract: key_vault — kernel-managed asymmetric keys (ECDSA / ECDH / verify).
//
// Layer: contracts (public, stable).
//
// All operations run in kernel context; private key material never
// leaves the kernel static slot table. Callers see opaque `i32`
// handles. Arg buffers use little-endian tightly-packed layouts;
// fields starting with `*_out` are written back by the kernel.

/// Returns 1 if a key-vault backend is present, 0 if not. Call with
/// handle=-1 and arg=null to detect at `module_new`.
pub const PROBE: u32 = 0x1000;

/// Store a private key. handle=-1.
/// arg layout: [key_type:u8][len:u8][_pad:u16][bytes[len]]
/// - key_type 1 = raw 32-byte P-256 scalar (for ECDSA + ECDH)
/// - len is the key-material length in bytes
/// Returns: slot handle (>= 0) or negative errno.
pub const STORE: u32 = 0x1001;

/// ECDH: derive shared secret. handle = slot.
/// arg layout: [peer_pub_len:u16][_pad:u16][peer_pub_bytes[len]][out[32]]
/// On success, the 32-byte X coordinate is written into the trailing
/// out region. Returns 0 on success, negative errno otherwise.
pub const ECDH: u32 = 0x1002;

/// ECDSA sign (P-256, deterministic RFC 6979 nonce). handle = slot.
/// arg layout: [hash_len:u16][_pad:u16][hash_bytes[hash_len]][sig_out[64]]
/// Returns 0 on success.
pub const SIGN: u32 = 0x1003;

/// ECDSA verify. handle = slot.
/// arg layout: [hash_len:u16][sig_len:u16][hash_bytes[hash_len]][sig_bytes[sig_len]]
/// Returns 1 if valid, 0 if invalid, negative errno on malformed input.
pub const VERIFY: u32 = 0x1004;

/// Zeroise and free the slot. handle = slot. Returns 0.
pub const DESTROY: u32 = 0x1005;

//! FNV-1a hash function (32-bit)

/// FNV-1a offset basis (32-bit)
const FNV_OFFSET: u32 = 2166136261;

/// FNV-1a prime (32-bit)
const FNV_PRIME: u32 = 16777619;

/// Compute FNV-1a hash (32-bit) over a byte slice.
pub fn fnv1a_hash(data: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

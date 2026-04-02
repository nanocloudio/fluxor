#![cfg_attr(not(feature = "host-linux"), no_std)]

#[cfg(any(feature = "rp", feature = "chip-bcm2712", feature = "host-linux"))]
pub mod kernel;
#[cfg(any(feature = "rp", feature = "chip-bcm2712", feature = "host-linux"))]
pub mod abi;
#[cfg(any(feature = "rp", feature = "chip-bcm2712", feature = "host-linux"))]
#[path = "../modules/mod.rs"]
pub mod modules;

pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811C9DC5u32;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

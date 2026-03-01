#![no_std]

pub mod io;
pub mod kernel;
pub mod abi;
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

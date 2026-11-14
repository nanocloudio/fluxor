//! Library code shared by modules, the kernel and the tools: crypto, DNSSEC
//! validation, the GPU device model and the cores more than one module
//! runs. `no_std`, no heap.
//!
//! Not ABI: nothing here is hashed into `ABI_SURFACE_DIGEST`, and a module
//! links only the functions it calls. The crate exports functions and
//! types, never data: a table a module read across the crate boundary
//! would be reached through a GOT entry, which no module may carry.

#![no_std]
#![allow(
    unsafe_code,
    reason = "the crypto reads and writes caller buffers by pointer and the cores parse records in place"
)]

pub mod crypto {
    //! Hashes, MACs, AEADs, signatures and key agreement.
    pub mod aes_gcm;
    pub mod b64;
    pub mod chacha20;
    pub mod ed25519;
    pub mod hmac;
    pub mod ml_dsa;
    pub mod p256;
    pub mod p384;
    pub mod rsa;
    pub mod sha1;
    pub mod sha256;
    pub mod sha3;
    pub mod sha384;
    pub mod zeroize;
}

/// DNSSEC record validation over the crypto above.
pub mod dnssec;

/// Open-addressed index over caller-owned slots.
pub mod hash_index;

pub mod gpu;

pub mod cores {
    //! State machines more than one module runs.
    pub mod attach_tunnel;
    pub mod chain_encap;
    pub mod nat;
    pub mod nonce_reservation;
    pub mod session_handoff;
    pub mod table_consumer;
    pub mod transport_continuity;
    pub mod transport_continuity_record;
    pub mod tuple_arena;
}

pub mod assets {
    //! Baked bitmaps.
    pub mod font5x7;
}

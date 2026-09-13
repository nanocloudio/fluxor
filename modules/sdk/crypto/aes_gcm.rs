// AES-128/256-GCM AEAD
// Pure Rust, no_std.
//
// # Timing exposure
//
// The block cipher is NOT constant-time on any target that lacks the
// ARMv8 Cryptography Extension. GHASH is constant-time on every
// target.
//
//   - `sub_bytes` indexes the 256-byte `SBOX` with a byte of the AES
//     state. That state is a function of the secret key, so the
//     address of every S-box load is secret-dependent. An adversary
//     who can observe the data-cache footprint of this code (shared
//     cache, co-located hyperthread, or any local process on a
//     multi-tenant host) can recover the key by the standard
//     cache-timing attack on table-driven AES. The table living in
//     `.rodata` bounds nothing here: read-only memory is cached like
//     any other.
//   - `GHash::gf_mul` is branchless: the accumulator bit and the
//     reduction carry are widened to masks and XORed unconditionally
//     over a fixed 128-iteration schedule, so the GHASH subkey `H`
//     (`AES_K(0^128)`, whose recovery is a tag-forgery capability)
//     drives neither control flow nor a load address.
//
// On aarch64 with `target_feature = "aes"` the block cipher runs on
// AESE/AESMC, which are data-independent, so the S-box exposure is
// absent there. GHASH stays scalar on every target — there is no
// PMULL implementation — but scalar here means branchless, not
// variable-time.
//
// `target_feature = "aes"` is set for the bcm2712 module build
// (`tools/src/modules_build.rs` appends `-C
// target-feature=+aes,+sha2,+neon`) and for the aarch64 kernel builds,
// which do not compile this file. Every other build — the host test
// harness including on aarch64 hosts, wasm32, rp2040, rp2350 — compiles
// the scalar path, because rustc does not infer the build host's CPU
// features without `-C target-cpu=native`.
//
// Callers that need a portable AEAD with no key-dependent memory
// addressing and no key-dependent branches should select
// ChaCha20-Poly1305 (`chacha20.rs`) instead.

// AES S-box (256 bytes, const — placed in .rodata, safe for PIC)
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

// ============================================================================
// AES core. SubBytes is a secret-indexed lookup into the `.rodata`
// S-box — see the timing-exposure note at the top of this file.
// ============================================================================

/// Multiply by 2 in GF(2^8)
#[inline(always)]
fn xtime(a: u8) -> u8 {
    let r = (a as u16) << 1;
    (r ^ (((r >> 8) & 1) * 0x1b)) as u8
}

/// Multiply in GF(2^8)
#[inline(always)]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    p
}

/// AES round key structure — supports up to AES-256 (15 round keys × 16 bytes)
struct AesKey {
    round_keys: [[u8; 16]; 15],
    rounds: usize,
}

impl AesKey {
    fn expand_128(key: &[u8; 16]) -> Self {
        let mut rk = [[0u8; 16]; 15];
        // SAFETY: pointer arithmetic over the AES round-key state and the
        // GHASH accumulator; both are fixed-size structs.
        unsafe {
            core::ptr::copy_nonoverlapping(key.as_ptr(), rk[0].as_mut_ptr(), 16);
        }

        let mut i = 1;
        while i <= 10 {
            let prev = rk[i - 1];
            // RotWord + SubWord + RCON
            rk[i][0] = SBOX[prev[13] as usize] ^ RCON[i] ^ prev[0];
            rk[i][1] = SBOX[prev[14] as usize] ^ prev[1];
            rk[i][2] = SBOX[prev[15] as usize] ^ prev[2];
            rk[i][3] = SBOX[prev[12] as usize] ^ prev[3];
            let mut j = 4;
            while j < 16 {
                rk[i][j] = rk[i][j - 4] ^ prev[j];
                j += 1;
            }
            i += 1;
        }
        Self {
            round_keys: rk,
            rounds: 10,
        }
    }

    fn expand_256(key: &[u8; 32]) -> Self {
        let mut rk = [[0u8; 16]; 15];
        // SAFETY: pointer arithmetic over the AES round-key state and the
        // GHASH accumulator; both are fixed-size structs.
        unsafe {
            core::ptr::copy_nonoverlapping(key.as_ptr(), rk[0].as_mut_ptr(), 16);
            core::ptr::copy_nonoverlapping(key.as_ptr().add(16), rk[1].as_mut_ptr(), 16);
        }

        let mut i = 2;
        let mut rcon_idx = 1;
        while i <= 14 {
            let prev = rk[i - 1];
            let prev2 = rk[i - 2];

            if i % 2 == 0 {
                // RotWord + SubWord + RCON
                rk[i][0] = SBOX[prev[13] as usize] ^ RCON[rcon_idx] ^ prev2[0];
                rk[i][1] = SBOX[prev[14] as usize] ^ prev2[1];
                rk[i][2] = SBOX[prev[15] as usize] ^ prev2[2];
                rk[i][3] = SBOX[prev[12] as usize] ^ prev2[3];
                rcon_idx += 1;
            } else {
                // AES-256 odd-index step: SubWord applied to the LAST
                // word of the previous round key (W[i-1] in FIPS-197
                // notation), i.e. `prev[12..15]` not `prev[0..3]`.
                // Caught by NIST GCM Test Case 13/14 — the previous
                // code was operating on W[i-4] which silently produced
                // a wrong key schedule with no other test ever
                // exercising it.
                rk[i][0] = SBOX[prev[12] as usize] ^ prev2[0];
                rk[i][1] = SBOX[prev[13] as usize] ^ prev2[1];
                rk[i][2] = SBOX[prev[14] as usize] ^ prev2[2];
                rk[i][3] = SBOX[prev[15] as usize] ^ prev2[3];
            }

            let mut j = 4;
            while j < 16 {
                rk[i][j] = rk[i][j - 4] ^ prev2[j];
                j += 1;
            }
            i += 1;
        }
        Self {
            round_keys: rk,
            rounds: 14,
        }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        // ARMv8 Cryptography Extension fast path. Gated on
        // `target_feature = "aes"` (not just `target_arch =
        // "aarch64"`) — bare ARMv8-A without the +crypto extension
        // SIGILLs on AESE/AESMC. Cortex-A76 (Pi 5, our pi5 build)
        // and every Pi-class A-core ships +crypto; the gate keeps
        // QEMU-unknown / older Cortex-A53 hosts honest.
        //
        // The feature is set for one build that compiles this file:
        // the bcm2712 PIC module build, whose RUSTFLAGS carry `-C
        // target-feature=+aes`. It is NOT set for the host test
        // harness even on a Pi 5, because rustc reports only the
        // target triple's baseline features (aarch64 baseline is
        // `neon` alone) unless a build asks for more, and the
        // harness does not. Host tests, wasm32, rp2040 and rp2350
        // therefore all execute the scalar path, with the S-box
        // cache-timing exposure documented at the top of this file.
        #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
        unsafe {
            encrypt_block_aarch64_aes(block, &self.round_keys, self.rounds);
            return;
        }
        // Scalar AddRoundKey + SubBytes + ShiftRows + MixColumns +
        // AddRoundKey loop. Byte-identical reference for KATs and
        // the fallback used on aarch64-without-crypto, rp2350
        // Cortex-M33, wasm32, and any host where the AES extension
        // isn't present.
        #[cfg(not(all(target_arch = "aarch64", target_feature = "aes")))]
        {
            // AddRoundKey (initial)
            xor_block(block, &self.round_keys[0]);

            // Main rounds
            let mut r = 1;
            while r < self.rounds {
                sub_bytes(block);
                shift_rows(block);
                mix_columns(block);
                xor_block(block, &self.round_keys[r]);
                r += 1;
            }

            // Final round (no MixColumns)
            sub_bytes(block);
            shift_rows(block);
            xor_block(block, &self.round_keys[self.rounds]);
        }
    }
}

/// ARMv8-A AES instructions for one block. `rounds` is 10 (AES-128)
/// or 14 (AES-256). The round-key array holds `rounds + 1` keys
/// (the last entry is the post-final-AESE EOR target).
///
/// Compiled only when both `target_arch = "aarch64"` AND
/// `target_feature = "aes"` are set — guards against SIGILL on
/// ARMv8-A cores without the Cryptography Extension. The bcm2712 PIC
/// build sets `-C target-feature=+aes` via the bcm2712 target
/// spec; host-test on the same Pi 5 inherits the host CPU's
/// feature set; non-aarch64 builds and aarch64-without-crypto
/// hosts fall back to the scalar SBOX path in `encrypt_block`.
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
#[inline(never)]
unsafe fn encrypt_block_aarch64_aes(block: &mut [u8; 16], rks: &[[u8; 16]; 15], rounds: usize) {
    // `aese` consumes v1; we need a fresh round-key register for
    // each round so we load them all upfront into v1..v15 then
    // pipeline AESE/AESMC against the contiguous register file.
    if rounds == 10 {
        core::arch::asm!(
            ".arch armv8-a+crypto",
            "ldr q0, [{state}]",
            "ldp q1, q2, [{rks}, #0]",
            "ldp q3, q4, [{rks}, #32]",
            "ldp q5, q6, [{rks}, #64]",
            "ldp q7, q8, [{rks}, #96]",
            "ldp q9, q10, [{rks}, #128]",
            "ldr q11, [{rks}, #160]",
            // Rounds 1-9: AESE then AESMC.
            "aese v0.16b, v1.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v2.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v3.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v4.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v5.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v6.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v7.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v8.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v9.16b",  "aesmc v0.16b, v0.16b",
            // Final round: AESE (no AESMC) then EOR with rk[10].
            "aese v0.16b, v10.16b",
            "eor v0.16b, v0.16b, v11.16b",
            "str q0, [{state}]",
            state = in(reg) block.as_mut_ptr(),
            rks = in(reg) rks.as_ptr(),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
        );
    } else {
        // AES-256 — 14 rounds → 15 round keys → 14 AESE + 13 AESMC
        // + 1 EOR. We hold rk[0..7] in v1..v8 for the first
        // batch, then reload rk[8..14] into v9..v15 + v1 (reuse).
        core::arch::asm!(
            ".arch armv8-a+crypto",
            "ldr q0, [{state}]",
            // rk[0..6] → v1..v7
            "ldp q1, q2, [{rks}, #0]",
            "ldp q3, q4, [{rks}, #32]",
            "ldp q5, q6, [{rks}, #64]",
            "ldr q7, [{rks}, #96]",
            // First 7 AESE+AESMC pairs.
            "aese v0.16b, v1.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v2.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v3.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v4.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v5.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v6.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v7.16b",  "aesmc v0.16b, v0.16b",
            // rk[7..14] → v1..v8 (reload).
            "ldp q1, q2, [{rks}, #112]",
            "ldp q3, q4, [{rks}, #144]",
            "ldp q5, q6, [{rks}, #176]",
            "ldp q7, q8, [{rks}, #208]",
            // Rounds 8..13: AESE + AESMC.
            "aese v0.16b, v1.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v2.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v3.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v4.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v5.16b",  "aesmc v0.16b, v0.16b",
            "aese v0.16b, v6.16b",  "aesmc v0.16b, v0.16b",
            // Final round: AESE (no AESMC) then EOR with rk[14].
            "aese v0.16b, v7.16b",
            "eor v0.16b, v0.16b, v8.16b",
            "str q0, [{state}]",
            state = in(reg) block.as_mut_ptr(),
            rks = in(reg) rks.as_ptr(),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _,
        );
    }
}

#[inline(always)]
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    let mut i = 0;
    while i < 16 {
        a[i] ^= b[i];
        i += 1;
    }
}

/// SubBytes. The index is a byte of the AES state and therefore
/// secret; this is a secret-indexed table lookup, and the load
/// address it produces is observable through the data cache. See the
/// timing-exposure note at the top of this file.
fn sub_bytes(block: &mut [u8; 16]) {
    let mut i = 0;
    while i < 16 {
        block[i] = SBOX[block[i] as usize];
        i += 1;
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    // Row 1: shift left 1
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    // Row 2: shift left 2
    let t0 = s[2];
    let t1 = s[6];
    s[2] = s[10];
    s[6] = s[14];
    s[10] = t0;
    s[14] = t1;
    // Row 3: shift left 3 (= right 1)
    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

fn mix_columns(s: &mut [u8; 16]) {
    let mut i = 0;
    while i < 16 {
        let a0 = s[i];
        let a1 = s[i + 1];
        let a2 = s[i + 2];
        let a3 = s[i + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;
        s[i] = a0 ^ xtime(a0 ^ a1) ^ t;
        s[i + 1] = a1 ^ xtime(a1 ^ a2) ^ t;
        s[i + 2] = a2 ^ xtime(a2 ^ a3) ^ t;
        s[i + 3] = a3 ^ xtime(a3 ^ a0) ^ t;
        i += 4;
    }
}

// ============================================================================
// GHASH (GF(2^128) multiplication for GCM)
// ============================================================================

/// GF(2^128) element as two u64 (big-endian bit ordering)
struct GHash {
    h_lo: u64,
    h_hi: u64,
    y_lo: u64,
    y_hi: u64,
}

impl GHash {
    fn new(h: &[u8; 16]) -> Self {
        Self {
            h_hi: u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]),
            h_lo: u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]),
            y_hi: 0,
            y_lo: 0,
        }
    }

    /// Multiply in GF(2^128) with reduction polynomial
    /// x^128 + x^7 + x^2 + x + 1.
    ///
    /// Branchless. The loop runs a fixed 128 iterations and neither
    /// the accumulator bit nor the reduction carry becomes a branch
    /// condition: each is widened to an all-ones/all-zeros mask, the
    /// mask is ANDed with the operand, and the result is XORed
    /// unconditionally. No secret value selects a control-flow edge
    /// or a memory address here.
    ///
    /// This matters because the GHASH subkey `H` is `AES_K(0^128)` and
    /// the shifting `V` starts at `H`: a timing observer who recovers
    /// `H` forges GCM authentication tags for that key without
    /// recovering the key itself. GHASH is scalar on every target,
    /// including the bcm2712 build with hardware AES, so this path is
    /// the one AES-GCM exposure that no target escapes.
    ///
    /// Constant-time here is a property of this function only; the
    /// block cipher feeding it is not (see the file header).
    fn gf_mul(&mut self) {
        let mut z_hi: u64 = 0;
        let mut z_lo: u64 = 0;
        let mut v_hi = self.h_hi;
        let mut v_lo = self.h_lo;
        let y_hi = self.y_hi;
        let y_lo = self.y_lo;

        // Process high 64 bits of Y, then the low 64 bits. Fixed
        // 64-iteration trip counts, no early exit.
        let mut word = 0;
        while word < 2 {
            let y = if word == 0 { y_hi } else { y_lo };
            let mut i: i32 = 63;
            while i >= 0 {
                // mask = 0xffff_ffff_ffff_ffff when the bit is set,
                // 0 when it is clear.
                let mask = ((y >> i as u32) & 1).wrapping_neg();
                z_hi ^= v_hi & mask;
                z_lo ^= v_lo & mask;

                // v >>= 1 with reduction by
                // R = x^128 + x^7 + x^2 + x + 1, applied under the
                // carry mask rather than under an `if`.
                let carry_mask = (v_lo & 1).wrapping_neg();
                v_lo = (v_lo >> 1) | (v_hi << 63);
                v_hi >>= 1;
                v_hi ^= 0xe100000000000000 & carry_mask;
                i -= 1;
            }
            word += 1;
        }

        self.y_hi = z_hi;
        self.y_lo = z_lo;
    }

    fn update_block(&mut self, block: &[u8; 16]) {
        self.y_hi ^= u64::from_be_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        self.y_lo ^= u64::from_be_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);
        self.gf_mul();
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        while offset + 16 <= data.len() {
            let mut block = [0u8; 16];
            // SAFETY: pointer arithmetic over the AES round-key state and the
            // GHASH accumulator; both are fixed-size structs.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), block.as_mut_ptr(), 16);
            }
            self.update_block(&block);
            offset += 16;
        }
        if offset < data.len() {
            let mut block = [0u8; 16];
            let remain = data.len() - offset;
            // SAFETY: pointer arithmetic over the AES round-key state and the
            // GHASH accumulator; both are fixed-size structs.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(offset),
                    block.as_mut_ptr(),
                    remain,
                );
            }
            self.update_block(&block);
        }
    }

    fn finalize_tag(mut self, aad_len: usize, ct_len: usize) -> [u8; 16] {
        // Append lengths block (bits, big-endian)
        let mut len_block = [0u8; 16];
        let aad_bits = (aad_len as u64) * 8;
        let ct_bits = (ct_len as u64) * 8;
        // SAFETY: pointer arithmetic over the AES round-key state and the
        // GHASH accumulator; both are fixed-size structs.
        unsafe {
            let a = aad_bits.to_be_bytes();
            let c = ct_bits.to_be_bytes();
            core::ptr::copy_nonoverlapping(a.as_ptr(), len_block.as_mut_ptr(), 8);
            core::ptr::copy_nonoverlapping(c.as_ptr(), len_block.as_mut_ptr().add(8), 8);
        }
        self.update_block(&len_block);

        let mut tag = [0u8; 16];
        // SAFETY: pointer arithmetic over the AES round-key state and the
        // GHASH accumulator; both are fixed-size structs.
        unsafe {
            let hi = self.y_hi.to_be_bytes();
            let lo = self.y_lo.to_be_bytes();
            core::ptr::copy_nonoverlapping(hi.as_ptr(), tag.as_mut_ptr(), 8);
            core::ptr::copy_nonoverlapping(lo.as_ptr(), tag.as_mut_ptr().add(8), 8);
        }
        tag
    }
}

// ============================================================================
// AES-GCM AEAD
// ============================================================================

pub const AES128_KEY_LEN: usize = 16;
pub const AES256_KEY_LEN: usize = 32;
pub const GCM_NONCE_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

/// True when this build's AES block cipher is data-independent, i.e.
/// when the ARMv8 Cryptography Extension path is compiled. Derived
/// from the same `cfg` as `AesKey::encrypt_block`'s fast path, so the
/// two cannot drift.
///
/// False means every block encryption indexes `SBOX` with a
/// key-dependent byte. GHASH is branchless regardless, so this
/// constant describes the block cipher only.
///
/// True for exactly one build of this file: the bcm2712 PIC module
/// build. The host test harness (including on a Pi 5), wasm32, rp2040
/// and rp2350 are all false.
pub const AES_IS_CONSTANT_TIME: bool = cfg!(all(target_arch = "aarch64", target_feature = "aes"));

/// Whether AES-GCM cipher suites may be offered or accepted by suite
/// selection on this target. Consulted by the TLS suite tables; this
/// module does not select suites itself.
///
/// When `AES_IS_CONSTANT_TIME` is false, selecting AES-GCM puts the
/// record key on the secret-indexed S-box, so selection becomes an
/// explicit posture rather than a fallback reachable by peer
/// preference alone. ChaCha20-Poly1305 (`chacha20.rs`) is
/// constant-time on every target and is the preferred suite.
///
/// Defaults:
///
///   - rp2040, rp2350 (`target_arch = "arm"`) and wasm32: **off**.
///     These are not general-purpose TLS clients, so RFC 8446 §9.1's
///     mandatory-to-implement argument for `TLS_AES_128_GCM_SHA256`
///     does not bind them, and declining AES-GCM is the complete
///     mitigation there.
///   - Every other target: on. On bcm2712 the block cipher is
///     data-independent. On the Linux host it is not, and that host
///     is the genuinely exposed target — multi-tenant, hardware data
///     caches, possible co-resident untrusted workloads — but it is
///     also the one target that must interoperate with arbitrary
///     peers, and a node that cannot speak `TLS_AES_128_GCM_SHA256`
///     is not a TLS 1.3 implementation. The default is therefore on
///     and the exposure is accepted, not absent.
pub const AES_GCM_SUITES_ENABLED: bool = !cfg!(any(target_arch = "arm", target_arch = "wasm32"));

/// AES-GCM context with expanded key and H (for GHASH)
pub struct AesGcm {
    aes: AesKey,
    h: [u8; 16], // GHASH subkey = AES_K(0^128)
}

impl Drop for AesKey {
    fn drop(&mut self) {
        let mut i = 0;
        while i < self.round_keys.len() {
            zeroize(&mut self.round_keys[i]);
            i += 1;
        }
    }
}

/// Public AES-ECB primitive — encrypts a single 16-byte block under
/// `key`. Used by QUIC header protection (RFC 9001 §5.4) and other
/// places that need a raw single-block primitive without GHASH state.
/// The function inlines the round-key expansion each call; callers
/// who do header protection per-packet should cache the expanded key
/// in `Aes128Hp` instead.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub fn aes128_ecb_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let aes = AesKey::expand_128(key);
    aes.encrypt_block(block);
}

/// Cached AES-128 encryption context for repeated single-block
/// encryption (header protection's hot path). Stores the expanded
/// round keys once per epoch.
pub struct Aes128Hp {
    aes: AesKey,
}

#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
impl Aes128Hp {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            aes: AesKey::expand_128(key),
        }
    }

    /// Encrypt one 16-byte block in place. Used to compute the
    /// header-protection mask from a 16-byte ciphertext sample.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.aes.encrypt_block(block);
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        zeroize(&mut self.h);
    }
}

impl AesGcm {
    pub fn new_128(key: &[u8; 16]) -> Self {
        let aes = AesKey::expand_128(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        Self { aes, h }
    }

    pub fn new_256(key: &[u8; 32]) -> Self {
        let aes = AesKey::expand_256(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        Self { aes, h }
    }

    /// Generate counter block from nonce (12 bytes) + counter (big-endian u32)
    fn make_j0(nonce: &[u8; 12]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        // SAFETY: pointer arithmetic over the AES round-key state and the
        // GHASH accumulator; both are fixed-size structs.
        unsafe {
            core::ptr::copy_nonoverlapping(nonce.as_ptr(), j0.as_mut_ptr(), 12);
        }
        j0[15] = 1; // Initial counter = 1
        j0
    }

    fn inc_counter(ctr: &mut [u8; 16]) {
        let mut c = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
        c = c.wrapping_add(1);
        let b = c.to_be_bytes();
        // SAFETY: pointer arithmetic over the AES round-key state and the
        // GHASH accumulator; both are fixed-size structs.
        unsafe {
            core::ptr::copy_nonoverlapping(b.as_ptr(), ctr.as_mut_ptr().add(12), 4);
        }
    }

    /// Encrypt data in-place and return tag.
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let mut ctr = Self::make_j0(nonce);

        // Encrypt J0 for tag XOR
        let mut tag_mask = ctr;
        self.aes.encrypt_block(&mut tag_mask);

        // Encrypt data with counter starting at J0+1
        Self::inc_counter(&mut ctr);
        self.ctr_xor(&mut ctr, data);

        // GHASH. `update` already zero-pads each call's trailing partial
        // block up to the GCM block boundary (see GHash::update), which is
        // exactly the padding GCM requires between AAD and ciphertext and
        // before the length block. Do NOT add an extra explicit padding
        // block here — that injects a spurious all-zero GHASH block for any
        // non-16-aligned AAD/ciphertext, producing a wrong tag. (It stayed
        // hidden because it's self-consistent encrypt↔decrypt and the only
        // GCM KAT used empty AAD + a block-aligned plaintext.)
        let mut ghash = GHash::new(&self.h);
        ghash.update(aad);
        ghash.update(data);

        let mut tag = ghash.finalize_tag(aad.len(), data.len());
        // XOR with encrypted J0
        let mut i = 0;
        while i < 16 {
            tag[i] ^= tag_mask[i];
            i += 1;
        }
        zeroize(&mut tag_mask);
        zeroize(&mut ctr);
        tag
    }

    /// Decrypt data in-place. Returns true if tag matches.
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let mut ctr = Self::make_j0(nonce);

        // Encrypt J0 for tag XOR
        let mut tag_mask = ctr;
        self.aes.encrypt_block(&mut tag_mask);

        // GHASH over ciphertext (before decryption). `update` already
        // zero-pads each call's trailing partial block to the GCM block
        // boundary, so no extra explicit padding block must be added (doing
        // so injects a spurious all-zero GHASH block for non-16-aligned
        // AAD/ciphertext and yields a wrong tag). Mirror `encrypt`.
        let mut ghash = GHash::new(&self.h);
        ghash.update(aad);
        ghash.update(data);
        let mut computed_tag = ghash.finalize_tag(aad.len(), data.len());
        let mut i = 0;
        while i < 16 {
            computed_tag[i] ^= tag_mask[i];
            i += 1;
        }

        // Tag comparison is constant-time in the tag: all 16 bytes are
        // folded into `diff` before any branch, so neither the number
        // of matching bytes nor the position of the first mismatch is
        // observable. This covers the comparison only — the GHASH that
        // produced `computed_tag` and the AES that produced `tag_mask`
        // carry the exposures documented at the top of this file.
        let mut diff = 0u8;
        i = 0;
        while i < 16 {
            diff |= computed_tag[i] ^ tag[i];
            i += 1;
        }

        if diff != 0 {
            zeroize(&mut tag_mask);
            zeroize(&mut computed_tag);
            zeroize(&mut ctr);
            return false;
        }

        // Decrypt
        Self::inc_counter(&mut ctr);
        self.ctr_xor(&mut ctr, data);
        zeroize(&mut tag_mask);
        zeroize(&mut computed_tag);
        zeroize(&mut ctr);
        true
    }

    fn ctr_xor(&self, ctr: &mut [u8; 16], data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let mut block = *ctr;
            self.aes.encrypt_block(&mut block);
            let remain = data.len() - offset;
            let take = if remain < 16 { remain } else { 16 };
            let mut j = 0;
            while j < take {
                data[offset + j] ^= block[j];
                j += 1;
            }
            Self::inc_counter(ctr);
            offset += take;
        }
    }
}

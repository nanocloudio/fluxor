// SHA-3 and SHAKE (FIPS 202) over Keccak-f[1600].
// Pure Rust, no_std, no heap.
//
// Two fixed-output hashes and two extendable-output functions, all one
// sponge with a different rate and domain-separation byte:
//
//   SHA3-256   rate 136  pad 0x06   32-byte digest
//   SHA3-512   rate  72  pad 0x06   64-byte digest
//   SHAKE128   rate 168  pad 0x1f   arbitrary output
//   SHAKE256   rate 136  pad 0x1f   arbitrary output
//
// The XOFs are the reason this file exists: ML-DSA (FIPS 204) expands
// every one of its matrices, secrets and challenges from a SHAKE stream,
// and reads that stream incrementally — `Shake128::squeeze` may be called
// as many times as the rejection sampler needs, each call continuing
// where the last stopped.
//
// NO CONSTANT TABLES. Keccak's round constants and rotation offsets are
// normally shipped as `const [u64; 24]` / `const [u32; 24]` arrays, and
// PIC aarch64 modules cannot use ADRP-based literal pool loads, so those
// arrays miscompile in .rodata — the same constraint that makes p256.rs
// assemble its curve constants with `pic_u256`. Here the constants are
// not assembled but DERIVED, because FIPS 202 defines them by
// construction rather than by table:
//
//   - round constants come from the §3.2.5 LFSR (x^8+x^6+x^5+x^4+1),
//     stepped seven times per round;
//   - the rho offsets are (t+1)(t+2)/2 mod 64 and the pi permutation is
//     (x, y) -> (y, 2x+3y), both walked by the §3.2.2/§3.2.3 recurrence
//     from lane (1, 0).
//
// So the definitions in the standard are what the code runs, and there is
// nothing in .rodata to relocate.
//
// Endianness: FIPS 202 lanes are little-endian, which is what the target
// is, so absorb/squeeze go through `u64::from_le_bytes` / `to_le_bytes`
// rather than assuming the host's layout.

/// Keccak-f[1600] state: 25 lanes of 64 bits.
const LANES: usize = 25;

/// Largest sponge rate this file uses (SHAKE128). Buffers that must hold
/// one block for any of the four functions are sized from this.
pub const MAX_RATE: usize = 168;

/// The Keccak-f[1600] permutation, 24 rounds of theta-rho-pi-chi-iota.
fn keccak_f1600(a: &mut [u64; LANES]) {
    // §3.2.5 LFSR state, initialised to 1 and carried across all 24
    // rounds — each round consumes seven steps, so the constants come out
    // in the order the standard defines them without a table.
    let mut lfsr: u8 = 1;

    for _round in 0..24 {
        // theta: parity of each column, then fold neighbours in.
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        // rho + pi, walked as one chain from lane (1, 0): each step
        // rotates the carried lane by (t+1)(t+2)/2 and deposits it at the
        // pi image of the current position.
        let (mut x, mut y) = (1usize, 0usize);
        let mut carried = a[1];
        for t in 0..24u32 {
            let ny = (2 * x + 3 * y) % 5;
            x = y;
            y = ny;
            let lane = x + 5 * y;
            let offset = ((t + 1) * (t + 2) / 2) % 64;
            let displaced = a[lane];
            a[lane] = carried.rotate_left(offset);
            carried = displaced;
        }

        // chi: the only non-linear step, applied row by row.
        for y in 0..5 {
            let row = [
                a[5 * y],
                a[5 * y + 1],
                a[5 * y + 2],
                a[5 * y + 3],
                a[5 * y + 4],
            ];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }

        // iota: seven LFSR steps supply the bits of this round's constant,
        // at positions 2^j - 1 of lane (0, 0).
        let mut rc = 0u64;
        for j in 0..7 {
            let bit = lfsr & 1;
            lfsr = if lfsr & 0x80 != 0 {
                (lfsr << 1) ^ 0x71
            } else {
                lfsr << 1
            };
            if bit != 0 {
                rc |= 1u64 << ((1usize << j) - 1);
            }
        }
        a[0] ^= rc;
    }
}

/// A Keccak sponge: absorb any number of bytes, pad, then squeeze any
/// number of bytes. `rate` and `pad` select which FIPS 202 function this
/// is; nothing else differs between them.
///
/// The type is public because ML-DSA drives SHAKE directly, in the
/// absorb-then-squeeze-repeatedly shape its rejection samplers need.
pub struct Keccak {
    state: [u64; LANES],
    rate: usize,
    pad: u8,
    /// Bytes absorbed into (or squeezed out of) the current block.
    pos: usize,
    /// False until `finalize` has applied the padding.
    squeezing: bool,
}

impl Keccak {
    /// A sponge with the given rate in bytes and domain-separation byte.
    pub fn new(rate: usize, pad: u8) -> Self {
        Self {
            state: [0u64; LANES],
            rate,
            pad,
            pos: 0,
            squeezing: false,
        }
    }

    /// XOR one byte into the state at byte offset `i`.
    fn absorb_byte(&mut self, i: usize, byte: u8) {
        let lane = i / 8;
        let shift = 8 * (i % 8);
        self.state[lane] ^= u64::from(byte) << shift;
    }

    /// Read the state byte at offset `i`.
    fn state_byte(&self, i: usize) -> u8 {
        ((self.state[i / 8] >> (8 * (i % 8))) & 0xff) as u8
    }

    /// Absorb `data`. Must not be called after `finalize`.
    pub fn update(&mut self, data: &[u8]) {
        debug_assert!(!self.squeezing, "absorb after pad");
        for &byte in data {
            self.absorb_byte(self.pos, byte);
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    /// Apply the pad10*1 rule and switch to squeezing. Idempotent, so a
    /// caller that squeezes without an explicit finalize still gets the
    /// padded stream.
    pub fn finalize(&mut self) {
        if self.squeezing {
            return;
        }
        self.absorb_byte(self.pos, self.pad);
        self.absorb_byte(self.rate - 1, 0x80);
        keccak_f1600(&mut self.state);
        self.pos = 0;
        self.squeezing = true;
    }

    /// Fill `out` with the next bytes of the output stream. May be called
    /// repeatedly; the stream continues across calls.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.finalize();
        for slot in out.iter_mut() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            *slot = self.state_byte(self.pos);
            self.pos += 1;
        }
    }

    /// Overwrite the state. Callers that absorbed key material use this
    /// before the sponge goes out of scope.
    pub fn zeroize_state(&mut self) {
        for lane in self.state.iter_mut() {
            // SAFETY: `lane` is a live, exclusively-borrowed u64.
            unsafe { core::ptr::write_volatile(lane, 0) };
        }
        self.pos = 0;
        self.squeezing = false;
    }
}

/// SHAKE128 sponge rate, in bytes.
pub const SHAKE128_RATE: usize = 168;
/// SHAKE256 sponge rate, in bytes.
pub const SHAKE256_RATE: usize = 136;
/// SHA3-256 sponge rate, in bytes.
pub const SHA3_256_RATE: usize = 136;
/// SHA3-512 sponge rate, in bytes.
pub const SHA3_512_RATE: usize = 72;

/// Domain separation for the fixed-output SHA-3 hashes (FIPS 202 §6.1).
pub const SHA3_PAD: u8 = 0x06;
/// Domain separation for the extendable-output functions (§6.2).
pub const SHAKE_PAD: u8 = 0x1f;

/// A SHAKE128 sponge, for a caller that squeezes in more than one go.
pub fn shake128_init() -> Keccak {
    Keccak::new(SHAKE128_RATE, SHAKE_PAD)
}

/// A SHAKE256 sponge, for a caller that squeezes in more than one go.
pub fn shake256_init() -> Keccak {
    Keccak::new(SHAKE256_RATE, SHAKE_PAD)
}

/// One-shot SHAKE128 over `msg` into `out`.
pub fn shake128(msg: &[u8], out: &mut [u8]) {
    let mut k = shake128_init();
    k.update(msg);
    k.squeeze(out);
}

/// One-shot SHAKE256 over `msg` into `out`.
pub fn shake256(msg: &[u8], out: &mut [u8]) {
    let mut k = shake256_init();
    k.update(msg);
    k.squeeze(out);
}

/// SHA3-256 of `msg`.
pub fn sha3_256(msg: &[u8]) -> [u8; 32] {
    let mut k = Keccak::new(SHA3_256_RATE, SHA3_PAD);
    k.update(msg);
    let mut out = [0u8; 32];
    k.squeeze(&mut out);
    out
}

/// SHA3-512 of `msg`.
pub fn sha3_512(msg: &[u8]) -> [u8; 64] {
    let mut k = Keccak::new(SHA3_512_RATE, SHA3_PAD);
    k.update(msg);
    let mut out = [0u8; 64];
    k.squeeze(&mut out);
    out
}

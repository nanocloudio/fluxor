//! Node images as the tools write them: the `wire::node_image` header, the
//! module table and the config, laid out by `node_image::place`, hashed,
//! pinned to this tree's ABI surface and, with a key, signed.
//!
//! One writer for every image a build emits: an RP flash slot or an OTA image
//! (`fluxor build --emit=image`), the payload `combine` appends after a
//! kernel, and the Linux graph file (`graph.img`).

use fluxor_abi::wire::node_image::{self, Header, Signature};
use sha2::Digest as _;

use crate::error::{Error, Result};

/// The header of an image whose header lies at address `base` and carries
/// `modules` then `config`: offsets from `place`, the payload digest and this
/// tree's ABI-surface pin. Unsigned.
pub fn header(base: u64, modules: &[u8], config: &[u8], epoch: u64) -> Result<Header> {
    let (modules_offset, config_offset) = node_image::place(base, modules.len() as u64);
    let narrow = |v: u64, what: &str| {
        u32::try_from(v)
            .map_err(|_| Error::Config(format!("node image {what} {v} does not fit 32 bits")))
    };
    let mut h = sha2::Sha256::new();
    h.update(modules);
    h.update(config);
    Ok(Header {
        epoch,
        modules_offset: narrow(modules_offset, "modules offset")?,
        modules_size: narrow(modules.len() as u64, "module table size")?,
        config_offset: narrow(config_offset, "config offset")?,
        config_size: narrow(config.len() as u64, "config size")?,
        digest: h.finalize().into(),
        abi_pin: crate::hash::abi_surface_digest(),
    })
}

/// Sign a header in place with the Ed25519 `seed`: the record over the
/// signed bytes. Answers the signer's public key.
pub fn sign(header: &mut [u8], seed: &[u8; 32]) -> [u8; 32] {
    use fluxor_sdk::crypto::ed25519::{ed25519_public_key, ed25519_sign};
    let pk = ed25519_public_key(seed);
    let signature = ed25519_sign(seed, &header[..node_image::SIGNED_LEN]);
    let id = sha2::Sha256::digest(pk);
    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&id[..4]);
    node_image::put_signature(header, &Signature { key_id, signature });
    pk
}

/// The header's bytes, signed with `seed` when given.
pub fn header_bytes(header: &Header, seed: Option<&[u8; 32]>) -> [u8; node_image::HEADER_SIZE] {
    let mut out = header.encode();
    if let Some(seed) = seed {
        sign(&mut out, seed);
    }
    out
}

/// A whole image based at 0, as long as its payload: header, the module
/// table at its offset, the config at its, the gaps erased (0xFF).
pub fn compose(
    modules: &[u8],
    config: &[u8],
    epoch: u64,
    seed: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    let h = header(0, modules, config, epoch)?;
    let mut out = vec![0xFFu8; h.end() as usize];
    out[..node_image::HEADER_SIZE].copy_from_slice(&header_bytes(&h, seed));
    let m = h.modules_offset as usize;
    out[m..m + modules.len()].copy_from_slice(modules);
    let c = h.config_offset as usize;
    out[c..c + config.len()].copy_from_slice(config);
    Ok(out)
}

/// The header of an image file, read as the kernel reads it, its regions
/// bounded by the file's length. `what` names the file in errors.
pub fn read(image: &[u8], what: &str) -> Result<Header> {
    Header::decode(image, image.len() as u64)
        .map_err(|e| Error::Config(format!("{what} is not a node image ({e:?})")))
}

/// `image` with its config replaced by `config`: the same module table and
/// epoch, re-hashed, and signed with `seed` when given (an image that was
/// signed and is re-written without a key is refused, since the result would
/// no longer verify).
pub fn with_config(
    image: &[u8],
    config: &[u8],
    seed: Option<&[u8; 32]>,
    what: &str,
) -> Result<Vec<u8>> {
    let h = read(image, what)?;
    if seed.is_none() && node_image::signature(image).is_some() {
        return Err(Error::Config(format!(
            "{what} is signed, and no signing key is configured to re-sign it with a changed \
             config (`$FLUXOR_SIGNING_KEY`, `[signing] key`)"
        )));
    }
    compose(h.modules(image), config, h.epoch, seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An image composed here reads back through the shared codec with every
    /// region where its header says, digest and pin included, and a signed
    /// one carries a record that verifies over the signed bytes.
    #[test]
    fn a_composed_image_reads_back() {
        let modules = vec![0x11u8; 300];
        let config = vec![0x22u8; 70];
        let seed = [5u8; 32];
        let img = compose(&modules, &config, 9, Some(&seed)).expect("composes");
        let h = read(&img, "img").expect("reads");
        assert_eq!(h.epoch, 9);
        assert_eq!(h.modules_offset, 4096);
        assert_eq!(h.config_offset, 4096 + 512);
        assert_eq!(h.modules(&img), &modules[..]);
        assert_eq!(h.config(&img), &config[..]);
        assert_eq!(img.len() as u64, h.end());
        assert_eq!(h.abi_pin, crate::hash::abi_surface_digest());
        let mut d = sha2::Sha256::new();
        d.update(&modules);
        d.update(&config);
        assert_eq!(h.digest, <[u8; 32]>::from(d.finalize()));
        let rec = node_image::signature(&img).expect("signed");
        let pk = fluxor_sdk::crypto::ed25519::ed25519_public_key(&seed);
        assert!(fluxor_sdk::crypto::ed25519::ed25519_verify(
            &pk,
            &img[..node_image::SIGNED_LEN],
            &rec.signature
        ));
        assert!(
            img[node_image::SIGNATURE_AT + node_image::SIGNATURE_LEN..node_image::HEADER_SIZE]
                .iter()
                .all(|&b| b == 0xFF)
        );
    }

    /// Replacing the config keeps the module table and epoch, moves the
    /// digest, and refuses to leave a signed image unsigned.
    #[test]
    fn a_replaced_config_is_rehashed() {
        let img = compose(&[0x33u8; 64], &[1u8; 40], 4, None).expect("composes");
        let out = with_config(&img, &[2u8; 90], None, "img").expect("unsigned stays unsigned");
        let (a, b) = (read(&img, "a").unwrap(), read(&out, "b").unwrap());
        assert_eq!(b.epoch, 4);
        assert_eq!(b.modules(&out), a.modules(&img));
        assert_eq!(b.config(&out), &[2u8; 90][..]);
        assert_ne!(a.digest, b.digest);
        let signed = compose(&[0x33u8; 64], &[1u8; 40], 4, Some(&[3u8; 32])).unwrap();
        assert!(with_config(&signed, &[2u8; 90], None, "img").is_err());
    }

    /// A header placed after a kernel puts the table on the next 4 KiB
    /// boundary of the address it runs at, not of the header.
    #[test]
    fn placement_aligns_the_table_absolutely() {
        let h = header(0x1003_2100, &[0u8; 16], &[0u8; 8], 0).unwrap();
        assert_eq!(0x1003_2100 + u64::from(h.modules_offset), 0x1003_3000);
        assert_eq!(h.config_offset, h.modules_offset + 256);
    }
}

//! `fluxor vault import|identity`: provision records into a `key_vault`
//! store image off the device, exactly as the vault files a key it made, so
//! the module that opens the label finds it.
//!
//! The image is the file a graph wires to the vault's `blocks` (a
//! `file_block` over it): two A/B slots of `image_size` bytes from
//! `start_sector` (512-byte sectors). The tool loads the valid slot with the
//! higher sequence, changes the record, and writes the next image to the
//! other slot, as the vault does. Records are sealed under the key the vault
//! derives (`SEAL_KEY_DERIVE`, context `records`) from `FLUXOR_SEAL_KEY`, the
//! host's sealing key: `fluxor_sdk::crypto::seal::derive`, the function the
//! kernel answers with.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use fluxor_abi::contracts::key_vault as kv;
use fluxor_sdk::cores::vault_image as image;
use fluxor_sdk::cores::vault_record as record;

use crate::error::{Error, Result};

/// The module type whose instance files the records: the vault itself.
pub const VAULT_MODULE: &str = "key_vault";
/// The context the vault derives its record key under.
pub const RECORDS_CTX: &[u8] = b"records";
/// The image size a graph's vault uses unless it says otherwise.
pub const DEFAULT_IMAGE_SIZE: usize = 8192;
/// Bytes per sector, the unit `start_sector` counts in.
const SECTOR: u64 = 512;

/// Where the image lives in its file.
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub image_size: usize,
    pub start_sector: u64,
}

impl Default for Geometry {
    fn default() -> Self {
        Self {
            image_size: DEFAULT_IMAGE_SIZE,
            start_sector: 0,
        }
    }
}

fn err(msg: impl Into<String>) -> Error {
    Error::Config(msg.into())
}

/// The host's sealing key from `FLUXOR_SEAL_KEY` (64 hex digits).
pub fn seal_key_from_env() -> Result<[u8; 32]> {
    let hex = std::env::var("FLUXOR_SEAL_KEY")
        .map_err(|_| err("FLUXOR_SEAL_KEY is not set (64 hex digits, the host's sealing key)"))?;
    parse_key_hex(hex.trim()).ok_or_else(|| err("FLUXOR_SEAL_KEY must be 64 hex digits"))
}

/// 32 bytes from 64 hex digits.
pub fn parse_key_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(k)
}

/// The key a `key_vault` seals its records under, given the host's sealing
/// key: what `SEAL_KEY_DERIVE("records")` answers the vault.
pub fn record_key(seal_key: &[u8; 32]) -> [u8; 32] {
    fluxor_sdk::crypto::seal::derive(
        seal_key,
        fluxor_abi::wire::fnv1a32(VAULT_MODULE.as_bytes()),
        RECORDS_CTX,
    )
    .unwrap_or([0; 32])
}

/// An image loaded from a file: its bytes, and the slot it came from
/// (`None` for a store never written).
struct Loaded {
    img: Vec<u8>,
    from: Option<u8>,
}

fn slot_offset(g: &Geometry, slot: u8) -> u64 {
    g.start_sector * SECTOR + u64::from(slot) * g.image_size as u64
}

fn load(path: &Path, g: &Geometry) -> Result<Loaded> {
    if !image::valid_len(g.image_size) {
        return Err(err(
            "--image-size must be a multiple of 512 of at least 512",
        ));
    }
    let mut best: Option<(u64, u8, Vec<u8>)> = None;
    if let Ok(mut f) = std::fs::File::open(path) {
        for slot in 0..image::SLOTS {
            let mut buf = vec![0u8; g.image_size];
            if f.seek(SeekFrom::Start(slot_offset(g, slot))).is_err() {
                continue;
            }
            if f.read_exact(&mut buf).is_err() || !image::valid(&buf) {
                continue;
            }
            let seq = image::seq(&buf);
            if best.as_ref().is_none_or(|(b, _, _)| seq > *b) {
                best = Some((seq, slot, buf));
            }
        }
    }
    Ok(match best {
        Some((_, slot, img)) => Loaded {
            img,
            from: Some(slot),
        },
        None => {
            let mut img = vec![0u8; g.image_size];
            image::format(&mut img, 0);
            Loaded { img, from: None }
        }
    })
}

/// Write `l`'s image to the slot not holding the one it was loaded from.
fn save(path: &Path, g: &Geometry, l: &Loaded) -> Result<()> {
    let slot = match l.from {
        Some(s) => 1 - s,
        None => 0,
    };
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| err(format!("{}: {e}", path.display())))?;
    let end = slot_offset(g, 2);
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len < end {
        f.set_len(end)
            .map_err(|e| err(format!("{}: {e}", path.display())))?;
    }
    f.seek(SeekFrom::Start(slot_offset(g, slot)))
        .and_then(|_| f.write_all(&l.img))
        .and_then(|()| f.sync_all())
        .map_err(|e| err(format!("{}: {e}", path.display())))
}

fn random(out: &mut [u8]) -> Result<()> {
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(out))
        .map_err(|e| err(format!("read /dev/urandom: {e}")))
}

/// File `key` under `module`/`label` with `suite` and `usage`, sealed under
/// `record_key`.
fn file(
    l: &mut Loaded,
    record_key: &[u8; 32],
    module: &str,
    label: &[u8],
    suite: u16,
    usage: u32,
    key: &[u8],
) -> Result<()> {
    let f = record::Filing {
        namespace: fluxor_abi::wire::fnv1a32(module.as_bytes()),
        realm: None,
        label,
    };
    let mut nonce = [0u8; 12];
    random(&mut nonce)?;
    let mut rec = [0u8; record::MAX_RECORD];
    let n = record::encode(&f, suite, usage, key, Some(record_key), &nonce, &mut rec)
        .ok_or_else(|| err("the record does not encode (label or key too long)"))?;
    let mut name = [0u8; record::MAX_NAME];
    let nl = record::name(&f, &mut name).ok_or_else(|| err("label too long"))?;
    match image::change(&mut l.img, &name[..nl], Some(&rec[..n])) {
        image::Change::Changed(_) | image::Change::Unchanged => Ok(()),
        image::Change::Full => Err(err("the image has no room for the record")),
    }
}

/// The key filed under `module`/`label`: `(suite, usage, key)`, `None` when
/// there is none; an error for one that does not open under `record_key`.
fn read_key(
    l: &Loaded,
    record_key: &[u8; 32],
    module: &str,
    label: &[u8],
) -> Result<Option<(u16, u32, Vec<u8>)>> {
    let f = record::Filing {
        namespace: fluxor_abi::wire::fnv1a32(module.as_bytes()),
        realm: None,
        label,
    };
    let mut name = [0u8; record::MAX_NAME];
    let nl = record::name(&f, &mut name).ok_or_else(|| err("label too long"))?;
    let mut rec = [0u8; record::MAX_RECORD];
    let Some(n) = image::read(&l.img, &name[..nl], &mut rec) else {
        return Ok(None);
    };
    let (suite, usage, clear) =
        record::facts(&rec[..n]).ok_or_else(|| err("a malformed record is filed there"))?;
    let mut header = [0u8; record::MAX_HEADER];
    let h = record::header(&f, suite, usage, clear, &mut header)
        .ok_or_else(|| err("a malformed record is filed there"))?;
    if n < h || rec[..h] != header[..h] {
        return Err(err("the record filed there does not match its name"));
    }
    if clear {
        return Ok(Some((suite, usage, rec[h..n].to_vec())));
    }
    let mut key = [0u8; record::MAX_KEY];
    let k = record::open(record_key, &header[..h], &rec[h..n], &mut key)
        .ok_or_else(|| err("the record filed there does not open under this FLUXOR_SEAL_KEY"))?;
    Ok(Some((suite, usage, key[..k].to_vec())))
}

fn check_names(module: &str, label: &str) -> Result<()> {
    if module.is_empty() {
        return Err(err("--module names the module type that opens the key"));
    }
    if label.is_empty() || label.len() > kv::MAX_LABEL {
        return Err(err(format!("--label must be 1..={} bytes", kv::MAX_LABEL)));
    }
    Ok(())
}

/// The key `fluxor vault import` files: its suite (`hmac-sha256` or
/// `aead-key`), its 32 bytes as hex, and whether an `aead-key` may also wrap.
pub struct ImportKey<'a> {
    pub suite: &'a str,
    pub key_hex: &'a str,
    pub wrap: bool,
}

/// `fluxor vault import`: file a 32-byte symmetric key for module type
/// `module` under `label`.
pub fn import(
    path: &Path,
    g: &Geometry,
    seal_key: &[u8; 32],
    module: &str,
    label: &str,
    key: &ImportKey<'_>,
) -> Result<()> {
    let ImportKey {
        suite,
        key_hex,
        wrap,
    } = *key;
    check_names(module, label)?;
    let (suite_id, mut usage) = match suite {
        "hmac-sha256" => (
            kv::suite::HMAC_SHA256,
            kv::usage::SIGN | kv::usage::VERIFY | kv::usage::PERSIST,
        ),
        "aead-key" => (
            kv::suite::AEAD_KEY,
            kv::usage::SEAL | kv::usage::OPEN | kv::usage::PERSIST,
        ),
        _ => return Err(err("--suite must be hmac-sha256 or aead-key")),
    };
    if wrap {
        if suite_id != kv::suite::AEAD_KEY {
            return Err(err("--wrap yes applies to an aead-key only"));
        }
        usage |= kv::usage::WRAP;
    }
    let key = parse_key_hex(key_hex)
        .ok_or_else(|| err("--key-hex must be 64 hex characters (32 bytes)"))?;
    let rk = record_key(seal_key);
    let mut l = load(path, g)?;
    file(&mut l, &rk, module, label.as_bytes(), suite_id, usage, &key)?;
    save(path, g, &l)
}

/// `fluxor vault identity`: the P-256 signing identity module type `module`
/// opens under `label`, generated and filed when it does not exist yet; its
/// SEC1 public key.
pub fn identity(
    path: &Path,
    g: &Geometry,
    seal_key: &[u8; 32],
    module: &str,
    label: &str,
) -> Result<[u8; 65]> {
    use fluxor_sdk::crypto::p256;
    check_names(module, label)?;
    let want = kv::usage::SIGN | kv::usage::EXPORT_PUBLIC | kv::usage::PERSIST;
    let rk = record_key(seal_key);
    let mut l = load(path, g)?;
    let scalar: [u8; 32] = match read_key(&l, &rk, module, label.as_bytes())? {
        Some((suite, usage, key)) => {
            if suite != kv::suite::P256 || want & !usage != 0 || key.len() != 32 {
                return Err(err(
                    "the key filed there is not a P-256 signing identity (suite or uses differ)",
                ));
            }
            key.try_into().map_err(|_| err("bad key length"))?
        }
        None => {
            let mut k = [0u8; 32];
            loop {
                random(&mut k)?;
                if p256::decode_private_scalar(&k).is_some() {
                    break;
                }
            }
            file(
                &mut l,
                &rk,
                module,
                label.as_bytes(),
                kv::suite::P256,
                want,
                &k,
            )?;
            save(path, g, &l)?;
            k
        }
    };
    p256::public_key_from_scalar(&scalar).ok_or_else(|| err("the key is not a P-256 scalar"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fluxor-vault-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        d
    }

    #[test]
    fn an_imported_key_opens_under_the_derived_record_key_only() {
        let p = tmp("import");
        let g = Geometry::default();
        let seal = [7u8; 32];
        let hex = "ab".repeat(32);
        let k = ImportKey {
            suite: "hmac-sha256",
            key_hex: &hex,
            wrap: false,
        };
        import(&p, &g, &seal, "dns", "tsig", &k).expect("import");
        let l = load(&p, &g).expect("load");
        assert_eq!(l.from, Some(0), "the first image lands in slot A");
        let (suite, usage, key) = read_key(&l, &record_key(&seal), "dns", b"tsig")
            .expect("opens")
            .expect("present");
        assert_eq!(suite, kv::suite::HMAC_SHA256);
        assert_eq!(
            usage,
            kv::usage::SIGN | kv::usage::VERIFY | kv::usage::PERSIST
        );
        assert_eq!(key, vec![0xAB; 32]);
        assert!(read_key(&l, &record_key(&[8u8; 32]), "dns", b"tsig").is_err());
        // Another module type's namespace holds nothing.
        assert!(read_key(&l, &record_key(&seal), "tls", b"tsig")
            .expect("reads")
            .is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn images_alternate_slots_and_the_newer_wins() {
        let p = tmp("alternate");
        let g = Geometry {
            image_size: 1024,
            start_sector: 4,
        };
        let seal = [1u8; 32];
        let a = "01".repeat(32);
        let b = "02".repeat(32);
        let ka = ImportKey {
            suite: "aead-key",
            key_hex: &a,
            wrap: true,
        };
        let kb = ImportKey {
            suite: "aead-key",
            key_hex: &b,
            wrap: false,
        };
        import(&p, &g, &seal, "m", "a", &ka).expect("a");
        import(&p, &g, &seal, "m", "b", &kb).expect("b");
        let l = load(&p, &g).expect("load");
        assert_eq!(l.from, Some(1));
        assert_eq!(image::seq(&l.img), 2);
        let rk = record_key(&seal);
        let (_, usage, _) = read_key(&l, &rk, "m", b"a").expect("a").expect("a");
        assert_ne!(usage & kv::usage::WRAP, 0);
        assert!(read_key(&l, &rk, "m", b"b").expect("b").is_some());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn an_identity_is_made_once_and_then_reopened() {
        let p = tmp("identity");
        let g = Geometry::default();
        let seal = [3u8; 32];
        let a = identity(&p, &g, &seal, "tls", "tls-custody").expect("made");
        let b = identity(&p, &g, &seal, "tls", "tls-custody").expect("reopened");
        assert_eq!(a, b);
        assert_eq!(a[0], 4);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn the_record_key_is_the_kernel_derivation() {
        let seal = [9u8; 32];
        let want = fluxor_sdk::crypto::seal::derive(
            &seal,
            fluxor_abi::wire::fnv1a32(b"key_vault"),
            b"records",
        )
        .expect("ctx fits");
        assert_eq!(record_key(&seal), want);
    }
}

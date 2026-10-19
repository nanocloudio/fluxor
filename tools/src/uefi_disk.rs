//! The disk a UEFI machine boots: GPT with one EFI system partition, FAT32,
//! holding the fluxor loader where the firmware looks by default and the
//! kernel image beside it.
//!
//! ```text
//! LBA 0          protective MBR
//! LBA 1          primary GPT header
//! LBA 2..33      partition entries (128 × 128 bytes)
//! LBA 2048..     the ESP:  the loader at the target's `loader_path`
//!                          (EFI/BOOT/BOOTAA64.EFI on aarch64)
//!                          fluxor/fluxor.img
//! LBA n-33..n-2  backup partition entries
//! LBA n-1        backup GPT header
//! ```
//!
//! The file is sparse and exactly [`DISK_BYTES`], so the backup header sits
//! at the last LBA a volume of that size has: 1 GiB, the smallest volume a
//! cloud machine boots from, and room to spare for an image of tens of MiB. The partition table is written here; the FAT is
//! made and filled by `mformat`/`mcopy` (mtools), the same class of host
//! tool as `picotool` and `qemu-img`.
//!
//! The GUIDs are derived from the ESP's contents, so the same inputs make
//! the same disk byte for byte.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const SECTOR: u64 = 512;
/// The ESP starts at 1 MiB: aligned for every block size a cloud volume or
/// an NVMe namespace uses.
const ESP_FIRST_LBA: u64 = 2048;
const ENTRIES: u64 = 128;
const ENTRY_SIZE: u64 = 128;
/// LBAs the partition entry array takes: 128 × 128 / 512.
const ENTRY_LBAS: u64 = ENTRIES * ENTRY_SIZE / SECTOR;

/// The disk's size.
pub const DISK_BYTES: u64 = 1 << 30;

/// The smallest disk the layout fits: the ESP must hold a FAT32 volume,
/// which mtools will not make below 32 MiB of clusters.
const MIN_DISK_BYTES: u64 = 64 << 20;

/// `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`, the EFI system partition type.
const ESP_TYPE: [u8; 16] = guid_bytes(
    0xC12A_7328,
    0xF81F,
    0x11D2,
    [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
);

/// One file to place on the ESP.
#[derive(Debug, Clone)]
pub struct EspFile {
    /// Its path on the ESP, `/`-separated, e.g. `EFI/BOOT/BOOTAA64.EFI`.
    pub esp_path: String,
    pub source: PathBuf,
}

/// What was written.
#[derive(Debug, Clone)]
pub struct DiskReport {
    pub disk_guid: String,
    pub files: Vec<FileReport>,
}

#[derive(Debug, Clone)]
pub struct FileReport {
    pub esp_path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Build the disk at `out`, `size` bytes, with `files` on its ESP.
pub fn build(out: &Path, size: u64, files: &[EspFile]) -> Result<DiskReport> {
    if size < MIN_DISK_BYTES || !size.is_multiple_of(SECTOR) {
        return Err(Error::Config(format!(
            "uefi disk: {size} bytes is not a whole number of sectors of at least {MIN_DISK_BYTES}"
        )));
    }
    let mut file_reports = Vec::new();
    let mut identity = Sha256::new();
    for f in files {
        let bytes = std::fs::read(&f.source).map_err(|e| {
            Error::Config(format!("uefi disk: reading {}: {e}", f.source.display()))
        })?;
        let digest = Sha256::digest(&bytes);
        identity.update(f.esp_path.as_bytes());
        identity.update(digest);
        file_reports.push(FileReport {
            esp_path: f.esp_path.clone(),
            bytes: bytes.len() as u64,
            sha256: crate::hash::hex(&digest),
        });
    }
    identity.update(size.to_le_bytes());
    let id = identity.finalize();
    let disk_guid = v4_guid(&id[..16]);
    let part_guid = v4_guid(&id[16..]);

    let total = size / SECTOR;
    let last_usable = total - 1 - ENTRY_LBAS - 1;
    let esp_last = last_usable;

    // The sparse file, then the tables.
    let _ = std::fs::remove_file(out);
    let mut disk = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out)
        .map_err(|e| Error::Config(format!("uefi disk: creating {}: {e}", out.display())))?;
    disk.set_len(size)
        .map_err(|e| Error::Config(format!("uefi disk: sizing {}: {e}", out.display())))?;

    let entries = partition_entries(&part_guid, ESP_FIRST_LBA, esp_last);
    let entries_crc = crc32(&entries);
    let primary = gpt_header(1, total - 1, 2, last_usable, &disk_guid, entries_crc);
    let backup = gpt_header(
        total - 1,
        1,
        total - 1 - ENTRY_LBAS,
        last_usable,
        &disk_guid,
        entries_crc,
    );

    let write_at = |disk: &mut std::fs::File, lba: u64, bytes: &[u8]| -> Result<()> {
        disk.seek(SeekFrom::Start(lba * SECTOR))
            .and_then(|_| disk.write_all(bytes))
            .map_err(|e| Error::Config(format!("uefi disk: writing {}: {e}", out.display())))
    };
    write_at(&mut disk, 0, &protective_mbr(total))?;
    write_at(&mut disk, 1, &primary)?;
    write_at(&mut disk, 2, &entries)?;
    write_at(&mut disk, total - 1 - ENTRY_LBAS, &entries)?;
    write_at(&mut disk, total - 1, &backup)?;
    drop(disk);

    // The FAT, inside the partition.
    let esp_sectors = esp_last - ESP_FIRST_LBA + 1;
    let image = format!("{}@@{}", out.display(), ESP_FIRST_LBA * SECTOR);
    mtool(
        "mformat",
        &[
            "-i",
            &image,
            "-F",
            "-T",
            &esp_sectors.to_string(),
            "-v",
            "FLUXOR",
            "::",
        ],
    )?;
    let mut made = std::collections::BTreeSet::new();
    for f in files {
        let parts: Vec<&str> = f.esp_path.split('/').collect();
        for depth in 1..parts.len() {
            let dir = format!("::/{}", parts[..depth].join("/"));
            if made.insert(dir.clone()) {
                mtool("mmd", &["-i", &image, &dir])?;
            }
        }
        let src = f.source.display().to_string();
        mtool(
            "mcopy",
            &["-i", &image, &src, &format!("::/{}", f.esp_path)],
        )?;
    }

    Ok(DiskReport {
        disk_guid: guid_string(&disk_guid),
        files: file_reports,
    })
}

fn mtool(tool: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(tool).args(args).output().map_err(|e| {
        Error::Config(format!(
            "uefi disk: running `{tool}`: {e} — the ESP is made with mtools \
             (`apt install mtools`)"
        ))
    })?;
    if !out.status.success() {
        return Err(Error::Config(format!(
            "uefi disk: `{tool} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

// ── GPT ──────────────────────────────────────────────────────────────────────

fn protective_mbr(total: u64) -> [u8; 512] {
    let mut m = [0u8; 512];
    let e = &mut m[446..462];
    e[0] = 0x00; // not bootable
    e[1..4].copy_from_slice(&[0x00, 0x02, 0x00]); // CHS of LBA 1
    e[4] = 0xEE; // GPT protective
    e[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    e[8..12].copy_from_slice(&1u32.to_le_bytes());
    let len = (total - 1).min(u32::MAX as u64) as u32;
    e[12..16].copy_from_slice(&len.to_le_bytes());
    m[510] = 0x55;
    m[511] = 0xAA;
    m
}

fn partition_entries(part_guid: &[u8; 16], first: u64, last: u64) -> Vec<u8> {
    let mut v = vec![0u8; (ENTRIES * ENTRY_SIZE) as usize];
    let e = &mut v[..ENTRY_SIZE as usize];
    e[0..16].copy_from_slice(&ESP_TYPE);
    e[16..32].copy_from_slice(part_guid);
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    // Attributes 0; the name, UTF-16LE, up to 36 code units.
    for (i, u) in "EFI system partition".encode_utf16().enumerate() {
        e[56 + 2 * i..58 + 2 * i].copy_from_slice(&u.to_le_bytes());
    }
    v
}

fn gpt_header(
    my_lba: u64,
    alternate_lba: u64,
    entries_lba: u64,
    last_usable: u64,
    disk_guid: &[u8; 16],
    entries_crc: u32,
) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    h[12..16].copy_from_slice(&92u32.to_le_bytes());
    // 16..20 header CRC, computed below over 92 bytes with it zeroed.
    h[24..32].copy_from_slice(&my_lba.to_le_bytes());
    h[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    h[40..48].copy_from_slice(&(2 + ENTRY_LBAS).to_le_bytes()); // first usable
    h[48..56].copy_from_slice(&last_usable.to_le_bytes());
    h[56..72].copy_from_slice(disk_guid);
    h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    h[80..84].copy_from_slice(&(ENTRIES as u32).to_le_bytes());
    h[84..88].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
    h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32(&h[..92]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    h
}

/// A GUID's on-disk bytes: the first three fields little-endian.
const fn guid_bytes(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// Sixteen bytes of a digest made into a well-formed random-kind (version 4)
/// GUID, in on-disk byte order.
fn v4_guid(seed: &[u8]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g.copy_from_slice(&seed[..16]);
    // Version 4 in the high nibble of field 3 (bytes 6..8 little-endian),
    // variant 10xx in byte 8.
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    g
}

fn guid_string(g: &[u8; 16]) -> String {
    let a = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let b = u16::from_le_bytes([g[4], g[5]]);
    let c = u16::from_le_bytes([g[6], g[7]]);
    format!(
        "{a:08x}-{b:04x}-{c:04x}-{:02x}{:02x}-{}",
        g[8],
        g[9],
        crate::hash::hex(&g[10..])
    )
}

/// CRC-32 (IEEE 802.3, reflected), the checksum GPT uses.
fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn the_esp_type_guid_has_its_on_disk_byte_order() {
        assert_eq!(
            ESP_TYPE,
            [
                0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
                0xC9, 0x3B
            ]
        );
    }

    fn mtools_present() -> bool {
        Command::new("mformat").arg("--version").output().is_ok()
    }

    /// The disk carries both GPT headers at the LBAs a volume of its size
    /// has, their CRCs hold, the ESP covers the usable space, and the files
    /// read back from the FAT byte for byte. The same inputs make the same
    /// disk.
    #[test]
    fn builds_a_gpt_disk_whose_esp_holds_the_files() {
        if !mtools_present() {
            eprintln!("mtools not installed; skipping the FAT half");
            return;
        }
        let dir = crate::rig::test_utils::unique_tmp_dir("uefi-disk");
        let loader = dir.join("loader.efi");
        let img = dir.join("fluxor.img");
        std::fs::write(&loader, b"MZ loader bytes").unwrap();
        std::fs::write(&img, vec![0xA5u8; 300_000]).unwrap();
        let files = [
            EspFile {
                esp_path: "EFI/BOOT/BOOTAA64.EFI".into(),
                source: loader.clone(),
            },
            EspFile {
                esp_path: "fluxor/fluxor.img".into(),
                source: img.clone(),
            },
        ];
        let disk = dir.join("fluxor.disk");
        let size = 96 << 20;
        let report = build(&disk, size, &files).unwrap();
        assert_eq!(std::fs::metadata(&disk).unwrap().len(), size);

        let raw = std::fs::read(&disk).unwrap();
        let total = size / SECTOR;
        let lba = |n: u64| &raw[(n * SECTOR) as usize..((n + 1) * SECTOR) as usize];
        assert_eq!(&lba(0)[510..], &[0x55, 0xAA]);
        assert_eq!(lba(0)[446 + 4], 0xEE);
        for (at, me, alt) in [(1, 1, total - 1), (total - 1, total - 1, 1)] {
            let h = lba(at);
            assert_eq!(&h[..8], b"EFI PART", "header at LBA {at}");
            let mut z = h[..92].to_vec();
            z[16..20].fill(0);
            assert_eq!(crc32(&z), u32::from_le_bytes(h[16..20].try_into().unwrap()));
            assert_eq!(u64::from_le_bytes(h[24..32].try_into().unwrap()), me);
            assert_eq!(u64::from_le_bytes(h[32..40].try_into().unwrap()), alt);
            let entries_lba = u64::from_le_bytes(h[72..80].try_into().unwrap());
            let entries = &raw
                [(entries_lba * SECTOR) as usize..((entries_lba + ENTRY_LBAS) * SECTOR) as usize];
            assert_eq!(
                crc32(entries),
                u32::from_le_bytes(h[88..92].try_into().unwrap())
            );
            assert_eq!(&entries[..16], &ESP_TYPE);
        }
        let entries_end = u64::from_le_bytes(lba(1)[48..56].try_into().unwrap());
        assert_eq!(entries_end, total - 1 - ENTRY_LBAS - 1, "last usable LBA");
        assert_eq!(report.files.len(), 2);

        let image = format!("{}@@{}", disk.display(), ESP_FIRST_LBA * SECTOR);
        for f in &files {
            let back = dir.join("back");
            let st = Command::new("mcopy")
                .args(["-n", "-i", &image, &format!("::/{}", f.esp_path)])
                .arg(&back)
                .status()
                .unwrap();
            assert!(st.success(), "{} reads back", f.esp_path);
            assert_eq!(
                std::fs::read(&back).unwrap(),
                std::fs::read(&f.source).unwrap()
            );
            std::fs::remove_file(&back).unwrap();
        }

        // Determinism: the GUIDs come from the contents, not the moment.
        let again = build(&dir.join("again.disk"), size, &files).unwrap();
        assert_eq!(again.disk_guid, report.disk_guid);
    }
}

// Runtime parameter overrides on Linux: the file-backed twin of the RP
// flash sector.
//
// The contract is the same on both platforms and so is the timing: a stored
// value is read ONCE at boot into a RAM table and merged into a module's
// compiled parameters immediately before it is instantiated. Nothing is
// re-read while a graph runs, because a parameter that changed under a
// module mid-step would be a different module than the one that started.
//
// What differs is only the medium. RP writes a flash sector; here it is a
// file, named by `FLUXOR_PARAM_STORE` or defaulting beside the rest of a
// workload's state. The layout is deliberately the simplest thing that
// round-trips:
//
//     "FXPS" version:u8=1 count:u8
//     [module_id:u8][tag:u8][value_len:u8][value[value_len]] * count
//
// A file that does not parse is ignored with a warning rather than failing
// the boot: an override store is an operator's convenience, and a corrupt
// one must not be the reason a deployment will not start. The compiled
// parameter is always a valid answer.

use std::sync::OnceLock;

const MAGIC: &[u8; 4] = b"FXPS";
const VERSION: u8 = 1;

/// As many overrides as the RP sector holds, so a deployment that works on
/// one platform is not surprised by the other.
const MAX_OVERRIDES: usize = 32;
/// The contract's own ceiling on one stored value.
const MAX_VALUE: usize = 250;

#[derive(Clone)]
struct Override {
    module_id: u8,
    tag: u8,
    value: Vec<u8>,
}

static TABLE: OnceLock<Vec<Override>> = OnceLock::new();

fn store_path() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("FLUXOR_PARAM_STORE") {
        return Some(std::path::PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/state"))
        })?;
    Some(base.join("fluxor/params.bin"))
}

fn parse(bytes: &[u8]) -> Option<Vec<Override>> {
    if bytes.len() < 6 || &bytes[..4] != MAGIC || bytes[4] != VERSION {
        return None;
    }
    let count = usize::from(bytes[5]);
    if count > MAX_OVERRIDES {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    let mut at = 6usize;
    for _ in 0..count {
        let module_id = *bytes.get(at)?;
        let tag = *bytes.get(at + 1)?;
        let len = usize::from(*bytes.get(at + 2)?);
        if len > MAX_VALUE {
            return None;
        }
        let value = bytes.get(at + 3..at + 3 + len)?.to_vec();
        at += 3 + len;
        out.push(Override {
            module_id,
            tag,
            value,
        });
    }
    Some(out)
}

/// Read the store once. Called at boot, before any module is instantiated.
pub fn boot_scan() {
    let _ = TABLE.get_or_init(|| {
        let Some(path) = store_path() else {
            return Vec::new();
        };
        let Ok(bytes) = std::fs::read(&path) else {
            return Vec::new();
        };
        match parse(&bytes) {
            Some(table) => {
                if !table.is_empty() {
                    log::info!(
                        "[params] {} runtime override(s) from {}",
                        table.len(),
                        path.display()
                    );
                }
                table
            }
            None => {
                log::warn!(
                    "[params] {} does not parse as a parameter store; ignoring it",
                    path.display()
                );
                Vec::new()
            }
        }
    });
}

fn table() -> &'static [Override] {
    boot_scan();
    TABLE.get().map(Vec::as_slice).unwrap_or(&[])
}

/// Append this module's overrides after its compiled parameters, so
/// `parse_tlv`'s last-writer-wins gives the stored value.
///
/// The TLV v2 shape is the RP implementation's, entry for entry: magic
/// 0xFE, version 0x02, a `u16` payload length, then `[tag][len][value]`
/// entries terminated by 0xFF.
///
/// # Safety
/// `buf` points to `max` writable bytes of which the first `len` are the
/// module's compiled parameters, as the HAL hook promises.
pub unsafe fn merge_runtime_overrides(
    module_id: u16,
    buf: *mut u8,
    len: usize,
    max: usize,
) -> usize {
    let overrides = table();
    if overrides.is_empty() || max < 4 || buf.is_null() {
        return len;
    }
    let id = u8::try_from(module_id).unwrap_or(u8::MAX);
    if !overrides.iter().any(|o| o.module_id == id) {
        return len;
    }
    let mut pos = len;
    if pos < 4 {
        // No compiled parameters: write the header this module would have
        // had, so the overrides have somewhere to be.
        *buf.add(0) = 0xFE;
        *buf.add(1) = 0x02;
        *buf.add(2) = 0;
        *buf.add(3) = 0;
        pos = 4;
    }
    // Where the compiled entries end: the declared payload length when it
    // is sane, else a walk to the 0xFF terminator.
    let declared = usize::from(u16::from_le_bytes([*buf.add(2), *buf.add(3)]));
    let mut write_at = if declared > 0 && 4 + declared <= pos {
        4 + declared
    } else {
        let mut p = 4usize;
        while p + 2 <= pos {
            if *buf.add(p) == 0xFF {
                break;
            }
            let entry_len = usize::from(*buf.add(p + 1));
            p += 2 + entry_len;
        }
        p
    };
    for o in overrides.iter().filter(|o| o.module_id == id) {
        let needed = 2 + o.value.len();
        // One byte is kept for the terminator; an override that does not
        // fit is dropped rather than half-written.
        if write_at + needed + 1 > max {
            log::warn!(
                "[params] override tag {} for module {} does not fit; compiled value stands",
                o.tag,
                id
            );
            break;
        }
        *buf.add(write_at) = o.tag;
        *buf.add(write_at + 1) = u8::try_from(o.value.len()).unwrap_or(0);
        if !o.value.is_empty() {
            core::ptr::copy_nonoverlapping(o.value.as_ptr(), buf.add(write_at + 2), o.value.len());
        }
        write_at += needed;
    }
    if write_at < max {
        *buf.add(write_at) = 0xFF;
        write_at += 1;
    }
    write_at
}

/// Write a store file. The CLI uses this to turn operator intent — an
/// applet's `--grant http=<origins>`, say — into the parameter a module
/// reads at instantiation, without the module learning where it came from.
pub fn write_store(path: &std::path::Path, entries: &[(u8, u8, Vec<u8>)]) -> std::io::Result<()> {
    if entries.len() > MAX_OVERRIDES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "too many overrides",
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(u8::try_from(entries.len()).unwrap_or(0));
    for (module_id, tag, value) in entries {
        if value.len() > MAX_VALUE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "override value too long",
            ));
        }
        out.push(*module_id);
        out.push(*tag);
        out.push(u8::try_from(value.len()).unwrap_or(0));
        out.extend_from_slice(value);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_round_trips() {
        let entries = vec![(3u8, 7u8, b"nanocloud.io".to_vec())];
        let dir = std::env::temp_dir().join("fluxor-param-store-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("params.bin");
        write_store(&path, &entries).expect("write");
        let bytes = std::fs::read(&path).expect("read");
        let parsed = parse(&bytes).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].module_id, 3);
        assert_eq!(parsed[0].tag, 7);
        assert_eq!(parsed[0].value, b"nanocloud.io");
    }

    #[test]
    fn a_corrupt_store_is_ignored_rather_than_fatal() {
        assert!(parse(b"nope").is_none());
        assert!(parse(b"FXPS\x02\x00").is_none(), "wrong version");
        // A count that overruns the buffer.
        assert!(parse(b"FXPS\x01\x05").is_none());
    }
}

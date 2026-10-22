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

/// The store's one-byte id for module `module_id`, or `None` when the id does
/// not fit one: no stored override can address that module, so it gets its
/// compiled params. Never a clamp — folding every high id onto 255 would hand
/// those modules the overrides stored for module 255.
fn stored_id(module_id: u16) -> Option<u8> {
    u8::try_from(module_id).ok()
}

/// Where a module's compiled params and its stored overrides are merged, one
/// instance at a time (`RuntimeParams::Merged`). Grown to the merge it holds:
/// there is no fixed ceiling on a merged block.
static MERGED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// The merged params of module `module_id`: `None` when the store holds no
/// override for it (it gets its compiled params in place, with no copy),
/// else `(ptr, len)` of its compiled params with the overrides merged over
/// them, in `MERGED`, sized to what the merge needs and valid until the next
/// call.
pub fn merged_params(module_id: u16, compiled: &[u8]) -> Option<(*const u8, usize)> {
    // The store addresses a module by a one-byte id, so a module whose id is
    // past it has no override (`stored_id`).
    let id = stored_id(module_id)?;
    let mine = || table().iter().filter(move |o| o.module_id == id);
    let n = mine().count();
    if n == 0 {
        return None;
    }
    let value_bytes: usize = mine().map(|o| o.value.len()).sum();
    // Room for every override entry, plus the header and terminator the
    // compiled params may lack.
    let max = compiled.len() + params_tlv::merge_room(n, value_bytes);
    let mut buf = MERGED.lock().unwrap_or_else(|e| e.into_inner());
    buf.clear();
    buf.resize(max, 0);
    buf[..compiled.len()].copy_from_slice(compiled);
    // Inserted before the basic section's terminator; the terminator and the
    // extended entries after it (certificates, keys, trust bundles) move up
    // whole, so a module with an override keeps its trust anchors.
    let merged = params_tlv::merge_overrides(
        &mut buf,
        compiled.len(),
        mine().map(|o| (o.tag, o.value.as_slice())),
    );
    if merged.dropped != 0 {
        log::warn!(
            "[params] {} override(s) for module {} do not fit; compiled values stand",
            merged.dropped,
            id
        );
    }
    // The Vec's heap block outlives the guard: nothing touches it until the
    // next call, which is the lifetime promised.
    Some((buf.as_ptr(), merged.len))
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

// host_asset_source built-in — streams a host file as OctetStream.
//
// Params declared in `modules/builtin/host/host_asset_source/manifest.toml`:
//   path: filesystem path to the asset (required, no default)
//
// Tag layout (declaration order, starting at 10):
//   10: path (str)

use std::fs::File;
use std::io::Read;

const HOST_ASSET_SOURCE_HASH: u32 = 0x504EEEF0; // fnv1a32("host_asset_source")
// Stay well below the smallest channel buffer (2 KB by default) — the
// kernel's ring `write` is all-or-nothing, so a chunk larger than the
// channel never gets written.
const CHUNK_SIZE: usize = 1024;

const ASSET_TAG_PATH: u8 = 10;

struct HostAssetState {
    out_chan: i32,
    file: Option<File>,
    eof: bool,
    /// Bytes read from the file but not yet written into the output
    /// channel (consumer was full). Drained before the next file read.
    pending: Vec<u8>,
    pending_pos: usize,
}

fn host_asset_step(state: *mut u8) -> i32 {
    let st = unsafe { instance_state::<HostAssetState>(state) };

    if st.out_chan < 0 {
        return 1;
    }

    // Drain pending bytes left over from a previous step where the
    // channel didn't have room. Only after pending clears do we read
    // more from the file — this preserves byte order and prevents
    // truncation when the consumer back-pressures.
    while st.pending_pos < st.pending.len() {
        let w = unsafe {
            channel::channel_write(
                st.out_chan,
                st.pending.as_ptr().add(st.pending_pos),
                st.pending.len() - st.pending_pos,
            )
        };
        if w > 0 {
            st.pending_pos += w as usize;
        } else {
            return 0;
        }
    }
    st.pending.clear();
    st.pending_pos = 0;

    if st.eof {
        return 1;
    }
    let Some(file) = st.file.as_mut() else {
        return 1;
    };

    let mut buf = [0u8; CHUNK_SIZE];
    let n = match file.read(&mut buf) {
        Ok(0) => {
            st.eof = true;
            log::info!("[host_asset] eof");
            return 1;
        }
        Ok(n) => n,
        Err(e) => {
            log::warn!("[host_asset] read error: {}", e);
            st.eof = true;
            return 1;
        }
    };

    let mut written = 0usize;
    while written < n {
        let w = unsafe {
            channel::channel_write(
                st.out_chan,
                buf.as_ptr().add(written),
                n - written,
            )
        };
        if w > 0 {
            written += w as usize;
        } else {
            // Channel full. Stash the remainder for the next step.
            st.pending.extend_from_slice(&buf[written..n]);
            return 0;
        }
    }
    0
}

/// Construct a `host_asset_source` BuiltInModule. Resolves params,
/// opens the asset file, and stashes per-instance state in the
/// bootstrap buffer so multiple `host_asset_source` modules in the
/// same graph keep separate state.
fn build_host_asset_source(module_idx: usize, params: &[u8]) -> scheduler::BuiltInModule {
    let mut path = String::new();
    walk_tlv(params, |tag, value| {
        if tag == ASSET_TAG_PATH {
            path = tlv_str(value).to_string();
        }
    });
    // `path` carries `required = true` in the manifest, so an empty
    // string here means the loader skipped its TLV validation.
    debug_assert!(!path.is_empty(), "host_asset_source: empty path");

    scheduler::set_current_module(module_idx);
    let out_chan = scheduler::get_module_port(module_idx, 1, 0);

    let (file, eof) = match File::open(&path) {
        Ok(f) => {
            log::info!("[host_asset] streaming {}", path);
            (Some(f), false)
        }
        Err(e) => {
            log::warn!("[host_asset] open '{}' failed: {}", path, e);
            (None, true)
        }
    };

    let mut m = scheduler::BuiltInModule::new("host_asset_source", host_asset_step);
    install_state(
        &mut m,
        Box::new(HostAssetState {
            out_chan,
            file,
            eof,
            pending: Vec::new(),
            pending_pos: 0,
        }),
    );
    log::info!(
        "[inst] module {} = host_asset_source (built-in) out={} path='{}'",
        module_idx, out_chan, path
    );
    m
}

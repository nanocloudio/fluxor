// host_asset_index built-in — indexed bank of host file paths.
//
// On IOCTL_NOTIFY(idx) received over the output channel (sent upstream
// by foundation/http via its file_ctrl), opens paths[idx] and streams
// its bytes through the same channel. Signals end-of-stream via
// IOCTL_SET_HUP so the consumer's HANDLER_FILE flow finalizes. The
// channel's hup flag is cleared by the consumer's own IOCTL_FLUSH on
// the next fetch (foundation/http already does this in
// `cache_try_or_fetch`).
//
// Params declared in
// `modules/builtin/host/host_asset_index/manifest.toml`:
//   paths: newline-separated list of filesystem paths (required).
//          Index in the list is the source_index a HANDLER_FILE route
//          declares to select that asset.
//
// Tag layout (declaration order, starting at 10):
//   10: paths (str)

// `File`, `Read`, and `CHUNK_SIZE` are pulled in via the sibling
// `host_asset_source.rs` `include!()` in `linux.rs`; both files share
// the parent module's namespace.

const HOST_ASSET_INDEX_HASH: u32 = 0xFB4428B3; // fnv1a32("host_asset_index")

const ASSET_INDEX_TAG_PATHS: u8 = 10;

struct HostAssetIndexState {
    out_chan: i32,
    paths: Vec<String>,
    /// Currently-open file (if any). Cleared on EOF or seek-out-of-range.
    current: Option<File>,
    /// Bytes read from the file but not yet written into the output
    /// channel (consumer was full). Drained before the next file read.
    pending: Vec<u8>,
    pending_pos: usize,
}

fn host_asset_index_step(state: *mut u8) -> i32 {
    let st = unsafe { instance_state::<HostAssetIndexState>(state) };

    if st.out_chan < 0 {
        return 1;
    }

    // 1. Drain any pending bytes from the previous step. The consumer
    //    must catch up before we read more from the file — preserves
    //    byte order under back-pressure.
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

    // 2. Check for an upstream NOTIFY: switch to a new asset.
    let mut seek_idx: u32 = 0;
    let res = fluxor::kernel::channel::channel_ioctl(
        st.out_chan,
        fluxor::kernel::channel::IOCTL_POLL_NOTIFY,
        &mut seek_idx as *mut u32 as *mut u8,
    );
    if res == 0 {
        // CHAN_OK: a new seek arrived. Open the file fresh.
        let idx = seek_idx as usize;
        if idx < st.paths.len() {
            match File::open(&st.paths[idx]) {
                Ok(f) => {
                    log::info!(
                        "[host_asset_index] streaming idx={} path={}",
                        idx, st.paths[idx]
                    );
                    st.current = Some(f);
                }
                Err(e) => {
                    log::warn!(
                        "[host_asset_index] open '{}' failed: {}",
                        st.paths[idx], e
                    );
                    st.current = None;
                    // Signal HUP so the consumer doesn't block forever.
                    fluxor::kernel::channel::channel_ioctl(
                        st.out_chan,
                        fluxor::kernel::channel::IOCTL_SET_HUP,
                        core::ptr::null_mut(),
                    );
                }
            }
        } else {
            log::warn!(
                "[host_asset_index] seek idx={} out of range (have {} paths)",
                idx, st.paths.len()
            );
            st.current = None;
            fluxor::kernel::channel::channel_ioctl(
                st.out_chan,
                fluxor::kernel::channel::IOCTL_SET_HUP,
                core::ptr::null_mut(),
            );
        }
    }

    // 3. Stream bytes from the current file, if any.
    let Some(file) = st.current.as_mut() else {
        return 0;
    };

    let mut buf = [0u8; CHUNK_SIZE];
    let n = match file.read(&mut buf) {
        Ok(0) => {
            // EOF reached. Signal HUP and close the file. The consumer
            // (e.g. foundation/http) flushes the channel before its
            // next IOCTL_NOTIFY, which clears the hup flag.
            fluxor::kernel::channel::channel_ioctl(
                st.out_chan,
                fluxor::kernel::channel::IOCTL_SET_HUP,
                core::ptr::null_mut(),
            );
            st.current = None;
            return 0;
        }
        Ok(n) => n,
        Err(e) => {
            log::warn!("[host_asset_index] read error: {}", e);
            fluxor::kernel::channel::channel_ioctl(
                st.out_chan,
                fluxor::kernel::channel::IOCTL_SET_HUP,
                core::ptr::null_mut(),
            );
            st.current = None;
            return 0;
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

/// Construct a `host_asset_index` BuiltInModule. Resolves params,
/// splits the newline-separated paths string, and stashes per-instance
/// state so multiple `host_asset_index` modules in the same graph keep
/// separate state.
fn build_host_asset_index(module_idx: usize, params: &[u8]) -> scheduler::BuiltInModule {
    let mut paths_str = String::new();
    walk_tlv(params, |tag, value| {
        if tag == ASSET_INDEX_TAG_PATHS {
            paths_str = tlv_str(value).to_string();
        }
    });
    // `paths` carries `required = true` in the manifest, so an empty
    // string here means the loader skipped its TLV validation.
    let paths: Vec<String> = paths_str
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    debug_assert!(!paths.is_empty(), "host_asset_index: empty paths");

    scheduler::set_current_module(module_idx);
    let out_chan = scheduler::get_module_port(module_idx, 1, 0);

    let mut m = scheduler::BuiltInModule::new("host_asset_index", host_asset_index_step);
    install_state(
        &mut m,
        Box::new(HostAssetIndexState {
            out_chan,
            paths: paths.clone(),
            current: None,
            pending: Vec::new(),
            pending_pos: 0,
        }),
    );
    log::info!(
        "[inst] module {} = host_asset_index (built-in) out={} paths={:?}",
        module_idx, out_chan, paths
    );
    m
}

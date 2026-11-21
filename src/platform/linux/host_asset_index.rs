// host_asset_index built-in — indexed bank of host file paths.
//
// Serves `stream_select` on its `stream` output: the consumer (e.g.
// foundation/http) binds the contract through its input port and calls
// `SELECT(idx)`; the module opens paths[idx] and streams its bytes through
// the channel, then ends the stream (`SET_HUP`) so the consumer's
// HANDLER_FILE flow finalizes. The consumer's own FLUSH before its next
// `SELECT` clears that HUP.
//
// Params declared in
// `modules/platform/wasm/host_asset_index/manifest.toml`:
//   paths: newline-separated list of filesystem paths (required).
//          Index in the list is the source_index a HANDLER_FILE route
//          declares to select that asset.
// Its TLV tag is declared there too, and generated into
// `abi::platform::native`.

// `File`, `Read`, and `CHUNK_SIZE` are pulled in via the sibling
// `host_asset_source.rs` `include!()` in `linux.rs`; both files share
// the parent module's namespace.


use fluxor::abi::platform::native::linux::host_asset_index as asset_index_tags;
use fluxor::abi::platform::native::linux::host_asset_index::TAG_PATHS as ASSET_INDEX_TAG_PATHS;

struct HostAssetIndexState {
    out_chan: i32,
    paths: Vec<String>,
    /// The index a `SELECT` asked for, until the step opens it.
    selected: Option<usize>,
    /// Currently-open file (if any). Cleared on EOF or seek-out-of-range.
    current: Option<File>,
    /// Bytes read from the file but not yet written into the output
    /// channel (consumer was full). Drained before the next file read.
    pending: Vec<u8>,
    pending_pos: usize,
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn host_asset_index_step(state: *mut u8) -> i32 {
    // SAFETY: kernel-owned arena sized to `HostAssetIndexState` by the loader.
    let st = unsafe { instance_state::<HostAssetIndexState>(state) };

    if st.out_chan < 0 {
        return 1;
    }

    // 1. Drain any pending bytes from the previous step. The consumer
    //    must catch up before we read more from the file — preserves
    //    byte order under back-pressure.
    while st.pending_pos < st.pending.len() {
        // SAFETY: `pending_pos < pending.len()` (loop condition); offset
        // stays within the owned Vec.
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

    // 2. A `SELECT` arrived: switch to that asset.
    if let Some(idx) = st.selected.take() {
        if idx < st.paths.len() {
            match File::open(&st.paths[idx]) {
                Ok(f) => {
                    log::info!(
                        "[host_asset_index] streaming idx={} path={}",
                        idx,
                        st.paths[idx]
                    );
                    st.current = Some(f);
                }
                Err(e) => {
                    log::warn!("[host_asset_index] open '{}' failed: {}", st.paths[idx], e);
                    st.current = None;
                    // Signal HUP so the consumer doesn't block forever.
                    channel::channel_set_hup(st.out_chan);
                }
            }
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
            // next `SELECT`, which clears the hup flag.
            channel::channel_set_hup(st.out_chan);
            st.current = None;
            return 0;
        }
        Ok(n) => n,
        Err(e) => {
            log::warn!("[host_asset_index] read error: {e}");
            channel::channel_set_hup(st.out_chan);
            st.current = None;
            return 0;
        }
    };

    let mut written = 0usize;
    while written < n {
        // SAFETY: `written < n <= buf.len()`; offset stays in-bounds.
        let w =
            unsafe { channel::channel_write(st.out_chan, buf.as_ptr().add(written), n - written) };
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

/// `stream_select` on `stream`: remember the index for the next step, which
/// opens it. `EINVAL` for an index past the paths.
///
/// # Safety
/// `state` is the `HostAssetIndexState` registered with this dispatch;
/// `arg[..arg_len]` is valid for the call.
unsafe extern "C" fn host_asset_index_select(
    state: *mut u8,
    _handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
    _data: *mut u8,
    _data_len: usize,
) -> i32 {
    use fluxor::abi::contracts::stream_select;
    if op != stream_select::SELECT {
        return fluxor::abi::errno::ENOSYS;
    }
    if state.is_null() || arg.is_null() {
        return fluxor::abi::errno::EINVAL;
    }
    // SAFETY: the caller hands back the state pointer registered with this
    // dispatch, the instance's leaked heap block, and `arg_len` bytes at
    // `arg`.
    let (st, arg) = unsafe {
        (
            &mut *state.cast::<HostAssetIndexState>(),
            core::slice::from_raw_parts(arg, arg_len),
        )
    };
    let idx = stream_select::select::parse(arg).and_then(|p| usize::try_from(p).ok());
    match idx {
        Some(idx) if idx < st.paths.len() => {
            st.selected = Some(idx);
            st.current = None;
            st.pending.clear();
            st.pending_pos = 0;
            0
        }
        _ => fluxor::abi::errno::EINVAL,
    }
}

/// Construct a `host_asset_index` instance. Resolves params,
/// splits the newline-separated paths string, and stashes per-instance
/// state so multiple `host_asset_index` modules in the same graph keep
/// separate state.
fn build_host_asset_index(module_idx: usize, params: &[u8]) -> Result<Box<HostAssetIndexState>, i32> {
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
    let out_chan = scheduler::module_port(module_idx, asset_index_tags::PORT_STREAM);
    let mut st = Box::new(HostAssetIndexState {
        out_chan,
        paths: paths.clone(),
        selected: None,
        current: None,
        pending: Vec::new(),
        pending_pos: 0,
    });
    // The heap block stays put for the instance's life (the slot's release
    // drops it after the graph's provider layers are reset), so the edge
    // server's state pointer stays valid.
    let state = (&mut *st as *mut HostAssetIndexState).cast::<u8>();
    let rc = fluxor::kernel::module::provider::register_builtin_edge_server(
        fluxor::abi::registry::stream_select::ID,
        module_idx as scheduler::ModuleId,
        host_asset_index_select,
        state,
    );
    if rc < 0 {
        log::warn!("[host_asset_index] module {module_idx}: stream_select not served: {rc}");
    }
    log::info!(
        "[inst] module {module_idx} = host_asset_index (built-in) out={out_chan} paths={paths:?}"
    );
    Ok(st)
}

impl HostNative for HostAssetIndexState {
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32> {
        build_host_asset_index(slot, params)
    }
}

/// The `host_asset_index` native module.
pub static HOST_ASSET_INDEX: NativeVtable = host_vtable::<HostAssetIndexState>(host_asset_index_step);

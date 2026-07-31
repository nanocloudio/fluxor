//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

// ============================================================================
// Static Storage
// ============================================================================

pub(crate) static mut STATIC_CONFIG: Config = Config::empty();
pub(crate) static mut STATIC_LOADER: ModuleLoader = ModuleLoader::new();

/// Get a reference to the static loader.
///
/// # Safety
/// Returns a `&'static ModuleLoader` aliasing the static `STATIC_LOADER`.
/// Caller must not hold a `static_loader_mut()` borrow concurrently.
pub unsafe fn static_loader() -> &'static ModuleLoader {
    let p = &raw const STATIC_LOADER;
    &*p
}

/// Mutable access to the static loader for platforms that initialize
/// it themselves (e.g. Pi 5 scans flash via the trailer).
///
/// # Safety
/// Returns an exclusive `&mut` to `STATIC_LOADER`. Only sound during
/// platform init before any module is stepped, or from the
/// reconfigure code path which is single-threaded by the
/// `reconfigure_phase` state machine.
pub unsafe fn static_loader_mut() -> &'static mut ModuleLoader {
    let p = &raw mut STATIC_LOADER;
    &mut *p
}

/// Mutable access to the static config, paired with `static_loader_mut`.
///
/// # Safety
/// Returns an exclusive `&mut` to `STATIC_CONFIG`. Same constraints as
/// `static_loader_mut`: init-time or single-threaded reconfigure only.
pub unsafe fn static_config_mut() -> &'static mut Config {
    let p = &raw mut STATIC_CONFIG;
    &mut *p
}

/// Get a reference to the static config. Returns the parsed FXWR header
/// + module list + edge list that `prepare_graph` consumes.
///
/// # Safety
/// Returns a `&'static Config` aliasing `STATIC_CONFIG`. Caller must not
/// hold a `static_config_mut()` borrow concurrently.
pub unsafe fn static_config() -> &'static Config {
    let p = &raw const STATIC_CONFIG;
    &*p
}

/// Install a fully-formed `Config` directly into the static slot. Used
/// by integration tests that drive `prepare_graph` against a synthetic
/// graph without round-tripping through the binary serializer.
///
/// # Safety
/// Overwrites `STATIC_CONFIG`. Caller must ensure no other reference to
/// `STATIC_CONFIG` is live (no module is mid-step, no other thread is
/// reading config). Test-only on hosted; reconfigure-time on bare metal.
pub unsafe fn install_static_config(cfg: Config) {
    // SAFETY: caller upholds the `# Safety` invariant — no concurrent
    // reader of STATIC_CONFIG is alive.
    let dst = unsafe {
        let p = &raw mut STATIC_CONFIG;
        &mut *p
    };
    *dst = cfg;
}

/// Populate the static config + loader from in-memory blobs.
///
/// `config_ptr` points to an FXWR-format config blob; `modules_ptr` to a
/// module-table blob. The caller must keep both memory ranges mapped
/// until module instantiation completes. After this returns `Ok`,
/// `prepare_graph()` is the next step.
///
/// **Length-aware variant**: callers that know the config blob length
/// (hosted targets reading from a file, wasm reading from a static
/// `[u8; N]` blob) should prefer [`populate_static_state_with_len`] so
/// the parser can reject sections that would extend past the mapped
/// range. The pointer-only entry continues to delegate to a strict
/// path internally with a 32 KiB upper bound — the historical
/// `MAX_CONFIG_SIZE`.
///
/// # Safety
/// `config_ptr` and `modules_ptr` must each point at a valid blob whose
/// internal length fields stay within the mapped range. Both ranges
/// must remain mapped for the lifetime of `STATIC_CONFIG` / loader use
/// (typically the entire kernel run on bare-metal targets). Mutates
/// the static config + loader; not safe to call after the scheduler
/// has started stepping modules.
pub unsafe fn populate_static_state(
    config_ptr: *const u8,
    config_len: usize,
    modules_ptr: *const u8,
) -> Result<(), &'static str> {
    // `config_len` is the platform's declared upper bound on the
    // config blob's mapped region. QEMU virt passes the gap between
    // QEMU_CONFIG_BLOB_ADDR and QEMU_MODULES_BLOB_ADDR; other
    // bare-metal paths use the slot size from their flash trailer.
    // SAFETY: caller upholds `# Safety` — single-threaded boot/init.
    let loader = unsafe {
        let p = &raw mut STATIC_LOADER;
        &mut *p
    };
    // SAFETY: as above.
    let config = unsafe {
        let p = &raw mut STATIC_CONFIG;
        &mut *p
    };
    loader
        .init_from_blob(modules_ptr)
        .map_err(|_| "loader init failed")?;
    // SAFETY: caller supplied valid (config_ptr, config_len) per `# Safety`.
    if !unsafe {
        crate::kernel::boot::config::read_config_from_ptr_with_len(config_ptr, config_len, config)
    } {
        return Err("config parse failed");
    }
    Ok(())
}

/// Length-aware counterpart to `populate_static_state`.
///
/// `config_blob` is the entire config region as a byte slice and
/// `modules_len` is the byte count the platform mapped for the
/// module-table region. Both lengths are the hard upper bound the
/// parser uses when validating section offsets — a header that claims
/// a body larger than the actual blob fails deterministically rather
/// than wandering past the mapping. Hosted targets (Linux: `Vec<u8>`
/// from disk; WASM: a static `[u8; N]`) call this variant.
///
/// # Safety
/// `modules_ptr` must point at a valid module-table blob whose
/// `modules_len` bytes are mapped and readable. `config_blob` may be
/// any slice the caller has a valid reference for. Mutates the static
/// config + loader; not safe to call after the scheduler has started
/// stepping modules.
pub unsafe fn populate_static_state_with_len(
    config_blob: &[u8],
    modules_ptr: *const u8,
    modules_len: usize,
) -> Result<(), &'static str> {
    // SAFETY: caller upholds `# Safety` — single-threaded boot/init.
    let loader = unsafe {
        let p = &raw mut STATIC_LOADER;
        &mut *p
    };
    // SAFETY: as above.
    let config = unsafe {
        let p = &raw mut STATIC_CONFIG;
        &mut *p
    };
    loader
        .init_from_blob_with_len(modules_ptr, modules_len)
        .map_err(|_| "loader init failed")?;
    if !crate::kernel::boot::config::read_config_from_slice(config_blob, config) {
        return Err("config parse failed");
    }
    Ok(())
}

/// Maximum ports per direction (in/out/ctrl) per module. Sized for
/// Quantum's session_processor, which multiplexes 7 logical input
/// streams across 7 ports with fan-in expansion. `pub(super)` so
/// `module_types` can size its `TeeModule::out_chans` /
/// `MergeModule::in_chans` arrays from the same constant.
pub(super) const MAX_PORTS: usize = 16;

/// Per-module port assignments (replaces old MODULE_CHANNELS tuple)
#[derive(Clone, Copy)]
pub struct ModulePorts {
    pub(crate) in_chans: [i32; MAX_PORTS],
    pub(crate) out_chans: [i32; MAX_PORTS],
    pub(crate) ctrl_chans: [i32; MAX_PORTS],
    pub(crate) in_count: u8,
    pub(crate) out_count: u8,
    pub(crate) ctrl_count: u8,
}

impl ModulePorts {
    pub(crate) const fn empty() -> Self {
        Self {
            in_chans: [-1; MAX_PORTS],
            out_chans: [-1; MAX_PORTS],
            ctrl_chans: [-1; MAX_PORTS],
            in_count: 0,
            out_count: 0,
            ctrl_count: 0,
        }
    }
}

/// Resolve a base-graph module's input-port channel by the module's config
/// `name_hash` (`rfc_workload_backend_metal.md` §3.3 discovery). `prepare_graph`
/// places config module index N at scheduler slot N, so scanning
/// `STATIC_CONFIG.modules` for the name_hash yields the slot whose port table we
/// read. Used by the metal `workload` backend to find the shared ip module's
/// `addr_ctl` port (`in[2]`) at CREATE. Returns the channel id, or `-1` when no
/// base-graph module carries that name_hash or the port is unwired.
/// Scheduler-thread only.
pub fn resolve_module_input_channel(name_hash: u32, port_idx: u8) -> i32 {
    // SAFETY: scheduler-thread read of STATIC_CONFIG (installed at boot, stable
    // for the graph's lifetime). Live-added workload modules are appended to
    // SCHED but not to STATIC_CONFIG, so this only ever resolves base-graph
    // modules — exactly the shared-ip-module case the backend needs.
    let cfg = unsafe { static_config() };
    for (idx, entry) in cfg.modules.iter().enumerate() {
        if let Some(e) = entry {
            if !e.is_empty() && e.name_hash == name_hash {
                return get_module_port(idx, 0 /* PORT_IN */, port_idx);
            }
        }
    }
    -1
}

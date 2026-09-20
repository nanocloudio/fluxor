//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`). Graph wiring: fan/port insertion + per-module instantiation.
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

/// Map a port's manifest `content_type` byte to a `FRAME_KIND_*`
/// discriminant. Auto-inserted tee/merge fans must not split frames
/// mid-payload — the consumer parser would read the body tail as a
/// bogus header — so when this returns a non-NONE kind the fan
/// switches to frame-aware transfer (peek length, drain full frame,
/// write atomically to all outputs).
pub fn port_frame_kind_from_content_type(content_type: u8) -> u8 {
    use module_types::{
        CONTENT_TYPE_ETHERNET_FRAME, CONTENT_TYPE_NET_PROTO, CONTENT_TYPE_TELEMETRY,
        FRAME_KIND_ETH, FRAME_KIND_NET, FRAME_KIND_NONE, FRAME_KIND_TELEMETRY,
    };
    match content_type {
        CONTENT_TYPE_ETHERNET_FRAME => FRAME_KIND_ETH,
        CONTENT_TYPE_NET_PROTO => FRAME_KIND_NET,
        CONTENT_TYPE_TELEMETRY => FRAME_KIND_TELEMETRY,
        _ => FRAME_KIND_NONE,
    }
}

/// Convert a `FanDirection` + ctrl bit into the manifest direction
/// byte (0=input, 1=output, 2=ctrl_input). Mirrors the encoding
/// produced by the manifest packer in `tools/src/manifest.rs`.
fn manifest_direction_byte(dir: FanDirection, port_key: u8) -> u8 {
    match dir {
        FanDirection::Out => 1,
        FanDirection::In => {
            if (port_key & 0x10) != 0 {
                2
            } else {
                0
            }
        }
    }
}

/// Look up a module's port content_type by its `name_hash`. Returns
/// `FRAME_KIND_NONE` when the module isn't in the loader table (host
/// built-in without a packed manifest) or the manifest doesn't
/// describe a port at the requested direction+index.
fn fanned_port_frame_kind(
    loader: &ModuleLoader,
    name_hash: u32,
    dir: FanDirection,
    port_key: u8,
) -> u8 {
    use module_types::FRAME_KIND_NONE;
    let direction_byte = manifest_direction_byte(dir, port_key);
    let index = port_key & 0x0F;
    if let Ok(module) = loader.find_by_name_hash(name_hash) {
        if let Some(ct) = module.port_content_type(direction_byte, index) {
            return port_frame_kind_from_content_type(ct);
        }
    }
    FRAME_KIND_NONE
}

/// Compute port grouping key for fan insertion.
///
/// Out: groups by from_port_index (one tee per output port).
/// In: groups by (is_ctrl << 4) | to_port_index (separate merge per port+type).
fn edge_port_key(edge: &Edge, direction: FanDirection) -> u8 {
    match direction {
        FanDirection::Out => edge.from_port_index,
        FanDirection::In => {
            let type_bit = if edge.is_ctrl() { 0x10 } else { 0x00 };
            type_bit | edge.to_port_index
        }
    }
}

/// Check if an edge connects to `module_idx` in the given direction.
fn edge_matches_module(edge: &Edge, module_idx: usize, direction: FanDirection) -> bool {
    match direction {
        FanDirection::Out => edge.from_module == module_idx,
        FanDirection::In => edge.to_module == module_idx,
    }
}

/// Insert tee (fan-out) or merge (fan-in) modules where a single port has
/// multiple edges.
///
/// Any `buffer_group` on edges that require a tee/merge is cleared and logged
/// at error level. Aliased mailbox chains are incompatible with fan modules
/// because in-place modification through a shared buffer would corrupt data
/// for the other consumers/producers in the fan.
fn insert_fan(
    direction: FanDirection,
    edges: &mut [Edge; MAX_CHANNELS],
    edge_count: &mut usize,
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
    loader: &ModuleLoader,
) -> bool {
    let original_count = *module_count;
    let (internal_hash, name) = match direction {
        FanDirection::Out => (INTERNAL_TEE_HASH, "tee"),
        FanDirection::In => (INTERNAL_MERGE_HASH, "merge"),
    };

    for module_idx in 0..original_count {
        let entry_id = match &module_list[module_idx] {
            Some(entry) if !is_internal_module(entry) => entry.id,
            _ => continue,
        };

        // Collect all edges connecting to this module in the given direction
        let mut matching = [0usize; MAX_CHANNELS];
        let mut match_count = 0;
        for (i, edge) in edges.iter().take(*edge_count).enumerate() {
            if edge_matches_module(edge, module_idx, direction) && match_count < MAX_CHANNELS {
                matching[match_count] = i;
                match_count += 1;
            }
        }

        if match_count <= 1 {
            continue;
        }

        // Group edges by port key. Each unique key gets its own tee/merge.
        // Invariant: every index in matching[0..match_count] is visited exactly once.
        let mut processed = [false; MAX_CHANNELS];
        for start in 0..match_count {
            if processed[start] {
                continue;
            }

            let port_key = edge_port_key(&edges[matching[start]], direction);

            // Collect all edges sharing this port key
            let mut group = [0usize; MAX_CHANNELS];
            let mut group_count = 0;
            for j in start..match_count {
                if !processed[j] && edge_port_key(&edges[matching[j]], direction) == port_key {
                    group[group_count] = matching[j];
                    group_count += 1;
                    processed[j] = true;
                }
            }

            if group_count <= 1 {
                continue;
            }

            // Multi-inbound consumers keep one channel per edge (priority
            // lanes) — no merge. Only data inputs (port_key without the
            // ctrl bit) qualify; ctrl fan-in still merges.
            if direction == FanDirection::In && (port_key & 0x10) == 0 {
                let consumer_hash = module_list[module_idx]
                    .as_ref()
                    .map(|e| e.name_hash)
                    .unwrap_or(0);
                if is_multi_inbound(consumer_hash) {
                    continue;
                }
            }

            // Invariant: buffer aliasing (buffer_group) is incompatible with tee/merge.
            // In-place modification through an aliased buffer would corrupt data for
            // other consumers in the fan. Strip and log at error level.
            for &ei in group.iter().take(group_count) {
                if edges[ei].buffer_group != 0 {
                    log::error!(
                        "[graph] fan module={} buffer_group={} cleared (incompatible)",
                        module_idx,
                        edges[ei].buffer_group
                    );
                    edges[ei].buffer_group = 0;
                }
            }

            // Insert tee/merge module for this port group
            if *edge_count + 1 > MAX_CHANNELS {
                log::error!("[graph] channel limit for {name} module={entry_id}");
                return false;
            }

            // The tee/merge inherits the fanned-on module's domain so
            // it runs in the same pump as the fan group it serves.
            let (fan_domain, fan_name_hash) = match &module_list[module_idx] {
                Some(e) => (e.domain_id, e.name_hash),
                None => (0, 0),
            };
            // Detect the fanned port's wire format from the module's
            // manifest content_type. If the fanned module is a host
            // built-in (no manifest), fall back to checking any peer's
            // manifest across the fan — both ends of an edge must
            // declare a compatible content_type, so peer-side gives
            // the same answer.
            let mut fan_kind = fanned_port_frame_kind(loader, fan_name_hash, direction, port_key);
            if fan_kind == module_types::FRAME_KIND_NONE {
                for k in 0..group_count {
                    let edge = &edges[group[k]];
                    let (peer_idx, peer_dir, peer_port_key) = match direction {
                        FanDirection::Out => (
                            edge.to_module,
                            FanDirection::In,
                            if edge.is_ctrl() { 0x10 } else { 0x00 } | edge.to_port_index,
                        ),
                        FanDirection::In => {
                            (edge.from_module, FanDirection::Out, edge.from_port_index)
                        }
                    };
                    let peer_hash = match &module_list[peer_idx] {
                        Some(e) => e.name_hash,
                        None => continue,
                    };
                    let peer_kind =
                        fanned_port_frame_kind(loader, peer_hash, peer_dir, peer_port_key);
                    if peer_kind != module_types::FRAME_KIND_NONE {
                        fan_kind = peer_kind;
                        break;
                    }
                }
            }
            let fan_idx = match push_internal_module(
                module_list,
                module_count,
                internal_hash,
                fan_domain,
                fan_kind,
            ) {
                Some(idx) => idx,
                None => return false,
            };

            // Add bridge edge: original module ↔ fan module.
            //
            // For fan-IN, `port_key` is produced by `edge_port_key` which
            // sets bit 0x10 when the consumer port is a *ctrl* input (see
            // there). The merge→consumer bridge must therefore be a ctrl
            // edge carrying the real (masked) port index — otherwise it
            // is built as a data edge at index 0x10 (16), which both
            // orphans the consumer's ctrl input AND lands a phantom data
            // input at index 16 (≥ MAX_PORTS → "input port limit in=17").
            let new_edge = match direction {
                FanDirection::Out => {
                    let mut e = Edge::simple(module_idx, fan_idx);
                    e.from_port_index = port_key;
                    e
                }
                FanDirection::In => {
                    let is_ctrl_port = (port_key & 0x10) != 0;
                    let real_port = port_key & 0x0f;
                    let mut e = if is_ctrl_port {
                        Edge::ctrl(fan_idx, module_idx)
                    } else {
                        Edge::simple(fan_idx, module_idx)
                    };
                    e.to_port_index = real_port;
                    e
                }
            };
            edges[*edge_count] = new_edge;
            *edge_count += 1;

            // Rewire group edges to go through the fan module. The
            // port indices on the rewritten edges must repack from 0
            // (one slot per fanned consumer/producer) because the
            // tee/merge module has only a single logical input/output
            // port — `collect_channels` places channels at
            // `from_port_index` / `to_port_index`, and if the original
            // edges all carried the same source-side port index (e.g.
            // every fan-out edge inheriting peer_router.raft_rpc's
            // index 3) they would land in the same slot and overwrite,
            // leaving the tee/merge with `out_chans[0..k] = -1` so its
            // poll loop bails before it does any work.
            for k in 0..group_count {
                match direction {
                    FanDirection::Out => {
                        edges[group[k]].from_module = fan_idx;
                        edges[group[k]].from_port_index = k as u8;
                    }
                    FanDirection::In => {
                        edges[group[k]].to_module = fan_idx;
                        edges[group[k]].to_port_index = k as u8;
                        // The producer→merge hop is plain data into the
                        // merge's inputs, regardless of whether the
                        // original edge targeted a ctrl port — the merge
                        // re-emits to the consumer's ctrl port via the
                        // bridge edge above. Without clearing this, an
                        // original ctrl edge keeps `to_port = "ctrl"`, so
                        // `collect_input_channels` (data only) counts zero
                        // merge inputs and the merge fails to install.
                        edges[group[k]].to_port = "in";
                    }
                }
            }
        }
    }

    true
}

pub(crate) fn insert_fan_out(
    edges: &mut [Edge; MAX_CHANNELS],
    edge_count: &mut usize,
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
    loader: &ModuleLoader,
) -> bool {
    insert_fan(
        FanDirection::Out,
        edges,
        edge_count,
        module_list,
        module_count,
        loader,
    )
}

pub(crate) fn insert_fan_in(
    edges: &mut [Edge; MAX_CHANNELS],
    edge_count: &mut usize,
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
    loader: &ModuleLoader,
) -> bool {
    insert_fan(
        FanDirection::In,
        edges,
        edge_count,
        module_list,
        module_count,
        loader,
    )
}

pub(crate) fn validate_hardware_requirements(config: &RunnerConfig) -> bool {
    let mut valid = true;

    if !is_spi_initialized(config.spi_bus) {
        log::error!("[boot] config spi bus={} not initialized", config.spi_bus);
        valid = false;
    }

    // Log which buses are available (informational for debugging)
    for bus in 0..2u8 {
        if is_spi_initialized(bus) {
            log::info!("[boot] spi{bus} available");
        }
    }
    for bus in 0..2u8 {
        if crate::kernel::module::syscalls::is_i2c_initialized(bus) {
            log::info!("[boot] i2c{bus} available");
        }
    }

    valid
}

/// Populate a module's port table from the compiled `sched.edges`.
///
/// Reads every edge touching `module_idx` and writes the resulting
/// in/out/ctrl channel handles into `sched.ports[instantiated]`.
/// Returns `false` if the module has more than `MAX_PORTS` channels in
/// any direction (a config error).
///
/// Used by platform setup paths that don't go through
/// `instantiate_one_module` — e.g. hosted built-ins that aren't in the
/// loader.
pub fn populate_module_ports_from_edges(module_idx: usize, instantiated: usize) -> bool {
    if module_idx >= MAX_MODULES || instantiated >= MAX_MODULES {
        return false;
    }
    // SAFETY: graph-prep context — single mutator; both indices bounded.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    let mut in_chans = [-1i32; MAX_CHANNELS];
    let mut out_chans = [-1i32; MAX_CHANNELS];
    let mut ctrl_chans = [-1i32; MAX_CHANNELS];
    let in_count = collect_input_channels(&sched.edges, module_idx, &mut in_chans);
    let out_count = collect_output_channels(&sched.edges, module_idx, &mut out_chans);
    let ctrl_count = collect_ctrl_channels(&sched.edges, module_idx, &mut ctrl_chans);
    populate_ports(
        &mut sched.ports[instantiated],
        &in_chans,
        in_count,
        &out_chans,
        out_count,
        &ctrl_chans,
        ctrl_count,
    )
}

/// Copy collected channels into ModulePorts.
/// Returns false if any port count exceeds MAX_PORTS (config error).
fn populate_ports(
    ports: &mut ModulePorts,
    in_chans: &[i32; MAX_CHANNELS],
    in_count: usize,
    out_chans: &[i32; MAX_CHANNELS],
    out_count: usize,
    ctrl_chans: &[i32; MAX_CHANNELS],
    ctrl_count: usize,
) -> bool {
    if in_count > MAX_PORTS {
        log::error!("[inst] input port limit in={in_count} max={MAX_PORTS}");
        return false;
    }
    if out_count > MAX_PORTS {
        log::error!("[inst] output port limit out={out_count} max={MAX_PORTS}");
        return false;
    }
    if ctrl_count > MAX_PORTS {
        log::error!("[inst] ctrl port limit ctrl={ctrl_count} max={MAX_PORTS}");
        return false;
    }
    ports.in_count = in_count as u8;
    ports.out_count = out_count as u8;
    ports.ctrl_count = ctrl_count as u8;
    let mut i = 0;
    while i < in_count {
        ports.in_chans[i] = in_chans[i];
        i += 1;
    }
    i = 0;
    while i < out_count {
        ports.out_chans[i] = out_chans[i];
        i += 1;
    }
    i = 0;
    while i < ctrl_count {
        ports.ctrl_chans[i] = ctrl_chans[i];
        i += 1;
    }
    true
}

/// Result of synchronous per-module instantiation.
pub enum InstantiateResult {
    /// Module ready, increment count
    Done,
    /// Module needs async completion
    Pending(crate::kernel::module::loader::DynamicModulePending),
    /// Fatal error
    Error(i32),
}

/// Synchronous per-module instantiation — all large locals live on the
/// regular call stack rather than in the async future state machine.
#[inline(never)]
pub fn instantiate_one_module(
    loader: &ModuleLoader,
    entry: &ModuleEntry,
    module_idx: usize,
    instantiated: usize,
    edges: &mut [Edge; MAX_CHANNELS],
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_ports: &mut [ModulePorts; MAX_MODULES],
) -> InstantiateResult {
    // Channel collection — large arrays stay on sync stack
    let mut in_chans = [-1i32; MAX_CHANNELS];
    let mut out_chans = [-1i32; MAX_CHANNELS];
    let mut ctrl_chans = [-1i32; MAX_CHANNELS];
    let in_count = collect_input_channels(edges, module_idx, &mut in_chans);
    let out_count = collect_output_channels(edges, module_idx, &mut out_chans);
    let ctrl_count = collect_ctrl_channels(edges, module_idx, &mut ctrl_chans);
    let in_chan = if in_count > 0 { in_chans[0] } else { -1 };
    let out_chan = if out_count > 0 { out_chans[0] } else { -1 };
    let ctrl_chan = if ctrl_count > 0 { ctrl_chans[0] } else { -1 };

    let ports = &mut module_ports[instantiated];
    if !populate_ports(
        ports,
        &in_chans,
        in_count,
        &out_chans,
        out_count,
        &ctrl_chans,
        ctrl_count,
    ) {
        log::error!("[inst] module={} port limit exceeded", entry.id);
        return InstantiateResult::Error(-1);
    }

    if entry.name_hash == INTERNAL_TEE_HASH {
        if in_count != 1 || out_count == 0 {
            log::error!("[inst] tee module={} invalid ports", entry.id);
            return InstantiateResult::Error(-1);
        }
        // Clamp to keep the index within `FAN_BUFS` even if an
        // out-of-range `domain_id` slips past
        // `compute_domain_exec_orders_static`.
        let domain = (entry.domain_id as usize).min(MAX_DOMAINS - 1) as u8;
        modules[instantiated] = ModuleSlot::Tee(TeeModule::new(
            in_chans[0],
            &out_chans,
            out_count,
            domain,
            entry.frame_kind,
        ));
        return InstantiateResult::Done;
    } else if entry.name_hash == INTERNAL_MERGE_HASH {
        if out_count != 1 || in_count == 0 {
            log::error!("[inst] merge module={} invalid ports", entry.id);
            return InstantiateResult::Error(-1);
        }
        let domain = (entry.domain_id as usize).min(MAX_DOMAINS - 1) as u8;
        modules[instantiated] = ModuleSlot::Merge(MergeModule::new(
            &in_chans,
            in_count,
            out_chans[0],
            domain,
            entry.frame_kind,
        ));
        return InstantiateResult::Done;
    }

    // Loader lookup
    let found_module = match loader.find_by_name_hash(entry.name_hash) {
        Ok(m) => m,
        Err(e) => {
            e.log("loader");
            return InstantiateResult::Error(-1);
        }
    };
    let name = found_module.name_str();
    let static_name = NameArena::intern(name);

    // Validate integrity/signature BEFORE any module export runs or any
    // manifest metadata is trusted. The `module_arena_size` export below is
    // module code, and `start_new` (which also validates) runs only after it —
    // so without an early gate here unverified native code executes. This is
    // redundant with start_new's check by design: defense in depth at the two
    // points where module code first becomes reachable.
    if let Err(e) = crate::kernel::module::loader::validate_module(&found_module, static_name) {
        e.log("validate");
        return InstantiateResult::Error(-1);
    }

    // Select capability-filtered syscall table based on module type
    let syscalls = get_table_for_module_type(found_module.header.module_type);

    // Record capability class and manifest metadata for enforcement
    // SAFETY: instantiate_one_module runs on the scheduler thread.
    unsafe {
        let p = &raw mut SCHED;
        let sched = &mut *p;
        sched.cap_class[instantiated] = match found_module.header.module_type {
            5 => 3, // Protocol → CAP_FULL
            3 => 1, // Sink → CAP_SERVICE_PIO
            4 => 2, // EventHandler → CAP_SERVICE_GPIO
            _ => 0, // Source, Transformer → CAP_SERVICE
        };
        sched.required_caps[instantiated] = found_module.header.required_caps();
        sched.permissions[instantiated] = found_module.manifest_permissions();
        // Boot-time record of what the capability gate will enforce for
        // this slot: the packed .fmod HEADER value (`required_caps()`),
        // which is what `check_contract_grant` gates on — distinct from the
        // manifest-derived mask, which is recomputed from `[[resources]]`.
        // A header of 0x0 for a module whose manifest declares contracts
        // means the packer never populated the header field, and every
        // `provider_call` to those contracts returns ENOSYS.
        log::info!(
            "[inst] module {} caps: required_caps=0x{:016x} cap_class={} permissions=0x{:02x}",
            instantiated,
            sched.required_caps[instantiated],
            sched.cap_class[instantiated],
            sched.permissions[instantiated],
        );
        // Store export table info for resolve_export_for_module
        sched.module_code_base[instantiated] = found_module.code_base() as usize;
        sched.module_code_size[instantiated] = found_module.header.code_size;
        sched.module_export_table[instantiated] = found_module.export_table_ptr();
        sched.module_export_count[instantiated] = found_module.header.export_count;
        let flags_byte = found_module.header.reserved[0];
        sched.mailbox_safe[instantiated] = (flags_byte & 0x01) != 0;
        sched.in_place_writer[instantiated] = (flags_byte & 0x02) != 0;
        let deferred = (flags_byte & 0x04) != 0;
        sched.deferred_ready[instantiated] = deferred;
        if deferred {
            sched.ready[instantiated] = false;
        }
    }

    // Clear the arena slot. A module has ONE arena and the loader allocates
    // it, because only the loader knows whether the module asked for
    // isolation — an isolated module's arena has to come from the
    // page-aligned region, and a second allocation here would hand
    // `arena_get` a different region from the one `heap_alloc` draws on,
    // at the cost of a second copy of it. The loader publishes what it
    // allocated through `set_module_arena`.
    // SAFETY: scheduler-thread context; sole mutator during instantiation.
    unsafe {
        let p = &raw mut SCHED;
        let sched = &mut *p;
        sched.arenas[instantiated] = ArenaInfo::empty();
    }

    // Copy params to static buffer and merge runtime overrides
    // SAFETY: PARAM_BUFFER is scheduler-thread owned; consumed by
    // start_new below.
    unsafe {
        let pb = &mut *core::ptr::addr_of_mut!(PARAM_BUFFER);
        pb.write(entry.params());

        // Overlay any runtime parameter overrides from flash store
        {
            let new_len = hal::merge_runtime_overrides(
                entry.id as u16,
                pb.as_mut_ptr(),
                pb.len(),
                MAX_MODULE_CONFIG_SIZE,
            );
            pb.set_len(new_len);
        }
    }

    // Full instantiation via start_new.
    // Set current module index so any syscall made from inside
    // module_new() can identify the calling module (state pointer,
    // heap, required_caps, loader-driven provider registration).
    set_current_module(instantiated);
    // SAFETY: PARAM_BUFFER lives for the duration of start_new; the
    // pointer's lifetime is bounded by this scope.
    let result = unsafe {
        let pb = core::ptr::addr_of!(PARAM_BUFFER);
        DynamicModule::start_new(
            &found_module,
            syscalls,
            crate::kernel::module::loader::ChannelHandles {
                in_chan,
                out_chan,
                ctrl_chan,
            },
            crate::kernel::module::loader::ParamSlice {
                ptr: (*pb).as_ptr(),
                len: (*pb).len(),
            },
            static_name,
        )
    };
    clear_instantiation_state();
    // module_new returned — drop module context (see step_one_module):
    // result-handling logs below are platform logs, owner-attributed to
    // the system, not to the module just instantiated.
    set_current_module(MAX_MODULES);

    match result {
        Ok(StartNewResult::Ready(dynamic)) => {
            modules[instantiated] = ModuleSlot::Dynamic(dynamic);
        }
        Ok(StartNewResult::Pending(pending)) => {
            // Record step period before returning
            // SAFETY: scheduler-thread context; instantiated bounded.
            unsafe {
                SCHED.step_period[instantiated] = found_module.header.step_period_ticks();
                // Apply the manifest's `step_phase` as the initial
                // counter value. With period P and phase φ, the first
                // eligible tick is at `P - φ`, so coarse-period
                // modules can be staggered to avoid convoy bursts.
                // `step_phase < period` is validated by the loader;
                // the clamp here is defense in depth so a malformed
                // header can't index modulo 0.
                let period = SCHED.step_period[instantiated];
                let phase = found_module.header.step_phase();
                SCHED.step_counter[instantiated] = if period > 0 { phase % period } else { 0 };
            }
            return InstantiateResult::Pending(pending);
        }
        Err(e) => {
            e.log("scheduler");
            return InstantiateResult::Error(-1);
        }
    }

    // Record step frequency hint from module header
    // SAFETY: scheduler-thread context; instantiated bounded.
    unsafe {
        SCHED.step_period[instantiated] = found_module.header.step_period_ticks();
        // See Pending arm above — same step_phase initialisation.
        let period = SCHED.step_period[instantiated];
        let phase = found_module.header.step_phase();
        SCHED.step_counter[instantiated] = if period > 0 { phase % period } else { 0 };
    }

    // Protection config is parsed inside `start_new`, BETWEEN heap
    // init and module_new, so module_new sees the declared heap
    // flags / fault policy on its very first `heap_alloc`.

    InstantiateResult::Done
}

// Platform-specific graph setup and main loop functions have been moved
// to their respective platform files (rp.rs, bcm2712.rs).
// They use the pub(crate) accessors: prepare_graph(), instantiate_one_module(),
// sched_mut(), sched_modules(), validate_buffer_groups(), compute_downstream_latency(),
// step_modules(), step_woken_modules().

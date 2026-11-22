//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`). Graph wiring: port tables and per-module
//! instantiation.
use super::*;

/// Which side of a module an edge is collected on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Out,
    In,
}

fn collect_channels(
    edges: &[Edge],
    module_idx: usize,
    direction: Side,
    ctrl_only: bool,
    out: &mut [i32],
) -> usize {
    let mut count = 0;
    for edge in edges.iter() {
        let matches = match direction {
            // A tap edge is written by the kernel's mirror, not the tapped
            // module: it is never one of that module's outputs.
            Side::Out => edge.from_module == module_idx && !edge.tap,
            Side::In => edge.to_module == module_idx && edge.is_ctrl() == ctrl_only,
        };
        // Producer reads `channel`; consumer reads `consumer_channel`
        // when a platform bridge has split the edge, otherwise `channel`.
        let chan_for_side = match direction {
            Side::Out => edge.channel,
            Side::In => {
                if edge.consumer_channel >= 0 {
                    edge.consumer_channel
                } else {
                    edge.channel
                }
            }
        };
        if chan_for_side >= 0 && matches {
            // Place at port index if it fits, otherwise append
            let port_idx = match direction {
                Side::Out => edge.from_port_index as usize,
                Side::In => edge.to_port_index as usize,
            };
            if port_idx < out.len() && out[port_idx] == -1 {
                out[port_idx] = chan_for_side;
                if port_idx >= count {
                    count = port_idx + 1;
                }
            } else if count < out.len() {
                out[count] = chan_for_side;
                count += 1;
            }
        }
    }
    count
}

pub(crate) fn collect_output_channels(edges: &[Edge], module_idx: usize, out: &mut [i32]) -> usize {
    collect_channels(edges, module_idx, Side::Out, false, out)
}

pub(crate) fn collect_input_channels(edges: &[Edge], module_idx: usize, out: &mut [i32]) -> usize {
    // Only collect non-ctrl (data) input channels
    collect_channels(edges, module_idx, Side::In, false, out)
}

pub(crate) fn collect_ctrl_channels(edges: &[Edge], module_idx: usize, out: &mut [i32]) -> usize {
    // Only collect ctrl input channels
    collect_channels(edges, module_idx, Side::In, true, out)
}

/// Populate a module's port table from the compiled `sched.edges`.
///
/// Reads every edge touching `module_idx` and writes the resulting
/// in/out/ctrl channel handles into `sched.ports[instantiated]`.
/// Returns `false` if the module has more than `MAX_PORTS` channels in
/// any direction (a config error).
///
/// Used by platform setup paths that don't go through
/// `instantiate_one_module` — e.g. hosted native modules that aren't in the
/// loader.
pub fn populate_module_ports_from_edges(module_idx: usize, instantiated: usize) -> bool {
    if module_idx >= module_slots() || instantiated >= module_slots() {
        return false;
    }
    // SAFETY: graph-prep context — single mutator; both indices bounded.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    let mut in_chans = [-1i32; MAX_PORTS + 1];
    let mut out_chans = [-1i32; MAX_PORTS + 1];
    let mut ctrl_chans = [-1i32; MAX_PORTS + 1];
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
    in_chans: &[i32],
    in_count: usize,
    out_chans: &[i32],
    out_count: usize,
    ctrl_chans: &[i32],
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
    edges: &mut [Edge],
    modules: &mut [ModuleSlot],
    module_ports: &mut [ModulePorts],
) -> InstantiateResult {
    // Channel collection — large arrays stay on sync stack
    let mut in_chans = [-1i32; MAX_PORTS + 1];
    let mut out_chans = [-1i32; MAX_PORTS + 1];
    let mut ctrl_chans = [-1i32; MAX_PORTS + 1];
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

    // Loader lookup
    let found_module = match loader.find_by_name_hash(entry.name_hash) {
        Ok(m) => m,
        Err(e) => {
            e.log("loader");
            return InstantiateResult::Error(-1);
        }
    };
    let static_name = found_module.image_name();

    // Every module gets the same table; what it may call is decided per op
    // at dispatch (`check_grant`) from the grants recorded below.
    let syscalls = get_syscall_table();

    // SAFETY: instantiate_one_module runs on the scheduler thread.
    unsafe {
        let p = &raw mut SCHED;
        let sched = &mut *p;
        sched.type_hash[instantiated] = entry.name_hash;
        let grants = found_module.manifest_grants();
        sched.grants[instantiated] = grants;
        log::info!(
            "[inst] module {} grants: contracts=0x{:016x} ops=0x{:016x}",
            instantiated,
            grants[0],
            grants[1],
        );
        // The code region provider pointers are validated against.
        sched.module_code_base[instantiated] = found_module.code_base() as usize;
        sched.module_code_size[instantiated] = found_module.header.code_size;
        let flags_byte = found_module.header.flags;
        sched.mailbox_safe[instantiated] =
            (flags_byte & crate::abi::wire::fmod::header::flag::MAILBOX_SAFE) != 0;
        sched.in_place_writer[instantiated] =
            (flags_byte & crate::abi::wire::fmod::header::flag::IN_PLACE_WRITER) != 0;
        let deferred = (flags_byte & crate::abi::wire::fmod::header::flag::DEFERRED_READY) != 0;
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

    // The params the module is handed. Compiled params are never copied: the
    // module gets a pointer into the resident config blob (or, for a live
    // add, into the request that carries them). Only an instance the platform
    // holds runtime overrides for gets a merged copy, in storage the platform
    // sizes to the merge; one that cannot be merged whole is refused, loudly,
    // before any of its state is set up — a truncated block would hand the
    // module a different config from the one the graph declares.
    let params = match hal::runtime_params(entry.id, entry.params()) {
        hal::RuntimeParams::Compiled => crate::kernel::module::loader::ParamSlice {
            ptr: entry.params().as_ptr(),
            len: entry.params().len(),
        },
        hal::RuntimeParams::Merged(ptr, len) => {
            crate::kernel::module::loader::ParamSlice { ptr, len }
        }
        hal::RuntimeParams::TooLarge(need) => {
            log::error!(
                "[inst] module={} ({}) params {} B with its runtime overrides need {} B, more \
                 than the platform's merge buffer holds — instance refused",
                entry.id,
                static_name,
                entry.params().len(),
                need
            );
            return InstantiateResult::Error(-1);
        }
    };

    // Full instantiation via start_new, as the new module: any syscall made
    // from inside module_new() identifies it (state pointer, heap,
    // grants, loader-driven provider registration). Afterwards the
    // context is the caller's again — a module staging a subgraph from its
    // own syscall, or no module at boot — so result-handling logs are never
    // the new module's.
    let result = with_module_context(instantiated, || {
        // SAFETY: `params` points into the resident config blob, the live-add
        // request, or the platform's merge storage, each valid until this
        // instance's `module_new` has completed (pending retries included).
        let r = unsafe {
            DynamicModule::start_new(
                &found_module,
                SCHED.module_signing[instantiated],
                syscalls,
                crate::kernel::module::loader::ChannelHandles {
                    in_chan,
                    out_chan,
                    ctrl_chan,
                },
                params,
                static_name,
            )
        };
        clear_instantiation_state();
        r
    });

    match result {
        Ok(StartNewResult::Ready(dynamic)) => {
            modules[instantiated] = ModuleSlot::Dynamic(dynamic);
        }
        Ok(StartNewResult::Pending(pending)) => {
            // Record step period before returning
            // SAFETY: scheduler-thread context; instantiated bounded.
            unsafe {
                SCHED.step_period[instantiated] = found_module.header.step_period;
                // The manifest's `step_phase` staggers modules of one
                // period (`step_phase < period`, validated by the loader).
                let period = SCHED.step_period[instantiated];
                let phase = found_module.header.step_phase;
                SCHED.step_phase[instantiated] = if period > 0 { phase % period } else { 0 };
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
        SCHED.step_period[instantiated] = found_module.header.step_period;
        // See Pending arm above — same step_phase initialisation.
        let period = SCHED.step_period[instantiated];
        let phase = found_module.header.step_phase;
        SCHED.step_phase[instantiated] = if period > 0 { phase % period } else { 0 };
    }

    // Protection config is parsed inside `start_new`, BETWEEN heap
    // init and module_new, so module_new sees the declared heap
    // flags / fault policy on its very first `heap_alloc`.

    InstantiateResult::Done
}

// Platform-specific graph setup and domain loop functions have been moved
// to their respective platform files (rp.rs, bcm2712.rs).
// They use the pub(crate) accessors: prepare_graph(), instantiate_one_module(),
// sched_mut(), validate_buffer_groups(), compute_downstream_latency(),
// pass::run().

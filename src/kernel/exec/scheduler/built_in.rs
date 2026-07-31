//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

// ============================================================================
// Channel Collection Helpers
// ============================================================================

fn collect_channels(
    edges: &[Edge; MAX_CHANNELS],
    module_idx: usize,
    direction: FanDirection,
    ctrl_only: bool,
    out: &mut [i32; MAX_CHANNELS],
) -> usize {
    let mut count = 0;
    for edge in edges.iter() {
        let matches = match direction {
            FanDirection::Out => edge.from_module == module_idx,
            FanDirection::In => edge.to_module == module_idx && edge.is_ctrl() == ctrl_only,
        };
        // Producer reads `channel`; consumer reads `consumer_channel`
        // when a platform bridge has split the edge, otherwise `channel`.
        let chan_for_side = match direction {
            FanDirection::Out => edge.channel,
            FanDirection::In => {
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
                FanDirection::Out => edge.from_port_index as usize,
                FanDirection::In => edge.to_port_index as usize,
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

pub(crate) fn collect_output_channels(
    edges: &[Edge; MAX_CHANNELS],
    module_idx: usize,
    out: &mut [i32; MAX_CHANNELS],
) -> usize {
    collect_channels(edges, module_idx, FanDirection::Out, false, out)
}

pub(crate) fn collect_input_channels(
    edges: &[Edge; MAX_CHANNELS],
    module_idx: usize,
    out: &mut [i32; MAX_CHANNELS],
) -> usize {
    // Only collect non-ctrl (data) input channels
    collect_channels(edges, module_idx, FanDirection::In, false, out)
}

pub(crate) fn collect_ctrl_channels(
    edges: &[Edge; MAX_CHANNELS],
    module_idx: usize,
    out: &mut [i32; MAX_CHANNELS],
) -> usize {
    // Only collect ctrl input channels
    collect_channels(edges, module_idx, FanDirection::In, true, out)
}

// ============================================================================
// Built-in module graph (no PIC loading, no config parsing)
// ============================================================================

/// Pair of (module name, step function) for `run_builtin_graph`.
pub type BuiltinModuleEntry = (&'static str, fn(*mut u8) -> i32);

/// Manually insert built-in modules and run the scheduler loop.
/// Used on platforms without flash/PIC (e.g. aarch64 QEMU).
///
/// `modules`: array of (name, step_fn) pairs. Channels between them are
/// created automatically: module[0].out → module[1].in → module[1].out → ...
pub fn run_builtin_graph(modules: &[BuiltinModuleEntry]) -> ! {
    let count = modules.len().min(MAX_MODULES);
    // SAFETY: built-in graph runs on a single core (qemu/rp) without PIC.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // Create channels between consecutive modules
    let mut channels = [0i32; MAX_MODULES];
    let mut chan_count = 0usize;
    if count > 1 {
        let mut i = 0;
        while i < count - 1 {
            let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, null(), 0);
            if ch >= 0 {
                channels[i] = ch;
                chan_count += 1;
            }
            i += 1;
        }
    }

    // Insert modules
    let mut i = 0;
    while i < count {
        let mut m = BuiltInModule::new(modules[i].0, modules[i].1);
        // Store channel handles in state: bytes 0-3 = input, 4-7 = output
        let state = m.state.as_mut_ptr();
        // Input channel (from previous module)
        let in_ch: i32 = if i > 0 { channels[i - 1] } else { -1 };
        // SAFETY: `state` is the just-constructed BuiltInModule's state
        // buffer (≥ 8 bytes by construction); single writer here.
        unsafe { core::ptr::write(state as *mut i32, in_ch) };
        // Output channel (to next module)
        let out_ch: i32 = if i < count - 1 { channels[i] } else { -1 };
        // SAFETY: as above; second 4 bytes of the state buffer.
        unsafe { core::ptr::write(state.add(4) as *mut i32, out_ch) };

        sched.modules[i] = ModuleSlot::BuiltIn(m);
        sched.ready[i] = true;
        i += 1;
    }

    log::info!("[sched] running modules={count} channels={chan_count}");

    // Synchronous main loop
    loop {
        // `wfi` halts the core until an interrupt; only valid on Arm
        // bare-metal targets. On wasm32 the host drives ticks
        // externally via `kernel_step()`, so this loop is unreachable
        // there — gate the asm so wasm32 compiles cleanly.
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        // SAFETY: WFI is a hint to halt the core until an interrupt;
        // no register/memory side-effects beyond the architectural wait.
        unsafe {
            core::arch::asm!("wfi"); // Wait for timer tick
        }
        #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
        core::hint::spin_loop();

        // SAFETY: built-in graph runs single-threaded.
        unsafe {
            DBG_TICK += 1;
        }
        // SAFETY: DBG_TICK aligned u32 read.
        let tick = unsafe { DBG_TICK };

        step_modules(&mut sched.modules, count);

        // Check event wake
        let wake = crate::kernel::ipc::event::take_wake_pending();
        if !wake.is_empty() {
            step_woken_modules(&mut sched.modules, count, &wake);
        }

        // Built-in-graph platforms (qemu / rp) don't have a separate
        // outer-loop heartbeat module; emit through the canonical
        // helper so cadence + message shape matches every other
        // platform.
        maybe_emit_alive(tick as u64, None);
    }
}

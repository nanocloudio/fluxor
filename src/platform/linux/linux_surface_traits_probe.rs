// linux_surface_traits_probe native module — a consumer of the Surface
// Traits surface on Linux that logs what it reads. Each `MSG_TRAITS` record
// on its input is decoded with the contract's own reader
// (`abi::contracts::input::surface_traits`) and logged by field, so the
// round trip linux_surface_traits → channel → this probe can be watched on
// a host with no display. A record the contract refuses is counted and
// logged as refused.

use fluxor::abi::contracts::input::surface_traits as probe_contract;
use fluxor::abi::platform::native::linux::linux_surface_traits_probe as surface_traits_probe_tags;

struct LinuxSurfaceTraitsProbeState {
    in_chan: i32,
    refused: u32,
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn linux_surface_traits_probe_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-owned per-instance arena for this module;
    // size-matched to `LinuxSurfaceTraitsProbeState` by the loader.
    let st = unsafe { instance_state::<LinuxSurfaceTraitsProbeState>(state) };
    if st.in_chan < 0 {
        return 0;
    }
    let mut buf = [0u8; probe_contract::EVENT_SIZE];
    loop {
        // SAFETY: channel_read takes (chan, *mut u8, max_len); buf is a stack
        // array sized to its length.
        let n = unsafe { channel::channel_read(st.in_chan, buf.as_mut_ptr(), buf.len()) };
        if n < probe_contract::EVENT_SIZE as i32 {
            break;
        }
        let Some(t) = probe_contract::decode(&buf) else {
            st.refused = st.refused.wrapping_add(1);
            log::warn!("[surface_traits] record refused; {} refused so far", st.refused);
            continue;
        };
        log::info!(
            "[surface_traits] epoch={} {}x{} orient={} sizeW={} sizeH={} displays={} \
             dpr_eighths={} modalities=0x{:04x}",
            t.epoch,
            t.viewport_w_px,
            t.viewport_h_px,
            t.orientation,
            t.size_class_w,
            t.size_class_h,
            t.display_count,
            t.dpr_eighths,
            t.modalities,
        );
    }
    0
}

fn build_linux_surface_traits_probe(module_idx: usize, _params: &[u8]) -> Result<Box<LinuxSurfaceTraitsProbeState>, i32> {
    let in_chan = scheduler::module_port(module_idx, surface_traits_probe_tags::PORT_EVENTS);
    let st = Box::new(LinuxSurfaceTraitsProbeState {
        in_chan,
        refused: 0,
    });
    log::info!("[inst] module {module_idx} = linux_surface_traits_probe (native; in_chan={in_chan})");
    Ok(st)
}

impl HostNative for LinuxSurfaceTraitsProbeState {
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32> {
        build_linux_surface_traits_probe(slot, params)
    }
}

/// The `linux_surface_traits_probe` native module.
pub static LINUX_SURFACE_TRAITS_PROBE: NativeVtable = host_vtable::<LinuxSurfaceTraitsProbeState>(linux_surface_traits_probe_step, native::linux_surface_traits_probe::STATE_BYTES);

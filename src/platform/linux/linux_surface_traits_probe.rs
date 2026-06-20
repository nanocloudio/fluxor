// linux_surface_traits_probe built-in — demo consumer of the Surface Traits
// surface on Linux. Reads `input::surface_traits::MSG_TRAITS` records from its
// input port and logs the decoded fields via `log::info!`, proving the
// round-trip end-to-end on a headless Linux box: linux_surface_traits →
// channel → this probe. Mirrors the wasm `surface_traits_probe`. Not a
// production module — it is the live acceptance check (criterion 1) for the
// Linux authority.

const LINUX_SURFACE_TRAITS_PROBE_HASH: u32 = 0xFADF_1AC6; // fnv1a32("linux_surface_traits_probe")
const PROBE_EVENT_RECORD: usize = 24;

struct LinuxSurfaceTraitsProbeState {
    in_chan: i32,
}

fn linux_surface_traits_probe_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-owned per-instance arena for this module;
    // size-matched to `LinuxSurfaceTraitsProbeState` by the loader.
    let st = unsafe { instance_state::<LinuxSurfaceTraitsProbeState>(state) };
    if st.in_chan < 0 {
        return 0;
    }
    let mut buf = [0u8; PROBE_EVENT_RECORD];
    loop {
        // SAFETY: channel_read takes (chan, *mut u8, max_len); buf is a stack
        // array sized to its length.
        let n = unsafe { channel::channel_read(st.in_chan, buf.as_mut_ptr(), buf.len()) };
        if n < PROBE_EVENT_RECORD as i32 {
            break;
        }
        let orientation = buf[1];
        let size_w = buf[2];
        let size_h = buf[3];
        let view_w = u16::from_le_bytes([buf[4], buf[5]]);
        let view_h = u16::from_le_bytes([buf[6], buf[7]]);
        let modalities = u16::from_le_bytes([buf[8], buf[9]]);
        let epoch = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let display_count = buf[21];
        log::info!(
            "[surface_traits] epoch={epoch} {view_w}x{view_h} orient={orientation} \
             sizeW={size_w} sizeH={size_h} displays={display_count} modalities=0x{modalities:04x}"
        );
    }
    0
}

fn build_linux_surface_traits_probe(module_idx: usize) -> scheduler::BuiltInModule {
    scheduler::set_current_module(module_idx);
    let in_chan = scheduler::get_module_port(module_idx, 0, 0);
    let mut m = scheduler::BuiltInModule::new(
        "linux_surface_traits_probe",
        linux_surface_traits_probe_step,
    );
    install_state(
        &mut m,
        Box::new(LinuxSurfaceTraitsProbeState { in_chan }),
    );
    log::info!("[inst] module {module_idx} = linux_surface_traits_probe (built-in, demo consumer; in_chan={in_chan})");
    m
}

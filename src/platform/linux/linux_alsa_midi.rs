// linux_alsa_midi built-in — STUB.
//
// Real implementation pending. When wired, this will open an ALSA
// seq client (`snd_seq_open`), publish input and/or output ports
// based on the `mode` param, decode incoming `SND_SEQ_EVENT_*` into
// the `input::midi` 4-byte frame shape (per
// `crates/fluxor-abi/src/contracts/input/midi.rs`), and re-encode outgoing
// frames back to ALSA events on the output side.
//
// Params declared in
// `modules/platform/linux/linux_alsa_midi/manifest.toml`:
//   mode:        enum {in, out, duplex} — selects which port(s) open
//   port_filter: str — substring match against ALSA client:port name
//   client_name: str — name the ALSA seq client publishes as
//
// Stub behaviour:
//   - registers in the built-in table so configs load cleanly,
//   - logs a one-shot STUB marker on construction,
//   - **drains** the input channel (`events_in`) every step so a
//     producer wired to MIDI output / duplex doesn't backpressure
//     into a black hole. Reads are discarded.
//
// Per-step drain cap: 256 bytes (64 MIDI frames) is well above
// realistic MIDI rates and bounds the CPU a runaway producer can
// steal from other modules in the same domain.

use fluxor::abi::platform::native::linux::linux_alsa_midi as alsa_midi_tags;


struct LinuxAlsaMidiState {
    /// `events_in` channel handle (input port). `-1` when no
    /// producer is wired (mode=in graphs leave it unbound).
    events_in: i32,
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn linux_alsa_midi_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-owned per-instance arena for this
    // module; size-matched to `LinuxAlsaMidiState` by the loader.
    let st = unsafe { instance_state::<LinuxAlsaMidiState>(state) };
    if st.events_in >= 0 {
        let mut scratch = [0u8; 256];
        // SAFETY: `channel_read` takes (chan, *mut u8, max_len); scratch
        // is a stack buffer sized to its array length.
        unsafe {
            let _ = channel::channel_read(st.events_in, scratch.as_mut_ptr(), scratch.len());
        }
    }
    0
}

fn build_linux_alsa_midi(module_idx: usize, _params: &[u8]) -> Result<Box<LinuxAlsaMidiState>, i32> {
    // Unbound in mode=in graphs, where the handle is -1.
    let events_in = scheduler::module_port(module_idx, alsa_midi_tags::PORT_EVENTS_IN);
    let st = Box::new(LinuxAlsaMidiState { events_in });
    log::warn!(
        "[inst] module {module_idx} = linux_alsa_midi (built-in, STUB — ALSA seq integration not yet implemented; \
         events_in={events_in} drains to /dev/null)"
    );
    Ok(st)
}

impl HostNative for LinuxAlsaMidiState {
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32> {
        build_linux_alsa_midi(slot, params)
    }
}

/// The `linux_alsa_midi` native module.
pub static LINUX_ALSA_MIDI: NativeVtable = host_vtable::<LinuxAlsaMidiState>(linux_alsa_midi_step, native::linux_alsa_midi::STATE_BYTES);

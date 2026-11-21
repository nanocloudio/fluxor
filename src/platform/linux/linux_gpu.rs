// linux_gpu built-in — the channel edge of the native GPU provider.
//
// Everything that decides anything lives in `fluxor::platform::linux::gpu`,
// which takes command bytes and produces outcome bytes and touches no channel.
// This file is the handful of lines that make it a graph module: read the
// input port, step, write the output port.
//
// Split that way so the provider can be driven against a real adapter from the
// host test harness. A backend that can only be exercised by booting a whole
// graph is a backend whose faults are found on hardware, at the end.

use fluxor::abi::platform::native::linux::linux_gpu as gpu_tags;
use fluxor::abi::platform::native::linux::linux_gpu::{
    TAG_RESIDENT_MB as GPU_TAG_RESIDENT_MB, TAG_STAGING_KB as GPU_TAG_STAGING_KB,
};
use fluxor::platform::linux::gpu::GpuProvider;


/// Bytes read from the command port per step. One whole record does not have
/// to fit in a read: the provider buffers a partial one and decodes it when
/// the rest arrives.
const READ_CHUNK: usize = 32 * 1024;

struct LinuxGpuInstance {
    in_chan: i32,
    out_chan: i32,
    provider: GpuProvider,
    /// Outcome bytes the output channel has not taken yet. Channel writes are
    /// all-or-nothing, so a run that does not fit is retained and retried —
    /// dropping it would be indistinguishable to a consumer from work that
    /// never ran.
    owed: Vec<u8>,
    /// Logged once, when the adapter opens or is refused.
    announced: bool,
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn linux_gpu_step(state: *mut u8) -> i32 {
    // SAFETY: the instance's arena state, holding the `LinuxGpuInstance`
    // `build_linux_gpu` built.
    let st = unsafe { instance_state::<LinuxGpuInstance>(state) };
    if st.in_chan < 0 {
        return 0;
    }

    // Retire what the channel would not take last step before producing more.
    flush_owed(st);

    // Read even with no adapter open: a request the provider never sees is a
    // request nobody can answer, and the provider answers what it cannot run.
    let mut buf = [0u8; READ_CHUNK];
    while st.provider.command_space() >= buf.len() {
        // SAFETY: stack buffer; `channel_read` writes at most `buf.len()`.
        let n = unsafe { channel::channel_read(st.in_chan, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        let taken = st.provider.feed(&buf[..n as usize]);
        if taken < n as usize {
            // Cannot happen while the space check above holds; if it ever
            // does, saying so beats losing the tail silently.
            log::error!("[linux_gpu] dropped {} command bytes", n as usize - taken);
        }
    }

    let mut produced = Vec::new();
    st.provider.step(&mut produced);
    if !st.announced && (st.provider.live() || st.provider.unavailable()) {
        st.announced = true;
        if st.provider.live() {
            let l = st.provider.limits();
            log::info!(
                "[linux_gpu] adapter live — align {} B, workgroup {}x{}x{}, {} bindings, \
                 resident {} MiB",
                l.min_align,
                l.max_workgroup[0],
                l.max_workgroup[1],
                l.max_workgroup[2],
                l.max_bindings,
                l.max_resident_bytes / (1024 * 1024),
            );
        } else {
            log::warn!("[linux_gpu] no adapter — every request is answered with a rejection");
        }
    }
    st.owed.extend_from_slice(&produced);
    flush_owed(st);
    0
}

/// Write as much of the owed outcome run as the channel will take.
fn flush_owed(st: &mut LinuxGpuInstance) {
    if st.out_chan < 0 {
        st.owed.clear();
        return;
    }
    if st.owed.is_empty() {
        return;
    }
    let mut sent = 0usize;
    while sent < st.owed.len() {
        // SAFETY: `sent < owed.len()`, so the pointer and length name bytes
        // inside the buffer.
        let n = unsafe {
            channel::channel_write(
                st.out_chan,
                st.owed.as_ptr().add(sent),
                st.owed.len() - sent,
            )
        };
        if n <= 0 {
            break;
        }
        sent += n as usize;
    }
    st.owed.drain(..sent);
}

fn build_linux_gpu(module_idx: usize, params: &[u8]) -> Result<Box<LinuxGpuInstance>, i32> {
    let mut resident_mb: u64 = 256;
    let mut staging_kb: u64 = 16 * 1024;
    walk_tlv(params, |tag, value| match tag {
        GPU_TAG_RESIDENT_MB => resident_mb = u64::from(tlv_u32(value)),
        GPU_TAG_STAGING_KB => staging_kb = u64::from(tlv_u32(value)),
        _ => {}
    });
    let in_chan = scheduler::module_port(module_idx, gpu_tags::PORT_COMMANDS);
    let out_chan = scheduler::module_port(module_idx, gpu_tags::PORT_OUTCOMES);

    // The device thread starts here and opens its adapter in the background:
    // adapter creation alone can take hundreds of milliseconds, and graph
    // construction has no more room for that than a step does.
    let provider = GpuProvider::new(
        resident_mb.saturating_mul(1024 * 1024),
        staging_kb.saturating_mul(1024),
    );
    let st = Box::new(LinuxGpuInstance {
            in_chan,
            out_chan,
            provider,
            owed: Vec::new(),
            announced: false,
        });
    log::info!(
        "[inst] module {module_idx} = linux_gpu (built-in) in={in_chan} out={out_chan} \
         resident={resident_mb} MiB staging={staging_kb} KiB"
    );
    Ok(st)
}

impl HostNative for LinuxGpuInstance {
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32> {
        build_linux_gpu(slot, params)
    }
}

/// The `linux_gpu` native module.
pub static LINUX_GPU: NativeVtable = host_vtable::<LinuxGpuInstance>(linux_gpu_step);

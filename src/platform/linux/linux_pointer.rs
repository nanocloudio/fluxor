// Native Linux pointer/touch input authority: the evdev source of
// `PointerEvents`. Reads Linux `input_event` records from an evdev device
// (or a FIFO carrying the same byte layout, for a run with no hardware)
// and writes pointer records (`abi::contracts::input::pointer`) on its
// `events` output, so an application that draws its own interface can
// hit-test a touchscreen or a mouse and scroll with its wheel.
//
// The decoding is `fluxor::platform::linux::evdev_pointer`: touch and mouse
// fold into down, move and up records scaled to the surface, and the wheel
// into `KIND_WHEEL` records in 1/120 detent. This file reads the device
// and writes the channel. Records wait in a bounded queue: one the channel
// refuses is offered again on the next step, and while the queue is full
// the device is not read, so a slow consumer delays input and loses none.
// Included into `linux.rs`; shares its imports.

use fluxor::abi::platform::native::linux::linux_pointer as pointer_tags;
use fluxor::abi::platform::native::linux::linux_pointer::{
    TAG_HEIGHT as POINTER_TAG_HEIGHT, TAG_PATH as POINTER_TAG_PATH, TAG_WIDTH as POINTER_TAG_WIDTH,
    TAG_X_MAX as POINTER_TAG_X_MAX, TAG_Y_MAX as POINTER_TAG_Y_MAX,
};
use fluxor::platform::linux::evdev_pointer::{EvdevPointer, EVENT_SIZE as EVDEV_EVENT_SIZE};
use fluxor::platform::linux::input_queue::RecordQueue;

struct LinuxPointerState {
    fd: i32,
    opened: bool,
    out_chan: i32,
    path: String,
    pointer: EvdevPointer,
    /// Records decoded and not yet taken by the channel.
    pending: RecordQueue,
    /// Device bytes read and not yet decoded: a FIFO may split an event,
    /// and a full queue leaves whole events waiting.
    rbuf: [u8; EVDEV_EVENT_SIZE * 64],
    rbuf_len: usize,
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn linux_pointer_step(state: *mut u8) -> i32 {
    // SAFETY: kernel-owned arena sized to `LinuxPointerState` by the loader.
    let st = unsafe { instance_state::<LinuxPointerState>(state) };
    if st.out_chan < 0 {
        return 0;
    }

    if !st.opened {
        st.opened = true;
        match std::ffi::CString::new(st.path.clone()) {
            Ok(c) => {
                // SAFETY: `c` is a valid NUL-terminated path for the call.
                let fd = unsafe {
                    libc::open(
                        c.as_ptr(),
                        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                };
                st.fd = fd;
                if fd < 0 {
                    log::warn!(
                        "[linux_pointer] open '{}' failed: no input this run (attach a device or point `path` at an evdev node or a FIFO)",
                        st.path
                    );
                } else {
                    log::info!("[linux_pointer] reading '{}'", st.path);
                }
            }
            Err(_) => st.fd = -1,
        }
    }

    let out_chan = st.out_chan;
    let mut write = |record: &[u8]| {
        // SAFETY: `record` is readable for its length; the channel copies it.
        let written = unsafe { channel::channel_write(out_chan, record.as_ptr(), record.len()) };
        written > 0 && written as usize == record.len()
    };
    st.pending.relay(&mut write);
    if st.fd < 0 {
        return 0;
    }

    // One read a step: what the buffer has room for, after any bytes kept.
    if st.rbuf_len < st.rbuf.len() {
        let want = st.rbuf.len() - st.rbuf_len;
        // SAFETY: writing into the tail of the buffer, at most `want` bytes.
        let n = unsafe {
            libc::read(
                st.fd,
                st.rbuf.as_mut_ptr().add(st.rbuf_len) as *mut libc::c_void,
                want,
            )
        };
        // Nothing to read, or the writer closed: neither is an error.
        if n > 0 {
            st.rbuf_len += n as usize;
        }
    }

    let used = st.pointer.feed(&st.rbuf[..st.rbuf_len], &mut st.pending);
    if used > 0 {
        st.rbuf.copy_within(used..st.rbuf_len, 0);
        st.rbuf_len -= used;
    }
    st.pending.relay(&mut write);
    0
}

fn build_linux_pointer(module_idx: usize, params: &[u8]) -> Result<Box<LinuxPointerState>, i32> {
    let mut path = String::from("/dev/input/event0");
    let mut width: i32 = 960;
    let mut height: i32 = 540;
    let mut x_max: i32 = 0;
    let mut y_max: i32 = 0;
    walk_tlv(params, |tag, value| match tag {
        POINTER_TAG_PATH => path = tlv_str(value).to_string(),
        POINTER_TAG_WIDTH => width = tlv_u32(value) as i32,
        POINTER_TAG_HEIGHT => height = tlv_u32(value) as i32,
        POINTER_TAG_X_MAX => x_max = tlv_u32(value) as i32,
        POINTER_TAG_Y_MAX => y_max = tlv_u32(value) as i32,
        _ => {}
    });
    let out_chan = scheduler::module_port(module_idx, pointer_tags::PORT_EVENTS);
    let st = Box::new(LinuxPointerState {
        fd: -1,
        opened: false,
        out_chan,
        path,
        pointer: EvdevPointer::new(width, height, x_max, y_max),
        pending: RecordQueue::default(),
        rbuf: [0u8; EVDEV_EVENT_SIZE * 64],
        rbuf_len: 0,
    });
    log::info!("[linux_pointer] surface {width}x{height} (x_max={x_max} y_max={y_max})");
    log::info!("[inst] module {module_idx} = linux_pointer (native) out_chan={out_chan}");
    Ok(st)
}

impl HostNative for LinuxPointerState {
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32> {
        build_linux_pointer(slot, params)
    }
}

/// The `linux_pointer` native module.
pub static LINUX_POINTER: NativeVtable =
    host_vtable::<LinuxPointerState>(linux_pointer_step, native::linux_pointer::STATE_BYTES);

// Native Linux pointer/touch input authority — the evdev counterpart of
// `wasm_browser_pointer`. Reads Linux `input_event` records from an evdev
// device (or a FIFO carrying the same byte layout, for headless testing)
// and emits `input::pointer::MSG_EVENT` 16-byte records on its `events`
// output, so a content-plane UI can hit-test taps on a connected LCD
// touchscreen or mouse with no host chrome.
//
// Absolute touch (ABS_X/ABS_Y, ABS_MT_POSITION_X/_Y + BTN_TOUCH) and
// relative mouse (REL_X/REL_Y + BTN_LEFT) both fold into down/move/up
// pointer records, scaled from the device axis range to the surface's
// logical geometry. Included into `linux.rs`; shares its imports.

use fluxor::platform::builtin_param_tags::linux_pointer::{
    TAG_HEIGHT as POINTER_TAG_HEIGHT, TAG_PATH as POINTER_TAG_PATH, TAG_WIDTH as POINTER_TAG_WIDTH,
    TAG_X_MAX as POINTER_TAG_X_MAX, TAG_Y_MAX as POINTER_TAG_Y_MAX,
};
use fluxor::platform::builtin_param_tags::linux_pointer as pointer_tags;

const LINUX_POINTER_HASH: u32 = 0xEEA3_12EF; // fnv1a32("linux_pointer")

// Linux `struct input_event` on 64-bit: timeval(16) + type(2) + code(2) +
// value(4). Reads on an evdev node return whole events; a FIFO may split,
// so a partial tail is carried across steps.
const EVDEV_EVENT_SIZE: usize = 24;

// event types
const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
// codes
const SYN_REPORT: u16 = 0x00;
const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const ABS_MT_POSITION_X: u16 = 0x35; // 53
const ABS_MT_POSITION_Y: u16 = 0x36; // 54
const BTN_LEFT: u16 = 0x110;
const BTN_TOUCH: u16 = 0x14a;

// input::pointer record — mirrors modules/sdk/contracts/input/pointer.rs.
const PTR_MSG_EVENT: u8 = 0x01;
const PTR_KIND_DOWN: u8 = 1;
const PTR_KIND_UP: u8 = 2;
const PTR_KIND_MOVE: u8 = 3;
const PTR_BTN_PRIMARY: u8 = 0x01;
const PTR_PRESSURE_DEFAULT: u16 = 511;

struct LinuxPointerState {
    fd: i32,
    opened: bool,
    out_chan: i32,
    width: i32,
    height: i32,
    x_max: i32,
    y_max: i32,
    cur_x: i32,
    cur_y: i32,
    down: bool,
    prev_down: bool,
    last_x: i32,
    last_y: i32,
    path: String,
    rbuf: [u8; EVDEV_EVENT_SIZE * 64],
    rbuf_len: usize,
}

/// Scale a raw axis value into logical space. `axis_max == 0` means the
/// value is already logical (mouse / pre-scaled FIFO input): pass through.
fn scale_axis(v: i32, axis_max: i32, logical: i32) -> i16 {
    let out = if axis_max > 0 {
        (v.max(0) as i64 * (logical as i64 - 1) / axis_max as i64) as i32
    } else {
        v
    };
    out.clamp(0, logical - 1) as i16
}

/// Emit one pointer record at a `SYN_REPORT` boundary if the frame carried
/// a meaningful transition (press edge, release edge, or a move while down).
fn linux_pointer_emit(st: &mut LinuxPointerState) {
    let kind = if st.down && !st.prev_down {
        PTR_KIND_DOWN
    } else if !st.down && st.prev_down {
        PTR_KIND_UP
    } else if st.down && (st.cur_x != st.last_x || st.cur_y != st.last_y) {
        PTR_KIND_MOVE
    } else {
        st.prev_down = st.down;
        return;
    };
    st.prev_down = st.down;
    st.last_x = st.cur_x;
    st.last_y = st.cur_y;

    let x = scale_axis(st.cur_x, st.x_max, st.width);
    let y = scale_axis(st.cur_y, st.y_max, st.height);
    let pressure: u16 = if st.down { PTR_PRESSURE_DEFAULT } else { 0 };

    let mut rec = [0u8; 16];
    rec[0] = PTR_MSG_EVENT;
    rec[1] = 0; // pointer_id
    rec[2] = kind;
    rec[3] = if st.down { PTR_BTN_PRIMARY } else { 0 };
    // rec[4] modifiers, rec[5] pad = 0
    rec[6..8].copy_from_slice(&pressure.to_le_bytes());
    rec[8..10].copy_from_slice(&x.to_le_bytes());
    rec[10..12].copy_from_slice(&y.to_le_bytes());
    // rec[12..16] pad = 0
    // SAFETY: 16-byte stack record; channel_write copies `len` bytes out.
    unsafe {
        channel::channel_write(st.out_chan, rec.as_ptr(), rec.len());
    }
}

fn linux_pointer_step(state: *mut u8) -> i32 {
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
                let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
                st.fd = fd;
                if fd < 0 {
                    log::warn!(
                        "[linux_pointer] open '{}' failed — no input this run (attach a device or point `path` at an evdev node / FIFO)",
                        st.path
                    );
                } else {
                    log::info!(
                        "[linux_pointer] reading '{}' → {}x{} logical (x_max={} y_max={})",
                        st.path, st.width, st.height, st.x_max, st.y_max
                    );
                }
            }
            Err(_) => st.fd = -1,
        }
    }
    if st.fd < 0 {
        return 0;
    }

    // Drain available input_event bytes (non-blocking) after any carried tail.
    loop {
        if st.rbuf_len >= st.rbuf.len() {
            break;
        }
        let want = st.rbuf.len() - st.rbuf_len;
        // SAFETY: writing into the tail of a fixed stack/heap buffer, ≤ `want`.
        let n = unsafe {
            libc::read(
                st.fd,
                st.rbuf.as_mut_ptr().add(st.rbuf_len) as *mut libc::c_void,
                want,
            )
        };
        if n <= 0 {
            break; // EAGAIN (no data) or EOF
        }
        st.rbuf_len += n as usize;
        if (n as usize) < want {
            break;
        }
    }

    // Decode whole events; a frame closes on SYN_REPORT.
    let mut off = 0usize;
    while off + EVDEV_EVENT_SIZE <= st.rbuf_len {
        let ev = &st.rbuf[off..off + EVDEV_EVENT_SIZE];
        let etype = u16::from_le_bytes([ev[16], ev[17]]);
        let code = u16::from_le_bytes([ev[18], ev[19]]);
        let value = i32::from_le_bytes([ev[20], ev[21], ev[22], ev[23]]);
        match etype {
            EV_ABS => match code {
                ABS_X | ABS_MT_POSITION_X => st.cur_x = value,
                ABS_Y | ABS_MT_POSITION_Y => st.cur_y = value,
                _ => {}
            },
            EV_REL => match code {
                REL_X => st.cur_x += value,
                REL_Y => st.cur_y += value,
                _ => {}
            },
            EV_KEY => {
                if code == BTN_TOUCH || code == BTN_LEFT {
                    st.down = value != 0;
                }
            }
            EV_SYN => {
                if code == SYN_REPORT {
                    linux_pointer_emit(st);
                }
            }
            _ => {}
        }
        off += EVDEV_EVENT_SIZE;
    }
    // Carry the partial-event tail (FIFO writers may not align to 24 bytes).
    if off > 0 {
        st.rbuf.copy_within(off..st.rbuf_len, 0);
        st.rbuf_len -= off;
    }
    0
}

fn build_linux_pointer(module_idx: usize, params: &[u8]) -> scheduler::BuiltInModule {
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

    scheduler::set_current_module(module_idx);
    let out_chan = scheduler::module_port(module_idx, pointer_tags::PORT_EVENTS);
    let mut m = scheduler::BuiltInModule::new("linux_pointer", linux_pointer_step);
    install_state(
        &mut m,
        Box::new(LinuxPointerState {
            fd: -1,
            opened: false,
            out_chan,
            width: width.max(1),
            height: height.max(1),
            x_max,
            y_max,
            cur_x: 0,
            cur_y: 0,
            down: false,
            prev_down: false,
            last_x: -1,
            last_y: -1,
            path,
            rbuf: [0u8; EVDEV_EVENT_SIZE * 64],
            rbuf_len: 0,
        }),
    );
    log::info!("[inst] module {module_idx} = linux_pointer (built-in) out_chan={out_chan}");
    m
}

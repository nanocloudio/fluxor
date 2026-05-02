//! `host_browser_fetch` built-in: HTTP fetch source. Opens the
//! configured URL through the host shim and emits the response body
//! bytes on its output channel as they arrive.
//!
//! State: heap-allocated; the BuiltInModule's 64-byte inline state
//! holds a `*mut FetchState` pointer.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    /// Issue an HTTP GET to `url_ptr[..url_len]` (UTF-8). Returns a
    /// non-negative handle the caller uses with `host_fetch_recv`,
    /// or negative errno. The shim opens the request asynchronously;
    /// `host_fetch_recv` returns 0 (pending) until the first chunk
    /// arrives.
    fn host_fetch_open(url_ptr: *const u8, url_len: usize) -> i32;

    /// Drain bytes from the response body into `buf`. Returns:
    /// `> 0` bytes written; `= 0` pending (no chunk yet, more may come);
    /// `= -1` EOF (response complete); `< -1` error.
    fn host_fetch_recv(handle: i32, buf: *mut u8, len: usize) -> i32;
}

const RX_BUF_BYTES: usize = 4096;
const URL_BUF_BYTES: usize = 256;
/// Per-`channel_write` chunk size. Fluxor's FIFO ring buffer is
/// all-or-nothing on writes (partial writes corrupt message framing),
/// so a write that exceeds the available space returns 0 with no
/// progress. Fragmenting here keeps each attempt small enough that
/// it almost always fits, even when the consumer is mid-drain.
/// CHANNEL_BUFFER_SIZE is 2 KiB by default; 512 leaves comfortable
/// headroom for partial-drain states.
const WRITE_CHUNK_BYTES: usize = 512;

#[repr(C)]
pub(crate) struct FetchState {
    pub out_chan: i32,
    pub handle: i32,
    pub url_len: u32,
    pub url: [u8; URL_BUF_BYTES],
    pub rx: [u8; RX_BUF_BYTES],
    /// Bytes already pulled from `host_fetch_recv` but not yet
    /// accepted by `channel_write` (back-pressured). The leading
    /// `pending_pos` bytes of `rx` are spent; bytes
    /// `[pending_pos .. pending_len)` are queued for the next write.
    /// `host_fetch_recv` is only called when `pending_len == pending_pos`
    /// (drained), so a partial write never loses data.
    pub pending_pos: u32,
    pub pending_len: u32,
    pub opened: bool,
    pub eof: bool,
}

unsafe fn alloc_state(out_chan: i32, url: &[u8]) -> *mut FetchState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<FetchState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut FetchState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let mut url_buf = [0u8; URL_BUF_BYTES];
    let copy_len = url.len().min(URL_BUF_BYTES);
    url_buf[..copy_len].copy_from_slice(&url[..copy_len]);
    core::ptr::write(
        raw,
        FetchState {
            out_chan,
            handle: -1,
            url_len: copy_len as u32,
            url: url_buf,
            rx: [0u8; RX_BUF_BYTES],
            pending_pos: 0,
            pending_len: 0,
            opened: false,
            eof: false,
        },
    );
    raw
}

fn fetch_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut FetchState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;

        if st.eof {
            return 0;
        }

        // Lazy connect on first step. Same pattern as websocket.
        if !st.opened {
            let h = host_fetch_open(st.url.as_ptr(), st.url_len as usize);
            if h >= 0 {
                st.handle = h;
                st.opened = true;
            } else {
                return 0;
            }
        }

        if st.out_chan < 0 {
            return 0;
        }

        // Two-phase per tick:
        //   1. Drain any pending bytes from a previous tick that
        //      `channel_write` couldn't take in full. Bytes are kept
        //      in `rx[pending_pos..pending_len]` and sent before any
        //      new chunk is read from the shim — partial writes
        //      never lose data.
        //   2. Once pending is empty, ask the shim for more bytes
        //      via `host_fetch_recv`, then attempt to write them.
        //      A partial write rolls the unwritten tail into pending.
        loop {
            // Phase 1: flush pending. Walk in `WRITE_CHUNK_BYTES`
            // pieces — each is small enough to fit a typical
            // 2 KiB channel buffer even when partly full.
            while st.pending_pos < st.pending_len {
                let start = st.pending_pos as usize;
                let remaining = (st.pending_len - st.pending_pos) as usize;
                let want = remaining.min(WRITE_CHUNK_BYTES);
                let written = channel::channel_write(
                    st.out_chan,
                    st.rx.as_ptr().add(start),
                    want,
                );
                if written <= 0 {
                    // Still no room — try again next tick.
                    return 0;
                }
                st.pending_pos += written as u32;
            }
            // Pending fully drained.
            st.pending_pos = 0;
            st.pending_len = 0;

            // Phase 2: pull more from the shim.
            let n = host_fetch_recv(st.handle, st.rx.as_mut_ptr(), st.rx.len());
            if n == 0 {
                return 0;
            }
            if n < 0 {
                // EOF or error. Signal HUP so the consumer can
                // finalize.
                st.eof = true;
                let _ = channel::channel_ioctl(
                    st.out_chan,
                    channel::IOCTL_SET_HUP,
                    core::ptr::null_mut(),
                );
                return 0;
            }
            // Write the freshly-fetched bytes in `WRITE_CHUNK_BYTES`
            // pieces. If any sub-chunk fails, stash the unwritten
            // remainder as pending and bail.
            let total = n as usize;
            let mut offset = 0usize;
            while offset < total {
                let want = (total - offset).min(WRITE_CHUNK_BYTES);
                let written = channel::channel_write(
                    st.out_chan,
                    st.rx.as_ptr().add(offset),
                    want,
                );
                if written <= 0 {
                    st.pending_pos = offset as u32;
                    st.pending_len = total as u32;
                    return 0;
                }
                offset += written as usize;
            }
            // Whole chunk delivered — loop and try the next.
        }
    }
}

pub(crate) unsafe fn build(url: &[u8], out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("host_browser_fetch", fetch_step);
    let raw = alloc_state(out_chan, url);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut FetchState, raw);
    m
}

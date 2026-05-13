//! `log` crate backend — formats records into the kernel log ring.
//!
//! Parallel to the RingLogger on RP platforms: both routes funnel every
//! `log::info!` etc. into `kernel::log_ring::push_bytes`. Wire output is
//! driven by an opt-in overlay module (log_uart / log_usb / log_net).

pub struct RingLogger;

impl log::Log for RingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        use core::fmt::Write;
        // Format into a stack buffer first, then push the whole record
        // (plus CRLF) into the ring in a single call. Incremental
        // write_str pushes let a preempting ISR or cross-core producer
        // interleave bytes with our message; per-record staging prevents
        // that on both single-core and multi-core boots.
        struct BufWriter<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }
        impl<'a> Write for BufWriter<'a> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let remaining = self.buf.len().saturating_sub(self.pos);
                let take = bytes.len().min(remaining);
                self.buf[self.pos..self.pos + take].copy_from_slice(&bytes[..take]);
                self.pos += take;
                Ok(())
            }
        }

        let mut buf = [0u8; 256];
        let written = {
            let mut w = BufWriter {
                buf: &mut buf,
                pos: 0,
            };
            let _ = core::fmt::write(&mut w, *record.args());
            if w.pos + 2 <= w.buf.len() {
                w.buf[w.pos] = b'\r';
                w.buf[w.pos + 1] = b'\n';
                w.pos += 2;
            }
            w.pos
        };
        fluxor::kernel::log_ring::push_bytes(&buf[..written]);
    }
    fn flush(&self) {}
}

// gpu_pump_core — the provider loop every GPU backend runs.
//
// Between the wire contract and a backend's device objects sits a channel
// pump: read command bytes, admit one record at a time, execute what admission
// produced, push outcome records back. The shape is the same for the
// null/replay provider, the browser one and the native one, and so are the
// four decisions inside it that are easy to get wrong in different ways in
// each copy:
//
//   - **A framing fault is latched, not repeated.** A byte FIFO cannot be
//     resynchronised, so the stream is over. Without latching, a provider
//     reports one rejection per read chunk, which reads to a producer as a
//     storm rather than as the single "this stream is finished" that it is.
//   - **A chunked program pack is assembled under one identity.** Chunks are
//     tied together by the program handle and refused unless they continue at
//     exactly the offset already received. Two interleaved loads spliced into
//     one buffer would produce an artifact whose digest check passes on bytes
//     nobody sent.
//   - **Outcome bytes are staged, not re-drained.** Channel writes are
//     all-or-nothing; a run the channel would not take is retried from where
//     it stopped. Re-draining the ring instead would need the ring's cursor
//     rolled back, and a provider that rolls it back at the wrong moment
//     emits every record twice.
//   - **A provider with no device still answers.** Discarding the requests it
//     cannot run would leave a consumer waiting on outcomes that can never
//     come, which is indistinguishable from a provider that is merely slow.
//
// What is NOT here is execution: what a dispatch does, how a pipeline is
// built, when a readback's bytes exist. That is the half each backend owns.
//
// Pure logic over caller-owned storage: no allocation, no clock, no syscall.
// `no_std`.
//
// Mount alongside `sdk/wire/gpu_wire.rs`, `sdk/cores/gpu_pack.rs` and
// `sdk/cores/gpu_device.rs`.

// ── Outcome staging ─────────────────────────────────────────────────────

/// How far a drained run of outcome records has got towards the output.
///
/// Lives in the provider's own state because it must survive a step: the
/// bytes are already out of the device's ring, so losing this cursor loses
/// them.
#[derive(Clone, Copy, Debug, Default)]
pub struct OutCursor {
    pub pending: u32,
    pub sent: u32,
}

/// Move outcome records from the device's ring to the caller's transport.
///
/// `write` takes a byte run and answers how many it accepted — negative or
/// zero meaning "not now". Whatever it leaves is retained here and retried,
/// so backpressure never becomes loss.
///
/// The caller must save the device's scalars AFTER this returns. Draining
/// advances the ring's cursor, and a save taken before it would roll that
/// cursor back and re-emit every record on the next step.
pub fn flush_outcomes(
    dev: &mut GpuDevice<'_>,
    stage: &mut [u8],
    cur: &mut OutCursor,
    mut write: impl FnMut(&[u8]) -> i32,
) {
    loop {
        if cur.pending == 0 {
            let n = dev.drain_outcomes(stage);
            if n == 0 {
                return;
            }
            cur.pending = n as u32;
            cur.sent = 0;
        }
        let from = cur.sent as usize;
        let to = cur.pending as usize;
        let wrote = write(&stage[from..to]);
        if wrote <= 0 {
            return;
        }
        cur.sent += wrote as u32;
        if cur.sent >= cur.pending {
            cur.pending = 0;
            cur.sent = 0;
        } else {
            return;
        }
    }
}

// ── Chunked program packs ───────────────────────────────────────────────

/// Progress through one program pack being assembled from several records.
#[derive(Clone, Copy, Debug)]
pub struct PackCursor {
    pub len: u32,
    pub slot: u16,
    pub active: bool,
}

impl PackCursor {
    #[must_use]
    pub const fn idle() -> Self {
        Self {
            len: 0,
            slot: NO_SLOT,
            active: false,
        }
    }
}

/// What absorbing a chunk means for the load as a whole.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PackChunk {
    /// The chunk was stored; more are expected. This chunk's own fence has
    /// been completed.
    More,
    /// Every declared byte has arrived and validated. The program is usable
    /// and the fence is complete.
    Loaded,
    /// The load failed and the fence carries the reason. The program slot is
    /// retired — a pack that did not validate leaves nothing behind.
    Failed(u16),
}

/// Absorb one `LOAD_PROGRAM` chunk into `buf`, validating the whole pack once
/// the last byte arrives.
///
/// One assembly buffer, one load: a second concurrent load is refused rather
/// than interleaved, because the alternative is an artifact assembled from two
/// producers' bytes that nonetheless passes its own digest check.
pub fn absorb_pack_chunk(
    dev: &mut GpuDevice<'_>,
    cur: &mut PackCursor,
    buf: &mut [u8],
    fence: u16,
    slot: u16,
    chunk_offset: u32,
    bytes: &[u8],
) -> PackChunk {
    if chunk_offset == 0 {
        if cur.active && cur.slot != slot {
            dev.fail(fence, REASON_RESOURCE_EXHAUSTED, 0);
            return PackChunk::Failed(REASON_RESOURCE_EXHAUSTED);
        }
        cur.active = true;
        cur.slot = slot;
        cur.len = 0;
    } else if !cur.active || cur.slot != slot || cur.len != chunk_offset {
        dev.fail(fence, REASON_BAD_RANGE, cur.len);
        return PackChunk::Failed(REASON_BAD_RANGE);
    }

    let end = cur.len as usize + bytes.len();
    if end > buf.len() {
        cur.active = false;
        dev.fail(fence, REASON_OVERSIZE, end as u32);
        return PackChunk::Failed(REASON_OVERSIZE);
    }
    buf[cur.len as usize..end].copy_from_slice(bytes);
    cur.len = end as u32;

    if dev.program_outstanding(slot) != 0 {
        // More to come. This chunk's own fence is done — the bytes landed.
        dev.complete(fence, 0);
        return PackChunk::More;
    }

    match dev.finish_program(slot, &buf[..end]) {
        Ok(()) => {
            dev.complete(fence, 0);
            *cur = PackCursor::idle();
            PackChunk::Loaded
        }
        Err(e) => {
            dev.fail(fence, REASON_BAD_PROGRAM, e as u32);
            *cur = PackCursor::idle();
            PackChunk::Failed(REASON_BAD_PROGRAM)
        }
    }
}

// ── The admit loop ──────────────────────────────────────────────────────

/// Why the pump stopped consuming.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PumpStop {
    /// Nothing left to read, or a partial record awaits more bytes.
    Drained,
    /// The outcome ring cannot hold another request's answers. Drain and
    /// resume; nothing was consumed.
    Backpressure,
    /// The backend asked to stop — it has work that must settle before more
    /// is admitted.
    BackendBusy,
    /// The stream desynchronised. It is finished; a rejection has been
    /// emitted and `faulted` is now set.
    Faulted,
}

/// Admit and execute records from `cmd[..*cmd_len]`, compacting what remains.
///
/// `exec` carries out one admitted request and answers whether the pump may
/// keep going. A backend that has just taken on work it must finish before
/// accepting more — a readback whose bytes are still owed, say — answers
/// false, and the caller resumes next step.
///
/// A faulted stream is never read again. That is the whole meaning of a
/// framing fault: the producer must reconnect.
pub fn pump_admit(
    dev: &mut GpuDevice<'_>,
    owner: u16,
    cmd: &mut [u8],
    cmd_len: &mut u32,
    faulted: &mut bool,
    mut exec: impl FnMut(&mut GpuDevice<'_>, &[u8], Work) -> bool,
) -> PumpStop {
    if *faulted {
        *cmd_len = 0;
        return PumpStop::Faulted;
    }
    let mut off = 0usize;
    let mut stop = PumpStop::Drained;
    while off < *cmd_len as usize {
        match dev.admit(owner, &cmd[off..*cmd_len as usize]) {
            Admit::NeedMore => break,
            Admit::Backpressure => {
                stop = PumpStop::Backpressure;
                break;
            }
            Admit::Fault { .. } => {
                off = *cmd_len as usize;
                *faulted = true;
                stop = PumpStop::Faulted;
                break;
            }
            Admit::Consumed { bytes, work } => {
                // The record is read straight out of the command buffer the
                // caller owns, so a backend copies upload bytes from it
                // without an intermediate staging copy. The device borrows
                // its own tables, never this buffer.
                let keep_going = exec(dev, &cmd[off..off + bytes], work);
                off += bytes;
                if !keep_going {
                    stop = PumpStop::BackendBusy;
                    break;
                }
            }
        }
    }
    if off > 0 {
        cmd.copy_within(off..*cmd_len as usize, 0);
        *cmd_len -= off as u32;
    }
    stop
}

/// Answer every whole record in `cmd[..*cmd_len]` with a rejection, and
/// compact what is left.
///
/// What a provider with no device does. Discarding the bytes is not an option:
/// to a consumer, a request that was silently dropped is indistinguishable
/// from one still in flight, so it would wait for an outcome that can never
/// come. `OUT_REJECTED` is the honest answer — nothing was admitted, no fence
/// was allocated, no state changed.
///
/// `emit` writes one whole record and answers how many bytes it took. A short
/// answer is backpressure: the record that was refused stays buffered and is
/// answered on a later call.
pub fn refuse_records(
    cmd: &mut [u8],
    cmd_len: &mut u32,
    faulted: &mut bool,
    reason: u16,
    mut emit: impl FnMut(&[u8]) -> i32,
) {
    if *faulted {
        *cmd_len = 0;
        return;
    }
    let end = *cmd_len as usize;
    let mut rec = [0u8; HEADER_LEN + REJECT_PAYLOAD_LEN];
    let mut off = 0usize;
    while off < end {
        match Header::decode(&cmd[off..end]) {
            Ok(Some(h)) if end - off >= h.total_len() => {
                let Some(n) = encode_reject(&mut rec, h.corr, reason, 0) else {
                    break;
                };
                if emit(&rec[..n]) != n as i32 {
                    break;
                }
                off += h.total_len();
            }
            // The rest of the record has not arrived. It is owed an answer
            // too, so keep it rather than answering a length nobody sent.
            Ok(_) => break,
            Err(fault) => {
                // A byte FIFO cannot be resynchronised by hunting for the next
                // plausible header, so the stream ends here.
                let Some(n) = encode_reject(&mut rec, 0, fault, 0) else {
                    break;
                };
                if emit(&rec[..n]) == n as i32 {
                    *faulted = true;
                    off = end;
                }
                break;
            }
        }
    }
    if off > 0 {
        cmd.copy_within(off..end, 0);
        *cmd_len -= off as u32;
    }
}

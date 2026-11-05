// Contract: agent — one request and its answer between a controller and a
// target's node agent: desired bundle, target descriptor revision, idempotency
// identity, observed activation and fenced status.
//
// Layer: contracts (public, stable).
//
// One record per message, little-endian, tightly packed, at most
// [`AGENT_RECORD_MAX`] bytes. Decoding checks every bound and never panics; a
// record that fails it is refused whole. Semantics are in
// `docs/architecture/agent_protocol.md`.
//
// ```text
// request (REQUEST_LEN):
//   [op:u8][flags:u8][workload_uid:16][desired_bundle_digest:32]
//   [descriptor_revision:32][idempotency_id:16][fence_epoch:u64][fence_seq:u64]
//
// response (RESPONSE_FIXED_LEN + diag_len):
//   [result:u8][target_id:32][workload_uid:16][descriptor_revision:32]
//   [idempotency_id:16][fence_epoch:u64][fence_seq:u64]
//   [observed_activation_digest:32][desired_bundle_digest:32]
//   [phase:u8][generation:u64][diag_len:u16][diag:diag_len]
//
// frame, on a socket, on stdio and on a `peer_tag` remote channel's local port:
//   [peer:32][len:u32][record:len]
// ```
//
// On a remote channel the 32-byte peer is the channel's own `peer_tag` prefix,
// which stands outside the framing, and `[len:u32][record]` is a `len32` record
// ([`CHANNEL_TABLE`]).

/// Bytes of the peer key fingerprint ahead of a frame.
pub const PEER_LEN: usize = 32;
/// Bytes of a frame ahead of its record: the peer and the record's length.
pub const FRAME_HEADER_LEN: usize = PEER_LEN + 4;
/// Largest record, either direction.
pub const AGENT_RECORD_MAX: usize = 8192;
/// A request is exactly this long.
pub const REQUEST_LEN: usize = 114;
/// A response without its diagnostic.
pub const RESPONSE_FIXED_LEN: usize = 188;
/// Longest diagnostic a response carries.
pub const DIAG_MAX: usize = AGENT_RECORD_MAX - RESPONSE_FIXED_LEN;
/// The `remote_channel` table entry that carries a frame unchanged under
/// `peer_tag: 1`. The largest record is the agent record and its length field.
pub const CHANNEL_TABLE: &str = "OctetStream:len32:8196";

/// What a request asks.
pub mod op {
    /// Make the desired bundle the workload's committed one.
    pub const APPLY: u8 = 1;
    /// Remove the workload from the target's desired state.
    pub const REMOVE: u8 = 2;
    /// Report phase, generation and activation. Changes nothing but the fence.
    pub const OBSERVE: u8 = 3;
}

/// How a request ended.
pub mod result {
    /// Done, or already done under this idempotency identity.
    pub const OK: u8 = 0;
    /// The request's fence is below the one the target holds.
    pub const REFUSED_FENCED: u8 = 1;
    /// The peer is not a controller of this target.
    pub const REFUSED_UNAUTHORIZED: u8 = 2;
    /// The request names another descriptor revision than the target's.
    pub const REFUSED_DESCRIPTOR: u8 = 3;
    /// This idempotency identity was used by a different request.
    pub const REFUSED_CONFLICT: u8 = 4;
    /// The target holds no bundle at the desired digest.
    pub const BUNDLE_MISSING: u8 = 5;
    /// Validation or composition refused; `diag` is its diagnostic.
    pub const REFUSED_ADMISSION: u8 = 6;
    /// The record is malformed.
    pub const BAD_REQUEST: u8 = 7;
    /// The target could not read or write its own state. Nothing is reported
    /// as done; the same request may be sent again.
    pub const FAULT: u8 = 8;
    /// Highest assigned value.
    pub const LAST: u8 = FAULT;
}

/// What the target observes of the workload.
pub mod phase {
    /// Neither desired nor committed here.
    pub const ABSENT: u8 = 0;
    /// Committed, and no live runtime reports having applied that generation.
    pub const COMMITTED: u8 = 1;
    /// The runtime applied it; the owner's modules are not all loaded.
    pub const ACTIVATING: u8 = 2;
    /// Every module loaded, none terminated, ready.
    pub const RUNNING: u8 = 3;
    /// Every module loaded, none terminated, some recovering.
    pub const UNREADY: u8 = 4;
    /// Leaving through a drain window.
    pub const DRAINING: u8 = 5;
    /// The owner ended.
    pub const TERMINATED: u8 = 6;
    /// Highest assigned value.
    pub const LAST: u8 = TERMINATED;
}

/// Why a record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Shorter than its fixed part, or than its `diag_len` says.
    Truncated,
    /// Longer than its fixed part and `diag_len` say.
    TrailingBytes,
    /// `op` names no operation.
    BadOp,
    /// A flag this protocol does not define is set.
    BadFlags,
    /// OBSERVE or REMOVE carries a desired bundle digest.
    UnexpectedDigest,
    /// `result` names no result.
    BadResult,
    /// `phase` names no phase.
    BadPhase,
    /// `diag_len` is over [`DIAG_MAX`].
    DiagTooLong,
}

/// A request record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub op: u8,
    pub flags: u8,
    pub workload_uid: [u8; 16],
    pub desired_bundle_digest: [u8; 32],
    pub descriptor_revision: [u8; 32],
    pub idempotency_id: [u8; 16],
    pub fence_epoch: u64,
    pub fence_seq: u64,
}

/// A response record; `diag` borrows the bytes it was decoded from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'a> {
    pub result: u8,
    pub target_id: [u8; 32],
    pub workload_uid: [u8; 16],
    pub descriptor_revision: [u8; 32],
    pub idempotency_id: [u8; 16],
    pub fence_epoch: u64,
    pub fence_seq: u64,
    pub observed_activation_digest: [u8; 32],
    pub desired_bundle_digest: [u8; 32],
    pub phase: u8,
    pub generation: u64,
    pub diag: &'a [u8],
}

const fn all_zero(bytes: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if bytes[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Sequential writer over a caller's buffer: `None` once a field does not fit.
struct Put<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Put<'_> {
    fn bytes(&mut self, src: &[u8]) -> Option<()> {
        let end = self.at.checked_add(src.len())?;
        let dst = self.out.get_mut(self.at..end)?;
        let mut i = 0;
        while i < src.len() {
            *dst.get_mut(i)? = *src.get(i)?;
            i += 1;
        }
        self.at = end;
        Some(())
    }
}

/// Sequential reader over a record: `None` once a field is not there.
struct Take<'a> {
    src: &'a [u8],
    at: usize,
}

impl<'a> Take<'a> {
    fn slice(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.src.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.slice(N)?;
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            out[i] = *s.get(i)?;
            i += 1;
        }
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.array()?))
    }
}

impl Request {
    /// Write the record to `out`; its length, or `None` when `out` is short.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut p = Put { out, at: 0 };
        p.bytes(&[self.op, self.flags])?;
        p.bytes(&self.workload_uid)?;
        p.bytes(&self.desired_bundle_digest)?;
        p.bytes(&self.descriptor_revision)?;
        p.bytes(&self.idempotency_id)?;
        p.bytes(&self.fence_epoch.to_le_bytes())?;
        p.bytes(&self.fence_seq.to_le_bytes())?;
        Some(p.at)
    }

    /// Read a whole record: exactly [`REQUEST_LEN`] bytes, a known `op`, no
    /// flags set, and no desired digest except on APPLY.
    pub fn decode(record: &[u8]) -> Result<Request, DecodeError> {
        if record.len() < REQUEST_LEN {
            return Err(DecodeError::Truncated);
        }
        if record.len() > REQUEST_LEN {
            return Err(DecodeError::TrailingBytes);
        }
        let mut t = Take { src: record, at: 0 };
        let (Some(op), Some(flags)) = (t.u8(), t.u8()) else {
            return Err(DecodeError::Truncated);
        };
        if op != op::APPLY && op != op::REMOVE && op != op::OBSERVE {
            return Err(DecodeError::BadOp);
        }
        if flags != 0 {
            return Err(DecodeError::BadFlags);
        }
        let (
            Some(workload_uid),
            Some(desired_bundle_digest),
            Some(descriptor_revision),
            Some(idempotency_id),
            Some(fence_epoch),
            Some(fence_seq),
        ) = (
            t.array::<16>(),
            t.array::<32>(),
            t.array::<32>(),
            t.array::<16>(),
            t.u64(),
            t.u64(),
        )
        else {
            return Err(DecodeError::Truncated);
        };
        if op != op::APPLY && !all_zero(&desired_bundle_digest) {
            return Err(DecodeError::UnexpectedDigest);
        }
        Ok(Request {
            op,
            flags,
            workload_uid,
            desired_bundle_digest,
            descriptor_revision,
            idempotency_id,
            fence_epoch,
            fence_seq,
        })
    }
}

impl Response<'_> {
    /// Write the record to `out`; its length, or `None` when `out` is short or
    /// `diag` is over [`DIAG_MAX`].
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if self.diag.len() > DIAG_MAX {
            return None;
        }
        let mut p = Put { out, at: 0 };
        p.bytes(&[self.result])?;
        p.bytes(&self.target_id)?;
        p.bytes(&self.workload_uid)?;
        p.bytes(&self.descriptor_revision)?;
        p.bytes(&self.idempotency_id)?;
        p.bytes(&self.fence_epoch.to_le_bytes())?;
        p.bytes(&self.fence_seq.to_le_bytes())?;
        p.bytes(&self.observed_activation_digest)?;
        p.bytes(&self.desired_bundle_digest)?;
        p.bytes(&[self.phase])?;
        p.bytes(&self.generation.to_le_bytes())?;
        p.bytes(&(self.diag.len() as u16).to_le_bytes())?;
        p.bytes(self.diag)?;
        Some(p.at)
    }

    /// Read a whole record: its fixed part and exactly `diag_len` bytes more,
    /// a known `result` and `phase`.
    pub fn decode(record: &[u8]) -> Result<Response<'_>, DecodeError> {
        if record.len() < RESPONSE_FIXED_LEN {
            return Err(DecodeError::Truncated);
        }
        let mut t = Take { src: record, at: 0 };
        let (
            Some(result),
            Some(target_id),
            Some(workload_uid),
            Some(descriptor_revision),
            Some(idempotency_id),
            Some(fence_epoch),
            Some(fence_seq),
            Some(observed_activation_digest),
            Some(desired_bundle_digest),
            Some(phase),
            Some(generation),
            Some(diag_len),
        ) = (
            t.u8(),
            t.array::<32>(),
            t.array::<16>(),
            t.array::<32>(),
            t.array::<16>(),
            t.u64(),
            t.u64(),
            t.array::<32>(),
            t.array::<32>(),
            t.u8(),
            t.u64(),
            t.u16(),
        )
        else {
            return Err(DecodeError::Truncated);
        };
        if result > result::LAST {
            return Err(DecodeError::BadResult);
        }
        if phase > phase::LAST {
            return Err(DecodeError::BadPhase);
        }
        let diag_len = diag_len as usize;
        if diag_len > DIAG_MAX {
            return Err(DecodeError::DiagTooLong);
        }
        let Some(diag) = t.slice(diag_len) else {
            return Err(DecodeError::Truncated);
        };
        if t.at != record.len() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Response {
            result,
            target_id,
            workload_uid,
            descriptor_revision,
            idempotency_id,
            fence_epoch,
            fence_seq,
            observed_activation_digest,
            desired_bundle_digest,
            phase,
            generation,
            diag,
        })
    }
}

/// Write a frame's header to `out`; [`FRAME_HEADER_LEN`], or `None` when `out`
/// is short or `len` is over [`AGENT_RECORD_MAX`].
pub fn encode_frame_header(peer: &[u8; PEER_LEN], len: usize, out: &mut [u8]) -> Option<usize> {
    if len > AGENT_RECORD_MAX {
        return None;
    }
    let mut p = Put { out, at: 0 };
    p.bytes(peer)?;
    p.bytes(&(len as u32).to_le_bytes())?;
    Some(p.at)
}

/// Read a frame's header: the peer and the record's length as the frame states
/// it, which the caller holds to [`AGENT_RECORD_MAX`] before reading the record.
pub fn decode_frame_header(header: &[u8]) -> Option<([u8; PEER_LEN], u32)> {
    let mut t = Take { src: header, at: 0 };
    let peer = t.array::<PEER_LEN>()?;
    let len = u32::from_le_bytes(t.array()?);
    Some((peer, len))
}

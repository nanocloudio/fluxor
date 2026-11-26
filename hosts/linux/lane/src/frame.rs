//! A contract call and its answer, as they cross a lane.
//!
//! ```text
//! call:   [call:u32][contract:u16][0:u16][opcode:u32][handle:i32]
//!         [caller slot:u16][0:u16][caller generation:u32]
//!         [owner_uid:16][authority_uid:16]
//!         [arg_len:u32][arg][data_len:u32][data]
//! answer: [call:u32][rc:i32][out_len:u32][out][out_data_len:u32][out_data]
//! ```
//!
//! `call` numbers the call on the lane; the answer names the call it
//! answers. The caller record names the module that made the call — its
//! scheduler slot and that slot's occupancy, the owner it runs as and the
//! owner whose authority it acts with — filled by the runtime from what the
//! kernel knows, never by the caller. `arg` is the op's flat record; `out`
//! is what the provider wrote back over it, never longer.
//!
//! `data` is the op's bulk span, moving the way the op's registry rule says
//! ([`fluxor_abi::registry::gate::Dir`]): `data_len` is always the span's
//! length as the caller holds it, and the bytes follow only when the span
//! moves in (`In`, `InOut`). The answer's `out_data` follows only when it
//! moves out (`Out`, `InOut`), at most `data_len` bytes. With `rc` =
//! `ERANGE`, `out_data_len` may exceed the bytes that follow: it is then the
//! length the answer needs, and the bytes are what fit.

use fluxor_abi::registry::gate::Dir;

/// Bytes of a call's fixed head, before `arg_len`.
pub const CALL_HDR: usize = 56;
/// Bytes of a call's framing beyond the head: the two length words.
pub const CALL_SPANS: usize = 8;
/// Bytes of an answer's fixed head, before `out_len`.
pub const ANSWER_HDR: usize = 8;
/// Bytes of an answer's framing beyond the head: the two length words.
pub const ANSWER_SPANS: usize = 8;

/// Whether a span moving `d` carries bytes toward the provider.
pub fn moves_in(d: Dir) -> bool {
    matches!(d, Dir::In | Dir::InOut)
}

/// Whether a span moving `d` carries bytes back toward the caller.
pub fn moves_out(d: Dir) -> bool {
    matches!(d, Dir::Out | Dir::InOut)
}

/// The module a call came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Caller {
    pub slot: u16,
    pub generation: u32,
    pub owner_uid: [u8; 16],
    pub authority_uid: [u8; 16],
}

impl Caller {
    /// Whether the caller acts with the node's authority. The runtime fills
    /// `authority_uid` with the uid of the owner whose authority the caller
    /// acts with; the node owner's is all zeros, and no workload is admitted
    /// with that uid.
    pub fn acts_for_node(&self) -> bool {
        self.authority_uid == [0; 16]
    }
}

/// A call's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallHead {
    pub call: u32,
    pub contract: u16,
    pub opcode: u32,
    pub handle: i32,
    pub caller: Caller,
}

/// A parsed call: its head, `arg`, the span length the caller holds and
/// the span bytes that crossed (empty unless the span moves in).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallRec<'a> {
    pub head: CallHead,
    pub arg: &'a [u8],
    pub data_len: usize,
    pub data: &'a [u8],
}

fn u32_at(rec: &[u8], at: usize) -> Option<u32> {
    let b = rec.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

impl CallHead {
    /// Write the call into `out`: the header, `arg`, and the span — its
    /// length `data_len`, and `data` (the bytes, empty unless it moves in).
    /// The record's length.
    pub fn encode(&self, arg: &[u8], data_len: usize, data: &[u8], out: &mut Vec<u8>) -> usize {
        out.clear();
        out.extend_from_slice(&self.call.to_le_bytes());
        out.extend_from_slice(&self.contract.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.opcode.to_le_bytes());
        out.extend_from_slice(&self.handle.to_le_bytes());
        out.extend_from_slice(&self.caller.slot.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.caller.generation.to_le_bytes());
        out.extend_from_slice(&self.caller.owner_uid);
        out.extend_from_slice(&self.caller.authority_uid);
        out.extend_from_slice(&(arg.len() as u32).to_le_bytes());
        out.extend_from_slice(arg);
        out.extend_from_slice(&(data_len as u32).to_le_bytes());
        out.extend_from_slice(data);
        out.len()
    }

    /// The call in `rec`, whose span moves `dir`. `None` when the record's
    /// lengths do not account for its bytes exactly.
    pub fn parse(rec: &[u8], dir: Dir) -> Option<CallRec<'_>> {
        if rec.len() < CALL_HDR + CALL_SPANS {
            return None;
        }
        let mut owner_uid = [0u8; 16];
        owner_uid.copy_from_slice(&rec[24..40]);
        let mut authority_uid = [0u8; 16];
        authority_uid.copy_from_slice(&rec[40..56]);
        let head = CallHead {
            call: u32_at(rec, 0)?,
            contract: u16::from_le_bytes([rec[4], rec[5]]),
            opcode: u32_at(rec, 8)?,
            handle: u32_at(rec, 12)? as i32,
            caller: Caller {
                slot: u16::from_le_bytes([rec[16], rec[17]]),
                generation: u32_at(rec, 20)?,
                owner_uid,
                authority_uid,
            },
        };
        let arg_len = u32_at(rec, CALL_HDR)? as usize;
        let arg_at = CALL_HDR + 4;
        let arg = rec.get(arg_at..arg_at.checked_add(arg_len)?)?;
        let len_at = arg_at + arg_len;
        let data_len = u32_at(rec, len_at)? as usize;
        let data = &rec[len_at + 4..];
        let expect = if moves_in(dir) { data_len } else { 0 };
        if data.len() != expect {
            return None;
        }
        Some(CallRec {
            head,
            arg,
            data_len,
            data,
        })
    }
}

/// A parsed answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerRec<'a> {
    pub call: u32,
    pub rc: i32,
    pub out: &'a [u8],
    /// The span's answered length: the bytes in `data`, or with `rc` =
    /// `ERANGE` possibly more — the length the answer needs.
    pub data_len: usize,
    pub data: &'a [u8],
}

/// Write an answer into `out`: `body` over the call's `arg`, then the span
/// — `data_len` (the bytes written, or with `ERANGE` the length needed)
/// and `data` (what is sent back; empty unless the span moves out). The
/// record's length.
pub fn encode_answer(
    call: u32,
    rc: i32,
    body: &[u8],
    data_len: usize,
    data: &[u8],
    out: &mut Vec<u8>,
) -> usize {
    out.clear();
    out.extend_from_slice(&call.to_le_bytes());
    out.extend_from_slice(&rc.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&(data_len as u32).to_le_bytes());
    out.extend_from_slice(data);
    out.len()
}

/// The answer in `rec`. `None` when its lengths do not account for its
/// bytes, or it sends back more span bytes than its stated length.
pub fn parse_answer(rec: &[u8]) -> Option<AnswerRec<'_>> {
    if rec.len() < ANSWER_HDR + ANSWER_SPANS {
        return None;
    }
    let call = u32_at(rec, 0)?;
    let rc = u32_at(rec, 4)? as i32;
    let out_len = u32_at(rec, ANSWER_HDR)? as usize;
    let out_at = ANSWER_HDR + 4;
    let out = rec.get(out_at..out_at.checked_add(out_len)?)?;
    let len_at = out_at + out_len;
    let data_len = u32_at(rec, len_at)? as usize;
    let data = &rec[len_at + 4..];
    if data.len() > data_len {
        return None;
    }
    Some(AnswerRec {
        call,
        rc,
        out,
        data_len,
        data,
    })
}

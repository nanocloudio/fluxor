//! The contracts a lane can carry, and the channels each declares.
//!
//! A served contract takes two table entries: its calls, runtime to
//! provider, and its answers, provider to runtime, each a mailbox of the
//! contract's own content type sized for the largest `arg` and `data` span
//! it takes. Both ends derive them from the contract id here, so a
//! provider's `HELLO` and the runtime's expectation are the same entries or
//! the lane is refused.
//!
//! Which way an op's `data` span moves is the registry's rule for it
//! ([`fluxor_abi::registry::gate::op_rule`]), the same rule the gateway
//! enforces; both ends read it, so a call's framing needs no direction
//! byte. A contract whose tables move in `data` names the most a lane
//! carries of one span ([`ServedContract::data_max`]): a bound on the
//! lane's mailbox, above any table its providers keep.

use fluxor_abi::contracts::key_custody;
use fluxor_abi::registry::gate::{self, Bound, Dir};
use fluxor_contracts::channel_table::Entry;

use crate::control::{dir, LaneEntry};
use crate::frame::{ANSWER_HDR, ANSWER_SPANS, CALL_HDR, CALL_SPANS};

/// What the lane knows of a contract it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServedContract {
    pub id: u16,
    pub call_ct: &'static [u8],
    pub answer_ct: &'static [u8],
    /// The longest `arg` any of its ops takes.
    pub arg_max: usize,
    /// The longest `data` span one call carries either way; 0 for a
    /// contract with no spans.
    pub data_max: usize,
    /// Ops whose non-negative answer is a handle the caller now holds.
    pub mints: [u32; 2],
    /// The op that frees such a handle (handle = it, no arg).
    pub destroy: u32,
}

impl ServedContract {
    /// Whether `op`'s answer is a handle the caller must collect or have
    /// destroyed for it.
    pub fn mints(&self, op: u32) -> bool {
        self.mints.contains(&op)
    }

    /// Which way `op`'s `data` span moves, and the most it may hold on this
    /// lane. `None` for an op the contract does not have.
    pub fn span(&self, op: u32) -> Option<(Dir, usize)> {
        if (op >> 8) as u16 != self.id && self.id != loopback::CONTRACT {
            return None;
        }
        if self.id == loopback::CONTRACT {
            return loopback::span(op).map(|d| (d, self.data_max));
        }
        let rule = gate::op_rule(op)?;
        let max = match rule.data_max {
            Bound::Any => self.data_max,
            Bound::Bytes(n) => n.min(self.data_max),
        };
        Some((rule.data, max))
    }

    /// The contract's call and answer entries.
    pub fn entries(&self) -> [LaneEntry; 2] {
        let call = Entry::mailbox(
            self.call_ct,
            (CALL_HDR + CALL_SPANS + self.arg_max + self.data_max) as u32,
        )
        .expect("a served contract's content types are table names");
        let answer = Entry::mailbox(
            self.answer_ct,
            (ANSWER_HDR + ANSWER_SPANS + self.arg_max + self.data_max) as u32,
        )
        .expect("a served contract's content types are table names");
        [
            LaneEntry {
                entry: call,
                dirs: dir::DOWN,
            },
            LaneEntry {
                entry: answer,
                dirs: dir::UP,
            },
        ]
    }
}

/// The node's network control plane as a host provider serves it.
pub mod net {
    /// `net_route` call and answer records.
    pub const ROUTE_CALL_CT: &[u8] = b"NetRouteCall";
    pub const ROUTE_ANSWER_CT: &[u8] = b"NetRouteAnswer";
    /// `net_policy` call and answer records.
    pub const POLICY_CALL_CT: &[u8] = b"NetPolicyCall";
    pub const POLICY_ANSWER_CT: &[u8] = b"NetPolicyAnswer";
    /// The most one table span carries across the lane: above a whole
    /// segment, peer-route or held-address table, a READ of all three, and
    /// one policy table.
    pub const DATA_MAX: usize = 64 << 10;
    /// The longest `arg` a `net_policy` op takes (the table name).
    pub const POLICY_ARG_MAX: usize = 1024;
    /// The longest `arg` a `net_route` op takes (CAPS' word).
    pub const ROUTE_ARG_MAX: usize = 4;
}

/// The lane facts of contract `id`, if a lane can carry it.
pub fn served(id: u16) -> Option<ServedContract> {
    if id == fluxor_abi::registry::key_custody::ID {
        return Some(ServedContract {
            id,
            call_ct: key_custody::CALL_CONTENT_TYPE,
            answer_ct: key_custody::ANSWER_CONTENT_TYPE,
            arg_max: key_custody::ARG_MAX,
            data_max: 0,
            mints: [key_custody::GENERATE, key_custody::FIND],
            destroy: key_custody::DESTROY,
        });
    }
    if id == fluxor_abi::registry::net_route::ID {
        return Some(ServedContract {
            id,
            call_ct: net::ROUTE_CALL_CT,
            answer_ct: net::ROUTE_ANSWER_CT,
            arg_max: net::ROUTE_ARG_MAX,
            data_max: net::DATA_MAX,
            mints: [u32::MAX, u32::MAX],
            destroy: u32::MAX,
        });
    }
    if id == fluxor_abi::registry::net_policy::ID {
        return Some(ServedContract {
            id,
            call_ct: net::POLICY_CALL_CT,
            answer_ct: net::POLICY_ANSWER_CT,
            arg_max: net::POLICY_ARG_MAX,
            data_max: net::DATA_MAX,
            mints: [u32::MAX, u32::MAX],
            destroy: u32::MAX,
        });
    }
    if id == loopback::CONTRACT {
        return Some(ServedContract {
            id,
            call_ct: b"LoopbackCall",
            answer_ct: b"LoopbackAnswer",
            arg_max: loopback::ARG_MAX,
            data_max: loopback::DATA_MAX,
            mints: [loopback::MINT, loopback::MINT],
            destroy: loopback::DESTROY,
        });
    }
    None
}

/// The test contract `fluxor-lane-loopback` serves. Its id is outside the
/// registry's contract space, so no graph can name it: only a test that
/// builds a lane by hand reaches it.
pub mod loopback {
    use fluxor_abi::registry::gate::Dir;

    pub const CONTRACT: u16 = 0xFF00;
    /// Longest `arg`.
    pub const ARG_MAX: usize = 256;
    /// Longest `data` span.
    pub const DATA_MAX: usize = 32 << 10;
    /// Answer `arg` as given; `rc` = its length.
    pub const ECHO: u32 = 0xFF00_0000;
    /// Answer after `[ms:u32]` milliseconds; `rc` = 0.
    pub const SLOW: u32 = 0xFF00_0001;
    /// Mint a handle; `rc` = it.
    pub const MINT: u32 = 0xFF00_0002;
    /// Destroy a minted handle; `rc` = 0.
    pub const DESTROY: u32 = 0xFF00_0003;
    /// Answer `[destroyed:u32][released:u32][last released slot:u16]`
    /// counts; `rc` = 10.
    pub const TALLY: u32 = 0xFF00_0004;
    /// `data` in: `rc` = the byte sum of the span, mod 2^31; `arg` out =
    /// `[len:u32]`.
    pub const SUM: u32 = 0xFF00_0005;
    /// `data` out: `arg` = `[want:u32][seed:u8]`; fills `want` bytes
    /// `seed, seed+1, …`. `rc` = `want`, or `ERANGE` with what fits sent and
    /// `want` as the span's answered length when the span is shorter.
    pub const FILL: u32 = 0xFF00_0006;
    /// `data` in and out: every byte xor `arg[0]`; `rc` = the span's length.
    pub const XOR: u32 = 0xFF00_0007;
    /// `arg` out: what the provider knows, as text — owners, lanes, its
    /// capabilities and incarnation (`key=value;…`); `rc` = its length.
    pub const FACTS: u32 = 0xFF00_0008;
    /// The port table the loopback states.
    pub const PORTS: &str = "Echo:len32:4096;Bulk:mailbox:60000";

    /// Which way `op`'s span moves.
    pub fn span(op: u32) -> Option<Dir> {
        match op {
            ECHO | SLOW | MINT | DESTROY | TALLY | FACTS => Some(Dir::None),
            SUM => Some(Dir::In),
            FILL => Some(Dir::Out),
            XOR => Some(Dir::InOut),
            _ => None,
        }
    }
}

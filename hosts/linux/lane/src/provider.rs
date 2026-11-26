//! The provider's end of a lane: connect on the inherited socket, say what
//! this provider is, take the rings, and serve.
//!
//! A provider is a `main` around [`Provider::connect`] and
//! [`Provider::serve`] with a [`Handler`]: the handler answers calls, takes
//! port and lane records and hears about callers, owners and lanes; the
//! lane does the rest. `serve` returns when the runtime says `STOP` or goes
//! away, and the provider then exits — it has nothing to outlive the
//! runtime for.

use std::collections::VecDeque;
use std::os::fd::{OwnedFd, RawFd};
use std::time::Duration;

use fluxor_abi::registry::gate::Dir;
use fluxor_contracts::channel_table::{self, Entry};

use crate::control::{self, dir, wants, Control, Gate, Hello, LaneEntry, LaneMsg, OwnerFact, Recv};
use crate::frame::{self, moves_in, moves_out, CallHead, Caller};
use crate::privilege;
use crate::ring::{Consumer, Producer, Push, View};
use crate::runtime::table_of;
use crate::served::served;
use crate::spawn::{LANE_ENV, LANE_FD};

/// Why a provider stopped serving.
#[derive(Debug)]
pub enum ServeError {
    /// No lane at descriptor 3.
    NoLane(std::io::Error),
    /// The runtime refused this provider ([`control::refuse`]).
    Refused(u8),
    /// This provider cannot serve as started; the runtime was told why.
    Unable(String),
    /// The runtime broke the protocol, handed over rings this side cannot
    /// trust, or went away before accepting.
    Protocol(&'static str),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::NoLane(e) => write!(f, "no lane at descriptor 3: {e}"),
            ServeError::Refused(r) => write!(f, "the runtime refused this provider (reason {r})"),
            ServeError::Unable(why) => write!(f, "cannot serve: {why}"),
            ServeError::Protocol(why) => write!(f, "lane protocol: {why}"),
        }
    }
}

/// What a provider is: the contracts it serves, its port channels and what
/// it needs and takes, as compiled into it.
pub struct Identity<'a> {
    pub contracts: &'a [u16],
    /// The port table, `content_type:framing:max_record;…`; empty for none.
    pub ports: &'a str,
    /// Capabilities it cannot serve without ([`privilege::cap`]).
    pub requires_caps: &'a [u32],
    /// What it takes beyond calls and port records ([`wants`]).
    pub wants: u8,
}

/// One call, as the provider sees it.
pub struct Call<'a> {
    pub contract: u16,
    pub opcode: u32,
    pub handle: i32,
    pub caller: Caller,
    pub arg: &'a [u8],
    /// Which way the op's `data` span moves.
    pub data_dir: Dir,
    /// The span's length as the caller holds it.
    pub data_len: usize,
    /// The span's bytes when it moves in; empty otherwise.
    pub data: &'a [u8],
}

/// A handler's answer to a call with a span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub rc: i32,
    /// Bytes of `out` that are the answer.
    pub out_len: usize,
    /// Bytes of the span's room that are the answer; with `rc` = `ERANGE`
    /// it may exceed the room — the length the answer needs.
    pub data_len: usize,
}

/// Where a handler sends port and lane records.
pub struct Outbox<'a> {
    up: &'a mut [Option<Producer>],
    ports: usize,
    lanes: &'a mut [DynLane],
    ctl: &'a Control,
}

impl Outbox<'_> {
    /// Commit `rec` to the runtime on port `i`.
    pub fn send(&mut self, i: usize, rec: &[u8]) -> Result<(), Push> {
        if i >= self.ports {
            return Err(Push::TooBig);
        }
        let Some(Some(p)) = self.up.get_mut(i) else {
            return Err(Push::TooBig);
        };
        p.push(rec)?;
        if p.take_waiting() {
            let _ = self.ctl.send(&[control::RING, i as u8, dir::UP], &[]);
        }
        Ok(())
    }

    /// What port `i`'s ring to the runtime can take now ([`View`]);
    /// [`View::NONE`] for no such port.
    pub fn view(&self, i: usize) -> View {
        match self.up.get(i) {
            Some(Some(p)) if i < self.ports => p.view(),
            _ => View::NONE,
        }
    }

    /// What dynamic lane `key`'s ring to the runtime can take now;
    /// [`View::NONE`] for no such lane.
    pub fn lane_view(&self, key: u8) -> View {
        self.lanes
            .iter()
            .find(|l| l.key == key)
            .map_or(View::NONE, |l| l.up.view())
    }

    /// Commit `rec` to the runtime on dynamic lane `key`.
    pub fn lane_send(&mut self, key: u8, rec: &[u8]) -> Result<(), Push> {
        let Some(l) = self.lanes.iter_mut().find(|l| l.key == key) else {
            return Err(Push::TooBig);
        };
        l.up.push(rec)?;
        if l.up.take_waiting() {
            let _ = self.ctl.send(&[control::LANE_RING, key, dir::UP], &[]);
        }
        Ok(())
    }
}

/// What a handler's [`Handler::poll`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    /// Nothing waits on the handler: the loop sleeps until a doorbell, a
    /// control packet, the handler's own descriptor ([`Handler::wake`]) or
    /// its beat.
    Idle,
    /// The handler holds something it could not hand on (a record a full
    /// ring refused): the loop wakes again on a short beat.
    Holding,
    /// The handler moved something: the loop goes round again at once.
    Busy,
}

/// What, beside the control socket and its rings, wakes an idle serve
/// loop ([`Handler::wake`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wake {
    /// A descriptor whose readability is the handler's own work arriving.
    pub fd: Option<RawFd>,
    /// The longest the loop sleeps idle: the handler's next deadline.
    pub within: Duration,
}

impl Wake {
    /// Nothing of the handler's own; the loop's idle beat.
    pub const BEAT: Wake = Wake {
        fd: None,
        within: Duration::from_secs(1),
    };
}

/// Records taken off one port or lane ring in one pass of the serve loop,
/// at most.
const RECORD_BURST: usize = 64;

/// What a provider does with what crosses its lane.
pub trait Handler {
    /// Answer `call`, writing the answer over `out` (as long as the call's
    /// `arg`): the return code, and how many bytes of `out` are the answer.
    fn call(&mut self, call: &Call<'_>, out: &mut [u8]) -> (i32, usize);

    /// Answer `call` whose op has a `data` span: `out` as for
    /// [`Handler::call`], `data` the span's room (its length as the caller
    /// holds it when the span moves out, holding the caller's bytes when it
    /// moves both ways; empty when it only moves in, the bytes then being
    /// `call.data`). A contract with no spans need not implement it.
    fn call_data(&mut self, call: &Call<'_>, out: &mut [u8], _data: &mut [u8]) -> Reply {
        let (rc, out_len) = self.call(call, out);
        Reply {
            rc,
            out_len,
            data_len: 0,
        }
    }

    /// A record arrived on port `i`.
    fn record(&mut self, _i: usize, _rec: &[u8], _out: &mut Outbox<'_>) {}

    /// The caller `(slot, generation)` is gone: free what it holds.
    fn released(&mut self, _slot: u16, _generation: u32) {}

    /// An owner's host process ([`wants::OWNERS`]): its facts, and a
    /// `NETLINK_ROUTE` socket inside its network namespace when the runtime
    /// could open one.
    fn owner(&mut self, _fact: OwnerFact, _netlink: Option<OwnedFd>) {}

    /// That owner's process is gone.
    fn owner_gone(&mut self, _slot: u16, _generation: u32) {}

    /// A dynamic lane changed ([`wants::LANES`]): `op` is a
    /// [`control::lane`] op. Records on an added lane arrive at
    /// [`Handler::lane_record`] and go back by [`Outbox::lane_send`].
    fn lane(&mut self, _op: u8, _key: u8, _owner_slot: u16, _owner_generation: u32) {}

    /// A record arrived on dynamic lane `key`.
    fn lane_record(&mut self, _key: u8, _rec: &[u8], _out: &mut Outbox<'_>) {}

    /// Whether the handler takes another record off port `i` now. One it
    /// does not take stays on its ring, which backs up to the runtime: the
    /// handler's way of pushing back on what it cannot yet act on.
    fn takes(&self, _i: usize) -> bool {
        true
    }

    /// As [`Handler::takes`], for dynamic lane `key`.
    fn takes_lane(&self, _key: u8) -> bool {
        true
    }

    /// What an owner may claim through port `i`'s records or a dynamic
    /// lane's ([`Gate`]): told for each before any of its records, and
    /// again whenever it changes.
    fn gate(&mut self, _gate: Gate) {}

    /// Owner `(slot, generation)` is freed: let go of everything held for
    /// it before this returns (the runtime waits for the answer).
    fn owner_released(&mut self, _slot: u16, _generation: u32) {}

    /// What wakes the loop for the handler, asked before each sleep.
    fn wake(&self) -> Wake {
        Wake::BEAT
    }

    /// Called on every pass of the serve loop: the handler's own work, and
    /// a retry of what it holds (a record a full ring refused).
    fn poll(&mut self, _out: &mut Outbox<'_>) -> Poll {
        Poll::Idle
    }
}

/// The serve loop's reusable buffers for one call: `arg` room, span room
/// and the answer record.
#[derive(Default)]
struct Scratch {
    out: Vec<u8>,
    room: Vec<u8>,
    answer: Vec<u8>,
}

/// A dynamic lane, provider side.
struct DynLane {
    key: u8,
    down: Consumer,
    up: Producer,
}

/// A connected provider.
pub struct Provider {
    ctl: Control,
    table: Vec<LaneEntry>,
    ports: usize,
    /// `(contract, call entry)` per served contract.
    contracts: Vec<(u16, usize)>,
    down: Vec<Option<Consumer>>,
    up: Vec<Option<Producer>>,
    /// Answers waiting for room on their ring: `(answer entry, record)`.
    owed: VecDeque<(usize, Vec<u8>)>,
    wants: u8,
    /// The most dynamic lanes the runtime will add.
    lanes_cap: usize,
    lanes: Vec<DynLane>,
    incarnation: [u8; 16],
}

/// The provider's own parameter string: its one argument.
pub fn args() -> String {
    std::env::args().nth(1).unwrap_or_default()
}

/// Whether the runtime started this process on a lane: the spawner names
/// the lane's descriptor in [`LANE_ENV`], and that descriptor is open. A
/// descriptor 3 left open by whoever ran the binary by hand is not a lane.
/// Read once; the variable is then removed, so nothing this process starts
/// inherits it. Ask first from `main`, before any thread starts.
pub fn lane_given() -> bool {
    static GIVEN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *GIVEN.get_or_init(|| {
        let named = std::env::var_os(LANE_ENV)
            .is_some_and(|v| v.to_str() == Some(LANE_FD.to_string().as_str()));
        std::env::remove_var(LANE_ENV);
        // SAFETY: F_GETFD on an integer descriptor touches no memory.
        named && unsafe { libc::fcntl(LANE_FD, libc::F_GETFD) } >= 0
    })
}

/// Sixteen fresh bytes for this start.
fn fresh_incarnation() -> [u8; 16] {
    let mut b = [0u8; 16];
    // SAFETY: `b` is writable for its length.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != b.len() as isize {
        // The clock and pid still differ between starts.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        b[..16].copy_from_slice(&t.to_le_bytes());
        b[12..16].copy_from_slice(&std::process::id().to_le_bytes());
    }
    b
}

/// Tell the runtime, on descriptor 3 and in place of `HELLO`, that this
/// provider cannot serve as started and why (the runtime closes the lane
/// and states the reason). For a reason found before [`Provider::connect`].
pub fn unable(why: &str) -> ServeError {
    if !lane_given() {
        return ServeError::Unable(why.to_string());
    }
    // SAFETY: descriptor 3 is the lane's socket ([`lane_given`]), placed
    // there for this process and owned by nothing else in it.
    if let Ok(ctl) = unsafe { Control::adopt(LANE_FD) } {
        let mut p = vec![control::UNABLE];
        p.extend_from_slice(why.as_bytes());
        p.truncate(control::PACKET_MAX);
        let _ = ctl.send(&p, &[]);
    }
    ServeError::Unable(why.to_string())
}

impl Provider {
    /// Connect on descriptor 3 as `id`, built against `digest`, and wait for
    /// the runtime to accept.
    pub fn connect(id: &Identity<'_>, digest: [u8; 32]) -> Result<Provider, ServeError> {
        if !lane_given() {
            return Err(ServeError::NoLane(std::io::Error::from_raw_os_error(
                libc::EBADF,
            )));
        }
        // SAFETY: descriptor 3 is the lane's socket ([`lane_given`]), placed
        // there for this process and owned by nothing else in it.
        let ctl = unsafe { Control::adopt(LANE_FD) }.map_err(ServeError::NoLane)?;
        Provider::connect_on(ctl, id, digest)
    }

    /// As [`Provider::connect`], over a socket already in hand.
    pub fn connect_on(
        ctl: Control,
        id: &Identity<'_>,
        digest: [u8; 32],
    ) -> Result<Provider, ServeError> {
        if let Err(why) = privilege::require(id.requires_caps) {
            let mut p = vec![control::UNABLE];
            p.extend_from_slice(why.as_bytes());
            p.truncate(control::PACKET_MAX);
            let _ = ctl.send(&p, &[]);
            return Err(ServeError::Unable(why));
        }
        let mut ports = [Entry::EMPTY; 16];
        let n = if id.ports.trim().is_empty() {
            0
        } else {
            channel_table::parse_into(id.ports.as_bytes(), u32::MAX, &mut ports)
                .map_err(|_| ServeError::Protocol("the provider's own port table does not parse"))?
        };
        let table = table_of(&ports[..n], id.contracts)
            .map_err(|_| ServeError::Protocol("the provider serves a contract no lane carries"))?;
        let incarnation = fresh_incarnation();
        let hello = Hello {
            digest,
            incarnation,
            wants: id.wants,
            contracts: id.contracts.to_vec(),
            table: table.clone(),
        };
        ctl.send(&hello.encode(), &[])
            .map_err(|_| ServeError::Protocol("the runtime is gone"))?;
        let mut buf = vec![0u8; control::PACKET_MAX];
        let (len, fds) = loop {
            ctl.wait(Duration::from_secs(10));
            match ctl.try_recv(&mut buf) {
                Ok(Recv::Packet(len, fds)) => break (len, fds),
                Ok(Recv::Empty) => {}
                Ok(Recv::Closed) | Err(_) => {
                    return Err(ServeError::Protocol("the runtime is gone"))
                }
            }
        };
        match buf.first() {
            Some(&control::ACCEPT) => {}
            Some(&control::REFUSE) => {
                return Err(ServeError::Refused(buf.get(1).copied().unwrap_or(0)))
            }
            _ => return Err(ServeError::Protocol("expected ACCEPT")),
        }
        let count = buf.get(1).copied().unwrap_or(0) as usize;
        if len != 2 + 2 * count + 2 || fds.len() != count {
            return Err(ServeError::Protocol(
                "ACCEPT names other rings than it carries",
            ));
        }
        let lanes_cap = u16::from_le_bytes([buf[2 + 2 * count], buf[3 + 2 * count]]) as usize;
        if lanes_cap > 0 && id.wants & wants::LANES == 0 {
            return Err(ServeError::Protocol(
                "lanes offered to a provider taking none",
            ));
        }
        let mut down: Vec<Option<Consumer>> = (0..table.len()).map(|_| None).collect();
        let mut up: Vec<Option<Producer>> = (0..table.len()).map(|_| None).collect();
        for (k, fd) in fds.iter().enumerate() {
            let entry = buf[2 + 2 * k] as usize;
            let d = buf[3 + 2 * k];
            let Some(le) = table.get(entry) else {
                return Err(ServeError::Protocol("a ring for no entry"));
            };
            let max = le.entry.max_record;
            match d {
                dir::DOWN if le.dirs & dir::DOWN != 0 && down[entry].is_none() => {
                    down[entry] = Some(
                        Consumer::attach(fd, max)
                            .map_err(|_| ServeError::Protocol("a ring this side cannot trust"))?,
                    );
                }
                dir::UP if le.dirs & dir::UP != 0 && up[entry].is_none() => {
                    up[entry] = Some(
                        Producer::attach(fd, max)
                            .map_err(|_| ServeError::Protocol("a ring this side cannot trust"))?,
                    );
                }
                _ => return Err(ServeError::Protocol("a ring the table does not have")),
            }
        }
        for (i, le) in table.iter().enumerate() {
            if (le.dirs & dir::DOWN != 0) != down[i].is_some()
                || (le.dirs & dir::UP != 0) != up[i].is_some()
            {
                return Err(ServeError::Protocol("a ring is missing"));
            }
        }
        let contracts = id
            .contracts
            .iter()
            .enumerate()
            .map(|(k, &c)| (c, n + 2 * k))
            .collect();
        Ok(Provider {
            ctl,
            table,
            ports: n,
            contracts,
            down,
            up,
            owed: VecDeque::new(),
            wants: id.wants,
            lanes_cap,
            lanes: Vec::new(),
            incarnation,
        })
    }

    /// This start's incarnation, as `HELLO` stated it.
    pub fn incarnation(&self) -> [u8; 16] {
        self.incarnation
    }

    /// The most dynamic lanes the runtime will add.
    pub fn lanes_capacity(&self) -> usize {
        self.lanes_cap
    }

    /// One control packet. `Ok(false)` on `STOP` or end of file.
    fn on_control(
        &mut self,
        pkt: &[u8],
        mut fds: Vec<OwnedFd>,
        h: &mut impl Handler,
    ) -> Result<bool, ServeError> {
        match pkt.first() {
            Some(&control::STOP) => return Ok(false),
            Some(&control::RELEASED) => {
                let (s, g) = control::parse_slot_gen(control::RELEASED, pkt)
                    .ok_or(ServeError::Protocol("a malformed RELEASED"))?;
                h.released(s, g);
            }
            Some(&control::RING | &control::LANE_RING) => {}
            Some(&control::OWNER) if self.wants & wants::OWNERS != 0 => {
                let fact =
                    OwnerFact::parse(pkt).ok_or(ServeError::Protocol("a malformed OWNER"))?;
                if fds.len() > 1 {
                    return Err(ServeError::Protocol("OWNER carries one descriptor at most"));
                }
                h.owner(fact, fds.pop());
            }
            Some(&control::OWNER_GONE) if self.wants & wants::OWNERS != 0 => {
                let (s, g) = control::parse_slot_gen(control::OWNER_GONE, pkt)
                    .ok_or(ServeError::Protocol("a malformed OWNER_GONE"))?;
                h.owner_gone(s, g);
            }
            Some(&control::GATE) => {
                let g = Gate::parse(pkt).ok_or(ServeError::Protocol("a malformed GATE"))?;
                let known = match g.on {
                    control::gate::PORT => usize::from(g.index) < self.ports,
                    _ => self.lanes.iter().any(|l| l.key == g.index),
                };
                if !known {
                    return Err(ServeError::Protocol("a GATE for no port or lane"));
                }
                h.gate(g);
            }
            Some(&control::OWNER_RELEASED) => {
                let (s, g) = control::parse_slot_gen(control::OWNER_RELEASED, pkt)
                    .ok_or(ServeError::Protocol("a malformed OWNER_RELEASED"))?;
                h.owner_released(s, g);
                let _ = self
                    .ctl
                    .send(&control::slot_gen(control::OWNER_RELEASED, s, g), &[]);
            }
            Some(&control::LANE) if self.wants & wants::LANES != 0 => {
                let m = LaneMsg::parse(pkt).ok_or(ServeError::Protocol("a malformed LANE"))?;
                match m.op {
                    control::lane::ADD => {
                        if fds.len() != 2
                            || self.lanes.len() >= self.lanes_cap
                            || self.lanes.iter().any(|l| l.key == m.key)
                        {
                            return Err(ServeError::Protocol("a LANE add this side cannot take"));
                        }
                        let down = Consumer::attach(&fds[0], m.max_record)
                            .map_err(|_| ServeError::Protocol("a ring this side cannot trust"))?;
                        let up = Producer::attach(&fds[1], m.max_record)
                            .map_err(|_| ServeError::Protocol("a ring this side cannot trust"))?;
                        self.lanes.push(DynLane {
                            key: m.key,
                            down,
                            up,
                        });
                    }
                    control::lane::DEL => {
                        let Some(i) = self.lanes.iter().position(|l| l.key == m.key) else {
                            return Err(ServeError::Protocol("a LANE delete for no lane"));
                        };
                        self.lanes.swap_remove(i);
                    }
                    control::lane::DRAIN => {
                        if !self.lanes.iter().any(|l| l.key == m.key) {
                            return Err(ServeError::Protocol("a LANE drain for no lane"));
                        }
                    }
                    _ => return Err(ServeError::Protocol("an unknown LANE op")),
                }
                h.lane(m.op, m.key, m.owner_slot, m.owner_generation);
            }
            _ => return Err(ServeError::Protocol("an unexpected control packet")),
        }
        Ok(true)
    }

    /// Serve until the runtime says `STOP` or goes away. `Ok` either way;
    /// `Err` when the runtime broke the protocol or a ring.
    pub fn serve(&mut self, h: &mut impl Handler) -> Result<(), ServeError> {
        let max = self
            .table
            .iter()
            .map(|le| le.entry.max_record as usize)
            .max()
            .unwrap_or(0);
        let mut rec = vec![0u8; max];
        let mut scratch = Scratch::default();
        let mut ctl_buf = vec![0u8; control::PACKET_MAX];
        let mut lane_rec = Vec::new();
        loop {
            let mut progressed = false;
            // Control first: STOP and end of file end the loop.
            loop {
                match self.ctl.try_recv(&mut ctl_buf) {
                    Ok(Recv::Packet(n, fds)) => {
                        progressed = true;
                        let pkt = ctl_buf[..n].to_vec();
                        if !self.on_control(&pkt, fds, h)? {
                            return Ok(());
                        }
                    }
                    Ok(Recv::Empty) => break,
                    Ok(Recv::Closed) => return Ok(()),
                    Err(_) => return Err(ServeError::Protocol("the control socket failed")),
                }
            }
            progressed |= self.flush_owed()?;
            // Port records, then calls.
            for i in 0..self.table.len() {
                if i < self.ports {
                    for _ in 0..RECORD_BURST {
                        if !h.takes(i) {
                            break;
                        }
                        let Some(Some(c)) = self.down.get_mut(i) else {
                            break;
                        };
                        let Some(n) = c
                            .pop(&mut rec)
                            .map_err(|_| ServeError::Protocol("a hostile ring"))?
                        else {
                            break;
                        };
                        progressed = true;
                        let mut ob = Outbox {
                            up: &mut self.up,
                            ports: self.ports,
                            lanes: &mut self.lanes,
                            ctl: &self.ctl,
                        };
                        h.record(i, &rec[..n], &mut ob);
                    }
                    continue;
                }
                let Some(Some(c)) = self.down.get_mut(i) else {
                    continue;
                };
                let Some(n) = c
                    .pop(&mut rec)
                    .map_err(|_| ServeError::Protocol("a hostile ring"))?
                else {
                    continue;
                };
                progressed = true;
                let Some(&(contract, at)) = self.contracts.iter().find(|&&(_, at)| at == i) else {
                    return Err(ServeError::Protocol("a call on no contract's ring"));
                };
                self.answer_call(contract, at, &rec[..n], h, &mut scratch)?;
            }
            // Dynamic lanes.
            for k in 0..self.lanes.len() {
                let key = self.lanes[k].key;
                let need = self.lanes[k].down.max_record() as usize;
                if lane_rec.len() < need {
                    lane_rec.resize(need, 0);
                }
                for _ in 0..RECORD_BURST {
                    if !h.takes_lane(key) {
                        break;
                    }
                    let Some(n) = self.lanes[k]
                        .down
                        .pop(&mut lane_rec)
                        .map_err(|_| ServeError::Protocol("a hostile lane ring"))?
                    else {
                        break;
                    };
                    progressed = true;
                    let mut ob = Outbox {
                        up: &mut self.up,
                        ports: self.ports,
                        lanes: &mut self.lanes,
                        ctl: &self.ctl,
                    };
                    h.lane_record(key, &lane_rec[..n], &mut ob);
                }
            }
            let polled = {
                let mut ob = Outbox {
                    up: &mut self.up,
                    ports: self.ports,
                    lanes: &mut self.lanes,
                    ctl: &self.ctl,
                };
                h.poll(&mut ob)
            };
            if progressed || polled == Poll::Busy {
                continue;
            }
            let holding = polled == Poll::Holding;
            // Asleep until a doorbell or a control packet: say so on every
            // ring this side consumes, look once more, then wait.
            // A ring the handler does not take from now is not waited on:
            // its records wait for the handler, which says when to look
            // again through its beat or its own descriptor.
            for (i, c) in self.down.iter().enumerate() {
                if let Some(c) = c {
                    if i >= self.ports || h.takes(i) {
                        c.set_waiting();
                    }
                }
            }
            for l in &self.lanes {
                if h.takes_lane(l.key) {
                    l.down.set_waiting();
                }
            }
            let mut ready = false;
            for (i, c) in self.down.iter_mut().enumerate() {
                if let Some(c) = c {
                    if i < self.ports && !h.takes(i) {
                        continue;
                    }
                    ready |= c
                        .ready()
                        .map_err(|_| ServeError::Protocol("a hostile ring"))?;
                }
            }
            for l in &mut self.lanes {
                if !h.takes_lane(l.key) {
                    continue;
                }
                ready |= l
                    .down
                    .ready()
                    .map_err(|_| ServeError::Protocol("a hostile lane ring"))?;
            }
            if !ready {
                // Owed answers are retried on a short beat: the runtime
                // reads its rings every step and rings nobody.
                let wake = h.wake();
                let beat = if self.owed.is_empty() && !holding {
                    wake.within
                } else {
                    wake.within.min(Duration::from_millis(1))
                };
                control::wait_either(self.ctl.raw(), wake.fd, beat);
            }
            for c in self.down.iter().flatten() {
                c.clear_waiting();
            }
            for l in &self.lanes {
                l.down.clear_waiting();
            }
        }
    }

    /// Parse one call off contract `contract`'s ring (entry `at`), have the
    /// handler answer it, and owe the answer.
    fn answer_call(
        &mut self,
        contract: u16,
        at: usize,
        rec: &[u8],
        h: &mut impl Handler,
        b: &mut Scratch,
    ) -> Result<(), ServeError> {
        let Scratch { out, room, answer } = b;
        let sc = served(contract).ok_or(ServeError::Protocol("a call on no served contract"))?;
        // The opcode sits at bytes 8..12 whatever the framing after it.
        let opcode = rec
            .get(8..12)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or(ServeError::Protocol("a malformed call"))?;
        let span = sc.span(opcode);
        let d = span.map_or(Dir::None, |(d, _)| d);
        let Some(c) = CallHead::parse(rec, d) else {
            return Err(ServeError::Protocol("a malformed call"));
        };
        let head = c.head;
        let reply = match span {
            Some((d, max)) if head.contract == contract && c.data_len <= max => {
                let call = Call {
                    contract,
                    opcode: head.opcode,
                    handle: head.handle,
                    caller: head.caller,
                    arg: c.arg,
                    data_dir: d,
                    data_len: c.data_len,
                    data: c.data,
                };
                out.clear();
                out.extend_from_slice(c.arg);
                room.clear();
                if moves_out(d) {
                    room.resize(c.data_len, 0);
                    if moves_in(d) {
                        room.copy_from_slice(c.data);
                    }
                }
                let r = if matches!(d, Dir::None) {
                    let (rc, len) = h.call(&call, out);
                    Reply {
                        rc,
                        out_len: len,
                        data_len: 0,
                    }
                } else {
                    h.call_data(&call, out, room)
                };
                let erange = r.rc == fluxor_abi::errno::ERANGE;
                Reply {
                    rc: r.rc,
                    out_len: r.out_len.min(c.arg.len()),
                    data_len: if !moves_out(d) {
                        0
                    } else if erange {
                        r.data_len
                    } else {
                        r.data_len.min(c.data_len)
                    },
                }
            }
            Some(_) => Reply {
                rc: fluxor_abi::errno::EINVAL,
                out_len: 0,
                data_len: 0,
            },
            None => Reply {
                rc: fluxor_abi::errno::ENOSYS,
                out_len: 0,
                data_len: 0,
            },
        };
        let sent = reply.data_len.min(room.len());
        frame::encode_answer(
            head.call,
            reply.rc,
            &out[..reply.out_len],
            reply.data_len,
            &room[..sent],
            answer,
        );
        self.owed.push_back((at + 1, answer.clone()));
        self.flush_owed()?;
        Ok(())
    }

    /// Commit owed answers while their rings have room. `true` when any
    /// went.
    fn flush_owed(&mut self) -> Result<bool, ServeError> {
        let mut any = false;
        while let Some((at, rec)) = self.owed.front() {
            let Some(Some(p)) = self.up.get_mut(*at) else {
                return Err(ServeError::Protocol("an answer for no ring"));
            };
            match p.push(rec) {
                Ok(()) => {
                    any = true;
                    if p.take_waiting() {
                        let _ = self.ctl.send(&[control::RING, *at as u8, dir::UP], &[]);
                    }
                    self.owed.pop_front();
                }
                Err(Push::Full) => break,
                Err(_) => return Err(ServeError::Protocol("an answer the ring refuses")),
            }
        }
        Ok(any)
    }

    /// Send records to the runtime outside a handler.
    pub fn outbox(&mut self) -> Outbox<'_> {
        Outbox {
            up: &mut self.up,
            ports: self.ports,
            lanes: &mut self.lanes,
            ctl: &self.ctl,
        }
    }
}

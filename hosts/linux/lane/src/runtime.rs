//! The runtime's end of a lane: start the provider, check what it says it
//! is, hand it its rings, and move records and calls across.
//!
//! Nothing here blocks for long. Starting a provider waits for its `HELLO`
//! up to [`Spec::hello_timeout`]; a call waits for its answer only as long
//! as the caller allows, then answers `EAGAIN` and is collected by the
//! identical repeat — the key vault's resumable rule.
//!
//! ## Calls
//!
//! A call is keyed on its caller's `(slot, generation)`, the contract, the
//! opcode, the handle and the SHA-256 of its `arg`, its `data` span's length
//! and, when the span moves in, the span's bytes. Each caller has at most
//! one call in flight per contract: a different call from a caller whose
//! call is still out answers `EBUSY` and starts nothing, as does a call
//! when [`CALLS_IN_FLIGHT`] calls are out. A call nobody repeats for
//! [`fluxor_abi::contracts::key_vault::sign::JOB_IDLE_MS`] is abandoned; a
//! caller that is gone ([`Lane::caller_gone`]) has its calls dropped and the
//! provider told. A handle minted for a call that is never collected is
//! destroyed at the provider, so nothing holds it.
//!
//! ## Owners and dynamic lanes
//!
//! A provider that takes them ([`control::wants`]) is told each owner's host
//! process as it starts and when it is gone ([`Lane::owner_fact`]), and is
//! handed dynamic lanes, each a ring pair of its own, as the kernel attaches
//! them ([`Lane::lane_add`]); their records cross like port records, never
//! as calls.

use std::ffi::OsString;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process::Child;
use std::time::{Duration, Instant};

use fluxor_abi::errno;
use fluxor_contracts::channel_table::Entry;

use fluxor_abi::registry::gate::Dir;

use crate::control::{self, dir, wants, Control, Gate, Hello, LaneEntry, LaneMsg, OwnerFact, Recv};
use crate::frame::{self, moves_in, moves_out, CallHead, Caller};
use crate::privilege::Privilege;
use crate::ring::{Consumer, Producer, Push};
use crate::served::{served, ServedContract};
use crate::spawn::{self, Launch};

/// Calls a lane holds out at once, across every caller.
pub const CALLS_IN_FLIGHT: usize = 16;

/// How long a call nobody repeats is kept.
pub const CALL_IDLE: Duration =
    Duration::from_millis(fluxor_abi::contracts::key_vault::sign::JOB_IDLE_MS);

/// How long a stopping provider is given to exit before it is killed.
const STOP_GRACE: Duration = Duration::from_millis(500);

/// What a lane is started from.
pub struct Spec {
    /// The provider binary.
    pub binary: PathBuf,
    /// Its own parameter string.
    pub args: String,
    /// The whole environment it starts with.
    pub env: Vec<(OsString, OsString)>,
    /// The port channels, index = port pair.
    pub ports: Vec<Entry>,
    /// The contracts the provider must serve.
    pub contracts: Vec<u16>,
    /// The ABI surface digest the provider must have been built against.
    pub digest: [u8; 32],
    /// The SHA-256 of the provider binary the node image pins: any other
    /// binary at the path is refused before it runs.
    pub pin: [u8; 32],
    /// How long the provider has to say `HELLO`.
    pub hello_timeout: Duration,
    /// The capabilities the provider keeps.
    pub privilege: Privilege,
    /// The most dynamic lanes this lane carries; 0 for none.
    pub lanes: usize,
}

/// Why a lane did not open.
#[derive(Debug)]
pub enum OpenError {
    /// No provider binary at the path.
    Absent(PathBuf),
    /// The binary at the path is not the one the node image pins.
    Unpinned(PathBuf),
    /// The process could not be started.
    Spawn(std::io::Error),
    /// A contract no lane can carry.
    Unserved(u16),
    /// The provider exited, said something other than `HELLO`, or said
    /// nothing in time.
    Hello(&'static str),
    /// It said `HELLO`, and what it said does not match ([`control::refuse`]).
    Refused(u8),
    /// It said `UNABLE`: it cannot serve as started, for the reason given.
    Unable(String),
    /// The rings could not be made or handed over.
    Rings(std::io::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Absent(p) => write!(f, "no provider binary at {}", p.display()),
            OpenError::Unpinned(p) => write!(
                f,
                "the provider binary at {} is not the one the node image pins",
                p.display()
            ),
            OpenError::Spawn(e) => write!(f, "the provider did not start: {e}"),
            OpenError::Unserved(c) => write!(f, "contract {c:#06x} is not one a lane carries"),
            OpenError::Hello(why) => write!(f, "no HELLO from the provider: {why}"),
            OpenError::Refused(r) => write!(
                f,
                "the provider's HELLO does not match: {}",
                match *r {
                    control::refuse::DIGEST => "built against another ABI surface",
                    control::refuse::CONTRACTS => "it serves other contracts",
                    control::refuse::TABLE => "its channel table differs",
                    control::refuse::LANES => "it takes no dynamic lanes",
                    _ => "protocol",
                }
            ),
            OpenError::Unable(why) => write!(f, "the provider cannot serve: {why}"),
            OpenError::Rings(e) => write!(f, "the rings could not be handed over: {e}"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    slot: u16,
    generation: u32,
    contract: u16,
    opcode: u32,
    handle: i32,
    arg: [u8; 32],
}

enum State {
    Sent,
    /// `(rc, out, the span's answered length, the span bytes sent back)`.
    Answered(i32, Vec<u8>, usize, Vec<u8>),
}

struct Pending {
    id: u32,
    key: Key,
    /// The owner the caller ran as, opaque to the lane.
    owner: u64,
    state: State,
    touched: Instant,
    /// A call the lane made itself (a destroy for a handle nobody
    /// collected): its answer is discarded.
    internal: bool,
    /// A call its caller abandoned while it was out: nobody collects its
    /// answer, and a handle it mints is destroyed when it arrives.
    orphan: bool,
}

impl Pending {
    /// A call a caller may still collect.
    fn collectable(&self) -> bool {
        !self.internal && !self.orphan
    }
}

/// One call, as the runtime hands it over.
#[derive(Clone, Copy, Debug)]
pub struct CallReq {
    pub caller: Caller,
    /// The owner the caller runs as, opaque to the lane; what
    /// [`Lane::owner_gone`] names.
    pub owner: u64,
    pub contract: u16,
    pub opcode: u32,
    pub handle: i32,
}

/// What a call answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub rc: i32,
    /// Bytes of the `data` span written back; with `rc` = `ERANGE`, the
    /// length the answer needs when the span was short (what fitted is
    /// written).
    pub data_len: usize,
}

/// A dynamic lane, runtime side.
struct RtLane {
    key: u8,
    down: Producer,
    up: Consumer,
}

/// An open lane.
pub struct Lane {
    child: Option<Child>,
    ctl: Control,
    table: Vec<LaneEntry>,
    ports: usize,
    contracts: Vec<(ServedContract, usize)>,
    down: Vec<Option<Producer>>,
    up: Vec<Option<Consumer>>,
    calls: Vec<Pending>,
    next_call: u32,
    closed: bool,
    scratch: Vec<u8>,
    rx: Vec<u8>,
    incarnation: [u8; 16],
    wants: u8,
    lanes_cap: usize,
    lanes: Vec<RtLane>,
}

/// The table a spec states: its ports both ways, then each contract's call
/// and answer entries.
pub fn table_of(ports: &[Entry], contracts: &[u16]) -> Result<Vec<LaneEntry>, OpenError> {
    let mut table: Vec<LaneEntry> = ports
        .iter()
        .map(|&entry| LaneEntry {
            entry,
            dirs: dir::BOTH,
        })
        .collect();
    for &c in contracts {
        let s = served(c).ok_or(OpenError::Unserved(c))?;
        table.extend_from_slice(&s.entries());
    }
    Ok(table)
}

/// The SHA-256 of the provider binary at `path`: what a node image pins
/// for it (`Spec::pin`).
pub fn binary_digest(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    spawn::digest_of(&spawn::open_binary(path)?)
}

impl Lane {
    /// Start the provider and open the lane, or say why not.
    pub fn open(spec: Spec) -> Result<Lane, OpenError> {
        let table = table_of(&spec.ports, &spec.contracts)?;
        if !spec.binary.is_file() {
            return Err(OpenError::Absent(spec.binary));
        }
        let (ctl, theirs) = Control::pair().map_err(OpenError::Spawn)?;
        let binary = spec.binary.clone();
        let child = spawn::spawn(
            Launch {
                binary: spec.binary,
                pin: spec.pin,
                args: spec.args,
                env: spec.env,
                privilege: spec.privilege,
            },
            theirs,
        )
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidData => OpenError::Unpinned(binary),
            _ => OpenError::Spawn(e),
        })?;
        let mut lane = Lane {
            child: Some(child),
            ctl,
            table,
            ports: spec.ports.len(),
            contracts: Vec::new(),
            down: Vec::new(),
            up: Vec::new(),
            calls: Vec::new(),
            next_call: 1,
            closed: false,
            scratch: Vec::new(),
            rx: Vec::new(),
            incarnation: [0; 16],
            wants: 0,
            lanes_cap: spec.lanes.min(usize::from(u16::MAX)),
            lanes: Vec::new(),
        };
        let mut at = spec.ports.len();
        for &c in &spec.contracts {
            if let Some(s) = served(c) {
                lane.contracts.push((s, at));
                at += 2;
            }
        }
        lane.handshake(&spec.digest, &spec.contracts, spec.hello_timeout)?;
        Ok(lane)
    }

    fn handshake(
        &mut self,
        digest: &[u8; 32],
        contracts: &[u16],
        timeout: Duration,
    ) -> Result<(), OpenError> {
        let mut buf = vec![0u8; control::PACKET_MAX];
        if !self.ctl.wait(timeout) {
            return Err(OpenError::Hello("none within the timeout"));
        }
        let n = match self.ctl.try_recv(&mut buf) {
            Ok(Recv::Packet(n, _)) if buf.first() == Some(&control::UNABLE) => {
                let why = String::from_utf8_lossy(&buf[1..n]).into_owned();
                return Err(OpenError::Unable(why));
            }
            Ok(Recv::Packet(n, _)) => n,
            Ok(Recv::Closed) => return Err(OpenError::Hello("the provider exited")),
            Ok(Recv::Empty) => return Err(OpenError::Hello("none within the timeout")),
            Err(_) => return Err(OpenError::Hello("the control socket failed")),
        };
        let Some(hello) = Hello::parse(&buf[..n]) else {
            let _ = self
                .ctl
                .send(&[control::REFUSE, control::refuse::PROTOCOL], &[]);
            return Err(OpenError::Refused(control::refuse::PROTOCOL));
        };
        let reason = if hello.digest != *digest {
            Some(control::refuse::DIGEST)
        } else if hello.contracts != contracts {
            Some(control::refuse::CONTRACTS)
        } else if hello.table != self.table {
            Some(control::refuse::TABLE)
        } else if self.lanes_cap > 0 && hello.wants & wants::LANES == 0 {
            Some(control::refuse::LANES)
        } else {
            None
        };
        if let Some(r) = reason {
            let _ = self.ctl.send(&[control::REFUSE, r], &[]);
            return Err(OpenError::Refused(r));
        }
        // One ring per (entry, dir): DOWN rings this side produces into,
        // UP rings it consumes from.
        let mut accept = vec![control::ACCEPT, 0];
        let mut fds = Vec::new();
        for (i, le) in self.table.iter().enumerate() {
            let max = le.entry.max_record;
            if le.dirs & dir::DOWN != 0 {
                let (p, fd) = Producer::create(max).map_err(ring_io)?;
                self.down.push(Some(p));
                accept.extend_from_slice(&[i as u8, dir::DOWN]);
                fds.push(fd);
            } else {
                self.down.push(None);
            }
            if le.dirs & dir::UP != 0 {
                let (c, fd) = Consumer::create(max).map_err(ring_io)?;
                self.up.push(Some(c));
                accept.extend_from_slice(&[i as u8, dir::UP]);
                fds.push(fd);
            } else {
                self.up.push(None);
            }
        }
        accept[1] = fds.len() as u8;
        accept.extend_from_slice(&(self.lanes_cap as u16).to_le_bytes());
        self.incarnation = hello.incarnation;
        self.wants = hello.wants;
        let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
        self.ctl.send(&accept, &raw).map_err(OpenError::Rings)?;
        let max = self
            .table
            .iter()
            .map(|le| le.entry.max_record as usize)
            .max()
            .unwrap_or(0);
        self.rx = vec![0u8; max];
        Ok(())
    }

    /// The provider's incarnation, as its `HELLO` stated it: fresh at every
    /// start.
    pub fn incarnation(&self) -> [u8; 16] {
        self.incarnation
    }

    /// Whether the provider takes owner facts.
    pub fn takes_owners(&self) -> bool {
        self.wants & wants::OWNERS != 0
    }

    /// The provider's process id while it runs.
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Whether the lane has closed: the provider exited or broke the
    /// protocol. Reads the control socket.
    pub fn is_closed(&mut self) -> bool {
        self.poll_control();
        self.closed
    }

    /// Read what the provider has sent on the control socket without
    /// waiting: doorbells (nothing to do; rings are read every step) and
    /// end of file, which closes the lane.
    pub fn poll_control(&mut self) {
        if self.closed {
            return;
        }
        let mut buf = [0u8; 64];
        loop {
            match self.ctl.try_recv(&mut buf) {
                Ok(Recv::Packet(..)) => {}
                Ok(Recv::Empty) => return,
                Ok(Recv::Closed) | Err(_) => {
                    self.close();
                    return;
                }
            }
        }
    }

    fn close(&mut self) {
        self.closed = true;
        // Every call out now answers EIO when its caller comes back for it.
        for p in &mut self.calls {
            if matches!(p.state, State::Sent) {
                p.state = State::Answered(errno::EIO, Vec::new(), 0, Vec::new());
            }
        }
    }

    /// Port channels on this lane.
    pub fn ports(&self) -> usize {
        self.ports
    }

    /// The table entry of port `i`.
    pub fn port_entry(&self, i: usize) -> Option<&Entry> {
        self.table
            .get(i)
            .filter(|_| i < self.ports)
            .map(|le| &le.entry)
    }

    /// Commit `rec` to the provider on port `i`. `Err(Push::Full)` leaves
    /// the overload decision to the caller.
    pub fn send(&mut self, i: usize, rec: &[u8]) -> Result<(), SendError> {
        if self.closed {
            return Err(SendError::Closed);
        }
        if i >= self.ports {
            return Err(SendError::NoPort);
        }
        self.push_down(i, rec)
    }

    fn push_down(&mut self, i: usize, rec: &[u8]) -> Result<(), SendError> {
        let Some(Some(p)) = self.down.get_mut(i) else {
            return Err(SendError::NoPort);
        };
        match p.push(rec) {
            Ok(()) => {}
            Err(Push::Full) => return Err(SendError::Full),
            Err(Push::TooBig) => return Err(SendError::TooBig),
            Err(Push::Hostile) => {
                self.close();
                return Err(SendError::Closed);
            }
        }
        if p.take_waiting()
            && self
                .ctl
                .send(&[control::RING, i as u8, dir::DOWN], &[])
                .is_err()
        {
            self.close();
        }
        Ok(())
    }

    /// Take the provider's next record on port `i` into `out` (at least the
    /// port's maximum long).
    pub fn recv(&mut self, i: usize, out: &mut [u8]) -> Result<Option<usize>, SendError> {
        if i >= self.ports {
            return Err(SendError::NoPort);
        }
        let Some(Some(c)) = self.up.get_mut(i) else {
            return Err(SendError::NoPort);
        };
        match c.pop(out) {
            Ok(r) => Ok(r),
            Err(crate::ring::Pop::Short) => Err(SendError::TooBig),
            Err(crate::ring::Pop::Hostile) => {
                self.close();
                Err(SendError::Closed)
            }
        }
    }

    /// Make or collect a call with no `data` span. `arg` is the op's record
    /// in, and holds the provider's answer on return when the call is
    /// answered. `wait` bounds how long this waits for an answer before
    /// answering `EAGAIN`.
    pub fn call(&mut self, req: CallReq, arg: &mut [u8], wait: Duration) -> i32 {
        self.call_data(req, arg, &mut [], wait).rc
    }

    /// Make or collect a call. `arg` as for [`Lane::call`]; `data` is the
    /// op's span, moving the way the op's registry rule says: its bytes
    /// cross when it moves in, and the answer's bytes are written over it
    /// when it moves out. A span the op does not have is `EINVAL`; one
    /// moving in that is longer than the lane carries is `E2BIG`; one
    /// moving out is offered to the provider up to what the lane carries.
    pub fn call_data(
        &mut self,
        req: CallReq,
        arg: &mut [u8],
        data: &mut [u8],
        wait: Duration,
    ) -> Answer {
        let refuse = |rc| Answer { rc, data_len: 0 };
        let Some(&(sc, _)) = self.contracts.iter().find(|(s, _)| s.id == req.contract) else {
            return refuse(errno::ENOSYS);
        };
        let Some((d, max)) = sc.span(req.opcode) else {
            return refuse(errno::ENOSYS);
        };
        if arg.len() > sc.arg_max {
            return refuse(errno::EINVAL);
        }
        if matches!(d, Dir::None) && !data.is_empty() {
            return refuse(errno::EINVAL);
        }
        if moves_in(d) && data.len() > max {
            return refuse(errno::E2BIG);
        }
        let span_len = data.len().min(max);
        self.collect();
        self.expire();
        let key = Key {
            slot: req.caller.slot,
            generation: req.caller.generation,
            contract: req.contract,
            opcode: req.opcode,
            handle: req.handle,
            arg: {
                let mut h = fluxor_sdk::crypto::sha256::Sha256::new();
                h.update(arg);
                h.update(&(span_len as u32).to_le_bytes());
                if moves_in(d) {
                    h.update(data);
                }
                h.finalize()
            },
        };
        let id = if let Some(p) = self
            .calls
            .iter_mut()
            .find(|p| p.collectable() && p.key == key)
        {
            p.touched = Instant::now();
            p.id
        } else {
            if self.closed {
                return refuse(errno::EIO);
            }
            let busy = self.calls.iter().any(|p| {
                p.collectable()
                    && p.key.slot == key.slot
                    && p.key.generation == key.generation
                    && p.key.contract == key.contract
            });
            if busy || self.calls.len() >= CALLS_IN_FLIGHT {
                return refuse(errno::EBUSY);
            }
            let id = self.next_id();
            let head = CallHead {
                call: id,
                contract: req.contract,
                opcode: req.opcode,
                handle: req.handle,
                caller: req.caller,
            };
            let mut rec = std::mem::take(&mut self.scratch);
            let bytes: &[u8] = if moves_in(d) { data } else { &[] };
            head.encode(arg, span_len, bytes, &mut rec);
            let at = self.call_ring(req.contract);
            let sent = self.push_down(at, &rec);
            self.scratch = rec;
            match sent {
                Ok(()) => {}
                Err(SendError::Full) => return refuse(errno::EBUSY),
                Err(_) => return refuse(errno::EIO),
            }
            self.calls.push(Pending {
                id,
                key,
                owner: req.owner,
                state: State::Sent,
                touched: Instant::now(),
                internal: false,
                orphan: false,
            });
            id
        };
        self.wait_for(id, wait);
        let Some(i) = self.calls.iter().position(|p| p.id == id) else {
            return refuse(errno::EIO);
        };
        if matches!(self.calls[i].state, State::Sent) {
            return refuse(errno::EAGAIN);
        }
        let p = self.calls.swap_remove(i);
        let State::Answered(rc, out, data_len, back) = p.state else {
            return refuse(errno::EIO);
        };
        if out.len() > arg.len() || back.len() > span_len || (!moves_out(d) && !back.is_empty()) {
            return refuse(errno::EIO);
        }
        if rc != errno::ERANGE && data_len > span_len {
            return refuse(errno::EIO);
        }
        arg[..out.len()].copy_from_slice(&out);
        data[..back.len()].copy_from_slice(&back);
        Answer { rc, data_len }
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_call;
        self.next_call = self.next_call.wrapping_add(1).max(1);
        id
    }

    fn call_ring(&self, contract: u16) -> usize {
        self.contracts
            .iter()
            .find(|(s, _)| s.id == contract)
            .map_or(usize::MAX, |&(_, at)| at)
    }

    /// Wait up to `budget` for call `id`'s answer, sleeping on the doorbell.
    fn wait_for(&mut self, id: u32, budget: Duration) {
        let deadline = Instant::now() + budget;
        loop {
            self.collect();
            let done = self
                .calls
                .iter()
                .find(|p| p.id == id)
                .is_none_or(|p| !matches!(p.state, State::Sent));
            let now = Instant::now();
            if done || self.closed || now >= deadline {
                return;
            }
            for &(_, at) in &self.contracts {
                if let Some(Some(c)) = self.up.get(at + 1) {
                    c.set_waiting();
                }
            }
            // Look once more after saying we sleep: an answer committed
            // before the flag was seen rang nobody.
            self.collect();
            let ready = self
                .calls
                .iter()
                .find(|p| p.id == id)
                .is_none_or(|p| !matches!(p.state, State::Sent));
            if !ready {
                self.ctl.wait(deadline - now);
            }
            for &(_, at) in &self.contracts {
                if let Some(Some(c)) = self.up.get(at + 1) {
                    c.clear_waiting();
                }
            }
            self.poll_control();
        }
    }

    /// Drain every answer ring into the pending calls.
    fn collect(&mut self) {
        for k in 0..self.contracts.len() {
            let at = self.contracts[k].1 + 1;
            loop {
                let Some(Some(c)) = self.up.get_mut(at) else {
                    break;
                };
                let n = match c.pop(&mut self.rx) {
                    Ok(Some(n)) => n,
                    Ok(None) => break,
                    Err(_) => {
                        self.close();
                        return;
                    }
                };
                let Some(a) = frame::parse_answer(&self.rx[..n]) else {
                    self.close();
                    return;
                };
                let (id, rc) = (a.call, a.rc);
                let answered = State::Answered(rc, a.out.to_vec(), a.data_len, a.data.to_vec());
                if let Some(i) = self.calls.iter().position(|p| p.id == id) {
                    if self.calls[i].internal {
                        self.calls.swap_remove(i);
                    } else if matches!(self.calls[i].state, State::Sent) {
                        self.calls[i].state = answered;
                        if self.calls[i].orphan {
                            let p = self.calls.swap_remove(i);
                            self.abandon(p);
                        }
                    }
                }
            }
        }
    }

    /// Drop calls nobody repeated for [`CALL_IDLE`].
    fn expire(&mut self) {
        let now = Instant::now();
        let mut i = 0;
        while i < self.calls.len() {
            if now.duration_since(self.calls[i].touched) >= CALL_IDLE {
                let p = self.calls.swap_remove(i);
                // An orphan never answered in all that time has nothing a
                // destroy could name; a call nobody repeated is abandoned.
                if p.collectable() {
                    self.abandon(p);
                }
            } else {
                i += 1;
            }
        }
    }

    /// Forget a call. A handle minted for it, answered and never collected,
    /// is destroyed at the provider; one minted after this is destroyed
    /// when its answer arrives (the call stays, internal, until then).
    fn abandon(&mut self, p: Pending) {
        if p.internal || self.closed {
            return;
        }
        let Some(&(sc, at)) = self.contracts.iter().find(|(s, _)| s.id == p.key.contract) else {
            return;
        };
        if !sc.mints(p.key.opcode) {
            return;
        }
        match p.state {
            State::Answered(rc, ..) if rc >= 0 => {
                let id = self.next_id();
                let head = CallHead {
                    call: id,
                    contract: sc.id,
                    opcode: sc.destroy,
                    handle: rc,
                    caller: Caller {
                        slot: p.key.slot,
                        generation: p.key.generation,
                        ..Caller::default()
                    },
                };
                let mut rec = std::mem::take(&mut self.scratch);
                head.encode(&[], 0, &[], &mut rec);
                if self.push_down(at, &rec).is_ok() {
                    self.calls.push(Pending {
                        id,
                        key: p.key,
                        owner: p.owner,
                        state: State::Sent,
                        touched: Instant::now(),
                        internal: true,
                        orphan: false,
                    });
                }
                self.scratch = rec;
            }
            State::Sent => {
                // Still out: when it is answered, the answer is a handle
                // nobody will collect.
                self.calls.push(Pending {
                    touched: Instant::now(),
                    orphan: true,
                    ..p
                });
            }
            State::Answered(..) => {}
        }
    }

    /// Caller `(slot, generation)` is gone: drop its calls and tell the
    /// provider, which frees what it holds for it.
    pub fn caller_gone(&mut self, slot: u16, generation: u32) {
        self.collect();
        let mut i = 0;
        while i < self.calls.len() {
            let k = self.calls[i].key;
            if self.calls[i].collectable() && k.slot == slot && k.generation == generation {
                let p = self.calls.swap_remove(i);
                self.abandon(p);
            } else {
                i += 1;
            }
        }
        if self.closed {
            return;
        }
        let msg = control::slot_gen(control::RELEASED, slot, generation);
        if self.ctl.send(&msg, &[]).is_err() {
            self.close();
        }
    }

    /// Tell the provider an owner's host process: its facts, and `netlink`,
    /// a `NETLINK_ROUTE` socket inside its network namespace, when there is
    /// one. Nothing is sent to a provider that takes no owner facts.
    pub fn owner_fact(&mut self, fact: OwnerFact, netlink: Option<&OwnedFd>) {
        if self.closed || !self.takes_owners() {
            return;
        }
        let fds: Vec<RawFd> = netlink.iter().map(|f| f.as_raw_fd()).collect();
        if self.ctl.send(&fact.encode(), &fds).is_err() {
            self.close();
        }
    }

    /// Tell the provider an owner's process is gone.
    pub fn owner_fact_gone(&mut self, slot: u16, generation: u32) {
        if self.closed || !self.takes_owners() {
            return;
        }
        let msg = control::slot_gen(control::OWNER_GONE, slot, generation);
        if self.ctl.send(&msg, &[]).is_err() {
            self.close();
        }
    }

    /// Tell the provider what an owner may claim through a port's records
    /// or a dynamic lane's ([`Gate`]). `E2BIG` for grants one packet cannot
    /// carry, `EIO` closed.
    pub fn gate(&mut self, gate: &Gate) -> Result<(), i32> {
        if self.closed {
            return Err(errno::EIO);
        }
        let p = gate.encode().ok_or(errno::E2BIG)?;
        if self.ctl.send(&p, &[]).is_err() {
            self.close();
            return Err(errno::EIO);
        }
        Ok(())
    }

    /// Tell the provider an owner is freed, and wait up to `wait` for it to
    /// say it has let go of what it held for the owner. `true` when it said
    /// so in time; a closed lane holds nothing and answers `true`.
    pub fn owner_released(&mut self, slot: u16, generation: u32, wait: Duration) -> bool {
        if self.closed {
            return true;
        }
        let msg = control::slot_gen(control::OWNER_RELEASED, slot, generation);
        if self.ctl.send(&msg, &[]).is_err() {
            self.close();
            return true;
        }
        let deadline = Instant::now() + wait;
        let mut buf = [0u8; 64];
        loop {
            match self.ctl.try_recv(&mut buf) {
                Ok(Recv::Packet(n, _)) => {
                    if control::parse_slot_gen(control::OWNER_RELEASED, &buf[..n])
                        == Some((slot, generation))
                    {
                        return true;
                    }
                }
                Ok(Recv::Empty) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return false;
                    }
                    self.ctl.wait(deadline - now);
                }
                Ok(Recv::Closed) | Err(_) => {
                    self.close();
                    return true;
                }
            }
        }
    }

    /// The most dynamic lanes this lane carries.
    pub fn lanes_capacity(&self) -> usize {
        self.lanes_cap
    }

    /// Dynamic lanes attached now.
    pub fn lanes_attached(&self) -> usize {
        self.lanes.len()
    }

    /// Attach dynamic lane `key` for owner `(owner_slot, owner_generation)`:
    /// a ring pair of `max_record` each way, handed to the provider.
    /// `ENOSPC` past capacity, `EEXIST` for a key attached, `EIO` closed.
    pub fn lane_add(
        &mut self,
        key: u8,
        owner_slot: u16,
        owner_generation: u32,
        max_record: u32,
    ) -> Result<(), i32> {
        if self.closed {
            return Err(errno::EIO);
        }
        if self.lanes.iter().any(|l| l.key == key) {
            return Err(errno::EEXIST);
        }
        if self.lanes.len() >= self.lanes_cap || max_record == 0 {
            return Err(errno::ENOSPC);
        }
        let (down, dfd) = Producer::create(max_record).map_err(|_| errno::ENOMEM)?;
        let (up, ufd) = Consumer::create(max_record).map_err(|_| errno::ENOMEM)?;
        let msg = LaneMsg {
            op: control::lane::ADD,
            key,
            owner_slot,
            owner_generation,
            max_record,
        };
        if self
            .ctl
            .send(&msg.encode(), &[dfd.as_raw_fd(), ufd.as_raw_fd()])
            .is_err()
        {
            self.close();
            return Err(errno::EIO);
        }
        self.lanes.push(RtLane { key, down, up });
        Ok(())
    }

    fn lane_op(&mut self, op: u8, key: u8) -> Result<(), i32> {
        let Some(i) = self.lanes.iter().position(|l| l.key == key) else {
            return Err(errno::ENOENT);
        };
        if op == control::lane::DEL {
            self.lanes.swap_remove(i);
        }
        if self.closed {
            return Ok(());
        }
        let msg = LaneMsg {
            op,
            key,
            owner_slot: 0,
            owner_generation: 0,
            max_record: 0,
        };
        if self.ctl.send(&msg.encode(), &[]).is_err() {
            self.close();
        }
        Ok(())
    }

    /// Detach dynamic lane `key`. `ENOENT` for none.
    pub fn lane_del(&mut self, key: u8) -> Result<(), i32> {
        self.lane_op(control::lane::DEL, key)
    }

    /// Say lane `key`'s owner is draining. `ENOENT` for none.
    pub fn lane_drain(&mut self, key: u8) -> Result<(), i32> {
        self.lane_op(control::lane::DRAIN, key)
    }

    /// Commit `rec` to the provider on dynamic lane `key`.
    pub fn lane_send(&mut self, key: u8, rec: &[u8]) -> Result<(), SendError> {
        if self.closed {
            return Err(SendError::Closed);
        }
        let Some(l) = self.lanes.iter_mut().find(|l| l.key == key) else {
            return Err(SendError::NoPort);
        };
        match l.down.push(rec) {
            Ok(()) => {}
            Err(Push::Full) => return Err(SendError::Full),
            Err(Push::TooBig) => return Err(SendError::TooBig),
            Err(Push::Hostile) => {
                self.close();
                return Err(SendError::Closed);
            }
        }
        if l.down.take_waiting()
            && self
                .ctl
                .send(&[control::LANE_RING, key, dir::DOWN], &[])
                .is_err()
        {
            self.close();
        }
        Ok(())
    }

    /// Take the provider's next record on dynamic lane `key` into `out` (at
    /// least the lane's maximum long).
    pub fn lane_recv(&mut self, key: u8, out: &mut [u8]) -> Result<Option<usize>, SendError> {
        let Some(l) = self.lanes.iter_mut().find(|l| l.key == key) else {
            return Err(SendError::NoPort);
        };
        match l.up.pop(out) {
            Ok(r) => Ok(r),
            Err(crate::ring::Pop::Short) => Err(SendError::TooBig),
            Err(crate::ring::Pop::Hostile) => {
                self.close();
                Err(SendError::Closed)
            }
        }
    }

    /// Owner `owner` is gone: drop the calls its modules made.
    pub fn owner_gone(&mut self, owner: u64) {
        self.collect();
        let mut i = 0;
        while i < self.calls.len() {
            if self.calls[i].collectable() && self.calls[i].owner == owner {
                let p = self.calls.swap_remove(i);
                self.abandon(p);
            } else {
                i += 1;
            }
        }
    }

    /// Housekeeping between calls: answers in, idle calls out, and calls
    /// whose caller `live` says is gone dropped (and the provider told).
    pub fn tick(&mut self, live: impl Fn(u16, u32) -> bool) {
        self.poll_control();
        self.collect();
        self.expire();
        let mut gone: Vec<(u16, u32)> = self
            .calls
            .iter()
            .filter(|p| p.collectable())
            .map(|p| (p.key.slot, p.key.generation))
            .filter(|&(s, g)| !live(s, g))
            .collect();
        gone.sort_unstable();
        gone.dedup();
        for (s, g) in gone {
            self.caller_gone(s, g);
        }
    }

    /// Calls out, the lane's own included.
    pub fn calls_out(&self) -> usize {
        self.calls.len()
    }

    /// Ask the provider to exit, give it [`STOP_GRACE`], then kill it.
    pub fn stop(&mut self) {
        if !self.closed {
            let _ = self.ctl.send(&[control::STOP], &[]);
        }
        self.close();
        if let Some(mut child) = self.child.take() {
            let deadline = Instant::now() + STOP_GRACE;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if Instant::now() < deadline => {
                        self.ctl.wait(Duration::from_millis(10));
                        let mut buf = [0u8; 64];
                        let _ = self.ctl.try_recv(&mut buf);
                    }
                    _ => break,
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Why a port record did not cross.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The ring has no room for it now.
    Full,
    /// Longer than the port's maximum (or a receive buffer shorter).
    TooBig,
    /// No such port.
    NoPort,
    /// The lane is closed.
    Closed,
}

fn ring_io(e: crate::ring::RingError) -> OpenError {
    OpenError::Rings(match e {
        crate::ring::RingError::Os(n) => std::io::Error::from_raw_os_error(n),
        _ => std::io::Error::from_raw_os_error(libc::EINVAL),
    })
}

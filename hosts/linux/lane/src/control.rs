//! The lane's control socket: one `socketpair(AF_UNIX, SOCK_SEQPACKET)`,
//! the provider's end at descriptor 3. Every message is one packet, its
//! first byte the kind:
//!
//! | kind | body | from | meaning |
//! |---|---|---|---|
//! | `HELLO` | `"FXLN"[digest:32][incarnation:16][wants:u8][n:u8][contract:u16 LE × n][m:u8][entry × m]` | provider, first | the ABI surface digest it was built against, this start's incarnation, what it takes beyond calls ([`wants`]), the contracts it serves and its whole channel table |
//! | `UNABLE` | `[reason: UTF-8]` | provider, in place of `HELLO` | it cannot serve as started (a privilege it needs is missing); the runtime closes the lane and states the reason |
//! | `ACCEPT` | `[n:u8][(entry:u8, dir:u8) × n][lanes:u16 LE]` + `n` descriptors (`SCM_RIGHTS`) | runtime | the table matched; one ring per `(entry, dir)`, in that order; the most dynamic lanes it will add |
//! | `REFUSE` | `[reason:u8]` | runtime | the table or digest differs ([`refuse`]); the runtime closes the lane |
//! | `RING` | `[entry:u8][dir:u8]` | either | a record was committed on a ring whose consumer said it was asleep |
//! | `STOP` | — | runtime | finish and exit |
//! | `RELEASED` | `[slot:u16 LE][generation:u32 LE]` | runtime | that caller is gone: free what it holds |
//! | `OWNER` | `[slot:u16][generation:u32][owner_uid:16][pid:u32]` + 0 or 1 descriptor | runtime | an owner's host process: its init's host pid, and a `NETLINK_ROUTE` socket opened inside its network namespace |
//! | `OWNER_GONE` | `[slot:u16][generation:u32]` | runtime | that owner's process is gone |
//! | `LANE` | `[op:u8][key:u8][owner slot:u16][owner generation:u32][max_record:u32]` + 2 descriptors on `ADD` | runtime | a dynamic lane added (its DOWN ring, then its UP ring), removed, or draining ([`lane`]) |
//! | `LANE_RING` | `[key:u8][dir:u8]` | either | a doorbell on a dynamic lane's ring |
//! | `GATE` | `[on:u8][index:u8][owner slot:u16][owner generation:u32][flags:u8][grants]` | runtime | what the owner whose commands arrive on a port's records (`on` = [`gate::PORT`], `index` its entry) or on a dynamic lane (`on` = [`gate::LANE`], `index` its key) may claim now ([`Gate`]) |
//! | `OWNER_RELEASED` | `[slot:u16][generation:u32]` | runtime, then provider | that owner is freed: let go of everything held for it; the provider answers with the same packet once it has |
//!
//! Every integer is little-endian.
//!
//! A table entry is `[ct_len:u8][content_type][framing:u8][len_off:u8]
//! [len_width:u8][len_add:u32 LE][max_record:u32 LE][dirs:u8]`. End of file
//! on the socket is "lane closed", whichever side it reaches.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use fluxor_contracts::channel_table::{Entry, CT_NAME_MAX};

pub const HELLO: u8 = 1;
pub const ACCEPT: u8 = 2;
pub const REFUSE: u8 = 3;
pub const RING: u8 = 4;
pub const STOP: u8 = 5;
pub const RELEASED: u8 = 6;
pub const UNABLE: u8 = 7;
pub const OWNER: u8 = 8;
pub const OWNER_GONE: u8 = 9;
pub const LANE: u8 = 10;
pub const LANE_RING: u8 = 11;
pub const GATE: u8 = 12;
pub const OWNER_RELEASED: u8 = 13;

/// What a provider takes beyond calls and port records, as `HELLO`'s
/// `wants` bits.
pub mod wants {
    /// Dynamic lanes (`LANE`).
    pub const LANES: u8 = 1 << 0;
    /// Owner facts (`OWNER`, `OWNER_GONE`).
    pub const OWNERS: u8 = 1 << 1;
}

/// `LANE` ops.
pub mod lane {
    /// A lane attached: two rings follow.
    pub const ADD: u8 = 1;
    /// The lane is gone; its rings are unmapped.
    pub const DEL: u8 = 2;
    /// The lane's owner is draining: admit nothing new on it.
    pub const DRAIN: u8 = 3;
}

/// An owner fact, as `OWNER` carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerFact {
    pub slot: u16,
    pub generation: u32,
    pub owner_uid: [u8; 16],
    pub pid: u32,
}

impl OwnerFact {
    /// Bytes of an `OWNER` packet.
    pub const LEN: usize = 1 + 2 + 4 + 16 + 4;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        p[0] = OWNER;
        p[1..3].copy_from_slice(&self.slot.to_le_bytes());
        p[3..7].copy_from_slice(&self.generation.to_le_bytes());
        p[7..23].copy_from_slice(&self.owner_uid);
        p[23..27].copy_from_slice(&self.pid.to_le_bytes());
        p
    }

    pub fn parse(p: &[u8]) -> Option<OwnerFact> {
        if p.len() != Self::LEN || p[0] != OWNER {
            return None;
        }
        let mut owner_uid = [0u8; 16];
        owner_uid.copy_from_slice(&p[7..23]);
        Some(OwnerFact {
            slot: u16::from_le_bytes([p[1], p[2]]),
            generation: u32::from_le_bytes([p[3], p[4], p[5], p[6]]),
            owner_uid,
            pid: u32::from_le_bytes([p[23], p[24], p[25], p[26]]),
        })
    }
}

/// A `LANE` packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneMsg {
    pub op: u8,
    pub key: u8,
    pub owner_slot: u16,
    pub owner_generation: u32,
    pub max_record: u32,
}

impl LaneMsg {
    /// Bytes of a `LANE` packet.
    pub const LEN: usize = 1 + 1 + 1 + 2 + 4 + 4;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        p[0] = LANE;
        p[1] = self.op;
        p[2] = self.key;
        p[3..5].copy_from_slice(&self.owner_slot.to_le_bytes());
        p[5..9].copy_from_slice(&self.owner_generation.to_le_bytes());
        p[9..13].copy_from_slice(&self.max_record.to_le_bytes());
        p
    }

    pub fn parse(p: &[u8]) -> Option<LaneMsg> {
        if p.len() != Self::LEN || p[0] != LANE {
            return None;
        }
        Some(LaneMsg {
            op: p[1],
            key: p[2],
            owner_slot: u16::from_le_bytes([p[3], p[4]]),
            owner_generation: u32::from_le_bytes([p[5], p[6], p[7], p[8]]),
            max_record: u32::from_le_bytes([p[9], p[10], p[11], p[12]]),
        })
    }
}

/// `GATE`: what an owner may claim through the records of one port or one
/// dynamic lane.
pub mod gate {
    /// `on`: a port pair, `index` its table entry.
    pub const PORT: u8 = 0;
    /// `on`: a dynamic lane, `index` its key.
    pub const LANE: u8 = 1;
    /// `flags`: the owner admits new work (it is not draining, paused or
    /// gone).
    pub const OPEN: u8 = 1 << 0;
    /// Every `flags` bit defined; a packet with another is refused.
    pub const FLAGS_KNOWN: u8 = OPEN;
}

/// A `GATE` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate {
    pub on: u8,
    pub index: u8,
    pub owner_slot: u16,
    pub owner_generation: u32,
    pub flags: u8,
    /// The owner's whole grant set (`[kind:u16][len:u16][bytes]` each), as
    /// the kernel's `OWNER_GRANTS` answers it: empty for an owner granted
    /// nothing.
    pub grants: Vec<u8>,
}

impl Gate {
    /// Bytes before the grants.
    pub const HEAD: usize = 1 + 1 + 1 + 2 + 4 + 1;
    /// The most grant bytes one packet carries.
    pub const GRANTS_MAX: usize = PACKET_MAX - Self::HEAD;

    /// The packet, or `None` when the grants do not fit one.
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.grants.len() > Self::GRANTS_MAX {
            return None;
        }
        let mut p = Vec::with_capacity(Self::HEAD + self.grants.len());
        p.push(GATE);
        p.push(self.on);
        p.push(self.index);
        p.extend_from_slice(&self.owner_slot.to_le_bytes());
        p.extend_from_slice(&self.owner_generation.to_le_bytes());
        p.push(self.flags);
        p.extend_from_slice(&self.grants);
        Some(p)
    }

    pub fn parse(p: &[u8]) -> Option<Gate> {
        if p.len() < Self::HEAD
            || p[0] != GATE
            || p[1] > gate::LANE
            || p[9] & !gate::FLAGS_KNOWN != 0
        {
            return None;
        }
        Some(Gate {
            on: p[1],
            index: p[2],
            owner_slot: u16::from_le_bytes([p[3], p[4]]),
            owner_generation: u32::from_le_bytes([p[5], p[6], p[7], p[8]]),
            flags: p[9],
            grants: p[Self::HEAD..].to_vec(),
        })
    }
}

/// `(slot, generation)` of a `RELEASED`, `OWNER_GONE` or `OWNER_RELEASED`
/// packet of `kind`.
pub fn parse_slot_gen(kind: u8, p: &[u8]) -> Option<(u16, u32)> {
    if p.len() != 7 || p[0] != kind {
        return None;
    }
    Some((
        u16::from_le_bytes([p[1], p[2]]),
        u32::from_le_bytes([p[3], p[4], p[5], p[6]]),
    ))
}

/// A `RELEASED`, `OWNER_GONE` or `OWNER_RELEASED` packet of `kind`.
pub fn slot_gen(kind: u8, slot: u16, generation: u32) -> [u8; 7] {
    let mut p = [0u8; 7];
    p[0] = kind;
    p[1..3].copy_from_slice(&slot.to_le_bytes());
    p[3..7].copy_from_slice(&generation.to_le_bytes());
    p
}

/// `HELLO`'s magic.
pub const HELLO_MAGIC: [u8; 4] = *b"FXLN";

/// Largest control packet.
pub const PACKET_MAX: usize = 4096;
/// Most descriptors one `ACCEPT` carries.
pub const FDS_MAX: usize = 64;

/// Which way a ring carries records.
pub mod dir {
    /// Runtime to provider.
    pub const DOWN: u8 = 1;
    /// Provider to runtime.
    pub const UP: u8 = 2;
    /// A port channel: one ring each way.
    pub const BOTH: u8 = DOWN | UP;
}

/// `REFUSE` reasons.
pub mod refuse {
    /// The provider was built against another ABI surface.
    pub const DIGEST: u8 = 1;
    /// The served contracts differ.
    pub const CONTRACTS: u8 = 2;
    /// The channel tables differ.
    pub const TABLE: u8 = 3;
    /// A packet the protocol does not allow at that point.
    pub const PROTOCOL: u8 = 4;
    /// The instance adds dynamic lanes and the provider takes none.
    pub const LANES: u8 = 5;
}

/// A lane table entry: the channel and which ways it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneEntry {
    pub entry: Entry,
    pub dirs: u8,
}

/// What a provider says in its `HELLO`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub digest: [u8; 32],
    /// This start of the provider: fresh at every start, so state it
    /// reports (a table generation) is known to have restarted.
    pub incarnation: [u8; 16],
    /// [`wants`] bits.
    pub wants: u8,
    pub contracts: Vec<u16>,
    pub table: Vec<LaneEntry>,
}

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.table.len() * 48);
        out.push(HELLO);
        out.extend_from_slice(&HELLO_MAGIC);
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.incarnation);
        out.push(self.wants);
        out.push(self.contracts.len() as u8);
        for c in &self.contracts {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.push(self.table.len() as u8);
        for le in &self.table {
            let e = &le.entry;
            out.push(e.ct_len);
            out.extend_from_slice(e.content_type());
            out.push(e.framing);
            out.push(e.len_off);
            out.push(e.len_width);
            out.extend_from_slice(&e.len_add.to_le_bytes());
            out.extend_from_slice(&e.max_record.to_le_bytes());
            out.push(le.dirs);
        }
        out
    }

    /// Parse a `HELLO` packet, kind byte included.
    pub fn parse(p: &[u8]) -> Option<Hello> {
        let mut r = Reader(p);
        if r.u8()? != HELLO || r.take(4)? != HELLO_MAGIC {
            return None;
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(r.take(32)?);
        let mut incarnation = [0u8; 16];
        incarnation.copy_from_slice(r.take(16)?);
        let wants = r.u8()?;
        let n = r.u8()? as usize;
        let mut contracts = Vec::with_capacity(n);
        for _ in 0..n {
            contracts.push(r.u16()?);
        }
        let m = r.u8()? as usize;
        let mut table = Vec::with_capacity(m);
        for _ in 0..m {
            let ct_len = r.u8()? as usize;
            if ct_len == 0 || ct_len > CT_NAME_MAX {
                return None;
            }
            let mut e = Entry::EMPTY;
            e.content_type[..ct_len].copy_from_slice(r.take(ct_len)?);
            e.ct_len = ct_len as u8;
            e.framing = r.u8()?;
            e.len_off = r.u8()?;
            e.len_width = r.u8()?;
            e.len_add = r.u32()?;
            e.max_record = r.u32()?;
            let dirs = r.u8()?;
            table.push(LaneEntry { entry: e, dirs });
        }
        if !r.0.is_empty() {
            return None;
        }
        Some(Hello {
            digest,
            incarnation,
            wants,
            contracts,
            table,
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Some(h)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// A connected control socket.
pub struct Control {
    fd: OwnedFd,
}

/// What one receive found.
#[derive(Debug)]
pub enum Recv {
    /// A packet of this many bytes, and the descriptors it carried.
    Packet(usize, Vec<OwnedFd>),
    /// Nothing waiting.
    Empty,
    /// The peer is gone.
    Closed,
}

impl Control {
    /// A connected pair: `(runtime end, provider end)`, both close-on-exec.
    pub fn pair() -> std::io::Result<(Control, OwnedFd)> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` is a writable two-element array for the call.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: both descriptors were just returned to us.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        Ok((Control { fd: a }, b))
    }

    /// Adopt an inherited descriptor as the control socket, marking it
    /// close-on-exec so nothing the holder starts inherits it.
    ///
    /// # Safety
    /// `fd` is an open descriptor nothing else owns.
    pub unsafe fn adopt(fd: RawFd) -> std::io::Result<Control> {
        // SAFETY: the caller's contract; integer arguments.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ty: libc::c_int = 0;
        let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `ty`/`len` are writable for the call.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut ty).cast(),
                &mut len,
            )
        };
        if rc != 0 || ty != libc::SOCK_SEQPACKET {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSOCK));
        }
        // SAFETY: the caller's contract: `fd` is open and ours alone.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Control { fd })
    }

    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Send one packet, with `fds` attached. A peer that is gone is an
    /// error; the caller treats it as the lane closing.
    pub fn send(&self, packet: &[u8], fds: &[RawFd]) -> std::io::Result<()> {
        if fds.len() > FDS_MAX {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut iov = libc::iovec {
            iov_base: packet.as_ptr() as *mut libc::c_void,
            iov_len: packet.len(),
        };
        let fd_bytes = core::mem::size_of_val(fds) as u32;
        let space = if fds.is_empty() {
            0
        } else {
            // SAFETY: CMSG_SPACE is a pure size computation.
            unsafe { libc::CMSG_SPACE(fd_bytes) as usize }
        };
        let mut cbuf = vec![0u64; space.div_ceil(8)];
        // SAFETY: a zeroed msghdr is a valid empty one.
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !fds.is_empty() {
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            // SAFETY: `msg_control` holds `space` bytes, room for one
            // header and `fds`; CMSG_FIRSTHDR is non-null for it.
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(fd_bytes) as _;
                core::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(c),
                    fd_bytes as usize,
                );
            }
        }
        // SAFETY: `msg` names live buffers for the call.
        let n = unsafe { libc::sendmsg(self.raw(), &msg, libc::MSG_NOSIGNAL) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n as usize != packet.len() {
            return Err(std::io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        Ok(())
    }

    /// Receive one packet into `buf` without waiting.
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<Recv> {
        self.recv_flags(buf, libc::MSG_DONTWAIT)
    }

    /// Wait up to `timeout` for the socket to be readable (or hung up).
    /// `true` when it is.
    pub fn wait(&self, timeout: Duration) -> bool {
        wait_readable(self.raw(), timeout)
    }

    fn recv_flags(&self, buf: &mut [u8], flags: libc::c_int) -> std::io::Result<Recv> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: CMSG_SPACE is a pure size computation.
        let space =
            unsafe { libc::CMSG_SPACE((FDS_MAX * core::mem::size_of::<RawFd>()) as u32) as usize };
        let mut cbuf = vec![0u64; space.div_ceil(8)];
        // SAFETY: a zeroed msghdr is a valid empty one.
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        // SAFETY: `msg` names live buffers for the call.
        let n = unsafe { libc::recvmsg(self.raw(), &mut msg, flags | libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EAGAIN) => Ok(Recv::Empty),
                Some(libc::ECONNRESET) => Ok(Recv::Closed),
                _ => Err(e),
            };
        }
        let mut fds = Vec::new();
        // SAFETY: walking the control buffer the kernel filled, by the
        // CMSG_* accessors; each SCM_RIGHTS payload is whole descriptors we
        // now own.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(c);
                    let bytes = (*c).cmsg_len as usize - (data as usize - c as usize);
                    let count = bytes / core::mem::size_of::<RawFd>();
                    for i in 0..count {
                        let fd = core::ptr::read_unaligned(data.cast::<RawFd>().add(i));
                        fds.push(OwnedFd::from_raw_fd(fd));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        if n == 0 {
            return Ok(Recv::Closed);
        }
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        Ok(Recv::Packet(n as usize, fds))
    }
}

/// The protocol of socket `fd` (`NETLINK_ROUTE` for an owner's netlink
/// socket), or `None` when it is no socket.
pub fn socket_protocol(fd: &OwnedFd) -> Option<i32> {
    let mut v: libc::c_int = -1;
    let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v`/`len` are writable for the call.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PROTOCOL,
            (&raw mut v).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(v)
}

/// Wait up to `timeout` for `fd` to be readable or hung up.
pub fn wait_readable(fd: RawFd, timeout: Duration) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ts = libc::timespec {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_nsec: libc::c_long::from(timeout.subsec_nanos() as i32),
    };
    // SAFETY: one pollfd and a timespec, both live for the call.
    let rc = unsafe { libc::ppoll(&mut p, 1, &ts, core::ptr::null()) };
    rc > 0
}

/// Wait up to `timeout` for `fd` or, when given, `also` to be readable or
/// hung up. `true` when either is.
pub fn wait_either(fd: RawFd, also: Option<RawFd>, timeout: Duration) -> bool {
    let mut p = [
        libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: also.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let ts = libc::timespec {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_nsec: libc::c_long::from(timeout.subsec_nanos() as i32),
    };
    let n = if also.is_some() { 2 } else { 1 };
    // SAFETY: `n` live pollfds and a timespec, all live for the call.
    let rc = unsafe { libc::ppoll(p.as_mut_ptr(), n, &ts, core::ptr::null()) };
    rc > 0
}

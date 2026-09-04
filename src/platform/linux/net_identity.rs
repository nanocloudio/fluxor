// ============================================================================
// Linux realization of the `workload` Tier-1 network fields
// ============================================================================
//
// Mechanism behind `NET_ISO_OWN` + the network identity in the `workload`
// CREATE header — not a consumer-facing surface. The contract carries only
// portable intents (own network domain; an address/segment); this module maps
// them onto the Linux mechanism: the sandbox's own netns (unshared in
// `host_backend.rs`), a veth pair whose peer is moved into that netns at creation, and
// the identity address configured on the peer.
//
// Division of labour (fluxor = mechanism, nanocloud = policy):
//   * fluxor creates `fxw<idx>` (host end, brought up, left unattached) and
//     `fxc<idx>` (container end, identity address + up), and brings `lo` up
//     inside the netns.
//   * bridge/route/netfilter plumbing of `fxw<idx>` — and IPAM that computed
//     the address in the first place — is the orchestrator's (CNI-chain)
//     policy, deliberately not done here.
//
// Teardown is free: the veth pair dies with the netns, which dies with the
// container process. IPv4 only for now; a `NET_FAM_IPV6` request is refused
// at admission (`ENOSYS`) rather than half-realized.
//
// The container-side configuration runs in a short-lived forked helper that
// `setns()`s into the container's netns — never on the platform thread, whose
// netns must not change.

use crate::kernel::sys::errno;

/// The network identity from the `workload` CREATE header (family already
/// validated by the provider; only IPv4 reaches this module today).
#[derive(Clone, Copy)]
pub struct NetIdentity {
    /// IPv4 address, network byte order as carried in the header.
    pub addr_v4: [u8; 4],
    /// Prefix length in bits (1..=32).
    pub prefix_len: u8,
}

/// Interface names for a sandbox slot: host end / container end. `idx` is a
/// `host_backend` sandbox slot index (`< MAX_SANDBOXES`), so `fx?{idx}` stays far inside the
/// IFNAMSIZ 15-byte limit; the assert keeps a future slot-table growth from
/// silently truncating or overflowing names.
fn ifnames(idx: usize) -> ([u8; 16], [u8; 16]) {
    debug_assert!(idx < super::host_backend::MAX_SANDBOXES);
    let mut host = [0u8; 16];
    let mut cont = [0u8; 16];
    let h = format!("fxw{idx}");
    let c = format!("fxc{idx}");
    debug_assert!(h.len() <= 15 && c.len() <= 15); // IFNAMSIZ = 15 chars + NUL
    host[..h.len()].copy_from_slice(h.as_bytes());
    cont[..c.len()].copy_from_slice(c.as_bytes());
    (host, cont)
}

// ---- minimal rtnetlink (no external deps) ----------------------------------

const NETLINK_ROUTE: i32 = 0;
const RTM_NEWLINK: u16 = 16;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLMSG_ERROR: u16 = 0x0002;

const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFLA_NET_NS_PID: u16 = 19;
const NLA_F_NESTED: u16 = 0x8000;

#[repr(C)]
struct NlMsgHdr {
    len: u32,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct IfInfoMsg {
    family: u8,
    _pad: u8,
    ty: u16,
    index: i32,
    flags: u32,
    change: u32,
}

/// Append a netlink attribute (4-byte aligned) to `buf`.
fn put_attr(buf: &mut Vec<u8>, ty: u16, data: &[u8]) {
    let len = 4 + data.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(data);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Begin a nested attribute; returns the offset to patch its length at end.
fn begin_nested(buf: &mut Vec<u8>, ty: u16) -> usize {
    let at = buf.len();
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
    at
}

fn end_nested(buf: &mut [u8], at: usize) {
    let len = (buf.len() - at) as u16;
    buf[at..at + 2].copy_from_slice(&len.to_ne_bytes());
}

/// Zero-terminated ifname attribute payload.
fn ifname_z(name: &[u8; 16]) -> Vec<u8> {
    let n = name.iter().position(|&b| b == 0).unwrap_or(16);
    let mut v = name[..n].to_vec();
    v.push(0);
    v
}

/// Create the veth pair for sandbox `idx`, moving the peer end into the netns
/// of `container_pid` at creation. Returns 0 or a negative errno.
fn create_veth(idx: usize, container_pid: i32) -> i32 {
    let (host, cont) = ifnames(idx);

    let mut msg: Vec<u8> = Vec::with_capacity(256);
    // nlmsghdr placeholder — length patched at the end.
    msg.extend_from_slice(&[0u8; core::mem::size_of::<NlMsgHdr>()]);
    // ifinfomsg for the host end.
    let ifi = IfInfoMsg::default();
    // SAFETY: IfInfoMsg is #[repr(C)], fully initialized, and read as plain
    // bytes for exactly its own size.
    msg.extend_from_slice(unsafe {
        core::slice::from_raw_parts(
            (&ifi as *const IfInfoMsg) as *const u8,
            core::mem::size_of::<IfInfoMsg>(),
        )
    });
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(&host));
    let linkinfo = begin_nested(&mut msg, IFLA_LINKINFO);
    put_attr(&mut msg, IFLA_INFO_KIND, b"veth");
    let infodata = begin_nested(&mut msg, IFLA_INFO_DATA);
    let peer = begin_nested(&mut msg, VETH_INFO_PEER);
    // VETH_INFO_PEER payload = ifinfomsg + attrs for the peer.
    // SAFETY: same as above — repr(C) struct viewed as its own bytes.
    msg.extend_from_slice(unsafe {
        core::slice::from_raw_parts(
            (&ifi as *const IfInfoMsg) as *const u8,
            core::mem::size_of::<IfInfoMsg>(),
        )
    });
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(&cont));
    put_attr(
        &mut msg,
        IFLA_NET_NS_PID,
        &(container_pid as u32).to_ne_bytes(),
    );
    end_nested(&mut msg, peer);
    end_nested(&mut msg, infodata);
    end_nested(&mut msg, linkinfo);

    let hdr = NlMsgHdr {
        len: msg.len() as u32,
        ty: RTM_NEWLINK,
        flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq: 1,
        pid: 0,
    };
    // SAFETY: NlMsgHdr is #[repr(C)], fully initialized, viewed as its own
    // bytes to patch the message-length prefix in place.
    msg[..core::mem::size_of::<NlMsgHdr>()].copy_from_slice(unsafe {
        core::slice::from_raw_parts(
            (&hdr as *const NlMsgHdr) as *const u8,
            core::mem::size_of::<NlMsgHdr>(),
        )
    });

    // SAFETY: plain libc socket/send/recv/close on a locally-owned fd; the
    // message buffer outlives the send and resp is sized for the recv.
    // EINTR is retried; CLOEXEC keeps the fd out of any forked child.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        );
        if fd < 0 {
            return errno::ERROR;
        }
        loop {
            let rc = libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0);
            if rc >= 0 {
                break;
            }
            if *libc::__errno_location() == libc::EINTR {
                continue;
            }
            libc::close(fd);
            return errno::ERROR;
        }
        // Read the ACK (nlmsgerr: header + error i32).
        let mut resp = [0u8; 256];
        let n = loop {
            let n = libc::recv(fd, resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0);
            if n >= 0 || *libc::__errno_location() != libc::EINTR {
                break n;
            }
        };
        libc::close(fd);
        if n < (core::mem::size_of::<NlMsgHdr>() + 4) as isize {
            return errno::ERROR;
        }
        let ty = u16::from_ne_bytes([resp[4], resp[5]]);
        if ty != NLMSG_ERROR {
            return errno::ERROR;
        }
        let err = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
        if err != 0 {
            return err; // already a negative errno from the kernel
        }
    }
    0
}

// ---- ioctl-side configuration ----------------------------------------------

/// SIOCSIFFLAGS IFF_UP on `name` using `sock`. Returns 0 or -1.
unsafe fn if_up(sock: i32, name: &[u8; 16]) -> i32 {
    let mut req: libc::ifreq = core::mem::zeroed();
    for (i, b) in name.iter().enumerate() {
        req.ifr_name[i] = *b as libc::c_char;
    }
    if libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut req) != 0 {
        return -1;
    }
    req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
    if libc::ioctl(sock, libc::SIOCSIFFLAGS, &req) != 0 {
        return -1;
    }
    0
}

/// SIOCSIFADDR/SIOCSIFNETMASK on `name`. Returns 0 or -1.
unsafe fn if_set_v4(sock: i32, name: &[u8; 16], addr: [u8; 4], prefix_len: u8) -> i32 {
    let mut req: libc::ifreq = core::mem::zeroed();
    for (i, b) in name.iter().enumerate() {
        req.ifr_name[i] = *b as libc::c_char;
    }
    let sin = &mut req.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
    (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
    (*sin).sin_addr.s_addr = u32::from_ne_bytes(addr);
    if libc::ioctl(sock, libc::SIOCSIFADDR, &req) != 0 {
        return -1;
    }
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        !(u32::MAX >> prefix_len)
    };
    (*sin).sin_addr.s_addr = mask.to_be();
    if libc::ioctl(sock, libc::SIOCSIFNETMASK, &req) != 0 {
        return -1;
    }
    0
}

/// Configure the inside of the container's netns: bring `lo` up, and when an
/// identity is present, set it on the container veth end and bring that up.
/// Runs in a forked helper that `setns()`s into the container netns — the
/// platform thread's netns is never changed. Returns 0 or a negative errno.
fn configure_inside(idx: usize, container_pid: i32, ident: Option<&NetIdentity>) -> i32 {
    // Everything the child needs is materialized BEFORE the fork — same
    // no-alloc-in-the-child doctrine as `hp_child`: the child touches only
    // stack + libc between fork and _exit.
    let path = format!("/proc/{container_pid}/ns/net\0");
    let (_, cont) = ifnames(idx);
    // SAFETY: fork + setns run in a short-lived helper child that only makes
    // libc calls and _exits; the parent side only waitpids the helper. Called
    // from single-threaded platform dispatch, so no other thread's netns or
    // locks are affected.
    unsafe {
        let child = libc::fork();
        if child < 0 {
            return errno::ERROR;
        }
        if child == 0 {
            // Helper: join the container netns, configure, exit with a code.
            let fd = libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                libc::_exit(10);
            }
            if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                libc::_exit(11);
            }
            libc::close(fd);
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if sock < 0 {
                libc::_exit(12);
            }
            let mut lo = [0u8; 16];
            lo[..2].copy_from_slice(b"lo");
            if if_up(sock, &lo) != 0 {
                libc::_exit(13);
            }
            if let Some(id) = ident {
                if if_set_v4(sock, &cont, id.addr_v4, id.prefix_len) != 0 {
                    libc::_exit(14);
                }
                if if_up(sock, &cont) != 0 {
                    libc::_exit(15);
                }
            }
            libc::_exit(0);
        }
        // Parent: reap the helper.
        let mut status: libc::c_int = 0;
        loop {
            let r = libc::waitpid(child, &mut status, 0);
            if r == child {
                break;
            }
            if r < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            return errno::ERROR;
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            0
        } else {
            errno::ERROR
        }
    }
}

/// Wait until `container_pid` is actually in its own netns (its
/// `/proc/<pid>/ns/net` differs from ours). The child unshares NEWNET after
/// the fork, so the parent must not resolve the pid's netns (veth peer move,
/// setns helper) until the unshare has happened — otherwise the peer lands in
/// the HOST netns. Doubles as the fail-closed gate: if the child died (e.g.
/// unprivileged unshare EPERM) or never diverges, realization fails and so
/// does CREATE. Returns 0 or a negative errno.
fn wait_own_netns(container_pid: i32) -> i32 {
    // Our own netns link must be readable — without it divergence cannot be
    // verified, and an unverifiable gate must refuse, not wave through.
    let Ok(own) = std::fs::read_link("/proc/self/ns/net") else {
        return errno::ERROR;
    };
    let path = format!("/proc/{container_pid}/ns/net");
    // ~1 s ceiling: 2000 × 500 µs. The divergence normally lands in the first
    // few iterations; the ceiling only bounds the failure path.
    for _ in 0..2000 {
        match std::fs::read_link(&path) {
            Ok(theirs) => {
                if own != theirs {
                    return 0;
                }
            }
            // Child gone (died before/at unshare) — fail fast.
            Err(_) => return errno::ERROR,
        }
        // SAFETY: plain nanosleep with a valid stack timespec.
        unsafe {
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 500_000,
            };
            libc::nanosleep(&ts, core::ptr::null_mut());
        }
    }
    errno::ERROR
}

/// Realize the workload's network domain for sandbox `idx`: `lo` up inside the
/// container netns; with an identity also a veth pair (`fxw<idx>` host-side,
/// up, unattached; `fxc<idx>` container-side with the identity address, up).
/// Called by `hp_spawn` after the container pid is known and before START
/// releases the barrier, so the network exists before the workload runs.
/// Returns 0 or a negative errno — a failure fails CREATE (the network is
/// Tier-1; a workload must not run with silently-weaker networking).
pub fn realize(idx: usize, container_pid: i32, ident: Option<&NetIdentity>) -> i32 {
    // Synchronize with the child's unshare before resolving its netns by pid
    // — and refuse to proceed if the netns never materialized.
    let rc = wait_own_netns(container_pid);
    if rc != 0 {
        return rc;
    }
    if let Some(id) = ident {
        let rc = create_veth(idx, container_pid);
        if rc != 0 {
            return rc;
        }
        // Bring the host end up (host netns — plain ioctl here on the
        // platform thread is fine; no setns involved).
        // SAFETY: locally-owned AF_INET socket used for two ioctls and closed.
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if sock < 0 {
                return errno::ERROR;
            }
            let (host, _) = ifnames(idx);
            let rc = if_up(sock, &host);
            libc::close(sock);
            if rc != 0 {
                return errno::ERROR;
            }
        }
        return configure_inside(idx, container_pid, Some(id));
    }
    configure_inside(idx, container_pid, None)
}

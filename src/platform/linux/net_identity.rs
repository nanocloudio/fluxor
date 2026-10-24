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
// Division of labour (fluxor = mechanism, the orchestrator = policy):
//   * fluxor creates `fx<stem>w<idx>` (host end, brought up, its alias
//     `fluxor:<tag>`) and `fxc<idx>` (container end, identity address + up),
//     and brings `lo` up inside the netns. `<stem>`/`<tag>` are this
//     runtime's instance (`instance.rs`), so two runtimes on one host never
//     ask for the same host-side name; the container end is created directly
//     inside the workload's own netns, where nothing else lives, so its name
//     never meets another runtime's.
//   * Segment 0: the host end is left unattached — its plumbing is the
//     orchestrator's.
//   * Segment ≥ 1 (a `net.route` segment): the node-side attachment is
//     fluxor's realization of `net.route` (`net_route.rs`). Inside the
//     netns, by rtnetlink from the setns helper (the ioctl route API has no
//     on-link flag): `addr/32`, a permanent neighbour entry for the gateway
//     → the host end's MAC, `default via gateway onlink`, the segment MTU.
//     The host side (`net_route::attach`): the address routed to the host
//     end from the gateway in the instance's table, the guard, forwarding.
//   * The address allocation itself is the orchestrator's, never done here.
//
// Teardown: the veth pair dies with the netns, which dies with the
// container process, and the container dies with its runtime (parent
// death, `confine.rs`). Whatever link a dead runtime still left is deleted
// when the next instance on the host collects its tag: `reclaim_links`
// deletes every link carrying it. IPv4 only: a `NET_FAM_IPV6` request is
// refused at admission (`ENOSYS`) rather than half-realized.
//
// The container-side configuration runs in a short-lived forked helper that
// `setns()`s into the container's netns — never on the platform thread, whose
// netns must not change.

use crate::kernel::sys::errno;

/// The network identity from the `workload` CREATE header (family already
/// validated by the provider: only IPv4 reaches this module).
#[derive(Clone, Copy)]
pub struct NetIdentity {
    /// IPv4 address, network byte order as carried in the header.
    pub addr_v4: [u8; 4],
    /// Prefix length in bits (1..=32).
    pub prefix_len: u8,
    /// The `net.route` segment the workload attaches to (validated at
    /// CREATE), or `None` for segment 0.
    pub segment: Option<crate::abi::contracts::net::route::Segment>,
}

/// Interface names for a sandbox slot of instance `tag`: host end /
/// container end. `idx` is a `host_backend` sandbox slot index
/// (`< MAX_SANDBOXES`), so `fx<stem>w<idx>` stays inside the IFNAMSIZ
/// 15-byte limit; the assert keeps a larger slot table from silently
/// truncating or overflowing names.
fn ifnames(tag: &str, idx: usize) -> ([u8; 16], [u8; 16]) {
    debug_assert!(idx < super::host_backend::MAX_SANDBOXES);
    (
        ifname_buf(&super::instance::workload_link_name(tag, idx)),
        ifname_buf(&format!("fxc{idx}")),
    )
}

fn ifname_buf(s: &str) -> [u8; 16] {
    debug_assert!(s.len() <= 15); // IFNAMSIZ = 15 chars + NUL
    let mut b = [0u8; 16];
    for (d, c) in b.iter_mut().zip(s.bytes().take(15)) {
        *d = c;
    }
    b
}

// ---- minimal rtnetlink (no external deps) ----------------------------------

const NETLINK_ROUTE: i32 = 0;
pub(super) const RTM_NEWLINK: u16 = 16;
pub(super) const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
pub(super) const NLM_F_DUMP: u16 = 0x0300;
pub(super) const NLMSG_DONE: u16 = 0x0003;
pub(super) const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
pub(super) const NLM_F_EXCL: u16 = 0x0200;
pub(super) const NLM_F_CREATE: u16 = 0x0400;
pub(super) const NLMSG_ERROR: u16 = 0x0002;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_IFALIAS: u16 = 20;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFLA_NET_NS_PID: u16 = 19;
const NLA_F_NESTED: u16 = 0x8000;
pub(super) const NLM_F_REPLACE: u16 = 0x0100;
pub(super) const RTM_NEWADDR: u16 = 20;
pub(super) const RTM_DELADDR: u16 = 21;
pub(super) const RTM_NEWROUTE: u16 = 24;
pub(super) const RTM_DELROUTE: u16 = 25;
pub(super) const RTM_GETROUTE: u16 = 26;
pub(super) const RTM_NEWNEIGH: u16 = 28;
pub(super) const RTM_NEWRULE: u16 = 32;
pub(super) const RTM_DELRULE: u16 = 33;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const FRA_PRIORITY: u16 = 6;
const FRA_TABLE: u16 = 15;
const NUD_PERMANENT: u16 = 0x80;
const RTNH_F_ONLINK: u32 = 4;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;
const FR_ACT_TO_TBL: u8 = 1;
const RT_TABLE_MAIN: u32 = 254;
/// Where an interface index sits in a link, address or neighbour message
/// (header, then the family header's index field at offset 4).
pub(super) const INDEX_AT: usize = 16 + 4;
/// Where the interface index sits in a route message built with
/// [`msg_route`]: `RTA_OIF` is its first attribute.
pub(super) const ROUTE_OIF_AT: usize = 16 + 12 + 4;

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
pub(super) fn put_attr(buf: &mut Vec<u8>, ty: u16, data: &[u8]) {
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

/// `ifi` viewed as its bytes.
fn ifinfo_bytes(ifi: &IfInfoMsg) -> &[u8] {
    // SAFETY: IfInfoMsg is #[repr(C)], fully initialized, and read as plain
    // bytes for exactly its own size.
    unsafe {
        core::slice::from_raw_parts(
            (ifi as *const IfInfoMsg) as *const u8,
            core::mem::size_of::<IfInfoMsg>(),
        )
    }
}

/// A message buffer: the header placeholder, then `ifi`.
fn nl_begin(ifi: &IfInfoMsg) -> Vec<u8> {
    let mut msg: Vec<u8> = Vec::with_capacity(256);
    msg.extend_from_slice(&[0u8; core::mem::size_of::<NlMsgHdr>()]);
    msg.extend_from_slice(ifinfo_bytes(ifi));
    msg
}

/// A message buffer: the header placeholder, then `fixed` (the family's
/// fixed header: `ifaddrmsg`, `rtmsg`, `ndmsg`, `fib_rule_hdr`).
pub(super) fn nl_begin_raw(fixed: &[u8]) -> Vec<u8> {
    let mut msg: Vec<u8> = Vec::with_capacity(256);
    msg.extend_from_slice(&[0u8; core::mem::size_of::<NlMsgHdr>()]);
    msg.extend_from_slice(fixed);
    msg
}

/// Patch the header of `msg` (from `nl_begin`) for `ty`/`flags`.
fn nl_finish(msg: &mut [u8], ty: u16, flags: u16) {
    let hdr = NlMsgHdr {
        len: msg.len() as u32,
        ty,
        flags,
        seq: 1,
        pid: 0,
    };
    // SAFETY: NlMsgHdr is #[repr(C)], fully initialized, viewed as its own
    // bytes to patch the message-length prefix in place.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&hdr as *const NlMsgHdr) as *const u8,
            core::mem::size_of::<NlMsgHdr>(),
        )
    };
    for (d, s) in msg.iter_mut().zip(bytes) {
        *d = *s;
    }
}

/// An rtnetlink socket, or a negative errno.
pub(super) fn nl_socket() -> Result<i32, i32> {
    // SAFETY: plain libc socket call; CLOEXEC keeps the fd out of any child.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        Err(errno::ERROR)
    } else {
        Ok(fd)
    }
}

/// Send `msg` on `fd`, retrying EINTR.
pub(super) fn nl_send(fd: i32, msg: &[u8]) -> Result<(), i32> {
    loop {
        // SAFETY: `msg` outlives the call; `fd` is a live netlink socket.
        let rc = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if rc >= 0 {
            return Ok(());
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(errno::ERROR);
        }
    }
}

/// Receive one datagram into `buf`, retrying EINTR.
pub(super) fn nl_recv(fd: i32, buf: &mut [u8]) -> isize {
    loop {
        // SAFETY: `buf` is a live, writable buffer of its own length.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return n;
        }
    }
}

/// Send one request and read its ACK. Returns 0 or a negative errno (the
/// kernel's own, when it refused). Allocation-free: a forked helper calls it
/// on messages built before the fork.
pub(super) fn nl_request(msg: &mut [u8], ty: u16, flags: u16) -> i32 {
    nl_finish(msg, ty, flags | NLM_F_REQUEST | NLM_F_ACK);
    let fd = match nl_socket() {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let mut resp = [0u8; 256];
    let n = match nl_send(fd, msg) {
        Ok(()) => nl_recv(fd, &mut resp),
        Err(e) => {
            // SAFETY: closing the socket opened above.
            unsafe { libc::close(fd) };
            return e;
        }
    };
    // SAFETY: closing the socket opened above.
    unsafe { libc::close(fd) };
    if n < (core::mem::size_of::<NlMsgHdr>() + 4) as isize {
        return errno::ERROR;
    }
    let ty = u16::from_ne_bytes([resp[4], resp[5]]);
    if ty != NLMSG_ERROR {
        return errno::ERROR;
    }
    // Already a negative errno from the kernel, or 0.
    i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]])
}

// ---- rtnetlink messages (shared with `net_route.rs`) -------------------------

fn table_byte(table: u32) -> u8 {
    if table < 256 {
        table as u8
    } else {
        0
    }
}

/// `addr/prefix_len` on link `index`.
pub(super) fn msg_addr(index: i32, addr: [u8; 4], prefix_len: u8) -> Vec<u8> {
    let mut fixed = [0u8; 8];
    fixed[0] = libc::AF_INET as u8;
    fixed[1] = prefix_len;
    fixed[4..8].copy_from_slice(&(index as u32).to_ne_bytes());
    let mut m = nl_begin_raw(&fixed);
    put_attr(&mut m, IFA_LOCAL, &addr);
    put_attr(&mut m, IFA_ADDRESS, &addr);
    m
}

/// A route in `table`: `dst/dst_len`, out `oif` (first, at
/// [`ROUTE_OIF_AT`]; 0 for none), via `gateway`, from `prefsrc`, with the
/// on-link flag when asked.
pub(super) fn msg_route(
    table: u32,
    dst: [u8; 4],
    dst_len: u8,
    oif: i32,
    gateway: Option<[u8; 4]>,
    prefsrc: Option<[u8; 4]>,
    onlink: bool,
) -> Vec<u8> {
    let mut fixed = [0u8; 12];
    fixed[0] = libc::AF_INET as u8;
    fixed[1] = dst_len;
    fixed[4] = table_byte(table);
    fixed[5] = RTPROT_STATIC;
    fixed[6] = if gateway.is_some() {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    fixed[7] = RTN_UNICAST;
    let flags = if onlink { RTNH_F_ONLINK } else { 0 };
    fixed[8..12].copy_from_slice(&flags.to_ne_bytes());
    let mut m = nl_begin_raw(&fixed);
    put_attr(&mut m, RTA_OIF, &(oif as u32).to_ne_bytes());
    put_attr(&mut m, RTA_TABLE, &table.to_ne_bytes());
    if dst_len > 0 {
        put_attr(&mut m, RTA_DST, &dst);
    }
    if let Some(g) = gateway {
        put_attr(&mut m, RTA_GATEWAY, &g);
    }
    if let Some(p) = prefsrc {
        put_attr(&mut m, RTA_PREFSRC, &p);
    }
    m
}

/// A route's identity for deletion: `dst/dst_len` in `table`.
pub(super) fn msg_route_key(table: u32, dst: [u8; 4], dst_len: u8) -> Vec<u8> {
    let mut fixed = [0u8; 12];
    fixed[0] = libc::AF_INET as u8;
    fixed[1] = dst_len;
    fixed[4] = table_byte(table);
    let mut m = nl_begin_raw(&fixed);
    put_attr(&mut m, RTA_TABLE, &table.to_ne_bytes());
    if dst_len > 0 {
        put_attr(&mut m, RTA_DST, &dst);
    }
    m
}

/// A permanent neighbour entry `addr → mac` on link `index`.
pub(super) fn msg_neigh(index: i32, addr: [u8; 4], mac: [u8; 6]) -> Vec<u8> {
    let mut fixed = [0u8; 12];
    fixed[0] = libc::AF_INET as u8;
    fixed[4..8].copy_from_slice(&index.to_ne_bytes());
    fixed[8..10].copy_from_slice(&NUD_PERMANENT.to_ne_bytes());
    let mut m = nl_begin_raw(&fixed);
    put_attr(&mut m, NDA_DST, &addr);
    put_attr(&mut m, NDA_LLADDR, &mac);
    m
}

/// Link `index` up, with `mtu` when given.
pub(super) fn msg_link_up(index: i32, mtu: Option<u32>) -> Vec<u8> {
    let ifi = IfInfoMsg {
        index,
        flags: libc::IFF_UP as u32,
        change: libc::IFF_UP as u32,
        ..IfInfoMsg::default()
    };
    let mut m = nl_begin(&ifi);
    if let Some(mtu) = mtu {
        put_attr(&mut m, IFLA_MTU, &mtu.to_ne_bytes());
    }
    m
}

/// The rule `from all lookup table` at `priority`.
pub(super) fn msg_rule(table: u32, priority: u32) -> Vec<u8> {
    let mut fixed = [0u8; 12];
    fixed[0] = libc::AF_INET as u8;
    fixed[4] = table_byte(table);
    fixed[7] = FR_ACT_TO_TBL;
    let mut m = nl_begin_raw(&fixed);
    put_attr(&mut m, FRA_TABLE, &table.to_ne_bytes());
    put_attr(&mut m, FRA_PRIORITY, &priority.to_ne_bytes());
    m
}

/// Create link `name` of `kind` (a dummy) in this network domain.
pub(super) fn create_kind(name: &str, kind: &[u8]) -> i32 {
    let mut msg = nl_begin(&IfInfoMsg::default());
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(&ifname_buf(name)));
    let linkinfo = begin_nested(&mut msg, IFLA_LINKINFO);
    put_attr(&mut msg, IFLA_INFO_KIND, kind);
    end_nested(&mut msg, linkinfo);
    nl_request(&mut msg, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
}

/// Create the veth pair `a`/`b`, both in this network domain.
pub(super) fn create_veth_pair(a: &str, b: &str) -> i32 {
    let ifi = IfInfoMsg::default();
    let mut msg = nl_begin(&ifi);
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(&ifname_buf(a)));
    let linkinfo = begin_nested(&mut msg, IFLA_LINKINFO);
    put_attr(&mut msg, IFLA_INFO_KIND, b"veth");
    let infodata = begin_nested(&mut msg, IFLA_INFO_DATA);
    let peer = begin_nested(&mut msg, VETH_INFO_PEER);
    msg.extend_from_slice(ifinfo_bytes(&ifi));
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(&ifname_buf(b)));
    end_nested(&mut msg, peer);
    end_nested(&mut msg, infodata);
    end_nested(&mut msg, linkinfo);
    nl_request(&mut msg, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
}

/// Set link `name`'s alias.
pub(super) fn alias_link(name: &str, alias: &str) -> i32 {
    set_alias(&ifname_buf(name), alias)
}

/// Delete link `name`; gone already counts as deleted.
pub(super) fn delete_link(name: &str) -> i32 {
    del_link_named(&ifname_buf(name))
}

/// Walk the netlink messages in one datagram: `f(type, message)`. `true`
/// once the datagram ends a dump; `Err` on a kernel error.
pub(super) fn walk_messages(buf: &[u8], mut f: impl FnMut(u16, &[u8])) -> Result<bool, i32> {
    let hdr = core::mem::size_of::<NlMsgHdr>();
    let mut at = 0usize;
    while at + hdr <= buf.len() {
        let h = buf.get(at..at + hdr).ok_or(errno::ERROR)?;
        let len = u32::from_ne_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let ty = u16::from_ne_bytes([h[4], h[5]]);
        if len < hdr || at + len > buf.len() {
            return Err(errno::ERROR);
        }
        match ty {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let code = buf
                    .get(at + hdr..at + hdr + 4)
                    .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
                    .unwrap_or(errno::ERROR);
                if code != 0 {
                    return Err(code);
                }
                return Ok(true);
            }
            _ => f(ty, buf.get(at..at + len).unwrap_or(&[])),
        }
        at += (len + 3) & !3;
    }
    Ok(false)
}

/// Walk the attributes of message `m` from `start`: `f(type, payload)`.
pub(super) fn walk_attrs(m: &[u8], start: usize, mut f: impl FnMut(u16, &[u8])) {
    let mut a = start;
    while a + 4 <= m.len() {
        let alen = u16::from_ne_bytes([m[a], m[a + 1]]) as usize;
        let aty = u16::from_ne_bytes([m[a + 2], m[a + 3]]) & !NLA_F_NESTED;
        if alen < 4 || a + alen > m.len() {
            break;
        }
        f(aty, m.get(a + 4..a + alen).unwrap_or(&[]));
        a += (alen + 3) & !3;
    }
}

/// One IPv4 route of a dump.
pub(super) struct RouteInfo {
    pub table: u32,
    pub dst: [u8; 4],
    pub dst_len: u8,
    pub oif: Option<i32>,
    pub kind: u8,
}

fn route_info(m: &[u8]) -> Option<RouteInfo> {
    let hdr = core::mem::size_of::<NlMsgHdr>();
    let r = m.get(hdr..hdr + 12)?;
    if r[0] != libc::AF_INET as u8 {
        return None;
    }
    let mut info = RouteInfo {
        table: r[4] as u32,
        dst: [0; 4],
        dst_len: r[1],
        oif: None,
        kind: r[7],
    };
    walk_attrs(m, hdr + 12, |ty, d| match ty {
        RTA_TABLE if d.len() == 4 => info.table = u32::from_ne_bytes([d[0], d[1], d[2], d[3]]),
        RTA_DST if d.len() == 4 => info.dst = [d[0], d[1], d[2], d[3]],
        RTA_OIF if d.len() == 4 => info.oif = Some(i32::from_ne_bytes([d[0], d[1], d[2], d[3]])),
        _ => {}
    });
    Some(info)
}

/// Every IPv4 route of every table.
pub(super) fn routes() -> Result<Vec<RouteInfo>, i32> {
    let mut fixed = [0u8; 12];
    fixed[0] = libc::AF_INET as u8;
    let mut msg = nl_begin_raw(&fixed);
    nl_finish(&mut msg, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP);
    let fd = nl_socket()?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    let result = (|| {
        nl_send(fd, &msg)?;
        loop {
            let n = nl_recv(fd, &mut buf);
            if n <= 0 {
                return Err(errno::ERROR);
            }
            let done = walk_messages(buf.get(..n as usize).unwrap_or(&[]), |ty, m| {
                if ty == RTM_NEWROUTE {
                    if let Some(r) = route_info(m) {
                        out.push(r);
                    }
                }
            })?;
            if done {
                return Ok(());
            }
        }
    })();
    // SAFETY: closing the socket opened above.
    unsafe { libc::close(fd) };
    result.map(|()| out)
}

/// The interfaces the main table's default routes leave by.
pub(super) fn default_route_links() -> Vec<i32> {
    routes()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.table == RT_TABLE_MAIN && r.dst_len == 0 && r.kind == RTN_UNICAST)
        .filter_map(|r| r.oif)
        .collect()
}

/// The interface the host would send traffic for `dst` out of.
pub(super) fn route_oif(dst: [u8; 4]) -> Option<i32> {
    let mut fixed = [0u8; 12];
    fixed[0] = libc::AF_INET as u8;
    fixed[1] = 32;
    let mut msg = nl_begin_raw(&fixed);
    put_attr(&mut msg, RTA_DST, &dst);
    nl_finish(&mut msg, RTM_GETROUTE, NLM_F_REQUEST);
    let fd = nl_socket().ok()?;
    let mut buf = [0u8; 4096];
    let mut oif = None;
    if nl_send(fd, &msg).is_ok() {
        let n = nl_recv(fd, &mut buf);
        if n > 0 {
            let _ = walk_messages(buf.get(..n as usize).unwrap_or(&[]), |ty, m| {
                if ty == RTM_NEWROUTE {
                    oif = route_info(m).and_then(|r| r.oif);
                }
            });
        }
    }
    // SAFETY: closing the socket opened above.
    unsafe { libc::close(fd) };
    oif
}

/// Create the veth pair `host`/`cont`, moving the peer end into the netns
/// of `container_pid` at creation. Returns 0 or a negative errno.
fn create_veth(host: &[u8; 16], cont: &[u8; 16], container_pid: i32) -> i32 {
    let ifi = IfInfoMsg::default();
    let mut msg = nl_begin(&ifi);
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(host));
    let linkinfo = begin_nested(&mut msg, IFLA_LINKINFO);
    put_attr(&mut msg, IFLA_INFO_KIND, b"veth");
    let infodata = begin_nested(&mut msg, IFLA_INFO_DATA);
    let peer = begin_nested(&mut msg, VETH_INFO_PEER);
    // VETH_INFO_PEER payload = ifinfomsg + attrs for the peer.
    msg.extend_from_slice(ifinfo_bytes(&ifi));
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(cont));
    put_attr(
        &mut msg,
        IFLA_NET_NS_PID,
        &(container_pid as u32).to_ne_bytes(),
    );
    end_nested(&mut msg, peer);
    end_nested(&mut msg, infodata);
    end_nested(&mut msg, linkinfo);
    nl_request(&mut msg, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
}

/// Set the alias of link `name` (the kernel does not take an alias at
/// creation). Returns 0 or a negative errno.
fn set_alias(name: &[u8; 16], alias: &str) -> i32 {
    let mut msg = nl_begin(&IfInfoMsg::default());
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(name));
    let mut a = alias.as_bytes().to_vec();
    a.push(0);
    put_attr(&mut msg, IFLA_IFALIAS, &a);
    nl_request(&mut msg, RTM_NEWLINK, 0)
}

/// Delete link `index`. A link already gone counts as deleted.
fn del_link(index: i32) -> i32 {
    let ifi = IfInfoMsg {
        index,
        ..IfInfoMsg::default()
    };
    let mut msg = nl_begin(&ifi);
    let rc = nl_request(&mut msg, RTM_DELLINK, 0);
    if rc == -libc::ENODEV {
        0
    } else {
        rc
    }
}

/// Delete link `name`. A link already gone counts as deleted.
fn del_link_named(name: &[u8; 16]) -> i32 {
    let mut msg = nl_begin(&IfInfoMsg::default());
    put_attr(&mut msg, IFLA_IFNAME, &ifname_z(name));
    let rc = nl_request(&mut msg, RTM_DELLINK, 0);
    if rc == -libc::ENODEV {
        0
    } else {
        rc
    }
}

/// One link of the host's network domain.
pub struct LinkInfo {
    pub index: i32,
    pub name: String,
    pub alias: Option<String>,
    /// Its hardware address, when it has a 6-byte one.
    pub mac: Option<[u8; 6]>,
}

/// A NUL-terminated attribute payload as a string.
fn attr_str(b: &[u8]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..n]).into_owned()
}

/// Parse the links out of one dump datagram; `true` once the dump is done.
fn parse_links(buf: &[u8], out: &mut Vec<LinkInfo>) -> Result<bool, i32> {
    let hdr = core::mem::size_of::<NlMsgHdr>();
    let ifi = core::mem::size_of::<IfInfoMsg>();
    let mut at = 0usize;
    while at + hdr <= buf.len() {
        let h = buf.get(at..at + hdr).ok_or(errno::ERROR)?;
        let len = u32::from_ne_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let ty = u16::from_ne_bytes([h[4], h[5]]);
        if len < hdr || at + len > buf.len() {
            return Err(errno::ERROR);
        }
        match ty {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => return Err(errno::ERROR),
            RTM_NEWLINK if len >= hdr + ifi => {
                let m = buf.get(at..at + len).ok_or(errno::ERROR)?;
                let index = i32::from_ne_bytes([m[hdr + 4], m[hdr + 5], m[hdr + 6], m[hdr + 7]]);
                let mut link = LinkInfo {
                    index,
                    name: String::new(),
                    alias: None,
                    mac: None,
                };
                let mut a = hdr + ifi;
                while a + 4 <= len {
                    let alen = u16::from_ne_bytes([m[a], m[a + 1]]) as usize;
                    let aty = u16::from_ne_bytes([m[a + 2], m[a + 3]]) & !NLA_F_NESTED;
                    if alen < 4 || a + alen > len {
                        break;
                    }
                    let data = m.get(a + 4..a + alen).unwrap_or(&[]);
                    match aty {
                        IFLA_IFNAME => link.name = attr_str(data),
                        IFLA_ADDRESS if data.len() == 6 => {
                            let mut m = [0u8; 6];
                            for (d, b) in m.iter_mut().zip(data) {
                                *d = *b;
                            }
                            link.mac = Some(m);
                        }
                        IFLA_IFALIAS => {
                            let s = attr_str(data);
                            if !s.is_empty() {
                                link.alias = Some(s);
                            }
                        }
                        _ => {}
                    }
                    a += (alen + 3) & !3;
                }
                out.push(link);
            }
            _ => {}
        }
        at += (len + 3) & !3;
    }
    Ok(false)
}

/// Every link in this process's network domain, with its alias.
pub fn links() -> Result<Vec<LinkInfo>, i32> {
    let mut msg = nl_begin(&IfInfoMsg::default());
    nl_finish(&mut msg, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
    let fd = nl_socket()?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    let result = (|| {
        nl_send(fd, &msg)?;
        loop {
            let n = nl_recv(fd, &mut buf);
            if n <= 0 {
                return Err(errno::ERROR);
            }
            if parse_links(buf.get(..n as usize).unwrap_or(&[]), &mut out)? {
                return Ok(());
            }
        }
    })();
    // SAFETY: closing the socket opened above.
    unsafe { libc::close(fd) };
    result.map(|()| out)
}

/// Reclaim hook (`instance::RECLAIMERS`): delete every host link the tag
/// left — by alias, and, when the context allows it, a link that lost its
/// alias (created, then the runtime died before naming it) by its name.
pub fn reclaim_links(ctx: &super::instance::ReclaimCtx<'_>) -> Result<(), i32> {
    let stem = super::instance::stem(ctx.tag);
    let mut result = Ok(());
    for l in links()? {
        let ours = match &l.alias {
            Some(a) => super::instance::alias_tag(a) == Some(ctx.tag),
            None => ctx.by_name && super::instance::is_link_name_of(&l.name, stem),
        };
        if !ours {
            continue;
        }
        let rc = del_link(l.index);
        if rc != 0 {
            log::warn!(
                "[net_identity] cannot delete link {} of tag {}: {rc}",
                l.name,
                ctx.tag
            );
            result = Err(rc);
        }
    }
    result
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
fn configure_inside(cont: [u8; 16], container_pid: i32, ident: Option<&NetIdentity>) -> i32 {
    // Everything the child needs is materialized BEFORE the fork — same
    // no-alloc-in-the-child doctrine as `hp_child`: the child touches only
    // stack + libc between fork and _exit.
    let path = format!("/proc/{container_pid}/ns/net\0");
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

/// Configure the inside of the container's netns for a segment attachment:
/// `lo` up; the container end up at the segment MTU, holding `addr/32`; a
/// permanent neighbour entry for the gateway → the host end's MAC; and the
/// default route via the gateway, on-link. By rtnetlink from a forked helper
/// that `setns()`s into the netns — the ioctl route API has no on-link flag.
/// Returns 0 or a negative errno.
fn configure_inside_attached(
    cont: [u8; 16],
    container_pid: i32,
    addr: [u8; 4],
    seg: &crate::abi::contracts::net::route::Segment,
    host_mac: [u8; 6],
) -> i32 {
    let mut gw = [0u8; 4];
    gw.copy_from_slice(&seg.gateway[..4]);
    let mtu = (seg.mtu != 0).then_some(seg.mtu as u32);
    // Built before the fork with index 0; the helper writes the container
    // end's index (known only inside the netns) into each in place.
    let mut link = msg_link_up(0, mtu);
    let mut address = msg_addr(0, addr, 32);
    let mut neigh = msg_neigh(0, gw, host_mac);
    let mut route = msg_route(RT_TABLE_MAIN, [0; 4], 0, 0, Some(gw), None, true);
    let path = format!("/proc/{container_pid}/ns/net\0");
    // SAFETY: as `configure_inside` — the helper child touches only its stack,
    // the messages built above (its own copy-on-write pages) and libc, then
    // _exits; the parent only waitpids it.
    unsafe {
        let child = libc::fork();
        if child < 0 {
            return errno::ERROR;
        }
        if child == 0 {
            let fd = libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                libc::_exit(20);
            }
            if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                libc::_exit(21);
            }
            libc::close(fd);
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if sock < 0 {
                libc::_exit(22);
            }
            let mut lo = [0u8; 16];
            lo[..2].copy_from_slice(b"lo");
            if if_up(sock, &lo) != 0 {
                libc::_exit(23);
            }
            libc::close(sock);
            let index = libc::if_nametoindex(cont.as_ptr() as *const libc::c_char);
            if index == 0 {
                libc::_exit(24);
            }
            let ib = index.to_ne_bytes();
            link[INDEX_AT..INDEX_AT + 4].copy_from_slice(&ib);
            address[INDEX_AT..INDEX_AT + 4].copy_from_slice(&ib);
            neigh[INDEX_AT..INDEX_AT + 4].copy_from_slice(&ib);
            route[ROUTE_OIF_AT..ROUTE_OIF_AT + 4].copy_from_slice(&ib);
            if nl_request(&mut link, RTM_NEWLINK, 0) != 0 {
                libc::_exit(25);
            }
            if nl_request(&mut address, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL) != 0 {
                libc::_exit(26);
            }
            if nl_request(&mut neigh, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE) != 0 {
                libc::_exit(27);
            }
            if nl_request(&mut route, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL) != 0 {
                libc::_exit(28);
            }
            libc::_exit(0);
        }
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
            log::warn!(
                "[net_identity] attaching the inside of the workload's domain failed (helper status {})",
                libc::WEXITSTATUS(status)
            );
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

/// The address each sandbox's workload was given, by sandbox index, kept for
/// its teardown.
static ADDRESSES: std::sync::Mutex<Vec<(usize, [u8; 4])>> = std::sync::Mutex::new(Vec::new());

/// Sandbox `idx`'s workload is destroyed: its address leaves the node. Its
/// connection state is discarded (`net_policy`), and a segment attachment
/// leaves the guard (`net_route`). The link and its routes go with the
/// workload's domain. A sandbox that held no address does nothing.
pub fn released(idx: usize) {
    let addr = {
        let mut a = ADDRESSES.lock().unwrap_or_else(|e| e.into_inner());
        let found = a.iter().position(|(i, _)| *i == idx).map(|p| a.remove(p).1);
        found
    };
    let Some(addr) = addr else { return };
    super::net_policy::discard_address_flows(addr);
    super::net_route::detach(addr);
}

fn remember(idx: usize, addr: [u8; 4]) {
    let mut a = ADDRESSES.lock().unwrap_or_else(|e| e.into_inner());
    a.retain(|(i, _)| *i != idx);
    a.push((idx, addr));
}

/// Realize the workload's network domain for sandbox `idx`: `lo` up inside the
/// container netns; with an identity also a veth pair (`fx<stem>w<idx>`
/// host-side, aliased with this instance's tag, up, unattached; `fxc<idx>`
/// container-side with the identity address, up). Called by `hp_spawn`
/// after the container pid is known and before START releases the barrier,
/// so the network exists before the workload runs. Returns 0 or a negative
/// errno — a failure fails CREATE (the network is Tier-1; a workload must
/// not run with silently-weaker networking). A host-side link needs this
/// runtime live in the host registry: one made under a tag that is not live
/// would be collected by the next instance to start.
pub fn realize(idx: usize, container_pid: i32, ident: Option<&NetIdentity>) -> i32 {
    // Synchronize with the child's unshare before resolving its netns by pid
    // — and refuse to proceed if the netns never materialized.
    let rc = wait_own_netns(container_pid);
    if rc != 0 {
        return rc;
    }
    let Some(id) = ident else {
        return configure_inside(ifname_buf("fxc"), container_pid, None);
    };
    let tag = match super::instance::live_tag() {
        Ok(t) => t,
        Err(e) => {
            log::warn!("[net_identity] not live in the host registry ({e}); refusing the link");
            return e;
        }
    };
    let (host, cont) = ifnames(&tag, idx);
    let rc = create_veth(&host, &cont, container_pid);
    if rc != 0 {
        return rc;
    }
    let rc = set_alias(&host, &super::instance::link_alias(&tag));
    if rc != 0 {
        del_link_named(&host);
        return rc;
    }
    // Bring the host end up (host netns — plain ioctl here on the
    // platform thread is fine; no setns involved).
    // SAFETY: locally-owned AF_INET socket used for two ioctls and closed.
    let up = unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            errno::ERROR
        } else {
            let rc = if_up(sock, &host);
            libc::close(sock);
            if rc != 0 {
                errno::ERROR
            } else {
                0
            }
        }
    };
    if up != 0 {
        del_link_named(&host);
        return up;
    }
    let Some(seg) = id.segment.as_ref() else {
        let rc = configure_inside(cont, container_pid, Some(id));
        if rc == 0 {
            remember(idx, id.addr_v4);
        }
        return rc;
    };
    // A segment attachment: the inside by rtnetlink, then the node side.
    let host_name = super::instance::workload_link_name(&tag, idx);
    let Some(l) = links()
        .ok()
        .and_then(|ls| ls.into_iter().find(|l| l.name == host_name))
    else {
        del_link_named(&host);
        return errno::ERROR;
    };
    let Some(mac) = l.mac else {
        del_link_named(&host);
        return errno::ERROR;
    };
    let rc = configure_inside_attached(cont, container_pid, id.addr_v4, seg, mac);
    if rc != 0 {
        del_link_named(&host);
        return rc;
    }
    let rc = super::net_route::attach(&host_name, l.index, id.addr_v4, seg);
    if rc != 0 {
        del_link_named(&host);
    } else {
        remember(idx, id.addr_v4);
    }
    rc
}

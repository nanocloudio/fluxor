//! Minimal rtnetlink, no external dependencies: the messages this provider
//! sends to the host's network domain (links, addresses, routes, neighbour
//! entries, rules), and the same requests on a socket the runtime opened
//! inside a workload owner's network domain ([`request_on`]), which is how
//! the provider configures a domain it never enters.

use fluxor_abi::errno;

const NETLINK_ROUTE: i32 = 0;
pub(crate) const RTM_NEWLINK: u16 = 16;
pub(crate) const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
pub(crate) const NLM_F_DUMP: u16 = 0x0300;
pub(crate) const NLMSG_DONE: u16 = 0x0003;
pub(crate) const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
pub(crate) const NLM_F_EXCL: u16 = 0x0200;
pub(crate) const NLM_F_CREATE: u16 = 0x0400;
pub(crate) const NLMSG_ERROR: u16 = 0x0002;

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
pub(crate) const NLM_F_REPLACE: u16 = 0x0100;
pub(crate) const RTM_NEWADDR: u16 = 20;
pub(crate) const RTM_DELADDR: u16 = 21;
pub(crate) const RTM_NEWROUTE: u16 = 24;
pub(crate) const RTM_DELROUTE: u16 = 25;
pub(crate) const RTM_GETROUTE: u16 = 26;
pub(crate) const RTM_NEWNEIGH: u16 = 28;
pub(crate) const RTM_NEWRULE: u16 = 32;
pub(crate) const RTM_DELRULE: u16 = 33;
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
pub(crate) const RT_TABLE_MAIN: u32 = 254;

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
pub(crate) fn put_attr(buf: &mut Vec<u8>, ty: u16, data: &[u8]) {
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
pub(crate) fn nl_begin_raw(fixed: &[u8]) -> Vec<u8> {
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
pub(crate) fn nl_socket() -> Result<i32, i32> {
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
pub(crate) fn nl_send(fd: i32, msg: &[u8]) -> Result<(), i32> {
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
pub(crate) fn nl_recv(fd: i32, buf: &mut [u8]) -> isize {
    loop {
        // SAFETY: `buf` is a live, writable buffer of its own length.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return n;
        }
    }
}

/// Send one request on a socket of its own and read its ACK. Returns 0 or
/// a negative errno (the kernel's own, when it refused).
pub(crate) fn nl_request(msg: &mut [u8], ty: u16, flags: u16) -> i32 {
    let fd = match nl_socket() {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let rc = request_on(fd, msg, ty, flags);
    // SAFETY: closing the socket opened above.
    unsafe { libc::close(fd) };
    rc
}

/// Send one request on `fd` (a `NETLINK_ROUTE` socket, perhaps one the
/// runtime opened inside a workload owner's network domain) and read its
/// ACK. Returns 0 or a negative errno.
pub fn request_on(fd: i32, msg: &mut [u8], ty: u16, flags: u16) -> i32 {
    nl_finish(msg, ty, flags | NLM_F_REQUEST | NLM_F_ACK);
    let mut resp = [0u8; 256];
    let n = match nl_send(fd, msg) {
        Ok(()) => nl_recv(fd, &mut resp),
        Err(e) => return e,
    };
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
pub(crate) fn msg_addr(index: i32, addr: [u8; 4], prefix_len: u8) -> Vec<u8> {
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
pub(crate) fn msg_route(
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
pub(crate) fn msg_route_key(table: u32, dst: [u8; 4], dst_len: u8) -> Vec<u8> {
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
pub(crate) fn msg_neigh(index: i32, addr: [u8; 4], mac: [u8; 6]) -> Vec<u8> {
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
pub(crate) fn msg_link_up(index: i32, mtu: Option<u32>) -> Vec<u8> {
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
pub(crate) fn msg_rule(table: u32, priority: u32) -> Vec<u8> {
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
pub(crate) fn create_kind(name: &str, kind: &[u8]) -> i32 {
    let mut msg = nl_begin(&IfInfoMsg::default());
    put_attr(&mut msg, IFLA_IFNAME, &name_z(name));
    let linkinfo = begin_nested(&mut msg, IFLA_LINKINFO);
    put_attr(&mut msg, IFLA_INFO_KIND, kind);
    end_nested(&mut msg, linkinfo);
    nl_request(&mut msg, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
}

/// Create the veth pair `a`/`b`, both in this network domain.
pub(crate) fn create_veth_pair(a: &str, b: &str) -> i32 {
    let ifi = IfInfoMsg::default();
    let mut msg = nl_begin(&ifi);
    put_attr(&mut msg, IFLA_IFNAME, &name_z(a));
    let linkinfo = begin_nested(&mut msg, IFLA_LINKINFO);
    put_attr(&mut msg, IFLA_INFO_KIND, b"veth");
    let infodata = begin_nested(&mut msg, IFLA_INFO_DATA);
    let peer = begin_nested(&mut msg, VETH_INFO_PEER);
    msg.extend_from_slice(ifinfo_bytes(&ifi));
    put_attr(&mut msg, IFLA_IFNAME, &name_z(b));
    end_nested(&mut msg, peer);
    end_nested(&mut msg, infodata);
    end_nested(&mut msg, linkinfo);
    nl_request(&mut msg, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
}

/// Set link `name`'s alias.
pub(crate) fn alias_link(name: &str, alias: &str) -> i32 {
    set_alias(name, alias)
}

/// Delete link `name`; gone already counts as deleted.
pub(crate) fn delete_link(name: &str) -> i32 {
    del_link_named(name)
}

/// Walk the netlink messages in one datagram: `f(type, message)`. `true`
/// once the datagram ends a dump; `Err` on a kernel error.
pub(crate) fn walk_messages(buf: &[u8], mut f: impl FnMut(u16, &[u8])) -> Result<bool, i32> {
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
pub(crate) fn walk_attrs(m: &[u8], start: usize, mut f: impl FnMut(u16, &[u8])) {
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
pub(crate) struct RouteInfo {
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
pub(crate) fn routes() -> Result<Vec<RouteInfo>, i32> {
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
pub(crate) fn default_route_links() -> Vec<i32> {
    routes()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.table == RT_TABLE_MAIN && r.dst_len == 0 && r.kind == RTN_UNICAST)
        .filter_map(|r| r.oif)
        .collect()
}

/// The interface the host would send traffic for `dst` out of.
pub(crate) fn route_oif(dst: [u8; 4]) -> Option<i32> {
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

/// Set the alias of link `name` (the kernel does not take an alias at
/// creation). Returns 0 or a negative errno.
fn set_alias(name: &str, alias: &str) -> i32 {
    let mut msg = nl_begin(&IfInfoMsg::default());
    put_attr(&mut msg, IFLA_IFNAME, &name_z(name));
    let mut a = alias.as_bytes().to_vec();
    a.push(0);
    put_attr(&mut msg, IFLA_IFALIAS, &a);
    nl_request(&mut msg, RTM_NEWLINK, 0)
}

/// Delete link `index`. A link already gone counts as deleted.
pub(crate) fn del_link(index: i32) -> i32 {
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
fn del_link_named(name: &str) -> i32 {
    let mut msg = nl_begin(&IfInfoMsg::default());
    put_attr(&mut msg, IFLA_IFNAME, &name_z(name));
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
    let fd = nl_socket()?;
    let r = links_on(fd);
    // SAFETY: closing the socket opened above.
    unsafe { libc::close(fd) };
    r
}

/// Every link of the network domain `fd` is a `NETLINK_ROUTE` socket in.
pub fn links_on(fd: i32) -> Result<Vec<LinkInfo>, i32> {
    let mut msg = nl_begin(&IfInfoMsg::default());
    nl_finish(&mut msg, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    nl_send(fd, &msg)?;
    loop {
        let n = nl_recv(fd, &mut buf);
        if n <= 0 {
            return Err(errno::ERROR);
        }
        if parse_links(buf.get(..n as usize).unwrap_or(&[]), &mut out)? {
            return Ok(out);
        }
    }
}

/// Create the veth pair `host`/`peer`, the peer end made directly inside
/// the network domain of process `pid`. Returns 0 or a negative errno.
pub fn create_veth_into(host: &str, peer: &str, pid: u32) -> i32 {
    let ifi = IfInfoMsg::default();
    let mut msg = nl_begin(&ifi);
    put_attr(&mut msg, IFLA_IFNAME, &name_z(host));
    let linkinfo = begin_nested(&mut msg, IFLA_LINKINFO);
    put_attr(&mut msg, IFLA_INFO_KIND, b"veth");
    let infodata = begin_nested(&mut msg, IFLA_INFO_DATA);
    let p = begin_nested(&mut msg, VETH_INFO_PEER);
    // VETH_INFO_PEER payload = ifinfomsg + attrs for the peer.
    msg.extend_from_slice(ifinfo_bytes(&ifi));
    put_attr(&mut msg, IFLA_IFNAME, &name_z(peer));
    put_attr(&mut msg, IFLA_NET_NS_PID, &pid.to_ne_bytes());
    end_nested(&mut msg, p);
    end_nested(&mut msg, infodata);
    end_nested(&mut msg, linkinfo);
    nl_request(&mut msg, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
}

/// A link name as a zero-terminated attribute payload.
fn name_z(name: &str) -> Vec<u8> {
    let mut v: Vec<u8> = name.bytes().take(15).collect();
    v.push(0);
    v
}

// linux_eth built-in — a Linux network interface as the Ethernet frame
// driver under `ip`, so the module's own TCP/IP stack runs on the hosted
// runtime exactly as it does over a NIC on bare metal. Frames cross both
// ports as the records every frame driver exchanges with `ip`,
// `[len:u16 LE][frame]`, and the first record out is the MAC announcement
// (`dst = src = mac`, EtherType 0).
//
// Two ways to reach the wire (`mode`):
//
// - `packet` (default): an `AF_PACKET` socket bound to an existing
//   interface — typically one end of a veth in a network namespace the
//   runtime owns, with no address of its own, so the host kernel there
//   answers nothing for the stack. The stack's MAC is the interface's.
//   Needs `CAP_NET_RAW` in that namespace's user namespace.
// - `tap`: a persistent TAP opened by name (`TUNSETIFF`, `IFF_TAP |
//   IFF_NO_PI`); the host kernel's side of it is a NIC. Needs access to
//   `/dev/net/tun`. The stack's MAC is a locally administered address
//   derived from the interface name.
//
// `mac` overrides either. A frame `frames_rx` has no room for is dropped and
// counted, as a NIC drops on a full ring; so is one longer than
// `ETH_FRAME_MAX` either way, never truncated. The interface is the boot
// graph's to name: built-ins are constructed only from the runtime's own
// configuration, and the reach is the runtime process's — its network
// namespace and the capabilities it holds there. The descriptor is
// close-on-exec, so no host-process workload the runtime starts inherits
// it. Included into `linux.rs`; shares its imports.

use fluxor::platform::builtin_param_tags::linux_eth as eth_tags;
use fluxor::platform::builtin_param_tags::linux_eth::{
    TAG_IFNAME as ETH_TAG_IFNAME, TAG_MAC as ETH_TAG_MAC, TAG_MODE as ETH_TAG_MODE,
};

const LINUX_ETH_HASH: u32 = 0xF682_A08D; // fnv1a32("linux_eth")

/// The largest frame either direction carries (no FCS, one VLAN tag).
const ETH_FRAME_MAX: usize = 1518;
/// Frames moved per direction per step.
const ETH_BURST: usize = 16;

const ETH_MODE_PACKET: u8 = 0;
const ETH_MODE_TAP: u8 = 1;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const ETH_P_ALL: u16 = 0x0003;

struct LinuxEthState {
    fd: i32,
    packet: bool,
    rx_out: i32,
    tx_in: i32,
    mac: [u8; 6],
    announced: bool,
    ifname: String,
    rx_frames: u64,
    tx_frames: u64,
    rx_dropped: u64,
    rx_oversize: u64,
    tx_dropped: u64,
    tx_malformed: u64,
}

/// `TUNSETIFF` / `SIOCGIFHWADDR` take a `struct ifreq`: the name, then a
/// union (the flags, or a `sockaddr` whose data is the address).
#[repr(C)]
struct EthIfreq {
    name: [u8; libc::IFNAMSIZ],
    union: [u8; 24],
}

fn eth_ifreq(name: &str) -> EthIfreq {
    let mut req = EthIfreq {
        name: [0; libc::IFNAMSIZ],
        union: [0; 24],
    };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    req
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Open the TAP `name`, non-blocking; the descriptor or the errno.
fn eth_open_tap(name: &str) -> Result<i32, i32> {
    // SAFETY: a NUL-terminated literal path.
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last_errno());
    }
    let mut req = eth_ifreq(name);
    req.union[..2].copy_from_slice(&(IFF_TAP | IFF_NO_PI).to_ne_bytes());
    // SAFETY: `req` is a live `ifreq`-shaped buffer the ioctl reads and writes.
    if unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut req as *mut EthIfreq) } < 0 {
        let e = last_errno();
        // SAFETY: `fd` is ours and open.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Bind an `AF_PACKET` socket to the interface `name`, non-blocking; the
/// descriptor and the interface's MAC, or the errno. The socket is made
/// with protocol 0, which receives nothing, and given `ETH_P_ALL` only by
/// the bind that names the interface: one made with `ETH_P_ALL` would
/// queue every interface's frames until the bind.
fn eth_open_packet(name: &str) -> Result<(i32, [u8; 6]), i32> {
    let proto = ETH_P_ALL.to_be();
    // SAFETY: plain socket creation.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(last_errno());
    }
    let close = |e: i32| {
        // SAFETY: `fd` is ours and open.
        unsafe { libc::close(fd) };
        e
    };
    let mut req = eth_ifreq(name);
    // SAFETY: `req` is a live `ifreq`-shaped buffer the ioctl writes.
    if unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX as _, &mut req as *mut EthIfreq) } < 0 {
        return Err(close(last_errno()));
    }
    let ifindex = i32::from_ne_bytes([req.union[0], req.union[1], req.union[2], req.union[3]]);
    let mut req = eth_ifreq(name);
    // SAFETY: as above; the union receives a `sockaddr` with the address.
    if unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as _, &mut req as *mut EthIfreq) } < 0 {
        return Err(close(last_errno()));
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&req.union[2..8]);
    // SAFETY: zero is a valid `sockaddr_ll` to fill in.
    let mut sll: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = proto;
    sll.sll_ifindex = ifindex;
    // SAFETY: `sll` is a live `sockaddr_ll` of the length given.
    let rc = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(close(last_errno()));
    }
    Ok((fd, mac))
}

/// Six hex octets, `:`-separated.
fn eth_parse_mac(mac: &str) -> Option<[u8; 6]> {
    let mut m = [0u8; 6];
    let mut n = 0;
    for p in mac.split(':') {
        if n == 6 {
            return None;
        }
        m[n] = u8::from_str_radix(p, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(m)
}

/// Read one frame into `buf`; its length, skipping a packet socket's view
/// of what this driver itself sent. The length is the frame's own: a
/// packet socket reports it whole (`MSG_TRUNC`) and a TAP read fills a
/// buffer one byte longer than any frame taken, so a reported length past
/// `ETH_FRAME_MAX` is a frame too long to carry, never a short one. At
/// most `ETH_BURST` outgoing frames are skipped in one call, so a step
/// stays bounded however much the interface sends.
fn eth_read(st: &LinuxEthState, buf: &mut [u8]) -> Option<usize> {
    if !st.packet {
        // SAFETY: reads at most `buf.len()` bytes into `buf`.
        let n = unsafe { libc::read(st.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        return (n > 0).then_some(n as usize);
    }
    for _ in 0..ETH_BURST {
        // SAFETY: zero is a valid `sockaddr_ll` for the kernel to fill in.
        let mut from: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
        let mut flen = core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: `buf` and `from` are live and of the lengths given.
        let n = unsafe {
            libc::recvfrom(
                st.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_TRUNC,
                &mut from as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut flen,
            )
        };
        if n <= 0 {
            return None;
        }
        if from.sll_pkttype != libc::PACKET_OUTGOING {
            return Some(n as usize);
        }
    }
    None
}

fn linux_eth_step(state: *mut u8) -> i32 {
    // SAFETY: kernel-owned arena sized to `LinuxEthState` by the loader.
    let st = unsafe { instance_state::<LinuxEthState>(state) };
    if st.fd < 0 {
        return 0;
    }
    if !st.announced && st.rx_out >= 0 {
        let mut rec = [0u8; 16];
        rec[0] = 14;
        rec[2..8].copy_from_slice(&st.mac);
        rec[8..14].copy_from_slice(&st.mac);
        // SAFETY: a stack record of the length given.
        if unsafe { channel::channel_write(st.rx_out, rec.as_ptr(), rec.len()) } == 16 {
            st.announced = true;
            log::info!(
                "[linux_eth] {} up mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                st.ifname,
                st.mac[0],
                st.mac[1],
                st.mac[2],
                st.mac[3],
                st.mac[4],
                st.mac[5]
            );
        }
        return 0;
    }

    // Wire → ip.
    let mut rec = [0u8; 2 + ETH_FRAME_MAX + 1];
    for _ in 0..ETH_BURST {
        let Some(n) = eth_read(st, &mut rec[2..]) else {
            break;
        };
        if n > ETH_FRAME_MAX {
            st.rx_oversize += 1;
            if st.rx_oversize.is_power_of_two() {
                log::warn!("[linux_eth] {} rx oversize n={}", st.ifname, st.rx_oversize);
            }
            continue;
        }
        rec[0] = n as u8;
        rec[1] = (n >> 8) as u8;
        // SAFETY: `2 + n` bytes of the record are initialised.
        if unsafe { channel::channel_write(st.rx_out, rec.as_ptr(), 2 + n) } == (2 + n) as i32 {
            st.rx_frames += 1;
        } else {
            st.rx_dropped += 1;
            if st.rx_dropped.is_power_of_two() {
                log::warn!("[linux_eth] {} rx dropped n={}", st.ifname, st.rx_dropped);
            }
        }
    }

    // ip → wire. Every writer lands a record whole (the channel takes a
    // write whole or not at all), so a record is read only once all of it
    // is buffered, and one too long for the wire is discarded whole: the
    // stream stays in step either way.
    for _ in 0..ETH_BURST {
        let mut hdr = [0u8; 2];
        // SAFETY: a two-byte stack buffer.
        if unsafe { channel::channel_peek(st.tx_in, hdr.as_mut_ptr(), 2) } != 2 {
            break;
        }
        let want = usize::from(u16::from_le_bytes(hdr));
        if want == 0 || want > ETH_FRAME_MAX {
            channel::channel_discard(st.tx_in, 2 + want);
            st.tx_malformed += 1;
            if st.tx_malformed.is_power_of_two() {
                log::warn!(
                    "[linux_eth] {} tx frame of {want} bytes refused n={}",
                    st.ifname,
                    st.tx_malformed
                );
            }
            continue;
        }
        // SAFETY: `2 + want <= rec.len()` bytes into the record buffer.
        if unsafe { channel::channel_peek(st.tx_in, rec.as_mut_ptr(), 2 + want) } != (2 + want) as i32 {
            break;
        }
        channel::channel_discard(st.tx_in, 2 + want);
        // SAFETY: `want` initialised bytes after the length.
        let w = unsafe { libc::write(st.fd, rec.as_ptr().add(2) as *const libc::c_void, want) };
        if w == want as isize {
            st.tx_frames += 1;
        } else {
            // A full socket buffer or a link that is down: the frame is lost,
            // as on a NIC whose ring is full; the transport recovers it.
            st.tx_dropped += 1;
            if st.tx_dropped.is_power_of_two() {
                log::warn!("[linux_eth] {} tx dropped n={}", st.ifname, st.tx_dropped);
            }
        }
    }
    0
}

/// Construct a `linux_eth` built-in on the interface its `ifname` names.
fn build_linux_eth(module_idx: usize, params: &[u8]) -> scheduler::BuiltInModule {
    let mut ifname = String::new();
    let mut mac = String::new();
    let mut mode = ETH_MODE_PACKET;
    walk_tlv(params, |tag, value| match tag {
        ETH_TAG_IFNAME => ifname = tlv_str(value).to_string(),
        ETH_TAG_MAC => mac = tlv_str(value).to_string(),
        ETH_TAG_MODE => mode = tlv_u8(value),
        _ => {}
    });
    scheduler::set_current_module(module_idx);
    let rx_out = scheduler::module_port(module_idx, eth_tags::PORT_FRAMES_RX);
    let tx_in = scheduler::module_port(module_idx, eth_tags::PORT_FRAMES_TX);
    let packet = mode != ETH_MODE_TAP;
    let derived = {
        let h = fluxor::abi::wire::fnv1a32(ifname.as_bytes());
        [
            0x02,
            0xF1,
            (h >> 24) as u8,
            (h >> 16) as u8,
            (h >> 8) as u8,
            h as u8,
        ]
    };
    let opened = if ifname.is_empty() || ifname.len() >= libc::IFNAMSIZ {
        Err(libc::EINVAL)
    } else if packet {
        eth_open_packet(&ifname)
    } else {
        eth_open_tap(&ifname).map(|fd| (fd, derived))
    };
    let (fd, own_mac) = match opened {
        Ok(v) => v,
        Err(e) => {
            log::error!("[linux_eth] open '{ifname}' failed: errno {e}");
            (-1, derived)
        }
    };
    let mac = eth_parse_mac(&mac).unwrap_or(own_mac);
    let mut m = scheduler::BuiltInModule::new("linux_eth", linux_eth_step);
    log::info!(
        "[inst] module {module_idx} = linux_eth (built-in) ifname='{ifname}' mode={} fd={fd} rx={rx_out} tx={tx_in}",
        if packet { "packet" } else { "tap" }
    );
    install_state(
        &mut m,
        Box::new(LinuxEthState {
            fd,
            packet,
            rx_out,
            tx_in,
            mac,
            announced: false,
            ifname,
            rx_frames: 0,
            tx_frames: 0,
            rx_dropped: 0,
            rx_oversize: 0,
            tx_dropped: 0,
            tx_malformed: 0,
        }),
    );
    m
}

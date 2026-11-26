//! `fluxor-provider-net` — the node's network on a Linux host, as a host
//! provider behind `host_lane serves = "net_route,net_policy"`: the control
//! plane, and the host sockets a graph names as `linux_net`.
//!
//! - [`tables`]: the `net_route` and `net_policy` stores, on the shared
//!   `net_tables` core, bound to the module the runtime names per call.
//! - [`route`]: segments, peer routes and held addresses realized in the
//!   host's network domain, the forwarding guard, the periodic probes.
//! - [`policy`]: a policy table as an `nft` table, applied whole.
//! - [`identity`]: the address-control port — a workload's address
//!   realized as a veth pair into its own network domain, configured
//!   through a netlink socket the runtime opened there.
//! - [`instance`]: the host registry runtimes on one host share: tags,
//!   claims, tunables, dead-tag collection.
//! - [`nft`] and [`netlink`]: the two ways it changes the host.
//! - [`sockets`]: the stream and datagram surfaces over the host's TCP and
//!   UDP, on the node graph's socket lanes and every workload's.
//! - [`endpoints`]: the bound-endpoint report, beside the runtime's owner
//!   facts.
//! - [`serve`]: the lane handler, and the restart hold.
//!
//! The provider administers the host's network (`CAP_NET_ADMIN`), sends
//! link-layer frames of its own (`CAP_NET_RAW`: the forwarding probe, a held
//! address's announcement) and binds the ports a graph asks for, those below
//! 1024 included (`CAP_NET_BIND_SERVICE`), when the runtime holds them and
//! grants them; it enters no namespace and executes nothing but `nft`.

#![allow(
    unsafe_code,
    reason = "netlink, packet and host sockets, epoll, getrandom, flock and the rule tool's \
              pre-exec descriptor sweep are system calls with no safe std equivalent"
)]

pub mod endpoints;
pub mod identity;
pub mod instance;
pub mod netlink;
pub mod nft;
pub mod policy;
pub mod route;
pub mod serve;
pub mod sockets;
pub mod tables;

//! The host lane: how `fluxor-linux` and a host provider process move
//! records and calls between them.
//!
//! A host provider stands behind ports or contracts the runtime would
//! otherwise serve in-process. It consumes and produces exactly the records
//! of those ports, framed as their content types frame them, and answers
//! exactly the ops of those contracts; the lane adds no ABI of its own.
//! What it adds is transport:
//!
//! - one sealed `memfd` ring per channel direction ([`ring`]): records are
//!   copied in by one side and out by the other, never shared in place;
//! - one `SOCK_SEQPACKET` control socket ([`control`]): the provider's
//!   `HELLO` (the ABI surface digest it was built against, the contracts it
//!   serves and its channel table, in `remote_channel`'s vocabulary),
//!   `ACCEPT` with the rings or `REFUSE`, doorbells, `STOP`; end of file is
//!   the lane closing;
//! - for a served contract, calls framed with the caller the kernel names
//!   and the op's `data` span ([`frame`]), answered resumably ([`runtime`]);
//! - owner facts (an owner's host pid and a netlink socket in its network
//!   namespace) and dynamic lanes, each a ring pair of its own, for a
//!   provider that takes them ([`control::wants`]);
//! - the provider's privilege, cut to what it is granted ([`privilege`]).
//!
//! The runtime side is [`runtime::Lane`]; the provider side is
//! [`provider::Provider`] with a [`provider::Handler`].

#![allow(
    unsafe_code,
    reason = "a lane is shared memory, descriptor passing and a forked child: memfd, mmap, \
              sendmsg/recvmsg with SCM_RIGHTS and pre-exec descriptor placement are system calls \
              with no safe std equivalent"
)]

pub mod control;
pub mod frame;
pub mod privilege;
pub mod provider;
pub mod ring;
pub mod runtime;
pub mod served;
pub mod spawn;

/// The ABI surface digest this build of the lane states and expects: the
/// one both ends were compiled against.
pub const ABI_SURFACE_DIGEST: [u8; 32] = fluxor_abi::abi_surface::ABI_SURFACE_DIGEST;

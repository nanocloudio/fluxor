//! What a provider process may do beyond an ordinary user's.
//!
//! The runtime starts every provider with the capabilities its
//! [`Privilege`] names and no others: the bounding set is cut to them (where
//! the runtime may cut it), they are the provider's permitted, effective,
//! inheritable and ambient sets, and nothing it execs can gain more —
//! `no_new_privs` is set, and a runtime running as root sets
//! `SECBIT_NOROOT` (locked) so that an exec as root does not regain every
//! capability. Ambient capabilities do pass to an ordinary binary the
//! provider execs (a helper such as `nft` keeps `CAP_NET_ADMIN`); which
//! helpers a provider execs is the provider's code, not a system filter.
//!
//! A capability the runtime does not hold itself cannot be granted: the
//! provider then starts without it, finds it missing ([`require`]) and says
//! `UNABLE` with the reason instead of `HELLO`, so the lane fails closed
//! and the reason reaches the runtime's log.

/// Capability numbers (`linux/capability.h`).
pub mod cap {
    pub const SETPCAP: u32 = 8;
    pub const NET_BIND_SERVICE: u32 = 10;
    pub const NET_ADMIN: u32 = 12;
    pub const NET_RAW: u32 = 13;
    pub const SYS_ADMIN: u32 = 21;

    /// The name of `c`, for a stated reason.
    pub fn name(c: u32) -> &'static str {
        match c {
            SETPCAP => "CAP_SETPCAP",
            NET_BIND_SERVICE => "CAP_NET_BIND_SERVICE",
            NET_ADMIN => "CAP_NET_ADMIN",
            NET_RAW => "CAP_NET_RAW",
            SYS_ADMIN => "CAP_SYS_ADMIN",
            _ => "a capability",
        }
    }
}

/// The capabilities a provider keeps, as a bit mask over capability
/// numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Privilege {
    pub keep: u64,
}

impl Privilege {
    /// Nothing beyond an ordinary process.
    pub const NONE: Privilege = Privilege { keep: 0 };

    /// Keep exactly `caps`.
    pub const fn of(caps: &[u32]) -> Privilege {
        let mut keep = 0u64;
        let mut i = 0;
        while i < caps.len() {
            keep |= 1u64 << caps[i];
            i += 1;
        }
        Privilege { keep }
    }
}

const VERSION_3: u32 = 0x2008_0522;
const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `(effective, permitted)` of this thread. Async-signal-safe.
fn get() -> Option<(u64, u64)> {
    let mut h = CapHeader {
        version: VERSION_3,
        pid: 0,
    };
    let mut d = [CapData::default(); 2];
    // SAFETY: a version-3 header and two data words, live for the call.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &mut h, d.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let join = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
    Some((
        join(d[0].effective, d[1].effective),
        join(d[0].permitted, d[1].permitted),
    ))
}

/// The capabilities this process holds effective now.
pub fn effective() -> u64 {
    get().map_or(0, |(e, _)| e)
}

/// The provider's side: every capability in `caps` is effective, or the
/// reason it cannot serve.
pub fn require(caps: &[u32]) -> Result<(), String> {
    let eff = effective();
    for &c in caps {
        if eff & (1u64 << c) == 0 {
            return Err(format!(
                "needs {} and was started without it (the runtime does not hold it)",
                cap::name(c)
            ));
        }
    }
    Ok(())
}

/// Reduce the calling (child, pre-exec) process to `p`. Async-signal-safe:
/// system calls only, nothing allocated. `Err` only where going on would
/// start the provider with more than `p` names.
pub(crate) fn apply_in_child(p: Privilege) -> std::io::Result<()> {
    let Some((eff, permitted)) = get() else {
        return Err(std::io::Error::last_os_error());
    };
    // The bounding set needs CAP_SETPCAP to cut; without it this process
    // holds no capability to lose, and no_new_privs below keeps it so.
    if eff & (1u64 << cap::SETPCAP) != 0 {
        for c in 0..64u32 {
            if p.keep & (1u64 << c) == 0 {
                // SAFETY: integer arguments; EINVAL past the last capability.
                unsafe { libc::prctl(libc::PR_CAPBSET_DROP, c as libc::c_ulong, 0, 0, 0) };
            }
        }
    }
    // SAFETY: integer arguments only.
    let root = unsafe { libc::getuid() == 0 || libc::geteuid() == 0 };
    if root {
        // SAFETY: integer arguments only.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_SECUREBITS,
                SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
                0,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let keep = p.keep & permitted;
    let lo = keep as u32;
    let hi = (keep >> 32) as u32;
    let mut h = CapHeader {
        version: VERSION_3,
        pid: 0,
    };
    let d = [
        CapData {
            effective: lo,
            permitted: lo,
            inheritable: lo,
        },
        CapData {
            effective: hi,
            permitted: hi,
            inheritable: hi,
        },
    ];
    // SAFETY: a version-3 header and two data words, live for the call.
    if unsafe { libc::syscall(libc::SYS_capset, &mut h, d.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for c in 0..64u32 {
        if keep & (1u64 << c) != 0 {
            // SAFETY: integer arguments. A refusal leaves the capability
            // out of the ambient set; the provider then finds it missing.
            unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    c as libc::c_ulong,
                    0,
                    0,
                )
            };
        }
    }
    // SAFETY: integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

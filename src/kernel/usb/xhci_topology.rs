//! xHCI route strings and port protocols.
//!
//! # The route string
//!
//! xHCI addresses a device not by a path of hub addresses but by a 20-bit
//! **route string**: five 4-bit fields, one per hub tier, each holding the
//! downstream port number that device sits behind at that tier. The host
//! controller uses it to steer a packet through the topology, so a wrong
//! route reaches the wrong device — not an error, a different device.
//!
//! Three things about it are easy to get wrong and produce no diagnostic:
//!
//! - **Tier 1 is the lowest nibble.** The tiers read outward from the root
//!   hub, so a device two tiers deep has its *first* hop in bits 0..3. Built
//!   the other way round the string is a valid route to somewhere else.
//! - **Port numbers are 1-based**, and zero in a nibble means "no more
//!   tiers". A 0-based port number silently truncates the route at that
//!   tier.
//! - **Depth is capped at five.** USB allows at most five hub tiers below the
//!   root, and a sixth has nowhere to go in the string — it would overwrite
//!   the first.
//!
//! The root ports themselves are *not* in the route string: a device on a
//! root port has route 0, and its port number travels in the slot context
//! instead. Encoding the root port into the string is the fourth mistake,
//! and it addresses a device one tier deeper than the one intended.

/// Hub tiers a route string can express.
pub const MAX_TIERS: usize = 5;
/// Bits per tier.
pub const TIER_BITS: u32 = 4;
/// Highest downstream port number a tier can name.
pub const MAX_PORT: u8 = 15;

/// Why a route could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// More than five hub tiers.
    TooDeep,
    /// A port number of zero, or above fifteen.
    InvalidPort,
}

/// A device's position in the topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RouteString(u32);

impl RouteString {
    /// A device directly on a root port.
    ///
    /// Route zero. The root port number is **not** encoded here — it travels
    /// in the slot context — and putting it in would address a device one
    /// tier deeper than intended.
    pub const fn root() -> Self {
        Self(0)
    }

    /// The raw 20-bit value, as it goes in the slot context.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Build a route from a path of downstream port numbers, nearest the root
    /// first.
    pub fn from_path(path: &[u8]) -> Result<Self, RouteError> {
        if path.len() > MAX_TIERS {
            return Err(RouteError::TooDeep);
        }
        let mut bits = 0u32;
        for (tier, &port) in path.iter().enumerate() {
            // Zero means "no further tier", so it cannot also be a port.
            if port == 0 || port > MAX_PORT {
                return Err(RouteError::InvalidPort);
            }
            bits |= (port as u32) << (tier as u32 * TIER_BITS);
        }
        Ok(Self(bits))
    }

    /// Extend a route by one tier, for a device found behind a hub whose own
    /// route is already known.
    ///
    /// This is how enumeration actually builds routes: a hub is discovered,
    /// then its children. Recomputing the whole path each time is what
    /// introduces an off-by-one in the tier.
    pub fn child(&self, port: u8) -> Result<Self, RouteError> {
        if port == 0 || port > MAX_PORT {
            return Err(RouteError::InvalidPort);
        }
        let tier = self.depth();
        if tier >= MAX_TIERS {
            return Err(RouteError::TooDeep);
        }
        Ok(Self(self.0 | ((port as u32) << (tier as u32 * TIER_BITS))))
    }

    /// How many hub tiers this route traverses.
    ///
    /// Counts up from tier 1 and stops at the first empty nibble, because a
    /// zero means "no more tiers" — scanning from the top would misread a
    /// route whose deeper tiers are empty.
    pub const fn depth(&self) -> usize {
        let mut n = 0;
        while n < MAX_TIERS {
            if (self.0 >> (n as u32 * TIER_BITS)) & 0xf == 0 {
                return n;
            }
            n += 1;
        }
        MAX_TIERS
    }

    /// The downstream port at `tier`, counting from 1 at the root.
    pub const fn port_at(&self, tier: usize) -> Option<u8> {
        if tier == 0 || tier > MAX_TIERS {
            return None;
        }
        let v = ((self.0 >> ((tier - 1) as u32 * TIER_BITS)) & 0xf) as u8;
        if v == 0 {
            None
        } else {
            Some(v)
        }
    }
}

/// A root port's speed, from the xHCI Supported Protocol capability.
///
/// The capability lists port ranges per protocol revision, so a controller's
/// USB2 and USB3 ports are *different port numbers on the same controller* —
/// not the same port in two modes. Treating them as one is how a SuperSpeed
/// device gets addressed through its companion USB2 port and enumerates at
/// full speed for no visible reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortProtocol {
    /// USB 2.0: low, full or high speed.
    Usb2,
    /// USB 3.x: SuperSpeed and above.
    Usb3,
}

/// One entry of the Supported Protocol capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolRange {
    /// Which protocol these ports speak.
    pub protocol: PortProtocol,
    /// First port, 1-based.
    pub port_offset: u8,
    /// How many ports.
    pub port_count: u8,
}

impl ProtocolRange {
    /// Whether `port` (1-based) is in this range.
    pub const fn contains(&self, port: u8) -> bool {
        port >= self.port_offset && (port - self.port_offset) < self.port_count
    }
}

/// Find the protocol a root port speaks.
///
/// `None` when no range claims it — which is a real condition, not an
/// impossible one: a controller may report fewer ports than its register
/// count suggests, and addressing an unclaimed port talks to nothing.
pub fn protocol_for_port(ranges: &[ProtocolRange], port: u8) -> Option<PortProtocol> {
    if port == 0 {
        return None;
    }
    ranges.iter().find(|r| r.contains(port)).map(|r| r.protocol)
}

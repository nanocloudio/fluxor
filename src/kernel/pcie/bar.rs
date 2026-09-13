//! PCIe BAR aperture claims.
//!
//! # Why an inherited address is not ownership
//!
//! Firmware leaves the BARs programmed, so a driver can read a peripheral by
//! writing down the address the bootloader used and dereferencing it. That
//! works, right up until it does not:
//!
//! - the address is only correct for the firmware that happened to boot;
//! - nothing stops two drivers using the same aperture, because neither
//!   asked;
//! - nothing notices when a device is removed, so a stale mapping keeps being
//!   written to whatever now occupies that address;
//! - teardown cannot be checked, because there was never a record of what was
//!   taken.
//!
//! An inherited address is therefore not an ownership proof. This registry
//! is what makes ownership explicit: an aperture must be claimed before it
//! can be resolved, and a claim names the device it belongs to, so releasing
//! that device releases everything it held and a leaked claim is visible.

/// Apertures tracked at once.
///
/// Bounded, like every other table in the kernel. A device that could claim
/// without limit would exhaust the registry every other device shares.
pub const MAX_CLAIMS: usize = 16;

/// A PCIe device, by its bus/device/function address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceAddress {
    /// Bus number.
    pub bus: u8,
    /// Device number.
    pub device: u8,
    /// Function number.
    pub function: u8,
}

/// A claim on one BAR aperture.
///
/// Carries a generation, like a transfer token, because slots are reused: a
/// handle held across a release would otherwise resolve to whatever device
/// took the slot next — and resolve to a *mapped address*, which is the worst
/// possible thing to be wrong about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarClaim {
    slot: u8,
    generation: u16,
}

/// Why a claim was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarError {
    /// Every slot is in use.
    RegistryFull,
    /// This device already holds this BAR.
    AlreadyClaimed,
    /// Another device's claim covers part of this range.
    Overlaps,
    /// The handle's generation does not match: the claim has been released
    /// and its slot reused.
    Stale,
    /// A zero-length aperture, or one that wraps the address space.
    InvalidRange,
    /// The requested offset is outside the claimed aperture.
    OutOfBounds,
}

#[derive(Clone, Copy)]
struct Slot {
    live: bool,
    generation: u16,
    owner: DeviceAddress,
    index: u8,
    base: u64,
    len: u64,
}

/// The BAR claim registry.
pub struct BarRegistry {
    slots: [Slot; MAX_CLAIMS],
}

impl Default for BarRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BarRegistry {
    /// An empty registry.
    pub const fn new() -> Self {
        Self {
            slots: [Slot {
                live: false,
                generation: 0,
                owner: DeviceAddress {
                    bus: 0,
                    device: 0,
                    function: 0,
                },
                index: 0,
                base: 0,
                len: 0,
            }; MAX_CLAIMS],
        }
    }

    /// Claim an aperture for a device.
    ///
    /// Refuses a range overlapping another device's claim. That check is the
    /// point of the registry: two drivers writing one aperture is a fault
    /// that presents as each one's device misbehaving intermittently, and
    /// neither driver can see the other.
    pub fn claim(
        &mut self,
        owner: DeviceAddress,
        index: u8,
        base: u64,
        len: u64,
    ) -> Result<BarClaim, BarError> {
        if len == 0 || base.checked_add(len).is_none() {
            return Err(BarError::InvalidRange);
        }

        for slot in self.slots.iter() {
            if !slot.live {
                continue;
            }
            if slot.owner == owner && slot.index == index {
                return Err(BarError::AlreadyClaimed);
            }
            // Half-open ranges: [base, base+len). Touching end-to-end is not
            // an overlap, and treating it as one would refuse two legitimate
            // adjacent apertures.
            let overlaps = base < slot.base + slot.len && slot.base < base + len;
            if overlaps {
                return Err(BarError::Overlaps);
            }
        }

        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.live {
                continue;
            }
            slot.live = true;
            slot.owner = owner;
            slot.index = index;
            slot.base = base;
            slot.len = len;
            return Ok(BarClaim {
                slot: i as u8,
                generation: slot.generation,
            });
        }
        Err(BarError::RegistryFull)
    }

    /// Resolve an offset within a claimed aperture to an address.
    ///
    /// **The only way to get an address out of this registry.** A driver that
    /// kept the base and added to it would bypass both the generation check
    /// and the bounds check, which are the two things separating a claim from
    /// a constant.
    pub fn resolve(&self, claim: BarClaim, offset: u64) -> Result<u64, BarError> {
        let slot = self.slots.get(claim.slot as usize).ok_or(BarError::Stale)?;
        if !slot.live || slot.generation != claim.generation {
            return Err(BarError::Stale);
        }
        if offset >= slot.len {
            return Err(BarError::OutOfBounds);
        }
        Ok(slot.base + offset)
    }

    /// Release one claim.
    ///
    /// Advances the slot's generation, so every outstanding handle to it
    /// becomes stale rather than resolving into the next occupant's aperture.
    pub fn release(&mut self, claim: BarClaim) -> Result<(), BarError> {
        let slot = self
            .slots
            .get_mut(claim.slot as usize)
            .ok_or(BarError::Stale)?;
        if !slot.live || slot.generation != claim.generation {
            return Err(BarError::Stale);
        }
        slot.live = false;
        slot.generation = slot.generation.wrapping_add(1);
        Ok(())
    }

    /// Release every claim held by a device, returning how many.
    ///
    /// **This is what makes teardown checkable.** A device removed without it
    /// leaves apertures claimed forever: the registry fills, and worse, a
    /// later device is refused a range nothing is actually using.
    pub fn release_device(&mut self, owner: DeviceAddress) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if slot.live && slot.owner == owner {
                slot.live = false;
                slot.generation = slot.generation.wrapping_add(1);
                n += 1;
            }
        }
        n
    }

    /// Claims currently held.
    pub fn live_claims(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }

    /// Whether any claim is outstanding.
    ///
    /// For an assertion at teardown: a driver that has released its device
    /// should leave none, and a non-zero count names a leak rather than
    /// letting it accumulate silently.
    pub fn is_empty(&self) -> bool {
        self.live_claims() == 0
    }
}

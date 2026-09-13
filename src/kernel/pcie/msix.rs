//! MSI-X vector allocation, and the CPU/device address distinction.
//!
//! # Vectors are controller-scoped
//!
//! Each controller owns a range of the interrupt space. Allocating from a
//! global pool means one controller's teardown can free a vector another is
//! still using, and the symptom is an interrupt arriving for a device that
//! has stopped expecting it — which reads as a spurious IRQ, not as a
//! bookkeeping fault.
//!
//! # An address the CPU sees is not an address the device sees
//!
//! Whether an SMMU translates these addresses is a property of the system,
//! not something to assume. With no IOMMU the two are equal and `ptr as u64`
//! happens to work; on one with an SMMU, or with a
//! PCIe window offset, it does not — and the failure is a DMA engine writing
//! to whatever the untranslated address happens to reach. Pi 5's PCIe already
//! puts peripherals behind a window, so this is not hypothetical.
//!
//! [`CpuAddress`] and [`DeviceAddress`] are therefore separate types with no
//! conversion between them except through a [`DmaTranslation`] that says what
//! the mapping is. Identity is one such mapping and has to be *named*, so
//! "we assumed identity" becomes a line of code rather than an absence.

/// An address as the CPU sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CpuAddress(pub u64);

/// An address as a device's DMA engine sees it.
///
/// Deliberately not convertible from [`CpuAddress`] without a translation:
/// `ptr as u64` into a descriptor is the bug this type exists to make
/// impossible to write by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceAddress(pub u64);

/// How CPU addresses map to device addresses for one controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaTranslation {
    /// The device sees exactly what the CPU sees.
    ///
    /// Correct only where no IOMMU and no window offset intervene. Naming it
    /// is the point: a driver declaring this has stated an assumption that
    /// can be checked against the platform, rather than leaving it implicit
    /// in a cast.
    Identity,
    /// The device sees the CPU address plus a fixed offset, as through a
    /// PCIe outbound window.
    Windowed {
        /// Added to a CPU address to get the device's view.
        offset: u64,
        /// The CPU range the window covers. Outside it, translation is not
        /// defined and DMA would not reach.
        cpu_base: u64,
        /// Length of that range.
        len: u64,
    },
}

/// Why an address could not be translated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaError {
    /// The address is outside any window this controller can reach. A
    /// descriptor built from it would have the engine write somewhere the
    /// driver did not intend, or nowhere at all.
    Unreachable,
    /// The translated address overflowed.
    Overflow,
}

impl DmaTranslation {
    /// Translate a CPU address for this controller's DMA engine.
    ///
    /// Returns [`DmaError::Unreachable`] rather than a plausible-looking
    /// number when the address is outside the window. An address a device
    /// cannot reach has to be reportable at the point of translation; the
    /// alternative is a DMA engine writing wherever the untranslated value
    /// happens to land.
    pub const fn to_device(&self, cpu: CpuAddress) -> Result<DeviceAddress, DmaError> {
        match *self {
            DmaTranslation::Identity => Ok(DeviceAddress(cpu.0)),
            DmaTranslation::Windowed {
                offset,
                cpu_base,
                len,
            } => {
                if cpu.0 < cpu_base {
                    return Err(DmaError::Unreachable);
                }
                let end = match cpu_base.checked_add(len) {
                    Some(e) => e,
                    None => return Err(DmaError::Overflow),
                };
                if cpu.0 >= end {
                    return Err(DmaError::Unreachable);
                }
                match cpu.0.checked_add(offset) {
                    Some(d) => Ok(DeviceAddress(d)),
                    None => Err(DmaError::Overflow),
                }
            }
        }
    }

    /// Whether a whole buffer is reachable, not merely its first byte.
    ///
    /// A descriptor names a base and a length, and a buffer that starts
    /// inside the window and ends outside it is the case a single-address
    /// check misses entirely — the transfer begins correctly and then writes
    /// past the mapping.
    pub const fn buffer_is_reachable(&self, cpu: CpuAddress, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let last = match cpu.0.checked_add(len - 1) {
            Some(l) => l,
            None => return false,
        };
        self.to_device(cpu).is_ok() && self.to_device(CpuAddress(last)).is_ok()
    }
}

/// Vectors one controller may hold.
pub const MAX_VECTORS_PER_CONTROLLER: usize = 32;

/// A controller's MSI-X vector allocation.
///
/// Scoped deliberately: a global pool lets one controller's teardown free a
/// vector another still has armed, and an interrupt then arrives for a device
/// that has stopped expecting it — indistinguishable from a spurious IRQ.
#[derive(Debug)]
pub struct VectorPool {
    /// First vector this controller owns.
    base: u16,
    /// How many it owns.
    count: u16,
    /// Bit per owned vector.
    allocated: u32,
}

/// Why a vector request failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorError {
    /// Every vector in this controller's range is in use.
    Exhausted,
    /// The vector is not in this controller's range.
    NotOwned,
    /// The vector is not currently allocated.
    NotAllocated,
    /// The range is empty or wider than a pool can track.
    InvalidRange,
}

impl VectorPool {
    /// A pool over `count` vectors starting at `base`.
    pub const fn new(base: u16, count: u16) -> Result<Self, VectorError> {
        if count == 0 || count as usize > MAX_VECTORS_PER_CONTROLLER {
            return Err(VectorError::InvalidRange);
        }
        Ok(Self {
            base,
            count,
            allocated: 0,
        })
    }

    /// Whether `vector` belongs to this controller.
    ///
    /// The check that makes scoping real: freeing another controller's vector
    /// is refused rather than silently clearing a bit in the wrong pool.
    pub const fn owns(&self, vector: u16) -> bool {
        vector >= self.base && (vector - self.base) < self.count
    }

    /// Allocate the lowest free vector.
    pub fn allocate(&mut self) -> Result<u16, VectorError> {
        for i in 0..self.count {
            let bit = 1u32 << i;
            if self.allocated & bit == 0 {
                self.allocated |= bit;
                return Ok(self.base + i);
            }
        }
        Err(VectorError::Exhausted)
    }

    /// Free one vector.
    pub fn free(&mut self, vector: u16) -> Result<(), VectorError> {
        if !self.owns(vector) {
            return Err(VectorError::NotOwned);
        }
        let bit = 1u32 << (vector - self.base);
        if self.allocated & bit == 0 {
            return Err(VectorError::NotAllocated);
        }
        self.allocated &= !bit;
        Ok(())
    }

    /// Free every vector this controller holds, returning how many.
    ///
    /// Teardown. A controller removed without it leaves vectors allocated
    /// that nothing will ever deliver to, and the pool cannot be reused.
    pub fn free_all(&mut self) -> usize {
        let n = self.allocated.count_ones() as usize;
        self.allocated = 0;
        n
    }

    /// Vectors currently allocated.
    pub const fn live(&self) -> u32 {
        self.allocated.count_ones()
    }

    /// Whether nothing is outstanding — for an assertion at teardown.
    pub const fn is_empty(&self) -> bool {
        self.allocated == 0
    }
}

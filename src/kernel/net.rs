//! Network Subsystem — pure slot management and opaque state storage.
//!
//! The kernel provides:
//! - Network interface slot registry (up to MAX_NETIFS slots)
//! - Opaque u8 state storage (meaning defined entirely by modules)
//! - Single IOCTL: cmd=1 (SET_STATE) stores raw u8 value
//!
//! All networking logic (drivers, protocol stacks, configuration)
//! lives in PIC modules. Interface type values and state values are
//! module-defined protocol — the kernel stores them without interpretation.

use portable_atomic::{AtomicU8, AtomicU32, AtomicBool, Ordering};

use crate::kernel::errno;

// ============================================================================
// Network Interface Slot
// ============================================================================

/// Maximum network interfaces
pub const MAX_NETIFS: usize = 4;

/// Network interface slot
///
/// Stores slot management and opaque state only. The kernel never
/// interprets state or provider_type values — modules own all semantics.
pub struct NetIfSlot {
    /// Current state (opaque u8, meaning defined by modules)
    state: AtomicU8,
    /// Interface type (opaque, module-defined)
    if_type: AtomicU8,
    /// Provider type (opaque u8: 1=frame by convention)
    provider_type: AtomicU8,
    /// In use flag
    in_use: AtomicBool,
    /// Channel handle for frame providers (-1 if none)
    provider_channel: AtomicU32,
}

impl NetIfSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            if_type: AtomicU8::new(0),
            provider_type: AtomicU8::new(0),
            in_use: AtomicBool::new(false),
            provider_channel: AtomicU32::new(0xFFFFFFFF),
        }
    }

    /// Get raw state value (opaque u8).
    pub fn state_raw(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    /// Set raw state value (opaque u8).
    pub fn set_state_raw(&self, state: u8) {
        self.state.store(state, Ordering::Release);
    }

    /// Get interface type (opaque u8, module-defined).
    /// Returns 0 if slot is not in use.
    pub fn if_type_raw(&self) -> u8 {
        if !self.in_use.load(Ordering::Acquire) {
            return 0;
        }
        self.if_type.load(Ordering::Acquire)
    }

    /// Get provider type (opaque u8: 1=frame by convention).
    pub fn provider_type_raw(&self) -> u8 {
        self.provider_type.load(Ordering::Acquire)
    }

    pub fn provider_channel(&self) -> i32 {
        self.provider_channel.load(Ordering::Acquire) as i32
    }

    pub fn is_free(&self) -> bool {
        !self.in_use.load(Ordering::Acquire)
    }

    /// Try to allocate this slot with given type and provider type.
    fn try_allocate(&self, if_type: u8, provider_type: u8) -> bool {
        if self.in_use.compare_exchange(
            false,
            true,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ).is_ok() {
            self.if_type.store(if_type, Ordering::Release);
            self.provider_type.store(provider_type, Ordering::Release);
            self.state.store(0, Ordering::Release);
            true
        } else {
            false
        }
    }

    pub fn reset(&self) {
        self.state.store(0, Ordering::Release);
        self.if_type.store(0, Ordering::Release);
        self.provider_type.store(0, Ordering::Release);
        self.provider_channel.store(0xFFFFFFFF, Ordering::Release);
        self.in_use.store(false, Ordering::Release);
    }

    pub fn set_provider_channel(&self, channel: i32) {
        self.provider_channel.store(channel as u32, Ordering::Release);
    }
}

impl Default for NetIfSlot {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Interface Registry
// ============================================================================

static NETIF_SLOTS: [NetIfSlot; MAX_NETIFS] = [
    NetIfSlot::new(),
    NetIfSlot::new(),
    NetIfSlot::new(),
    NetIfSlot::new(),
];

// ============================================================================
// IOCTL Commands
// ============================================================================

mod ioctl {
    /// Generic state transition. arg[0] = target state value (u8, opaque).
    pub const SET_STATE: u32 = 1;
}

// ============================================================================
// Error Codes
// ============================================================================

pub const NET_OK: i32 = errno::OK;
pub const NET_ERROR: i32 = errno::ERROR;
pub const NET_EINVAL: i32 = errno::EINVAL;
pub const NET_EBUSY: i32 = errno::EBUSY;
pub const NET_ENODEV: i32 = errno::ENODEV;

// ============================================================================
// Network Interface Service
// ============================================================================

/// Network interface service — pure slot management and opaque state storage.
///
/// All networking logic (drivers, protocol stacks, configuration) lives in PIC modules.
/// The kernel provides slot management and raw u8 state storage only.
pub struct NetIfService;

impl NetIfService {
    /// Open a network interface.
    ///
    /// `if_type` is an opaque module-defined value. All types are
    /// dynamically allocated to any free slot.
    pub fn open(if_type: u8) -> i32 {
        if if_type == 0 {
            return NET_EINVAL;
        }

        // First check if a slot with this type already exists.
        // This allows multiple modules to share a netif handle
        // (e.g. wifi policy module reading state of cyw43's netif).
        for i in 0..MAX_NETIFS {
            let slot = &NETIF_SLOTS[i];
            if !slot.is_free() && slot.if_type_raw() == if_type {
                return i as i32;
            }
        }

        // No existing slot — allocate a new one
        for i in 0..MAX_NETIFS {
            let slot = &NETIF_SLOTS[i];
            if slot.try_allocate(if_type, 1) {
                return i as i32;
            }
        }
        NET_EBUSY
    }

    /// Register a frame provider (PIC module that sends/receives raw frames).
    /// `if_type` is opaque (module-defined).
    pub fn register_frame_provider(if_type: u8, channel: i32) -> i32 {
        for i in 0..MAX_NETIFS {
            let slot = &NETIF_SLOTS[i];
            if slot.try_allocate(if_type, 1) { // provider_type 1 = frame
                slot.set_provider_channel(channel);
                return i as i32;
            }
        }
        NET_EBUSY
    }

    /// Close/unregister a network interface
    pub fn close(handle: i32) -> i32 {
        if let Some(slot) = Self::get_slot(handle) {
            slot.reset();
            NET_OK
        } else {
            NET_EINVAL
        }
    }

    /// Get interface state (raw u8, opaque)
    pub fn state(handle: i32) -> i32 {
        if let Some(slot) = Self::get_slot(handle) {
            slot.state_raw() as i32
        } else {
            NET_EINVAL
        }
    }

    /// Interface ioctl — raw u8 state storage.
    ///
    /// cmd=1 (SET_STATE): arg[0] is the target state value (opaque u8).
    /// All other commands return ENODEV.
    ///
    /// # Safety
    /// `arg` must be null or point to a valid buffer of at least 1 byte.
    pub unsafe fn ioctl(handle: i32, cmd: u32, arg: *mut u8) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return NET_EINVAL,
        };

        match cmd {
            ioctl::SET_STATE => {
                if arg.is_null() { return NET_EINVAL; }
                let state = *arg;
                slot.set_state_raw(state);
                NET_OK
            }
            _ => NET_ENODEV,
        }
    }

    fn get_slot(handle: i32) -> Option<&'static NetIfSlot> {
        if handle < 0 || handle >= MAX_NETIFS as i32 {
            return None;
        }
        let slot = &NETIF_SLOTS[handle as usize];
        if slot.is_free() {
            return None;
        }
        Some(slot)
    }

    /// Get slot for internal use
    pub fn get_slot_by_index(index: usize) -> Option<&'static NetIfSlot> {
        NETIF_SLOTS.get(index)
    }

}


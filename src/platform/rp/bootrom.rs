//! RP bootrom function lookup.
//!
//! The flash erase and program routines live in the chip's mask ROM, not in
//! our image — they must, because erasing flash makes the flash unreadable
//! and code executing from it would vanish mid-operation. Reaching them means
//! walking a table the bootrom publishes in its first few words.
//!
//! # The two chips do this differently
//!
//! Both publish a `rom_table_lookup` function pointer as a 16-bit value near
//! address zero, but at different offsets and **with different signatures**:
//!
//! - **RP2040** — pointer at `0x18`; called as `lookup(table, code)`, where
//!   `table` is a second pointer read from `0x14`.
//! - **RP2350 (Arm)** — pointer at `0x16`; called as `lookup(code, flags)`,
//!   with no table argument, and the flags say whether the caller is running
//!   secure or non-secure.
//!
//! Calling one form on the other chip passes the wrong number of arguments to
//! a real function pointer. The result is not a fault but a plausible-looking
//! return value, used as a function pointer, and jumped to — while flash is
//! disconnected and interrupts are off.
//!
//! The function *codes* are shared: two ASCII characters packed little-endian.

/// Pack a two-character bootrom table code.
///
/// `ROM_TABLE_CODE` in the SDK. Shared by both chips.
#[inline]
pub const fn table_code(c1: u8, c2: u8) -> u32 {
    (c1 as u32) | ((c2 as u32) << 8)
}

/// The bootrom functions this kernel calls.
///
/// Named rather than spelled at the call site: `table_code(b'R', b'E')` at
/// the point of use invites `b'E', b'R'`, which looks identical in review and
/// resolves to a different function or to nothing at all.
pub mod code {
    use super::table_code;

    /// `connect_internal_flash` — take the QSPI pads back from XIP.
    pub const CONNECT_INTERNAL_FLASH: u32 = table_code(b'I', b'F');
    /// `flash_exit_xip` — leave continuous-read mode.
    pub const FLASH_EXIT_XIP: u32 = table_code(b'E', b'X');
    /// `flash_range_erase`.
    pub const FLASH_RANGE_ERASE: u32 = table_code(b'R', b'E');
    /// `flash_range_program`.
    pub const FLASH_RANGE_PROGRAM: u32 = table_code(b'R', b'P');
    /// `flash_flush_cache` — discard the XIP cache so reads see new data.
    pub const FLASH_FLUSH_CACHE: u32 = table_code(b'F', b'C');
    /// `flash_enter_cmd_xip` — restore a basic XIP mode.
    pub const FLASH_ENTER_CMD_XIP: u32 = table_code(b'C', b'X');
    /// `reset_usb_boot` — RP2040's BOOTSEL entry.
    pub const RESET_USB_BOOT: u32 = table_code(b'U', b'B');
    /// `reboot` — RP2350's general reboot, which carries BOOTSEL as a type.
    pub const REBOOT: u32 = table_code(b'R', b'B');
    /// `get_sys_info` (RP2350): chip, boot and flash information.
    pub const GET_SYS_INFO: u32 = table_code(b'G', b'S');
}

/// Well-known addresses in the bootrom's header.
pub mod well_known {
    /// Pointer to the function table. RP2040 needs this as an argument to
    /// the lookup; RP2350 does not.
    pub const FUNC_TABLE: usize = 0x14;
    /// Pointer to `rom_table_lookup` on RP2350 (Arm) — **A2 silicon and
    /// later**, held as a 16-bit value.
    pub const TABLE_LOOKUP_RP2350_A2: usize = 0x16;
    /// Pointer to `rom_table_lookup` on RP2350 (Arm) — **A1 silicon**, held
    /// as a full 32-bit value at a different offset.
    ///
    /// A1 and A2 disagree about both where this lives and how wide it is.
    /// Reading the A2 location on an A1 part yields half of something else,
    /// and the `blx` that follows branches into whatever that happens to be
    /// — a HardFault before any handler has been installed to report it.
    pub const TABLE_LOOKUP_RP2350_A1: usize = 0x18;
    /// The bootrom's version number. `1` is A1 silicon; anything else is A2
    /// or later.
    pub const ROM_VERSION: usize = 0x13;
    /// Pointer to `rom_table_lookup` on RP2040.
    pub const TABLE_LOOKUP_RP2040: usize = 0x18;

    /// One past the last address the bootrom occupies: 16 KiB on RP2040,
    /// 32 KiB on RP2350, both mapped from zero.
    ///
    /// Every pointer read out of the header below is a bootrom function, so
    /// it lies inside this window. Checking that is what makes a header read
    /// from the wrong offset — the wrong silicon revision, a bootrom that
    /// publishes neither — a `None` instead of a `blx` into whatever the
    /// bytes happened to be, which faults before any handler is installed to
    /// report it.
    #[cfg(feature = "chip-rp2040")]
    pub const ROM_END: usize = 16 * 1024;
    /// One past the last address the bootrom occupies.
    #[cfg(not(feature = "chip-rp2040"))]
    pub const ROM_END: usize = 32 * 1024;
}

/// Whether `addr` could be a bootrom entry point.
///
/// Zero means the bootrom does not publish the entry. Anything at or beyond
/// the bootrom's own end is not one of its functions, whatever the header
/// offset it came from suggested.
#[cfg(feature = "rp")]
const fn is_rom_pointer(addr: usize) -> bool {
    addr != 0 && addr < well_known::ROM_END
}

/// RP2350 lookup flags: the caller is Arm code running secure.
///
/// Non-secure would be `0x0010`. This kernel runs secure — it owns the whole
/// part — so asking for the non-secure entry would return a pointer that
/// faults on call.
pub const RT_FLAG_FUNC_ARM_SEC: u32 = 0x0004;

#[cfg(feature = "rp")]
pub use rp::*;

#[cfg(feature = "rp")]
mod rp {
    #[cfg(not(feature = "chip-rp2040"))]
    use super::RT_FLAG_FUNC_ARM_SEC;
    use super::{is_rom_pointer, well_known};

    /// Read a 16-bit well-known pointer from the bootrom header.
    ///
    /// # Safety
    /// `addr` must be one of the [`well_known`] offsets.
    #[inline(always)]
    unsafe fn hword_as_ptr(addr: usize) -> usize {
        // SAFETY: the bootrom header is mapped from address zero on both
        // chips and is read-only; the caller passes a documented offset.
        unsafe { core::ptr::read_volatile(addr as *const u16) as usize }
    }

    /// The bootrom's version number. `1` is A1 silicon.
    ///
    /// # Safety
    /// Reads a fixed byte in the bootrom header, which is mapped and
    /// read-only from reset.
    #[cfg(not(feature = "chip-rp2040"))]
    #[inline(always)]
    #[link_section = ".data.ram_func"]
    unsafe fn rom_version() -> u8 {
        // SAFETY: the bootrom header is mapped from address zero.
        unsafe { core::ptr::read_volatile(well_known::ROM_VERSION as *const u8) }
    }

    /// Look up a bootrom function by code.
    ///
    /// Returns `None` when the bootrom does not publish it, which is a real
    /// possibility across bootrom revisions and is why this is not an
    /// `unwrap`: calling a null pointer with flash disconnected leaves no
    /// diagnostic at all.
    ///
    /// # Safety
    /// Must be callable with flash disconnected — this function and
    /// everything it touches is in RAM.
    #[inline(always)]
    #[link_section = ".data.ram_func"]
    pub unsafe fn lookup(code: u32) -> Option<usize> {
        let found = {
            #[cfg(feature = "chip-rp2040")]
            {
                // RP2040: lookup(table, code).
                type LookupFn = unsafe extern "C" fn(usize, u32) -> usize;
                // SAFETY: both pointers come from the bootrom's own header.
                unsafe {
                    let lookup_addr = hword_as_ptr(well_known::TABLE_LOOKUP_RP2040);
                    let table = hword_as_ptr(well_known::FUNC_TABLE);
                    if !is_rom_pointer(lookup_addr) || !is_rom_pointer(table) {
                        return None;
                    }
                    let f: LookupFn = core::mem::transmute(lookup_addr);
                    f(table, code)
                }
            }
            #[cfg(not(feature = "chip-rp2040"))]
            {
                // RP2350 (Arm): lookup(code, flags), no table argument.
                //
                // Where the pointer lives depends on the silicon revision,
                // and so does its width: A1 keeps a 32-bit value at 0x18,
                // A2 a 16-bit one at 0x16. The version byte at 0x13 is the
                // only thing that says which part this is — assuming either
                // reads a number that is not a function address on the
                // other, and branching to it faults with no handler yet
                // able to say so.
                type LookupFn = unsafe extern "C" fn(u32, u32) -> usize;
                // SAFETY: the pointer comes from the bootrom's own header.
                unsafe {
                    let lookup_addr = if rom_version() == 1 {
                        core::ptr::read_volatile(well_known::TABLE_LOOKUP_RP2350_A1 as *const u32)
                            as usize
                    } else {
                        hword_as_ptr(well_known::TABLE_LOOKUP_RP2350_A2)
                    };
                    if !is_rom_pointer(lookup_addr) {
                        return None;
                    }
                    let f: LookupFn = core::mem::transmute(lookup_addr);
                    f(code, RT_FLAG_FUNC_ARM_SEC)
                }
            }
        };
        if found == 0 {
            None
        } else {
            Some(found)
        }
    }

    /// The bootrom entry points a flash operation needs, resolved together.
    ///
    /// Resolved *before* flash is disconnected and carried into the critical
    /// section, so the lookup itself never runs with flash unavailable. All
    /// or nothing: a partial set would disconnect flash and then discover it
    /// cannot reconnect it.
    #[derive(Clone, Copy)]
    pub struct FlashRom {
        /// `connect_internal_flash()`.
        pub connect: unsafe extern "C" fn(),
        /// `flash_exit_xip()`.
        pub exit_xip: unsafe extern "C" fn(),
        /// `flash_flush_cache()`.
        pub flush_cache: unsafe extern "C" fn(),
    }

    /// `flash_range_erase(offset, count, block_size, block_cmd)`.
    pub type EraseFn = unsafe extern "C" fn(u32, usize, u32, u8);
    /// `flash_range_program(offset, data, count)`.
    pub type ProgramFn = unsafe extern "C" fn(u32, *const u8, usize);

    impl FlashRom {
        /// Resolve the common entry points, or `None` if any is missing.
        pub fn resolve() -> Option<Self> {
            use super::code;
            // SAFETY: reading the bootrom header; flash is still connected.
            unsafe {
                Some(Self {
                    connect: core::mem::transmute::<usize, unsafe extern "C" fn()>(lookup(
                        code::CONNECT_INTERNAL_FLASH,
                    )?),
                    exit_xip: core::mem::transmute::<usize, unsafe extern "C" fn()>(lookup(
                        code::FLASH_EXIT_XIP,
                    )?),
                    flush_cache: core::mem::transmute::<usize, unsafe extern "C" fn()>(lookup(
                        code::FLASH_FLUSH_CACHE,
                    )?),
                })
            }
        }
    }

    /// Resolve `flash_range_erase`.
    pub fn erase_fn() -> Option<EraseFn> {
        // SAFETY: as `FlashRom::resolve`.
        unsafe { lookup(super::code::FLASH_RANGE_ERASE).map(|p| core::mem::transmute(p)) }
    }

    /// Resolve `flash_range_program`.
    pub fn program_fn() -> Option<ProgramFn> {
        // SAFETY: as `FlashRom::resolve`.
        unsafe { lookup(super::code::FLASH_RANGE_PROGRAM).map(|p| core::mem::transmute(p)) }
    }
}

// ============================================================================
// BOOTSEL entry
// ============================================================================

/// Interface-disable flags for BOOTSEL entry.
///
/// **PICOBOOT must stay enabled.** It is the interface `picotool` speaks, so
/// disabling it leaves a board that entered BOOTSEL but cannot be driven by
/// host tooling — which is precisely the recovery path this exists to
/// provide.
pub mod bootsel_flags {
    /// Hide the mass-storage (drag-and-drop UF2) interface.
    pub const DISABLE_MSD: u32 = 0x01;
    /// Hide the PICOBOOT interface. Never set by [`super::enter_bootsel`].
    pub const DISABLE_PICOBOOT: u32 = 0x02;
}

/// RP2350 `reboot` flags. RP2040 reaches BOOTSEL through `reset_usb_boot`
/// instead and has no use for them, and a host build has no bootrom at all —
/// the earlier gate covered only the first of those.
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
mod reboot_flags {
    /// Reboot into BOOTSEL. `p0` is a GPIO pin number, `p1` the BOOTSEL
    /// flags.
    /// Reboot into the application in flash.
    pub const TYPE_NORMAL: u32 = 0x0;
    pub const TYPE_BOOTSEL: u32 = 0x2;
    /// Do not return if the reboot was successfully initiated. The watchdog
    /// is asynchronous, so without this the call returns and the caller runs
    /// on for an indeterminate time before the reset lands.
    pub const NO_RETURN_ON_SUCCESS: u32 = 0x100;
    /// How long the bootrom is asked to wait before the reset lands.
    ///
    /// **Not zero.** The SDK passes 10 ms and that is the only value with
    /// any field evidence behind it. A zero delay asks for a reset scheduled
    /// for right now, which does not survive the rest of the bootrom's own
    /// teardown — the call comes back instead of rebooting, and a caller
    /// that treats "did not return" as the success path simply stops.
    pub const BOOTSEL_DELAY_MS: u32 = 10;
}

#[cfg(feature = "rp")]
pub use bootsel::*;

#[cfg(feature = "rp")]
mod bootsel {
    #[cfg(not(feature = "chip-rp2040"))]
    use super::reboot_flags;
    use super::{bootsel_flags, code};

    /// Enter ROM BOOTSEL, exposing PICOBOOT so host tooling can take over.
    ///
    /// `disable_msd` hides the drag-and-drop UF2 volume, which is worth doing
    /// for an automated rig — a mass-storage device appearing on a host can
    /// trigger indexers and automounters that interfere with the PICOBOOT
    /// session. PICOBOOT itself is never disabled.
    ///
    /// Returns only on failure. A bootrom that does not publish the entry
    /// point cannot be made to, so the caller is told rather than left
    /// believing a reset is coming.
    ///
    /// The two chips get here by different routes: RP2040 has a dedicated
    /// `reset_usb_boot`, while RP2350 folds it into a general `reboot` with a
    /// boot-type flag. Same outcome, different function and different
    /// argument shape — calling one form on the other passes the wrong
    /// arguments to a real function pointer.
    pub fn enter_bootsel(disable_msd: bool) -> Result<core::convert::Infallible, BootselError> {
        let interface_flags = if disable_msd {
            bootsel_flags::DISABLE_MSD
        } else {
            0
        };

        #[cfg(feature = "chip-rp2040")]
        {
            // reset_usb_boot(usb_activity_gpio_pin_mask, disable_interface_mask)
            type ResetUsbBootFn = unsafe extern "C" fn(u32, u32) -> !;
            // SAFETY: resolved from the bootrom's own table; the function
            // does not return, which its type states.
            unsafe {
                let Some(p) = super::lookup(code::RESET_USB_BOOT) else {
                    return Err(BootselError::NotPublished);
                };
                let f: ResetUsbBootFn = core::mem::transmute(p);
                f(0, interface_flags)
            }
        }
        #[cfg(not(feature = "chip-rp2040"))]
        {
            // reboot(flags, delay_ms, p0, p1)
            type RebootFn = unsafe extern "C" fn(u32, u32, u32, u32) -> i32;
            // SAFETY: as above. This one *can* return — it reports an error
            // rather than rebooting if the request is refused.
            let rc = unsafe {
                let Some(p) = super::lookup(code::REBOOT) else {
                    return Err(BootselError::NotPublished);
                };
                let f: RebootFn = core::mem::transmute(p);
                f(
                    reboot_flags::TYPE_BOOTSEL | reboot_flags::NO_RETURN_ON_SUCCESS,
                    reboot_flags::BOOTSEL_DELAY_MS,
                    // `p0` carries the BOOTSEL interface flags and `p1` the
                    // activity GPIO. That is the order the SDK's own call
                    // site passes them in, which is what the ROM reads;
                    // the header's comment beside the constant describes
                    // them the other way round.
                    interface_flags,
                    // No activity GPIO: BOOTSEL_FLAG_GPIO_PIN_SPECIFIED is
                    // not set, so this is ignored.
                    0,
                )
            };
            Err(BootselError::Refused(rc))
        }
    }

    /// Reboot into the application in flash, as `picotool reboot` asks.
    ///
    /// Returns only on failure, like [`enter_bootsel`]. RP2350's bootrom
    /// has a general `reboot` with a "normal" type; RP2040's has none, so
    /// there the watchdog is armed with every block selected for reset and
    /// triggered — the SDK's `watchdog_reboot(0, 0, ..)`.
    pub fn reboot_to_flash() -> Result<core::convert::Infallible, BootselError> {
        #[cfg(feature = "chip-rp2040")]
        {
            use crate::platform::chip::{PSM_WDSEL, PSM_WDSEL_MASK, WATCHDOG_CTRL};
            use crate::platform::rp_regs::{modify32, write32};
            const TRIGGER: u32 = 1 << 31;
            // SAFETY: fixed MMIO registers generated from the silicon TOML;
            // single boot thread. Selecting every block but the oscillators
            // is what makes the watchdog reset a whole-chip reset.
            unsafe {
                write32(PSM_WDSEL as usize, PSM_WDSEL_MASK);
                modify32(WATCHDOG_CTRL as usize, |v| v | TRIGGER);
            }
            loop {
                crate::arch::cortex_m::nop();
            }
        }
        #[cfg(not(feature = "chip-rp2040"))]
        {
            type RebootFn = unsafe extern "C" fn(u32, u32, u32, u32) -> i32;
            // SAFETY: resolved from the bootrom's own table; may return with
            // an error, which is reported rather than treated as a reboot.
            let rc = unsafe {
                let Some(p) = super::lookup(code::REBOOT) else {
                    return Err(BootselError::NotPublished);
                };
                let f: RebootFn = core::mem::transmute(p);
                f(
                    reboot_flags::TYPE_NORMAL | reboot_flags::NO_RETURN_ON_SUCCESS,
                    reboot_flags::BOOTSEL_DELAY_MS,
                    0,
                    0,
                )
            };
            Err(BootselError::Refused(rc))
        }
    }

    /// The chip's unique 64-bit ID, as the ROM's own USB serial reports it.
    ///
    /// Formatted as sixteen upper-case hex digits this is the serial the
    /// bootrom presents in BOOTSEL, which is what `picotool` uses to find a
    /// board again after asking it to reboot: a running device without the
    /// same serial is one picotool can reboot but never re-find. The bytes
    /// are the SDK's `pico_get_unique_board_id` ordering — the two words
    /// after the package word of `SYS_INFO_CHIP_INFO`, most significant
    /// first — so the two strings are equal.
    ///
    /// `None` on RP2040, whose ID lives in the flash device and needs the
    /// flash's own RUID command rather than a ROM call.
    pub fn unique_id() -> Option<u64> {
        #[cfg(feature = "chip-rp2040")]
        {
            None
        }
        #[cfg(not(feature = "chip-rp2040"))]
        {
            const SYS_INFO_CHIP_INFO: u32 = 0x0001;
            type GetSysInfoFn = unsafe extern "C" fn(*mut u32, u32, u32) -> i32;
            let mut words = [0u32; 9];
            // SAFETY: resolved from the bootrom's own table; the buffer is
            // nine words, which is what the SDK passes for every flag.
            let rc = unsafe {
                let p = super::lookup(code::GET_SYS_INFO)?;
                let f: GetSysInfoFn = core::mem::transmute(p);
                f(words.as_mut_ptr(), words.len() as u32, SYS_INFO_CHIP_INFO)
            };
            // Four words back: the flags echoed, package, then the two ID
            // words. Anything else is a ROM this code does not understand.
            if rc != 4 {
                return None;
            }
            Some((u64::from(words[3]) << 32) | u64::from(words[2]))
        }
    }

    /// Why BOOTSEL entry failed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BootselError {
        /// The bootrom does not publish the entry point.
        NotPublished,
        /// The bootrom refused, with its own error code.
        Refused(i32),
    }
}

//! RP runtime IO support.

pub mod gpio {
    //! Runtime GPIO registry with dynamic pin configuration.
    //!
    //! Trades compile-time pin types for runtime handles using AnyPin.
    //! Allows full GPIO configuration from config without hard-coded pin types.

    use portable_atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};

    use crate::kernel::sys::errno;

    /// Maximum GPIO pins on RP2350B (superset for array sizing).
    /// Always 48 — runtime detection gates which pins are usable.
    pub const MAX_GPIO: usize = 48;

    /// Runtime GPIO limit set at boot from config target.
    /// RP2350A (QFN-60): 30 pins (0-29), RP2350B (QFN-80): 48 pins (0-47).
    static RUNTIME_MAX_GPIO: AtomicU8 = AtomicU8::new(48);

    /// Set runtime GPIO limit (called once at boot from config target).
    pub fn set_runtime_max_gpio(max: u8) {
        RUNTIME_MAX_GPIO.store(max, Ordering::Release);
    }

    /// Get runtime GPIO limit.
    pub fn runtime_max_gpio() -> u8 {
        RUNTIME_MAX_GPIO.load(Ordering::Acquire)
    }

    use crate::platform::rp_gpio_regs as gpio_regs;

    /// IO_BANK0 `FUNCSEL` for software control of a pin (SIO).
    const FUNCSEL_SIO: u32 = 5;
    /// `FUNCSEL` 31 releases the pin from every peripheral.
    const FUNCSEL_NONE: u32 = 31;

    /// Pin mode/direction
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum PinMode {
        Unconfigured = 0,
        Input = 1,
        Output = 2,
        // Future: Pio, Spi, I2c, Uart, Pwm for alt functions
    }

    /// Pull configuration
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum PinPull {
        None = 0,
        Up = 1,
        Down = 2,
    }

    impl PinPull {
        /// Apply this pull to a pad configuration.
        ///
        /// Both bits set is a pad pulled in two directions at once — the
        /// hardware permits it and the result is a weak divider rather than
        /// a defined level, so the two are set from one choice.
        fn apply(self, cfg: gpio_regs::PadConfig) -> gpio_regs::PadConfig {
            cfg.pull_up(matches!(self, PinPull::Up))
                .pull_down(matches!(self, PinPull::Down))
        }
    }

    /// A GPIO slot holding runtime pin state.
    ///
    /// Holds the pin's *configuration*, not a handle to it: ownership is
    /// `CLAIMED`, and nothing else needs to duplicate it.
    struct GpioSlot {
        /// Current mode.
        mode: PinMode,
        /// Current pull setting.
        pull: PinPull,
    }

    impl GpioSlot {
        const fn new() -> Self {
            Self {
                mode: PinMode::Unconfigured,
                pull: PinPull::None,
            }
        }
    }

    /// Claimed status for each pin (atomic for thread safety)
    static CLAIMED: [AtomicBool; MAX_GPIO] = [const { AtomicBool::new(false) }; MAX_GPIO];

    /// Owner module index for each pin (0xFF = kernel/unowned).
    /// Set by syscall entry points when a module claims a pin.
    /// Kernel-claimed pins (via init_from_config) keep the default 0xFF.
    const OWNER_KERNEL: u8 = 0xFF;
    static OWNER: [AtomicU8; MAX_GPIO] = [const { AtomicU8::new(OWNER_KERNEL) }; MAX_GPIO];

    /// Intended owner for each pin (set by init_from_config, consumed at module instantiation).
    /// 0xFF = kernel-owned (no handoff), 0-7 = module index to grant to.
    /// This is a staging area: init_from_config stores the intended owner here,
    /// and grant_pending_pins() transfers ownership when the module is instantiated.
    static PENDING_OWNER: [AtomicU8; MAX_GPIO] = [const { AtomicU8::new(OWNER_KERNEL) }; MAX_GPIO];

    /// GPIO slots — one per pin.
    ///
    /// # Safety
    ///
    /// `static mut` is technically UB for shared access under Rust's memory model.
    /// This is sound here because the platform is single-core and synchronous:
    /// syscalls run inside the scheduler tick and cannot
    /// preempt each other.  Each slot is further guarded by `CLAIMED`, ensuring
    /// only one logical owner accesses a slot at a time.  If the executor ever
    /// becomes multi-core or preemptive, these must be wrapped in
    /// `Mutex<CriticalSectionRawMutex, _>`.
    static mut SLOTS: [GpioSlot; MAX_GPIO] = [const { GpioSlot::new() }; MAX_GPIO];

    /// Validate handle and return the index plus a mutable reference to the slot.
    ///
    /// Returns `Err(ERROR)` for invalid handle, `Err(EAGAIN)` if not claimed.
    unsafe fn claimed_slot_mut(handle: i32) -> Result<(usize, &'static mut GpioSlot), i32> {
        if handle < 0 || handle as usize >= MAX_GPIO {
            return Err(errno::ERROR);
        }
        let idx = handle as usize;
        if !CLAIMED[idx].load(Ordering::Acquire) {
            return Err(errno::EAGAIN);
        }
        Ok((idx, &mut SLOTS[idx]))
    }

    /// Claim a GPIO pin by number.
    ///
    /// Returns handle (same as pin number) on success, or:
    /// - `ERROR` if pin number invalid
    /// - `EAGAIN` if already claimed
    pub fn gpio_claim(pin_num: u8) -> i32 {
        if pin_num >= runtime_max_gpio() {
            log::error!(
                "[gpio] claim pin {} rejected: max={}",
                pin_num,
                runtime_max_gpio()
            );
            return errno::ERROR;
        }

        // Atomic claim
        if CLAIMED[pin_num as usize]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            log::warn!("[gpio] pin {pin_num} already claimed");
            return errno::EAGAIN;
        }

        pin_num as i32
    }

    /// Release a GPIO pin.
    ///
    /// Returns 0 on success, `ERROR` if invalid handle or not claimed.
    pub fn gpio_release(handle: i32) -> i32 {
        if handle < 0 || handle as usize >= MAX_GPIO {
            return errno::ERROR;
        }

        let idx = handle as usize;
        if !CLAIMED[idx].load(Ordering::Acquire) {
            return errno::ERROR;
        }

        // SAFETY: SLOTS is mutated only by claim/release helpers under the
        // CLAIMED atomic guard; `idx` is range-checked above.
        unsafe {
            SLOTS[idx].mode = PinMode::Unconfigured;
            SLOTS[idx].mode = PinMode::Unconfigured;
        }

        CLAIMED[idx].store(false, Ordering::Release);
        OWNER[idx].store(OWNER_KERNEL, Ordering::Release);
        0
    }

    /// Check if a pin is claimed.
    pub fn gpio_is_claimed(pin_num: u8) -> bool {
        if pin_num as usize >= MAX_GPIO {
            return false;
        }
        CLAIMED[pin_num as usize].load(Ordering::Acquire)
    }

    /// Set the owner module for a GPIO pin.
    /// Called from syscall entry points after a successful claim.
    pub fn gpio_set_owner(pin_num: u8, owner: u8) {
        if (pin_num as usize) < MAX_GPIO {
            OWNER[pin_num as usize].store(owner, Ordering::Release);
        }
    }

    /// Check if the current module owns the given GPIO handle.
    ///
    /// Returns true if:
    ///   - the pin is kernel-owned (owner == 0xFF) — allows kernel internal use
    ///   - the pin is owned by the currently executing module
    ///
    /// Returns false otherwise (another module owns this pin).
    pub fn gpio_check_owner(handle: i32) -> bool {
        if handle < 0 || handle as usize >= MAX_GPIO {
            return false;
        }
        let owner = OWNER[handle as usize].load(Ordering::Acquire);
        owner == OWNER_KERNEL
            || owner == crate::kernel::exec::scheduler::current_module_index() as u8
    }

    /// Release all GPIO pins owned by a specific module.
    /// Called on module termination to prevent resource leaks.
    pub fn release_owned_by(module_idx: u8) {
        for i in 0..MAX_GPIO {
            if OWNER[i].load(Ordering::Acquire) == module_idx && CLAIMED[i].load(Ordering::Acquire)
            {
                // SAFETY: IRQ_EDGE_CONFIG indexed by `i` (< MAX_GPIO from loop bound);
                // gated by CLAIMED + module-owner check above.
                unsafe {
                    IRQ_EDGE_CONFIG[i] = 0;
                }
                EDGE_ACTIVE_MASK[edge_word(i)].fetch_and(!edge_bit(i), Ordering::Release);
                GPIO_EVENT_BINDING[i].store(-1, Ordering::Release);
                // SAFETY: SLOTS[i] mutated only while CLAIMED guard is true;
                // `i` is bounded by the MAX_GPIO loop.
                unsafe {
                    SLOTS[i].mode = PinMode::Unconfigured;
                    SLOTS[i].mode = PinMode::Unconfigured;
                }
                CLAIMED[i].store(false, Ordering::Release);
                OWNER[i].store(OWNER_KERNEL, Ordering::Release);
            }
        }
    }

    /// Grant all pending GPIO pins to a module. Called during module instantiation.
    ///
    /// For each pin where PENDING_OWNER matches module_idx:
    /// - Transfers ownership from kernel (0xFF) to the module
    /// - Clears the pending owner flag
    ///
    /// After this, the module owns the pin and can use it without calling GPIO::CLAIM.
    /// The pin was already configured (direction, pull, initial level) by init_from_config().
    pub fn grant_pending_pins(module_idx: u8) {
        for pin in 0..MAX_GPIO {
            let pending = PENDING_OWNER[pin].load(Ordering::Acquire);
            if pending == module_idx && CLAIMED[pin].load(Ordering::Acquire) {
                // Transfer ownership from kernel to module
                OWNER[pin].store(module_idx, Ordering::Release);
                // Clear pending (0xFF = no pending handoff)
                PENDING_OWNER[pin].store(OWNER_KERNEL, Ordering::Release);
            }
        }
    }

    /// Set pin mode (input/output).
    ///
    /// For `Input` and `Unconfigured` modes, `initial_level` is ignored.
    ///
    /// Returns 0 on success, or:
    /// - `ERROR` if invalid handle
    /// - `EAGAIN` if not claimed
    pub fn gpio_set_mode(handle: i32, mode: PinMode, initial_level: bool) -> i32 {
        // SAFETY: `claimed_slot_mut` validates the handle and CLAIMED guard
        // before returning the &mut; serial caller path (kernel scheduler thread).
        let (idx, slot) = match unsafe { claimed_slot_mut(handle) } {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[gpio] set_mode invalid handle={handle}");
                return e;
            }
        };

        let pin = idx as u8;
        // SAFETY: the pin is claimed (CLAIMED guard) and this is the only
        // path that configures it.
        unsafe {
            match mode {
                PinMode::Output => {
                    // Level before output-enable, so the pin never briefly
                    // drives the wrong value at whatever is attached.
                    gpio_regs::set_function(pin, FUNCSEL_SIO);
                    gpio_regs::set_pad_output(pin, gpio_regs::Drive::Ma4);
                    gpio_regs::set_level(pin, initial_level);
                    gpio_regs::set_output_enable(pin, true);
                }
                PinMode::Input => {
                    gpio_regs::set_function(pin, FUNCSEL_SIO);
                    let cfg = slot
                        .pull
                        .apply(gpio_regs::PadConfig::default().input_enable(true));
                    gpio_regs::write_pad(pin, cfg);
                    gpio_regs::set_output_enable(pin, false);
                }
                PinMode::Unconfigured => {
                    // Stop driving before anything else: a pin left as an
                    // output while its function changes can contend with
                    // whatever the new function drives.
                    gpio_regs::set_output_enable(pin, false);
                    gpio_regs::set_function(pin, FUNCSEL_NONE);
                }
            }
        }

        slot.mode = mode;
        0
    }

    /// Set pull configuration.
    ///
    /// Stores the pull setting. If the pin is already an input, the pad is
    /// rewritten immediately; otherwise the setting takes effect on the next
    /// `gpio_set_mode(..., Input, ...)` call.
    ///
    /// Returns 0 on success, `ERROR` if invalid handle, `EAGAIN` if not claimed.
    pub fn gpio_set_pull(handle: i32, pull: PinPull) -> i32 {
        // SAFETY: handle validated by claimed_slot_mut.
        let (idx, slot) = match unsafe { claimed_slot_mut(handle) } {
            Ok(v) => v,
            Err(e) => return e,
        };

        slot.pull = pull;

        // Already an input: rewrite the pad now. Otherwise the stored
        // setting is applied the next time the pin becomes one.
        if slot.mode == PinMode::Input {
            let cfg = pull.apply(gpio_regs::PadConfig::default().input_enable(true));
            // SAFETY: the pin is claimed and currently an input.
            unsafe { gpio_regs::write_pad(idx as u8, cfg) };
        }

        0
    }

    /// Set output level.
    ///
    /// Returns 0 on success, `ERROR` if invalid, `EAGAIN` if not claimed,
    /// `ENOTSUP` if not in output mode.
    pub fn gpio_set_level(handle: i32, high: bool) -> i32 {
        // SAFETY: handle validated by claimed_slot_mut.
        let (idx, slot) = match unsafe { claimed_slot_mut(handle) } {
            Ok(v) => v,
            Err(e) => return e,
        };

        if slot.mode == PinMode::Output {
            // SAFETY: the pin is claimed and configured as an output.
            unsafe { gpio_regs::set_level(idx as u8, high) };
            0
        } else {
            errno::ENOTSUP // Not in output mode
        }
    }

    /// Get input level.
    ///
    /// Returns 1 if high, 0 if low, or:
    /// - `ERROR` if invalid handle
    /// - `EAGAIN` if not claimed
    /// - `ENOTSUP` if not in input mode
    pub fn gpio_get_level(handle: i32) -> i32 {
        // SAFETY: handle validated by claimed_slot_mut.
        let (idx, slot) = match unsafe { claimed_slot_mut(handle) } {
            Ok(v) => v,
            Err(e) => return e,
        };

        if slot.mode == PinMode::Input {
            // SAFETY: the pin is claimed and configured as an input.
            if unsafe { gpio_regs::read_level(idx as u8) } {
                1
            } else {
                0
            }
        } else {
            errno::ENOTSUP // Not in input mode
        }
    }

    /// Get current mode of a claimed pin.
    pub fn gpio_get_mode(handle: i32) -> PinMode {
        // SAFETY: handle validated by claimed_slot_mut.
        match unsafe { claimed_slot_mut(handle) } {
            Ok((_idx, slot)) => slot.mode,
            Err(_) => PinMode::Unconfigured,
        }
    }

    // ============================================================================
    // Syscall wrappers (extern "C" for PIC modules)
    // ============================================================================

    /// Syscall: claim GPIO pin
    ///
    /// # Safety
    /// `extern "C"` syscall ABI shim. Takes no pointers; marked
    /// `unsafe` only to match the syscall-table signature.
    pub unsafe extern "C" fn syscall_gpio_claim(pin_num: u8) -> i32 {
        gpio_claim(pin_num)
    }

    /// Syscall: release GPIO pin
    ///
    /// # Safety
    /// `extern "C"` syscall ABI shim. Takes no pointers; marked
    /// `unsafe` only to match the syscall-table signature. The
    /// underlying `gpio_release` checks ownership before unmapping.
    pub unsafe extern "C" fn syscall_gpio_release(handle: i32) -> i32 {
        gpio_release(handle)
    }

    /// Syscall: set pin mode
    /// mode: 1=input, 2=output
    /// initial_level: for outputs, 0=low, 1=high
    ///
    /// # Safety
    /// `extern "C"` syscall ABI shim. Takes no pointers; marked
    /// `unsafe` only to match the syscall-table signature.
    pub unsafe extern "C" fn syscall_gpio_set_mode(
        handle: i32,
        mode: u8,
        initial_level: u8,
    ) -> i32 {
        let pin_mode = match mode {
            1 => PinMode::Input,
            2 => PinMode::Output,
            _ => return errno::ERROR,
        };
        gpio_set_mode(handle, pin_mode, initial_level != 0)
    }

    /// Syscall: set pull configuration
    /// pull: 0=none, 1=up, 2=down
    ///
    /// # Safety
    /// `extern "C"` syscall ABI shim. Takes no pointers; marked
    /// `unsafe` only to match the syscall-table signature.
    pub unsafe extern "C" fn syscall_gpio_set_pull(handle: i32, pull: u8) -> i32 {
        let pin_pull = match pull {
            0 => PinPull::None,
            1 => PinPull::Up,
            2 => PinPull::Down,
            _ => return errno::ERROR,
        };
        gpio_set_pull(handle, pin_pull)
    }

    /// Syscall: set output level
    ///
    /// # Safety
    /// `extern "C"` syscall ABI shim. Takes no pointers; marked
    /// `unsafe` only to match the syscall-table signature.
    pub unsafe extern "C" fn syscall_gpio_set_level(handle: i32, high: u8) -> i32 {
        gpio_set_level(handle, high != 0)
    }

    /// Syscall: get input level
    ///
    /// # Safety
    /// `extern "C"` syscall ABI shim. Takes no pointers; marked
    /// `unsafe` only to match the syscall-table signature.
    pub unsafe extern "C" fn syscall_gpio_get_level(handle: i32) -> i32 {
        gpio_get_level(handle)
    }

    // ============================================================================
    // Software-polled GPIO edge detection
    // ============================================================================
    //
    // Per-pin edge interest + last-level tracking. poll_gpio_edges() is called
    // once per scheduler tick (~1ms) and compares current vs last level, setting
    // pending flags when edges match registered interest.

    /// Edge interest: 0=disabled, 1=rising, 2=falling, 3=both
    static mut IRQ_EDGE_CONFIG: [u8; MAX_GPIO] = [0; MAX_GPIO];
    /// Last observed level for each pin (for edge detection)
    static mut LAST_LEVEL: [u8; MAX_GPIO] = [0; MAX_GPIO];
    /// Pending edge flags: bit 0 = rising detected, bit 1 = falling detected
    static mut IRQ_PENDING: [u8; MAX_GPIO] = [0; MAX_GPIO];

    /// Bitmask of pins with active edge detection. Bit N set = pin N has
    /// non-zero IRQ_EDGE_CONFIG. Two words cover GPIO 0-31 and 32-47.
    /// Avoids iterating all MAX_GPIO pins every tick.
    static EDGE_ACTIVE_MASK: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];

    /// Which word of EDGE_ACTIVE_MASK a pin belongs to.
    #[inline(always)]
    fn edge_word(pin: usize) -> usize {
        pin >> 5
    }

    /// Bit position within a word of EDGE_ACTIVE_MASK.
    #[inline(always)]
    fn edge_bit(pin: usize) -> u32 {
        1u32 << (pin & 31)
    }

    /// Event handle bound to each GPIO pin for edge-triggered event signaling.
    /// -1 = no binding. Read by poll_gpio_edges(). Set by gpio_watch_edge().
    static GPIO_EVENT_BINDING: [AtomicI32; MAX_GPIO] = [const { AtomicI32::new(-1) }; MAX_GPIO];

    // Edge interest constants — re-exported from abi::gpio_edge.
    pub use crate::abi::contracts::hal::gpio::edge::BOTH as EDGE_BOTH;
    pub use crate::abi::contracts::hal::gpio::edge::FALLING as EDGE_FALLING;
    pub use crate::abi::contracts::hal::gpio::edge::NONE as EDGE_NONE;
    pub use crate::abi::contracts::hal::gpio::edge::RISING as EDGE_RISING;

    /// Set edge detection interest for a claimed pin.
    /// edge: 0=disable, 1=rising, 2=falling, 3=both
    pub fn gpio_set_irq(handle: i32, edge: u8) -> i32 {
        if handle < 0 || handle as usize >= MAX_GPIO {
            return errno::ERROR;
        }
        let idx = handle as usize;
        if !CLAIMED[idx].load(Ordering::Acquire) {
            return errno::EAGAIN;
        }
        if edge > 3 {
            return errno::EINVAL;
        }
        // SAFETY: IRQ_EDGE_CONFIG / IRQ_PENDING / LAST_LEVEL indexed by `idx`
        // (< MAX_GPIO). Mutation is serial: kernel scheduler thread only.
        unsafe {
            IRQ_EDGE_CONFIG[idx] = edge;
            IRQ_PENDING[idx] = 0;
            // Sample current level as baseline
            LAST_LEVEL[idx] = read_pin_level(idx);
        }
        // Update active mask
        if edge != 0 {
            EDGE_ACTIVE_MASK[edge_word(idx)].fetch_or(edge_bit(idx), Ordering::Release);
        } else {
            EDGE_ACTIVE_MASK[edge_word(idx)].fetch_and(!edge_bit(idx), Ordering::Release);
        }
        0
    }

    /// Poll and clear pending edge flags.
    /// Returns edge flags: bit 0 = rising, bit 1 = falling. 0 = no edge.
    pub fn gpio_poll_irq(handle: i32) -> i32 {
        if handle < 0 || handle as usize >= MAX_GPIO {
            return errno::ERROR;
        }
        let idx = handle as usize;
        if !CLAIMED[idx].load(Ordering::Acquire) {
            return errno::EAGAIN;
        }
        // SAFETY: IRQ_PENDING indexed by `idx` (< MAX_GPIO); serial scheduler thread.
        unsafe {
            let pending = IRQ_PENDING[idx];
            IRQ_PENDING[idx] = 0;
            pending as i32
        }
    }

    /// Read the raw level of a pin regardless of mode.
    /// Returns 0 or 1.
    unsafe fn read_pin_level(idx: usize) -> u8 {
        let slot = &SLOTS[idx];
        if slot.mode == PinMode::Input {
            // SAFETY: the pin is claimed and configured as an input.
            if unsafe { gpio_regs::read_level(idx as u8) } {
                1
            } else {
                0
            }
        } else if slot.mode == PinMode::Output {
            // SAFETY: as above; reports what the pin is driven to.
            if unsafe { gpio_regs::read_driven_level(idx as u8) } {
                1
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Poll GPIO pins with active edge interest. Called once per scheduler tick.
    /// Uses a bitmask to skip pins without edge detection — O(active pins) not O(MAX_GPIO).
    pub fn poll_gpio_edges() {
        // SAFETY: scheduler-thread-only entry point. `idx` is computed from
        // `word * 32 + bit_pos` where `bit_pos < 32`; `word` is the
        // EDGE_ACTIVE_MASK array index. EDGE_ACTIVE_MASK was sized so its
        // bits cover MAX_GPIO indices, so `idx < MAX_GPIO` for any set bit.
        // `IRQ_EDGE_CONFIG`/`IRQ_PENDING`/`LAST_LEVEL` are mutated only on
        // this thread (and gpio_set_irq, also kernel scheduler thread).
        unsafe {
            for (word, mask_atomic) in EDGE_ACTIVE_MASK.iter().enumerate() {
                let mut mask = mask_atomic.load(Ordering::Acquire);
                while mask != 0 {
                    let bit_pos = mask.trailing_zeros() as usize;
                    mask &= mask - 1; // clear lowest set bit
                    let idx = word * 32 + bit_pos;

                    let config = IRQ_EDGE_CONFIG[idx];
                    let current = read_pin_level(idx);
                    let last = LAST_LEVEL[idx];
                    if current != last {
                        let mut edge_detected = false;
                        if current > last && (config & EDGE_RISING) != 0 {
                            IRQ_PENDING[idx] |= EDGE_RISING;
                            edge_detected = true;
                        }
                        if current < last && (config & EDGE_FALLING) != 0 {
                            IRQ_PENDING[idx] |= EDGE_FALLING;
                            edge_detected = true;
                        }
                        LAST_LEVEL[idx] = current;
                        if edge_detected {
                            let evt = GPIO_EVENT_BINDING[idx].load(Ordering::Relaxed);
                            if evt >= 0 {
                                crate::kernel::ipc::event::event_signal(evt);
                            }
                        }
                    }
                }
            }
        }
    }

    // ============================================================================
    // Edge-to-event binding (GPIO provider owns the full lifecycle)
    // ============================================================================

    /// Bind an event to a GPIO pin's edge detection.
    /// pin: GPIO pin number, edge: 1=rising 2=falling 3=both, event_handle: tagged event fd.
    /// Caller (provider dispatch) must have already verified pin ownership.
    pub fn gpio_watch_edge(pin: u8, edge: u8, event_handle: i32) -> i32 {
        let idx = pin as usize;
        if idx >= MAX_GPIO {
            return errno::EINVAL;
        }
        if edge == 0 || edge > 3 {
            return errno::EINVAL;
        }
        if !CLAIMED[idx].load(Ordering::Acquire) {
            return errno::ENODEV;
        }
        // Already has an event binding?
        if GPIO_EVENT_BINDING[idx].load(Ordering::Acquire) >= 0 {
            return errno::EBUSY;
        }
        // Set up edge detection
        let rc = gpio_set_irq(pin as i32, edge);
        if rc < 0 {
            return rc;
        }
        // Bind the event
        GPIO_EVENT_BINDING[idx].store(event_handle, Ordering::Release);
        0
    }

    /// Check whether a GPIO pin is currently claimed.
    pub fn is_claimed(pin: u8) -> bool {
        if (pin as usize) < MAX_GPIO {
            CLAIMED[pin as usize].load(Ordering::Acquire)
        } else {
            false
        }
    }

    // ============================================================================
    // Config-driven initialization
    // ============================================================================

    use crate::kernel::boot::config::{GpioConfig, GpioDirection, GpioLevel, GpioPull};

    /// Initialize a GPIO pin from config.
    ///
    /// Claims the pin, sets up mode/pull/level, and records intended owner.
    /// The pin is initially kernel-owned (owner=0xFF). If config specifies
    /// owner_module_id != 0xFF, that value is stored in PENDING_OWNER and
    /// grant_pending_pins() will transfer ownership when the module instantiates.
    ///
    /// Returns handle on success, <0 on error.
    pub fn init_from_config(cfg: &GpioConfig) -> i32 {
        let handle = gpio_claim(cfg.pin);
        if handle < 0 {
            log::warn!("[gpio] pin {} claim failed rc={}", cfg.pin, handle);
            return handle;
        }

        // Set pull first (used when creating input)
        let pull = match cfg.pull {
            GpioPull::None => PinPull::None,
            GpioPull::Up => PinPull::Up,
            GpioPull::Down => PinPull::Down,
        };
        gpio_set_pull(handle, pull);

        // Set mode
        let initial_high = cfg.initial == GpioLevel::High;
        let mode = match cfg.direction {
            GpioDirection::Input => PinMode::Input,
            GpioDirection::Output => PinMode::Output,
        };

        let result = gpio_set_mode(handle, mode, initial_high);
        if result < 0 {
            log::warn!("[gpio] pin {} set_mode failed rc={}", cfg.pin, result);
            gpio_release(handle);
            return result;
        }

        // Record intended owner (actual handoff happens at module instantiation)
        // Pin stays kernel-owned (OWNER=0xFF) until grant_pending_pins() is called.
        PENDING_OWNER[cfg.pin as usize].store(cfg.owner_module_id, Ordering::Release);

        if cfg.owner_module_id != OWNER_KERNEL {
            log::info!(
                "[gpio] pin {} {:?} owner=module{}",
                cfg.pin,
                cfg.direction,
                cfg.owner_module_id
            );
        } else {
            log::info!("[gpio] pin {} {:?}", cfg.pin, cfg.direction);
        }
        handle
    }

    /// Initialize all GPIO pins from hardware config.
    ///
    /// Returns number of pins successfully initialized.
    pub fn init_all_from_config(gpio_configs: &[Option<GpioConfig>]) -> usize {
        let mut count = 0;
        for cfg in gpio_configs.iter().flatten() {
            if init_from_config(cfg) >= 0 {
                count += 1;
            }
        }
        count
    }
}

pub mod pio {
    //! PIO utility functions for register bridges and pin setup.
    //!
    //! These are used by the
    //! PIO register bridges (0x0C70-0x0C7B) in providers.rs and by
    //! boot-time PIO pin configuration.

    use portable_atomic::{AtomicU32, Ordering};

    // ============================================================================
    // Instruction Memory Management
    // ============================================================================

    /// Bitmap of used PIO instruction memory slots per PIO block.
    pub static PIO_INSTRUCTIONS_USED: [AtomicU32; 3] =
        [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

    /// Allocate contiguous instruction slots in a PIO block.
    ///
    /// Uses first-fit with atomic CAS on the shared `PIO_INSTRUCTIONS_USED` bitmap.
    /// Returns `(origin, mask)` where origin is the start address and mask is the
    /// allocated bits to pass to `free_instruction_slots()` later.
    pub fn alloc_instruction_slots(pio_num: u8, count: usize) -> Option<(u8, u32)> {
        if count == 0 || count > 32 {
            return None;
        }

        let instructions_used = &PIO_INSTRUCTIONS_USED[pio_num as usize];
        let mut current = instructions_used.load(Ordering::Acquire);

        for start in 0..=(32 - count) {
            let mask = ((1u32 << count) - 1) << start;
            if current & mask == 0 {
                match instructions_used.compare_exchange(
                    current,
                    current | mask,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Some((start as u8, mask)),
                    Err(new_current) => current = new_current,
                }
            }
        }
        None
    }

    /// Free previously allocated instruction slots.
    pub fn free_instruction_slots(pio_num: u8, mask: u32) {
        if mask != 0 {
            PIO_INSTRUCTIONS_USED[pio_num as usize].fetch_and(!mask, Ordering::Release);
        }
    }

    // ============================================================================
    // Config-Driven Pin Setup
    // ============================================================================

    /// Pull resistor configuration for PIO pins.
    #[derive(Clone, Copy)]
    pub enum PioPull {
        /// Pull-down enabled (for CYW43 DIO/DATA2 strap during power-on).
        PullDown,
        /// Pull-up enabled (default for general data/clock pins).
        PullUp,
        /// No pull resistor (gSPI DIO/CLK).
        None,
    }

    /// IO_BANK0 `FUNCSEL` for PIO0; PIO1 and PIO2 follow consecutively.
    const PIO0_FUNCSEL: u32 = 6;

    /// Configure a GPIO pin for PIO use.
    ///
    /// Accepts a runtime pin number, which is why it writes the registers
    /// rather than going through a typed pin.
    pub fn setup_pio_pin(pin: u8, pio_num: u8, pull: PioPull) {
        debug_assert!(
            pin < crate::platform::rp_io::gpio::runtime_max_gpio(),
            "PIO pin out of range"
        );
        use crate::platform::rp_gpio_regs as gpio_regs;

        let funcsel = PIO0_FUNCSEL + pio_num as u32;
        let cfg = gpio_regs::PadConfig::default()
            .schmitt(true)
            .slew_fast(true)
            .input_enable(true)
            .pull_up(matches!(pull, PioPull::PullUp))
            .pull_down(matches!(pull, PioPull::PullDown))
            .drive(gpio_regs::Drive::Ma12);
        // SAFETY: `pin` is within the runtime GPIO range (asserted above) and
        // is being claimed for this PIO by the caller.
        unsafe {
            gpio_regs::set_function(pin, funcsel);
            gpio_regs::write_pad(pin, cfg);
        }
    }
}

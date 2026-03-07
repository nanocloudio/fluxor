//! PIO subsystem: stream (continuous DMA) and cmd (bidirectional transfers).
//!
//! Shared types, instruction memory management, and both service implementations
//! in a single flat module.

use core::cell::UnsafeCell;
use portable_atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering, compiler_fence};

use embassy_rp::dma::Channel;
use embassy_rp::pac;
use embassy_rp::pio::{Instance, StateMachine};
use embassy_rp::Peri;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

use crate::abi::StreamTime;
use crate::kernel::errno;

// ============================================================================
// Constants
// ============================================================================

/// Maximum PIO program length (32 instructions per PIO block)
pub const MAX_PIO_INSTRUCTIONS: usize = 32;

/// Bitmap of used PIO instruction memory slots per PIO block.
/// Shared between stream and cmd for instruction memory allocation.
pub static PIO_INSTRUCTIONS_USED: [AtomicU32; 3] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

// ============================================================================
// Shared PIO Program Type
// ============================================================================

/// PIO program configuration (module-provided).
///
/// Used by both stream and cmd services. Contains the instruction words
/// plus wrap/sideset metadata needed to configure a PIO state machine.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PioProgram {
    pub instructions: [u16; MAX_PIO_INSTRUCTIONS],
    pub length: u8,
    pub wrap_target: u8,
    pub wrap: u8,
    pub sideset_bits: u8,
    pub sideset_optional: bool,
    pub sideset_pindirs: bool,
}

impl PioProgram {
    pub const fn empty() -> Self {
        Self {
            instructions: [0; MAX_PIO_INSTRUCTIONS],
            length: 0,
            wrap_target: 0,
            wrap: 0,
            sideset_bits: 0,
            sideset_optional: false,
            sideset_pindirs: false,
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.length > 0
    }

    /// Validate program constraints before loading into PIO hardware.
    ///
    /// Checks: non-empty, fits instruction memory, wrap in range, sideset <= 5.
    pub fn validate(&self) -> bool {
        if self.length == 0 || self.length as usize > MAX_PIO_INSTRUCTIONS {
            return false;
        }
        if self.wrap_target >= self.length || self.wrap >= self.length {
            return false;
        }
        if self.sideset_bits > 5 {
            return false;
        }
        true
    }
}

impl Default for PioProgram {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Shared Slot State
// ============================================================================

/// Slot lifecycle state shared by stream and cmd PIO services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PioSlotState {
    /// Not allocated
    Free = 0,
    /// Allocated, awaiting configuration
    Allocated = 1,
    /// Configured and ready
    Ready = 2,
    /// Operation in progress
    Busy = 3,
}

impl From<u8> for PioSlotState {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Allocated,
            2 => Self::Ready,
            3 => Self::Busy,
            _ => Self::Free,
        }
    }
}

// ============================================================================
// Shared Program Construction
// ============================================================================

/// Validate raw program parameters and construct a PioProgram.
///
/// Returns None if parameters are invalid (null pointer, out-of-range values).
///
/// # Safety
/// `instructions` must point to at least `len` valid u16 values.
pub unsafe fn build_program_from_raw(
    instructions: *const u16,
    len: usize,
    wrap_target: u8,
    wrap: u8,
    sideset_bits: u8,
    options: u8,
) -> Option<PioProgram> {
    if instructions.is_null() || len == 0 || len > MAX_PIO_INSTRUCTIONS {
        return None;
    }
    if wrap_target as usize >= len || wrap as usize >= len {
        return None;
    }
    if sideset_bits > 5 {
        return None;
    }

    let mut program = PioProgram::empty();
    program.length = len as u8;
    program.wrap_target = wrap_target;
    program.wrap = wrap;
    program.sideset_bits = sideset_bits;
    program.sideset_optional = (options & 0x01) != 0;
    program.sideset_pindirs = (options & 0x02) != 0;

    for i in 0..len {
        program.instructions[i] = *instructions.add(i);
    }

    Some(program)
}

// ============================================================================
// Shared Instruction Memory Management
// ============================================================================

/// Get PAC PIO instance by block index (0, 1, 2).
pub fn pio_pac(pio_num: u8) -> pac::pio::Pio {
    crate::kernel::chip::pio_pac(pio_num)
}

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

/// Write PIO program instructions to instruction memory at the given origin.
pub fn write_program_instructions(pio_num: u8, program: &PioProgram, origin: u8) {
    let pio = pio_pac(pio_num);
    for i in 0..program.length as usize {
        let addr = (origin as usize + i) % 32;
        pio.instr_mem(addr).write(|w| {
            w.set_instr_mem(program.instructions[i]);
        });
    }
    log::info!("[pio] pio{} wrote {} instr @{}", pio_num, program.length, origin);
}

// ============================================================================
// Config-Driven Pin Setup (bypasses Embassy typed pins)
// ============================================================================

/// Pull resistor configuration for PIO pins.
#[derive(Clone, Copy)]
pub enum PioPull {
    /// Pull-down enabled (for CYW43 DIO/DATA2 strap during power-on).
    PullDown,
    /// Pull-up enabled (default for general data/clock pins).
    PullUp,
    /// No pull resistor (matches Embassy's Pull::None for gSPI DIO/CLK).
    None,
}

/// Configure a GPIO pin for PIO use via direct PAC register writes.
///
/// Equivalent to Embassy's `make_pio_pin` but accepts a runtime pin number.
/// FUNCSEL values: PIO0=6, PIO1=7, PIO2=8.
pub fn setup_pio_pin(pin: u8, pio_num: u8, pull: PioPull) {
    debug_assert!(pin < crate::io::gpio::runtime_max_gpio(), "PIO pin out of range");
    let funcsel = 6 + pio_num;
    pac::IO_BANK0.gpio(pin as usize).ctrl().write(|w| {
        w.set_funcsel(funcsel as _);
    });
    pac::PADS_BANK0.gpio(pin as usize).write(|w| {
        crate::kernel::chip::pad_set_iso_false!(w);
        w.set_schmitt(true);
        w.set_slewfast(true);
        w.set_ie(true);
        w.set_od(false);
        w.set_pue(matches!(pull, PioPull::PullUp));
        w.set_pde(matches!(pull, PioPull::PullDown));
        w.set_drive(pac::pads::vals::Drive::_12M_A);
    });
}

/// Set a GPIO pin as output-low via PIO SM SET instructions (direct PAC).
///
/// Replaces Embassy's `sm.set_pin_dirs(Out, &[pin])` + `sm.set_pins(Low, &[pin])`
/// which require typed `Pin<PIO>` references. Uses the same instruction encoding.
pub fn set_sm_pin_output(pio_num: u8, sm_idx: u8, pin: u8) {
    debug_assert!(pin < 32, "SM pin must be < 32");
    let pio = pio_pac(pio_num);
    let sm = pio.sm(sm_idx as usize);

    // Save pinctrl and execctrl, clear out_sticky (same as Embassy's with_paused)
    let saved_pinctrl = sm.pinctrl().read();
    let saved_execctrl = sm.execctrl().read();
    sm.execctrl().modify(|w| w.set_out_sticky(false));

    // SET PINDIRS, 1 (set pin as output)
    sm.pinctrl().write(|w| {
        w.set_set_base(pin);
        w.set_set_count(1);
    });
    sm.instr().write(|w| w.set_instr(0b111_00000_100_00001));

    // SET PINS, 0 (drive low)
    sm.instr().write(|w| w.set_instr(0b111_00000_000_00000));

    // Restore
    sm.pinctrl().write_value(saved_pinctrl);
    sm.execctrl().write_value(saved_execctrl);
}

/// Validate a PIO program, free old instruction slots, allocate new ones,
/// and write instructions to PIO instruction memory.
///
/// On success, returns the origin address. `used_mask` is updated in-place
/// (old mask freed, new mask stored). On failure, `used_mask` is cleared
/// and the function returns None.
pub fn prepare_program_load(
    pio_num: u8,
    program: &PioProgram,
    used_mask: &mut u32,
) -> Option<u8> {
    if !program.validate() {
        log::warn!("[pio] program validation failed");
        return None;
    }
    free_instruction_slots(pio_num, *used_mask);
    *used_mask = 0;

    let (origin, mask) = match alloc_instruction_slots(pio_num, program.length as usize) {
        Some(v) => v,
        None => {
            log::error!("[pio] no free instruction slots");
            return None;
        }
    };
    *used_mask = mask;
    write_program_instructions(pio_num, program, origin);
    Some(origin)
}

// ============================================================================
// PIO Stream: Double-Buffered DMA Streaming
// ============================================================================

/// Maximum number of concurrent PIO streams
pub const MAX_STREAMS: usize = 2;

/// Maximum buffer size per stream (in u32 words).
/// 2048 words = 8KB per buffer = ~46ms at 44100Hz stereo.
/// Modules choose their push size ≤ MAX_BUFFER_WORDS (I2S uses 512 words).
/// Mailbox producers must push exactly the size the sink expects per DMA buffer.
pub const MAX_BUFFER_WORDS: usize = 2048;

/// Double-buffered PIO stream slot
pub struct PioStreamSlot {
    buffer_a: [u32; MAX_BUFFER_WORDS],
    buffer_b: [u32; MAX_BUFFER_WORDS],
    front_is_b: AtomicBool,
    state: AtomicU8,
    /// Owner module index (0xFF = kernel/unowned)
    owner: AtomicU8,
    push_count: AtomicUsize,
    push_pending: AtomicBool,
    out_pin: AtomicU8,
    sideset_base: AtomicU8,
    clock_divider: AtomicU32,
    shift_bits: AtomicU8,
    program: UnsafeCell<PioProgram>,
    program_pending: AtomicBool,
    /// 0=none, 1=pending, 2=loaded, 3=error
    program_status: AtomicU8,
    completion_signal: Signal<CriticalSectionRawMutex, ()>,
    /// Units consumed by hardware (monotonic), split into two AtomicU32
    /// to avoid torn reads on ARM32 where AtomicU64 is unavailable.
    consumed_units_lo: AtomicU32,
    consumed_units_hi: AtomicU32,
    /// Units currently queued (waiting for DMA)
    queued_units: AtomicU32,
    /// Consumption rate in units/second (Q16.16 fixed point)
    units_per_sec_q16: AtomicU32,
    /// Monotonic microsecond timestamp of first push (split hi/lo, write-once per session)
    t0_micros_lo: AtomicU32,
    t0_micros_hi: AtomicU32,
}

unsafe impl Sync for PioStreamSlot {}

impl PioStreamSlot {
    pub const fn new() -> Self {
        Self {
            buffer_a: [0; MAX_BUFFER_WORDS],
            buffer_b: [0; MAX_BUFFER_WORDS],
            front_is_b: AtomicBool::new(false),
            state: AtomicU8::new(PioSlotState::Free as u8),
            owner: AtomicU8::new(0xFF),
            push_count: AtomicUsize::new(0),
            push_pending: AtomicBool::new(false),
            out_pin: AtomicU8::new(0),
            sideset_base: AtomicU8::new(0),
            clock_divider: AtomicU32::new(0),
            shift_bits: AtomicU8::new(32),
            program: UnsafeCell::new(PioProgram::empty()),
            program_pending: AtomicBool::new(false),
            program_status: AtomicU8::new(0),
            completion_signal: Signal::new(),
            consumed_units_lo: AtomicU32::new(0),
            consumed_units_hi: AtomicU32::new(0),
            queued_units: AtomicU32::new(0),
            units_per_sec_q16: AtomicU32::new(0),
            t0_micros_lo: AtomicU32::new(0),
            t0_micros_hi: AtomicU32::new(0),
        }
    }

    pub fn state(&self) -> PioSlotState {
        PioSlotState::from(self.state.load(Ordering::Acquire))
    }

    pub fn set_state(&self, state: PioSlotState) {
        self.state.store(state as u8, Ordering::Release);
    }

    pub fn back_buffer_ptr(&self) -> *mut u32 {
        if self.front_is_b.load(Ordering::Acquire) {
            self.buffer_a.as_ptr() as *mut u32
        } else {
            self.buffer_b.as_ptr() as *mut u32
        }
    }

    pub fn front_buffer(&self) -> &[u32] {
        if self.front_is_b.load(Ordering::Acquire) {
            &self.buffer_b
        } else {
            &self.buffer_a
        }
    }

    pub fn swap_buffers(&self) {
        let was_b = self.front_is_b.load(Ordering::Acquire);
        self.front_is_b.store(!was_b, Ordering::Release);
    }

    pub fn set_push_pending(&self, count: usize) {
        self.push_count.store(count, Ordering::Release);
        self.push_pending.store(true, Ordering::Release);
    }

    pub fn take_push_pending(&self) -> Option<usize> {
        if self.push_pending.swap(false, Ordering::AcqRel) {
            Some(self.push_count.load(Ordering::Acquire))
        } else {
            None
        }
    }

    pub fn is_push_pending(&self) -> bool {
        self.push_pending.load(Ordering::Acquire)
    }

    pub fn out_pin(&self) -> u8 {
        self.out_pin.load(Ordering::Acquire)
    }

    pub fn sideset_base(&self) -> u8 {
        self.sideset_base.load(Ordering::Acquire)
    }

    pub fn clock_divider(&self) -> u32 {
        self.clock_divider.load(Ordering::Acquire)
    }

    pub fn shift_bits(&self) -> u8 {
        self.shift_bits.load(Ordering::Acquire)
    }

    pub fn configure(&self, out_pin: u8, sideset_base: u8, clock_divider: u32, shift_bits: u8) {
        self.out_pin.store(out_pin, Ordering::Release);
        self.sideset_base.store(sideset_base, Ordering::Release);
        self.clock_divider.store(clock_divider, Ordering::Release);
        self.shift_bits.store(shift_bits, Ordering::Release);
        self.set_state(PioSlotState::Ready);
    }

    pub unsafe fn load_program(&self, program: &PioProgram) {
        let ptr = self.program.get();
        (*ptr) = *program;
    }

    pub fn set_program_pending(&self) {
        self.program_pending.store(true, Ordering::Release);
    }

    pub fn take_program_pending(&self) -> bool {
        self.program_pending.swap(false, Ordering::AcqRel)
    }

    pub fn is_program_pending(&self) -> bool {
        self.program_pending.load(Ordering::Acquire)
    }

    pub fn program_status(&self) -> u8 {
        self.program_status.load(Ordering::Acquire)
    }

    pub fn set_program_status(&self, status: u8) {
        self.program_status.store(status, Ordering::Release);
    }

    pub unsafe fn program(&self) -> &PioProgram {
        &*self.program.get()
    }

    pub fn signal_complete(&self) {
        self.completion_signal.signal(());
    }

    pub async fn wait_complete(&self) {
        if self.is_dma_active() {
            self.completion_signal.wait().await;
        }
    }

    pub fn is_dma_active(&self) -> bool {
        self.is_push_pending() || self.state() == PioSlotState::Busy
    }

    pub fn reset_completion(&self) {
        self.completion_signal.reset();
    }

    pub fn reset(&self) {
        self.front_is_b.store(false, Ordering::Release);
        self.push_count.store(0, Ordering::Release);
        self.push_pending.store(false, Ordering::Release);
        self.program_pending.store(false, Ordering::Release);
        self.program_status.store(0, Ordering::Release);
        self.consumed_units_lo.store(0, Ordering::Release);
        self.consumed_units_hi.store(0, Ordering::Release);
        self.queued_units.store(0, Ordering::Release);
        self.units_per_sec_q16.store(0, Ordering::Release);
        self.t0_micros_lo.store(0, Ordering::Release);
        self.t0_micros_hi.store(0, Ordering::Release);
        unsafe {
            (*self.program.get()) = PioProgram::empty();
        }
        self.set_state(PioSlotState::Free);
    }

    /// Set the consumption rate (units/second in Q16.16 fixed point)
    pub fn set_units_per_sec(&self, rate_q16: u32) {
        self.units_per_sec_q16.store(rate_q16, Ordering::Release);
    }

    /// Capture t0 on first push (consumed == 0 && queued == 0 means fresh stream).
    /// Write-once per session; reset() clears for next session.
    fn try_set_t0(&self) {
        if self.t0_micros_lo.load(Ordering::Acquire) == 0
            && self.t0_micros_hi.load(Ordering::Acquire) == 0
        {
            let now = embassy_time::Instant::now().as_micros();
            self.t0_micros_lo.store(now as u32, Ordering::Release);
            self.t0_micros_hi.store((now >> 32) as u32, Ordering::Release);
        }
    }

    /// Add units to the queued count (called when push is accepted)
    pub fn add_queued_units(&self, count: u32) {
        self.queued_units.fetch_add(count, Ordering::AcqRel);
    }

    /// Transfer units from queued to consumed (called on DMA completion).
    ///
    /// Single-writer: only called from the DMA completion context.
    /// Stores high word after low word so readers can detect mid-update via high word.
    pub fn complete_units(&self, count: u32) {
        // Subtract from queued (saturating to guard against mismatched counts)
        let prev = self.queued_units.load(Ordering::Acquire);
        let new = prev.saturating_sub(count);
        self.queued_units.store(new, Ordering::Release);
        // Add to consumed — reconstruct u64 from split halves
        let lo = self.consumed_units_lo.load(Ordering::Acquire) as u64;
        let hi = self.consumed_units_hi.load(Ordering::Acquire) as u64;
        let total = (hi << 32) | lo;
        let updated = total + count as u64;
        self.consumed_units_lo.store(updated as u32, Ordering::Release);
        self.consumed_units_hi.store((updated >> 32) as u32, Ordering::Release);
    }

    /// Get current stream timing information.
    ///
    /// Reads consumed_units with a consistency check: re-reads the high word
    /// to detect torn reads from a concurrent `complete_units()` call.
    pub fn get_stream_time(&self) -> StreamTime {
        let consumed = loop {
            let hi1 = self.consumed_units_hi.load(Ordering::Acquire);
            let lo = self.consumed_units_lo.load(Ordering::Acquire);
            let hi2 = self.consumed_units_hi.load(Ordering::Acquire);
            if hi1 == hi2 {
                break ((hi1 as u64) << 32) | (lo as u64);
            }
        };
        let t0_lo = self.t0_micros_lo.load(Ordering::Acquire) as u64;
        let t0_hi = self.t0_micros_hi.load(Ordering::Acquire) as u64;
        StreamTime {
            consumed_units: consumed,
            queued_units: self.queued_units.load(Ordering::Acquire),
            units_per_sec_q16: self.units_per_sec_q16.load(Ordering::Acquire),
            t0_micros: (t0_hi << 32) | t0_lo,
        }
    }
}

/// Static pool of PIO stream slots
static STREAM_SLOTS: [PioStreamSlot; MAX_STREAMS] = [
    PioStreamSlot::new(),
    PioStreamSlot::new(),
];

// ============================================================================
// PIO Stream Service
// ============================================================================

/// PIO Stream Service - provides syscall implementations
pub struct PioStreamService;

impl PioStreamService {
    pub fn alloc() -> i32 {
        let owner = crate::kernel::scheduler::current_module_index() as u8;
        for (i, slot) in STREAM_SLOTS.iter().enumerate() {
            if slot.state.compare_exchange(
                PioSlotState::Free as u8,
                PioSlotState::Allocated as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                slot.owner.store(owner, Ordering::Release);
                return i as i32;
            }
        }
        log::warn!("[pio] stream no free slots");
        errno::ENOMEM
    }

    /// Check if the current module owns this stream handle.
    fn check_owner(handle: i32) -> bool {
        if handle < 0 || handle >= MAX_STREAMS as i32 {
            return false;
        }
        let owner = STREAM_SLOTS[handle as usize].owner.load(Ordering::Acquire);
        owner == 0xFF || owner == crate::kernel::scheduler::current_module_index() as u8
    }

    pub fn load_program(
        handle: i32,
        instructions: *const u16,
        len: usize,
        wrap_target: u8,
        wrap: u8,
        sideset_bits: u8,
        options: u8,
    ) -> i32 {
        if handle < 0 || handle >= MAX_STREAMS as i32 || !Self::check_owner(handle) {
            return errno::EINVAL;
        }
        let slot = &STREAM_SLOTS[handle as usize];
        let state = slot.state();

        if state == PioSlotState::Free || state == PioSlotState::Busy {
            return errno::EBUSY;
        }

        let program = match unsafe {
            build_program_from_raw(instructions, len, wrap_target, wrap, sideset_bits, options)
        } {
            Some(p) => p,
            None => return errno::EINVAL,
        };

        unsafe { slot.load_program(&program); }

        slot.set_program_status(1); // pending
        slot.set_program_pending();

        0
    }

    pub fn get_buffer(handle: i32) -> *mut u32 {
        if handle < 0 || handle >= MAX_STREAMS as i32 || !Self::check_owner(handle) {
            return core::ptr::null_mut();
        }
        let slot = &STREAM_SLOTS[handle as usize];
        if slot.state() == PioSlotState::Free {
            return core::ptr::null_mut();
        }
        // Don't return back buffer while a push is pending — the runner is
        // about to swap it to become the front buffer for DMA.
        if slot.is_push_pending() {
            return core::ptr::null_mut();
        }
        slot.back_buffer_ptr()
    }

    pub fn configure(handle: i32, out_pin: u8, sideset_base: u8, clock_divider: u32, shift_bits: u8) -> i32 {
        if handle < 0 || handle >= MAX_STREAMS as i32 || !Self::check_owner(handle) {
            return errno::EINVAL;
        }
        let slot = &STREAM_SLOTS[handle as usize];
        let state = slot.state();
        if state == PioSlotState::Free {
            return errno::ERROR;
        }
        slot.configure(out_pin, sideset_base, clock_divider, shift_bits);
        0
    }

    /// Check if a new buffer can be submitted.
    ///
    /// Returns 1 if the back buffer is available for writing and push() can be called.
    /// This allows true double-buffering: the producer can fill the back buffer
    /// while DMA is active on the front buffer, enabling gapless streaming.
    pub fn can_push(handle: i32) -> i32 {
        if handle < 0 || handle >= MAX_STREAMS as i32 || !Self::check_owner(handle) {
            return 0;
        }
        let slot = &STREAM_SLOTS[handle as usize];
        // Only check if a push is already pending, NOT if DMA is busy.
        // This enables pipelining: producer fills back buffer while DMA runs.
        if slot.state() == PioSlotState::Free {
            return 0;
        }
        if slot.is_push_pending() { 0 } else { 1 }
    }

    pub fn push(handle: i32, count: usize) -> i32 {
        if handle < 0 || handle >= MAX_STREAMS as i32 || !Self::check_owner(handle) {
            return errno::EINVAL;
        }
        if count == 0 || count > MAX_BUFFER_WORDS {
            return errno::EINVAL;
        }

        let slot = &STREAM_SLOTS[handle as usize];
        let state = slot.state();
        if state != PioSlotState::Ready && state != PioSlotState::Busy {
            return errno::ERROR;
        }

        if slot.is_push_pending() {
            return errno::EBUSY;
        }

        // Capture t0 on first push (stream start timestamp)
        slot.try_set_t0();

        // Track queued units (count = u32 words = stereo frames for I2S)
        slot.add_queued_units(count as u32);

        slot.reset_completion();
        slot.set_push_pending(count);

        0
    }

    pub fn free(handle: i32) {
        if handle < 0 || handle >= MAX_STREAMS as i32 || !Self::check_owner(handle) {
            return;
        }
        let slot = &STREAM_SLOTS[handle as usize];
        slot.owner.store(0xFF, Ordering::Release);
        slot.reset();
    }

    pub fn is_program_pending_for(handle: usize) -> bool {
        if handle >= MAX_STREAMS {
            return false;
        }
        STREAM_SLOTS[handle].is_program_pending()
    }

    pub fn take_program_pending_for(handle: usize) -> bool {
        if handle >= MAX_STREAMS {
            return false;
        }
        STREAM_SLOTS[handle].take_program_pending()
    }

    pub fn set_program_status_for(handle: usize, status: u8) {
        if handle < MAX_STREAMS {
            STREAM_SLOTS[handle].set_program_status(status);
        }
    }

    pub fn program_status_for(handle: i32) -> i32 {
        if handle < 0 || handle >= MAX_STREAMS as i32 {
            return errno::EINVAL;
        }
        STREAM_SLOTS[handle as usize].program_status() as i32
    }

    pub fn is_push_pending_for(handle: usize) -> bool {
        if handle >= MAX_STREAMS {
            return false;
        }
        STREAM_SLOTS[handle].is_push_pending()
    }

    pub fn take_push_pending_for(handle: usize) -> Option<usize> {
        if handle >= MAX_STREAMS {
            return None;
        }
        STREAM_SLOTS[handle].take_push_pending()
    }

    pub fn get_front_buffer(handle: usize) -> Option<&'static [u32]> {
        if handle >= MAX_STREAMS {
            return None;
        }
        let slot = &STREAM_SLOTS[handle];
        if slot.state() == PioSlotState::Free {
            return None;
        }
        Some(slot.front_buffer())
    }

    pub fn get_config(handle: usize) -> Option<(u8, u8, u32, u8)> {
        if handle >= MAX_STREAMS {
            return None;
        }
        let slot = &STREAM_SLOTS[handle];
        let state = slot.state();
        // Only return config if state is Ready or Busy (i.e., configure() was called)
        // Don't return config for Allocated state - config values aren't set yet
        if state != PioSlotState::Ready && state != PioSlotState::Busy {
            return None;
        }
        Some((slot.out_pin(), slot.sideset_base(), slot.clock_divider(), slot.shift_bits()))
    }

    pub fn set_busy(handle: usize, busy: bool) {
        if handle >= MAX_STREAMS {
            return;
        }
        let slot = &STREAM_SLOTS[handle];
        if busy {
            slot.set_state(PioSlotState::Busy);
        } else {
            slot.set_state(PioSlotState::Ready);
        }
    }

    pub fn swap_buffers_for(handle: usize) {
        if handle >= MAX_STREAMS {
            return;
        }
        STREAM_SLOTS[handle].swap_buffers();
    }

    pub fn signal_complete(handle: usize) {
        if handle >= MAX_STREAMS {
            return;
        }
        STREAM_SLOTS[handle].signal_complete();
    }

    pub unsafe fn get_program(handle: usize) -> Option<&'static PioProgram> {
        if handle >= MAX_STREAMS {
            return None;
        }
        let slot = &STREAM_SLOTS[handle];
        if slot.state() == PioSlotState::Free {
            return None;
        }
        Some(slot.program())
    }

    /// Mark units as consumed by hardware (called on DMA completion)
    pub fn complete_units_for(handle: usize, count: u32) {
        if handle >= MAX_STREAMS {
            return;
        }
        STREAM_SLOTS[handle].complete_units(count);
    }

    /// Set the consumption rate for a stream (units/second in Q16.16 fixed point)
    pub fn set_units_per_sec_for(handle: usize, rate_q16: u32) {
        if handle >= MAX_STREAMS {
            return;
        }
        STREAM_SLOTS[handle].set_units_per_sec(rate_q16);
    }

    /// Get stream timing information
    pub fn stream_time(handle: i32) -> Option<StreamTime> {
        if handle < 0 || handle >= MAX_STREAMS as i32 || !Self::check_owner(handle) {
            return None;
        }
        let slot = &STREAM_SLOTS[handle as usize];
        if slot.state() == PioSlotState::Free {
            return None;
        }
        Some(slot.get_stream_time())
    }

    /// Get stream timing from the first active stream (no ownership check).
    /// Used by system-level queries so any module can read the stream clock.
    pub fn stream_time_any() -> Option<StreamTime> {
        for i in 0..MAX_STREAMS {
            let slot = &STREAM_SLOTS[i];
            let state = slot.state();
            if state == PioSlotState::Ready || state == PioSlotState::Busy {
                return Some(slot.get_stream_time());
            }
        }
        None
    }

    /// Release all PIO stream slots owned by a specific module.
    pub fn release_owned_by(module_idx: u8) {
        for slot in STREAM_SLOTS.iter() {
            if slot.owner.load(Ordering::Acquire) == module_idx
                && slot.state() != PioSlotState::Free
            {
                slot.owner.store(0xFF, Ordering::Release);
                slot.reset();
            }
        }
    }
}

// ============================================================================
// PIO Stream Runner (Embassy task that executes DMA)
// ============================================================================

/// PIO Stream Runner - owns PIO/DMA resources and executes pending pushes
pub struct PioStreamRunner<'d, PIO: Instance, const SM: usize, DMA: Channel> {
    sm: StateMachine<'d, PIO, SM>,
    dma: Peri<'d, DMA>,
    pin_num: u8,
    sideset_pin0: Option<u8>,
    sideset_pin1: Option<u8>,
    slot: usize,
    pio_num: u8,
    program_loaded: bool,
    program_origin: Option<u8>,
    used_mask: u32,
}

impl<'d, PIO: Instance, const SM: usize, DMA: Channel> PioStreamRunner<'d, PIO, SM, DMA> {
    /// Create a new PIO stream runner (single output pin)
    pub fn new(
        sm: StateMachine<'d, PIO, SM>,
        dma: Peri<'d, DMA>,
        pin_num: u8,
        slot: usize,
        pio_num: u8,
    ) -> Self {
        log::info!("[pio] stream slot={} PIO{}", slot, pio_num);
        Self {
            sm,
            dma,
            pin_num,
            sideset_pin0: None,
            sideset_pin1: None,
            slot,
            pio_num,
            program_loaded: false,
            program_origin: None,
            used_mask: 0,
        }
    }

    /// Create a new PIO stream runner with sideset pins (for I2S)
    pub fn new_with_sideset(
        sm: StateMachine<'d, PIO, SM>,
        dma: Peri<'d, DMA>,
        out_pin: u8,
        sideset_pin0: u8,
        sideset_pin1: u8,
        slot: usize,
        pio_num: u8,
    ) -> Self {
        log::info!("[pio] stream slot={} PIO{} sideset", slot, pio_num);
        Self {
            sm,
            dma,
            pin_num: out_pin,
            sideset_pin0: Some(sideset_pin0),
            sideset_pin1: Some(sideset_pin1),
            slot,
            pio_num,
            program_loaded: false,
            program_origin: None,
            used_mask: 0,
        }
    }

    fn load_program(&mut self, program: &PioProgram, out_pin: u8, sideset_base: u8, clock_divider: u32, shift_bits: u8) -> bool {
        self.sm.set_enable(false);

        let origin = match prepare_program_load(self.pio_num, program, &mut self.used_mask) {
            Some(o) => o,
            None => return false,
        };
        self.configure_sm_pac(program, origin, out_pin, sideset_base, clock_divider, shift_bits);

        set_sm_pin_output(self.pio_num, SM as u8, self.pin_num);
        if let Some(ss0) = self.sideset_pin0 {
            set_sm_pin_output(self.pio_num, SM as u8, ss0);
        }
        if let Some(ss1) = self.sideset_pin1 {
            set_sm_pin_output(self.pio_num, SM as u8, ss1);
        }

        self.sm.set_enable(true);
        self.program_loaded = true;
        self.program_origin = Some(origin);
        true
    }

    fn free_instructions(&mut self) {
        if self.used_mask != 0 {
            free_instruction_slots(self.pio_num, self.used_mask);
            self.used_mask = 0;
            self.program_origin = None;
        }
    }

    fn configure_sm_pac(&self, program: &PioProgram, origin: u8, out_pin: u8, sideset_base: u8, clock_divider: u32, shift_bits: u8) {
        let pio = pio_pac(self.pio_num);
        let sm = pio.sm(SM);

        sm.execctrl().modify(|w| {
            w.set_wrap_bottom(origin + program.wrap_target);
            w.set_wrap_top(origin + program.wrap);
            w.set_side_en(program.sideset_optional);
            w.set_side_pindir(program.sideset_pindirs);
        });

        sm.pinctrl().modify(|w| {
            w.set_out_base(out_pin);
            w.set_out_count(1);
            w.set_sideset_base(sideset_base);
            w.set_sideset_count(program.sideset_bits);
            w.set_set_base(out_pin);
            w.set_set_count(1);
        });

        sm.clkdiv().write(|w| {
            w.0 = clock_divider << 8;
        });

        sm.shiftctrl().modify(|w| {
            w.set_fjoin_tx(true);
            w.set_fjoin_rx(false);
            w.set_autopull(true);
            w.set_out_shiftdir(false); // shift left (MSB first)
            w.set_pull_thresh(shift_bits);
        });

        // Set pin directions
        sm.pinctrl().modify(|w| {
            w.set_set_base(out_pin);
            w.set_set_count(1);
        });
        let set_pindirs_1 = 0xE081_u16;
        sm.instr().write(|w| w.set_instr(set_pindirs_1));

        if sideset_base != out_pin {
            sm.pinctrl().modify(|w| {
                w.set_set_base(sideset_base);
                w.set_set_count(program.sideset_bits);
            });
            let sideset_mask = (1u16 << program.sideset_bits) - 1;
            let set_pindirs_ss = 0xE080_u16 | sideset_mask;
            sm.instr().write(|w| w.set_instr(set_pindirs_ss));
        }

        sm.pinctrl().modify(|w| {
            w.set_set_base(out_pin);
            w.set_set_count(1);
        });

        // Jump to entry point
        let entry_point = origin + program.wrap;
        let jmp_instr = 0x0000 | (entry_point as u16);
        sm.instr().write(|w| w.set_instr(jmp_instr));

        // Enable state machine
        pio.ctrl().modify(|w| {
            let current = w.sm_enable();
            w.set_sm_enable(current | (1 << SM));
        });
    }

    /// Try to load a pending program if both program AND config are ready.
    /// Only consumes the program_pending flag if loading succeeds.
    fn try_load_pending_program(&mut self) {
        // Check if program is pending
        if !PioStreamService::is_program_pending_for(self.slot) {
            return;
        }

        // Check if config is ready BEFORE taking the flag
        // get_config returns None if state is not Ready/Busy (i.e., configure() not called)
        let config = match PioStreamService::get_config(self.slot) {
            Some(c) => c,
            None => return, // Config not ready yet, don't consume the flag
        };

        // Get program BEFORE taking the flag
        let program = match unsafe { PioStreamService::get_program(self.slot) } {
            Some(p) => p,
            None => return, // No program, don't consume the flag
        };

        // Now we know both program and config are ready - take the flag
        if !PioStreamService::take_program_pending_for(self.slot) {
            return; // Someone else took it (race)
        }

        // Load the program
        let (out_pin, sideset_base, clock_div, shift_bits) = config;
        if self.load_program(program, out_pin, sideset_base, clock_div, shift_bits) {
            PioStreamService::set_program_status_for(self.slot, 2); // loaded
            log::info!("[pio] stream loaded slot={}", self.slot);
        } else {
            PioStreamService::set_program_status_for(self.slot, 3); // error
            log::error!("[pio] stream load failed slot={}", self.slot);
        }
    }

    /// Run the stream runner (call this in an Embassy task)
    pub async fn run(&mut self) -> ! {
        // Check for initial pending program (config must also be ready)
        self.try_load_pending_program();

        loop {
            // Detect slot freed — release instruction memory to avoid leak.
            // Slot can be freed by PioStreamService::free() or release_owned_by()
            // while the runner still holds used_mask from a previous program load.
            if self.program_loaded && STREAM_SLOTS[self.slot].state() == PioSlotState::Free {
                self.free_instructions();
                self.program_loaded = false;
            }

            // Check for pending program load (only proceed if config is ready)
            self.try_load_pending_program();

            // Check for pending push
            if self.program_loaded {
                if PioStreamService::is_push_pending_for(self.slot) {
                    // Set busy before taking pending to close the window where
                    // can_push() could return 1 between take and set_busy.
                    PioStreamService::set_busy(self.slot, true);

                    if let Some(count) = PioStreamService::take_push_pending_for(self.slot) {
                        PioStreamService::swap_buffers_for(self.slot);

                        if let Some(buffer) = PioStreamService::get_front_buffer(self.slot) {
                            let data = &buffer[..count];
                            let tx = self.sm.tx();
                            tx.dma_push(self.dma.reborrow(), data, false).await;

                            // Track consumed units (count = u32 words = stereo frames for I2S)
                            PioStreamService::complete_units_for(self.slot, count as u32);

                            PioStreamService::signal_complete(self.slot);

                            // Fast path: if next push is already pending (common in
                            // steady-state streaming), skip set_busy(false) and the
                            // yield. This eliminates the Busy→Ready→Busy state
                            // round-trip and keeps the DMA gap to a few µs.
                            if PioStreamService::is_push_pending_for(self.slot) {
                                continue;
                            }

                            PioStreamService::set_busy(self.slot, false);
                        } else {
                            PioStreamService::set_busy(self.slot, false);
                        }
                    } else {
                        PioStreamService::set_busy(self.slot, false);
                    }
                }
            }

            // Yield if nothing pending
            if !PioStreamService::is_push_pending_for(self.slot) {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(1)).await;
            }
        }
    }
}

// ============================================================================
// Stream Syscall Implementations
// ============================================================================

pub unsafe extern "C" fn syscall_pio_stream_alloc(_max_words: usize) -> i32 {
    use crate::kernel::fd::{tag_fd, FD_TAG_PIO_STREAM};
    tag_fd(FD_TAG_PIO_STREAM, PioStreamService::alloc())
}

pub unsafe extern "C" fn syscall_pio_stream_load_program(
    handle: i32,
    instructions: *const u16,
    len: usize,
    wrap_target: u8,
    wrap: u8,
    sideset_bits: u8,
    options: u8,
) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioStreamService::load_program(handle, instructions, len, wrap_target, wrap, sideset_bits, options)
}

pub unsafe extern "C" fn syscall_pio_stream_get_buffer(handle: i32) -> *mut u32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioStreamService::get_buffer(handle)
}

pub unsafe extern "C" fn syscall_pio_stream_configure(
    handle: i32,
    out_pin: u8,
    sideset_base: u8,
    clock_divider: u32,
    shift_bits: u8,
) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioStreamService::configure(handle, out_pin, sideset_base, clock_divider, shift_bits)
}

pub unsafe extern "C" fn syscall_pio_stream_can_push(handle: i32) -> i32 {
    let slot = crate::kernel::fd::slot_of(handle);
    PioStreamService::can_push(slot)
}

pub unsafe extern "C" fn syscall_pio_stream_push(handle: i32, count: usize) -> i32 {
    let slot = crate::kernel::fd::slot_of(handle);
    PioStreamService::push(slot, count)
}

pub unsafe extern "C" fn syscall_pio_stream_free(handle: i32) {
    let handle = crate::kernel::fd::slot_of(handle);
    PioStreamService::free(handle)
}

pub unsafe extern "C" fn syscall_stream_time(handle: i32, out: *mut StreamTime) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    if out.is_null() {
        return errno::EINVAL;
    }
    match PioStreamService::stream_time(handle) {
        Some(time) => {
            *out = time;
            0
        }
        None => errno::ERROR,
    }
}

/// Get direct access to PIO back buffer with capacity.
///
/// This allows modules to write directly to the PIO buffer without intermediate copies.
/// Returns pointer to back buffer, and writes capacity (in u32 words) to capacity_out.
pub unsafe extern "C" fn syscall_pio_direct_buffer(handle: i32, capacity_out: *mut u32) -> *mut u32 {
    let handle = crate::kernel::fd::slot_of(handle);
    if handle < 0 || handle >= MAX_STREAMS as i32 || !PioStreamService::check_owner(handle) {
        return core::ptr::null_mut();
    }
    let slot = &STREAM_SLOTS[handle as usize];
    if slot.state() == PioSlotState::Free {
        return core::ptr::null_mut();
    }
    // Don't return back buffer while a push is pending — the runner is about
    // to swap it to become the front buffer for DMA. Writing now would corrupt
    // the in-flight transfer.
    if slot.is_push_pending() {
        return core::ptr::null_mut();
    }
    if !capacity_out.is_null() {
        *capacity_out = MAX_BUFFER_WORDS as u32;
    }
    slot.back_buffer_ptr()
}

/// Push directly after writing to the buffer obtained from pio_direct_buffer.
///
/// words: number of u32 words written to the buffer
/// Returns 0 on success, <0 on error.
pub unsafe extern "C" fn syscall_pio_direct_push(handle: i32, words: u32) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioStreamService::push(handle, words as usize)
}

// ============================================================================
// PIO Command: Bidirectional Transfers
// ============================================================================

/// Maximum number of concurrent PIO command slots
pub const MAX_CMD_SLOTS: usize = 2;

/// Maximum transfer size in u32 words for command/response DMA.
/// 512 words = 2048 bytes, sufficient for large peripheral frames.
const MAX_CMD_SCRATCH_WORDS: usize = 512;

/// Transfer request stored in slot for the async runner to process
#[repr(C)]
// ============================================================================
// Command Slot
// ============================================================================

/// PIO command/response slot
pub struct PioCmdSlot {
    /// Slot state
    state: AtomicU8,
    /// Owner module index (0xFF = kernel/unowned)
    owner: AtomicU8,
    /// PIO instance index (0, 1, 2)
    pio_idx: AtomicU8,
    /// State machine index within PIO (0-3)
    sm_idx: AtomicU8,
    /// Data pin number
    data_pin: AtomicU8,
    /// Clock pin number (or sideset pin)
    clk_pin: AtomicU8,
    /// Clock divider (Q16.16 fixed point, stored as raw u32)
    clock_div: AtomicU32,
    /// Program origin (instruction memory start address), set by runner.
    /// 0xFF = not loaded yet. Used by transfer() for forced JMP.
    program_origin: AtomicU8,
    /// DMA channel number for this slot, set by runner at creation.
    /// Used by transfer() for PAC-level DMA.
    dma_channel: AtomicU8,
    /// PIO program
    program: UnsafeCell<PioProgram>,
    /// Program load pending
    program_pending: AtomicBool,
    /// 0=none, 1=pending, 2=loaded, 3=error
    program_status: AtomicU8,
}

// Safety: program UnsafeCell access is protected by pending flags
// (single-writer pattern: syscall writes, runner reads, never concurrent)
unsafe impl Sync for PioCmdSlot {}

impl PioCmdSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(PioSlotState::Free as u8),
            owner: AtomicU8::new(0xFF),
            pio_idx: AtomicU8::new(0),
            sm_idx: AtomicU8::new(0),
            data_pin: AtomicU8::new(0),
            clk_pin: AtomicU8::new(0),
            clock_div: AtomicU32::new(0),
            program_origin: AtomicU8::new(0xFF),
            dma_channel: AtomicU8::new(0xFF),
            program: UnsafeCell::new(PioProgram::empty()),
            program_pending: AtomicBool::new(false),
            program_status: AtomicU8::new(0),
        }
    }

    pub fn state(&self) -> PioSlotState {
        PioSlotState::from(self.state.load(Ordering::Acquire))
    }

    pub fn set_state(&self, state: PioSlotState) {
        self.state.store(state as u8, Ordering::Release);
    }

    pub fn pio_idx(&self) -> u8 {
        self.pio_idx.load(Ordering::Acquire)
    }

    pub fn sm_idx(&self) -> u8 {
        self.sm_idx.load(Ordering::Acquire)
    }

    pub fn data_pin(&self) -> u8 {
        self.data_pin.load(Ordering::Acquire)
    }

    pub fn clk_pin(&self) -> u8 {
        self.clk_pin.load(Ordering::Acquire)
    }

    pub fn clock_div(&self) -> u32 {
        self.clock_div.load(Ordering::Acquire)
    }

    pub unsafe fn program(&self) -> &PioProgram {
        &*self.program.get()
    }

    pub fn is_program_pending(&self) -> bool {
        self.program_pending.load(Ordering::Acquire)
    }

    pub fn take_program_pending(&self) -> bool {
        self.program_pending.swap(false, Ordering::AcqRel)
    }

    pub fn program_status(&self) -> u8 {
        self.program_status.load(Ordering::Acquire)
    }

    pub fn set_program_status(&self, status: u8) {
        self.program_status.store(status, Ordering::Release);
    }

    pub fn reset(&self) {
        self.state.store(PioSlotState::Free as u8, Ordering::Release);
        self.pio_idx.store(0, Ordering::Release);
        self.sm_idx.store(0, Ordering::Release);
        self.data_pin.store(0, Ordering::Release);
        self.clk_pin.store(0, Ordering::Release);
        self.clock_div.store(0, Ordering::Release);
        self.program_origin.store(0xFF, Ordering::Release);
        // Note: dma_channel is NOT reset — it's set once by the runner and stays valid
        self.program_pending.store(false, Ordering::Release);
        self.program_status.store(0, Ordering::Release);
        unsafe {
            *self.program.get() = PioProgram::empty();
        }
    }
}

// ============================================================================
// Global Command Slot Pool
// ============================================================================

static CMD_SLOTS: [PioCmdSlot; MAX_CMD_SLOTS] = [
    PioCmdSlot::new(),
    PioCmdSlot::new(),
];

/// Word-aligned scratch buffers for DMA transfers (one per command slot).
/// Module buffers may be unaligned and not word-sized; DMA requires both.
/// Using static scratch avoids alignment UB and prevents buffer overread/overwrite.
static mut CMD_SCRATCH: [[u32; MAX_CMD_SCRATCH_WORDS]; MAX_CMD_SLOTS] =
    [[0; MAX_CMD_SCRATCH_WORDS]; MAX_CMD_SLOTS];

// ============================================================================
// PIO Command Service
// ============================================================================

/// PIO Command Service — provides syscall implementations
pub struct PioCmdService;

impl PioCmdService {
    /// Allocate a PIO command slot
    ///
    /// pio_idx: PIO instance (0, 1, 2)
    /// sm_idx: state machine within PIO (0-3)
    pub fn alloc(pio_idx: u8, sm_idx: u8) -> i32 {
        if pio_idx > 2 || sm_idx > 3 {
            return errno::EINVAL;
        }

        let owner = crate::kernel::scheduler::current_module_index() as u8;
        for (i, slot) in CMD_SLOTS.iter().enumerate() {
            if slot.state.compare_exchange(
                PioSlotState::Free as u8,
                PioSlotState::Allocated as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                slot.owner.store(owner, Ordering::Release);
                slot.pio_idx.store(pio_idx, Ordering::Release);
                slot.sm_idx.store(sm_idx, Ordering::Release);
                log::info!("[pio] cmd slot={} PIO{}:SM{}", i, pio_idx, sm_idx);
                return i as i32;
            }
        }

        log::warn!("[pio] cmd no free slots");
        errno::ENOMEM
    }

    /// Load a PIO program into a command slot
    pub fn load_program(
        handle: i32,
        instructions: *const u16,
        len: usize,
        wrap_target: u8,
        wrap: u8,
        sideset_bits: u8,
        options: u8,
    ) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return errno::EINVAL,
        };

        let state = slot.state();
        if state == PioSlotState::Free || state == PioSlotState::Busy {
            return errno::EBUSY;
        }

        let program = match unsafe {
            build_program_from_raw(instructions, len, wrap_target, wrap, sideset_bits, options)
        } {
            Some(p) => p,
            None => return errno::EINVAL,
        };

        unsafe { *slot.program.get() = program; }

        slot.set_program_status(1); // pending
        slot.program_pending.store(true, Ordering::Release);

        0
    }

    /// Configure pin mapping and clock divider
    ///
    /// data_pin: bidirectional data pin (DIO for gSPI)
    /// clk_pin: clock/sideset pin
    /// clock_div: clock divider (Q16.16 format, same as pio_stream)
    pub fn configure(handle: i32, data_pin: u8, clk_pin: u8, clock_div: u32) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return errno::EINVAL,
        };

        let state = slot.state();
        if state == PioSlotState::Free {
            return errno::ERROR;
        }

        slot.data_pin.store(data_pin, Ordering::Release);
        slot.clk_pin.store(clk_pin, Ordering::Release);
        slot.clock_div.store(clock_div, Ordering::Release);
        slot.set_state(PioSlotState::Ready);

        0
    }

    /// Start a bidirectional transfer
    ///
    /// tx_ptr/tx_len: data to shift out (null/0 for RX-only)
    /// rx_ptr/rx_len: buffer for shifted-in data (null/0 for TX-only)
    ///
    /// Returns 0 on success (transfer started), EBUSY if transfer in progress
    /// Execute a PIO cmd transfer synchronously using PAC-level DMA.
    ///
    /// Buffer format: `[tx_words(4)][data...][rx_words(4)]`
    /// Returns total bytes on success, negative errno on error.
    ///
    /// Single-core cooperative scheduling means the async runner is not
    /// executing concurrently, so PAC register access is safe.
    pub fn transfer(
        handle: i32,
        tx_ptr: *const u8,
        tx_len: usize,
        rx_ptr: *mut u8,
        rx_len: usize,
    ) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return errno::EINVAL,
        };

        if slot.state() != PioSlotState::Ready {
            return errno::EBUSY;
        }

        if tx_ptr.is_null() || tx_len < 8 {
            return errno::EINVAL;
        }

        // Read tx_words from first 4 bytes
        let tx_words = unsafe {
            core::ptr::read_unaligned(tx_ptr as *const u32)
        } as usize;

        // Read rx_words from buffer at offset 4 + tx_words*4
        let rw_off = 4 + tx_words * 4;
        let rx_words = if rw_off + 4 <= tx_len {
            (unsafe { core::ptr::read_unaligned(tx_ptr.add(rw_off) as *const u32) }) as usize
        } else {
            0
        };

        if tx_words > MAX_CMD_SCRATCH_WORDS {
            return errno::EINVAL;
        }

        let handle_idx = handle as usize;

        // Copy TX data to aligned scratch
        let scratch = unsafe { &mut CMD_SCRATCH[handle_idx] };
        let tx_data_bytes = tx_words * 4;
        if tx_words > 0 {
            scratch[tx_words - 1] = 0;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tx_ptr.add(4),
                    scratch.as_mut_ptr() as *mut u8,
                    tx_data_bytes,
                );
            }
        }

        // Compute bit counts (Embassy convention)
        let write_bits = if tx_words > 0 { tx_words * 32 - 1 } else { 0 };
        let read_words = if rx_words > 0 { rx_words } else { 1 };
        let read_bits = read_words * 32 - 1;

        // Get slot metadata
        let origin = slot.program_origin.load(Ordering::Acquire);
        if origin == 0xFF {
            return errno::ERROR;
        }
        let pio_idx = slot.pio_idx();
        let sm_idx = slot.sm_idx() as usize;
        let dma_ch = slot.dma_channel.load(Ordering::Acquire);
        if dma_ch == 0xFF {
            return errno::ERROR;
        }

        // Per-transaction SM setup via PAC
        pac_sm_set_enable(pio_idx, sm_idx, false);
        pac_sm_set_x(pio_idx, sm_idx, write_bits as u32);
        pac_sm_set_y(pio_idx, sm_idx, read_bits as u32);
        pac_sm_set_pindir(pio_idx, sm_idx, 0b1);
        pac_sm_jmp(pio_idx, sm_idx, origin);
        pac_sm_set_enable(pio_idx, sm_idx, true);

        // DMA TX: scratch → PIO TXF
        let pio = pio_pac(pio_idx);
        let tx_dreq = pio_idx * 8 + sm_idx as u8;
        if tx_words > 0 {
            dma_transfer_blocking(
                dma_ch,
                scratch.as_ptr() as u32,
                pio.txf(sm_idx).as_ptr() as u32,
                tx_words as u32,
                tx_dreq,
                true,
                false,
            );
        }

        // DMA RX: PIO RXF → scratch
        let rx_dreq = pio_idx * 8 + sm_idx as u8 + 4;
        dma_transfer_blocking(
            dma_ch,
            pio.rxf(sm_idx).as_ptr() as u32,
            scratch.as_mut_ptr() as u32,
            read_words as u32,
            rx_dreq,
            false,
            true,
        );

        // Copy RX data to caller's buffer
        let mut total_bytes = tx_len as i32;
        if rx_words > 0 && !rx_ptr.is_null() && rx_len > 0 {
            let copy_len = (rx_words * 4).min(rx_len);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    scratch.as_ptr() as *const u8,
                    rx_ptr,
                    copy_len,
                );
            }
            total_bytes += rx_len as i32;
        }

        total_bytes
    }

    /// Poll for transfer completion.
    ///
    /// With synchronous CMD_TRANSFER, transfers always complete inline.
    /// Returns 0 (nothing pending). Kept for ABI compatibility.
    pub fn poll(handle: i32) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return errno::EINVAL,
        };
        if slot.state() == PioSlotState::Ready {
            0 // Transfer completed synchronously, nothing pending
        } else {
            errno::ERROR
        }
    }

    /// Free a command slot
    pub fn free(handle: i32) {
        if let Some(slot) = Self::get_slot(handle) {
            slot.owner.store(0xFF, Ordering::Release);
            slot.reset();
        }
    }

    fn get_slot(handle: i32) -> Option<&'static PioCmdSlot> {
        let slot = Self::get_slot_raw(handle)?;
        if slot.state() == PioSlotState::Free {
            return None;
        }
        // Ownership check: only the owning module may access this slot
        let owner = slot.owner.load(Ordering::Acquire);
        if owner != 0xFF && owner != crate::kernel::scheduler::current_module_index() as u8 {
            return None;
        }
        Some(slot)
    }

    fn get_slot_raw(handle: i32) -> Option<&'static PioCmdSlot> {
        if handle < 0 || handle >= MAX_CMD_SLOTS as i32 {
            return None;
        }
        Some(&CMD_SLOTS[handle as usize])
    }

    // -- Runner-side accessors --

    pub fn get_slot_by_index(index: usize) -> Option<&'static PioCmdSlot> {
        CMD_SLOTS.get(index)
    }

    pub fn program_status_for(handle: i32) -> i32 {
        if handle < 0 || handle >= MAX_CMD_SLOTS as i32 {
            return errno::EINVAL;
        }
        CMD_SLOTS[handle as usize].program_status() as i32
    }

    /// Release all PIO command slots owned by a specific module.
    pub fn release_owned_by(module_idx: u8) {
        for slot in CMD_SLOTS.iter() {
            if slot.owner.load(Ordering::Acquire) == module_idx
                && slot.state() != PioSlotState::Free
            {
                slot.owner.store(0xFF, Ordering::Release);
                slot.reset();
            }
        }
    }
}

// ============================================================================
// PIO Command Runner (Embassy task)
// ============================================================================

/// PIO Command Runner — owns PIO SM + DMA resources, handles program loading
pub struct PioCmdRunner<'d, PIO: Instance, const SM: usize, DMA: Channel> {
    #[allow(dead_code)] // Held for Embassy resource ownership (prevents double-use)
    sm: StateMachine<'d, PIO, SM>,
    #[allow(dead_code)] // Held for Embassy resource ownership; number stored in slot at construction
    dma: Peri<'d, DMA>,
    #[allow(dead_code)] // Stored for future diagnostic use
    data_pin_num: u8,
    #[allow(dead_code)] // Stored for future diagnostic use
    clk_pin_num: Option<u8>,
    slot: usize,
    pio_num: u8,
    program_loaded: bool,
    program_origin: Option<u8>,
    used_mask: u32,
}

impl<'d, PIO: Instance, const SM: usize, DMA: Channel> PioCmdRunner<'d, PIO, SM, DMA> {
    /// Create a new PIO command runner
    pub fn new(
        sm: StateMachine<'d, PIO, SM>,
        dma: Peri<'d, DMA>,
        data_pin_num: u8,
        slot: usize,
        pio_num: u8,
    ) -> Self {
        log::info!("[pio] cmd ready slot={} PIO{}:SM{}", slot, pio_num, SM);
        // Store DMA channel number in slot for sync_transfer() access
        if let Some(s) = PioCmdService::get_slot_by_index(slot) {
            s.dma_channel.store(dma.number(), Ordering::Release);
        }
        Self {
            sm,
            dma,
            data_pin_num,
            clk_pin_num: None,
            slot,
            pio_num,
            program_loaded: false,
            program_origin: None,
            used_mask: 0,
        }
    }

    /// Create a new PIO command runner with a separate clock/sideset pin
    pub fn new_with_clk(
        sm: StateMachine<'d, PIO, SM>,
        dma: Peri<'d, DMA>,
        data_pin_num: u8,
        clk_pin_num: u8,
        slot: usize,
        pio_num: u8,
    ) -> Self {
        log::info!("[pio] cmd ready slot={} PIO{}:SM{} clk", slot, pio_num, SM);
        // Store DMA channel number in slot for sync_transfer() access
        if let Some(s) = PioCmdService::get_slot_by_index(slot) {
            s.dma_channel.store(dma.number(), Ordering::Release);
        }
        Self {
            sm,
            dma,
            data_pin_num,
            clk_pin_num: Some(clk_pin_num),
            slot,
            pio_num,
            program_loaded: false,
            program_origin: None,
            used_mask: 0,
        }
    }

    fn load_program(&mut self, program: &PioProgram, data_pin: u8, clk_pin: u8, clock_div: u32) -> bool {
        let pio = pio_pac(self.pio_num);

        // Disable SM via PAC (not Embassy — avoids internal state mismatch)
        pio.ctrl().modify(|w| {
            w.set_sm_enable(w.sm_enable() & !(1 << SM));
        });

        let origin = match prepare_program_load(self.pio_num, program, &mut self.used_mask) {
            Some(o) => o,
            None => return false,
        };
        // Configure SM — left disabled; each process_transfer sets up forced
        // instructions (set_x, set_y, set_pindir, exec_jmp) then enables SM.
        self.configure_sm_pac(program, origin, data_pin, clk_pin, clock_div);

        self.program_loaded = true;
        self.program_origin = Some(origin);
        true
    }

    fn free_instructions(&mut self) {
        if self.used_mask != 0 {
            free_instruction_slots(self.pio_num, self.used_mask);
            self.used_mask = 0;
            self.program_origin = None;
        }
    }

    fn configure_sm_pac(
        &self,
        program: &PioProgram,
        origin: u8,
        data_pin: u8,
        clk_pin: u8,
        clock_div: u32,
    ) {
        let pio = pio_pac(self.pio_num);
        let sm = pio.sm(SM);

        sm.execctrl().modify(|w| {
            w.set_wrap_bottom(origin + program.wrap_target);
            w.set_wrap_top(origin + program.wrap);
            w.set_side_en(program.sideset_optional);
            w.set_side_pindir(program.sideset_pindirs);
        });

        sm.pinctrl().modify(|w| {
            w.set_out_base(data_pin);
            w.set_out_count(1);
            w.set_in_base(data_pin);
            w.set_set_base(data_pin);
            w.set_set_count(1);
            w.set_sideset_base(clk_pin);
            w.set_sideset_count(program.sideset_bits);
        });

        sm.clkdiv().write(|w| {
            w.0 = clock_div << 8;
        });

        // Autopull + autopush, MSB-first (shift left), 32-bit threshold.
        // Matches Embassy's cyw43-pio SM config exactly.
        sm.shiftctrl().modify(|w| {
            w.set_fjoin_tx(false);
            w.set_fjoin_rx(false);
            w.set_autopull(true);      // autopull feeds TX data via `out`
            w.set_autopush(true);      // autopush captures RX data via `in`
            w.set_out_shiftdir(false); // MSB first (shift left)
            w.set_in_shiftdir(false);  // MSB first (shift left)
            w.set_pull_thresh(0);      // 0 = 32-bit threshold
            w.set_push_thresh(0);      // 0 = 32-bit threshold
        });

        // Jump to entry point (SM stays disabled — enabled when FIFO has data)
        let entry_point = origin + program.wrap_target;
        let jmp_instr = 0x0000 | (entry_point as u16);
        sm.instr().write(|w| w.set_instr(jmp_instr));

        // Force DIO and CLK as output LOW before chip power-on.
        // CYW43439 samples DATA2 (our DIO pin) during power-on reset to select
        // gSPI mode. Must be actively driven LOW — matches Embassy's
        // sm.set_pin_dirs(Out) + sm.set_pins(Low) sequence.
        set_sm_pin_output(self.pio_num, SM as u8, data_pin);
        set_sm_pin_output(self.pio_num, SM as u8, clk_pin);

        // Enable input sync bypass on DIO pin for reduced input latency.
        // Bypasses the 2-flipflop synchronizer for faster sampling.
        // Matches Embassy's pin_io.set_input_sync_bypass(true).
        pio.input_sync_bypass().modify(|w| *w |= 1u32 << data_pin);
    }

    /// Check for and load a pending program
    fn try_load_pending_program(&mut self) {
        let slot = match PioCmdService::get_slot_by_index(self.slot) {
            Some(s) => s,
            None => return,
        };

        if !slot.is_program_pending() {
            return;
        }

        // Need config to be set (state = Ready or later)
        if slot.state() == PioSlotState::Allocated {
            // Config not set yet — wait
            return;
        }

        // Validate pio_idx: module requested PIO must match this runner's PIO
        if slot.pio_idx() != self.pio_num {
            log::error!("[pio] cmd slot={} pio_idx={} != runner pio_num={}, rejecting",
                self.slot, slot.pio_idx(), self.pio_num);
            slot.take_program_pending(); // consume the flag
            slot.set_program_status(3); // error
            return;
        }

        if !slot.take_program_pending() {
            return;
        }

        let program = unsafe { slot.program() };
        let data_pin = slot.data_pin();
        let clk_pin = slot.clk_pin();
        let clock_div = slot.clock_div();

        if self.load_program(program, data_pin, clk_pin, clock_div) {
            // Store origin in slot so sync_transfer() can access it
            if let Some(origin) = self.program_origin {
                slot.program_origin.store(origin, Ordering::Release);
            }
            slot.set_program_status(2); // loaded
        } else {
            slot.set_program_status(3); // error
        }
    }

    /// Run the command runner (call this in an Embassy task).
    ///
    /// Transfers are handled synchronously in `PioCmdService::transfer()` via
    /// PAC-level DMA (called from syscall context). The runner only handles
    /// program loading and slot lifecycle.
    pub async fn run(&mut self) -> ! {
        loop {
            // Detect slot freed — release instruction memory to avoid leak.
            if self.program_loaded {
                if let Some(s) = PioCmdService::get_slot_by_index(self.slot) {
                    if s.state() == PioSlotState::Free {
                        self.free_instructions();
                        self.program_loaded = false;
                    }
                }
            }

            // Check for pending program load
            self.try_load_pending_program();

            // Yield
            embassy_time::Timer::after(embassy_time::Duration::from_millis(1)).await;
        }
    }
}

// ============================================================================
// PAC-level PIO Transfer Helpers
// ============================================================================

/// Execute a forced instruction on a PIO state machine via PAC.
fn pac_sm_exec(pio_idx: u8, sm: usize, instr: u16) {
    let pio = pio_pac(pio_idx);
    pio.sm(sm).instr().write(|w| w.set_instr(instr));
    cortex_m::asm::delay(10);
}

/// Set X register: push value to TXF, then force `OUT X, 32`.
fn pac_sm_set_x(pio_idx: u8, sm: usize, value: u32) {
    let pio = pio_pac(pio_idx);
    pio.txf(sm).write_value(value);
    pac_sm_exec(pio_idx, sm, 0x6020); // OUT X, 32
}

/// Set Y register: push value to TXF, then force `OUT Y, 32`.
fn pac_sm_set_y(pio_idx: u8, sm: usize, value: u32) {
    let pio = pio_pac(pio_idx);
    pio.txf(sm).write_value(value);
    pac_sm_exec(pio_idx, sm, 0x6040); // OUT Y, 32
}

/// Force `SET PINDIRS, value`.
fn pac_sm_set_pindir(pio_idx: u8, sm: usize, value: u8) {
    pac_sm_exec(pio_idx, sm, 0xE080 | value as u16); // SET PINDIRS, n
}

/// Force `JMP addr`.
fn pac_sm_jmp(pio_idx: u8, sm: usize, addr: u8) {
    pac_sm_exec(pio_idx, sm, addr as u16); // JMP addr (opcode 000)
}

/// Enable or disable a PIO state machine via PAC.
fn pac_sm_set_enable(pio_idx: u8, sm: usize, enable: bool) {
    let pio = pio_pac(pio_idx);
    pio.ctrl().modify(|w| {
        let mask = 1u8 << sm;
        if enable {
            w.set_sm_enable(w.sm_enable() | mask);
        } else {
            w.set_sm_enable(w.sm_enable() & !mask);
        }
    });
}

/// Perform a synchronous DMA transfer using PAC registers. Busy-waits for completion.
fn dma_transfer_blocking(
    dma_ch: u8,
    read_addr: u32,
    write_addr: u32,
    count: u32,
    dreq: u8,
    incr_read: bool,
    incr_write: bool,
) {
    let ch = pac::DMA.ch(dma_ch as usize);
    ch.read_addr().write_value(read_addr);
    ch.write_addr().write_value(write_addr);
    crate::kernel::chip::dma_write_trans_count(&ch, count);
    compiler_fence(Ordering::SeqCst);
    ch.ctrl_trig().write(|w| {
        w.set_treq_sel(pac::dma::vals::TreqSel::from(dreq));
        w.set_data_size(pac::dma::vals::DataSize::SIZE_WORD);
        w.set_incr_read(incr_read);
        w.set_incr_write(incr_write);
        w.set_chain_to(dma_ch); // chain to self = no chaining
        w.set_en(true);
    });
    compiler_fence(Ordering::SeqCst);
    while ch.ctrl_trig().read().busy() {}
    compiler_fence(Ordering::SeqCst);
}

// ============================================================================
// Command Syscall Entry Points
// ============================================================================

pub unsafe extern "C" fn syscall_pio_cmd_alloc(pio_idx: u8, sm_idx: u8) -> i32 {
    use crate::kernel::fd::{tag_fd, FD_TAG_PIO_CMD};
    tag_fd(FD_TAG_PIO_CMD, PioCmdService::alloc(pio_idx, sm_idx))
}

pub unsafe extern "C" fn syscall_pio_cmd_load_program(
    handle: i32,
    instructions: *const u16,
    len: usize,
    wrap_target: u8,
    wrap: u8,
    sideset_bits: u8,
    options: u8,
) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioCmdService::load_program(handle, instructions, len, wrap_target, wrap, sideset_bits, options)
}

pub unsafe extern "C" fn syscall_pio_cmd_configure(
    handle: i32,
    data_pin: u8,
    clk_pin: u8,
    clock_div: u32,
) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioCmdService::configure(handle, data_pin, clk_pin, clock_div)
}

pub unsafe extern "C" fn syscall_pio_cmd_transfer(
    handle: i32,
    tx_ptr: *const u8,
    tx_len: usize,
    rx_ptr: *mut u8,
    rx_len: usize,
) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioCmdService::transfer(handle, tx_ptr, tx_len, rx_ptr, rx_len)
}

pub unsafe extern "C" fn syscall_pio_cmd_poll(handle: i32) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioCmdService::poll(handle)
}

pub unsafe extern "C" fn syscall_pio_cmd_free(handle: i32) {
    let handle = crate::kernel::fd::slot_of(handle);
    PioCmdService::free(handle)
}

// ============================================================================
// PIO RX Stream: Continuous DMA Input Capture
// ============================================================================

/// Maximum number of concurrent PIO RX streams
pub const MAX_RX_STREAMS: usize = 1;

/// Buffer size in u32 words for RX stream.
/// 512 words = 2048 bytes = ~32ms at 16kHz stereo, ~11.6ms at 44.1kHz stereo.
pub const RX_BUFFER_WORDS: usize = 512;

/// Double-buffered PIO RX stream slot.
///
/// DMA continuously fills one buffer while the module reads from the other.
/// If the module is too slow, the overflow counter increments and capture
/// continues without gaps (correct for real-time audio).
pub struct PioRxStreamSlot {
    buffer_a: [u32; RX_BUFFER_WORDS],
    buffer_b: [u32; RX_BUFFER_WORDS],
    /// Which buffer DMA is currently filling (true=B, false=A)
    dma_fills_b: AtomicBool,
    state: AtomicU8,
    owner: AtomicU8,
    /// Set by runner when a buffer is full and ready for module to read
    pull_ready: AtomicBool,
    /// Number of words in the ready buffer
    pull_count: AtomicUsize,
    /// Module has taken the ready buffer
    pull_taken: AtomicBool,
    /// Overflow counter (DMA completed but module hadn't read previous buffer)
    overflow_count: AtomicU32,
    // Config
    in_pin: AtomicU8,
    sideset_base: AtomicU8,
    clock_divider: AtomicU32,
    shift_bits: AtomicU8,
    // Program
    program: UnsafeCell<PioProgram>,
    program_pending: AtomicBool,
    program_status: AtomicU8,
    // Rate
    units_per_sec_q16: AtomicU32,
}

unsafe impl Sync for PioRxStreamSlot {}

impl PioRxStreamSlot {
    pub const fn new() -> Self {
        Self {
            buffer_a: [0; RX_BUFFER_WORDS],
            buffer_b: [0; RX_BUFFER_WORDS],
            dma_fills_b: AtomicBool::new(false),
            state: AtomicU8::new(PioSlotState::Free as u8),
            owner: AtomicU8::new(0xFF),
            pull_ready: AtomicBool::new(false),
            pull_count: AtomicUsize::new(0),
            pull_taken: AtomicBool::new(false),
            overflow_count: AtomicU32::new(0),
            in_pin: AtomicU8::new(0),
            sideset_base: AtomicU8::new(0),
            clock_divider: AtomicU32::new(0),
            shift_bits: AtomicU8::new(32),
            program: UnsafeCell::new(PioProgram::empty()),
            program_pending: AtomicBool::new(false),
            program_status: AtomicU8::new(0),
            units_per_sec_q16: AtomicU32::new(0),
        }
    }

    pub fn state(&self) -> PioSlotState {
        PioSlotState::from(self.state.load(Ordering::Acquire))
    }

    pub fn set_state(&self, state: PioSlotState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// Get pointer to the buffer the module can read from (not being DMA-filled).
    pub fn readable_buffer_ptr(&self) -> *const u32 {
        if self.dma_fills_b.load(Ordering::Acquire) {
            // DMA fills B → module reads A
            self.buffer_a.as_ptr()
        } else {
            // DMA fills A → module reads B
            self.buffer_b.as_ptr()
        }
    }

    /// Get mutable pointer to the buffer DMA should fill.
    fn dma_fill_buffer(&self) -> *mut u32 {
        if self.dma_fills_b.load(Ordering::Acquire) {
            self.buffer_b.as_ptr() as *mut u32
        } else {
            self.buffer_a.as_ptr() as *mut u32
        }
    }

    /// Swap which buffer DMA fills.
    fn swap_buffers(&self) {
        let was_b = self.dma_fills_b.load(Ordering::Acquire);
        self.dma_fills_b.store(!was_b, Ordering::Release);
    }

    pub fn configure(&self, in_pin: u8, sideset_base: u8, clock_divider: u32, shift_bits: u8) {
        self.in_pin.store(in_pin, Ordering::Release);
        self.sideset_base.store(sideset_base, Ordering::Release);
        self.clock_divider.store(clock_divider, Ordering::Release);
        self.shift_bits.store(shift_bits, Ordering::Release);
        self.set_state(PioSlotState::Ready);
    }

    pub fn in_pin(&self) -> u8 { self.in_pin.load(Ordering::Acquire) }
    pub fn sideset_base(&self) -> u8 { self.sideset_base.load(Ordering::Acquire) }
    pub fn clock_divider(&self) -> u32 { self.clock_divider.load(Ordering::Acquire) }
    pub fn shift_bits(&self) -> u8 { self.shift_bits.load(Ordering::Acquire) }

    pub unsafe fn load_program(&self, program: &PioProgram) {
        let ptr = self.program.get();
        (*ptr) = *program;
    }

    pub fn set_program_pending(&self) {
        self.program_pending.store(true, Ordering::Release);
    }

    pub fn take_program_pending(&self) -> bool {
        self.program_pending.swap(false, Ordering::AcqRel)
    }

    pub fn is_program_pending(&self) -> bool {
        self.program_pending.load(Ordering::Acquire)
    }

    pub fn program_status(&self) -> u8 {
        self.program_status.load(Ordering::Acquire)
    }

    pub fn set_program_status(&self, status: u8) {
        self.program_status.store(status, Ordering::Release);
    }

    pub unsafe fn program(&self) -> &PioProgram {
        &*self.program.get()
    }

    pub fn set_pull_ready(&self, count: usize) {
        self.pull_count.store(count, Ordering::Release);
        self.pull_taken.store(false, Ordering::Release);
        self.pull_ready.store(true, Ordering::Release);
    }

    pub fn can_pull(&self) -> bool {
        self.pull_ready.load(Ordering::Acquire)
    }

    /// Take the ready buffer. Returns word count if successful.
    pub fn take_pull_ready(&self) -> Option<usize> {
        if self.pull_ready.swap(false, Ordering::AcqRel) {
            self.pull_taken.store(true, Ordering::Release);
            Some(self.pull_count.load(Ordering::Acquire))
        } else {
            None
        }
    }

    /// Check if module has taken (acknowledged) the last ready buffer.
    pub fn is_taken(&self) -> bool {
        self.pull_taken.load(Ordering::Acquire)
    }

    pub fn overflow_count(&self) -> u32 {
        self.overflow_count.load(Ordering::Acquire)
    }

    pub fn reset(&self) {
        self.dma_fills_b.store(false, Ordering::Release);
        self.pull_ready.store(false, Ordering::Release);
        self.pull_count.store(0, Ordering::Release);
        self.pull_taken.store(false, Ordering::Release);
        self.overflow_count.store(0, Ordering::Release);
        self.program_pending.store(false, Ordering::Release);
        self.program_status.store(0, Ordering::Release);
        self.units_per_sec_q16.store(0, Ordering::Release);
        unsafe {
            (*self.program.get()) = PioProgram::empty();
        }
        self.set_state(PioSlotState::Free);
    }
}

/// Static pool of PIO RX stream slots
static RX_STREAM_SLOTS: [PioRxStreamSlot; MAX_RX_STREAMS] = [
    PioRxStreamSlot::new(),
];

// ============================================================================
// PIO RX Stream Service
// ============================================================================

pub struct PioRxStreamService;

impl PioRxStreamService {
    pub fn alloc() -> i32 {
        let owner = crate::kernel::scheduler::current_module_index() as u8;
        for (i, slot) in RX_STREAM_SLOTS.iter().enumerate() {
            if slot.state.compare_exchange(
                PioSlotState::Free as u8,
                PioSlotState::Allocated as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                slot.owner.store(owner, Ordering::Release);
                return i as i32;
            }
        }
        log::warn!("[pio] rx no free slots");
        errno::ENOMEM
    }

    fn check_owner(handle: i32) -> bool {
        if handle < 0 || handle >= MAX_RX_STREAMS as i32 {
            return false;
        }
        let owner = RX_STREAM_SLOTS[handle as usize].owner.load(Ordering::Acquire);
        owner == 0xFF || owner == crate::kernel::scheduler::current_module_index() as u8
    }

    pub fn load_program(
        handle: i32,
        instructions: *const u16,
        len: usize,
        wrap_target: u8,
        wrap: u8,
        sideset_bits: u8,
        options: u8,
    ) -> i32 {
        if handle < 0 || handle >= MAX_RX_STREAMS as i32 || !Self::check_owner(handle) {
            return errno::EINVAL;
        }
        let slot = &RX_STREAM_SLOTS[handle as usize];
        let state = slot.state();
        if state == PioSlotState::Free || state == PioSlotState::Busy {
            return errno::EBUSY;
        }

        let program = match unsafe {
            build_program_from_raw(instructions, len, wrap_target, wrap, sideset_bits, options)
        } {
            Some(p) => p,
            None => return errno::EINVAL,
        };

        unsafe { slot.load_program(&program); }
        slot.set_program_status(1); // pending
        slot.set_program_pending();

        0
    }

    pub fn configure(handle: i32, in_pin: u8, sideset_base: u8, clock_divider: u32, shift_bits: u8) -> i32 {
        if handle < 0 || handle >= MAX_RX_STREAMS as i32 || !Self::check_owner(handle) {
            return errno::EINVAL;
        }
        let slot = &RX_STREAM_SLOTS[handle as usize];
        if slot.state() == PioSlotState::Free {
            return errno::ERROR;
        }
        slot.configure(in_pin, sideset_base, clock_divider, shift_bits);
        0
    }

    pub fn can_pull(handle: i32) -> i32 {
        if handle < 0 || handle >= MAX_RX_STREAMS as i32 {
            return 0;
        }
        let slot = &RX_STREAM_SLOTS[handle as usize];
        if slot.state() == PioSlotState::Free {
            return 0;
        }
        if slot.can_pull() { 1 } else { 0 }
    }

    /// Acknowledge reading of the ready buffer. Returns word count.
    pub fn pull(handle: i32) -> i32 {
        if handle < 0 || handle >= MAX_RX_STREAMS as i32 || !Self::check_owner(handle) {
            return errno::EINVAL;
        }
        let slot = &RX_STREAM_SLOTS[handle as usize];
        match slot.take_pull_ready() {
            Some(count) => count as i32,
            None => 0, // nothing ready
        }
    }

    /// Get pointer to the readable buffer.
    pub fn get_buffer(handle: i32) -> *const u32 {
        if handle < 0 || handle >= MAX_RX_STREAMS as i32 || !Self::check_owner(handle) {
            return core::ptr::null();
        }
        let slot = &RX_STREAM_SLOTS[handle as usize];
        if slot.state() == PioSlotState::Free || !slot.can_pull() {
            return core::ptr::null();
        }
        slot.readable_buffer_ptr()
    }

    pub fn free(handle: i32) {
        if handle < 0 || handle >= MAX_RX_STREAMS as i32 || !Self::check_owner(handle) {
            return;
        }
        let slot = &RX_STREAM_SLOTS[handle as usize];
        slot.owner.store(0xFF, Ordering::Release);
        slot.reset();
    }

    pub fn set_rate(handle: i32, rate_q16: u32) {
        if handle >= 0 && (handle as usize) < MAX_RX_STREAMS {
            RX_STREAM_SLOTS[handle as usize].units_per_sec_q16.store(rate_q16, Ordering::Release);
        }
    }

    pub fn release_owned_by(module_idx: u8) {
        for slot in RX_STREAM_SLOTS.iter() {
            if slot.owner.load(Ordering::Acquire) == module_idx
                && slot.state() != PioSlotState::Free
            {
                slot.owner.store(0xFF, Ordering::Release);
                slot.reset();
            }
        }
    }

    // --- Runner-facing helpers ---

    pub fn is_program_pending_for(handle: usize) -> bool {
        if handle >= MAX_RX_STREAMS { return false; }
        RX_STREAM_SLOTS[handle].is_program_pending()
    }

    pub fn take_program_pending_for(handle: usize) -> bool {
        if handle >= MAX_RX_STREAMS { return false; }
        RX_STREAM_SLOTS[handle].take_program_pending()
    }

    pub fn set_program_status_for(handle: usize, status: u8) {
        if handle < MAX_RX_STREAMS {
            RX_STREAM_SLOTS[handle].set_program_status(status);
        }
    }

    pub fn get_config(handle: usize) -> Option<(u8, u8, u32, u8)> {
        if handle >= MAX_RX_STREAMS { return None; }
        let slot = &RX_STREAM_SLOTS[handle];
        let state = slot.state();
        if state != PioSlotState::Ready && state != PioSlotState::Busy {
            return None;
        }
        Some((slot.in_pin(), slot.sideset_base(), slot.clock_divider(), slot.shift_bits()))
    }

    pub unsafe fn get_program(handle: usize) -> Option<&'static PioProgram> {
        if handle >= MAX_RX_STREAMS { return None; }
        let slot = &RX_STREAM_SLOTS[handle];
        if slot.state() == PioSlotState::Free { return None; }
        Some(slot.program())
    }

    pub fn get_dma_fill_buffer(handle: usize) -> *mut u32 {
        if handle >= MAX_RX_STREAMS { return core::ptr::null_mut(); }
        RX_STREAM_SLOTS[handle].dma_fill_buffer()
    }

    pub fn signal_buffer_ready(handle: usize, count: usize) {
        if handle >= MAX_RX_STREAMS { return; }
        let slot = &RX_STREAM_SLOTS[handle];
        // Check if module took the previous buffer
        if slot.can_pull() && !slot.is_taken() {
            // Module didn't read previous buffer — overflow
            slot.overflow_count.fetch_add(1, Ordering::Relaxed);
        }
        slot.swap_buffers();
        slot.set_pull_ready(count);
    }

    pub fn set_busy(handle: usize, busy: bool) {
        if handle >= MAX_RX_STREAMS { return; }
        let slot = &RX_STREAM_SLOTS[handle];
        if busy {
            slot.set_state(PioSlotState::Busy);
        } else {
            slot.set_state(PioSlotState::Ready);
        }
    }
}

// ============================================================================
// PIO RX Stream Runner (Embassy task that executes DMA capture)
// ============================================================================

pub struct PioRxStreamRunner<'d, PIO: Instance, const SM: usize, DMA: Channel> {
    sm: StateMachine<'d, PIO, SM>,
    dma: Peri<'d, DMA>,
    _in_pin: u8,
    sideset_pin0: Option<u8>,
    sideset_pin1: Option<u8>,
    slot: usize,
    pio_num: u8,
    program_loaded: bool,
    program_origin: Option<u8>,
    used_mask: u32,
}

impl<'d, PIO: Instance, const SM: usize, DMA: Channel> PioRxStreamRunner<'d, PIO, SM, DMA> {
    pub fn new_with_sideset(
        sm: StateMachine<'d, PIO, SM>,
        dma: Peri<'d, DMA>,
        in_pin: u8,
        sideset_pin0: u8,
        sideset_pin1: u8,
        slot: usize,
        pio_num: u8,
    ) -> Self {
        log::info!("[pio] rx ready slot={} PIO{}", slot, pio_num);
        Self {
            sm,
            dma,
            _in_pin: in_pin,
            sideset_pin0: Some(sideset_pin0),
            sideset_pin1: Some(sideset_pin1),
            slot,
            pio_num,
            program_loaded: false,
            program_origin: None,
            used_mask: 0,
        }
    }

    fn load_program(&mut self, program: &PioProgram, in_pin: u8, sideset_base: u8, clock_divider: u32, shift_bits: u8) -> bool {
        self.sm.set_enable(false);

        let origin = match prepare_program_load(self.pio_num, program, &mut self.used_mask) {
            Some(o) => o,
            None => return false,
        };
        self.configure_sm_pac(program, origin, in_pin, sideset_base, clock_divider, shift_bits);

        // Setup pins for PIO
        setup_pio_pin(in_pin, self.pio_num, PioPull::PullUp);
        // Data pin is INPUT — do NOT set pindirs to output
        // Sideset pins are outputs (BCLK/LRCLK — master mode)
        if let Some(ss0) = self.sideset_pin0 {
            setup_pio_pin(ss0, self.pio_num, PioPull::PullUp);
            set_sm_pin_output(self.pio_num, SM as u8, ss0);
        }
        if let Some(ss1) = self.sideset_pin1 {
            setup_pio_pin(ss1, self.pio_num, PioPull::PullUp);
            set_sm_pin_output(self.pio_num, SM as u8, ss1);
        }

        self.sm.set_enable(true);
        self.program_loaded = true;
        self.program_origin = Some(origin);
        true
    }

    fn free_instructions(&mut self) {
        if self.used_mask != 0 {
            free_instruction_slots(self.pio_num, self.used_mask);
            self.used_mask = 0;
            self.program_origin = None;
        }
    }

    fn configure_sm_pac(&self, program: &PioProgram, origin: u8, in_pin: u8, sideset_base: u8, clock_divider: u32, shift_bits: u8) {
        let pio = pio_pac(self.pio_num);
        let sm = pio.sm(SM);

        // Execution control: wrap boundaries
        sm.execctrl().modify(|w| {
            w.set_wrap_bottom(origin + program.wrap_target);
            w.set_wrap_top(origin + program.wrap);
            w.set_side_en(program.sideset_optional);
            w.set_side_pindir(program.sideset_pindirs);
        });

        // Pin control: in_base for data input, sideset for clock outputs
        sm.pinctrl().modify(|w| {
            w.set_in_base(in_pin);
            w.set_sideset_base(sideset_base);
            w.set_sideset_count(program.sideset_bits);
            // No out pins for RX
            w.set_out_count(0);
            w.set_set_count(1);
            w.set_set_base(in_pin);
        });

        // Clock divider
        sm.clkdiv().write(|w| {
            w.0 = clock_divider << 8;
        });

        // Shift control: RX-specific
        sm.shiftctrl().modify(|w| {
            w.set_fjoin_rx(true);    // Join FIFOs for deeper RX buffer
            w.set_fjoin_tx(false);
            w.set_autopush(true);    // Auto-push when shift register full
            w.set_in_shiftdir(false); // Shift left (MSB first for I2S)
            w.set_push_thresh(shift_bits);
            w.set_autopull(false);   // No autopull for RX
        });

        // Set sideset pins as outputs
        if sideset_base != in_pin {
            sm.pinctrl().modify(|w| {
                w.set_set_base(sideset_base);
                w.set_set_count(program.sideset_bits);
            });
            let sideset_mask = (1u16 << program.sideset_bits) - 1;
            let set_pindirs_ss = 0xE080_u16 | sideset_mask;
            sm.instr().write(|w| w.set_instr(set_pindirs_ss));
        }

        // Restore pinctrl for normal operation
        sm.pinctrl().modify(|w| {
            w.set_in_base(in_pin);
            w.set_sideset_base(sideset_base);
            w.set_sideset_count(program.sideset_bits);
            w.set_set_base(in_pin);
            w.set_set_count(1);
        });

        // Jump to entry point (program.wrap = last instruction = entry point)
        let entry_point = origin + program.wrap;
        let jmp_instr = 0x0000 | (entry_point as u16);
        sm.instr().write(|w| w.set_instr(jmp_instr));

        // Enable state machine
        pio.ctrl().modify(|w| {
            let current = w.sm_enable();
            w.set_sm_enable(current | (1 << SM));
        });
    }

    fn try_load_pending_program(&mut self) {
        if !PioRxStreamService::is_program_pending_for(self.slot) {
            return;
        }
        let config = match PioRxStreamService::get_config(self.slot) {
            Some(c) => c,
            None => return,
        };
        let program = match unsafe { PioRxStreamService::get_program(self.slot) } {
            Some(p) => p,
            None => return,
        };
        if !PioRxStreamService::take_program_pending_for(self.slot) {
            return;
        }

        let (in_pin, sideset_base, clock_div, shift_bits) = config;
        if self.load_program(program, in_pin, sideset_base, clock_div, shift_bits) {
            PioRxStreamService::set_program_status_for(self.slot, 2); // loaded
            log::info!("[pio] rx loaded slot={}", self.slot);
        } else {
            PioRxStreamService::set_program_status_for(self.slot, 3); // error
            log::error!("[pio] rx load failed slot={}", self.slot);
        }
    }

    /// Run the RX stream runner (call this in an Embassy task).
    ///
    /// Continuously captures DMA buffers from PIO RX FIFO. The module reads
    /// completed buffers via can_pull/get_buffer/pull. If the module is too
    /// slow, overflow is counted but capture never stalls.
    pub async fn run(&mut self) -> ! {
        self.try_load_pending_program();

        loop {
            // Detect slot freed — release instruction memory
            if self.program_loaded && RX_STREAM_SLOTS[self.slot].state() == PioSlotState::Free {
                self.free_instructions();
                self.program_loaded = false;
                self.sm.set_enable(false);
            }

            // Check for pending program load
            self.try_load_pending_program();

            if self.program_loaded {
                PioRxStreamService::set_busy(self.slot, true);

                // Get the buffer to fill via DMA
                let fill_buf = PioRxStreamService::get_dma_fill_buffer(self.slot);
                let fill_slice = unsafe {
                    core::slice::from_raw_parts_mut(fill_buf, RX_BUFFER_WORDS)
                };

                // DMA pull: blocks until RX FIFO fills the buffer
                let rx = self.sm.rx();
                rx.dma_pull(self.dma.reborrow(), fill_slice, false).await;

                // Signal buffer ready to module (handles overflow counting + swap)
                PioRxStreamService::signal_buffer_ready(self.slot, RX_BUFFER_WORDS);

                PioRxStreamService::set_busy(self.slot, false);
            } else {
                // No program loaded, yield
                embassy_time::Timer::after(embassy_time::Duration::from_millis(1)).await;
            }
        }
    }
}

// ============================================================================
// RX Stream Syscall Implementations
// ============================================================================

pub unsafe extern "C" fn syscall_pio_rx_stream_alloc() -> i32 {
    use crate::kernel::fd::{tag_fd, FD_TAG_PIO_RX_STREAM};
    tag_fd(FD_TAG_PIO_RX_STREAM, PioRxStreamService::alloc())
}

pub unsafe extern "C" fn syscall_pio_rx_stream_load_program(
    handle: i32,
    instructions: *const u16,
    len: usize,
    wrap_target: u8,
    wrap: u8,
    sideset_bits: u8,
    options: u8,
) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioRxStreamService::load_program(handle, instructions, len, wrap_target, wrap, sideset_bits, options)
}

pub unsafe extern "C" fn syscall_pio_rx_stream_configure(
    handle: i32,
    in_pin: u8,
    sideset_base: u8,
    clock_divider: u32,
    shift_bits: u8,
) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioRxStreamService::configure(handle, in_pin, sideset_base, clock_divider, shift_bits)
}

pub unsafe extern "C" fn syscall_pio_rx_stream_get_buffer(handle: i32) -> *const u32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioRxStreamService::get_buffer(handle)
}

pub unsafe extern "C" fn syscall_pio_rx_stream_can_pull(handle: i32) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioRxStreamService::can_pull(handle)
}

pub unsafe extern "C" fn syscall_pio_rx_stream_pull(handle: i32) -> i32 {
    let handle = crate::kernel::fd::slot_of(handle);
    PioRxStreamService::pull(handle)
}

pub unsafe extern "C" fn syscall_pio_rx_stream_free(handle: i32) {
    let handle = crate::kernel::fd::slot_of(handle);
    PioRxStreamService::free(handle)
}

// RGB parallel output moved to src/io/rgb.rs


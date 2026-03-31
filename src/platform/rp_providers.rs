// RP-family hardware providers for the syscall system.
//
// This file is `include!`d from `src/kernel/syscalls.rs` under `#[cfg(feature = "rp")]`.
// All symbols share the `syscalls` module namespace — they can reference E_NOSYS,
// channel::*, gpio::*, etc. directly.

use embassy_time::{Duration, Timer};
use crate::io::spi::SpiBus;
use crate::io::pio;
use crate::io::i2c::{I2cBus, I2cError};
use crate::io::uart::UartBus;
use crate::io::adc::AdcBus;

// ============================================================================
// SPI Subsystem
// ============================================================================

const MAX_SPI_HANDLES: usize = 8;
const INVALID_HANDLE: i32 = -1;
const SPI_MODE_MASK: u8 = 0b0000_1111;
const SPI_MAX_FREQ_HZ: u32 = 12_000_000;

/// Sentinel owner value: handle not owned by any module (kernel-owned or unassigned).
const OWNER_KERNEL: u8 = 0xFF;

static mut SPI_BUSES: [*mut SpiBus; 2] = [null_mut(), null_mut()];

#[derive(Clone, Copy)]
struct SpiHandle {
    in_use: bool,
    bus_id: u8,      // Which SPI bus (0 or 1)
    cs_handle: i32,  // GPIO handle (= pin number with new GPIO module)
    freq: u32,
    mode: u8,
    owner: u8,       // Module index that opened this handle (OWNER_KERNEL if kernel-owned)
}

impl SpiHandle {
    const fn empty() -> Self {
        Self {
            in_use: false,
            bus_id: 0,
            cs_handle: INVALID_HANDLE,
            freq: 0,
            mode: 0,
            owner: OWNER_KERNEL,
        }
    }
}

/// Per-handle SPI operation state for the async bridge.
/// This allows each handle to have a pending operation without global contention.
struct SpiOperation {
    pending: AtomicBool,      // true = operation staged, awaiting execution
    result: AtomicI32,        // 0 = in progress, >0 = bytes transferred, <0 = error
    tx_ptr: *const u8,
    tx_len: usize,
    rx_ptr: *mut u8,
    rx_len: usize,
    fill: u8,
}

// SAFETY: SpiOperation is only accessed from:
// - Syscall thread (writes pending/pointers when pending=false, reads result when pending=false)
// - Async task (reads/clears pending, reads pointers, writes result)
// The pending atomic provides the synchronization.
unsafe impl Sync for SpiOperation {}

impl SpiOperation {
    const fn empty() -> Self {
        Self {
            pending: AtomicBool::new(false),
            result: AtomicI32::new(0),
            tx_ptr: core::ptr::null(),
            tx_len: 0,
            rx_ptr: core::ptr::null_mut(),
            rx_len: 0,
            fill: 0xFF,
        }
    }
}

static mut SPI_HANDLES: [SpiHandle; MAX_SPI_HANDLES] = [SpiHandle::empty(); MAX_SPI_HANDLES];
static mut SPI_OPERATIONS: [SpiOperation; MAX_SPI_HANDLES] = [const { SpiOperation::empty() }; MAX_SPI_HANDLES];
static SPI_OWNER: [AtomicI32; 2] = [AtomicI32::new(INVALID_HANDLE), AtomicI32::new(INVALID_HANDLE)];
/// Currently executing SPI operation's handle index (or INVALID_HANDLE if none).
static SPI_ACTIVE_HANDLE: AtomicI32 = AtomicI32::new(INVALID_HANDLE);
/// Per-bus busy flag: true when the async task is executing a transfer on that bus.
static SPI_BUSY: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];

pub fn set_spi_bus(bus_id: u8, bus: &'static mut SpiBus) {
    if (bus_id as usize) < 2 {
        unsafe { SPI_BUSES[bus_id as usize] = bus as *mut SpiBus; }
    }
}

/// Get mutable reference to a specific SPI bus, or None if not initialized.
unsafe fn spi_bus_for(bus_id: u8) -> Option<&'static mut SpiBus> {
    if (bus_id as usize) >= 2 { return None; }
    let ptr = SPI_BUSES[bus_id as usize];
    if ptr.is_null() { None } else { Some(&mut *ptr) }
}

fn spi_handle(handle: i32) -> Option<&'static SpiHandle> {
    if handle < 0 {
        return None;
    }
    let idx = handle as usize;
    if idx >= MAX_SPI_HANDLES {
        return None;
    }
    unsafe {
        let slot = &SPI_HANDLES[idx];
        if slot.in_use && (slot.owner == OWNER_KERNEL
            || slot.owner == crate::kernel::scheduler::current_module_index() as u8)
        {
            Some(slot)
        } else {
            None
        }
    }
}

fn spi_handle_mut(handle: i32) -> Option<&'static mut SpiHandle> {
    if handle < 0 {
        return None;
    }
    let idx = handle as usize;
    if idx >= MAX_SPI_HANDLES {
        return None;
    }
    unsafe {
        let slot = &mut SPI_HANDLES[idx];
        if slot.in_use && (slot.owner == OWNER_KERNEL
            || slot.owner == crate::kernel::scheduler::current_module_index() as u8)
        {
            Some(slot)
        } else {
            None
        }
    }
}

/// Get bus_id for a valid SPI handle index. Defaults to 0 if handle invalid.
fn spi_handle_bus(handle: i32) -> usize {
    if handle >= 0 && (handle as usize) < MAX_SPI_HANDLES {
        unsafe { SPI_HANDLES[handle as usize].bus_id as usize }
    } else {
        0
    }
}

/// Check if a GPIO pin has been claimed
pub fn is_gpio_registered(pin_num: u8) -> bool {
    gpio::gpio_is_claimed(pin_num)
}

/// Convenience syscall: claim + configure as output
/// Returns handle on success, <0 on error
pub unsafe extern "C" fn syscall_gpio_request_output(pin_num: u8) -> i32 {
    let handle = gpio::gpio_claim(pin_num);
    if handle < 0 {
        return handle;
    }
    gpio::gpio_set_owner(pin_num, crate::kernel::scheduler::current_module_index() as u8);
    // Configure as output, initially high (typical for CS pins)
    let result = gpio::gpio_set_mode(handle, gpio::PinMode::Output, true);
    if result < 0 {
        gpio::gpio_release(handle);
        return result;
    }
    handle
}

/// Virtual handle for the board user button (BOOTSEL on Pico).
/// Outside the normal GPIO handle range (0..31).
const USER_BUTTON_HANDLE: i32 = 0xFF;

/// Convenience syscall: claim + configure as input with pull
/// pull: 0=none, 1=up, 2=down
/// Pin 0xFF = board user button (BOOTSEL on Pico)
/// Returns handle on success, <0 on error
pub unsafe extern "C" fn syscall_gpio_request_input(pin_num: u8, pull: u8) -> i32 {
    if pin_num == 0xFF {
        // Board user button — return virtual handle
        return USER_BUTTON_HANDLE;
    }
    let handle = gpio::gpio_claim(pin_num);
    if handle < 0 {
        return handle;
    }
    gpio::gpio_set_owner(pin_num, crate::kernel::scheduler::current_module_index() as u8);
    // Set pull configuration
    let pin_pull = match pull {
        1 => gpio::PinPull::Up,
        2 => gpio::PinPull::Down,
        _ => gpio::PinPull::None,
    };
    gpio::gpio_set_pull(handle, pin_pull);
    // Configure as input
    let result = gpio::gpio_set_mode(handle, gpio::PinMode::Input, false);
    if result < 0 {
        gpio::gpio_release(handle);
        return result;
    }
    handle
}

/// GPIO get level wrapper — handles virtual user button handle
unsafe extern "C" fn syscall_gpio_get_level(handle: i32) -> i32 {
    if handle == USER_BUTTON_HANDLE {
        return crate::kernel::resource::flash_sideband_read_cs();
    }
    if !gpio::gpio_check_owner(handle) {
        return E_INVAL;
    }
    gpio::gpio_get_level(handle)
}

// ============================================================================
// SPI Syscalls
// ============================================================================

pub unsafe extern "C" fn syscall_spi_open(
    bus: u8,
    cs_handle: i32,
    freq_hz: u32,
    mode: u8,
) -> i32 {
    if bus > 1 || mode > 3 {
        return E_INVAL;
    }
    if !is_spi_initialized(bus) {
        return E_NOSYS;
    }
    // With the new GPIO module, cs_handle is the pin number
    // Check if the pin is claimed (meaning it's available for use)
    if cs_handle >= 0 && !gpio::gpio_is_claimed(cs_handle as u8) {
        return E_INVAL;  // CS pin not claimed/configured
    }
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    for i in 0..MAX_SPI_HANDLES {
        if !SPI_HANDLES[i].in_use {
            SPI_HANDLES[i] = SpiHandle {
                in_use: true,
                bus_id: bus,
                cs_handle,
                freq: freq_hz,
                mode,
                owner,
            };
            return i as i32;
        }
    }
    E_AGAIN  // No free handles
}

pub unsafe extern "C" fn syscall_spi_close(handle: i32) {
    if handle < 0 {
        return;
    }
    let idx = handle as usize;
    if idx >= MAX_SPI_HANDLES || !SPI_HANDLES[idx].in_use {
        return;
    }
    // Only the owning module (or kernel) may close a handle
    let slot_owner = SPI_HANDLES[idx].owner;
    if slot_owner != OWNER_KERNEL
        && slot_owner != crate::kernel::scheduler::current_module_index() as u8
    {
        return;
    }
    let bus = SPI_HANDLES[idx].bus_id as usize;
    if SPI_OWNER[bus].load(Ordering::Acquire) == handle {
        let slot = SPI_HANDLES[idx];
        if slot.cs_handle >= 0 {
            // Set CS high before closing
            let _ = gpio::gpio_set_level(slot.cs_handle, true);
        }
        SPI_OWNER[bus].store(INVALID_HANDLE, Ordering::Release);
    }
    SPI_HANDLES[idx] = SpiHandle::empty();
    if SPI_ACTIVE_HANDLE.load(Ordering::Acquire) == handle {
        SPI_ACTIVE_HANDLE.store(INVALID_HANDLE, Ordering::Release);
    }
}

pub unsafe extern "C" fn syscall_spi_begin(handle: i32) -> i32 {
    if spi_handle(handle).is_none() {
        return E_INVAL;
    }
    let bus = spi_handle_bus(handle);
    match SPI_OWNER[bus].compare_exchange(
        INVALID_HANDLE,
        handle,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {}
        Err(existing) if existing == handle => {}
        Err(_) => return E_BUSY,
    }
    0
}

pub unsafe extern "C" fn syscall_spi_end(handle: i32) {
    let bus = spi_handle_bus(handle);
    if SPI_OWNER[bus].load(Ordering::Acquire) != handle {
        return;
    }
    SPI_OWNER[bus].store(INVALID_HANDLE, Ordering::Release);
}

pub unsafe extern "C" fn syscall_spi_set_cs(handle: i32, level: u8) -> i32 {
    let Some(slot) = spi_handle(handle) else {
        return E_INVAL;
    };
    if slot.cs_handle < 0 {
        return E_INVAL;
    }
    // Use gpio module to set the CS level
    gpio::gpio_set_level(slot.cs_handle, level != 0)
}

pub unsafe extern "C" fn syscall_spi_claim(handle: i32, timeout_ms: u32) -> i32 {
    if spi_handle(handle).is_none() {
        return E_INVAL;
    }
    let bus = spi_handle_bus(handle);
    let deadline = embassy_time::Instant::now().as_millis() as u32 + timeout_ms;
    loop {
        match SPI_OWNER[bus].compare_exchange(
            INVALID_HANDLE,
            handle,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return 0,
            Err(existing) if existing == handle => return 0,
            Err(_) => {}
        }
        if timeout_ms == 0 {
            return E_BUSY;
        }
        let now = embassy_time::Instant::now().as_millis() as u32;
        if now.wrapping_sub(deadline) as i32 >= 0 {
            return E_BUSY;
        }
        core::hint::spin_loop();
    }
}

pub unsafe extern "C" fn syscall_spi_configure(handle: i32, freq_hz: u32, mode: u8) -> i32 {
    if mode > 3 {
        return E_INVAL;
    }
    let Some(slot) = spi_handle_mut(handle) else {
        return E_INVAL;
    };
    slot.freq = freq_hz;
    slot.mode = mode;
    let bus = spi_handle_bus(handle);
    if SPI_OWNER[bus].load(Ordering::Acquire) == handle {
        if let Some(spi) = spi_bus_for(bus as u8) {
            let _ = spi.set_config(freq_hz, mode);
        }
    }
    0
}

pub unsafe extern "C" fn syscall_spi_transfer_start(
    handle: i32,
    tx: *const u8,
    rx: *mut u8,
    len: usize,
    fill: u8,
) -> i32 {
    let bus = spi_handle_bus(handle);
    if SPI_OWNER[bus].load(Ordering::Acquire) != handle {
        return E_BUSY;  // Not bus owner
    }
    if spi_handle(handle).is_none() {
        return E_INVAL;
    }
    let idx = handle as usize;
    let op = &mut SPI_OPERATIONS[idx];

    // Check if this handle already has a pending operation
    if op.pending.load(Ordering::Acquire) {
        return E_BUSY;  // This handle's previous transfer not yet complete
    }

    // Store operation parameters in per-handle state
    op.tx_ptr = tx;
    op.tx_len = len;
    op.rx_ptr = rx;
    op.rx_len = len;
    op.fill = fill;
    op.result.store(0, Ordering::Release);

    // Mark operation as pending (async task will pick it up)
    op.pending.store(true, Ordering::Release);
    0
}

pub unsafe extern "C" fn syscall_spi_transfer_poll(handle: i32) -> i32 {
    let bus = spi_handle_bus(handle);
    if SPI_OWNER[bus].load(Ordering::Acquire) != handle {
        return E_BUSY;
    }
    if handle < 0 || (handle as usize) >= MAX_SPI_HANDLES {
        return E_INVAL;
    }
    let idx = handle as usize;
    let op = &SPI_OPERATIONS[idx];

    // Operation still pending or being executed by async task
    if op.pending.load(Ordering::Acquire) {
        return 0;
    }

    // Check result (0 = never started or already consumed, nonzero = transfer complete)
    let res = op.result.load(Ordering::Acquire);
    if res != 0 {
        // Clear result for next transfer
        op.result.store(0, Ordering::Release);
    }
    res
}

pub unsafe extern "C" fn syscall_spi_poll_byte(handle: i32) -> i32 {
    let bus = spi_handle_bus(handle);
    if SPI_OWNER[bus].load(Ordering::Acquire) != handle {
        return E_BUSY;
    }
    if handle < 0 || (handle as usize) >= MAX_SPI_HANDLES {
        return E_INVAL;
    }
    let idx = handle as usize;
    let op = &SPI_OPERATIONS[idx];

    // Operation still pending
    if op.pending.load(Ordering::Acquire) {
        return 0;
    }

    let res = op.result.load(Ordering::Acquire);
    if res != 0 {
        op.result.store(0, Ordering::Release);
    }
    if res > 0 {
        // Success - encode first byte in return value
        let byte = if !op.rx_ptr.is_null() {
            *op.rx_ptr
        } else {
            0
        };
        0x100 | (byte as i32)
    } else {
        res
    }
}

pub unsafe extern "C" fn syscall_spi_get_caps(caps_out: *mut SpiCaps) -> i32 {
    if caps_out.is_null() {
        return E_INVAL;
    }
    (*caps_out).max_freq_hz = SPI_MAX_FREQ_HZ;
    (*caps_out).mode_mask = SPI_MODE_MASK;
    0
}

/// Round-robin index for fair scheduling of pending SPI operations.
static mut SPI_NEXT_HANDLE: usize = 0;

#[embassy_executor::task]
pub async fn spi_async_task() -> ! {
    loop {
        // Scan handles for pending operations (round-robin for fairness)
        let mut found_idx: Option<usize> = None;
        unsafe {
            let start = SPI_NEXT_HANDLE;
            for offset in 0..MAX_SPI_HANDLES {
                let idx = (start + offset) % MAX_SPI_HANDLES;
                if SPI_OPERATIONS[idx].pending.load(Ordering::Acquire) {
                    found_idx = Some(idx);
                    SPI_NEXT_HANDLE = (idx + 1) % MAX_SPI_HANDLES;
                    break;
                }
            }
        }

        if let Some(idx) = found_idx {
            let bus_id = unsafe { SPI_HANDLES[idx].bus_id };
            SPI_BUSY[bus_id as usize].store(true, Ordering::Release);
            SPI_ACTIVE_HANDLE.store(idx as i32, Ordering::Release);

            let (tx, tx_len, rx, rx_len, fill) = unsafe {
                let op = &SPI_OPERATIONS[idx];
                (op.tx_ptr, op.tx_len, op.rx_ptr, op.rx_len, op.fill)
            };

            // Configure bus for this handle's settings
            unsafe {
                let handles = &*(&raw const SPI_HANDLES);
                if let Some(slot) = handles.get(idx) {
                    if slot.in_use {
                        if let Some(bus) = spi_bus_for(bus_id) {
                            let _ = bus.set_config(slot.freq, slot.mode);
                        }
                    }
                }
            }

            // Note: op.result == 0 is "pending", so never store 0 for a completed transfer.
            let len = tx_len.max(rx_len);
            let result: i32 = if len == 0 {
                // Zero-length transfer: report 1 so poll sees completion.
                1
            } else if let Some(bus) = unsafe { spi_bus_for(bus_id) } {
                unsafe {
                    let r = if !rx.is_null() && !tx.is_null() {
                        let tx_slice = core::slice::from_raw_parts(tx, tx_len);
                        let rx_slice = core::slice::from_raw_parts_mut(rx, rx_len);
                        bus.transfer(rx_slice, tx_slice).await
                    } else if !rx.is_null() {
                        let rx_slice = core::slice::from_raw_parts_mut(rx, rx_len);
                        rx_slice.fill(fill);
                        bus.transfer_in_place(rx_slice).await
                    } else if !tx.is_null() {
                        let tx_slice = core::slice::from_raw_parts(tx, tx_len);
                        bus.write(tx_slice).await
                    } else {
                        let mut chunk = [0u8; 64];
                        let mut remaining = len;
                        let mut last_err = None;
                        while remaining > 0 {
                            let n = remaining.min(chunk.len());
                            chunk[..n].fill(fill);
                            match bus.write(&chunk[..n]).await {
                                Ok(()) => remaining -= n,
                                Err(e) => { last_err = Some(e); break; }
                            }
                        }
                        match last_err {
                            None => Ok(()),
                            Some(e) => Err(e),
                        }
                    };
                    match r {
                        Ok(()) => len as i32,
                        Err(_) => errno::ERROR,
                    }
                }
            } else {
                errno::ERROR
            };

            // Store result and clear pending flag (order matters: result before clearing pending)
            unsafe {
                let op = &SPI_OPERATIONS[idx];
                op.result.store(result, Ordering::Release);
                op.pending.store(false, Ordering::Release);
            }
            SPI_ACTIVE_HANDLE.store(INVALID_HANDLE, Ordering::Release);
            SPI_BUSY[bus_id as usize].store(false, Ordering::Release);
        } else {
            Timer::after(Duration::from_millis(1)).await;
        }
    }
}

// ============================================================================
// I2C Subsystem
// ============================================================================

const MAX_I2C_HANDLES: usize = 8;

#[derive(Clone, Copy)]
struct I2cHandle {
    in_use: bool,
    bus_id: u8,
    addr: u8,
    owner: u8,  // Module index that opened this handle (OWNER_KERNEL if kernel-owned)
}

impl I2cHandle {
    const fn empty() -> Self {
        Self { in_use: false, bus_id: 0, addr: 0, owner: OWNER_KERNEL }
    }
}

static mut I2C_BUSES: [*mut I2cBus; 2] = [core::ptr::null_mut(), core::ptr::null_mut()];
static mut I2C_HANDLES: [I2cHandle; MAX_I2C_HANDLES] = [I2cHandle::empty(); MAX_I2C_HANDLES];
static I2C_OWNER: [AtomicI32; 2] = [AtomicI32::new(-1), AtomicI32::new(-1)];

// I2C async bridge — per-handle operation state (same pattern as SPI)
const I2C_OP_WRITE: u8 = 0;
const I2C_OP_READ: u8 = 1;
const I2C_OP_WRITE_READ: u8 = 2;

/// Per-handle I2C operation state for the async bridge.
struct I2cOperation {
    pending: AtomicBool,      // true = operation staged, awaiting execution
    done: AtomicBool,         // true = operation complete, result ready
    result: AtomicI32,        // >0 = bytes transferred, <0 = error
    op: u8,                   // I2C_OP_WRITE/READ/WRITE_READ
    tx_ptr: *const u8,
    tx_len: usize,
    rx_ptr: *mut u8,
    rx_len: usize,
}

// SAFETY: I2cOperation is only accessed from:
// - Syscall thread (writes pending/pointers when pending=false, reads done/result)
// - Async task (reads/clears pending, reads pointers, writes done/result)
// The pending/done atomics provide the synchronization.
unsafe impl Sync for I2cOperation {}

impl I2cOperation {
    const fn empty() -> Self {
        Self {
            pending: AtomicBool::new(false),
            done: AtomicBool::new(false),
            result: AtomicI32::new(0),
            op: 0,
            tx_ptr: core::ptr::null(),
            tx_len: 0,
            rx_ptr: core::ptr::null_mut(),
            rx_len: 0,
        }
    }
}

static mut I2C_OPERATIONS: [I2cOperation; MAX_I2C_HANDLES] = [const { I2cOperation::empty() }; MAX_I2C_HANDLES];
/// Per-bus busy flag: true when the async task is executing a transfer.
static I2C_BUSY: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];

pub fn set_i2c_bus(bus_id: u8, bus: &'static mut I2cBus) {
    if (bus_id as usize) < 2 {
        unsafe { I2C_BUSES[bus_id as usize] = bus as *mut I2cBus; }
    }
}

/// Get I2C bus by bus_id. Returns None if not initialized.
unsafe fn i2c_bus_for(bus_id: u8) -> Option<&'static mut I2cBus> {
    let ptr = I2C_BUSES[bus_id as usize];
    if ptr.is_null() { None } else { Some(&mut *ptr) }
}

/// Get bus_id for a valid I2C handle index. Defaults to 0 if handle invalid.
fn i2c_handle_bus(handle: i32) -> usize {
    if handle >= 0 && (handle as usize) < MAX_I2C_HANDLES {
        unsafe { I2C_HANDLES[handle as usize].bus_id as usize }
    } else {
        0
    }
}

fn i2c_error_to_errno(e: I2cError) -> i32 {
    match e {
        I2cError::Nack => errno::ENXIO,       // No device at address
        I2cError::ArbitrationLoss => errno::EBUSY,
        I2cError::InvalidArg => errno::EINVAL,
        I2cError::Other => errno::ERROR,
    }
}

pub unsafe extern "C" fn syscall_i2c_open(bus: u8, addr: u8, _freq_hz: u32) -> i32 {
    if bus > 1 {
        return E_INVAL;
    }
    if !is_i2c_initialized(bus) {
        return E_NOSYS;
    }
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    let handles = &raw mut I2C_HANDLES;
    for i in 0..MAX_I2C_HANDLES {
        if !(*handles)[i].in_use {
            (*handles)[i].in_use = true;
            (*handles)[i].bus_id = bus;
            (*handles)[i].addr = addr;
            (*handles)[i].owner = owner;
            return i as i32;
        }
    }
    errno::ENOMEM
}

pub unsafe extern "C" fn syscall_i2c_close(handle: i32) {
    if handle >= 0 && (handle as usize) < MAX_I2C_HANDLES {
        let idx = handle as usize;
        // Only the owning module (or kernel) may close a handle
        let slot_owner = I2C_HANDLES[idx].owner;
        if slot_owner != OWNER_KERNEL
            && slot_owner != crate::kernel::scheduler::current_module_index() as u8
        {
            return;
        }
        let bus = I2C_HANDLES[idx].bus_id as usize;
        I2C_HANDLES[idx].in_use = false;
        if I2C_OWNER[bus].load(Ordering::Acquire) == handle {
            I2C_OWNER[bus].store(-1, Ordering::Release);
        }
    }
}

/// Start or poll an I2C transfer.
///
/// Returns: 0 = pending, >0 = bytes transferred, <0 = error.
/// On first call, stages the transfer and returns 0.
/// On subsequent calls, returns 0 while in progress, then the result.
unsafe fn i2c_start_or_poll(
    handle: i32,
    op: u8,
    tx: *const u8,
    tx_len: usize,
    rx: *mut u8,
    rx_len: usize,
) -> i32 {
    if handle < 0 || (handle as usize) >= MAX_I2C_HANDLES
        || !I2C_HANDLES[handle as usize].in_use
    {
        return E_INVAL;
    }
    // Ownership check: only the module that opened this handle may use it
    let slot_owner = I2C_HANDLES[handle as usize].owner;
    if slot_owner != OWNER_KERNEL
        && slot_owner != crate::kernel::scheduler::current_module_index() as u8
    {
        return E_INVAL;
    }
    let bus = i2c_handle_bus(handle);
    if I2C_OWNER[bus].load(Ordering::Acquire) != handle {
        return E_BUSY;
    }

    let idx = handle as usize;
    let op_state = &mut I2C_OPERATIONS[idx];

    // Transfer complete — return result
    if op_state.done.load(Ordering::Acquire) {
        let result = op_state.result.load(Ordering::Acquire);
        op_state.done.store(false, Ordering::Release);
        return result;
    }

    // Transfer in progress — still waiting
    if op_state.pending.load(Ordering::Acquire) {
        return 0;
    }

    // Idle — stage a new transfer in per-handle state
    op_state.op = op;
    op_state.tx_ptr = tx;
    op_state.tx_len = tx_len;
    op_state.rx_ptr = rx;
    op_state.rx_len = rx_len;
    op_state.pending.store(true, Ordering::Release);
    0
}

pub unsafe extern "C" fn syscall_i2c_write(handle: i32, data: *const u8, len: usize) -> i32 {
    if data.is_null() || len == 0 { return E_INVAL; }
    i2c_start_or_poll(handle, I2C_OP_WRITE, data, len, core::ptr::null_mut(), 0)
}

pub unsafe extern "C" fn syscall_i2c_read(handle: i32, buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() || len == 0 { return E_INVAL; }
    i2c_start_or_poll(handle, I2C_OP_READ, core::ptr::null(), 0, buf, len)
}

pub unsafe extern "C" fn syscall_i2c_write_read(
    handle: i32,
    tx: *const u8,
    tx_len: usize,
    rx: *mut u8,
    rx_len: usize,
) -> i32 {
    if tx.is_null() || tx_len == 0 || rx.is_null() || rx_len == 0 { return E_INVAL; }
    i2c_start_or_poll(handle, I2C_OP_WRITE_READ, tx, tx_len, rx, rx_len)
}

pub unsafe extern "C" fn syscall_i2c_claim(handle: i32, _timeout_ms: u32) -> i32 {
    if handle < 0 || (handle as usize) >= MAX_I2C_HANDLES
        || !I2C_HANDLES[handle as usize].in_use
    {
        return E_INVAL;
    }
    let slot_owner = I2C_HANDLES[handle as usize].owner;
    if slot_owner != OWNER_KERNEL
        && slot_owner != crate::kernel::scheduler::current_module_index() as u8
    {
        return E_INVAL;
    }
    let bus = i2c_handle_bus(handle);
    match I2C_OWNER[bus].compare_exchange(-1, handle, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => 0,
        Err(current) if current == handle => 0, // Already own it
        Err(_) => E_BUSY,
    }
}

pub unsafe extern "C" fn syscall_i2c_release(handle: i32) {
    if handle >= 0 && (handle as usize) < MAX_I2C_HANDLES {
        let slot_owner = I2C_HANDLES[handle as usize].owner;
        if slot_owner != OWNER_KERNEL
            && slot_owner != crate::kernel::scheduler::current_module_index() as u8
        {
            return;
        }
    }
    let bus = i2c_handle_bus(handle);
    let _ = I2C_OWNER[bus].compare_exchange(handle, -1, Ordering::AcqRel, Ordering::Acquire);
}

/// Round-robin index for fair scheduling of pending I2C operations.
static mut I2C_NEXT_HANDLE: usize = 0;

/// I2C async task — polls for pending transfers and executes them via the HAL.
#[embassy_executor::task]
pub async fn i2c_async_task() -> ! {
    loop {
        // Scan handles for pending operations (round-robin for fairness)
        let mut found_idx: Option<usize> = None;
        unsafe {
            let start = I2C_NEXT_HANDLE;
            for offset in 0..MAX_I2C_HANDLES {
                let idx = (start + offset) % MAX_I2C_HANDLES;
                if I2C_OPERATIONS[idx].pending.load(Ordering::Acquire) {
                    found_idx = Some(idx);
                    I2C_NEXT_HANDLE = (idx + 1) % MAX_I2C_HANDLES;
                    break;
                }
            }
        }

        if let Some(idx) = found_idx {
            let bus_id = unsafe { I2C_HANDLES[idx].bus_id };
            I2C_BUSY[bus_id as usize].store(true, Ordering::Release);

            let (addr, op, tx, tx_len, rx, rx_len) = unsafe {
                let handles = &*(&raw const I2C_HANDLES);
                let op_state = &I2C_OPERATIONS[idx];
                (
                    handles[idx].addr,
                    op_state.op,
                    op_state.tx_ptr,
                    op_state.tx_len,
                    op_state.rx_ptr,
                    op_state.rx_len,
                )
            };

            let result = if let Some(bus) = unsafe { i2c_bus_for(bus_id) } {
                unsafe {
                    match op {
                        I2C_OP_WRITE => {
                            let data = core::slice::from_raw_parts(tx, tx_len);
                            match bus.write(addr, data).await {
                                Ok(()) => tx_len as i32,
                                Err(e) => i2c_error_to_errno(e),
                            }
                        }
                        I2C_OP_READ => {
                            let buf = core::slice::from_raw_parts_mut(rx, rx_len);
                            match bus.read(addr, buf).await {
                                Ok(()) => rx_len as i32,
                                Err(e) => i2c_error_to_errno(e),
                            }
                        }
                        I2C_OP_WRITE_READ => {
                            let tx_data = core::slice::from_raw_parts(tx, tx_len);
                            let rx_buf = core::slice::from_raw_parts_mut(rx, rx_len);
                            match bus.write_read(addr, tx_data, rx_buf).await {
                                Ok(()) => rx_len as i32,
                                Err(e) => i2c_error_to_errno(e),
                            }
                        }
                        _ => errno::ERROR,
                    }
                }
            } else {
                errno::ERROR
            };

            // Store result and clear pending, set done (order matters)
            unsafe {
                let op_state = &I2C_OPERATIONS[idx];
                op_state.result.store(result, Ordering::Release);
                op_state.pending.store(false, Ordering::Release);
                op_state.done.store(true, Ordering::Release);
            }
            I2C_BUSY[bus_id as usize].store(false, Ordering::Release);
        } else {
            Timer::after(Duration::from_millis(1)).await;
        }
    }
}

// ============================================================================
// UART Subsystem
// ============================================================================

const MAX_UART_HANDLES: usize = 4;

const UART_OP_WRITE: u8 = 0;
const UART_OP_READ: u8 = 1;

#[derive(Clone, Copy)]
struct UartHandle {
    in_use: bool,
    bus_id: u8,
    owner: u8,
}

impl UartHandle {
    const fn empty() -> Self {
        Self { in_use: false, bus_id: 0, owner: OWNER_KERNEL }
    }
}

/// Per-handle UART operation state for the async bridge.
struct UartOperation {
    pending: AtomicBool,
    done: AtomicBool,
    result: AtomicI32,
    op: u8,
    tx_ptr: *const u8,
    tx_len: usize,
    rx_ptr: *mut u8,
    rx_len: usize,
}

unsafe impl Sync for UartOperation {}

impl UartOperation {
    const fn empty() -> Self {
        Self {
            pending: AtomicBool::new(false),
            done: AtomicBool::new(false),
            result: AtomicI32::new(0),
            op: 0,
            tx_ptr: core::ptr::null(),
            tx_len: 0,
            rx_ptr: core::ptr::null_mut(),
            rx_len: 0,
        }
    }
}

static mut UART_BUSES: [*mut UartBus; 2] = [core::ptr::null_mut(); 2];
static mut UART_HANDLES: [UartHandle; MAX_UART_HANDLES] = [UartHandle::empty(); MAX_UART_HANDLES];
static mut UART_OPERATIONS: [UartOperation; MAX_UART_HANDLES] = [const { UartOperation::empty() }; MAX_UART_HANDLES];
static mut UART_NEXT_HANDLE: usize = 0;

pub fn set_uart_bus(bus_id: u8, bus: &'static mut UartBus) {
    unsafe {
        if (bus_id as usize) < 2 {
            UART_BUSES[bus_id as usize] = bus as *mut UartBus;
        }
    }
}

pub fn mark_uart_initialized(bus: u8) {
    unsafe { (*(&raw mut HARDWARE_CONTEXT)).mark_uart_initialized(bus) }
}

unsafe fn syscall_uart_open(bus: u8) -> i32 {
    if bus > 1 || UART_BUSES[bus as usize].is_null() {
        return E_NOSYS;
    }
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    let handles = &raw mut UART_HANDLES;
    for i in 0..MAX_UART_HANDLES {
        if !(*handles)[i].in_use {
            (*handles)[i].in_use = true;
            (*handles)[i].owner = owner;
            (*handles)[i].bus_id = bus;
            return i as i32;
        }
    }
    errno::ENOMEM
}

unsafe fn syscall_uart_close(handle: i32) {
    if handle >= 0 && (handle as usize) < MAX_UART_HANDLES {
        let idx = handle as usize;
        let slot_owner = UART_HANDLES[idx].owner;
        if slot_owner != OWNER_KERNEL
            && slot_owner != crate::kernel::scheduler::current_module_index() as u8
        {
            return;
        }
        UART_HANDLES[idx].in_use = false;
        UART_OPERATIONS[idx].pending.store(false, Ordering::Release);
        UART_OPERATIONS[idx].done.store(false, Ordering::Release);
    }
}

unsafe fn uart_start_or_poll(
    handle: i32,
    op: u8,
    tx: *const u8,
    tx_len: usize,
    rx: *mut u8,
    rx_len: usize,
) -> i32 {
    if handle < 0 || (handle as usize) >= MAX_UART_HANDLES
        || !UART_HANDLES[handle as usize].in_use
    {
        return E_INVAL;
    }
    let slot_owner = UART_HANDLES[handle as usize].owner;
    if slot_owner != OWNER_KERNEL
        && slot_owner != crate::kernel::scheduler::current_module_index() as u8
    {
        return E_INVAL;
    }

    let idx = handle as usize;
    let op_state = &mut UART_OPERATIONS[idx];

    if op_state.done.load(Ordering::Acquire) {
        let result = op_state.result.load(Ordering::Acquire);
        op_state.done.store(false, Ordering::Release);
        return result;
    }

    if op_state.pending.load(Ordering::Acquire) {
        return 0;
    }

    op_state.op = op;
    op_state.tx_ptr = tx;
    op_state.tx_len = tx_len;
    op_state.rx_ptr = rx;
    op_state.rx_len = rx_len;
    op_state.pending.store(true, Ordering::Release);
    0
}

unsafe fn uart_bus_for(bus_id: u8) -> Option<&'static mut UartBus> {
    let ptr = UART_BUSES[bus_id as usize];
    if ptr.is_null() { None } else { Some(&mut *ptr) }
}

/// UART async task — polls for pending transfers and executes them.
/// Handles both TX (write) and RX (read) operations across all handles.
#[embassy_executor::task]
pub async fn uart_async_task() -> ! {
    loop {
        let mut found_idx: Option<usize> = None;
        unsafe {
            let start = UART_NEXT_HANDLE;
            for offset in 0..MAX_UART_HANDLES {
                let idx = (start + offset) % MAX_UART_HANDLES;
                if UART_OPERATIONS[idx].pending.load(Ordering::Acquire) {
                    found_idx = Some(idx);
                    UART_NEXT_HANDLE = (idx + 1) % MAX_UART_HANDLES;
                    break;
                }
            }
        }

        if let Some(idx) = found_idx {
            let (bus_id, op, tx, tx_len, rx, rx_len) = unsafe {
                let op_state = &UART_OPERATIONS[idx];
                (
                    UART_HANDLES[idx].bus_id,
                    op_state.op,
                    op_state.tx_ptr,
                    op_state.tx_len,
                    op_state.rx_ptr,
                    op_state.rx_len,
                )
            };

            let result = if let Some(bus) = unsafe { uart_bus_for(bus_id) } {
                match op {
                    UART_OP_WRITE => {
                        let data = unsafe { core::slice::from_raw_parts(tx, tx_len) };
                        match bus.write(data).await {
                            Ok(n) => n as i32,
                            Err(_) => errno::ERROR,
                        }
                    }
                    UART_OP_READ => {
                        let buf = unsafe { core::slice::from_raw_parts_mut(rx, rx_len) };
                        match bus.read(buf).await {
                            Ok(n) => n as i32,
                            Err(_) => errno::ERROR,
                        }
                    }
                    _ => errno::ERROR,
                }
            } else {
                errno::ERROR
            };

            unsafe {
                let op_state = &UART_OPERATIONS[idx];
                op_state.result.store(result, Ordering::Release);
                op_state.pending.store(false, Ordering::Release);
                op_state.done.store(true, Ordering::Release);
            }
        } else {
            Timer::after(Duration::from_millis(1)).await;
        }
    }
}

// ============================================================================
// ADC Subsystem
// ============================================================================

const MAX_ADC_HANDLES: usize = 4;

#[derive(Clone, Copy)]
struct AdcHandle {
    in_use: bool,
    channel: u8,   // ADC channel (0-4)
    owner: u8,
}

impl AdcHandle {
    const fn empty() -> Self {
        Self { in_use: false, channel: 0, owner: OWNER_KERNEL }
    }
}

/// Per-handle ADC operation state.
struct AdcOperation {
    pending: AtomicBool,
    done: AtomicBool,
    result: AtomicI32,  // 12-bit value (0-4095) or negative errno
}

unsafe impl Sync for AdcOperation {}

impl AdcOperation {
    const fn empty() -> Self {
        Self {
            pending: AtomicBool::new(false),
            done: AtomicBool::new(false),
            result: AtomicI32::new(0),
        }
    }
}

static mut ADC_DEV: *mut AdcBus = core::ptr::null_mut();
static mut ADC_HANDLES: [AdcHandle; MAX_ADC_HANDLES] = [AdcHandle::empty(); MAX_ADC_HANDLES];
static mut ADC_OPERATIONS: [AdcOperation; MAX_ADC_HANDLES] = [const { AdcOperation::empty() }; MAX_ADC_HANDLES];

pub fn set_adc_bus(bus: &'static mut AdcBus) {
    unsafe { ADC_DEV = bus as *mut AdcBus; }
}

pub fn mark_adc_initialized() {
    unsafe { (*(&raw mut HARDWARE_CONTEXT)).mark_adc_initialized() }
}

unsafe fn syscall_adc_open(channel: u8) -> i32 {
    if channel > 4 || ADC_DEV.is_null() {
        return E_NOSYS;
    }
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    let handles = &raw mut ADC_HANDLES;
    for i in 0..MAX_ADC_HANDLES {
        if !(*handles)[i].in_use {
            (*handles)[i].in_use = true;
            (*handles)[i].channel = channel;
            (*handles)[i].owner = owner;
            return i as i32;
        }
    }
    errno::ENOMEM
}

unsafe fn syscall_adc_close(handle: i32) {
    if handle >= 0 && (handle as usize) < MAX_ADC_HANDLES {
        let idx = handle as usize;
        let slot_owner = ADC_HANDLES[idx].owner;
        if slot_owner != OWNER_KERNEL
            && slot_owner != crate::kernel::scheduler::current_module_index() as u8
        {
            return;
        }
        ADC_HANDLES[idx].in_use = false;
        ADC_OPERATIONS[idx].pending.store(false, Ordering::Release);
        ADC_OPERATIONS[idx].done.store(false, Ordering::Release);
    }
}

unsafe fn adc_start_or_poll(handle: i32) -> i32 {
    if handle < 0 || (handle as usize) >= MAX_ADC_HANDLES
        || !ADC_HANDLES[handle as usize].in_use
    {
        return E_INVAL;
    }
    let slot_owner = ADC_HANDLES[handle as usize].owner;
    if slot_owner != OWNER_KERNEL
        && slot_owner != crate::kernel::scheduler::current_module_index() as u8
    {
        return E_INVAL;
    }

    let idx = handle as usize;
    let op_state = &mut ADC_OPERATIONS[idx];

    if op_state.done.load(Ordering::Acquire) {
        let result = op_state.result.load(Ordering::Acquire);
        op_state.done.store(false, Ordering::Release);
        return result;
    }

    if op_state.pending.load(Ordering::Acquire) {
        return 0;
    }

    op_state.pending.store(true, Ordering::Release);
    0
}

#[embassy_executor::task]
pub async fn adc_async_task() -> ! {
    loop {
        let mut found = false;
        unsafe {
            if !ADC_DEV.is_null() {
                let bus = &mut *ADC_DEV;
                for i in 0..MAX_ADC_HANDLES {
                    if ADC_OPERATIONS[i].pending.load(Ordering::Acquire)
                        && ADC_HANDLES[i].in_use
                    {
                        found = true;
                        let ch = ADC_HANDLES[i].channel;
                        let result = match bus.read_channel(ch).await {
                            Ok(v) => v as i32,
                            Err(_) => errno::ENOSYS,
                        };
                        ADC_OPERATIONS[i].result.store(result, Ordering::Release);
                        ADC_OPERATIONS[i].done.store(true, Ordering::Release);
                        ADC_OPERATIONS[i].pending.store(false, Ordering::Release);
                        break; // service one, re-scan
                    }
                }
            }
        }
        if !found {
            Timer::after(Duration::from_millis(1)).await;
        }
    }
}

// ============================================================================
// Per-class provider dispatchers (RP-specific)
// ============================================================================

unsafe fn gpio_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::dev_gpio;
    match opcode {
        dev_gpio::CLAIM => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let result = gpio::syscall_gpio_claim(*arg);
            if result >= 0 {
                gpio::gpio_set_owner(*arg, crate::kernel::scheduler::current_module_index() as u8);
            }
            result
        }
        dev_gpio::REQUEST_OUTPUT => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            syscall_gpio_request_output(*arg)
        }
        dev_gpio::REQUEST_INPUT => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            syscall_gpio_request_input(*arg, *arg.add(1))
        }
        dev_gpio::RELEASE => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            gpio::syscall_gpio_release(handle)
        }
        dev_gpio::SET_MODE => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            gpio::syscall_gpio_set_mode(handle, *arg, *arg.add(1))
        }
        dev_gpio::SET_PULL => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            gpio::syscall_gpio_set_pull(handle, *arg)
        }
        dev_gpio::SET_LEVEL => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            gpio::syscall_gpio_set_level(handle, *arg)
        }
        dev_gpio::GET_LEVEL => {
            syscall_gpio_get_level(handle)
        }
        dev_gpio::SET_IRQ => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            gpio::syscall_gpio_set_irq(handle, *arg)
        }
        dev_gpio::POLL_IRQ => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            gpio::syscall_gpio_poll_irq(handle)
        }
        dev_gpio::WATCH_EDGE => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let edge = *arg;
            let evt = i32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            gpio::gpio_watch_edge(handle as u8, edge, evt)
        }
        dev_gpio::UNWATCH_EDGE => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            gpio::gpio_unwatch_edge(handle as u8)
        }
        _ => E_NOSYS,
    }
}

unsafe fn spi_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::{dev_spi, SpiOpenArgs, SpiTransferStartArgs};
    match opcode {
        dev_spi::OPEN => {
            if arg.is_null() || arg_len < core::mem::size_of::<SpiOpenArgs>() { return E_INVAL; }
            let a = &*(arg as *const SpiOpenArgs);
            syscall_spi_open(a.bus, a.cs_handle, a.freq_hz, a.mode)
        }
        dev_spi::CLOSE => { syscall_spi_close(handle); 0 }
        dev_spi::BEGIN => syscall_spi_begin(handle),
        dev_spi::END => { syscall_spi_end(handle); 0 }
        dev_spi::SET_CS => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            syscall_spi_set_cs(handle, *arg)
        }
        dev_spi::CLAIM => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let timeout = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            syscall_spi_claim(handle, timeout)
        }
        dev_spi::CONFIGURE => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let freq = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            syscall_spi_configure(handle, freq, *arg.add(4))
        }
        dev_spi::TRANSFER_START => {
            if arg.is_null() || arg_len < core::mem::size_of::<SpiTransferStartArgs>() { return E_INVAL; }
            let a = &*(arg as *const SpiTransferStartArgs);
            syscall_spi_transfer_start(handle, a.tx, a.rx, a.len as usize, a.fill)
        }
        dev_spi::TRANSFER_POLL => syscall_spi_transfer_poll(handle),
        dev_spi::POLL_BYTE => syscall_spi_poll_byte(handle),
        dev_spi::GET_CAPS => {
            if arg.is_null() || arg_len < core::mem::size_of::<SpiCaps>() { return E_INVAL; }
            syscall_spi_get_caps(arg as *mut SpiCaps)
        }
        _ => E_NOSYS,
    }
}

unsafe fn i2c_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::dev_i2c;
    match opcode {
        dev_i2c::OPEN => {
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let bus = *arg;
            let addr = *arg.add(1);
            let freq_hz = if arg_len >= 7 {
                u32::from_le_bytes([*arg.add(3), *arg.add(4), *arg.add(5), *arg.add(6)])
            } else {
                400_000
            };
            syscall_i2c_open(bus, addr, freq_hz)
        }
        dev_i2c::CLOSE => { syscall_i2c_close(handle); 0 }
        dev_i2c::WRITE => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            syscall_i2c_write(handle, arg, arg_len)
        }
        dev_i2c::READ => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            syscall_i2c_read(handle, arg as *mut u8, arg_len)
        }
        dev_i2c::WRITE_READ => {
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let tx_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if tx_len == 0 || 2 + tx_len >= arg_len { return E_INVAL; }
            let tx = arg.add(2);
            let rx = arg.add(2 + tx_len) as *mut u8;
            let rx_len = arg_len - 2 - tx_len;
            syscall_i2c_write_read(handle, tx, tx_len, rx, rx_len)
        }
        dev_i2c::CLAIM => syscall_i2c_claim(handle, 0),
        dev_i2c::RELEASE => { syscall_i2c_release(handle); 0 }
        _ => E_NOSYS,
    }
}

unsafe fn pio_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::{dev_pio, PioLoadProgramArgs, PioConfigureArgs, PioRxConfigureArgs, PioCmdConfigureArgs, PioCmdTransferArgs};
    match opcode {
        // --- Stream opcodes ---
        dev_pio::STREAM_ALLOC => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let words = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
            pio::syscall_pio_stream_alloc(words)
        }
        dev_pio::STREAM_LOAD_PROGRAM => {
            if arg.is_null() || arg_len < core::mem::size_of::<PioLoadProgramArgs>() { return E_INVAL; }
            let a = &*(arg as *const PioLoadProgramArgs);
            pio::syscall_pio_stream_load_program(
                handle, a.program, a.program_len as usize,
                a.wrap_target, a.wrap, a.sideset_bits, a.options,
            )
        }
        dev_pio::STREAM_CONFIGURE => {
            if arg.is_null() || arg_len < core::mem::size_of::<PioConfigureArgs>() { return E_INVAL; }
            let a = &*(arg as *const PioConfigureArgs);
            pio::syscall_pio_stream_configure(
                handle, a.data_pin, a.clock_base, a.clock_div, a.shift_bits,
            )
        }
        dev_pio::STREAM_CAN_PUSH => pio::syscall_pio_stream_can_push(handle),
        dev_pio::STREAM_PUSH => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let words = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
            pio::syscall_pio_stream_push(handle, words)
        }
        dev_pio::STREAM_FREE => { pio::syscall_pio_stream_free(handle); 0 }
        dev_pio::STREAM_SET_RATE => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let rate = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            pio::PioStreamService::set_units_per_sec_for(handle as usize, rate);
            0
        }
        // --- Cmd opcodes ---
        dev_pio::CMD_ALLOC => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            pio::syscall_pio_cmd_alloc(*arg, *arg.add(1))
        }
        dev_pio::CMD_LOAD_PROGRAM => {
            if arg.is_null() || arg_len < core::mem::size_of::<PioLoadProgramArgs>() { return E_INVAL; }
            let a = &*(arg as *const PioLoadProgramArgs);
            pio::syscall_pio_cmd_load_program(
                handle, a.program, a.program_len as usize,
                a.wrap_target, a.wrap, a.sideset_bits, a.options,
            )
        }
        dev_pio::CMD_CONFIGURE => {
            if arg.is_null() || arg_len < core::mem::size_of::<PioCmdConfigureArgs>() { return E_INVAL; }
            let a = &*(arg as *const PioCmdConfigureArgs);
            pio::syscall_pio_cmd_configure(handle, a.data_pin, a.clk_pin, a.clock_div)
        }
        dev_pio::CMD_TRANSFER => {
            if arg.is_null() || arg_len < core::mem::size_of::<PioCmdTransferArgs>() { return E_INVAL; }
            let a = &*(arg as *const PioCmdTransferArgs);
            pio::syscall_pio_cmd_transfer(
                handle, a.tx_ptr, a.tx_len as usize, a.rx_ptr, a.rx_len as usize,
            )
        }
        dev_pio::CMD_POLL => pio::syscall_pio_cmd_poll(handle),
        dev_pio::CMD_FREE => { pio::syscall_pio_cmd_free(handle); 0 }
        // --- RX Stream opcodes ---
        dev_pio::RX_STREAM_ALLOC => {
            pio::syscall_pio_rx_stream_alloc()
        }
        dev_pio::RX_STREAM_LOAD_PROGRAM => {
            if arg.is_null() || arg_len < core::mem::size_of::<PioLoadProgramArgs>() { return E_INVAL; }
            let a = &*(arg as *const PioLoadProgramArgs);
            pio::syscall_pio_rx_stream_load_program(
                handle, a.program, a.program_len as usize,
                a.wrap_target, a.wrap, a.sideset_bits, a.options,
            )
        }
        dev_pio::RX_STREAM_CONFIGURE => {
            if arg.is_null() || arg_len < core::mem::size_of::<PioRxConfigureArgs>() { return E_INVAL; }
            let a = &*(arg as *const PioRxConfigureArgs);
            pio::syscall_pio_rx_stream_configure(
                handle, a.in_pin, a.sideset_base, a.clock_div, a.shift_bits,
            )
        }
        dev_pio::RX_STREAM_CAN_PULL => pio::syscall_pio_rx_stream_can_pull(handle),
        dev_pio::RX_STREAM_PULL => pio::syscall_pio_rx_stream_pull(handle),
        dev_pio::RX_STREAM_GET_BUFFER => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let ptr = pio::syscall_pio_rx_stream_get_buffer(handle);
            *(arg as *mut u32) = ptr as u32;
            if ptr.is_null() { 0 } else { pio::RX_BUFFER_WORDS as i32 }
        }
        dev_pio::RX_STREAM_FREE => { pio::syscall_pio_rx_stream_free(handle); 0 }
        dev_pio::RX_STREAM_SET_RATE => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let rate = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            pio::PioRxStreamService::set_rate(handle, rate);
            0
        }
        // RGB opcodes 0x0430-0x0437 removed — display logic moved to PIC module
        _ => E_NOSYS,
    }
}

unsafe fn uart_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::dev_uart;
    match opcode {
        dev_uart::OPEN => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            syscall_uart_open(*arg)
        }
        dev_uart::CLOSE => { syscall_uart_close(handle); 0 }
        dev_uart::WRITE => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            uart_start_or_poll(handle, UART_OP_WRITE, arg as *const u8, arg_len, core::ptr::null_mut(), 0)
        }
        dev_uart::READ => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            uart_start_or_poll(handle, UART_OP_READ, core::ptr::null(), 0, arg, arg_len)
        }
        dev_uart::POLL => {
            if handle < 0 || (handle as usize) >= MAX_UART_HANDLES { return E_INVAL; }
            let idx = handle as usize;
            if UART_OPERATIONS[idx].done.load(Ordering::Acquire) {
                let result = UART_OPERATIONS[idx].result.load(Ordering::Acquire);
                UART_OPERATIONS[idx].done.store(false, Ordering::Release);
                result
            } else if UART_OPERATIONS[idx].pending.load(Ordering::Acquire) {
                0
            } else {
                E_INVAL
            }
        }
        dev_uart::CONFIGURE => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            0
        }
        _ => E_NOSYS,
    }
}

unsafe fn adc_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::dev_adc;
    match opcode {
        dev_adc::OPEN => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            syscall_adc_open(*arg)
        }
        dev_adc::CLOSE => { syscall_adc_close(handle); 0 }
        dev_adc::READ => adc_start_or_poll(handle),
        dev_adc::POLL => {
            if handle < 0 || (handle as usize) >= MAX_ADC_HANDLES { return E_INVAL; }
            let idx = handle as usize;
            if ADC_OPERATIONS[idx].done.load(Ordering::Acquire) {
                let result = ADC_OPERATIONS[idx].result.load(Ordering::Acquire);
                ADC_OPERATIONS[idx].done.store(false, Ordering::Release);
                result
            } else if ADC_OPERATIONS[idx].pending.load(Ordering::Acquire) {
                0
            } else {
                E_INVAL
            }
        }
        dev_adc::CONFIGURE => E_NOSYS,
        _ => E_NOSYS,
    }
}

// ============================================================================
// Raw PAC GPIO 9-bit SPI bit-bang (for display register init)
// ============================================================================

/// Set a pin as SIO output with initial level.
unsafe fn spi9_pac_gpio_init(pin: u8, high: bool) {
    use embassy_rp::pac;
    pac::IO_BANK0.gpio(pin as usize).ctrl().write(|w| w.set_funcsel(5));
    pac::PADS_BANK0.gpio(pin as usize).write(|w| {
        super::chip::pad_set_iso_false!(w);
        w.set_schmitt(false);
        w.set_slewfast(false);
        w.set_ie(true);
        w.set_od(false);
        w.set_pue(false);
        w.set_pde(false);
        w.set_drive(pac::pads::vals::Drive::_4M_A);
    });
    let bank = (pin >> 5) as usize;
    let bit = 1u32 << (pin & 31);
    if high {
        pac::SIO.gpio_out(bank).value_set().write_value(bit);
    } else {
        pac::SIO.gpio_out(bank).value_clr().write_value(bit);
    }
    pac::SIO.gpio_oe(bank).value_set().write_value(bit);
}

/// Set a SIO output pin level.
#[inline(always)]
unsafe fn spi9_pac_pin_set(pin: u8, high: bool) {
    use embassy_rp::pac;
    let bank = (pin >> 5) as usize;
    let bit = 1u32 << (pin & 31);
    if high {
        pac::SIO.gpio_out(bank).value_set().write_value(bit);
    } else {
        pac::SIO.gpio_out(bank).value_clr().write_value(bit);
    }
}

/// Busy-wait for `us` microseconds using the RP hardware TIMER.
#[inline(always)]
unsafe fn spi9_timer_us(us: u32) {
    let timer = super::chip::timer();
    let t0 = timer.timerawl().read();
    while timer.timerawl().read().wrapping_sub(t0) < us {}
}

/// Busy-wait ~100 us using hardware TIMER.
#[inline(always)]
unsafe fn spi9_pac_delay() {
    spi9_timer_us(100);
}

/// Busy-wait ~N ms using hardware TIMER.
#[inline(always)]
unsafe fn spi9_pac_delay_ms(ms: u32) {
    spi9_timer_us(ms * 1000);
}

/// Send one 9-bit SPI word. Clock idle low, data on rising edge, MSB first.
unsafe fn spi9_pac_write_word(sck: u8, sda: u8, word: u16) {
    for i in (0..=8i32).rev() {
        spi9_pac_pin_set(sda, (word & (1u16 << i as u32)) != 0);
        spi9_timer_us(10);   // Data setup time before rising edge
        spi9_pac_pin_set(sck, true);
        spi9_pac_delay();     // 100 us SCK high time
        spi9_pac_pin_set(sck, false);
        spi9_pac_delay();     // 100 us SCK low time
    }
}

/// Send 9-bit SPI command + data bytes, CS-framed.
unsafe fn spi9_pac_send(cs: u8, sck: u8, sda: u8, cmd: u8, data: *const u8, data_len: usize, hold_cs: bool) {
    spi9_pac_pin_set(cs, false);
    spi9_timer_us(5);  // CS setup time before first clock
    spi9_pac_write_word(sck, sda, cmd as u16); // DC=0 for command
    for i in 0..data_len {
        spi9_pac_write_word(sck, sda, 0x0100 | *data.add(i) as u16); // DC=1 for data
    }
    if !hold_cs {
        spi9_timer_us(5);  // CS hold time after last clock
        spi9_pac_pin_set(cs, true);
    }
}

/// Reset sequence + SIO pin init for 9-bit SPI.
unsafe fn spi9_pac_reset(rst: u8, cs: u8, sck: u8, sda: u8) {
    spi9_pac_gpio_init(cs, true);
    spi9_pac_gpio_init(sck, false);
    spi9_pac_gpio_init(sda, false);
    spi9_pac_gpio_init(rst, true);

    spi9_pac_pin_set(rst, true);
    spi9_pac_delay_ms(20);
    spi9_pac_pin_set(rst, false);
    spi9_pac_delay_ms(20);
    spi9_pac_pin_set(rst, true);
    spi9_pac_delay_ms(200);
}

// ============================================================================
// RP System Extension Dispatch
// ============================================================================
//
// Handles hardware-specific system opcodes (PWM, PIO registers, DMA, SPI9)
// delegated from system_provider_dispatch's catch-all arm.

unsafe fn rp_system_extension_dispatch(_handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::dev_system;
    match opcode {
        // ── Raw PWM register bridge ─────────────────────────────────
        dev_system::PWM_PIN_ENABLE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let pin = *arg as usize;
            if pin >= gpio::runtime_max_gpio() as usize { return E_INVAL; }
            use embassy_rp::pac;
            pac::IO_BANK0.gpio(pin).ctrl().write(|w| w.set_funcsel(4));
            pac::PADS_BANK0.gpio(pin).modify(|w| {
                w.set_ie(false);
                w.set_od(false);
                super::chip::pad_set_iso_false!(w);
            });
            0
        }
        dev_system::PWM_PIN_DISABLE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let pin = *arg as usize;
            if pin >= gpio::runtime_max_gpio() as usize { return E_INVAL; }
            use embassy_rp::pac;
            pac::IO_BANK0.gpio(pin).ctrl().write(|w| w.set_funcsel(31));
            0
        }
        dev_system::PWM_SLICE_WRITE => {
            if arg.is_null() || arg_len < 6 { return E_INVAL; }
            let slice = *arg as usize;
            let reg = *arg.add(1);
            let value = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            if slice >= 12 { return E_INVAL; }
            use embassy_rp::pac;
            let ch = pac::PWM.ch(slice);
            match reg {
                0 => ch.csr().write(|w| w.0 = value),
                1 => ch.div().write(|w| w.0 = value),
                2 => ch.ctr().write(|w| w.0 = value),
                3 => ch.cc().write(|w| w.0 = value),
                4 => ch.top().write(|w| w.0 = value),
                _ => return E_INVAL,
            }
            0
        }
        dev_system::PWM_SLICE_READ => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let slice = *arg as usize;
            let reg = *arg.add(1);
            if slice >= 12 { return E_INVAL; }
            use embassy_rp::pac;
            let ch = pac::PWM.ch(slice);
            match reg {
                0 => ch.csr().read().0 as i32,
                1 => ch.div().read().0 as i32,
                2 => ch.ctr().read().0 as i32,
                3 => ch.cc().read().0 as i32,
                4 => ch.top().read().0 as i32,
                _ => E_INVAL,
            }
        }
        // ── Raw PIO register bridge ───────────────────────────────────
        dev_system::PIO_SM_EXEC => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let pio_num = *arg;
            let sm = *arg.add(1);
            if pio_num > 2 || sm > 3 { return E_INVAL; }
            let instr = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
            pio::pio_pac(pio_num).sm(sm as usize).instr().write(|w| w.set_instr(instr));
            0
        }
        dev_system::PIO_SM_WRITE_REG => {
            if arg.is_null() || arg_len < 7 { return E_INVAL; }
            let pio_num = *arg;
            let sm_idx = *arg.add(1);
            let reg = *arg.add(2);
            if pio_num > 2 || sm_idx > 3 { return E_INVAL; }
            let value = u32::from_le_bytes([*arg.add(3), *arg.add(4), *arg.add(5), *arg.add(6)]);
            let sm = pio::pio_pac(pio_num).sm(sm_idx as usize);
            match reg {
                0 => sm.clkdiv().write(|w| w.0 = value),
                1 => sm.execctrl().write(|w| w.0 = value),
                2 => sm.shiftctrl().write(|w| w.0 = value),
                3 => sm.pinctrl().write(|w| w.0 = value),
                _ => return E_INVAL,
            }
            0
        }
        dev_system::PIO_SM_READ_REG => {
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let pio_num = *arg;
            let sm_idx = *arg.add(1);
            let reg = *arg.add(2);
            if pio_num > 2 || sm_idx > 3 { return E_INVAL; }
            let sm = pio::pio_pac(pio_num).sm(sm_idx as usize);
            match reg {
                0 => sm.clkdiv().read().0 as i32,
                1 => sm.execctrl().read().0 as i32,
                2 => sm.shiftctrl().read().0 as i32,
                3 => sm.pinctrl().read().0 as i32,
                4 => sm.addr().read().addr() as i32,
                _ => E_INVAL,
            }
        }
        dev_system::PIO_SM_ENABLE => {
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let pio_num = *arg;
            let mask = *arg.add(1) & 0x0F;
            let enable = *arg.add(2);
            if pio_num > 2 { return E_INVAL; }
            let p = pio::pio_pac(pio_num);
            p.ctrl().modify(|w| {
                if enable != 0 {
                    w.set_sm_enable(w.sm_enable() | mask);
                } else {
                    w.set_sm_enable(w.sm_enable() & !mask);
                }
            });
            0
        }
        dev_system::PIO_INSTR_ALLOC => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let pio_num = *arg;
            let count = *arg.add(1);
            if pio_num > 2 || count == 0 || count > 32 { return E_INVAL; }
            match pio::alloc_instruction_slots(pio_num, count as usize) {
                Some((origin, mask)) => {
                    // Write mask back to arg[2..6] so caller can free later
                    if arg_len >= 6 {
                        let mask_bytes = mask.to_le_bytes();
                        *arg.add(2) = mask_bytes[0];
                        *arg.add(3) = mask_bytes[1];
                        *arg.add(4) = mask_bytes[2];
                        *arg.add(5) = mask_bytes[3];
                    }
                    origin as i32
                }
                None => E_NOMEM,
            }
        }
        dev_system::PIO_INSTR_WRITE => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let pio_num = *arg;
            let addr = *arg.add(1);
            if pio_num > 2 || addr > 31 { return E_INVAL; }
            let instr = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
            pio::pio_pac(pio_num).instr_mem(addr as usize).write(|w| w.0 = instr as u32);
            0
        }
        dev_system::PIO_INSTR_FREE => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let pio_num = *arg;
            if pio_num > 2 { return E_INVAL; }
            let mask = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            pio::free_instruction_slots(pio_num, mask);
            0
        }
        dev_system::PIO_PIN_SETUP => {
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let pin = *arg;
            let pio_num = *arg.add(1);
            let pull = *arg.add(2);
            if pio_num > 2 || pin as usize >= gpio::runtime_max_gpio() as usize { return E_INVAL; }
            let pio_pull = match pull {
                0 => pio::PioPull::None,
                1 => pio::PioPull::PullDown,
                2 => pio::PioPull::PullUp,
                _ => return E_INVAL,
            };
            pio::setup_pio_pin(pin, pio_num, pio_pull);
            0
        }
        dev_system::PIO_GPIOBASE => {
            // PIO GPIOBASE: RP2350 only (register absent on RP2040 PAC)
            #[cfg(not(feature = "chip-rp2040"))]
            {
                if arg.is_null() || arg_len < 2 { return E_INVAL; }
                let pio_num = *arg;
                let base16 = *arg.add(1);
                if pio_num > 2 { return E_INVAL; }
                pio::pio_pac(pio_num).gpiobase().write(|w| w.set_gpiobase(base16 != 0));
                0
            }
            #[cfg(feature = "chip-rp2040")]
            { E_NOSYS }
        }
        dev_system::PIO_TXF_WRITE => {
            if arg.is_null() || arg_len < 6 { return E_INVAL; }
            let pio_num = *arg;
            let sm = *arg.add(1);
            if pio_num > 2 || sm > 3 { return E_INVAL; }
            let value = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            pio::pio_pac(pio_num).txf(sm as usize).write_value(value);
            0
        }
        dev_system::PIO_FSTAT_READ => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let pio_num = *arg;
            if pio_num > 2 { return E_INVAL; }
            pio::pio_pac(pio_num).fstat().read().0 as i32
        }
        dev_system::PIO_SM_RESTART => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let pio_num = *arg;
            let mask = *arg.add(1) & 0x0F;
            if pio_num > 2 { return E_INVAL; }
            let p = pio::pio_pac(pio_num);
            p.ctrl().modify(|w| {
                w.set_sm_restart(mask);
                w.set_clkdiv_restart(mask);
            });
            0
        }
        // ── Raw DMA bridge ────────────────────────────────────────────
        dev_system::DMA_ALLOC => {
            dma_alloc_channel()
        }
        dev_system::DMA_FREE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let ch = *arg;
            dma_free_channel(ch)
        }
        dev_system::DMA_START => {
            if arg.is_null() || arg_len < 15 { return E_INVAL; }
            let ch = *arg;
            let read_addr = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            let write_addr = u32::from_le_bytes([*arg.add(5), *arg.add(6), *arg.add(7), *arg.add(8)]);
            let count = u32::from_le_bytes([*arg.add(9), *arg.add(10), *arg.add(11), *arg.add(12)]);
            let dreq = *arg.add(13);
            let flags = *arg.add(14);
            dma_start_raw(ch, read_addr, write_addr, count, dreq, flags)
        }
        dev_system::DMA_BUSY => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let ch = *arg;
            dma_busy(ch)
        }
        dev_system::DMA_ABORT => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let ch = *arg;
            dma_abort(ch)
        }
        dev_system::SPI9_SEND => {
            // 9-bit SPI bit-bang: send command + data using raw PAC GPIO.
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let cs = *arg;
            let sck = *arg.add(1);
            let sda = *arg.add(2);
            let cmd = *arg.add(3);
            let data_len = *arg.add(4) as usize;
            if arg_len < 5 + data_len { return E_INVAL; }
            let hold_cs = if arg_len > 5 + data_len { *arg.add(5 + data_len) != 0 } else { false };
            spi9_pac_send(cs, sck, sda, cmd, arg.add(5), data_len, hold_cs);
            0
        }
        dev_system::SPI9_RESET => {
            // 9-bit SPI reset: RST high->low->high + init SIO pins
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let rst = *arg;
            let cs = *arg.add(1);
            let sck = *arg.add(2);
            let sda = *arg.add(3);
            spi9_pac_reset(rst, cs, sck, sda);
            0
        }
        dev_system::SPI9_CS_SET => {
            // Set CS pin level: arg=[cs_pin:u8, level:u8]
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let cs = *arg;
            let level = *arg.add(1) != 0;
            spi9_pac_pin_set(cs, level);
            0
        }
        _ => E_NOSYS,
    }
}

// ============================================================================
// RP Provider Registration + Cleanup
// ============================================================================

/// Register RP-specific device class providers.
/// Called from init_providers().
fn init_rp_providers() {
    use crate::abi::dev_class;
    use crate::kernel::provider;
    provider::register(dev_class::GPIO, gpio_provider_dispatch);
    provider::register(dev_class::SPI, spi_provider_dispatch);
    provider::register(dev_class::I2C, i2c_provider_dispatch);
    provider::register(dev_class::PIO, pio_provider_dispatch);
    provider::register(dev_class::UART, uart_provider_dispatch);
    provider::register(dev_class::ADC, adc_provider_dispatch);
    // Register system extension for hardware opcodes
    register_system_extension(rp_system_extension_dispatch);
}

/// Release all RP-specific hardware handles owned by a module.
fn release_rp_handles(module_idx: u8) {
    unsafe {
        // Release SPI handles
        for i in 0..MAX_SPI_HANDLES {
            if SPI_HANDLES[i].in_use && SPI_HANDLES[i].owner == module_idx {
                // Release bus ownership if held
                let bus = SPI_HANDLES[i].bus_id as usize;
                if SPI_OWNER[bus].load(Ordering::Acquire) == i as i32 {
                    let slot = SPI_HANDLES[i];
                    if slot.cs_handle >= 0 {
                        let _ = gpio::gpio_set_level(slot.cs_handle, true);
                    }
                    SPI_OWNER[bus].store(INVALID_HANDLE, Ordering::Release);
                }
                SPI_HANDLES[i] = SpiHandle::empty();
                // Clear any pending operation for this handle
                SPI_OPERATIONS[i].pending.store(false, Ordering::Release);
                SPI_OPERATIONS[i].result.store(0, Ordering::Release);
                if SPI_ACTIVE_HANDLE.load(Ordering::Acquire) == i as i32 {
                    SPI_ACTIVE_HANDLE.store(INVALID_HANDLE, Ordering::Release);
                }
            }
        }
        // Release I2C handles
        for i in 0..MAX_I2C_HANDLES {
            if I2C_HANDLES[i].in_use && I2C_HANDLES[i].owner == module_idx {
                let bus = I2C_HANDLES[i].bus_id as usize;
                if I2C_OWNER[bus].load(Ordering::Acquire) == i as i32 {
                    I2C_OWNER[bus].store(-1, Ordering::Release);
                }
                I2C_HANDLES[i] = I2cHandle::empty();
                // Clear any pending operation for this handle
                I2C_OPERATIONS[i].pending.store(false, Ordering::Release);
                I2C_OPERATIONS[i].done.store(false, Ordering::Release);
                I2C_OPERATIONS[i].result.store(0, Ordering::Release);
            }
        }
        // Release UART handles
        for i in 0..MAX_UART_HANDLES {
            if UART_HANDLES[i].in_use && UART_HANDLES[i].owner == module_idx {
                UART_HANDLES[i] = UartHandle::empty();
                UART_OPERATIONS[i].pending.store(false, Ordering::Release);
                UART_OPERATIONS[i].done.store(false, Ordering::Release);
                UART_OPERATIONS[i].result.store(0, Ordering::Release);
            }
        }
        // Release ADC handles
        for i in 0..MAX_ADC_HANDLES {
            if ADC_HANDLES[i].in_use && ADC_HANDLES[i].owner == module_idx {
                ADC_HANDLES[i] = AdcHandle::empty();
                ADC_OPERATIONS[i].pending.store(false, Ordering::Release);
                ADC_OPERATIONS[i].done.store(false, Ordering::Release);
                ADC_OPERATIONS[i].result.store(0, Ordering::Release);
            }
        }
    }
    // Release PIO stream slots
    pio::PioStreamService::release_owned_by(module_idx);
    // Release PIO command slots
    pio::PioCmdService::release_owned_by(module_idx);
    // Release PIO RX stream slots
    pio::PioRxStreamService::release_owned_by(module_idx);
    // Release GPIO pins
    gpio::release_owned_by(module_idx);
}

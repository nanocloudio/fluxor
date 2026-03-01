//! gSPI protocol layer for CYW43.
//!
//! Implements the Infineon gSPI half-duplex protocol over pio_cmd syscalls.
//!
//! # Transaction Flow
//!
//! A gSPI transaction (synchronous — completes in one call):
//! 1. CS assert (GPIO low)
//! 2. Send 32-bit command word + optional data via PIO DMA (blocking)
//! 3. Receive response data via PIO DMA (if read command)
//! 4. CS deassert (GPIO high)
//!
//! txn_write/txn_read execute the full transfer inline. For backward
//! compatibility with existing callers, they set txn_step = WaitPio and
//! return 0. txn_poll then returns the result immediately (no kernel call).

use super::constants::*;
use super::Cyw43State;
use super::abi::{PioCmdTransferArgs, dev_pio, dev_gpio};

// ============================================================================
// PIO Word Byte Swap
// ============================================================================

/// Swap the two 16-bit halves of a u32.
/// Required for all gSPI accesses BEFORE 32-bit word mode is configured.
/// The CYW43 chip starts in 16-bit word mode and reassembles two 16-bit
/// halves with swapped order. Embassy calls this `swap16()`.
#[inline]
pub fn swap16(x: u32) -> u32 {
    x.rotate_left(16)
}

// ============================================================================
// gSPI Command Construction
// ============================================================================

/// Build a gSPI command word.
#[inline]
pub fn make_cmd(write: bool, function: u32, address: u32, size: u32) -> u32 {
    let mut cmd = 0u32;
    if write {
        cmd |= GSPI_CMD_WRITE;
    }
    cmd |= GSPI_CMD_INCR; // auto-increment for multi-byte
    cmd |= (function & 0x3) << GSPI_CMD_FUNC_SHIFT;
    cmd |= (address & 0x1FFFF) << GSPI_CMD_ADDR_SHIFT;
    cmd |= size & GSPI_CMD_SIZE_MASK;
    cmd
}

/// Build a gSPI command word for a bus register read/write (function 0).
/// Bus registers are 8-bit, 16-bit, or 32-bit depending on address.
#[inline]
pub fn bus_cmd(write: bool, addr: u32, size: u32) -> u32 {
    make_cmd(write, FUNC_BUS, addr, size)
}

/// Build a gSPI command word for a backplane register access (function 1).
#[inline]
pub fn bp_cmd(write: bool, addr: u32, size: u32) -> u32 {
    make_cmd(write, FUNC_BACKPLANE, addr & BP_WIN_MASK, size)
}

/// Build a gSPI command word for WLAN data (function 2).
#[inline]
pub fn wlan_cmd(write: bool, size: u32) -> u32 {
    make_cmd(write, FUNC_WLAN, 0, size)
}

// ============================================================================
// Transaction State Machine
// ============================================================================

/// Transaction substep tracking
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxnStep {
    /// No transaction in progress
    Idle = 0,
    /// CS asserted, PIO transfer started, waiting for completion
    WaitPio = 1,
    /// Transfer complete, CS deasserted, result ready
    Done = 2,
}

/// Execute a gSPI write transaction (synchronous).
///
/// Builds command + data into the TX buffer and executes PIO DMA inline.
/// CS is asserted before and deasserted after the transfer.
/// Returns 0 on success, <0 on error.
///
/// TX buffer layout: [tx_words(4)] [cmd(4)] [data(padded)] [rx_words=0(4)]
///
/// Sets txn_step = WaitPio for backward compat; call `txn_poll()` to
/// retrieve the result (returns immediately, no kernel call).
pub unsafe fn txn_write(
    s: &mut Cyw43State,
    function: u32,
    address: u32,
    data: &[u8],
) -> i32 {
    let sys = &*s.syscalls;

    if s.txn_step != TxnStep::Idle {
        return -1; // Transaction already in progress
    }

    let size = data.len();
    if size > MAX_FRAME_SIZE {
        return -2;
    }

    // Build command word
    let cmd = make_cmd(true, function, address, size as u32);

    // Calculate TX words: 1 command + ceil(data_bytes/4) data words
    let data_padded = (size + 3) & !3;
    let data_words = data_padded / 4;
    let tx_words: u32 = (1 + data_words) as u32; // cmd + data

    // tx_words for PIO (native LE so DMA pushes correct u32)
    let tw_bytes = tx_words.to_le_bytes();
    s.txn_buf[0] = tw_bytes[0];
    s.txn_buf[1] = tw_bytes[1];
    s.txn_buf[2] = tw_bytes[2];
    s.txn_buf[3] = tw_bytes[3];

    // Command word (native LE — PIO shifts MSB first from the u32)
    let cmd_bytes = cmd.to_le_bytes();
    s.txn_buf[4] = cmd_bytes[0];
    s.txn_buf[5] = cmd_bytes[1];
    s.txn_buf[6] = cmd_bytes[2];
    s.txn_buf[7] = cmd_bytes[3];

    // Copy data after command
    let mut i = 0;
    while i < size {
        s.txn_buf[8 + i] = data[i];
        i += 1;
    }

    // Zero-pad to 4-byte boundary
    while i < data_padded {
        s.txn_buf[8 + i] = 0;
        i += 1;
    }

    // No byte-swap needed: PIO shifts each u32 MSB first, and the chip
    // reassembles the same 32-bit value. For 8-bit writes, the data byte
    // sits in bits[7:0] of the u32 (native LE position), which is where
    // the chip expects it. Embassy/pico-sdk also send raw u32 without swap.

    // Append rx_words = 0 (no RX phase for writes)
    // Use raw pointer to avoid bounds-check panic in PIC
    let rx_off = 8 + data_padded;
    let rp = s.txn_buf.as_mut_ptr().add(rx_off);
    *rp = 0;
    *rp.add(1) = 0;
    *rp.add(2) = 0;
    *rp.add(3) = 0;

    // Total TX DMA bytes: tx_words(4) + cmd(4) + data(padded) + rx_words(4)
    let tx_bytes = rx_off + 4;

    // Assert CS
    { let mut _l = [0u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }

    // Start PIO transfer (TX only, no RX)
    let transfer_args = PioCmdTransferArgs {
        tx_ptr: s.txn_buf.as_ptr(),
        tx_len: tx_bytes as u32,
        rx_ptr: core::ptr::null_mut(),
        rx_len: 0,
    };
    let result = (sys.dev_call)(
        s.pio_handle,
        dev_pio::CMD_TRANSFER,
        &transfer_args as *const _ as *mut u8,
        core::mem::size_of::<PioCmdTransferArgs>(),
    );

    // Deassert CS — transfer completes synchronously
    { let mut _l = [1u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }

    if result < 0 {
        return result;
    }

    s.txn_step = TxnStep::WaitPio;
    s.txn_len = size as u16;
    s.txn_rx_skip_words = 0; // no RX phase for writes
    0
}

/// Execute a gSPI read transaction (synchronous).
///
/// Builds command into TX buffer and executes PIO DMA inline (TX + RX).
/// CS is asserted before and deasserted after the transfer.
/// Returns 0 on success, <0 on error.
///
/// TX buffer layout: [tx_words=1(4)] [cmd(4)] [rx_words(4)]
///
/// RX includes response word + optional pad word (backplane) + payload:
///   - Bus/WLAN reads: rx_words = 1 (response) + payload_words
///   - Backplane reads: rx_words = 2 (response + pad) + payload_words
///
/// Sets txn_step = WaitPio for backward compat; call `txn_poll()` to
/// retrieve the result. Read payload via `rxn_u32()` / `rxn_payload_ptr()`.
pub unsafe fn txn_read(
    s: &mut Cyw43State,
    function: u32,
    address: u32,
    read_len: usize,
) -> i32 {
    let sys = &*s.syscalls;

    if s.txn_step != TxnStep::Idle {
        return -1;
    }

    if read_len > 1500 {
        return -2;
    }

    // Build command word
    let cmd = make_cmd(false, function, address, read_len as u32);

    // RX word count: skip + payload + status.
    // With RESPONSE_DELAY=4, all functions have a padding word before payload.
    // Backplane always has 1 padding word. Bus/WLAN skip depends on RESPONSE_DELAY.
    let skip_words: usize = if function == FUNC_BACKPLANE {
        1  // backplane always has 1 padding word
    } else if function == FUNC_BUS {
        GSPI_SKIP_WORDS_BUS
    } else {
        GSPI_SKIP_WORDS_WLAN
    };
    let payload_padded = (read_len + 3) & !3;
    let payload_words = payload_padded / 4;
    let rx_words: u32 = (skip_words + payload_words + GSPI_STATUS_WORDS) as u32;

    // TX buffer: [tx_words(4)] [cmd(4)] [rx_words(4)]
    let tx_words: u32 = 1; // just the command word
    let tw_bytes = tx_words.to_le_bytes();
    s.txn_buf[0] = tw_bytes[0];
    s.txn_buf[1] = tw_bytes[1];
    s.txn_buf[2] = tw_bytes[2];
    s.txn_buf[3] = tw_bytes[3];

    // Command word (native LE — PIO shifts MSB first from the u32)
    let cmd_bytes = cmd.to_le_bytes();
    s.txn_buf[4] = cmd_bytes[0];
    s.txn_buf[5] = cmd_bytes[1];
    s.txn_buf[6] = cmd_bytes[2];
    s.txn_buf[7] = cmd_bytes[3];

    // rx_words (native LE — consumed by PIO internally)
    let rw_bytes = rx_words.to_le_bytes();
    s.txn_buf[8] = rw_bytes[0];
    s.txn_buf[9] = rw_bytes[1];
    s.txn_buf[10] = rw_bytes[2];
    s.txn_buf[11] = rw_bytes[3];

    let tx_bytes: usize = 12; // tx_words(4) + cmd(4) + rx_words(4)
    let rx_bytes = rx_words as usize * 4;

    // Store skip info for txn_poll / rxn accessors
    s.txn_rx_skip_words = skip_words as u8;
    s.txn_rx_payload_len = read_len as u16;

    // Assert CS
    { let mut _l = [0u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }

    // Start PIO transfer (TX cmd+rx_count, RX response+payload)
    let transfer_args = PioCmdTransferArgs {
        tx_ptr: s.txn_buf.as_ptr(),
        tx_len: tx_bytes as u32,
        rx_ptr: s.rxn_buf.as_mut_ptr(),
        rx_len: rx_bytes as u32,
    };
    let result = (sys.dev_call)(
        s.pio_handle,
        dev_pio::CMD_TRANSFER,
        &transfer_args as *const _ as *mut u8,
        core::mem::size_of::<PioCmdTransferArgs>(),
    );

    // Deassert CS — transfer completes synchronously
    { let mut _l = [1u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }

    if result < 0 {
        return result;
    }

    s.txn_step = TxnStep::WaitPio;
    s.txn_len = read_len as u16;
    0
}

/// Complete a gSPI transaction.
///
/// Transfer already completed synchronously in txn_write/txn_read.
/// Returns the byte count immediately (no kernel call).
pub unsafe fn txn_poll(s: &mut Cyw43State) -> i32 {
    if s.txn_step != TxnStep::WaitPio {
        return -1;
    }

    s.txn_step = TxnStep::Idle;
    s.txn_len as i32
}

/// Reset transaction state (e.g., after error).
pub unsafe fn txn_reset(s: &mut Cyw43State) {
    let sys = &*s.syscalls;
    // Ensure CS is high
    { let mut _l = [1u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }
    s.txn_step = TxnStep::Idle;
    s.txn_len = 0;
}

// ============================================================================
// Higher-Level Bus Operations
// ============================================================================

/// Read a 32-bit bus register (function 0).
/// Must be called when txn is idle. Starts read, caller must poll.
pub unsafe fn bus_read32_start(s: &mut Cyw43State, addr: u32) -> i32 {
    txn_read(s, FUNC_BUS, addr, 4)
}

/// Write a 32-bit bus register (function 0).
pub unsafe fn bus_write32_start(s: &mut Cyw43State, addr: u32, value: u32) -> i32 {
    let data = value.to_le_bytes();
    txn_write(s, FUNC_BUS, addr, &data)
}

/// Read an 8-bit bus register.
pub unsafe fn bus_read8_start(s: &mut Cyw43State, addr: u32) -> i32 {
    txn_read(s, FUNC_BUS, addr, 1)
}

/// Write an 8-bit bus register.
pub unsafe fn bus_write8_start(s: &mut Cyw43State, addr: u32, value: u8) -> i32 {
    txn_write(s, FUNC_BUS, addr, &[value])
}

/// Write a 32-bit value with swap16 on both cmd and data (pre-init, 16-bit mode).
/// Embassy uses this for bus config before 32-bit word mode is active.
pub unsafe fn bus_write32_swapped_start(s: &mut Cyw43State, addr: u32, value: u32) -> i32 {
    let sys = &*s.syscalls;

    if s.txn_step != TxnStep::Idle {
        return -1;
    }

    let cmd = swap16(make_cmd(true, FUNC_BUS, addr, 4));
    let data = swap16(value);
    let tx_words: u32 = 2; // cmd + data

    let tw = tx_words.to_le_bytes();
    s.txn_buf[0] = tw[0]; s.txn_buf[1] = tw[1]; s.txn_buf[2] = tw[2]; s.txn_buf[3] = tw[3];

    let cb = cmd.to_le_bytes();
    s.txn_buf[4] = cb[0]; s.txn_buf[5] = cb[1]; s.txn_buf[6] = cb[2]; s.txn_buf[7] = cb[3];

    let db = data.to_le_bytes();
    s.txn_buf[8] = db[0]; s.txn_buf[9] = db[1]; s.txn_buf[10] = db[2]; s.txn_buf[11] = db[3];

    // rx_words = 0
    s.txn_buf[12] = 0; s.txn_buf[13] = 0; s.txn_buf[14] = 0; s.txn_buf[15] = 0;

    // Assert CS
    { let mut _l = [0u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }

    let transfer_args = PioCmdTransferArgs {
        tx_ptr: s.txn_buf.as_ptr(),
        tx_len: 16, // tx_words(4) + cmd(4) + data(4) + rx_words(4)
        rx_ptr: core::ptr::null_mut(),
        rx_len: 0,
    };
    let result = (sys.dev_call)(
        s.pio_handle,
        dev_pio::CMD_TRANSFER,
        &transfer_args as *const _ as *mut u8,
        core::mem::size_of::<PioCmdTransferArgs>(),
    );

    // Deassert CS — transfer completes synchronously
    { let mut _l = [1u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }

    if result < 0 {
        return result;
    }

    s.txn_step = TxnStep::WaitPio;
    s.txn_len = 4;
    s.txn_rx_skip_words = 0;
    0
}

/// Read a 32-bit value with swap16 on cmd (pre-init, 16-bit mode).
/// Reads 2 RX words (payload + status), no skip. Caller must swap16 the result.
pub unsafe fn bus_read32_swapped_start(s: &mut Cyw43State, addr: u32) -> i32 {
    let sys = &*s.syscalls;

    if s.txn_step != TxnStep::Idle {
        return -1;
    }

    let cmd = swap16(make_cmd(false, FUNC_BUS, addr, 4));
    let tx_words: u32 = 1;
    let rx_words: u32 = 2; // payload + status (no skip for bus)

    let tw = tx_words.to_le_bytes();
    s.txn_buf[0] = tw[0]; s.txn_buf[1] = tw[1]; s.txn_buf[2] = tw[2]; s.txn_buf[3] = tw[3];

    let cb = cmd.to_le_bytes();
    s.txn_buf[4] = cb[0]; s.txn_buf[5] = cb[1]; s.txn_buf[6] = cb[2]; s.txn_buf[7] = cb[3];

    let rw = rx_words.to_le_bytes();
    s.txn_buf[8] = rw[0]; s.txn_buf[9] = rw[1]; s.txn_buf[10] = rw[2]; s.txn_buf[11] = rw[3];

    s.txn_rx_skip_words = 0;
    s.txn_rx_payload_len = 4;

    // Assert CS
    { let mut _l = [0u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }

    let transfer_args = PioCmdTransferArgs {
        tx_ptr: s.txn_buf.as_ptr(),
        tx_len: 12,
        rx_ptr: s.rxn_buf.as_mut_ptr(),
        rx_len: 8, // 2 words * 4 bytes
    };
    let result = (sys.dev_call)(
        s.pio_handle,
        dev_pio::CMD_TRANSFER,
        &transfer_args as *const _ as *mut u8,
        core::mem::size_of::<PioCmdTransferArgs>(),
    );

    // Deassert CS — transfer completes synchronously
    { let mut _l = [1u8]; (sys.dev_call)(s.cs_handle, dev_gpio::SET_LEVEL, _l.as_mut_ptr(), 1); }

    if result < 0 {
        return result;
    }

    s.txn_step = TxnStep::WaitPio;
    s.txn_len = 4;
    0
}

/// Get the u32 result from a swapped read (apply swap16 to undo 16-bit mode).
pub fn rxn_u32_swapped(s: &Cyw43State) -> u32 {
    swap16(rxn_u32(s))
}

/// Get a pointer to the start of payload data in the RX buffer.
/// Skips the response word (and pad word for backplane reads).
pub fn rxn_payload_ptr(s: &Cyw43State) -> *const u8 {
    let skip = s.txn_rx_skip_words as usize * 4;
    unsafe { s.rxn_buf.as_ptr().add(skip) }
}

/// Get the u32 result from the RX buffer after a completed read.
/// Skips response/pad words to read actual payload.
pub fn rxn_u32(s: &Cyw43State) -> u32 {
    let p = rxn_payload_ptr(s);
    unsafe {
        u32::from_le_bytes([
            *p,
            *p.add(1),
            *p.add(2),
            *p.add(3),
        ])
    }
}

/// Get the u8 result from the RX buffer after a completed read.
/// Skips response/pad words to read actual payload.
pub fn rxn_u8(s: &Cyw43State) -> u8 {
    let p = rxn_payload_ptr(s);
    unsafe { *p }
}

/// Read raw u32 word at index from rxn_buf (post-swap, no skip).
/// Used for debugging to inspect response/pad words.
pub fn rxn_raw_u32(s: &Cyw43State, word_idx: usize) -> u32 {
    let off = word_idx * 4;
    if off + 3 >= s.rxn_buf.len() {
        return 0;
    }
    let p = unsafe { s.rxn_buf.as_ptr().add(off) };
    unsafe {
        u32::from_le_bytes([
            *p,
            *p.add(1),
            *p.add(2),
            *p.add(3),
        ])
    }
}

// ============================================================================
// Backplane Operations
// ============================================================================

/// Set the backplane window to access a given address.
/// The window register is function 1, and covers 32KB.
/// Returns: 0 = already in window (no transaction), 1 = transaction started (needs poll),
///          <0 = error.
pub unsafe fn bp_set_window(s: &mut Cyw43State, addr: u32) -> i32 {
    let window = addr & !BP_WIN_MASK;
    if window == s.bp_window {
        return 0; // Already in correct window
    }
    s.bp_window_target = window;

    // Write the window register (3 bytes: bits 31:15 of the address)
    // The window register is at backplane address 0x1000A (3 bytes)
    let win_bytes = [
        ((window >> 8) & 0xFF) as u8,
        ((window >> 16) & 0xFF) as u8,
        ((window >> 24) & 0xFF) as u8,
    ];
    let r = txn_write(s, FUNC_BACKPLANE, REG_BP_WIN, &win_bytes);
    if r < 0 { return r; }
    1 // Transaction started, caller must poll then call bp_window_done
}

/// Called after bp_set_window transaction completes.
pub fn bp_window_done(s: &mut Cyw43State) {
    s.bp_window = s.bp_window_target;
}

/// Start a backplane read (8-bit).
/// Assumes window is already set correctly.
pub unsafe fn bp_read8_start(s: &mut Cyw43State, addr: u32) -> i32 {
    txn_read(s, FUNC_BACKPLANE, addr & BP_WIN_MASK, 1)
}

/// Start a backplane write (8-bit).
pub unsafe fn bp_write8_start(s: &mut Cyw43State, addr: u32, value: u8) -> i32 {
    txn_write(s, FUNC_BACKPLANE, addr & BP_WIN_MASK, &[value])
}

/// Read 8-bit SPI wrapper register (chip clock CSR, sleep CSR, etc.).
/// Wrapper registers live at 0x1000x and are accessed via FUNC_BACKPLANE
/// with the full address preserved (no BP_WIN_MASK — bit 16 must be set).
pub unsafe fn wrapper_read8_start(s: &mut Cyw43State, addr: u32) -> i32 {
    txn_read(s, FUNC_BACKPLANE, addr, 1)
}

/// Write 8-bit SPI wrapper register.
pub unsafe fn wrapper_write8_start(s: &mut Cyw43State, addr: u32, value: u8) -> i32 {
    txn_write(s, FUNC_BACKPLANE, addr, &[value])
}

/// Start a backplane read (32-bit).
/// Embassy ORs BP_32BIT_FLAG (0x8000) into the address for 32-bit backplane reads.
pub unsafe fn bp_read32_start(s: &mut Cyw43State, addr: u32) -> i32 {
    txn_read(s, FUNC_BACKPLANE, (addr & BP_WIN_MASK) | BP_32BIT_FLAG, 4)
}

/// Start a backplane write (32-bit).
/// Embassy ORs BP_32BIT_FLAG (0x8000) into the address for 32-bit backplane writes.
pub unsafe fn bp_write32_start(s: &mut Cyw43State, addr: u32, value: u32) -> i32 {
    let data = value.to_le_bytes();
    txn_write(s, FUNC_BACKPLANE, (addr & BP_WIN_MASK) | BP_32BIT_FLAG, &data)
}

/// Start a backplane block write (for firmware/NVRAM upload).
/// Caller must ensure `len` doesn't cross a 32KB window boundary.
pub unsafe fn bp_write_block_start(
    s: &mut Cyw43State,
    addr: u32,
    data: *const u8,
    len: usize,
) -> i32 {
    let slice = core::slice::from_raw_parts(data, len);
    txn_write(s, FUNC_BACKPLANE, addr & BP_WIN_MASK, slice)
}

// ============================================================================
// Synchronous Convenience Wrappers
// ============================================================================

/// Synchronous gSPI write — txn_write + txn_poll in one call.
/// Returns >0 on success, <0 on error. Leaves txn in Idle state.
pub unsafe fn txn_write_sync(
    s: &mut Cyw43State,
    function: u32,
    address: u32,
    data: &[u8],
) -> i32 {
    let r = txn_write(s, function, address, data);
    if r < 0 { return r; }
    txn_poll(s)
}

/// Synchronous gSPI read — txn_read + txn_poll in one call.
/// RX data available in s.rxn_buf via rxn_u32/rxn_payload_ptr after return.
/// Returns >0 on success (bytes read), <0 on error.
pub unsafe fn txn_read_sync(
    s: &mut Cyw43State,
    function: u32,
    address: u32,
    read_len: usize,
) -> i32 {
    let r = txn_read(s, function, address, read_len);
    if r < 0 { return r; }
    txn_poll(s)
}

/// Synchronous backplane window set.
/// Returns 0 if already in correct window, >0 if window was changed.
pub unsafe fn bp_set_window_sync(s: &mut Cyw43State, addr: u32) -> i32 {
    let window = addr & !BP_WIN_MASK;
    if window == s.bp_window {
        return 0;
    }
    let win_bytes = [
        ((window >> 8) & 0xFF) as u8,
        ((window >> 16) & 0xFF) as u8,
        ((window >> 24) & 0xFF) as u8,
    ];
    let r = txn_write_sync(s, FUNC_BACKPLANE, REG_BP_WIN, &win_bytes);
    if r < 0 { return r; }
    s.bp_window = window;
    1
}

/// Synchronous backplane block write (for firmware/NVRAM upload).
/// Handles window setting + data write in one call.
pub unsafe fn bp_write_block_sync(
    s: &mut Cyw43State,
    addr: u32,
    data: *const u8,
    len: usize,
) -> i32 {
    let r = bp_set_window_sync(s, addr);
    if r < 0 { return r; }

    let slice = core::slice::from_raw_parts(data, len);
    txn_write_sync(s, FUNC_BACKPLANE, addr & BP_WIN_MASK, slice)
}

// ============================================================================
// WLAN (Function 2) Operations
// ============================================================================

/// Start a WLAN frame write (function 2).
pub unsafe fn wlan_write_start(
    s: &mut Cyw43State,
    data: *const u8,
    len: usize,
) -> i32 {
    if len > MAX_FRAME_SIZE {
        return -2;
    }
    let slice = core::slice::from_raw_parts(data, len);
    txn_write(s, FUNC_WLAN, 0, slice)
}

/// Start a WLAN frame read (function 2).
/// Read len is determined from status register F2 packet length.
pub unsafe fn wlan_read_start(s: &mut Cyw43State, len: usize) -> i32 {
    txn_read(s, FUNC_WLAN, 0, len)
}

// ============================================================================
// BT (Function 3) Operations
// ============================================================================

/// Start a BT frame write (function 3, HCI commands to chip).
pub unsafe fn bt_write_start(
    s: &mut Cyw43State,
    data: *const u8,
    len: usize,
) -> i32 {
    if len > MAX_FRAME_SIZE {
        return -2;
    }
    let slice = core::slice::from_raw_parts(data, len);
    txn_write(s, FUNC_BT, 0, slice)
}

/// Start a BT frame read (function 3, HCI events/data from chip).
/// Read len is determined from status register F3 packet length.
pub unsafe fn bt_read_start(s: &mut Cyw43State, len: usize) -> i32 {
    txn_read(s, FUNC_BT, 0, len)
}

// ============================================================================
// SDPCM Framing
// ============================================================================

/// Build an SDPCM + CDC ioctl header in the given buffer.
///
/// Returns the total header length (SDPCM + CDC).
/// The caller must append the ioctl payload data after this header.
///
/// # Safety
/// `buf` must point to at least `SDPCM_HEADER_LEN + CDC_HEADER_LEN` writable bytes.
pub unsafe fn build_ioctl_header(
    buf: &mut [u8; super::MAX_FRAME_SIZE],
    channel: u8,
    sdpcm_seq: u8,
    cmd: u32,
    iface: u8,
    payload_len: usize,
) -> usize {
    let total_len = SDPCM_HEADER_LEN + CDC_HEADER_LEN + payload_len;
    let p = buf.as_mut_ptr();

    // SDPCM header (12 bytes)
    *p.add(0) = (total_len & 0xFF) as u8;
    *p.add(1) = ((total_len >> 8) & 0xFF) as u8;
    *p.add(2) = (!total_len & 0xFF) as u8;
    *p.add(3) = ((!total_len >> 8) & 0xFF) as u8;
    *p.add(4) = sdpcm_seq;
    *p.add(5) = channel;
    *p.add(6) = 0;
    *p.add(7) = SDPCM_HEADER_LEN as u8;
    *p.add(8) = 0;
    *p.add(9) = 0;
    *p.add(10) = 0;
    *p.add(11) = 0;

    // CDC header (16 bytes) — starts at offset 12
    // Layout: cmd(u32) + len(u32) + flags(u16) + id(u16) + status(u32)
    let c = SDPCM_HEADER_LEN;
    // cmd: u32 LE [0..4]
    *p.add(c + 0) = (cmd & 0xFF) as u8;
    *p.add(c + 1) = ((cmd >> 8) & 0xFF) as u8;
    *p.add(c + 2) = ((cmd >> 16) & 0xFF) as u8;
    *p.add(c + 3) = ((cmd >> 24) & 0xFF) as u8;
    // len: u32 LE [4..8]
    *p.add(c + 4) = (payload_len & 0xFF) as u8;
    *p.add(c + 5) = ((payload_len >> 8) & 0xFF) as u8;
    *p.add(c + 6) = 0;
    *p.add(c + 7) = 0;
    // flags: u16 LE [8..10] — SET(0x02) + interface bits
    let flags: u16 = 0x02 | ((iface as u16 & 0x07) << 12);
    *p.add(c + 8) = (flags & 0xFF) as u8;
    *p.add(c + 9) = ((flags >> 8) & 0xFF) as u8;
    // id: u16 LE [10..12] — unique per ioctl for response matching
    *p.add(c + 10) = sdpcm_seq;
    *p.add(c + 11) = 0;
    // status: u32 LE [12..16] = 0
    *p.add(c + 12) = 0;
    *p.add(c + 13) = 0;
    *p.add(c + 14) = 0;
    *p.add(c + 15) = 0;

    SDPCM_HEADER_LEN + CDC_HEADER_LEN
}

/// Build an SDPCM + CDC header for a GET ioctl.
/// Same as build_ioctl_header but with SET flag cleared (flags bit 1 = 0).
/// For GET_VAR, payload is the variable name (null-terminated), and the firmware
/// returns the value in the response frame at the same CDC offset.
pub unsafe fn build_ioctl_header_get(
    buf: &mut [u8; super::MAX_FRAME_SIZE],
    channel: u8,
    sdpcm_seq: u8,
    cmd: u32,
    iface: u8,
    payload_len: usize,
) -> usize {
    let total_len = SDPCM_HEADER_LEN + CDC_HEADER_LEN + payload_len;
    let p = buf.as_mut_ptr();

    // SDPCM header (12 bytes)
    *p.add(0) = (total_len & 0xFF) as u8;
    *p.add(1) = ((total_len >> 8) & 0xFF) as u8;
    *p.add(2) = (!total_len & 0xFF) as u8;
    *p.add(3) = ((!total_len >> 8) & 0xFF) as u8;
    *p.add(4) = sdpcm_seq;
    *p.add(5) = channel;
    *p.add(6) = 0;
    *p.add(7) = SDPCM_HEADER_LEN as u8;
    *p.add(8) = 0;
    *p.add(9) = 0;
    *p.add(10) = 0;
    *p.add(11) = 0;

    // CDC header (16 bytes) — GET: flags = interface bits only (no SET bit)
    let c = SDPCM_HEADER_LEN;
    *p.add(c + 0) = (cmd & 0xFF) as u8;
    *p.add(c + 1) = ((cmd >> 8) & 0xFF) as u8;
    *p.add(c + 2) = ((cmd >> 16) & 0xFF) as u8;
    *p.add(c + 3) = ((cmd >> 24) & 0xFF) as u8;
    *p.add(c + 4) = (payload_len & 0xFF) as u8;
    *p.add(c + 5) = ((payload_len >> 8) & 0xFF) as u8;
    *p.add(c + 6) = 0;
    *p.add(c + 7) = 0;
    // flags: GET = no SET bit (0x00) + interface bits
    let flags: u16 = (iface as u16 & 0x07) << 12;
    *p.add(c + 8) = (flags & 0xFF) as u8;
    *p.add(c + 9) = ((flags >> 8) & 0xFF) as u8;
    *p.add(c + 10) = sdpcm_seq;
    *p.add(c + 11) = 0;
    *p.add(c + 12) = 0;
    *p.add(c + 13) = 0;
    *p.add(c + 14) = 0;
    *p.add(c + 15) = 0;

    SDPCM_HEADER_LEN + CDC_HEADER_LEN
}

/// Build an SDPCM data frame header (for TX ethernet frames).
///
/// Returns the total header length (SDPCM + BDC).
///
/// # Safety
/// `buf` must point to a writable frame buffer.
pub unsafe fn build_data_header(
    buf: &mut [u8; super::MAX_FRAME_SIZE],
    sdpcm_seq: u8,
    payload_len: usize,
) -> usize {
    let total_len = SDPCM_HEADER_LEN + BDC_HEADER_LEN + payload_len;
    let p = buf.as_mut_ptr();

    *p.add(0) = (total_len & 0xFF) as u8;
    *p.add(1) = ((total_len >> 8) & 0xFF) as u8;
    *p.add(2) = (!total_len & 0xFF) as u8;
    *p.add(3) = ((!total_len >> 8) & 0xFF) as u8;
    *p.add(4) = sdpcm_seq;
    *p.add(5) = SDPCM_CHAN_DATA;
    *p.add(6) = 0;
    *p.add(7) = SDPCM_HEADER_LEN as u8;
    *p.add(8) = 0;
    *p.add(9) = 0;
    *p.add(10) = 0;
    *p.add(11) = 0;

    // BDC header (4 bytes)
    let b = SDPCM_HEADER_LEN;
    *p.add(b + 0) = 0x20; // BDC version 2
    *p.add(b + 1) = 0;
    *p.add(b + 2) = 0;
    *p.add(b + 3) = 0;

    SDPCM_HEADER_LEN + BDC_HEADER_LEN
}

/// Parse an SDPCM header from received data.
///
/// Returns (channel, data_offset, data_len) or (-1, 0, 0) if invalid.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
pub unsafe fn parse_sdpcm_header(data: *const u8, len: usize) -> (i8, usize, usize) {
    if len < SDPCM_HEADER_LEN {
        return (-1, 0, 0);
    }

    let frame_len = (*data as u16 | ((*data.add(1) as u16) << 8)) as usize;
    let check = (*data.add(2) as u16 | ((*data.add(3) as u16) << 8)) as usize;

    // Validate checksum (~length)
    if (frame_len ^ check) != 0xFFFF {
        return (-1, 0, 0);
    }

    if frame_len > len || frame_len < SDPCM_HEADER_LEN {
        return (-1, 0, 0);
    }

    let channel = *data.add(5) & 0x0F;
    let data_offset = *data.add(7) as usize;

    if data_offset < SDPCM_HEADER_LEN || data_offset > frame_len {
        return (-1, 0, 0);
    }

    let data_len = frame_len - data_offset;
    (channel as i8, data_offset, data_len)
}

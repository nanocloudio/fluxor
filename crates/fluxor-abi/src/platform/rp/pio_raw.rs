// Platform: RP PIO raw register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the pio PIC provider module. Portable consumers should call
// the HAL PIO contract (`platform/rp/pio.rs`) instead.

/// Completion of a `CMD_TRANSFER` started earlier: 1 busy, 0 done.
pub use super::super::super::registry::rp_raw::PIO_CMD_POLL as CMD_POLL;
/// Atomic PIO CMD transfer — sets up SM + starts DMA in one call.
/// handle = the caller's claim of the PIO block, arg = [`cmd_transfer`].
/// Performs: disable SM, set X (write_bits), set Y (read_bits),
/// SET PINDIRS=1, JMP origin, arm both DMA directions, enable SM. Returns 0
/// once started; `CMD_POLL` reports completion.
pub use super::super::super::registry::rp_raw::PIO_CMD_TRANSFER as CMD_TRANSFER;
/// Read PIO FSTAT register.
/// handle=-1, arg=[pio:u8] (1 byte). Returns fstat as i32.
pub use super::super::super::registry::rp_raw::PIO_FSTAT_READ as FSTAT_READ;
/// Set PIO GPIOBASE register.
/// handle=-1, arg=[pio:u8, base16:u8] (2 bytes). base16: 0=GPIO 0-31, 1=GPIO 16-47.
pub use super::super::super::registry::rp_raw::PIO_GPIOBASE as GPIOBASE;
/// Set PIO INPUT_SYNC_BYPASS register (bypass 2-FF synchronizer on input pins).
/// handle=-1, arg=[pio:u8, pin_mask:u32 LE] (5 bytes). Sets bits in bypass reg.
pub use super::super::super::registry::rp_raw::PIO_INPUT_SYNC_BYPASS as INPUT_SYNC_BYPASS;
/// Allocate contiguous instruction slots.
/// handle=-1, arg=[pio:u8, count:u8] (2 bytes). Returns origin as i32, or <0 error.
pub use super::super::super::registry::rp_raw::PIO_INSTR_ALLOC as INSTR_ALLOC;
/// Free instruction slots by mask.
/// handle=-1, arg=[pio:u8, mask:u32 LE] (5 bytes).
pub use super::super::super::registry::rp_raw::PIO_INSTR_FREE as INSTR_FREE;
/// Write a single instruction to PIO instruction memory.
/// handle=-1, arg=[pio:u8, slot:u8, instr:u16 LE] (4 bytes).
pub use super::super::super::registry::rp_raw::PIO_INSTR_WRITE as INSTR_WRITE;
/// The input level of a pin set up for PIO: 1 high, 0 low.
/// handle=-1, arg=[pin:u8] (1 byte). A peripheral that signals pending
/// work on its data line between transfers is read here without a transfer.
pub use super::super::super::registry::rp_raw::PIO_PIN_LEVEL as PIN_LEVEL;
/// Setup a GPIO pin for PIO use (funcsel + pad config).
/// handle=-1, arg=[pin:u8, pio_num:u8, pull:u8] (3 bytes).
/// pull: 0=none, 1=pull-down, 2=pull-up.
pub use super::super::super::registry::rp_raw::PIO_PIN_SETUP as PIN_SETUP;
/// Atomic multi-SM enable/disable.
/// handle=-1, arg=[pio:u8, mask:u8, enable:u8] (3 bytes).
pub use super::super::super::registry::rp_raw::PIO_SM_ENABLE as SM_ENABLE;
/// Force-execute an instruction on a PIO SM.
/// handle=-1, arg=[pio:u8, sm:u8, instr:u16 LE] (4 bytes).
pub use super::super::super::registry::rp_raw::PIO_SM_EXEC as SM_EXEC;
/// Read a PIO SM register.
/// handle=-1, arg=[pio:u8, sm:u8, reg:u8] (3 bytes). Returns register value as i32.
/// Registers: 0=CLKDIV, 1=EXECCTRL, 2=SHIFTCTRL, 3=PINCTRL, 4=ADDR.
pub use super::super::super::registry::rp_raw::PIO_SM_READ_REG as SM_READ_REG;
/// SM restart + clock divider restart.
/// handle=-1, arg=[pio:u8, mask:u8] (2 bytes).
pub use super::super::super::registry::rp_raw::PIO_SM_RESTART as SM_RESTART;
/// Write a PIO SM register.
/// handle=-1, arg=[pio:u8, sm:u8, reg:u8, value:u32 LE] (7 bytes).
/// Registers: 0=CLKDIV, 1=EXECCTRL, 2=SHIFTCTRL, 3=PINCTRL.
pub use super::super::super::registry::rp_raw::PIO_SM_WRITE_REG as SM_WRITE_REG;
/// Write a 32-bit value to a PIO SM TX FIFO.
/// handle=-1, arg=[pio:u8, sm:u8, value:u32 LE] (6 bytes).
pub use super::super::super::registry::rp_raw::PIO_TXF_WRITE as TXF_WRITE;

/// `CMD_TRANSFER` argument. The TX words (`tx_words`) and the RX words
/// (`ceil((read_bits + 1) / 32)`, at least one) lie in one span the caller
/// lent on its PIO claim handle (`lend::OPEN`, direction inout).
pub mod cmd_transfer {
    /// `u8` — PIO block.
    pub const PIO: usize = 0;
    /// `u8` — state machine.
    pub const SM: usize = 1;
    /// `u8` — program origin from `INSTR_ALLOC`.
    pub const ORIGIN: usize = 2;
    /// `u32` LE — bits to write, minus one (0 for none).
    pub const WRITE_BITS: usize = 4;
    /// `u32` LE — bits to read, minus one (0 for none).
    pub const READ_BITS: usize = 8;
    /// `u32` LE — the lend's cookie.
    pub const LEND: usize = 12;
    /// `u32` LE — TX words' offset in the lend.
    pub const TX_OFFSET: usize = 16;
    /// `u32` LE — TX words.
    pub const TX_WORDS: usize = 20;
    /// `u32` LE — RX words' offset in the lend.
    pub const RX_OFFSET: usize = 24;
    /// `u8` — the caller's TX DMA channel number.
    pub const CH_TX: usize = 28;
    /// `u8` — the caller's RX DMA channel number.
    pub const CH_RX: usize = 29;
    /// Total length, in bytes.
    pub const LEN: usize = 32;
}

// Platform: RP PIO raw register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the pio PIC provider module. Portable consumers should call
// the HAL PIO contract (`contracts/hal/pio.rs`) instead.

/// Force-execute an instruction on a PIO SM.
/// handle=-1, arg=[pio:u8, sm:u8, instr:u16 LE] (4 bytes).
pub const SM_EXEC: u32 = 0x0C70;
/// Write a PIO SM register.
/// handle=-1, arg=[pio:u8, sm:u8, reg:u8, value:u32 LE] (7 bytes).
/// Registers: 0=CLKDIV, 1=EXECCTRL, 2=SHIFTCTRL, 3=PINCTRL.
pub const SM_WRITE_REG: u32 = 0x0C71;
/// Read a PIO SM register.
/// handle=-1, arg=[pio:u8, sm:u8, reg:u8] (3 bytes). Returns register value as i32.
/// Registers: 0=CLKDIV, 1=EXECCTRL, 2=SHIFTCTRL, 3=PINCTRL, 4=ADDR.
pub const SM_READ_REG: u32 = 0x0C72;
/// Atomic multi-SM enable/disable.
/// handle=-1, arg=[pio:u8, mask:u8, enable:u8] (3 bytes).
pub const SM_ENABLE: u32 = 0x0C73;
/// Allocate contiguous instruction slots.
/// handle=-1, arg=[pio:u8, count:u8] (2 bytes). Returns origin as i32, or <0 error.
pub const INSTR_ALLOC: u32 = 0x0C74;
/// Write a single instruction to PIO instruction memory.
/// handle=-1, arg=[pio:u8, addr:u8, instr:u16 LE] (4 bytes).
pub const INSTR_WRITE: u32 = 0x0C75;
/// Free instruction slots by mask.
/// handle=-1, arg=[pio:u8, mask:u32 LE] (5 bytes).
pub const INSTR_FREE: u32 = 0x0C76;
/// Setup a GPIO pin for PIO use (funcsel + pad config).
/// handle=-1, arg=[pin:u8, pio_num:u8, pull:u8] (3 bytes).
/// pull: 0=none, 1=pull-down, 2=pull-up.
pub const PIN_SETUP: u32 = 0x0C77;
/// Set PIO GPIOBASE register.
/// handle=-1, arg=[pio:u8, base16:u8] (2 bytes). base16: 0=GPIO 0-31, 1=GPIO 16-47.
pub const GPIOBASE: u32 = 0x0C78;
/// Write a 32-bit value to a PIO SM TX FIFO.
/// handle=-1, arg=[pio:u8, sm:u8, value:u32 LE] (6 bytes).
pub const TXF_WRITE: u32 = 0x0C79;
/// Read PIO FSTAT register.
/// handle=-1, arg=[pio:u8] (1 byte). Returns fstat as i32.
pub const FSTAT_READ: u32 = 0x0C7A;
/// SM restart + clock divider restart.
/// handle=-1, arg=[pio:u8, mask:u8] (2 bytes).
pub const SM_RESTART: u32 = 0x0C7B;
/// Set PIO INPUT_SYNC_BYPASS register (bypass 2-FF synchronizer on input pins).
/// handle=-1, arg=[pio:u8, pin_mask:u32 LE] (5 bytes). Sets bits in bypass reg.
pub const INPUT_SYNC_BYPASS: u32 = 0x0C7C;
/// Atomic PIO CMD transfer — sets up SM + runs DMA in one call.
/// handle=-1, arg = PioCmdExecTransferArgs (28 bytes).
/// Performs: disable SM, set X (write_bits), set Y (read_bits),
/// SET PINDIRS=1, JMP origin, arm DMA, enable SM, wait completion.
/// Returns total bytes transferred or negative errno.
pub const CMD_TRANSFER: u32 = 0x0C7D;

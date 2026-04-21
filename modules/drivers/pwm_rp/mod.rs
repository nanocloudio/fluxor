//! PWM Provider PIC Module
//!
//! Registers as the HAL_PWM provider (contract id 0x0F). Other modules
//! call `PWM::OPEN/SET_DUTY/CONFIGURE/CLOSE` through `provider_call` on
//! a HAL_PWM handle; the kernel routes to this module's dispatch function.
//!
//! Uses the kernel's raw PWM register bridge (PWM_SLICE_WRITE/READ (platform_raw))
//! and GPIO provider for pin management. All slot tracking and pin-to-slice
//! mapping lives here, not in the kernel.
//!
//! This mirrors the CYW43 pattern: kernel provides raw hardware access,
//! module implements the domain logic.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const MAX_SLOTS: usize = 8;
const NUM_SLICES: usize = 12;
const DEFAULT_TOP: u16 = 0xFFFE;

// PWM opcodes (dev_pwm)
const PWM_OPEN: u32 = 0x0F00;
const PWM_CLOSE: u32 = 0x0F01;
const PWM_CONFIGURE: u32 = 0x0F02;
const PWM_SET_DUTY: u32 = 0x0F03;
const PWM_GET_DUTY: u32 = 0x0F04;

// GPIO opcodes
const GPIO_CLAIM: u32 = 0x0100;
const GPIO_RELEASE: u32 = 0x0104;

// System raw PWM bridge opcodes
const SYS_PWM_PIN_ENABLE: u32 = 0x0C60;
const SYS_PWM_PIN_DISABLE: u32 = 0x0C61;
const SYS_PWM_SLICE_WRITE: u32 = 0x0C62;

// PWM slice register indices
const REG_CSR: u8 = 0;
const REG_DIV: u8 = 1;
const REG_CTR: u8 = 2;
const REG_CC: u8 = 3;
const REG_TOP: u8 = 4;

// Contract id (HAL_PWM).
const HAL_PWM_CONTRACT: u32 = 0x000F;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct PwmSlot {
    in_use: bool,
    pin: u8,
    slice: u8,
    channel_b: bool, // false=A (even pin), true=B (odd pin)
    top: u16,
    duty: u16,
}

#[repr(C)]
struct PwmState {
    syscalls: *const SyscallTable,
    signaled_ready: bool,
    _pad: [u8; 3],
    slots: [PwmSlot; MAX_SLOTS],
    slice_used: [bool; NUM_SLICES],
}

// ============================================================================
// Raw PWM register helpers
// ============================================================================

unsafe fn raw_slice_write(sys: &SyscallTable, slice: u8, reg: u8, value: u32) -> i32 {
    let vb = value.to_le_bytes();
    let mut buf = [slice, reg, vb[0], vb[1], vb[2], vb[3]];
    (sys.provider_call)(-1, SYS_PWM_SLICE_WRITE, buf.as_mut_ptr(), 6)
}

unsafe fn raw_pin_enable(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.provider_call)(-1, SYS_PWM_PIN_ENABLE, arg.as_mut_ptr(), 1)
}

unsafe fn raw_pin_disable(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.provider_call)(-1, SYS_PWM_PIN_DISABLE, arg.as_mut_ptr(), 1)
}

unsafe fn gpio_claim(sys: &SyscallTable, pin: u8) -> i32 {
    // GPIO claim returns a handle; route through provider_open so
    // the kernel binds it to the HAL_GPIO contract.
    const HAL_GPIO_CONTRACT: u32 = 0x0001;
    let arg = [pin];
    (sys.provider_open)(HAL_GPIO_CONTRACT, GPIO_CLAIM, arg.as_ptr(), 1)
}

unsafe fn gpio_release(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.provider_call)(handle, GPIO_RELEASE, core::ptr::null_mut(), 0)
}

// ============================================================================
// Slot management (pointer arithmetic — no array indexing)
// ============================================================================

unsafe fn find_free_slot(s: &PwmState) -> i32 {
    let base = s.slots.as_ptr();
    let mut i = 0usize;
    while i < MAX_SLOTS {
        let slot = &*base.add(i);
        if !slot.in_use {
            return i as i32;
        }
        i += 1;
    }
    -1
}

unsafe fn get_slot(s: &PwmState, handle: i32) -> *const PwmSlot {
    if handle < 0 || (handle as usize) >= MAX_SLOTS {
        return core::ptr::null();
    }
    let slot = &*s.slots.as_ptr().add(handle as usize);
    if !slot.in_use {
        return core::ptr::null();
    }
    slot as *const PwmSlot
}

unsafe fn get_slot_mut(s: &mut PwmState, handle: i32) -> *mut PwmSlot {
    if handle < 0 || (handle as usize) >= MAX_SLOTS {
        return core::ptr::null_mut();
    }
    let slot = &mut *s.slots.as_mut_ptr().add(handle as usize);
    if !slot.in_use {
        return core::ptr::null_mut();
    }
    slot as *mut PwmSlot
}

// ============================================================================
// Provider dispatch — called by the kernel when a consumer does
// provider_call on a HAL_PWM handle.
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
#[link_section = ".text.pwm_provider_dispatch"]
pub unsafe extern "C" fn pwm_provider_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() {
        return -22; // EINVAL
    }
    let s = &mut *(state as *mut PwmState);
    if s.syscalls.is_null() {
        return -22;
    }
    let sys = &*s.syscalls;

    match opcode {
        PWM_OPEN => {
            if arg.is_null() || arg_len < 1 {
                return -22;
            }
            let pin = *arg;
            if pin > 29 {
                return -22;
            }

            // Pin to slice mapping: slice = pin / 2 (use shift, no division)
            let slice = pin >> 1;
            if (slice as usize) >= NUM_SLICES {
                return -22;
            }

            // Check slice conflict (pointer arithmetic)
            let slice_ptr = s.slice_used.as_ptr().add(slice as usize);
            if *slice_ptr {
                return -16; // EBUSY
            }

            // Find free slot
            let idx = find_free_slot(s);
            if idx < 0 {
                return -12; // ENOMEM
            }

            // Claim GPIO pin
            let gpio_result = gpio_claim(sys, pin);
            if gpio_result < 0 {
                return gpio_result;
            }

            // Set pin to PWM function
            raw_pin_enable(sys, pin);

            // Mark slice used (pointer arithmetic)
            let slice_mut = s.slice_used.as_mut_ptr().add(slice as usize);
            *slice_mut = true;

            // Initialize slot (pointer arithmetic)
            let slot = &mut *s.slots.as_mut_ptr().add(idx as usize);
            slot.in_use = true;
            slot.pin = pin;
            slot.slice = slice;
            slot.channel_b = (pin & 1) != 0;
            slot.top = DEFAULT_TOP;
            slot.duty = 0;

            // Reset counter
            raw_slice_write(sys, slice, REG_CTR, 0);

            // Set default divider (1.0 = no division)
            raw_slice_write(sys, slice, REG_DIV, 1 << 4);

            // Set TOP
            raw_slice_write(sys, slice, REG_TOP, DEFAULT_TOP as u32);

            // Zero duty for this channel
            if slot.channel_b {
                // CC register: bits [31:16] = B, [15:0] = A
                // Read-modify-write: keep A, set B to 0
                raw_slice_write(sys, slice, REG_CC, 0);
            } else {
                raw_slice_write(sys, slice, REG_CC, 0);
            }

            // Enable slice: CSR bit 0 = EN
            raw_slice_write(sys, slice, REG_CSR, 1);

            idx
        }

        PWM_CLOSE => {
            let slot_ptr = get_slot_mut(s, handle);
            if slot_ptr.is_null() {
                return -22;
            }
            let slot = &mut *slot_ptr;
            let slice = slot.slice;
            let pin = slot.pin;

            // Zero duty
            raw_slice_write(sys, slice, REG_CC, 0);

            // Disable slice
            raw_slice_write(sys, slice, REG_CSR, 0);

            // Reset pin funcsel
            raw_pin_disable(sys, pin);

            // Release GPIO
            gpio_release(sys, pin as i32);

            // Free slice
            let slice_mut = s.slice_used.as_mut_ptr().add(slice as usize);
            *slice_mut = false;

            // Free slot
            slot.in_use = false;

            0
        }

        PWM_CONFIGURE => {
            let slot_ptr = get_slot_mut(s, handle);
            if slot_ptr.is_null() {
                return -22;
            }
            if arg.is_null() || arg_len < 4 {
                return -22;
            }
            let slot = &mut *slot_ptr;
            let top = u16::from_le_bytes([*arg, *arg.add(1)]);
            let div_int = *arg.add(2);
            let div_frac = *arg.add(3);

            if div_int == 0 {
                return -22;
            }

            slot.top = top;

            // Clamp existing duty
            if slot.duty > top {
                slot.duty = top;
                // Update CC
                let cc_val = if slot.channel_b {
                    (slot.duty as u32) << 16
                } else {
                    slot.duty as u32
                };
                raw_slice_write(sys, slot.slice, REG_CC, cc_val);
            }

            // Set divider: [int:8 << 4 | frac:4]
            let div_val = ((div_int as u32) << 4) | ((div_frac as u32) & 0x0F);
            raw_slice_write(sys, slot.slice, REG_DIV, div_val);

            // Set TOP
            raw_slice_write(sys, slot.slice, REG_TOP, top as u32);

            0
        }

        PWM_SET_DUTY => {
            let slot_ptr = get_slot_mut(s, handle);
            if slot_ptr.is_null() {
                return -22;
            }
            if arg.is_null() || arg_len < 2 {
                return -22;
            }
            let slot = &mut *slot_ptr;
            let mut duty = u16::from_le_bytes([*arg, *arg.add(1)]);

            // Clamp to top
            if duty > slot.top {
                duty = slot.top;
            }
            slot.duty = duty;

            // Write CC register for correct channel
            let cc_val = if slot.channel_b {
                (duty as u32) << 16
            } else {
                duty as u32
            };
            raw_slice_write(sys, slot.slice, REG_CC, cc_val);

            0
        }

        PWM_GET_DUTY => {
            let slot_ptr = get_slot(s, handle);
            if slot_ptr.is_null() {
                return -22;
            }
            (*slot_ptr).duty as i32
        }

        _ => -38, // ENOSYS
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<PwmState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<PwmState>() {
            return -2;
        }

        let s = &mut *(state as *mut PwmState);
        s.syscalls = syscalls as *const SyscallTable;
        s.signaled_ready = false;

        // Slots and slice_used are zero-initialized by kernel's alloc_state()
        // (in_use=false, slice_used=false for all entries)

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut PwmState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Signal ready (once). Provider registration is handled by the
        // loader via `module_provides_contract` — no runtime syscall.
        if !s.signaled_ready {
            s.signaled_ready = true;
            return 3; // StepOutcome::Ready
        }

        0 // Continue
    }
}

#[no_mangle]
#[link_section = ".text.module_provides_contract"]
pub extern "C" fn module_provides_contract() -> u32 {
    HAL_PWM_CONTRACT
}

// ============================================================================
// Deferred ready — gates downstream until first step signals Ready
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> i32 {
    1
}

// ============================================================================
// Panic Handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/* Generic linker script for stateless PIC modules (all architectures) */
/* Code runs from flash (XIP on RP) or embedded blob (aarch64). */
/* State is passed via pointer from kernel — no RAM section needed. */
ENTRY(module_init)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
}

SECTIONS
{
    .text : {
        _code_start = .;
        KEEP(*(.text.module_state_size*))
        KEEP(*(.text.module_init*))
        KEEP(*(.text.module_new*))
        KEEP(*(.text.module_step*))
        KEEP(*(.text.module_channel_hints*))
        KEEP(*(.text.module_in_place_safe*))
        KEEP(*(.text.module_mailbox_safe*))
        KEEP(*(.text.module_deferred_ready*))
        KEEP(*(.text.module_drain*))
        KEEP(*(.text.module_arena_size*))
        KEEP(*(.text.module_isr_init*))
        KEEP(*(.text.module_isr_entry*))
        *(.text*)
        . = ALIGN(8);
    } > FLASH

    .rodata : {
        *(.rodata*)
        . = ALIGN(8);
        _code_end = .;
    } > FLASH

    .data : {
        *(.data*)
        . = ALIGN(8);
    } > FLASH

    .param_schema : {
        KEEP(*(.param_schema*))
        . = ALIGN(8);
    } > FLASH

    /DISCARD/ : {
        *(.bss*)
        *(COMMON)
        *(.ARM.exidx*)
        *(.ARM.extab*)
        *(.ARM.attributes)
        *(.eh_frame*)
        *(.comment)
        *(.note*)
        *(.debug*)
    }
}

PROVIDE(_code_size = _code_end - _code_start);
PROVIDE(_data_size = 0);
PROVIDE(_bss_size = 0);

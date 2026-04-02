/* Generic linker script for stateless PIC modules */
/* Code runs from flash (XIP), state is passed via pointer from kernel */
ENTRY(module_init)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 64K
    /* No RAM section - modules are stateless, state passed via pointer */
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
        *(.text*)
        . = ALIGN(4);
    } > FLASH

    .rodata : {
        *(.rodata*)
        . = ALIGN(4);
        _code_end = .;
    } > FLASH

    /* .data in FLASH (read-only constants) - separate section for packer compatibility */
    .data : {
        *(.data*)
        . = ALIGN(4);
    } > FLASH

    /* Parameter schema — embedded metadata for config tool.
       Must be AFTER .data so it doesn't create a VMA gap between
       .text/.rodata and .data (the packer strips .param_schema from
       the code+data layout). */
    .param_schema : {
        KEEP(*(.param_schema*))
        . = ALIGN(4);
    } > FLASH

    /* Discard .bss - modules must not use static mut variables */
    /DISCARD/ : {
        *(.bss*)
        *(COMMON)
        *(.ARM.exidx*)
        *(.ARM.extab*)
        *(.comment)
        *(.note*)
        *(.debug*)
        *(.ARM.attributes)
    }
}

PROVIDE(_code_size = _code_end - _code_start);
/* No data or bss in stateless modules */
PROVIDE(_data_size = 0);
PROVIDE(_bss_size = 0);

/* Linker script for CYW43 driver module.
 *
 * Extended FLASH region to accommodate ~230KB firmware blob in .rodata.
 * Code runs from flash (XIP), firmware blob is read directly from flash.
 */
ENTRY(module_init)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 320K
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

    .data : {
        *(.data*)
        . = ALIGN(4);
    } > FLASH

    .param_schema : {
        KEEP(*(.param_schema*))
        . = ALIGN(4);
    } > FLASH

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
PROVIDE(_data_size = 0);
PROVIDE(_bss_size = 0);

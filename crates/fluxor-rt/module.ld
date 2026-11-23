/* Generic linker script for stateless PIC modules (all architectures) */
/* Code runs from flash (XIP on RP) or embedded blob (aarch64). */
/* State is passed via pointer from kernel — no RAM section needed. */
ENTRY(module_init)

MEMORY
{
    /* The one region a module image links into: its code, its constant
     * data and its parameter schema, on every module ABI. The name is the
     * linker's; on aarch64 the image runs from RAM, on RP in place from
     * flash. 512 KiB is a ceiling on one module, not a budget of any
     * target's memory: the largest module (a codec with its tables) is
     * about half of it. Data larger than that is a program of the
     * instance, carried in the node image and read in place, not part of
     * the module. The loader's own ceiling on a module's code is
     * `MAX_MODULE_CODE_SIZE` (src/kernel/config.rs). */
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 512K
}

SECTIONS
{
    .text : {
        _code_start = .;
        /* The entry points (the registry's `entry_point` list, held equal
         * by `tools/tests/module_ld_keeps_the_entry_points.rs`): the kernel
         * finds them by export hash, so nothing in the module references
         * them and --gc-sections would discard them unless kept here. */
        KEEP(*(.text.module_init*))
        KEEP(*(.text.module_new*))
        KEEP(*(.text.module_step*))
        KEEP(*(.text.module_pipeline_refill*))
        KEEP(*(.text.module_post_tick_flush*))
        KEEP(*(.text.module_drain*))
        KEEP(*(.text.module_isr_entry*))
        KEEP(*(.text.module_provider_dispatch*))
        KEEP(*(.text.module_provider_selector*))
        *(.text*)
        . = ALIGN(8);
    } > FLASH

    .rodata : {
        *(.rodata*)
        /* LLVM emits switch-table dispatch tables to `.data.rel.ro` when
         * a `match` over a small enum of references is large enough to
         * be jump-tableable. They are conceptually rodata, not .data, so
         * funnel them here (the .data output section is `_data_size = 0`
         * and would otherwise be discarded at load, and a dispatch table
         * in a discarded section faults on its first call). The loader
         * applies no relocations, so a table that holds addresses is
         * only correct if the code never reads them as addresses; module
         * sources compute such references in code instead (see
         * docs/architecture/module_architecture.md, "Position-independent
         * data"). */
        *(.data.rel.ro*)
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

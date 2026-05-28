/* Generic linker script for stateless PIC modules (all architectures) */
/* Code runs from flash (XIP on RP) or embedded blob (aarch64). */
/* State is passed via pointer from kernel — no RAM section needed. */
ENTRY(module_init)

MEMORY
{
    /* Per-module size cap. Not a real flash budget on any target —
     * bcm2712 mmaps modules from RAM, rp2040/rp2350 XIP-image hosts
     * multi-MB flash. The cap exists purely as a "modules should be
     * small" guideline. Raised from 256K to 512K because mp3_codec
     * already sits at ~254K in normal mode (99% full) and overflows
     * with `MP3_PROBE=1` debug-probe rodata. 512K leaves comfortable
     * headroom for the largest current module + probe builds + a
     * future codec or two without re-litigating this number. */
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 512K
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
        KEEP(*(.text.module_provider_dispatch*))
        KEEP(*(.text.module_provides_contract*))
        KEEP(*(.text.module_flash_store_dispatch*))
        KEEP(*(.text.module_isr_init*))
        KEEP(*(.text.module_isr_entry*))
        KEEP(*(.text.backing_provider_dispatch*))
        *(.text*)
        . = ALIGN(8);
    } > FLASH

    .rodata : {
        *(.rodata*)
        /* LLVM emits switch-table dispatch tables to `.data.rel.ro` when
         * a `match` over a small enum of references is large enough to
         * be jump-tableable. These tables hold pointers into .rodata
         * that the kernel module loader must relocate at load time —
         * they're conceptually rodata, not .data, so funnel them here
         * (the .data output section is `_data_size = 0` and would
         * otherwise be discarded at load). Without this the dispatch
         * tables land in a discarded section and the first call
         * SIGSEGVs (seen in aac_codec's huffman_2step_pair/quad). */
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

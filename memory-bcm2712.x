/* BCM2712 / aarch64 bare-metal linker script
 *
 * RAM origin is board-dependent:
 *   QEMU virt: 0x4008_0000 (default -kernel load address)
 *   Pi 5 / CM5: 0x8_0000 (GPU firmware loads kernel8.img here)
 *
 * Origin is set by build.rs via: -DRAM_ORIGIN=0x... (cargo:rustc-link-arg)
 * Default: QEMU virt address if not overridden.
 */

ENTRY(_start)
EXTERN(_start)

MEMORY {
    RAM : ORIGIN = RAM_ORIGIN, LENGTH = 128M
}

SECTIONS {
    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    } > RAM

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    } > RAM

    .data : ALIGN(8) {
        *(.data .data.*)
    } > RAM

    .bss (NOLOAD) : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    .uninit (NOLOAD) : ALIGN(8) {
        *(.uninit .uninit.*)
    } > RAM

    /* Stack at end of used RAM */
    . = ALIGN(16);
    __stack_start = .;
    . = . + 64K;
    __stack_end = .;

    /DISCARD/ : {
        *(.ARM.exidx .ARM.exidx.*)
        *(.eh_frame)
    }
}

/* Stubs for RP-specific linker symbols referenced by config.rs */
__end_block_addr = 0;
__start_block_addr = 0;

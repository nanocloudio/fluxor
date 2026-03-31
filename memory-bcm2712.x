/* BCM2712 / QEMU virt — aarch64 bare-metal linker script
 *
 * QEMU virt loads the kernel image at 0x4008_0000 (default -kernel load address).
 * We place .text there and put the stack + heap above it.
 *
 * For real BCM2712 (Pi 5 / CM5), the arm stub loads kernel8.img at 0x80000.
 * Switch RAM origin to 0x80000 for real hardware.
 */

ENTRY(_start)
EXTERN(_start)

MEMORY {
    /* QEMU virt: -kernel loads at this address */
    RAM : ORIGIN = 0x40080000, LENGTH = 128M
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

    .bss (NOLOAD) : ALIGN(8) {
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

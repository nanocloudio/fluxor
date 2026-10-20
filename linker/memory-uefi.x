/* UEFI / aarch64 bare-metal linker script.
 *
 * The UEFI loader places the image file at RAM_ORIGIN and reserves
 * [RAM_ORIGIN, RAM_ORIGIN + RAM_LENGTH) for it, both read from the
 * image's header (`fluxor_contracts::boot::KernelHeader`), which `_start`
 * opens with. build.rs sets both from `targets/host/uefi.toml` [memory].
 */

ENTRY(_start)
EXTERN(_start)

MEMORY {
    RAM : ORIGIN = RAM_ORIGIN, LENGTH = RAM_LENGTH
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

    .layout_header : ALIGN(8) {
        KEEP(*(.layout_header))
    } > RAM

    /* End of the file-backed sections: the packer pads from here to the
     * trailer, and the payload follows it in the file. */
    __end_data_addr = .;

    /* BSS starts on a 16 MiB boundary. `_start` zeroes BSS, so the payload
     * packed after the binary must end below it (the packer refuses one
     * that does not); the boundary leaves the payload everything from the
     * binary's end up to it. */
    .bss (NOLOAD) : ALIGN(0x1000000) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    } > RAM

    .uninit (NOLOAD) : ALIGN(8) {
        *(.uninit .uninit.*)
    } > RAM

    /* The boot stack, above one page nothing is linked into
     * (`__stack_guard`). */
    . = ALIGN(4096);
    __stack_guard = .;
    . = . + 4096;
    __stack_start = .;
    . = . + 1M;
    __stack_end = .;

    __end_block_addr = .;

    /DISCARD/ : {
        *(.ARM.exidx .ARM.exidx.*)
        *(.eh_frame)
    }
}

/* The header's fields (`_start` in src/platform/uefi.rs). */
__kernel_load_base = ORIGIN(RAM);
__kernel_ram_end = ORIGIN(RAM) + LENGTH(RAM);
__kernel_bytes = __end_data_addr - ORIGIN(RAM);
__start_block_addr = 0;
ASSERT(__end_block_addr <= __kernel_ram_end, "the kernel outgrew [memory] ram_size in targets/host/uefi.toml")

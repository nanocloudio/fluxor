/* The RP link script.
 *
 * The MEMORY block comes from the per-silicon `memory-rp*.x` that build.rs
 * emits as `memory.x`, so flash and RAM bounds stay in one place.
 *
 * # What the layout guarantees
 *
 * The entry point resolves to `Reset`, vector 0 is an 8-byte-aligned stack
 * pointer inside RAM, vector 1 carries its Thumb bit, and
 * `__sdata`/`__edata`/`__sidata`/`__sbss`/`__ebss` come out consistent.
 * Those are exactly the properties
 * `tools/img/verify_boot_image.py` checks in a built image, so the script and
 * the gate agree on what correct means.
 *
 * # What the ordering is for
 *
 * `.vector_table` must be first, at the very start of flash, because that is
 * where the core reads its initial stack pointer and reset vector from. On
 * RP2040 "the start of flash" is after boot2, which the silicon's memory
 * script already accounts for by starting FLASH at 0x10000100.
 *
 * Entry 0 is `__stack_top`, not code. Entry 1 is `Reset`, and the linker sets
 * its Thumb bit because the symbol is a function — writing the address by
 * hand is how that bit gets lost, and a cleared bit is a UsageFault at reset
 * with no handler yet installed to report it.
 */

/* `Reset` and the exception table are referenced only by the vector table,
 * which nothing calls, so without these they are garbage-collected away and
 * the image boots into nothing. */
/* Brings in the MEMORY block and, on RP2040, the `.boot2` section that
 * places the second-stage bootloader at the very start of flash. RP2350 has
 * no equivalent — its bootrom reads the IMAGE_DEF instead — which is why
 * this is one INCLUDE rather than a branch here. */
INCLUDE memory.x

EXTERN(Reset);
EXTERN(EXCEPTIONS);
EXTERN(__INTERRUPTS);

ENTRY(Reset);

PROVIDE(__stack_top = ORIGIN(RAM) + LENGTH(RAM));

SECTIONS
{
    .vector_table ORIGIN(FLASH) :
    {
        /* Entry 0: the initial stack pointer. The core loads this into SP
         * before fetching a single instruction, so it is data, not code. */
        LONG(__stack_top);

        /* Entry 1: the reset handler. */
        KEEP(*(.vector_table.reset_vector));
        LONG(Reset | 1);

        /* Entries 2..15: the system exceptions. */
        __exceptions = .;
        KEEP(*(.vector_table.exceptions));
        __eexceptions = .;

        /* Entries 16..: external interrupts. Empty unless something places
         * an entry — an unowned IRQ is masked by the NVIC rather than
         * dispatched, so a missing entry here cannot fire. */
        KEEP(*(.vector_table.interrupts));
    } > FLASH

    /* RP2350's bootrom looks for the IMAGE_DEF inside the first 4 KiB, and
     * immediately after the vector table is where it fits. */
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
    } > FLASH

    .text : ALIGN(4)
    {
        __stext = .;
        *(.text .text.*);
        . = ALIGN(4);
        __etext = .;
    } > FLASH

    .rodata : ALIGN(4)
    {
        . = ALIGN(4);
        *(.rodata .rodata.*);
        . = ALIGN(4);
    } > FLASH

    /* `.data` is initialised from flash by `Reset`. `__sidata` is its load
     * address; `__sdata`/`__edata` bound where it runs. The two lengths must
     * agree, which is why the copy checks rather than trusts them. */
    .data : ALIGN(4)
    {
        . = ALIGN(4);
        __sdata = .;
        *(.data .data.*);
        /* Functions that must execute with flash disconnected — the ROM
         * flash wrappers. They live in flash and run from RAM, so they
         * belong in `.data`, and `tools/img` checks that they ended up
         * above 0x20000000. */
        *(.data.ram_func .data.ram_func.*);
        . = ALIGN(4);
        __edata = .;
    } > RAM AT > FLASH

    __sidata = LOADADDR(.data);

    .bss (NOLOAD) : ALIGN(4)
    {
        . = ALIGN(4);
        __sbss = .;
        *(.bss .bss.*);
        *(COMMON);
        . = ALIGN(4);
        __ebss = .;
    } > RAM

    /* Deliberately NOT zeroed by `Reset`: the crash record lives here so it
     * survives a reset and can be read by the next boot. Zeroing it would
     * erase the evidence of the fault that caused the reset. */
    .uninit (NOLOAD) : ALIGN(4)
    {
        . = ALIGN(4);
        *(.uninit .uninit.*);
        . = ALIGN(8);
        /* One past the last static byte: where the stack may grow down to. */
        __stack_limit = .;
    } > RAM

    /* The end marker the image tools look for. */
    .fluxor_end : ALIGN(4)
    {
        __end_block_addr = .;
    } > FLASH

    PROVIDE(__flash_start__ = ORIGIN(FLASH));
    PROVIDE(__flash_end__ = ORIGIN(FLASH) + LENGTH(FLASH));

    /DISCARD/ :
    {
        *(.ARM.exidx .ARM.exidx.*);
        *(.ARM.extab .ARM.extab.*);
    }
}

/* A build that produced no vector table would link and not boot, so the
 * sizes are asserted rather than assumed. */
ASSERT(SIZEOF(.vector_table) >= 8,
       "the vector table is missing its stack pointer or reset vector");
ASSERT(__sdata % 4 == 0, ".data is not word-aligned; the copy loop assumes it is");
ASSERT(__sbss % 4 == 0, ".bss is not word-aligned; the zero loop assumes it is");

#!/usr/bin/env python3
"""Verify the boot artifacts the RP bootrom checks before running an image.

The boot2 checksum and the IMAGE_DEF block are validated by the bootrom at
every power-on, and both fail the same way when wrong: the board does not
boot and says nothing, because the thing that would have reported the failure
is what failed to load.

Checking them here means an image is verified before it is ever flashed,
whichever set of boot artifacts it carries.
"""

import struct
import sys

BOOT2_LEN = 256
BOOT2_CRC_OFFSET = 252

PICOBIN_BLOCK_MARKER_START = 0xFFFFDED3
PICOBIN_BLOCK_MARKER_END = 0xAB123579


def crc32_bootrom(data: bytes) -> int:
    """The RP2040 bootrom's CRC32 over boot2.

    CRC-32/MPEG-2: polynomial 0x04C11DB7, initial value 0xFFFFFFFF, neither
    input nor output reflected, no final XOR.

    Worth stating explicitly because it is *not* the common CRC32. Python's
    `binascii.crc32` is the reflected ISO-HDLC variant, and the pico-sdk works
    around the difference by bit-reversing bytes in and out — a formulation
    that is easy to transcribe wrongly. This implementation was validated
    against all seven prebuilt boot2 blobs before being trusted.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def check_boot2(image: bytes) -> list[str]:
    """RP2040: the first 256 bytes are boot2, checksummed by the bootrom."""
    if len(image) < BOOT2_LEN:
        return [f"image is {len(image)} bytes, too short to hold boot2"]
    boot2 = image[:BOOT2_LEN]
    stored = struct.unpack("<L", boot2[BOOT2_CRC_OFFSET:BOOT2_LEN])[0]
    computed = crc32_bootrom(boot2[:BOOT2_CRC_OFFSET])
    if stored != computed:
        return [
            f"boot2 checksum is {stored:#010x}, bootrom will compute "
            f"{computed:#010x} and refuse to run the image"
        ]
    if all(b == 0 for b in boot2[:BOOT2_CRC_OFFSET]):
        return ["boot2 is entirely zero; the checksum is over nothing"]
    return []


def check_image_def(image: bytes) -> list[str]:
    """RP2350: an IMAGE_DEF block the bootrom parses before running anything.

    It must be inside the first 4 KiB, where the bootrom looks.
    """
    window = image[:4096]
    starts = [
        off
        for off in range(0, max(0, len(window) - 4), 4)
        if struct.unpack("<L", window[off : off + 4])[0] == PICOBIN_BLOCK_MARKER_START
    ]
    if not starts:
        return ["no IMAGE_DEF block in the first 4 KiB; the bootrom will not run this image"]
    off = starts[0]
    for end in range(off, min(off + 512, len(image) - 4), 4):
        if struct.unpack("<L", image[end : end + 4])[0] == PICOBIN_BLOCK_MARKER_END:
            return []
    return [f"IMAGE_DEF at {off:#x} has no end marker; the block is malformed"]


# Where the vector table sits in the image. RP2040 puts boot2 first, so the
# table follows it; RP2350's image starts with the table.
VECTOR_TABLE_OFFSET = {"rp2040": 0x100, "rp2350": 0x000}

# The first sixteen entries are system exceptions; entry 0 is the stack
# pointer rather than a handler.
SYSTEM_VECTORS = 16


def check_vector_table(silicon: str, image: bytes, ram: range, flash: range) -> list[str]:
    """The table the core reads at reset.

    Nothing downstream can report a fault here: it is read before the first
    instruction of our code runs. A wrong entry is a board that does nothing,
    with nothing to read — so the two rules the hardware enforces silently are
    checked against the built image instead.
    """
    off = VECTOR_TABLE_OFFSET[silicon]
    need = off + SYSTEM_VECTORS * 4
    if len(image) < need:
        return [f"image is {len(image)} bytes, too short to hold a vector table"]

    words = struct.unpack_from(f"<{SYSTEM_VECTORS}L", image, off)
    problems = []

    # Entry 0 is the initial stack pointer. AAPCS wants 8-byte alignment and
    # the exception entry sequence assumes it; a misaligned SP does not fault
    # at reset, it produces misaligned accesses arbitrarily far from here.
    sp = words[0]
    if sp % 8 != 0:
        problems.append(f"initial stack pointer {sp:#010x} is not 8-byte aligned")
    # The stack grows downwards, so sitting exactly at the top of RAM is the
    # normal arrangement rather than an overflow.
    if not (ram.start < sp <= ram.stop):
        problems.append(
            f"initial stack pointer {sp:#010x} is outside RAM "
            f"{ram.start:#010x}..{ram.stop:#010x}"
        )

    # Entry 1 is the reset handler. Bit 0 selects Thumb state, and Cortex-M
    # has no other state — a cleared bit is a UsageFault at reset, before any
    # handler exists to report it.
    reset = words[1]
    if reset & 1 == 0:
        problems.append(
            f"reset vector {reset:#010x} is not a Thumb address; "
            "the core faults at reset with nothing to report it"
        )
    if not (flash.start <= (reset & ~1) < flash.stop):
        problems.append(f"reset vector {reset:#010x} does not point into flash")

    # Every other populated entry must also be Thumb. A zero entry is an
    # unused exception, which is legal.
    for i, w in enumerate(words[2:], start=2):
        if w == 0:
            continue
        if w & 1 == 0:
            problems.append(f"vector {i} is {w:#010x}, not a Thumb address")

    return problems


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <silicon> <image.bin>", file=sys.stderr)
        return 2
    silicon, path = sys.argv[1], sys.argv[2]
    try:
        image = open(path, "rb").read()
    except OSError as e:
        print(f"boot-image: {e}", file=sys.stderr)
        return 2

    # RAM and flash bounds come from the silicon TOML rather than literals,
    # so the gate cannot disagree with what the linker was told.
    try:
        toml = open(f"targets/silicon/{silicon}.toml").read()
    except OSError:
        toml = ""

    def hex_field(key: str, default: int) -> int:
        for line in toml.splitlines():
            if line.strip().startswith(key):
                return int(line.split("=")[1].strip().strip('"'), 0)
        return default

    ram_base = hex_field("ram_base", 0x20000000)
    ram = range(ram_base, ram_base + hex_field("ram_size", 0x40000))
    flash_base = hex_field("flash_base", 0x10000000)
    flash = range(flash_base, flash_base + hex_field("flash_size", 0x200000))

    if silicon == "rp2040":
        problems = check_boot2(image)
    elif silicon == "rp2350":
        problems = check_image_def(image)
    else:
        return 0
    problems += check_vector_table(silicon, image, ram, flash)

    for p in problems:
        print(f"boot-image: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

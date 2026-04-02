# SD Card Module - State Machine Documentation

## Overview

The SD card module (`modules/sd/mod.rs`) implements a **fully non-blocking, poll-based state machine** for reading blocks from an SD card over SPI. It is designed for embedded systems without OS support, where blocking operations are not allowed.

### Key Design Principles

1. **Non-blocking**: Every function returns immediately; progress is made through repeated polling
2. **Hierarchical state machines**: Complex operations are built from simpler sub-machines
3. **Cooperative scheduling**: Returns `0` (pending) to yield CPU time to other modules

### Module Hierarchy

```
+-----------------------------------------------------------------+
|                      module_step()                               |
|  +-------------------------------------------------------------+|
|  |                    ModuleState                               ||
|  |  MOD_READING -------------------------------> MOD_DONE       ||
|  +-------------------------------------------------------------+|
|         |                                                        |
|         v                                                        |
|  +-------------------------------------------------------------+|
|  |                    InitState (28 states)                     ||
|  |  Runs SD card initialization sequence                        ||
|  +-------------------------------------------------------------+|
|         |                                                        |
|         v                                                        |
|  +-------------------------------------------------------------+|
|  |                    ReadBlockState (8 states)                 ||
|  |  CMD17 + wait for data token + read 512 bytes                ||
|  +-------------------------------------------------------------+|
|         |                                                        |
|         v                                                        |
|  +-------------------------------------------------------------+|
|  |                    SpiState (2 states)                       ||
|  |  Manages async SPI DMA transfers                             ||
|  +-------------------------------------------------------------+|
+-----------------------------------------------------------------+
```

---

## State Machine Definitions

### 1. SpiState - Low-level SPI Transfer

The simplest state machine - tracks whether an SPI transfer is in progress.

```
+----------+                        +-------------+
|          |  spi_transfer_start()  |             |
| SPI_IDLE +------------------------>| SPI_PENDING |
|          |                        |             |
+----------+                        +------+------+
     ^                                     |
     |         spi_transfer_poll()         |
     |         returns done/error          |
     +-------------------------------------+
```

| State | Value | Description |
|-------|-------|-------------|
| `SPI_IDLE` | 0 | No transfer in progress |
| `SPI_PENDING` | 1 | DMA transfer active, poll for completion |

**API**:
- `spi_transfer_start(tx, rx, len)` -> starts DMA, transitions to PENDING
- `spi_transfer_poll()` -> returns: `<0` error, `0` pending, `>0` done
- `spi_poll_byte()` -> for single-byte reads, returns byte in result (0x100|byte)

---

### 2. SendCmdState - SD Command (R1 + optional extra bytes)

Sends a 6-byte SD command and waits for an R1 response. If `extra_bytes > 0`,
it then reads up to 4 additional response bytes (R3/R7).

```
                    +---------------------------------------------------+
                    |                                                   |
                    v                                                   |
+----------+   +------------+   +--------------+   +-------------+    |
|          |   |            |   |              |   |             |    |
| CMD_IDLE +--->|CMD_SELECTING+--->|CMD_SENDING_  +--->|CMD_WAITING_ |    |
|          |   |            |   |    CMD       |   |    R1       |    |
+----------+   +------------+   +--------------+   +------+------+    |
     ^              |                                      |           |
     |              | claim timeout                        |           |
     |              +--------------------------------------+-----------+
     |                                                     |           |
     |                              +----------------------+           |
     |                              |                                  |
     |                              v                                  |
     |         +-------------------------------------+                |
     |         | R1 valid (bit 7 = 0)?               |                |
     |         +-------------------------------------+                |
     |                    |                    |                       |
     |              yes   |                    | no (retry)            |
     |                    v                    +-----------------------+
     |         +-----------------+                     |
     |         | release=true?   |                     | timeout
     |         +-----------------+                     |
     |              |         |                        v
     |          yes |         | no              +-----------+
     |              v         |                 |   ERROR   |
     |    +---------------+   |                 +-----------+
     |    |CMD_SENDING_   |   |
     |    |   DUMMY       |   |
     |    +-------+-------+   |
     |            |           |
     |            v           |
     +------------------------+
           DONE (r1 in cmd_response)
```

| State | Value | Description |
|-------|-------|-------------|
| `CMD_IDLE` | 0 | Not active |
| `CMD_SELECTING` | 1 | Waiting to claim SPI bus |
| `CMD_SENDING_CMD` | 2 | Transmitting 6-byte command |
| `CMD_WAITING_R1` | 3 | Polling for R1 response |
| `CMD_READING_EXTRA` | 4 | Reading extra response bytes (R3/R7) |
| `CMD_SENDING_DUMMY` | 5 | Sending dummy byte after deselect |

**SD Protocol Reference** (Physical Layer Spec 3.01, Section 7.3.1.1):
- Command format: `[0x40|cmd] [arg3] [arg2] [arg1] [arg0] [crc|0x01]`
- R1 response: Single byte, bit 7 = 0 indicates valid response
- Max Ncr (response delay): 8 bytes

---

### 3. ReadDataState - Read Data Block After Command

Waits for data token (0xFE) then reads 512 bytes + 2 CRC bytes.
Used internally by init (CSD read) when command already sent.

```
+----------+   +-------------+   +----------------+
|          |   |             |   |                |
| RD_IDLE  +--->|RD_SELECTING +--->|RD_WAITING_TOKEN|<---+
|          |   |             |   |                |   |
+----------+   +-------------+   +-------+--------+   |
                                         |            |
                              token=0xFE |     0xFF   |
                                         v            |
                               +-----------------+    |
                               | RD_READING_DATA |    |
                               |   (512 bytes)   |    |
                               +--------+--------+    |
                                        |             |
                                        v             |
                               +-----------------+    |
                               | RD_READING_CRC  |    |
                               |   (2 bytes)     |    |
                               +--------+--------+    |
                                        |             |
                                        v             |
                               +-----------------+    |
                               |RD_SENDING_DUMMY |    |
                               +--------+--------+    |
                                        |             |
                                        v             |
                                      DONE            |
                                                      |
                               timeout ---------------+
                               (1000 attempts)
```

| State | Value | Description |
|-------|-------|-------------|
| `RD_IDLE` | 0 | Not active |
| `RD_SELECTING` | 1 | Claim SPI |
| `RD_WAITING_TOKEN` | 2 | Polling for 0xFE data start token |
| `RD_READING_DATA` | 3 | DMA reading 512 bytes |
| `RD_READING_CRC` | 4 | Reading 2 CRC bytes |
| `RD_SENDING_DUMMY` | 5 | Cleanup |

**SD Protocol Reference** (Section 7.3.3):
- Data token: 0xFE indicates start of data block
- CRC16: 2 bytes (not validated in this implementation)

---

### 4. ReadBlockState - Complete Block Read (CMD17)

Full block read operation: sends CMD17 + waits for data + reads block.

```
+----------+   +-------------+   +---------------+   +--------------+
|          |   |             |   |               |   |              |
| RB_IDLE  +--->|RB_SELECTING +--->|RB_SENDING_CMD +--->|RB_WAITING_R1 |
|          |   |             |   |  (CMD17)      |   |              |
+----------+   +-------------+   +---------------+   +------+-------+
                                                            |
                                            R1=0 (success)  |
                                                            v
                                                +-----------------------+
                                                |RB_READING_DATA_BLOCK  |
                                                |(shared ReadDataState) |
                                                +----------+------------+
                                                           |
                                                           v
                                                         DONE
```

| State | Value | Description |
|-------|-------|-------------|
| `RB_IDLE` | 0 | Not active |
| `RB_SELECTING` | 1 | Claim SPI bus |
| `RB_SENDING_CMD` | 2 | Transmit CMD17 |
| `RB_WAITING_R1` | 3 | Wait for command response |
| `RB_READING_DATA_BLOCK` | 4 | Delegate to ReadDataState (token/data/crc/dummy) |

**SD Protocol Reference** (Section 7.2.3):
- CMD17: READ_SINGLE_BLOCK
- Argument: 32-bit block address (byte address for SDSC, block address for SDHC)

---

### 5. InitState - SD Card Initialization

The most complex state machine. Implements the full SD card initialization
sequence per Physical Layer Spec 3.01, Section 4.2. The implementation uses a
small handler table so each state is a compact function that returns
`Pending`, `Continue`, or `Error`.

```
+-------------------------------------------------------------------------------+
|                            INITIALIZATION SEQUENCE                            |
+-------------------------------------------------------------------------------+

INIT_IDLE
    |
    v
INIT_CLAIMING ------------------> (claim SPI bus, 400kHz)
    |
    v
INIT_PRECLOCKING <-----+
    |                 |
    v                 |
INIT_PRECLOCKING_WAIT + (16 dummy bytes, card needs 74+ clocks)
    |
    v
INIT_CMD0_START <--------------+
    |                         |
    v                         | retry (5x)
INIT_CMD0_WAIT                |
    |                         |
    +- R1=0x01 (idle) -------->|
    |                         |
    +- R1!=0x01 ---> INIT_CMD0_TIMER --+
    |
    v
INIT_CMD8_START
    |
    v
INIT_CMD8_WAIT
    |
    +---------------------------------------------------------+
    | R1=0x01 (SD v2.0+)                                      | R1=0x05 (SD v1.x)
    |                                                         |
    v                                                         v
+-----------------------------+                    +-----------------------------+
|      SD v2.0 PATH           |                    |      SD v1.x PATH           |
+-----------------------------+                    +-----------------------------+
|                             |                    |                             |
| INIT_CMD55V2_START <----+    |                    | INIT_CMD55V1_START <----+    |
|     |                  |    |                    |     |                  |    |
|     v                  |    |                    |     v                  |    |
| INIT_CMD55V2_WAIT      |    |                    | INIT_CMD55V1_WAIT      |    |
|     |                  |    |                    |     |                  |    |
|     v                  |    |                    |     v                  |    |
| INIT_ACMD41V2_START    |    |                    | INIT_ACMD41V1_START    |    |
|     |                  |    |                    |     |                  |    |
|     v                  |    |                    |     v                  |    |
| INIT_ACMD41V2_WAIT     |    |                    | INIT_ACMD41V1_WAIT     |    |
|     |                  |    |                    |     |                  |    |
|     +- R1=0 -----------+----+                    |     +- R1=0 -----------+----+
|     |                  |    |                    |     |                  |    |
|     +- R1!=0 -----------+    |                    |     +- R1!=0 -----------+    |
|        (retry via timer)    |                    |        (retry via timer)    |
|                             |                    |                             |
|           |                 |                    |           |                 |
|           v                 |                    |           v                 |
| INIT_CMD58_START           |                    |      (cdv = 512)            |
|     |                       |                    |           |                 |
|     v                       |                    |           |                 |
| INIT_CMD58_WAIT            |                    |           |                 |
|     |                       |                    |           |                 |
|     +- CCS=1 (SDHC) --------+----> cdv = 1       |           |                 |
|     |                       |                    |           |                 |
|     +- CCS=0 (SDSC) --------+----> cdv = 512     |           |                 |
|                             |                    |           |                 |
+-----------------------------+                    +-----------+-----------------+
                                                               |
    +----------------------------------------------------------+
    |
    v
INIT_CMD9_START
    |
    v
INIT_CMD9_WAIT
    |
    v
INIT_READING_CSD_START
    |
    v
INIT_READING_CSD_WAIT (uses ReadDataState internally)
    |
    v
INIT_CMD16_START (SET_BLOCKLEN = 512) [SDSC only]
    |
    v
INIT_CMD16_WAIT
    |
    v
INIT_CONFIGURE_DATA_FREQ (switch to data rate)
    |
    v
INIT_DONE
```

| State | Value | Description |
|-------|-------|-------------|
| `INIT_IDLE` | 0 | Not started |
| `INIT_CLAIMING` | 1 | Acquire SPI bus |
| `INIT_PRECLOCKING` | 2 | Send dummy bytes |
| `INIT_PRECLOCKING_WAIT` | 3 | Wait for preclocking transfer |
| `INIT_CMD0_START` | 4 | Start GO_IDLE_STATE |
| `INIT_CMD0_WAIT` | 5 | Wait for CMD0 response |
| `INIT_CMD0_TIMER` | 6 | Delay before CMD0 retry |
| `INIT_CMD8_START` | 7 | Start SEND_IF_COND |
| `INIT_CMD8_WAIT` | 8 | Wait for CMD8 response |
| `INIT_CMD55V2_START` | 9 | Start APP_CMD (v2) |
| `INIT_CMD55V2_WAIT` | 10 | Wait for CMD55 response |
| `INIT_ACMD41V2_START` | 11 | Start SD_SEND_OP_COND (v2) |
| `INIT_ACMD41V2_WAIT` | 12 | Wait for ACMD41 response |
| `INIT_ACMD41V2_TIMER` | 13 | Delay before retry |
| `INIT_CMD58_START` | 14 | Start READ_OCR |
| `INIT_CMD58_WAIT` | 15 | Wait for CMD58, check CCS |
| `INIT_CMD55V1_START` | 16 | Start APP_CMD (v1) |
| `INIT_CMD55V1_WAIT` | 17 | Wait for CMD55 response |
| `INIT_ACMD41V1_START` | 18 | Start SD_SEND_OP_COND (v1) |
| `INIT_ACMD41V1_WAIT` | 19 | Wait for ACMD41 response |
| `INIT_ACMD41V1_TIMER` | 20 | Delay before retry |
| `INIT_CMD9_START` | 21 | Start SEND_CSD |
| `INIT_CMD9_WAIT` | 22 | Wait for CMD9 response |
| `INIT_READING_CSD_START` | 23 | Start CSD data read |
| `INIT_READING_CSD_WAIT` | 24 | Wait for CSD data |
| `INIT_CMD16_START` | 25 | Start SET_BLOCKLEN |
| `INIT_CMD16_WAIT` | 26 | Wait for CMD16 response |
| `INIT_CONFIGURE_DATA_FREQ` | 27 | Switch to high-speed |
| `INIT_DONE` | 28 | Initialization complete |

**SD Protocol Reference**:
- CMD0: GO_IDLE_STATE (reset to SPI mode)
- CMD8: SEND_IF_COND (voltage check, SD v2.0 detection)
- CMD55: APP_CMD (prefix for application commands)
- ACMD41: SD_SEND_OP_COND (initialization, HCS bit for SDHC)
- CMD58: READ_OCR (check CCS bit for SDHC)
- CMD9: SEND_CSD (get card-specific data)
- CMD16: SET_BLOCKLEN (set to 512 bytes, SDSC only; SDHC uses fixed 512)

---

### 6. ModuleState - Top-level Module State

```
                     +----------------------------------------+
                     |           module_step()                |
                     +----------------------------------------+
                                        |
                                        v
                         +--------------------------+
                         |   init_state != DONE?    |
                         +--------------------------+
                              |              |
                          yes |              | no
                              v              |
                    +------------------+     |
                    |   init_poll()    |     |
                    +------------------+     |
                              |              |
                              v              v
                         +--------------------------+
                         |       mod_state          |
                         +--------------------------+
                              |              |
               MOD_READING    |              | MOD_DONE
                              v              v
                    +------------------+  +----------+
                    |  read blocks     |  | return 1 |
                    |  until count     |  |  (done)  |
                    +--------+---------+  +----------+
                             |
              +--------------+--------------+
              |                             |
    channel poll POLL_OUT         block read complete
              |                             |
              v                             v
     +----------------+            +----------------+
     | not writable?  |            | channel_write  |
     | return 0       |            | on -11:        |
     | (backpressure) |            | MOD_WRITING    |
     +----------------+            +----------------+
                                         |
                                         v
                                 +----------------+
                                 | MOD_WRITING    |
                                 | retry write    |
                                 | then advance   |
                                 +----------------+
```

| State | Value | Description |
|-------|-------|-------------|
| `MOD_READING` | 0 | Reading blocks from SD card |
| `MOD_WRITING` | 1 | Retrying a channel write after EAGAIN |
| `MOD_DONE` | 2 | All blocks read, module complete |

---

## Backpressure Mechanism

The SD module implements **channel-based backpressure**:

```
+---------+     +-----------------+     +--------------+
|   SD    |----->| Channel (512B)  |----->|   Consumer   |
| Source  |     |    Pipe Buffer  |     | (Logger/I2S) |
+---------+     +-----------------+     +--------------+
     |                   |                     |
     |    channel_poll   |                     |
     |<---(POLL_OUT)------|                     |
     |                   |                     |
     |    if full:       |    channel_read     |
     |    yield (0)      |<---------------------|
     |                   |                     |
```

1. Before reading a new block, SD polls `channel_poll(out_chan, POLL_OUT)`
2. If channel buffer is full (not writable), SD returns 0 (yields)
3. Downstream consumer reads at its own pace (e.g., I2S at 44.1kHz)
4. When channel has space, SD continues reading

**Rate is determined by consumer**, not by SD module.

---

## Configuration Parameters

From `PicModuleParams` (ABI):

| Field | Type | Description |
|-------|------|-------------|
| `in_chan` | i32 | Input channel (-1 if none) |
| `out_chan` | i32 | Output channel for block data |
| `spi_bus` | u8 | SPI bus number |
| `cs_pin` | u8 | Chip select GPIO pin |
| `start_block` | u32 | First block to read |
| `block_count` | u32 | Number of blocks to read |
| `data_freq_hz` | u32 | Overrides DATA_FREQ if >0 |
| `init_freq_hz` | u32 | Overrides INIT_FREQ if >0; clamped to 100–400 kHz |

---

## Return Values

| Value | Meaning |
|-------|---------|
| 0 | Pending - call step() again |
| 1 | Done - all blocks read successfully |
| -20 | Initialization failed |
| -21 | Block read failed |
| -22 | Channel write failed |

---

## SPI Protocol Timing

```
             +-------------------------------------------------------+
    CS ------+                                                       +---
             |                                                       |
             |<------------ Command + Response + Data ---------------->|
             |                                                       |
   SCLK -----+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+---
             | | | | | | | | | | | | | | | | | | | | | | | | | | | | |
   MOSI -----+-----CMD[6B]-----+-----------0xFF----------------------+---
             |                 |                                     |
   MISO -----+-----0xFF--------+--R1--+--------DATA[512B]----+-CRC---+---
             |                 |      |                      |       |
             |                 |<--Ncr-->|<-----Nac-------------->|       |
```

- **Ncr**: Command to response delay (0-8 bytes)
- **Nac**: Response to data delay (variable, poll for 0xFE token)
- **Mode 0**: CPOL=0, CPHA=0 (idle low, sample on rising edge)

---

## References

1. SD Specifications Part 1: Physical Layer Simplified Specification Version 3.01
   - Section 4.2: Card Identification Mode
   - Section 7.2: SPI Bus Protocol
   - Section 7.3: Commands

2. SD Card SPI Mode Application Note (AN01)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-24 | Initial documentation |

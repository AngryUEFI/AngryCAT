# AngryCAT

* Catastrophic Automation Tool
* Command & Annihilation Toolkit
* Catastrophic Action Trigger
* microCode Adjustment Tool

Python tool to drive testing with AngryUEFI

# Dependencies
Uses uv as package manager, e.g. `pacman -S uv`.

# Running
`uv run path/to/script.py --arguments --for --script.py`
* Not all files need extra packages, you might get away with plain python.
* *Note* The experiments might not write fully valid json, check the end of the file and remove partial entries and add a closing `]` if needed.

# Protocol

AngryUEFI listens on a TCP port, default 3239, and receives commands from this script. This script sends a single command at a time. AngryUEFI sends back at least one message in response. AngryUEFI will never send data outside of this request/response flow. A request must be a maximum of 8204 = 8192+12 Bytes. Response messages are up to 1052 = 1024 + 32 + 12 Bytes. Text transmitted is UCS-2  unless otherwise noted due to UEFI using this encoding. For most text using python encoding `utf_16_be` should work.

## Packets
A packet is a single request to AngryUEFI or a single response from AngryUEFI. 

### Header
The header is 12 Bytes. Unless otherwise noted integers are unsigned little-endian.

* 4 Byte Message Length, including Header minus Message Length
* 4 Byte Metadata
* 4 Byte Message Type

#### Message Length
32 bit unsigned little-endian integer. Length does not include this field, but all other header fields and the actual payload. The maximum valid length value is thus 8192 Bytes Payload + 4 Bytes Message Type + 4 Bytes Metadata = 8200 Bytes.

#### Metadata
* 1 Byte Major Version = 1
* 1 Byte Minor Version = 0
* 1 Byte Control
* 1 Byte Reserved

The control Byte encodes the following bitfields. Bit 7 denotes the MSB, Bit 0 the LSB
* Bit 0 - Multi message: 0 = End of Transmission, 1 = Another message follows
* Bits 1-7 - Reserved

#### Message Type
32 bit unsigned little-endian integer. Not necessarily continuous. See section Messages for detailed list.
By convention requests have MSB not set, responses have MSB set.

### Payload
Maximum 8192 Bytes. Actual length denoted by Message Length field - 8. Contents depend on the Message Type.

# Requests
These messages are sent from AngryCAT to AngryUEFI.

## PING
* ID: 0x1
* Expects a PONG response with the same message from AngryUEFI

### Structure
* 4 Byte unsigned LE message length
* Length Bytes message

## MULTIPING
* ID: 0x2
* Expects multiple PONG responses with the same message from AngryUEFI

### Structure
* 4 Byte unsigned LE PONG count - how many PONG responses are requested
* 4 Byte unsigned LE message length
* Length Bytes message

## GETMSGSIZE
* ID: 0x3
* Expects the size of the send message as a MSGSIZE response
* AngryUEFI should verify the received message matches the size indicated in the Message Length header

### Structure
* 4 Byte unsigned LE message length
* Length Bytes message

## REBOOT
* ID: 0x21
* Reboots the system
* Optionally perform a "warm reboot"
    * UEFI spec offers both warm and cold reboots
    * difference is not fully documented and likely hardware specific
* Returns a STATUS response before rebooting

### Structure
* 4 Byte unsigned LE options
    * 3 Byte unused
    * 1 Byte flags, Bit 0: LSB
        * Bit 0 - perform a warm reboot instead of a cold reboot

## SENDUCODE
* ID: 0x101
* Places a ucode update in the specified slot
* AngryUEFI currently has 10 slots in total
    * Known good ucode - slot 0
    * Currently testing ucode - slot 1
    * Base ucodes - slots 2-9
* returns a STATUS response

### Structure
* 4 Byte unsigned LE target slot
* 4 Byte unsigned LE ucode size
* ucode update bytes

## FLIPBITS
* ID 0x121
* Flips the specified bits in the source ucode slot
* Result is placed in slot 1
* bit positions are indexed as follows:
    * index/8 -> target byte
    * index % 8 -> target bit
    * the LSB is 0, the MSB is 7
* Responds with STATUS

### Structure
* 4 Byte unsigned LE source slot
    * can use slot 1 to flip bits in an already processed update
* 4 Byte unsinged LE number of bit flips
* array of 4 Byte unsigned LE of bit positions to flip
    * uses 4 byte to support big updates in future revisions
    * enough space for more than 2000 flips

## APPLYUCODE
* ID 0x141
* Applies the ucode in the specified slot
* Microcode is applied with interrupts disabled
* Responds with a UCODERESPONSE
* Optionally applies the known good update afterwards
    * this is done directly in the assembly stub to limit executed instructions

### Structure
* 4 Byte unsigned LE target slot
* 4 Byte unsigned LE options
    * 3 Byte unused
    * 1 Byte flags, Bit 0: LSB
        * Bit 0 - apply known good update after the test update

## APPLYUCODEEXCUTETEST
* ID 0x151
* Applies the ucode in the specified slot
* Microcode is applied with interrupts disabled
* Runs the machine code in specified slot
* Executes on given core number
* TODO: timeout is broken, must set to 0 for now (AngryUEFI is missing a timer implementation)
* TODO: core != 0 required further testing, only basic testing has been performed
* Responds with a UCODEEXECUTETESTRESPONSE
* Optionally applies the known good update afterwards
    * this is done directly in the assembly stub to limit executed instructions

### Structure
* 4 Byte unsigned LE target ucode slot
* 4 Byte unsigned LE target machine code slot
* 4 Byte unsigned LE target core number
* 4 Byte unsigned LE timeout in ms for execution, 0 for unlimited
* 4 Byte unsigned LE options
    * 3 Byte unused
    * 1 Byte flags, Bit 0: LSB
        * Bit 0 - apply known good update after the test update

## READMSR
* ID 0x201
* Reads the specified MSR
* Responds with a MSRRESPONSE

### Structure
* 4 Byte unsigned LE target MSR

## GETCORECOUNT
* ID 0x211
* Returns the core count of the system
* Responds with a CORECOUNTRESPONSE

### Structure
* No parameters

## SENDMACHINECODE
* ID 0x301
* Stores the given bytes in the specified machine code slot
* Responds with a STATUS

* AngryUEFI currently has 10 slots in total
    * Initial machine code - slot 0 NOTE: not implemented yet
    * free slots - slots 1-9
* returns a STATUS response

### Structure
* 4 Byte unsigned LE target slot
* 4 Byte unsigned LE machine code size
* machine code bytes


# Responses
These messages are sent from AngryUEFI to AngryCAT after receiving a request.

## STATUS
* ID: 0x80000000
* Indicates status of the response. It is up to the individual requests and responses whether to use this message.
* It is recommended to use custom response IDs for more specific and structured responses
* If a fault happens in AngryUEFI *and* it can be recovered to the point a message can be sent, AngryUEFI will send this response with status code = 0xFFFFFFFF
* Codes > 0x8000000 are reserved for AngryUEFI and indicate errors outside a message handler

### Structure
* 4 Byte unsigned LE status code - request specific code, by convention 0 means success, 0xFFFFFFFF means AngryUEFI encountered an internal error
* 4 Byte unsigned LE text length - set to 0 if no text follows
* text length Bytes status text - free form/request specific text with details on the status

## PONG
* ID: 0x80000001
* Response to a PING request

### Structure
* 4 Byte unsigned LE message length
* Length Bytes message

## MSGSIZE
* ID: 0x80000003
* Response to a GETMSGSIZE request

### Structure
* 4 Byte unsinged LE received message length

## UCODERESPONSE
* ID 0x80000141
* Returns the `rdtsc` difference
    * `rdtscp` is run before and after the `wrmsr` instruction
    * *Note*: the emulator does not support `rdtscp`, currently `rdtsc` is used
    * only some basic instructions are executed to load registers
    * no memory accesses are done
    * check AngryUEIF/stubs.s for instruction list
* Returns RAX
    * the GPF handler writes 0xdead to RAX
    * GPF is triggered if the ucode update is rejected

## UCODEEXECUTETESTRESPONSE
* ID 0x80000151
* Returns the `rdtsc` difference
    * `rdtscp` is run before and after the `wrmsr` instruction
    * *Note*: the emulator does not support `rdtscp`, currently `rdtsc` is used
    * only some basic instructions are executed to load registers
    * no memory accesses are done
    * check AngryUEIF/stubs.s for instruction list
* Returns RAX
    * the GPF handler writes 0xdead to RAX
    * GPF is triggered if the ucode update is rejected
* Returns a flag field with execution status
* Returns the contents of the result buffer
    * Length is returned as 8 Byte in the packet

### Structure
* 8 Byte LE unsigned - `rdtsc` difference
* 8 Byte LE unsigned - value of RAX
* 8 Byte unsigned LE flags
    * 7 Byte unused
    * 1 Byte flags, Bit 0: LSB
        * Bit 0 - set if timeout was reached when waiting for execution to complete
* 8 Byte LE unsigned - length of result buffer
* up to 1024 Bytes result buffer

## MSRRESPONSE
* ID 0x80000201
* Contains the EAX and EDX values after executing the `rdmsr` instruction

### Strucutre
* 4 Byte LE unsigned - EAX value
* 4 Byte LE unsigned - EDX value

## CORECOUNTRESPONSE
* ID 0x80000211
* Contains the core count of the processor
* if 0 an error during execution was found
* should be at least 1

### Strucutre
* 8 Byte LE unsigned - core count

# AngryCAT

* Catastrophic Automation Tool
* Command & Annihilation Toolkit
* Catastrophic Action Trigger
* microCode Adjustment Tool

Python tool to drive testing with AngryUEFI

# Protocol

AngryUEFI listens on a TCP port, default 3239, and receives commands from this script. This script sends a single command at a time. AngryUEFI sends back at least one message in response. AngryUEFI will never send data outside of this request/response flow. A request must be a maximum of 8204 = 8192+12 Bytes. Response messages are up to 1036 = 1024+12 Bytes. Text transmitted is UCS-2  unless otherwise noted due to UEFI using this encoding. For most text using python encoding `utf_16_be` should work.

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

## SENDUCODE
* ID: 0x101
* Places a ucode update in the specified slot
* AngryUEFI currently has 10 slots in total
    * Known good ucode - slot 0
    * Currently testing ucode - slot 1
    * Base ucodes - slots 2-10
* returns a STATUS response

### Structure
* 4 Byte unsigned LE target slot
* 4 Byte unsigned LE ucode size
* ucode update bytes

## FLIPBITS
* ID 0x121
* Flips the specified bits in the target ucode slot
* Result is placed in slot 1
* bit positions are indexed as follows:
    * index/8 -> target byte
    * index % 8 -> target bit
    * the LSB is 0, the MSB is 7
* Responds with STATUS

### Structure
* 4 Byte unsigned LE target slot
* 4 Byte unsinged LE number of bit flips
* array of 2 Byte unsigned LE of bit positions to flip

## APPLYUCODE
* ID 0x141
* Applies the ucode in the specified slot
* Microcode is applied with interrupts disabled
* Responds with a UCODERESPONSE

### Structure
* 4 Byte unsigned LE target slot

## READMSR
* ID 0x201
* Reads the specified MSR
* Responds with a MSRRESPONSE

### Structure
* 4 Byte unsigned LE target MSR

# Responses
These messages are sent from AngryUEFI to AngryCAT after receiving a request.

## STATUS
* ID: 0x80000000
* Indicates status of the response. It is up to the individual requests and responses whether to use this message.
* It is recommended to use custom response IDs for more specific and structured responses
* If a fault happens in AngryUEFI *and* it can be recovered to the point a message can be sent, AngryUEFI will send this response with status code = 0xFFFFFFFF

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
    * `rdtsc` is run right before and right after the `wrmsr` instruction

### Structure
* 8 Byte LE unsigned - `rdtsc` difference

## MSRRESPONSE
* ID 0x80000201
* Contains the EAX and EDX values are executing the `rdmsr` instruction

### Strucutre
* 4 Byte LE unsigned - EAX value
* 4 Byte LE unsigned - EDX value

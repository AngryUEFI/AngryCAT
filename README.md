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

AngryUEFI listens on a TCP port, default 3239, and receives commands from this script. This script sends a single command at a time. AngryUEFI sends back at least one message in response. AngryUEFI will never send data outside of this request/response flow. A request must be a maximum of 1MB + 12 Bytes. Response messages are up to 1412 = 1400 (Payload) + 12 (Header) Bytes (under default MTU of 1500). Text transmitted is UCS-2  unless otherwise noted due to UEFI using this encoding. For most text using python encoding `utf_16_le` should work.

## Packets
A packet is a single request to AngryUEFI or a single response from AngryUEFI. 

### Header
The header is 12 Bytes. Unless otherwise noted integers are unsigned little-endian.

* 4 Byte Message Length, including Header minus Message Length
* 4 Byte Metadata
* 4 Byte Message Type

#### Message Length
32 bit unsigned little-endian integer. Length does not include this field, but all other header fields and the actual payload. The maximum valid length value is thus 1MB Bytes Payload + 4 Bytes Message Type + 4 Bytes Metadata.

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
Maximum 1MB. Actual length denoted by Message Length field - 8. Contents depend on the Message Type.

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

## GETPAGINGINFO
* ID: 0x11
* Requests information on the paging setup of the given core
* Responds with one or more PAGINGINFO packets
* Note: all memory reads are done from core 0, AngryUEFI assumes core 0 has the full address space identity mapped

### Structure
* 8 Byte - core ID
    * if the core is not started or not present this will be rejected
    * if the core is not ready to accept a job, the cached core CR3 value will be used
    * if the core is ready to accept a job, the current CR3 value will be retrieved and used
    * if the core faulted, the current core CR3 will be read from the context, but might not have been updated
    * if the core timed out, the current core CR3 will be read from the context, but might not have been updated
* 4 times 8 Byte - index to send
    * indicates which entry to send from PML4, PDPT, PD and PT
    * sending the special value 0xffff (CURRENT_TABLE) will stop traversing and send the entire current table
    * sending the special value 0xfffe (PREVIOUS_ENTRY) will stop traversing and send the previous level's entry
    * any value, expcept the special values, above the max limit of the structure will be rejected
    * Examples:
        * 0, 0xfffe, 0, 0: returns the first PML4 entry
        * 0xffff, 0, 0, 0: returns the entire PML4
        * 0, 0xffff, 0, 0: returns the entire first PDPT
        * 0, 0, 0, 0: returns the first page table entry in the first page directory in the first page directory pointer table in the first PML4 entry
        * 0, 0, 0, 1: returns the second page table entry in the first page directory in the first page directory pointer table in the first PML4 entry
        * 0, 0, 0, 0xfffe: returns the first page directory entry in the first page directory pointer table in the first PML4 entry
        * 0, 0, 0, 0xffff: returns all page table entries in the first page directory in the first page directory pointer table in the first PML4 entry
        * 512, 0, 0, 0: rejected, PML4 has only 512 entries

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
* Timeout is the amount 1ms stalls core 0 waits for the job to switch to Ready state after the job was launched
* Timeout = 0 means to wait forever, not recommended as jobs can lock up a core
* If the job is run on core 0 timeout is disregarded
* Responds with a UCODEEXECUTETESTRESPONSE
* Optionally applies the known good update afterwards
    * this is done directly in the assembly stub to limit executed instructions
* If the ucode update is rejected (aka GPF handler is entered), the machine code is not executed

### Structure
* 4 Byte unsigned LE target ucode slot
* 4 Byte unsigned LE target machine code slot
* 4 Byte unsigned LE target core number
* 4 Byte unsigned LE timeout in roughly ms for execution, 0 for unlimited
* 4 Byte unsigned LE options
    * 3 Byte unused
    * 1 Byte flags, Bit 0: LSB
        * Bit 0 - apply known good update after the test update

## GETLASTTESTRESULT
* ID 0x152
* Get the result of the last executed test on requested core
* Returns two messages, in this order:
    * Returns a CORESTATUSRESPONSE (last message = False)
    * Returns a UCODEEXECUTETESTRESPONSE (last message = True)
* Returns the state as-is, if a job on the core is still running this might be invalid/corrupted

### Structure
* 8 Byte unsigned LE core number

## EXECUTEMACHINECODE
* ID 0x153
* Runs the machine code in specified slot
* Executes on given core number
* Timeout is the amount 1ms stalls core 0 waits for the job to switch to Ready state after the job was launched
* Timeout = 0 means to wait forever, not recommended as jobs can lock up a core
* If the job is run on core 0 timeout is disregarded
* Responds with a UCODEEXECUTETESTRESPONSE
    * RDTSC difference and RAX are set to 0

### Structure
* 4 Byte unsigned LE target machine code slot
* 4 Byte unsigned LE target core number
* 4 Byte unsigned LE timeout in roughly ms for execution, 0 for unlimited

## READMSR
* ID 0x201
* Reads the specified MSR
* Responds with a MSRRESPONSE

### Structure
* 4 Byte unsigned LE target MSR

## READMSRONCORE
* ID 0x202
* Reads the specified MSR on the specified core ID
* Note: will not read MSRs on cores not ready to accept jobs
* Responds with a MSRRESPONSE
* Responds with a STATUS if the internal timeout of 100ms is reached (stuck core, even though ready)

### Structure
* 4 Byte unsigned LE target MSR
* 8 Byte unsigned LE target core ID

## GETCORECOUNT
* ID 0x211
* Returns the core count of the system
* Responds with a CORECOUNTRESPONSE

### Structure
* No parameters

## STARTCORE
* ID 0x212
* Start the specified core ID
* Core will go into a busy wait loop until a test is started on it
* After a test the core will again busy wait for a new test
* Once started a core can not be stopped, reboot the system to stop it
* Core 0 is the boot core and always running
* Send core = 0 to start all avaible cores
* Responds with a STATUS response

### Structure
* 8 Byte unsigned LE core to start

## GETCORESTATUS
* ID 0x213
* Get the status of the specified core ID
* Core ID 0 is the boot core
* Core 0 can not be stopped/busy, it runs the network stack
* Responds with a CORESTATUSRESPONSE

### Structure
* 8 Byte unsigned LE core to get information on

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

## PAGINGINFO
* ID: 0x80000011
* Response to a GETPAGINGINFO request
* AngryUEFI has a limit of how many entries it will include in a single packet, check the last packet bit in the metadata!
* AngryCAT must retrieve all packets until the last packet is encountered, even if the required information was already read

### Structure
* 8 Byte flags
    * Byte 0, Bit 0 - fresh core CR3: if 0 -> could not retrieve the current CR3 value, used cached value, if 1 -> updated CR3 value
    * Byte 0, Bit 1 - CR3 update faulted core: if 0 -> core did not fault, if 1 -> core faulted
    * Byte 0, Bit 2 - CR3 update timed out: if 0 -> core did not timeout, if 1 -> core timed out
    * rest reserved
* 8 Byte CR3 value of requested core
* 8 Byte entry count
* entry count amount of 16 Byte entries and entry meta data
    * 8 Byte paging entry metadata
        * 2 Byte position in table
            * e.g. the first entry in the PML4 will have this set to 0
        * 1 Byte paging structure level
            * 1 - Page Table
            * 2 - Page Directory
            * 3 - Page Directory Pointer Table
            * 4 - PML4
        * 5 Bytes reserved
    * 8 Byte paging entry
    * each entry represents a single paging entry, e.g. a page table entry or a PML4 entry

## UCODERESPONSE
* ID 0x80000141
* Returns the `rdtsc` difference
    * `rdtscp` is run before and after the `wrmsr` instruction
    * only some basic instructions are executed to load registers
    * no memory accesses are done
    * check AngryUEFI/stubs.s for instruction list
* Returns RAX
    * the GPF handler writes 0xdead to RAX
    * GPF is triggered if the ucode update is rejected

## UCODEEXECUTETESTRESPONSE
* ID 0x80000151
* Returns the `rdtsc` difference
    * `rdtscp` is run before and after the `wrmsr` instruction
    * only some basic instructions are executed to load registers
    * check AngryUEFI/stubs.s for instruction list
* Returns RAX
    * the GPF handler writes 0xdead to RAX
    * GPF is triggered if the ucode update is rejected
* Returns a flag field with execution status
* If the job has not finished, this is the current status and might be incomplete/corrupted/undefined
* Returns the contents of the result buffer
    * Length is returned as 8 Byte in the packet

### Structure
* 8 Byte LE unsigned - `rdtsc` difference
* 8 Byte LE unsigned - value of RAX
* 8 Byte unsigned LE job flags
    * 7 Byte unused
    * 1 Byte flags, Bit 0: LSB
        * Bit 0 - set if timeout was reached when waiting for execution to complete; always 0 in response to GETLASTTESTRESULT
        * Bit 1 - set if core signaled a fault, use GETCORESTATUS to get infos on what happened
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

## CORESTATUSRESPONSE
* ID 0x80000213
* Contains the status of the requested core
* Core 0 is the boot core and will always report (Present, Started, Ready, Not Queued, Not Faulted)
* Note on timestamps: on modern CPUs this should be constant even across cores, but keep in mind that these come from two different cores

### Strucutre
* 8 Byte unsigned LE flags
    * 7 Byte unused
    * 1 Byte flags, Bit 0: LSB
        * Bit 0 - Present Bit: if set -> requestd core is present, if not set -> requested core is not present, all other values are undefined
        * Bit 1 - Started Bit: if set -> core was started, if not set -> core was not started and can be started
        * Bit 2 - Ready Bit: if set -> core is ready to accept a job, if not set -> core is running a job or hanging
        * Bit 3 - Job Queued Bit: if set -> core has a queued job, all data for the job was written, but has not picked it up yet, if not set -> core has picked up the job or job is still being written
        * Bit 4 - Context Locked Bit: if set -> context is currently locked, if not set -> context is not locked
        * Bit 5 - Core Faulted Bit: if set -> core encountered a fault, if not set -> core did not encounter a fault; reset when a new job starts
* 8 Byte unsigned LE last heartbeat RDTSC - when the core last updated its heartbeat field, core 0 does not regularly update this field
* 8 Byte unsigned LE current RDTSC - RDTSC on core 0 when this resonse was generated, used as reference for requested core heartbeat
* 8 Byte unsigned LE fault info length - number of bytes of fault info, if core did not fault (Core Faulted Bit == 0), this is also 0 and no fault info follows
* fault info length Bytes Fault Info - raw dump of CoreFaultInfo of this core, for definitions of buffer see AngryUEFI/handlers/fault_handling.h; members are zeroed when a new job starts (if the core could recover itself)

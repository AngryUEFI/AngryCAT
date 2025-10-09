# Test Setup API Documentation

This document provides comprehensive documentation for the AngryCAT test setup system, including the public APIs for testsetups and the registry.

For a quickstart see [Most Basic Usage](#most-basic-usage).

## Table of Contents

1. [Overview](#overview)
2. [Base Classes](#base-classes)
3. [Registry Functions](#registry-functions)
4. [Predefined Architectures](#predefined-architectures)
5. [Usage Examples](#usage-examples)

## Overview

The test setup system provides dynamic loading and management of test setups, CPU types, and architectures. Test setups represent physical or virtual systems that execute tests over the network.

Auto-discovery is enabled by default - setups are automatically discovered when the module is imported.

## Base Classes

### Architecture

Represents a CPU architecture (e.g., Zen1, Zen2, Zen3).

**Attributes:**
- `name`: Architecture name
- `attributes`: Dictionary of architecture-specific attributes

* Most useful attribute is `ucode_revision_msr` that is used internally to get the ucode revision.

### CpuType

Represents a specific CPU type with its architecture and template microcode update.

**Attributes:**
- `name`: CPU type name
- `cpuid`: CPU ID value
- `architecture`: The Architecture this CPU belongs to
- `template_update`: Path to template microcode update binary file
- `known_match_regs`: Dictionary of known match registers
- `attributes`: Additional CPU-specific attributes

### TestSetup

Base class for test setups. A test setup represents a physical or virtual system that can execute tests.

**Key Methods:**

#### Connection Management
- `connect(allow_retry=True)`: Establish connection to the test setup
- `disconnect()`: Close connection to test setup

#### Network Operations
- `send_packet(packet: Packet)`: Send a packet to the test setup
- `receive_packets() -> list[Packet]`: Receive packets from the test setup
- `ping(msg="Hello AngryUEFI!") -> bool`: Send a ping packet to check connectivity

#### Reboot Operations
- `reboot(wait_for_ping: bool = True)`: Reboot the test setup
- `pin_reset()`: Trigger hardware reset via pin control
- `pin_power(long: bool = False)`: Control power via pin operations

#### Core Management
- `get_core_count(force_refresh=False)`: Get the number of cores
- `get_core_status(core_id: int)`: Query the current status of a core
- `start_core(core_number)`: Start a specific core
- `start_all_cores()`: Start all cores
- `mark_core_dead(core_id: int)`: Mark a core as blocked
- `determine_free_core(allow_reboot=True, allow_boot_core=False) -> int`: Find a free core for testing

#### Microcode Operations
- `assemble_ucode(ucode: str | List[str] | ByteString, **kwargs) -> bytes`: Assemble microcode
- `send_ucode(ucode: str | List[str] | ByteString, slot_number: int = 1, **kwargs)`: Send microcode to setup
- `get_ucode_revision(core_id: int) -> Optional[int]`: Query the microcode version on a core

#### Machine Code Operations
- `assemble_machine_code(assembly: str) -> bytes`: Assemble x86-64 machine code
- `send_machine_code(machine_code: str | ByteString, target_slot=1)`: Send machine code to setup

#### Testing Operations
- `run_test(ucode, machine_code, core_number=None, timeout=100, apply_known_good=False, mark_core_dead=False)`: Run a complete test
- `apply_ucode_execute_mc(core_number=None, ucode_slot=1, mc_slot=1, timeout=100, apply_known_good=False, mark_core_dead=False)`: Apply microcode and execute machine code

#### Utility Methods
- `read_msr(core_id: int, msr: int) -> Optional[int]`: Read an MSR on a core
- `refresh_core(core_number)`: Refresh core status and microcode version
- `refresh_cores()`: Refresh all cores
- `ready_clean_setup(do_reboot=False)`: Prepare setup for clean testing

#### Optional attributes
- `_custom_pin_action`: Implement a custom way to handle pin actions, gets the test setup and one of `"reset_pin", "power_pin_long", "power_pin_short"` as argument, return `True` if the call worked
- `_custom_led_status`: Implement a custom way to get the LED status, gets the test setup as argument, return `True` if the LED is on

**Runtime options:**
- `auto_reboot_on_error`: set to `False` to prevent automatic recoveries, APIs will raise instead
- `auto_start_cores`: set to `False` to prevent automatic start of all cores after reboot
- `after_reboot_delay`: minimal wait time after a reboot request, allows async network calls to catch up
- `socket_timeout`: Configure internal timeout for network operations
- `reboot_timeout`: Configure internal max wait time after reboot for network to connect

## Registry Functions

### Setup Management

#### `get_setup(architecture: str | Architecture | None = None, name: str | None = None, **criteria) -> TestSetup | None`

Query for a test setup instance by criteria.

**Parameters:**
- `architecture`: Required architecture (string name or Architecture instance)
- `name`: Specific setup name to retrieve
- `**criteria`: Additional criteria to match against setup attributes

**Returns:** First matching TestSetup instance, or None if not found

#### `get_all_setups(architecture: str | Architecture | None = None) -> list[TestSetup]`

Get all test setups, optionally filtered by architecture.

**Parameters:**
- `architecture`: Optional architecture filter

**Returns:** List of matching TestSetup instances

### Configuration Management

#### `get_config(key: str, default: Any = None) -> Any`

Get a global configuration value by key.

**Parameters:**
- `key`: Configuration key
- `default`: Default value if key not found

**Returns:** Configuration value or default

#### `get_all_config() -> dict[str, Any]`

Get all global configuration values.

**Returns:** Dictionary of all configuration values

#### `set_config(key: str, value: Any) -> None`

Set a global configuration value.

**Parameters:**
- `key`: Configuration key
- `value`: Configuration value

## Predefined Architectures

The system includes predefined AMD Zen architectures:

### `Zen1`
- **Name:** "Zen1"
- **Ucode Revision MSR:** 0x8b
- **Family:** 0x17
- **Model Range:** (0x00, 0x0F)
- **Vendor:** "AMD"

### `Zen2`
- **Name:** "Zen2"
- **Ucode Revision MSR:** 0x8b
- **Family:** 0x17
- **Model Range:** (0x30, 0x3F)
- **Vendor:** "AMD"

### `Zen3`
- **Name:** "Zen3"
- **Ucode Revision MSR:** 0x8b
- **Family:** 0x19
- **Model Range:** (0x00, 0x0F)
- **Vendor:** "AMD"

### `Zen4`
- **Name:** "Zen4"
- **Ucode Revision MSR:** 0x8b
- **Family:** 0x19
- **Model Range:** (0x60, 0x6F)
- **Vendor:** "AMD"

### `Zen5`
- **Name:** "Zen5"
- **Ucode Revision MSR:** 0x8b
- **Family:** 0x1A
- **Model Range:** (0x00, 0x0F)
- **Vendor:** "AMD"

## Usage Examples

### Most Basic Usage

```python
from angrycat.testsetup.registry import get_setup

mc = """
    nop
    ret
"""

ucode = [
        "--match", "all=0",
        "--nop", "all",
        "--match", f"0=1",

        # @0x1fc0
        "--insn", "q0i0=0x0",


        # @0x1fc4
        "--insn", "q4i0=mov r11, r11, 0x0",
        "--insn", "q4i1=mov r11, r11, 0x0",
        "--insn", "q4i2=mov r11, r11, 0x0",
        "--insn", "q4i3=mov r11, r11, 0x0",
        "--seq",  "4=0x03100082",

        "--hdr-revlow", f"{0x23}",
        "--hdr-autorun", "false"
    ]

zen3 = get_setup("Zen3")
# connect and get the setup into a clean state
zen3.ready_clean_setup(do_reboot=True)
# auto selects cores, slots and compiles mc & ucode
res = zen3.run_test(ucode, mc)
print(res)
```

See `usage_example.py` for a complete script.

### Basic Setup Discovery

```python
from angrycat.testsetup import get_setup, get_all_setups

# Get a specific setup by name
setup = get_setup(name="lab_zen3_machine_1")

# Get all setups for a specific architecture
zen3_setups = get_all_setups(architecture="Zen3")

# Get a setup by architecture and criteria
setup = get_setup(architecture="Zen3", location="Lab A")
```

### Creating Custom Setups

```python
from angrycat.testsetup import TestSetup, CpuType, Zen3

# Define a custom CPU type
custom_cpu = CpuType(
    name="AMD Ryzen 9 5950X",
    cpuid=0x00A20F01,
    architecture=Zen3,
    template_update="custom_template.bin",
    known_match_regs={
        "fcos": 0xc98,
        "rdrand": 0x0c34,
    }
)

# define a custom pin action
def my_custom_action(setup, pin_name) -> bool:
    if pin_name == "reset_pin":
        res = url_call("https://example.com")
        return res.returncode == 200

# Create a test setup
my_setup = TestSetup(
    name="my_custom_setup",
    cpu_type=custom_cpu,
    host="192.168.1.100",
    port=3239,
    location="My Lab",
    has_smt=True,
    notes="Custom test setup",
    _custom_pin_action = my_custom_action
)
```

### Working with Setups

```python
# Connect to a setup
setup = get_setup(name="lab_zen3_machine_1")
setup.connect()

# Check core status
core_count = setup.get_core_count()
print(f"Setup has {core_count} cores")

# Find a free core
free_core = setup.determine_free_core()
print(f"Free core: {free_core}")

# Run a test
result = setup.run_test(
    ucode=["mov eax, 0x12345678"],
    machine_code="mov eax, 0x87654321",
    core_number=free_core,
    timeout=100
)

# Disconnect
setup.disconnect()
```

### Configuration Management

```python
from angrycat.testsetup import set_config, get_config

# Set global configuration
set_config("zentool_path", "/usr/local/bin/zentool")
set_config("log_level", "INFO")

# Get configuration
zentool_path = get_config("zentool_path", "zentool")
log_level = get_config("log_level", "WARNING")
```

## Directory Structure

The system searches for test setup definitions in the following directories:

1. **Built-in directory:** `src/angrycat/testsetup/testsetups/`
2. **Development directory:** `testsetups/` (relative to project root)
3. **Environment variable:** `ANGRYCAT_TESTSETUP_DIRS` (colon-separated paths)

## File Format

Test setup definitions are Python files that can contain:

- `Architecture` instances
- `CpuType` instances  
- `TestSetup` instances
- Functions that return these types
- A `config` dictionary for global configuration

Example file structure:
```python
# Define architectures
zen3 = Architecture("Zen3", ucode_revision_msr=0x8b, ...)

# Define CPU types
cpu5600 = CpuType("AMD Ryzen 5 5600", 0x00A20F12, zen3, ...)

# Define test setups
lab_machine = TestSetup("lab_machine", cpu5600, "192.168.1.100", 3239, ...)

# Optional: global configuration
config = {
    "zentool_path": "/usr/local/bin/zentool",
    "log_level": "INFO"
}
```

## Error Handling

The system includes error handling:

- **NetworkError**: Raised when network operations fail
- **RebootError**: Raised when reboot operations fail
- **ValueError**: Raised for invalid parameters or missing dependencies

The TestSetup class includes automatic error recovery with multi-stage recovery (reconnect → hard reboot → reconnect) and automatic retry mechanisms.

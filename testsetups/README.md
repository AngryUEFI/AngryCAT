# Test Setup Definitions

This directory contains test setup definitions for the AngryCAT framework.

## Directory Structure

You can organize this directory in multiple ways:

1. **All-in-one**: Define CPU types and setups in the same file
2. **Separated** (recommended): 
   - Shared CPU type files (e.g., `ryzen5_cpus.py`) - CPU definitions
   - Individual setup files that import and use those CPU types

## Creating Test Setups

Test setups are defined in Python files by directly instantiating `TestSetup` with configuration attributes. Each file can contain one or more setup definitions.

### Basic Example

```python
from angrycat.testsetup import Zen3, CpuType, TestSetup

# Define or import a CPU type
cpu = CpuType(
    name="AMD Ryzen 5 5600",
    cpuid=0x00A20F12,
    architecture=Zen3,
    template_update="cpu00A20F12_template.bin",
    known_match_regs={
        "fcos": 0xc98,
        "rdrand": 0x0c34,
    },
)

# Create test setups by instantiating TestSetup directly
my_setup = TestSetup(
    name="my_setup",
    cpu_type=cpu,
    host="192.168.1.10",
    port=3239,
    location="Lab A",
    has_smt=True,
    has_badram=False,
)
```

**See `example_setup.py` for a complete working example showing CPU sharing, imports, and multiple setups.**

### Sharing CPU Types

For CPU types used by multiple setups, define them in a separate file and import them:

```python
# In your setup file
from .ryzen5_cpus import cpu5600  # Import shared CPU type

# Or retrieve from registry
# cpu5600 = get_cpu_type("AMD Ryzen 5 5600")

# Create multiple setups using the same CPU
machine1 = TestSetup(
    name="machine1",
    cpu_type=cpu5600,
    host="192.168.1.10",
    port=3239,
    has_smt=True,
    has_badram=False,
)

machine2 = TestSetup(
    name="machine2",
    cpu_type=cpu5600,  # Same CPU, different machine
    host="192.168.1.11",
    port=3239,
    has_smt=True,
    has_badram=True,
)
```

**See `example_setup.py` for detailed examples of importing CPU types and fallback patterns.**

### CPU-Only Files

You can define CPU types in files without any TestSetup instances.
They will be automatically discovered and available via the registry.

**See `ryzen5_cpus.py` for a complete example of CPU-only definitions.**

```python
# Using CPU types from registry in your tests
from angrycat.testsetup import get_cpu_type

cpu = get_cpu_type("AMD Ryzen 5 1600")
print(f"CPUID: 0x{cpu.cpuid:08X}")
print(f"Match regs: {cpu.known_match_regs}")
```

### Predefined Architectures

AngryCAT provides predefined AMD Zen architectures:
- `Zen1` - First generation Zen
- `Zen2` - Second generation Zen
- `Zen3` - Third generation Zen
- `Zen4` - Fourth generation Zen
- `Zen5` - Fifth generation Zen

All Zen architectures share:
- `ucode_revision_msr = 0x8b` - MSR for reading microcode revision

### CPU Type Attributes

When defining a CPU type, you must provide:

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | str | CPU model name |
| `cpuid` | int | CPUID value |
| `architecture` | Architecture | Architecture instance (e.g., Zen3) |
| `template_update` | str \| Path \| None | Path to template microcode binary (see below) |
| `known_match_regs` | dict[str, int] | Microcode match registers: `{"instruction": offset}` |

Optional attributes can be added as keyword arguments.

**Example:** See `ryzen5_cpus.py` for real CPU definitions with match registers.

### Test Setup Attributes

When defining a test setup, you must provide:

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | str | Setup identifier/name |
| `cpu_type` | CpuType | The CPU type of this setup |
| `host` | str | Network host address |
| `port` | int | Network port |
| `has_smt` | bool | Whether the setup supports Simultaneous Multithreading |
| `has_badram` | bool | Whether the setup has bad RAM that needs to be avoided |

Optional attributes can be added as keyword arguments (e.g., `location`, `notes`).

### Template Update Path Resolution

The `template_update` parameter supports three formats for maximum flexibility:

#### 1. Path Instance (Relative or Absolute)
```python
from pathlib import Path

cpu = CpuType(
    name="My CPU",
    template_update=Path("templates/my_template.bin"),  # Relative to this file
    # ...
)

# Or absolute:
cpu = CpuType(
    name="My CPU",
    template_update=Path("/opt/angrycat/templates/my_template.bin"),
    # ...
)
```
- Relative paths are resolved relative to the directory containing the CPU definition file
- Absolute paths are used as-is

#### 2. Filename Only (Automatic Search)
```python
cpu = CpuType(
    name="My CPU",
    template_update="my_template.bin",  # Searches all setup directories
    # ...
)
```
- If you provide just a filename ending in `.bin` (no path separators)
- The framework searches all directories in `ANGRYCAT_TESTSETUP_DIRS` recursively
- Uses the first matching file found

#### 3. Relative Path String
```python
cpu = CpuType(
    name="My CPU",
    template_update="templates/my_template.bin",  # Relative to this file
    # ...
)
```
- String containing path separators (e.g., `"templates/file.bin"`)
- Resolved relative to the directory containing the CPU definition file

**Note**: After loading, `cpu.template_update` will be a `Path` instance pointing to the resolved absolute path, or `None` if the file wasn't found.

### Registry Functions

**For Setups:**
- `get_setup(name=...)` - Get setup by name
- `get_setup(architecture=...)` - Get setup by architecture
- `get_all_setups()` - Get all setups
- `get_all_setups(architecture="Zen3")` - Get all setups for architecture

**For CPU Types:**
- `get_cpu_type(name)` - Get CPU type by name
- `get_all_cpu_types()` - Get all CPU types
- `get_all_cpu_types(architecture="Zen3")` - Get CPU types for architecture

**For Architectures:**
- `get_architecture(name)` - Get architecture by name

### Using Test Setups

In your test code or scripts:

```python
from angrycat.testsetup import get_setup, get_cpu_type, get_all_setups

# Get a specific setup by name
setup = get_setup(name="lab_zen3_machine_1")

# Get any setup with Zen3 architecture
setup = get_setup(architecture="Zen3")

# Get setup with specific criteria
setup = get_setup(architecture="Zen3", location="Lab A")

# Get all available setups
all_setups = get_all_setups()

# Get all setups for an architecture
zen3_setups = get_all_setups(architecture="Zen3")

# Get CPU type information
cpu = get_cpu_type("AMD Ryzen 9 5950X")
print(f"CPU ID: 0x{cpu.cpuid:X}")
print(f"Template: {cpu.template_update}")
print(f"Match regs: {cpu.known_match_regs}")

# Access architecture attributes
print(f"Architecture: {setup.architecture.name}")
print(f"Ucode MSR: 0x{setup.architecture.attributes['ucode_revision_msr']:X}")

# Access setup attributes
print(f"SMT Support: {setup.get_config('has_smt')}")
print(f"Bad RAM: {setup.get_config('has_badram')}")
```

## Custom Setup Directories

You can define additional setup directories using the `ANGRYCAT_TESTSETUP_DIRS` environment variable:

```bash
export ANGRYCAT_TESTSETUP_DIRS="/path/to/setups1:/path/to/setups2"
```

Multiple paths should be separated by `:` on Unix/Linux or `;` on Windows.

## Example Files

- **`ryzen5_cpus.py`** - Real AMD Ryzen 5 CPU definitions (Zen1-Zen5)
  - Shows how to define CPU types with match registers
  - Demonstrates different template path resolution methods
  - CPU-only file (no test setups)

- **`example_setup.py`** - Complete test setup examples
  - Shows how to import and share CPU types
  - Demonstrates direct TestSetup instantiation
  - Includes fallback patterns and local CPU definitions
  - Multiple setups sharing the same CPU type
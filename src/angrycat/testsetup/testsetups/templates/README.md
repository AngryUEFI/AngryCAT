# Template Updates

This directory contains template microcode update binary files for different CPU types.

## File Naming Convention

Files should be named based on the CPUID and a short description of their purpose:
- `cpu00800F11_template.bin` - AMD Ryzen 5 1600 template
- `cpu00800F11_encrypted_template.bin` -  AMD Ryzen 5 1600 encrypted template
- `cpu00870F10_template.bin` - AMD Ryzen 5 3600X template
- `cpu00A20F12_template.bin` - AMD Ryzen 5 5600 template
- `cpu00A60F12_template.bin` - AMD Ryzen 5 7500F template
- etc.

For variant templates (e.g., encrypted, modified), append a descriptive suffix:
- `cpu00800F11_encrypted_template.bin` - AMD Ryzen 5 1600 encrypted template
- `cpu00870F10_modified_template.bin` - AMD Ryzen 5 3600X modified template

## Usage

Template updates can be referenced in CPU definitions in three ways:

### 1. Relative Path (Path object)
```python
from pathlib import Path

cpu = CpuType(
    name="My CPU",
    template_update=Path("templates/my_template.bin"),
    # ...
)
```

### 2. Filename Only (searched in all setup directories)
```python
cpu = CpuType(
    name="My CPU",
    template_update="my_template.bin",  # Will search all dirs, use leading ./ for relative path if needed
    # ...
)
```

### 3. Relative Path String
```python
cpu = CpuType(
    name="My CPU",
    template_update="templates/my_template.bin",
    # ...
)
```

All relative paths are resolved relative to the Python file containing the CPU definition.


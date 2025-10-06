"""
AMD Ryzen 5 CPU type definitions across different Zen architectures.

These CPU definitions are adapted from the legacy format and include
microcode match register offsets in the known_match_regs dictionary.
The format is: instruction_name -> offset
"""

from angrycat.testsetup import Zen1, Zen2, Zen3, Zen4, Zen5, CpuType


# AMD Ryzen 5 1600 (Zen1)
cpu1600 = CpuType(
    name="AMD Ryzen 5 1600",
    cpuid=0x00800F11,
    architecture=Zen1,
    template_update="cpu00800F11_template.bin",
    known_match_regs={
        "shld": 0x420,
        "shrd": 0x440,
        "fcos": 0xc98,
    },
)

# AMD Ryzen 5 3600X (Zen2)
cpu3600x = CpuType(
    name="AMD Ryzen 5 3600X",
    cpuid=0x00870F10,
    architecture=Zen2,
    template_update="cpu00870F10_template.bin",
    known_match_regs={
        "shld": 0x420,
        "shrd": 0x440,
        "fcos": 0xcb8,
        "rdrand": 0x543,
    },
)

# AMD Ryzen 5 5600 (Zen3)
cpu5600 = CpuType(
    name="AMD Ryzen 5 5600",
    cpuid=0x00A20F12,
    architecture=Zen3,
    template_update="cpu00A20F12_template.bin",
    known_match_regs={
        "fcos": 0xc98,
        "rdrand": 0x0c34,
    },
)

# AMD Ryzen 5 7500F (Zen4)
cpu7500f = CpuType(
    name="AMD Ryzen 5 7500F",
    cpuid=0x00A60F12,
    architecture=Zen4,
    template_update="cpu00A60F12_template.bin",
    known_match_regs={
        "fcos": 0x0c98,
        "rdrand": 0x4d5,
    },
)

# AMD Ryzen 5 9600 (Zen5)
# Note: match registers are likely incorrect (copied from similar CPU)
cpu9600 = CpuType(
    name="AMD Ryzen 5 9600",
    cpuid=0x00B40F40,
    architecture=Zen5,
    template_update="cpu00B40F40_ver0B404006_2024-02-02_D222E366_orig.bin",
    known_match_regs={
        "shld": 0x420,
        "shrd": 0x440,
        "fcos": 0xcb8,
        "rdrand": 0x543,
    },
)


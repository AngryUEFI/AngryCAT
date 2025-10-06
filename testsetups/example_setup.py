"""
Example test setup definition.

This file demonstrates how to define test setups for the AngryCAT framework
using real AMD Zen architectures.

It shows two approaches:
1. Importing a shared CPU type from another file (recommended for reuse)
2. Defining a CPU type locally in this file
"""

from angrycat.testsetup import Zen1, Zen2, Zen3, CpuType, TestSetup, get_cpu_type


# Approach 1: Import a shared CPU type from ryzen5_cpus.py
# This is the recommended approach when multiple setups use the same CPU
# The CPU type is automatically discovered from ryzen5_cpus.py
# You can access it using get_cpu_type() or import it directly:

# Option A: Get CPU type by name (lazy loading from registry)
# cpu1600 = get_cpu_type("AMD Ryzen 5 1600")

# Option B: Import directly (requires ryzen5_cpus to be loaded first)
# Since we're in the same directory, we can import:
try:
    from .ryzen5_cpus import cpu1600, cpu3600x, cpu5600
except ImportError:
    # Fallback if running standalone - define locally
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


# Approach 2: Define a CPU type locally
# Use this when the CPU is unique to this setup
# Example showing absolute Path for template update
from pathlib import Path as PathLib

local_cpu = CpuType(
    name="AMD EPYC 7763",
    cpuid=0x00A00F11,
    architecture=Zen3,
    template_update=PathLib(__file__).parent / "templates/zen3_epyc_template.bin",
    known_match_regs={
        "fcos": 0xc98,
        "rdrand": 0x0c34,
    },
    cores=64,
    threads=128,
    family=0x19,
    model=0x01,
    stepping=0x01,
)


# Create setup instances using shared CPU types
# Multiple setups can share the same CPU type
# TestSetup is instantiated directly - it will provide default implementations
# for connect(), disconnect(), and is_available() based on the attributes

lab_zen1_machine = TestSetup(
    name="lab_zen1_machine",
    cpu_type=cpu1600,  # Using shared Zen1 CPU type
    host="192.168.1.100",
    port=3239,
    location="Lab A",
    has_smt=True,
    has_badram=False,
    notes="Zen1 development machine with Ryzen 5 1600",
)

lab_zen2_machine = TestSetup(
    name="lab_zen2_machine",
    cpu_type=cpu3600x,  # Using shared Zen2 CPU type
    host="192.168.1.101",
    port=3239,
    location="Lab A",
    has_smt=True,
    has_badram=True,
    notes="Zen2 testing machine with Ryzen 5 3600X",
)

lab_zen3_machine_1 = TestSetup(
    name="lab_zen3_machine_1",
    cpu_type=cpu5600,  # Using shared Zen3 CPU type
    host="192.168.1.102",
    port=3239,
    location="Lab A",
    has_smt=True,
    has_badram=False,
    notes="Zen3 testing machine with Ryzen 5 5600",
)

lab_zen3_machine_2 = TestSetup(
    name="lab_zen3_machine_2",
    cpu_type=cpu5600,  # Same CPU type, different machine
    host="192.168.1.103",
    port=3239,
    location="Lab B",
    has_smt=True,
    has_badram=True,
    notes="Another Zen3 machine sharing the same CPU type",
)

# Using locally defined CPU type
server_epyc = TestSetup(
    name="server_epyc",
    cpu_type=local_cpu,  # Using locally defined CPU
    host="192.168.1.200",
    port=3239,
    location="Server Room",
    has_smt=True,
    has_badram=False,
    notes="High-core-count EPYC server",
)
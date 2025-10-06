"""
AngryCAT Test Setup Management

This module provides dynamic loading and management of test setups.
Test setups are physical or virtual systems that execute tests over the network.

Auto-discovery is enabled by default - setups are automatically discovered
when this module is imported.
"""

from .base import Architecture, CpuType, TestSetup
from .registry import (
    get_setup,
    get_all_setups,
    register_setup,
    discover_setups,
    get_cpu_type,
    get_all_cpu_types,
    register_cpu_type,
    get_architecture,
    register_architecture,
    get_config,
    get_all_config,
    set_config,
)
from .architectures import (
    Zen1,
    Zen2,
    Zen3,
    Zen4,
    Zen5,
)

__all__ = [
    # Base classes
    "Architecture",
    "CpuType",
    "TestSetup",
    # Registry functions - Setups
    "get_setup",
    "get_all_setups",
    "register_setup",
    "discover_setups",
    # Registry functions - CPU Types
    "get_cpu_type",
    "get_all_cpu_types",
    "register_cpu_type",
    # Registry functions - Architectures
    "get_architecture",
    "register_architecture",
    # Registry functions - Configuration
    "get_config",
    "get_all_config",
    "set_config",
    # Predefined Zen architectures
    "Zen1",
    "Zen2",
    "Zen3",
    "Zen4",
    "Zen5",
]

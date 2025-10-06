"""
Base classes for test setup management.
"""

from pathlib import Path
from typing import Any

import logging
logger = logging.getLogger()


class Architecture:
    """
    Represents a CPU architecture (e.g., Zen1, Zen2, Zen3).
    
    Architectures have attributes that describe their characteristics.
    """
    
    def __init__(self, name: str, **attributes):
        """
        Initialize an Architecture.
        
        Args:
            name: Architecture name (e.g., "Zen1", "Zen2", "Zen3")
            **attributes: Additional architecture-specific attributes
        """
        self.name = name
        self.attributes = attributes
    
    def __str__(self):
        return self.name
    
    def __repr__(self):
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.attributes.items())
        if attrs:
            return f"Architecture({self.name!r}, {attrs})"
        return f"Architecture({self.name!r})"


class CpuType:
    """
    Represents a specific CPU type.
    
    Each CPU type belongs to an architecture and has a template microcode update.
    """
    
    def __init__(
        self,
        name: str,
        cpuid: int,
        architecture: Architecture,
        template_update: str | Path | None,
        known_match_regs: dict | None = None,
        **attributes
    ):
        """
        Initialize a CPU type.
        
        Args:
            name: CPU type name (e.g., "AMD Ryzen 9 5950X")
            cpuid: CPU ID value
            architecture: The Architecture this CPU belongs to
            template_update: Path to template microcode update binary file (str, Path, or None)
            known_match_regs: Dictionary of known match registers
            **attributes: Additional CPU-specific attributes
        """
        self.name = name
        self.cpuid = cpuid
        self.architecture = architecture
        # Store raw template_update for later resolution by registry
        self._template_update_raw = template_update
        # Will be resolved to Path by registry during discovery
        self.template_update: Path | None = None
        if isinstance(template_update, Path) and template_update.is_absolute():
            self.template_update = template_update
        self.known_match_regs = known_match_regs if known_match_regs is not None else {}
        self.attributes = attributes
    
    def __str__(self):
        return f"{self.name} ({self.architecture})"
    
    def __repr__(self):
        return f"CpuType({self.name!r}, cpuid=0x{self.cpuid:X}, {self.architecture.name!r})"


class TestSetup:
    """
    Base class for test setups.
    
    A test setup represents a physical or virtual system that can execute tests.
    Setups communicate over the network and have instance-specific configurations.
    
    This class can be instantiated directly and will read attributes from the
    definition file to determine connection behavior.
    """
    
    def __init__(
        self,
        name: str,
        cpu_type: CpuType | str,
        host: str,
        port: int,
        **config
    ):
        """
        Initialize a test setup.
        
        Args:
            name: Setup identifier/name
            cpu_type: The CPU type of this setup (CpuType instance or string name)
            host: Network host address
            port: Network port
            **config: Instance-specific configuration options
        """
        self.name = name
        
        # Handle CPU type - can be a CpuType instance or string name
        if isinstance(cpu_type, str):
            # Store the string for later resolution during discovery
            self._cpu_type_name = cpu_type
            self.cpu_type = None  # Will be resolved later
        else:
            self.cpu_type = cpu_type
            self._cpu_type_name = None
            
        self.host = host
        self.port = port
        self._config = config
        self._connected = False
    
    def _resolve_cpu_type(self) -> None:
        """
        Resolve the CPU type from string name to CpuType instance.
        This is called during discovery after all CPU types have been registered.
        """
        if self._cpu_type_name is not None and self.cpu_type is None:
            from .registry import get_cpu_type
            resolved_cpu_type = get_cpu_type(self._cpu_type_name)
            if resolved_cpu_type is None:
                raise ValueError(f"CPU type '{self._cpu_type_name}' not found in registry")
            self.cpu_type = resolved_cpu_type
    
    @property
    def architecture(self) -> Architecture:
        """Get the architecture of this setup's CPU."""
        if self.cpu_type is None:
            raise ValueError(f"CPU type not resolved for setup '{self.name}'")
        return self.cpu_type.architecture
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self._config.get(key, default)
    
    def set_config(self, key: str, value: Any) -> None:
        """
        Set a configuration value at runtime.
        
        Args:
            key: Configuration key
            value: New value
        """
        self._config[key] = value
    
    def update_config(self, **config) -> None:
        """
        Update multiple configuration values.
        
        Args:
            **config: Configuration key-value pairs to update
        """
        self._config.update(config)
    
    def connect(self) -> None:
        """
        Establish connection to the test setup.
        
        Default implementation will be provided based on setup attributes.
        Override this method for custom connection logic.
        """
        # Default implementation - to be expanded later
        self._connected = True
    
    def disconnect(self) -> None:
        """
        Disconnect from the test setup.
        
        Default implementation will be provided based on setup attributes.
        Override this method for custom disconnection logic.
        """
        # Default implementation - to be expanded later
        self._connected = False
    
    def is_available(self) -> bool:
        """
        Check if the setup is available for testing.
        
        Default implementation will be provided based on setup attributes.
        Override this method for custom availability checks.
        
        Returns:
            True if setup is available, False otherwise
        """
        # Default implementation - to be expanded later
        return True
    
    def __str__(self):
        if self.cpu_type is None:
            return f"{self.name} (CPU type not resolved)"
        return f"{self.name} ({self.cpu_type})"
    
    def __repr__(self):
        cpu_name = self.cpu_type.name if self.cpu_type is not None else "None"
        return f"TestSetup({self.name!r}, {cpu_name!r}, {self.host!r}:{self.port})"

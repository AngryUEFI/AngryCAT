"""
Test setup registry and dynamic loading system.
"""

import os
import sys
import importlib.util
from pathlib import Path

from .base import Architecture, CpuType, TestSetup


# Global registries
_setup_registry: dict[str, TestSetup] = {}
_cpu_type_registry: dict[str, CpuType] = {}
_architecture_registry: dict[str, Architecture] = {}
_discovery_completed: bool = False


def _get_setup_directories() -> list[Path]:
    """
    Get all directories to search for test setup definitions.
    
    Returns:
        List of Path objects for setup directories
    """
    directories = []
    
    # 1. Built-in testsetups directory in the module itself
    builtin_dir = Path(__file__).parent / "testsetups"
    if builtin_dir.exists() and builtin_dir.is_dir():
        directories.append(builtin_dir)
    
    # 2. Development testsetups directory relative to project root
    try:
        current = Path(__file__).resolve()
        for parent in current.parents:
            if (parent / "pyproject.toml").exists():
                dev_dir = parent / "testsetups"
                if dev_dir.exists() and dev_dir.is_dir() and dev_dir != builtin_dir:
                    directories.append(dev_dir)
                break
    except (OSError, RecursionError):
        pass
    
    # 3. Additional directories from environment variable
    env_dirs = os.environ.get("ANGRYCAT_TESTSETUP_DIRS", "")
    if env_dirs:
        for dir_path in env_dirs.split(os.pathsep):
            if dir_path:
                try:
                    path = Path(dir_path).resolve()
                    if path.exists() and path.is_dir() and path not in directories:
                        directories.append(path)
                except (OSError, RecursionError):
                    print(f"Warning: Could not resolve path '{dir_path}', skipping.")
                    continue
    
    return directories


def _resolve_template_path(
    template_update: str | Path | None,
    source_file: Path,
    search_dirs: list[Path]
) -> Path | None:
    """
    Resolve a template update path based on the input format.
    
    Args:
        template_update: Template path specification (Path, filename, or relative path)
        source_file: Path to the file containing the CPU definition
        search_dirs: List of directories to search for .bin files
        
    Returns:
        Resolved absolute Path or None if not found
    """
    if template_update is None:
        return None
    
    # Case 1: Already an absolute Path
    if isinstance(template_update, Path):
        if template_update.is_absolute():
            return template_update
        # Relative Path - resolve relative to source file directory
        try:
            resolved = (source_file.parent / template_update).resolve()
            return resolved if resolved.exists() else None
        except (OSError, RecursionError):
            return None
    
    # Convert string to Path for processing
    template_path = Path(template_update)
    
    # Case 2: Just a filename (no path separators) - search in all setup directories
    if template_path.name == template_update and template_update.endswith('.bin'):
        for search_dir in search_dirs:
            try:
                for bin_file in search_dir.glob("**/*.bin"):
                    if bin_file.name == template_update:
                        return bin_file
            except (OSError, RecursionError):
                continue
        return None
    
    # Case 3: Relative path string - resolve relative to source file
    try:
        resolved = (source_file.parent / template_path).resolve()
        return resolved if resolved.exists() else None
    except (OSError, RecursionError):
        return None


def _load_definitions_from_file(filepath: Path) -> tuple[list[TestSetup], list[CpuType], list[Architecture]]:
    """
    Load test setup, CPU type, and architecture definitions from a Python file.
    
    Args:
        filepath: Path to Python file containing definitions
        
    Returns:
        Tuple of (setups, cpu_types, architectures) found in the file
    """
    setups = []
    cpu_types = []
    architectures = []
    
    # Load the module
    spec = importlib.util.spec_from_file_location(f"testsetup_{filepath.stem}", filepath)
    if spec is None or spec.loader is None:
        return setups, cpu_types, architectures
    
    module = importlib.util.module_from_spec(spec)
    
    # Temporarily add to sys.modules for imports to work
    module_name = f"_angrycat_testsetup_{filepath.stem}"
    sys.modules[module_name] = module
    
    try:
        spec.loader.exec_module(module)
        
        # Look for Architecture, CpuType, and TestSetup instances
        for attr_name in dir(module):
            if attr_name.startswith("_"):
                continue
            if attr_name.startswith("example_"):
                continue
            
            try:
                attr = getattr(module, attr_name)
            except Exception:
                continue
            
            # Check if it's a TestSetup instance
            if isinstance(attr, TestSetup):
                setups.append(attr)
            
            # Check if it's a CpuType instance
            elif isinstance(attr, CpuType):
                cpu_types.append(attr)
            
            # Check if it's an Architecture instance
            elif isinstance(attr, Architecture):
                architectures.append(attr)
            
            # Check if it's a callable that might return definitions
            elif callable(attr):
                func_name_lower = attr_name.lower()
                if any(prefix in func_name_lower for prefix in ["get_", "load_", "create_"]):
                    try:
                        result = attr()
                        if isinstance(result, TestSetup):
                            setups.append(result)
                        elif isinstance(result, CpuType):
                            cpu_types.append(result)
                        elif isinstance(result, Architecture):
                            architectures.append(result)
                        elif isinstance(result, list):
                            for item in result:
                                if isinstance(item, TestSetup):
                                    setups.append(item)
                                elif isinstance(item, CpuType):
                                    cpu_types.append(item)
                                elif isinstance(item, Architecture):
                                    architectures.append(item)
                    except Exception:
                        pass
    
    except Exception as e:
        print(f"Warning: Failed to load definitions from {filepath}: {e}")
    
    finally:
        # Clean up
        if module_name in sys.modules:
            del sys.modules[module_name]
    
    return setups, cpu_types, architectures


def discover_setups() -> None:
    """
    Discover and load all test setups, CPU types, and architectures from configured directories.
    
    This function follows these steps:
    1. Collect directories to search (built-in + user-supplied)
    2. Scan directories for *.py files (excluding __init__.py and example_*)
    3. For each file: scan for CPUs, then Architectures, then TestSetups
    4. Instantiate and register CPUs, Architectures, then TestSetups
    """
    global _discovery_completed
    
    # Skip if already completed
    if _discovery_completed:
        return
    
    # Mark as in progress to prevent concurrent calls
    _discovery_completed = True
    
    global _setup_registry, _cpu_type_registry, _architecture_registry
    
    # Step 1: Collect directories to search
    directories = _get_setup_directories()
    
    # Step 2: Scan directories for *.py files
    python_files = []
    for directory in directories:
        try:
            for py_file in directory.glob("*.py"):
                # Exclude __init__.py and example_*
                if py_file.name == "__init__.py":
                    continue
                if py_file.name.startswith("example_"):
                    continue
                python_files.append(py_file)
        except (OSError, RecursionError) as e:
            print(f"Warning: Could not process directory '{directory}': {e}")
            continue
    
    # Step 3: For each file, scan for CPUs, then Architectures, then TestSetups
    all_cpu_types = []
    all_architectures = []
    all_setups = []
    
    for py_file in python_files:
        try:
            setups, cpu_types, architectures = _load_definitions_from_file(py_file)
            
            # Collect all definitions
            all_cpu_types.extend(cpu_types)
            all_architectures.extend(architectures)
            all_setups.extend(setups)
            
        except Exception as e:
            print(f"Warning: Failed to load file '{py_file}': {e}")
            continue
    
    # Step 4: Instantiate and register in order: CPUs, Architectures, TestSetups
    
    # 4a. Register CPU types first
    for cpu_type in all_cpu_types:
        # Resolve template paths for CPU types
        if hasattr(cpu_type, '_template_update_raw') and cpu_type.template_update is None:
            try:
                # Find the source file for this CPU type
                source_file = None
                for py_file in python_files:
                    try:
                        setups, cpu_types, architectures = _load_definitions_from_file(py_file)
                        if cpu_type in cpu_types:
                            source_file = py_file
                            break
                    except Exception:
                        continue
                
                if source_file:
                    resolved_path = _resolve_template_path(
                        cpu_type._template_update_raw,
                        source_file,
                        directories
                    )
                    cpu_type.template_update = resolved_path
            except Exception as e:
                print(f"Warning: Could not resolve template path for {cpu_type.name}: {e}")
                cpu_type.template_update = None
        
        _cpu_type_registry[cpu_type.name] = cpu_type
    
    # 4b. Register architectures
    for arch in all_architectures:
        _architecture_registry[arch.name] = arch
    
    # 4c. Register setups last (after CPUs and architectures are available)
    for setup in all_setups:
        # Resolve CPU type if it was specified as a string
        try:
            setup._resolve_cpu_type()
        except ValueError as e:
            print(f"Warning: Setup '{setup.name}' has invalid CPU type: {e}")
            continue
        
        if setup.cpu_type is None:
            print(f"Warning: Setup '{setup.name}' has no CPU type, skipping.")
            continue
        _setup_registry[setup.name] = setup


def register_setup(setup: TestSetup) -> None:
    """
    Manually register a test setup.
    
    Args:
        setup: TestSetup instance to register
    """
    global _setup_registry
    _setup_registry[setup.name] = setup


def register_cpu_type(cpu_type: CpuType) -> None:
    """
    Manually register a CPU type.
    
    Args:
        cpu_type: CpuType instance to register
    """
    global _cpu_type_registry
    _cpu_type_registry[cpu_type.name] = cpu_type


def register_architecture(architecture: Architecture) -> None:
    """
    Manually register an architecture.
    
    Args:
        architecture: Architecture instance to register
    """
    global _architecture_registry
    _architecture_registry[architecture.name] = architecture


def get_cpu_type(name: str) -> CpuType | None:
    """
    Get a CPU type by name.
    
    Args:
        name: CPU type name
        
    Returns:
        CpuType instance or None if not found
    """
    # Ensure definitions are discovered
    if not _discovery_completed:
        discover_setups()
    
    return _cpu_type_registry.get(name)


def get_all_cpu_types(architecture: str | Architecture | None = None) -> list[CpuType]:
    """
    Get all CPU types, optionally filtered by architecture.
    
    Args:
        architecture: Optional architecture filter
        
    Returns:
        List of CpuType instances
    """
    # Ensure definitions are discovered
    if not _discovery_completed:
        discover_setups()
    
    if architecture is None:
        return list(_cpu_type_registry.values())
    
    arch_name = architecture if isinstance(architecture, str) else architecture.name
    return [
        cpu_type for cpu_type in _cpu_type_registry.values()
        if cpu_type.architecture.name == arch_name
    ]


def get_architecture(name: str) -> Architecture | None:
    """
    Get an architecture by name.
    
    Args:
        name: Architecture name
        
    Returns:
        Architecture instance or None if not found
    """
    # Ensure definitions are discovered
    if not _discovery_completed:
        discover_setups()
    
    return _architecture_registry.get(name)


def get_setup(
    architecture: str | Architecture | None = None,
    name: str | None = None,
    **criteria
) -> TestSetup | None:
    """
    Query for a test setup instance by criteria.
    
    Args:
        architecture: Required architecture (string name or Architecture instance)
        name: Specific setup name to retrieve
        **criteria: Additional criteria to match against setup attributes
        
    Returns:
        First matching TestSetup instance, or None if not found
    """
    # Ensure setups are discovered
    if not _discovery_completed:
        discover_setups()
    
    # Filter by name if specified
    if name:
        return _setup_registry.get(name)
    
    # Filter by architecture and other criteria
    for setup in _setup_registry.values():
        # Check architecture
        if architecture:
            arch_name = architecture if isinstance(architecture, str) else architecture.name
            if setup.architecture.name != arch_name:
                continue
        
        # Check additional criteria
        match = True
        for key, value in criteria.items():
            setup_value = None
            
            # Check in setup config
            if key in setup._config:
                setup_value = setup._config[key]
            # Check in CPU attributes
            elif setup.cpu_type is not None and key in setup.cpu_type.attributes:
                setup_value = setup.cpu_type.attributes[key]
            # Check in architecture attributes
            elif setup.cpu_type is not None and key in setup.architecture.attributes:
                setup_value = setup.architecture.attributes[key]
            # Check as setup attribute
            elif hasattr(setup, key):
                setup_value = getattr(setup, key)
            else:
                match = False
                break
            
            if setup_value != value:
                match = False
                break
        
        if match:
            return setup
    
    return None


def get_all_setups(architecture: str | Architecture | None = None) -> list[TestSetup]:
    """
    Get all test setups, optionally filtered by architecture.
    
    Args:
        architecture: Optional architecture filter
        
    Returns:
        List of matching TestSetup instances
    """
    # Ensure setups are discovered
    if not _discovery_completed:
        discover_setups()
    
    if architecture is None:
        return list(_setup_registry.values())
    
    arch_name = architecture if isinstance(architecture, str) else architecture.name
    return [
        setup for setup in _setup_registry.values()
        if setup.architecture.name == arch_name
    ]
from enum import Enum, auto
from dataclasses import dataclass
import socket
import time
from typing import ByteString, Dict, List, Optional
from pathlib import Path
import requests
import subprocess

from keystone import Ks, KS_ARCH_X86, KS_MODE_64


import logging
logger = logging.getLogger()

from angrycat.util import generate_temp_filename

from angrycat.protocol import (
    Packet,
    PingPacket,
    RebootPacket,
    PacketType,
    CoreStatusResponsePacket,
    GetCoreStatusPacket,
    ReadMsrOnCorePacket,
    MsrResponsePacket,
    StartCorePacket,
    StatusPacket,
    GetCoreCountPacket,
    CoreCountResponsePacket,
    PongPacket,
    SendUcodePacket,
    SendMachineCodePacket,
    ApplyUcodeExecuteTestPacket,
    UcodeExecuteTestResponsePacket,
)

# set some sane defaults for critical parameters
_default_base_config = {
    "zentool_path": "zentool",
}

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


class ConnectionState(Enum):
    """State machine for connection management"""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    RECONNECTING = auto()
    REBOOTING = auto()
    FAILED = auto()


class CoreState(Enum):
    """State machine for individual core status"""
    RUNNING = auto()
    LOCKED_UP = auto()
    BLOCKED = auto()


@dataclass
class CoreInfo:
    """Container for core state information"""
    state: CoreState
    last_status_packet: Optional[CoreStatusResponsePacket] = None
    last_ucode_rev: Optional[int] = None
    
    def __repr__(self):
        return f"CoreInfo(state={self.state.name}, version={self.last_ucode_rev})"


class NetworkError(Exception):
    """Raised when network operations fail"""
    pass


class RebootError(Exception):
    """Raised when reboot operations fail"""
    pass

class TestSetup:
    """
    Base class for test setups.
    
    A test setup represents a physical or virtual system that can execute tests.
    Setups communicate over the network and have instance-specific configurations.
    
    This class can be instantiated directly and will read attributes from the
    definition file to determine connection behavior.

    Design Principles:
    -----------------
    1. State Management: Uses explicit state machines to track connection and core states
    2. Error Recovery: Implements multi-stage recovery (reconnect -> hard reboot -> reconnect)
    3. Automatic Retry: send_packet() automatically retries once after successful recovery
    4. Timeout Handling: Separate timeouts for normal operations and reboot sequences
    5. Automatic Recovery: Optional automatic recovery on network errors
    6. Core Tracking: Maintains state for multiple cores with version information
    7. Ping Verification: Reboot methods verify setup responsiveness via ping packets
    
    State Transition Logic:
    ----------------------
    Connection States:
        DISCONNECTED -> CONNECTING -> CONNECTED
        CONNECTED -> RECONNECTING (on error) -> CONNECTED
        CONNECTED -> REBOOTING (on reboot) -> CONNECTED
        RECONNECTING -> FAILED (after all recovery attempts)
    
    Core States:
        RUNNING <-> LOCKED_UP (detected via status query)
        Any state -> BLOCKED (via mark_core_blocked)
        BLOCKED -> RUNNING (on reboot)
    
    Error Recovery Flow:
    -------------------
    When send_packet() encounters a network error:
    1. Attempt reconnect
    2. Attempt hard reboot
    3. Attempt reconnect again
    4. Retry sending the packet once
    5. If retry fails, raise NetworkError
    
    Reboot Flow:
    -----------
    When reboot() is called:
    1. Hard reboot
    2. Wait for successful ping response (optional, default on)
    3. Reset all blocked cores to RUNNING
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
        self.auto_reboot_on_error = True
        self._tried_import_config = False

        # Connection state
        self._state = ConnectionState.DISCONNECTED
        self._socket: Optional[socket.socket] = None
        # delayed init
        self._cores = dict[int, CoreInfo]()
        self._socket_timeout = 3.0
        self.reboot_timeout = 30.0
        self.after_reboot_delay = 3.0
        self.auto_start_cores = True
        self._cores_started = False
        # just a shortcut
        self._ucode_revision_msr = 0x0
        self._cached_core_count = 0
    
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
            self._ucode_revision_msr = self.architecture.attributes.get("ucode_revision_msr", 0x0)
    
    @property
    def architecture(self) -> Architecture:
        """Get the architecture of this setup's CPU."""
        if self.cpu_type is None:
            raise ValueError(f"CPU type not resolved for setup '{self.name}'")
        return self.cpu_type.architecture
    
    @property
    def state(self) -> ConnectionState:
        """Get current connection state"""
        return self._state

    @property
    def socket_timeout(self) -> float:
        """Get the socket timeout"""
        return self._socket_timeout

    @socket_timeout.setter
    def socket_timeout(self, value: float) -> None:
        """Set the socket timeout"""
        self._socket_timeout = value
        if self._socket is not None:
            self._socket.settimeout(value)
    
    @property
    def is_connected(self) -> bool:
        """Check if currently connected"""
        return self._state == ConnectionState.CONNECTED

    def _transition_state(self, new_state: ConnectionState) -> None:
        """
        Transition to a new connection state with logging.
        
        This provides a single point for state transitions, making it easier
        to debug state machine behavior and add hooks if needed.
        """
        old_state = self._state
        self._state = new_state
        logger.debug(f"State transition: {old_state.name} -> {new_state.name}")
        if new_state == ConnectionState.CONNECTED:
            self._reset_blocked_cores()
            if not self._cores_started:
                if self.auto_start_cores:
                    self.start_all_cores()
                self._cores_started = True
        elif new_state == ConnectionState.REBOOTING:
            self._reset_blocked_cores()
            self._cores_started = False
    
    def _create_socket(self) -> socket.socket:
        """
        Create and configure a new socket.
        
        Returns:
            Configured socket object
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.socket_timeout)
        return sock

    def _import_config(self) -> None:
        """
        Import the configuration for the test setup.
        """
        if not self._tried_import_config:
            self._tried_import_config = True
            from .registry import get_all_config
            global_config = get_all_config()
            self._config.update(global_config)
            # merge in default config if not already set
            for k, v in _default_base_config.items():
                if k not in self._config:
                    self._config[k] = v
    
    def connect(self, allow_retry=True) -> None:
        """
        Establish connection to the test setup.
        
        Raises:
            NetworkError: If connection fails
        """
        self._import_config()
        self._transition_state(ConnectionState.CONNECTING)
        
        try:
            self._socket = self._create_socket()
            self._socket.connect((self.host, self.port))
            self._transition_state(ConnectionState.CONNECTED)
            logger.info(f"Connected to {self.host}:{self.port}")
        except ConnectionRefusedError as e:
            self._transition_state(ConnectionState.DISCONNECTED)
            self._socket = None
            if allow_retry and self.auto_reboot_on_error:
                logger.warning(f"Failed to connect: {e}. Retrying...")
                self.reboot(False)
                self._wait_for_ping(allow_retry=False)
                return self.connect(allow_retry=False)
            raise NetworkError(f"Failed to connect: {e}")
        except (socket.error, socket.timeout) as e:
            self._transition_state(ConnectionState.DISCONNECTED)
            self._socket = None
            raise NetworkError(f"Failed to connect: {e}")

    
    def disconnect(self) -> None:
        """Close connection to test setup"""
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                logger.warning(f"Error closing socket: {e}")
            finally:
                self._socket = None
        self._transition_state(ConnectionState.DISCONNECTED)
        logger.info("Disconnected from test setup")
    
    def _reconnect(self) -> bool:
        """
        Attempt to reconnect to the test setup.
        
        Returns:
            True if reconnection successful, False otherwise
        """
        logger.info("Attempting to reconnect...")
        self._transition_state(ConnectionState.RECONNECTING)
        
        try:
            self.disconnect()
            self.connect()
            return True
        except NetworkError as e:
            logger.error(f"Reconnection failed: {e}")
            return False
    
    def _handle_network_error(self, error: Exception) -> None:
        """
        Handle network errors with automatic recovery flow.
        
        Recovery Flow:
        1. Try reconnecting
        2. Try hard reboot
        3. Try reconnecting again
        4. Fail with exception
        
        Args:
            error: The original network error
            
        Raises:
            NetworkError: If all recovery attempts fail
        """
        if not self.auto_reboot_on_error:
            raise NetworkError(f"Network error (auto-reboot disabled): {error}")
        
        logger.warning(f"Network error detected: {error}. Starting recovery...")
        
        # Step 1: Try reconnecting
        if self._reconnect():
            logger.info("Recovery successful via reconnect")
            return
        
        # Step 2: Try hard reboot
        logger.info("Reconnect failed, attempting hard reboot...")
        try:
            self._perform_hard_reboot()
        except RebootError as e:
            logger.error(f"Hard reboot failed: {e}")
        
        # Step 3: Try reconnecting again
        if self._reconnect():
            logger.info("Recovery successful after hard reboot")
            return
        
        # Step 4: All recovery attempts failed
        self._transition_state(ConnectionState.FAILED)
        raise NetworkError(f"All recovery attempts failed. Original error: {error}")
    
    def send_packet(self, packet: Packet, _retry_after_reboot: bool = True) -> None:
        """
        Send a packet to the test setup.
        
        If a network error occurs and auto_reboot_on_error is enabled,
        the error recovery flow is triggered. After recovery, the packet
        send is retried once. If it fails again, an exception is raised.
        
        Args:
            packet: Raw packet data to send
            _retry_after_reboot: Internal flag to prevent infinite retry loop
            
        Raises:
            NetworkError: If not connected or send fails after recovery
        """
        if not self.is_connected or not self._socket:
            raise NetworkError("Not connected to test setup")
        
        try:
            buf = packet.pack()
            self._socket.sendall(buf)
            logger.debug(f"Sent {packet.message_type.name}: {len(buf)} bytes")
        except (socket.error, socket.timeout) as e:
            logger.error(f"Failed to send packet: {e}")
            
            # Only attempt recovery and retry if this is the first attempt
            if _retry_after_reboot and self.auto_reboot_on_error:
                try:
                    self._handle_network_error(e)
                    # Recovery successful, retry sending the packet
                    logger.info("Retrying packet send after recovery...")
                    self.send_packet(packet, _retry_after_reboot=False)
                except NetworkError:
                    # Recovery failed or second send failed
                    raise
            else:
                # Either retry is disabled or this is already a retry
                raise NetworkError(f"Failed to send packet: {e}")
    
    def receive_packets(self) -> list[Packet]:
        """
        Receive packets from the test setup.

        Returns:
            Received packets
            
        Raises:
            NetworkError: If not connected or receive fails
        """
        if not self.is_connected or not self._socket:
            raise NetworkError("Not connected to test setup")
        
        try:
            pkts = Packet.read_messages(self._socket)
            logger.debug(f"Received packets: {len(pkts)}")
            return pkts
        except (socket.error, socket.timeout) as e:
            logger.warning(f"Failed to receive packet: {e}")
            self._handle_network_error(e)
            return []
    
    def _send_ping_packet(self) -> bool:
        """
        Send a ping packet to check if the test setup is responsive.
        
        This calls an existing ping function. Ping packets can themselves
        trigger network errors if the setup is not ready.
        
        Returns:
            True if ping successful, False otherwise
        """
        try:
            ping_packet = PingPacket(message=b"ping")
            self.send_packet(ping_packet, _retry_after_reboot=False)
            response = self.receive_packets()
            if len(response) != 1:
                return False
            if response[0].message_type != PacketType.PONG:
                return False
            return True
        except (NetworkError, socket.error, socket.timeout) as e:
            logger.debug(f"Ping failed: {e}")
            return False
    
    def _wait_for_ping(self, allow_retry=True) -> None:
        """
        Wait for successful ping response after reboot.
        
        Attempts to ping the test setup repeatedly until either:
        - A successful ping is received
        - The reboot_timeout period expires
        
        Raises:
            RebootError: If no successful ping received within timeout
        """
        logger.info(f"Waiting up to {self.reboot_timeout}s for ping response...")
        start_time = time.time()
        ping_interval = 2.0  # Try ping every 2 seconds
        
        while (time.time() - start_time) < self.reboot_timeout:
            # Try to reconnect if not connected
            if not self.is_connected:
                try:
                    self.connect(allow_retry=allow_retry)
                except NetworkError:
                    # Not ready yet, continue waiting
                    pass
            
            # Try to ping
            if self.is_connected and self._send_ping_packet():
                elapsed = time.time() - start_time
                logger.info(f"Ping successful after {elapsed:.1f}s")
                return
            
            # Wait before next attempt
            time.sleep(ping_interval)
        
        # Timeout reached without successful ping
        raise RebootError(
            f"No ping response received within {self.reboot_timeout}s timeout"
        )
    
    def send_reboot_packet(self, wait_for_ping: bool = True) -> None:
        """
        Send a reboot command packet to the test setup.
        
        This implements a "soft" reboot via network command.
        After sending, optionally waits for successful ping response.
        
        Args:
            wait_for_ping: If True, wait for ping response after reboot
        
        Raises:
            RebootError: If reboot packet fails or ping timeout occurs
        """
        logger.info("Sending reboot packet...")
        self._transition_state(ConnectionState.REBOOTING)
        
        try:
            reboot_packet = RebootPacket()
            self.send_packet(reboot_packet, _retry_after_reboot=False)
            
            # Disconnect and wait for reboot
            self.disconnect()
            
            if wait_for_ping:
                self._wait_for_ping()
            else:
                time.sleep(self.after_reboot_delay)
            
        except Exception as e:
            if isinstance(e, RebootError):
                raise
            raise RebootError(f"Failed to send reboot packet: {e}")
    
    def _perform_hard_reboot(self, wait_for_ping: bool = True) -> None:
        """
        Trigger a hardware reboot of the test setup.
        
        More reliable than soft reboot.
        
        Args:
            wait_for_ping: If True, wait for ping response after reboot
        
        Raises:
            RebootError: If hard reboot fails or ping timeout occurs
        """
        logger.info("Triggering hard reboot...")
        self._transition_state(ConnectionState.REBOOTING)
        
        self.pin_reset()
        try:
            if wait_for_ping:
                self._wait_for_ping()
            
            logger.info("Hard reboot completed")
        except Exception as e:
            if isinstance(e, RebootError):
                raise
            raise RebootError(f"Hard reboot failed: {e}")
    
    def reboot(self, wait_for_ping: bool = True) -> None:
        """
        Reboot the test setup.

        After successful reboot, optionally waits for ping response to
        confirm the setup is responsive. All blocked cores are reset to RUNNING.
        
        Args:
            wait_for_ping: If True (default), wait for successful ping after reboot
        
        Raises:
            RebootError: If both reboot methods fail or ping timeout occurs
        """
        logger.info("Initiating reboot sequence...")
        
        try:
            self._perform_hard_reboot(wait_for_ping=wait_for_ping)
            logger.info("Reboot successful (via hard reboot)")
        except RebootError as e:
            raise RebootError(f"Both reboot methods failed: {e}")
    
    def _reset_blocked_cores(self) -> None:
        """
        Reset all blocked cores to RUNNING state after reboot.
        
        This is called automatically after successful reboot operations.
        Locked up cores are not automatically reset - they require explicit
        status query to determine if they recovered.
        """
        for core_id, core_info in self._cores.items():
            if core_info.state == CoreState.BLOCKED:
                core_info.state = CoreState.RUNNING
                logger.info(f"Core {core_id} unblocked after reboot")
    
    def mark_core_dead(self, core_id: int) -> None:
        """
        Mark a core as administratively blocked.
        
        Blocked cores will not be used until explicitly unblocked or
        until a reboot occurs.
        
        Args:
            core_id: ID of the core to block
        """
        if core_id not in self._cores:
            self._cores[core_id] = CoreInfo(state=CoreState.BLOCKED)
        
        old_state = self._cores[core_id].state
        self._cores[core_id].state = CoreState.BLOCKED
        logger.info(f"Core {core_id} marked as blocked (was {old_state.name})")
    
    def get_core_status(self, core_id: int) -> CoreStatusResponsePacket:
        """
        Query the current status of a core.
        
        This queries the actual hardware state via network packets.
        
        Args:
            core_id: ID of the core to query
            
        Returns:
            Current state of the core
            
        Raises:
            NetworkError: If query fails
        """

        pkt = GetCoreStatusPacket(core=core_id)
        self.send_packet(pkt)
        response = self.receive_packets()
        if len(response) != 1:
            raise NetworkError(f"Invalid response to GetCoreStatusPacket: {response}")
        if not isinstance(response[0], CoreStatusResponsePacket):
            raise NetworkError(f"Invalid response to GetCoreStatusPacket: {response}")
        return response[0]
    
    def get_ucode_revision(self, core_id: int) -> Optional[int]:
        """
        Query the code version running on a core.
        
        This queries the actual ucode version via network packets.
        
        Args:
            core_id: ID of the core to query
            
        Returns:
            Ucode version
            
        Raises:
            NetworkError: If query fails
        """

        if self.cpu_type is None:
            raise ValueError(f"CPU type not resolved for setup '{self.name}'")
        version = self.read_msr(core_id, self._ucode_revision_msr)
        return version

    def _is_core_blocked(self, core_id: int) -> bool:
        """
        Check if a core is blocked.
        """
        if core_id not in self._cores:
            self._cores[core_id] = CoreInfo(state=CoreState.RUNNING)
        return self._cores[core_id].state == CoreState.BLOCKED
    
    def read_msr(self, core_id: int, msr: int) -> Optional[int]:
        """
        Read an MSR on a core.

        Args:
            core_id: ID of the core to read the MSR on
            msr: MSR to read

        Returns:
            Value of the MSR
        """
        if self._is_core_blocked(core_id):
            logger.warning(f"Tried reading MSR on blocked core {core_id}.")
            return None
        pkt = ReadMsrOnCorePacket(target_msr=msr, target_core=core_id)
        self.send_packet(pkt)
        response = self.receive_packets()
        if len(response) != 1:
            raise NetworkError(f"Invalid response to ReadMsrOnCorePacket: {response}")
        if isinstance(response[0], StatusPacket):
            pkt = response[0]
            if pkt.status_code in [0x205, 0x2]:
                logger.warning(f"Core {core_id} is blocked! Status code: {pkt.status_code}, message: {pkt.text}")
                self.mark_core_dead(core_id)
                return None
        if not isinstance(response[0], MsrResponsePacket):
            raise NetworkError(f"Invalid response to ReadMsrOnCorePacket: {response}")
        val = (response[0].edx << 32) | response[0].eax
        if msr == self.architecture.attributes.get("ucode_revision_msr", 0x0):
            self._update_core_status(core_id, patch_revision=val)
            logger.info(f"Ucode revision on core {core_id}: 0x{val:x}.")
        logger.debug(f"MSR 0x{msr:x} on core {core_id}: 0x{val:x}")
        return val
    
    def get_all_cores_info(self) -> Dict[int, CoreInfo]:
        """
        Get information about all cores.
        
        Returns:
            Dictionary mapping core ID to CoreInfo
        """
        return self._cores.copy()

    def _have_ha_setup(self):
        if self._config.get("ha_token") is not None and self._config.get("ha_entity_name") is not None and self._config.get("ha_base_url") is not None:
            return True
        logger.warning(f"No HA config for setup {self.name}!")
        return False

    def _send_pin_action(self, pin_name):
        custom_pin_action = self._config.get("_custom_pin_action")
        if custom_pin_action is not None:
            return custom_pin_action(self, pin_name)
        if self._have_ha_setup():
            entity_name = f"switch.{self._config.get('ha_entity_name')}_{pin_name}"

            headers = {
                "Authorization": f"Bearer {self._config.get('ha_token')}",
                "Content-Type": "application/json"
            }
            payload = {
                "entity_id": entity_name
            }
            
            response = requests.post(f"{self._config.get('ha_base_url')}/api/services/switch/turn_on", json=payload, headers=headers)

            return response.status_code == 200

    def pin_reset(self) -> None:
        self._transition_state(ConnectionState.REBOOTING)
        logger.info(f"Resetting {self.name}.")
        self._send_pin_action("reset_pin")
        time.sleep(self.after_reboot_delay)

    def pin_power(self, long: bool = False):
        self._transition_state(ConnectionState.REBOOTING)
        if long:
            logger.info(f"Long power press {self.name}.")
            return self._send_pin_action("power_pin_long")
        else:
            logger.info(f"Short power press {self.name}.")
            return self._send_pin_action("power_pin_short")

    def get_led_status(self):
        custom_led_status = self._config.get("_custom_led_status")
        if custom_led_status is not None:
            return custom_led_status(self)
        logger.warning("LED status is not implemented.")
        return False

    def start_all_cores(self):
        for core_state in self._cores.values():
            if core_state.state == CoreState.LOCKED_UP:
                core_state.state = CoreState.RUNNING
        return self.start_core(0)

    def start_core(self, core_number):
        pkt = StartCorePacket(core = core_number)
        self.send_packet(pkt)

        pkts = self.receive_packets()
        if len(pkts) != 1 or not isinstance(pkts[0], StatusPacket):
            raise ValueError("Unable to get core count.")
        pkt = pkts[0]
        if pkt.status_code != 0:
            raise ValueError(f"Status code {pkt.status_code}, message: {pkt.text}")

    def get_core_count(self, force_refresh=False):
        if force_refresh or self._cached_core_count == 0:
            self._cached_core_count = self._get_core_count()
        return self._cached_core_count

    def _get_core_count(self):
        pkt = GetCoreCountPacket()
        self.send_packet(pkt)

        pkts = self.receive_packets()
        if len(pkts) != 1 or not isinstance(pkts[0], CoreCountResponsePacket):
            raise ValueError("Unable to get core count.")
        return pkts[0].core_count

    def wait_for_ready(self):
        return self._wait_for_ping()
    
    def _update_core_status(self, core_number: int, status_packet = None, patch_revision = None):
        if core_number not in self._cores:
            self._cores[core_number] = CoreInfo(state=CoreState.RUNNING)
        if status_packet is not None:
            self._cores[core_number].last_status_packet = status_packet
            if not status_packet.ready:
                self._cores[core_number].state = CoreState.LOCKED_UP
        if patch_revision is not None:
            self._cores[core_number].last_ucode_rev = patch_revision

    def ping(self, msg="Hello AngryUEFI!") -> bool:
        ping_packet = PingPacket(message=msg.encode())
        self.send_packet(ping_packet)
        response = self.receive_packets()
        if len(response) != 1 or not isinstance(response[0], PongPacket):
            return False
        return True

    def refresh_core(self, core_number):
        if self._is_core_blocked(core_number):
            return
        core_status = self.get_core_status(core_number)
        res = None
        if core_status.started:
            res = self.get_ucode_revision(core_number)

        self._update_core_status(core_number, patch_revision=res, status_packet=core_status)
    
    def refresh_cores(self):
        core_count = self.get_core_count()
        for core in range(core_count):
            self.refresh_core(core)

    def ready_clean_setup(self, do_reboot=False):
        if not self.is_connected:
            self.connect()
        if do_reboot:
            self.reboot()
        self.wait_for_ready()
        self.start_all_cores()
        self.refresh_cores()

    def determine_free_core(self, allow_reboot=True, allow_boot_core=False) -> int:
        self.refresh_cores()
        for k, v in self._cores.items():
            if not allow_boot_core and k == 0:
                continue
            if v.state == CoreState.BLOCKED:
                continue
            if v.state == CoreState.LOCKED_UP:
                continue
            if v.last_status_packet is None or not v.last_status_packet.started or not v.last_status_packet.ready:
                continue
            logger.debug(f"Selected free core {k}.")
            return k
        
        if not allow_reboot:
            raise ValueError(f"No ready cores and no (further) reboot allowed.")

        logger.debug(f"No ready core, requesting reboot")
        self.reboot()

        return self.determine_free_core(allow_reboot=False, allow_boot_core=allow_boot_core)

    @classmethod
    def _get_ucode_temp_path(cls, cpu_name: str, base_dir: str = "/tmp/angrycat_ucode_blobs/"):
        return generate_temp_filename({"cpu":cpu_name}, base_dir)

    def _exec_zentool(self, args):
        if self._config.get("zentool_path") is None:
            raise ValueError("zentool path is not set.")
        
        result = subprocess.run([self._config.get("zentool_path")] + args, check=False, capture_output=True, text=True)
        return result
    
    def _assemble_zentool(self, ucode: List[str], **kwargs) -> bytes:
        result = self._exec_zentool(["--version"])
        if result.returncode != 0:
            raise ValueError(f"Unable to execute zentool, got return code {result.returncode}. Check path.")

        if self.cpu_type is None:
            raise ValueError("CPU type not resolved for setup '{self.name}'")
        temp_file = self._get_ucode_temp_path(self.cpu_type.name)
        default_options = [
            f"--output={temp_file}",
            "edit",
        ]
        add_donor_file = kwargs.pop("zentool_default_donor_file", True)

        args = default_options[:]
        args.extend(ucode)
        if add_donor_file:
            args.append(str(self.cpu_type.template_update))

        result = self._exec_zentool(args)
        if result.returncode != 0:
            logger.warning(f"Zentool assemble returned returncode:{result.returncode}")
            logger.warning(f"Zentool assemble returned stdout:\n{result.stdout}")
            logger.warning(f"Zentool assemble returned stderr:\n{result.stderr}")
            raise ValueError(f"Unable to assemble via zentool, got code {result.returncode}")

        args = [
            "resign",
            temp_file
        ]
        result = self._exec_zentool(args)
        if result.returncode != 0:
            logger.warning(f"Zentool resign returned returncode:{result.returncode}")
            logger.warning(f"Zentool resign returned stdout:\n{result.stdout}")
            logger.warning(f"Zentool resign returned stderr:\n{result.stderr}")
            raise ValueError(f"Unable to resign via zentool, got code {result.returncode}")

        return bytes(open(temp_file, "rb").read())

    def assemble_ucode(self, ucode: str | List[str] | ByteString, **kwargs) -> bytes:
        if isinstance(ucode, (bytes, bytearray, memoryview)):
            return bytes(ucode)
        elif isinstance(ucode, str):
            # pass to ZenUtils macro assembler
            raise ValueError("Not implemented: ZenUtils macro assembler")
        elif isinstance(ucode, List) and all(isinstance(x, str) for x in ucode):
            # list of arguments to zentool
            return self._assemble_zentool(ucode, **kwargs)
        else:
            raise TypeError(
                f"Invalid type for ucode: {type(ucode)}. "
                "Expected str, List[str], or ByteString."
            )
    
    def send_ucode(self, ucode: str | List[str] | ByteString, slot_number: int = 1, **kwargs):
        ucode_buf = self.assemble_ucode(ucode, **kwargs)

        pkt = SendUcodePacket(target_slot=slot_number, ucode = ucode_buf)
        self.send_packet(pkt)

        pkts = self.receive_packets()
        if len(pkts) != 1 or not isinstance(pkts[0], StatusPacket):
            raise ValueError(f"Unable to send ucode, got invalid response.")
        resp = pkts[0]
        if resp.status_code != 0:
            raise ValueError(f"Status code {resp.status_code}, message: {resp.text}")

    def assemble_machine_code(self, assembly: str) -> bytes:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        mc, count = ks.asm(assembly, 0x1000)
        logger.debug(f"Assembled {count} bytes.")
        return bytes(mc)  # pyright: ignore[reportArgumentType]

    def send_machine_code(self, machine_code: str | ByteString, target_slot=1):
        mc = None
        if isinstance(machine_code, str):
            mc = self.assemble_machine_code(machine_code)
        elif isinstance(machine_code, (bytes, bytearray, memoryview)):
            mc = bytes(machine_code)
        else:
            raise TypeError(
                f"Invalid type for machine code: {type(machine_code)}. "
                "Expected str or ByteString."
            )

        pkt = SendMachineCodePacket(target_slot=target_slot, machine_code=mc)
        self.send_packet(pkt)

        pkts = self.receive_packets()
        if len(pkts) != 1 or not isinstance(pkts[0], StatusPacket):
            raise ValueError(f"Unable to send machine code, got invalid response.")
        resp = pkts[0]
        if resp.status_code != 0:
            raise ValueError(f"Status code {resp.status_code}, message: {resp.text}")

    def apply_ucode_execute_mc(self, core_number=None, ucode_slot=1, mc_slot=1, timeout=100, apply_known_good=False, mark_core_dead=False):
        if core_number is None:
            core_number = self.determine_free_core()
        if mark_core_dead:
            self.mark_core_dead(core_number)
        pkt = ApplyUcodeExecuteTestPacket(target_ucode_slot=ucode_slot, target_machine_code_slot=mc_slot, target_core=core_number, timeout=timeout, apply_known_good=apply_known_good)
        self.send_packet(pkt)

        pkts = self.receive_packets()
        if len(pkts) != 1 or not isinstance(pkts[0], UcodeExecuteTestResponsePacket):
            raise ValueError(f"Invalid response to apple & execute test.")
        return pkts[0]

    def run_test(self, ucode: str | List[str] | ByteString | int, machine_code: str | ByteString | int, core_number = None, timeout = 100, apply_known_good=False, mark_core_dead=False):
        ucode_slot = ucode
        if not isinstance(ucode, int):
            ucode_slot = 1
            self.send_ucode(ucode, ucode_slot)
        mc_slot = machine_code
        if not isinstance(machine_code, int):
            mc_slot = 1
            self.send_machine_code(machine_code, mc_slot)
        
        return self.apply_ucode_execute_mc(core_number, ucode_slot, mc_slot, timeout, apply_known_good, mark_core_dead)  # pyright: ignore[reportArgumentType]


    
    def __str__(self):
        if self.cpu_type is None:
            return f"{self.name} (CPU type not resolved)"
        return f"{self.name} ({self.cpu_type})"
    
    def __repr__(self):
        cpu_name = self.cpu_type.name if self.cpu_type is not None else "None"
        return f"TestSetup({self.name!r}, {cpu_name!r}, {self.host!r}:{self.port})"

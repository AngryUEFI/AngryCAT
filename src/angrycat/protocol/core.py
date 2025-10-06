#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class CoreStatusFaultInfo:
    """
    Core fault information structure.
    
    Contains detailed CPU state at the time of a fault including
    registers, control registers, and fault details.
    """
    def __init__(self, data: bytes):
        if len(data) < 216:
            raise ValueError(f"Expected ≥216 bytes, got {len(data)}")
        fields = struct.unpack("<27Q", data[:216])
        (
            self.fault_occured, self.fault_number, self.error_code, self.old_rip,
            self.rax_value, self.rbx_value, self.rcx_value, self.rdx_value,
            self.rsi_value, self.rdi_value, self.rsp_value, self.rbp_value,
            self.r8_value, self.r9_value, self.r10_value, self.r11_value,
            self.r12_value, self.r13_value, self.r14_value, self.r15_value,
            self.rflags_value, self.cr0_value, self.cr2_value, self.cr3_value,
            self.cr4_value, self.cs_value, self.original_rsp
        ) = fields

    def description(self):
        """Short description of the fault."""
        return (f"Fault#=0x{self.fault_number:016X}, "
                f"Err=0x{self.error_code:016X}, RIP=0x{self.old_rip:016X}")

    def long_description(self):
        """Detailed description with all register values."""
        attrs = [a for a in dir(self) if a.endswith("_value") or a in ("fault_number","error_code","old_rip")]
        return "\n".join(f"{name}: 0x{getattr(self,name):016X}" for name in attrs)


class GetCoreCountPacket(Packet):
    """
    GETCORECOUNT request packet (ID: 0x211).
    
    Returns the core count of the system.
    Responds with CORECOUNTRESPONSE.
    """
    message_type = PacketType.GETCORECOUNT
    
    def __init__(self, *, payload: bytes | None = None):
        pass
    
    def pack(self):
        hdr = struct.pack("<I4B I",
                          8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr
    
    def __repr__(self):
        return "GetCoreCountPacket()"


class CoreCountResponsePacket(Packet):
    """
    CORECOUNTRESPONSE packet (ID: 0x80000211).
    
    Response to GETCORECOUNT.
    Contains the number of cores in the system.
    """
    message_type = PacketType.CORECOUNTRESPONSE
    
    def __init__(self, *, payload: bytes | None = None, core_count: int | None = None):
        if payload is not None:
            self.core_count = struct.unpack("<Q", payload[:8])[0]
        elif core_count is not None:
            self.core_count = core_count
        else:
            raise ValueError("Provide payload or core_count")
    
    def pack(self):
        payload = struct.pack("<Q", self.core_count)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"CoreCountResponsePacket(core_count={self.core_count}, control={self.control})"


class StartCorePacket(Packet):
    """
    STARTCORE request packet (ID: 0x212).
    
    Starts the specified core. Use core=0 to start all available cores.
    Returns a STATUS response.
    """
    message_type = PacketType.STARTCORE
    
    def __init__(self, *, payload: bytes | None = None, core: int | None = None):
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Provide payload or core")
    
    def pack(self):
        payload = struct.pack("<Q", self.core)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"StartCorePacket(core={self.core}, control={self.control})"


class GetCoreStatusPacket(Packet):
    """
    GETCORESTATUS request packet (ID: 0x213).
    
    Gets the status of the specified core.
    Responds with CORESTATUSRESPONSE.
    """
    message_type = PacketType.GETCORESTATUS
    
    def __init__(self, *, payload: bytes | None = None, core: int | None = None):
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Provide payload or core")
    
    def pack(self):
        payload = struct.pack("<Q", self.core)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"GetCoreStatusPacket(core={self.core}, control={self.control})"


class GetLastTestResultPacket(Packet):
    """
    GETLASTTESTRESULT request packet (ID: 0x152).
    
    Gets the last test result from the specified core.
    Returns CORESTATUSRESPONSE followed by UCODEEXECUTETESTRESPONSE.
    """
    message_type = PacketType.GETLASTTESTRESULT
    
    def __init__(self, *, payload: bytes | None = None, core: int | None = None):
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Provide payload or core")
    
    def pack(self):
        payload = struct.pack("<Q", self.core)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"GetLastTestResultPacket(core={self.core}, control={self.control})"


class CoreStatusResponsePacket(Packet):
    """
    CORESTATUSRESPONSE packet (ID: 0x80000213).
    
    Response to GETCORESTATUS and GETLASTTESTRESULT.
    Contains core status flags, heartbeat info, and optional fault info.
    """
    message_type = PacketType.CORESTATUSRESPONSE
    
    def __init__(self, *, payload: bytes | None = None,
                 flags: int | None = None, last_heartbeat: int | None = None,
                 current_rdtsc: int | None = None, fault_info: CoreStatusFaultInfo | None = None):
        if payload is not None:
            self.flags = struct.unpack("<Q", payload[:8])[0]
            self.last_heartbeat = struct.unpack("<Q", payload[8:16])[0]
            self.current_rdtsc  = struct.unpack("<Q", payload[16:24])[0]
            if len(payload) > 24:
                fl = struct.unpack("<Q", payload[24:32])[0]
                self.fault_info = CoreStatusFaultInfo(payload[32:32+fl]) if fl else None
            else:
                self.fault_info = None
        elif None not in (flags, last_heartbeat, current_rdtsc):
            self.flags, self.last_heartbeat, self.current_rdtsc, self.fault_info = flags, last_heartbeat, current_rdtsc, fault_info
        else:
            raise ValueError("Provide payload or flags+heartbeat+rdtsc")
    
    @property
    def present(self):
        """True if the core is present in the system."""
        return bool(self.flags & 0x1)
    
    @property
    def started(self):
        """True if the core has been started."""
        return bool(self.flags & 0x2)
    
    @property
    def ready(self):
        """True if the core is ready to accept a job."""
        return bool(self.flags & 0x4)
    
    @property
    def job_queued(self):
        """True if the core has a queued job."""
        return bool(self.flags & 0x8)
    
    @property
    def is_locked(self):
        """True if the core context is locked."""
        return bool(self.flags & 0x10)
    
    @property
    def faulted(self):
        """True if the core has faulted."""
        return bool(self.flags & 0x20)
    
    def pack(self):
        raise NotImplementedError("For responses only")
    
    def __repr__(self):
        base = (f"CoreStatusResponsePacket(flags=0x{self.flags:016X} "
                f"(present={self.present},started={self.started},ready={self.ready},"
                f"queued={self.job_queued},locked={self.is_locked},faulted={self.faulted}), "
                f"hb={self.last_heartbeat}, rdtsc={self.current_rdtsc}, control={self.control})")
        if self.fault_info:
            base += "\n  Fault: " + self.fault_info.description()
        return base


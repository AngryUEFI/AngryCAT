#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class ReadMsrPacket(Packet):
    """
    READMSR request packet (ID: 0x201).
    
    Reads the specified MSR on the boot core.
    Returns a MSRRESPONSE.
    """
    message_type = PacketType.READMSR
    
    def __init__(self, *, payload: bytes | None = None, target_msr: int | None = None):
        if payload is not None:
            self.target_msr = struct.unpack("<I", payload[:4])[0]
        elif target_msr is not None:
            self.target_msr = target_msr
        else:
            raise ValueError("Provide payload or target_msr")
    
    def pack(self):
        payload = struct.pack("<I", self.target_msr)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"ReadMsrPacket(target_msr=0x{self.target_msr:X}, control={self.control})"


class ReadMsrOnCorePacket(Packet):
    """
    READMSRONCORE request packet (ID: 0x202).
    
    Reads the specified MSR on the specified core.
    Returns a MSRRESPONSE or STATUS if timeout is reached.
    """
    message_type = PacketType.READMSRONCORE
    
    def __init__(self, *, payload: bytes | None = None, target_msr: int | None = None, target_core: int | None = None):
        if payload is not None:
            self.target_msr = struct.unpack("<I", payload[:4])[0]
            self.target_core = struct.unpack("<Q", payload[4:12])[0]
        elif target_msr is not None and target_core is not None:
            self.target_msr, self.target_core = target_msr, target_core
        else:
            raise ValueError("Provide payload or both target_msr & target_core")
    
    def pack(self):
        payload = struct.pack("<I Q", self.target_msr, self.target_core)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"ReadMsrOnCorePacket(target_msr=0x{self.target_msr:X}, target_core={self.target_core}, control={self.control})"


class MsrResponsePacket(Packet):
    """
    MSRRESPONSE packet (ID: 0x80000201).
    
    Response to READMSR and READMSRONCORE.
    Contains EAX and EDX values from the rdmsr instruction.
    """
    message_type = PacketType.MSRRESPONSE
    
    def __init__(self, *, payload: bytes | None = None, eax: int | None = None, edx: int | None = None):
        if payload is not None:
            self.eax, self.edx = struct.unpack("<II", payload[:8])
        elif eax is not None and edx is not None:
            self.eax, self.edx = eax, edx
        else:
            raise ValueError("Provide payload or both eax & edx")
    
    def pack(self):
        payload = struct.pack("<II", self.eax, self.edx)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"MsrResponsePacket(eax=0x{self.eax:X}, edx=0x{self.edx:X}, control={self.control})"


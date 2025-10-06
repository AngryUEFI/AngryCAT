#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class SendMachineCodePacket(Packet):
    """
    SENDMACHINECODE request packet (ID: 0x301).
    
    Stores machine code in the specified slot.
    Returns a STATUS response.
    """
    message_type = PacketType.SENDMACHINECODE
    
    def __init__(self, *, payload: bytes | None = None,
                 target_slot: int | None = None,
                 machine_code: bytes | None = None):
        if payload is not None:
            self.target_slot = struct.unpack("<I", payload[:4])[0]
            sz = struct.unpack("<I", payload[4:8])[0]
            self.machine_code = payload[8:8+sz]
        elif None not in (target_slot, machine_code):
            self.target_slot, self.machine_code = target_slot, machine_code
        else:
            raise ValueError("Provide payload or both target_slot & machine_code")
    
    def pack(self):
        payload = struct.pack("<II", self.target_slot, len(self.machine_code)) + self.machine_code
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"SendMachineCodePacket(target_slot={self.target_slot}, code_size={len(self.machine_code)}, control={self.control})"


class ApplyUcodeExecuteTestPacket(Packet):
    """
    APPLYUCODEEXCUTETEST request packet (ID: 0x151).
    
    Applies microcode and executes machine code test on specified core.
    Returns a UCODEEXECUTETESTRESPONSE.
    """
    message_type = PacketType.APPLYUCODEEXCUTETEST
    
    def __init__(self, *, payload: bytes | None = None,
                 target_ucode_slot: int | None = None,
                 target_machine_code_slot: int | None = None,
                 target_core: int | None = None,
                 timeout: int | None = None,
                 apply_known_good: bool | None = None):
        if payload is not None:
            a,b,c,d,e = struct.unpack("<5I", payload[:20])
            self.target_ucode_slot, self.target_machine_code_slot, self.target_core, self.timeout, opts = a,b,c,d,e
            self.apply_known_good = bool(opts & 0x1)
        elif None not in (target_ucode_slot, target_machine_code_slot, target_core, timeout, apply_known_good):
            self.target_ucode_slot = target_ucode_slot
            self.target_machine_code_slot = target_machine_code_slot
            self.target_core = target_core
            self.timeout = timeout
            self.apply_known_good = apply_known_good
        else:
            raise ValueError("Provide payload or all args")
    
    def pack(self):
        opts = 1 if self.apply_known_good else 0
        payload = struct.pack("<5I",
                              self.target_ucode_slot,
                              self.target_machine_code_slot,
                              self.target_core,
                              self.timeout,
                              opts)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return (f"ApplyUcodeExecuteTestPacket(ucode_slot={self.target_ucode_slot}, "
                f"mc_slot={self.target_machine_code_slot}, core={self.target_core}, "
                f"timeout={self.timeout}, apply_known_good={self.apply_known_good}, control={self.control})")


class ExecuteMachineCodePacket(Packet):
    """
    EXECUTEMACHINECODE request packet (ID: 0x153).
    
    Executes machine code on specified core without applying microcode.
    Returns a UCODEEXECUTETESTRESPONSE.
    """
    message_type = PacketType.EXECUTEMACHINECODE
    
    def __init__(self, *, payload: bytes | None = None,
                 target_machine_code_slot: int | None = None,
                 target_core: int | None = None,
                 timeout: int | None = None):
        if payload is not None:
            self.target_machine_code_slot, self.target_core, self.timeout = struct.unpack("<3I", payload[:12])
        elif None not in (target_machine_code_slot, target_core, timeout):
            self.target_machine_code_slot = target_machine_code_slot
            self.target_core = target_core
            self.timeout = timeout
        else:
            raise ValueError("Provide payload or all args")
    
    def pack(self):
        payload = struct.pack("<3I",
                              self.target_machine_code_slot,
                              self.target_core,
                              self.timeout)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return (f"ExecuteMachineCodePacket(mc_slot={self.target_machine_code_slot}, "
                f"core={self.target_core}, timeout={self.timeout}, control={self.control})")


class UcodeExecuteTestResponsePacket(Packet):
    """
    UCODEEXECUTETESTRESPONSE packet (ID: 0x80000151).
    
    Response to APPLYUCODEEXCUTETEST, EXECUTEMACHINECODE, and GETLASTTESTRESULT.
    Contains execution results including RDTSC diff, RAX, flags, and result buffer.
    """
    message_type = PacketType.UCODEEXECUTETESTRESPONSE
    
    def __init__(self, *, payload: bytes | None = None,
                 rdtsc_diff: int | None = None, rax: int | None = None,
                 flags: int | None = None, result_buffer: bytes | None = None):
        if payload is not None:
            self.rdtsc_diff = struct.unpack("<Q", payload[:8])[0]
            self.rax       = struct.unpack("<Q", payload[8:16])[0]
            self.flags     = struct.unpack("<Q", payload[16:24])[0]
            rl = struct.unpack("<Q", payload[24:32])[0]
            self.result_buffer = payload[32:32+rl]
        elif None not in (rdtsc_diff, rax, flags, result_buffer):
            self.rdtsc_diff, self.rax, self.flags, self.result_buffer = rdtsc_diff, rax, flags, result_buffer
        else:
            raise ValueError("Provide payload or all fields")
    
    @property
    def timeout_reached(self): 
        """True if timeout was reached waiting for execution to complete."""
        return bool(self.flags & 0x1)
    
    @property
    def core_faulted(self):
        """True if core signaled a fault during execution."""
        return bool(self.flags & 0x2)
    
    def pack(self):
        rl = len(self.result_buffer)
        payload = (
            struct.pack("<Q", self.rdtsc_diff) +
            struct.pack("<Q", self.rax) +
            struct.pack("<Q", self.flags) +
            struct.pack("<Q", rl) +
            self.result_buffer
        )
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return (f"UcodeExecuteTestResponsePacket(rdtsc_diff={self.rdtsc_diff}, "
                f"rax=0x{self.rax:016X}, flags=0x{self.flags:016X} "
                f"(timeout={self.timeout_reached}, faulted={self.core_faulted}), "
                f"buffer_len={len(self.result_buffer)}, control={self.control})")


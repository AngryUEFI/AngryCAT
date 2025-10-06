#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class SendUcodePacket(Packet):
    """
    SENDUCODE request packet (ID: 0x101).
    
    Places a microcode update in the specified slot.
    Returns a STATUS response.
    """
    message_type = PacketType.SENDUCODE
    
    def __init__(self, *, payload: bytes | None = None, target_slot: int | None = None, ucode: bytes | None = None):
        if payload is not None:
            self.target_slot = struct.unpack("<I", payload[:4])[0]
            sz = struct.unpack("<I", payload[4:8])[0]
            self.ucode = payload[8:8+sz]
        elif target_slot is not None and ucode is not None:
            self.target_slot, self.ucode = target_slot, ucode
        else:
            raise ValueError("Provide payload or both target_slot & ucode")
    
    def pack(self):
        sz = len(self.ucode)
        payload = struct.pack("<II", self.target_slot, sz) + self.ucode
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"SendUcodePacket(target_slot={self.target_slot}, ucode_size={len(self.ucode)}, control={self.control})"


class FlipBitsPacket(Packet):
    """
    FLIPBITS request packet (ID: 0x121).
    
    Flips specified bits in the source microcode slot.
    Result is placed in slot 1.
    Returns a STATUS response.
    """
    message_type = PacketType.FLIPBITS
    
    def __init__(self, *, payload: bytes | None = None, source_slot: int | None = None, flips: list | None = None):
        if payload is not None:
            self.source_slot = struct.unpack("<I", payload[:4])[0]
            n = struct.unpack("<I", payload[4:8])[0]
            self.flip_positions = [struct.unpack("<I", payload[8+4*i:12+4*i])[0] for i in range(n)]
        elif source_slot is not None and flips is not None:
            self.source_slot, self.flip_positions = source_slot, flips
        else:
            raise ValueError("Provide payload or both source_slot & flips")
    
    def pack(self):
        payload = struct.pack("<II", self.source_slot, len(self.flip_positions))
        for p in self.flip_positions:
            payload += struct.pack("<I", p)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"FlipBitsPacket(source_slot={self.source_slot}, num_flips={len(self.flip_positions)}, control={self.control})"


class ApplyUcodePacket(Packet):
    """
    APPLYUCODE request packet (ID: 0x141).
    
    Applies the microcode in the specified slot.
    Optionally applies known good update afterwards.
    Returns a UCODERESPONSE.
    """
    message_type = PacketType.APPLYUCODE
    
    def __init__(self, *, payload: bytes | None = None, target_slot: int | None = None, apply_known_good: bool | None = None):
        if payload is not None:
            self.target_slot = struct.unpack("<I", payload[:4])[0]
            opts = struct.unpack("<I", payload[4:8])[0]
            self.apply_known_good = bool(opts & 0x1)
        elif target_slot is not None and apply_known_good is not None:
            self.target_slot, self.apply_known_good = target_slot, apply_known_good
        else:
            raise ValueError("Provide payload or both target_slot & apply_known_good")
    
    def pack(self):
        opts = 1 if self.apply_known_good else 0
        payload = struct.pack("<II", self.target_slot, opts)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"ApplyUcodePacket(target_slot={self.target_slot}, apply_known_good={self.apply_known_good}, control={self.control})"


class UcodeResponsePacket(Packet):
    """
    UCODERESPONSE packet (ID: 0x80000141).
    
    Response to APPLYUCODE.
    Contains RDTSC difference and RAX value (0xdead if GPF occurred).
    """
    message_type = PacketType.UCODERESPONSE
    
    def __init__(self, *, payload: bytes | None = None, rdtsc_diff: int | None = None, rax: int | None = None):
        if payload is not None:
            self.rdtsc_diff, self.rax = struct.unpack("<QQ", payload[:16])
        elif rdtsc_diff is not None and rax is not None:
            self.rdtsc_diff, self.rax = rdtsc_diff, rax
        else:
            raise ValueError("Provide payload or both rdtsc_diff & rax")
    
    def pack(self):
        payload = struct.pack("<QQ", self.rdtsc_diff, self.rax)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"UcodeResponsePacket(rdtsc_diff={self.rdtsc_diff}, rax=0x{self.rax:016X}, control={self.control})"


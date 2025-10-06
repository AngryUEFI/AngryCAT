#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class RebootPacket(Packet):
    """
    REBOOT request packet (ID: 0x21).
    
    Reboots the system. Optionally performs a warm reboot.
    Returns a STATUS response before rebooting.
    """
    message_type = PacketType.REBOOT
    
    def __init__(self, *, payload: bytes | None = None, warm: bool = False):
        if payload is not None:
            opts = struct.unpack("<I", payload[:4])[0]
            self.warm = bool(opts & 0x1)
        else:
            self.warm = warm
    
    def pack(self):
        flags = 1 if self.warm else 0
        payload = struct.pack("<I", flags)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"RebootPacket(warm={self.warm}, control={self.control})"


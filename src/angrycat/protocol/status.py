#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class StatusPacket(Packet):
    """
    STATUS response packet (ID: 0x80000000).
    
    Generic status response used by multiple request types including:
    - REBOOT, SENDUCODE, FLIPBITS, SENDMACHINECODE, STARTCORE, etc.
    
    Status code 0 indicates success.
    Status code 0xFFFFFFFF indicates an internal AngryUEFI error.
    """
    message_type = PacketType.STATUS
    
    def __init__(self, *, payload: bytes | None = None, status_code: int | None = None, text: str = ""):
        if payload is not None:
            self.status_code = struct.unpack("<I", payload[:4])[0]
            tl = struct.unpack("<I", payload[4:8])[0]
            self.text = payload[8:8+tl].decode("utf_16_le") if tl else ""
        elif status_code is not None:
            self.status_code, self.text = status_code, text
        else:
            raise ValueError("Provide payload or status_code")
    
    def pack(self):
        tb = self.text.encode("utf_16_le")
        payload = struct.pack("<I", self.status_code) + struct.pack("<I", len(tb)) + tb
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"StatusPacket(code=0x{self.status_code:X}, text={self.text}, control={self.control})"


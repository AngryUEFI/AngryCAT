#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class PingPacket(Packet):
    """PING request packet (ID: 0x1). Expects a PONG response."""
    message_type = PacketType.PING
    
    def __init__(self, *, payload: bytes | None = None, message: bytes | None = None):
        if payload is not None:
            l = struct.unpack("<I", payload[:4])[0]
            self.message = payload[4:4+l]
        elif message is not None:
            self.message = message
        else:
            raise ValueError("Provide payload or message")
    
    def pack(self):
        msg = self.message
        payload = struct.pack("<I", len(msg)) + msg
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"PingPacket(message={self.message!r}, control={self.control})"


class MultipingPacket(Packet):
    """MULTIPING request packet (ID: 0x2). Expects multiple PONG responses."""
    message_type = PacketType.MULTIPING
    
    def __init__(self, *, payload: bytes | None = None, count: int | None = None, message: bytes | None = None):
        if payload is not None:
            self.count = struct.unpack("<I", payload[:4])[0]
            ml = struct.unpack("<I", payload[4:8])[0]
            self.message = payload[8:8+ml]
        elif count is not None and message is not None:
            self.count, self.message = count, message
        else:
            raise ValueError("Provide payload or both count & message")
    
    def pack(self):
        msg = self.message
        payload = struct.pack("<I", self.count) + struct.pack("<I", len(msg)) + msg
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"MultipingPacket(count={self.count}, message={self.message!r}, control={self.control})"


class GetMsgSizePacket(Packet):
    """GETMSGSIZE request packet (ID: 0x3). Expects a MSGSIZE response."""
    message_type = PacketType.GETMSGSIZE
    
    def __init__(self, *, payload: bytes | None = None, message: bytes | None = None):
        if payload is not None:
            l = struct.unpack("<I", payload[:4])[0]
            self.message = payload[4:4+l]
        elif message is not None:
            self.message = message
        else:
            raise ValueError("Provide payload or message")
    
    def pack(self):
        msg = self.message
        payload = struct.pack("<I", len(msg)) + msg
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"GetMsgSizePacket(message={self.message!r}, control={self.control})"


class PongPacket(Packet):
    """PONG response packet (ID: 0x80000001). Response to PING and MULTIPING."""
    message_type = PacketType.PONG
    
    def __init__(self, *, payload: bytes | None = None, message: bytes | None = None):
        if payload is not None:
            l = struct.unpack("<I", payload[:4])[0]
            self.message = payload[4:4+l]
        elif message is not None:
            self.message = message
        else:
            raise ValueError("Provide payload or message")
    
    def pack(self):
        payload = struct.pack("<I", len(self.message)) + self.message
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        msg = self.message.decode("utf_16_le")
        return f"PongPacket(message={msg}, control={self.control})"


class MsgSizePacket(Packet):
    """MSGSIZE response packet (ID: 0x80000003). Response to GETMSGSIZE."""
    message_type = PacketType.MSGSIZE
    
    def __init__(self, *, payload: bytes | None = None, received_length: int | None = None):
        if payload is not None:
            self.received_length = struct.unpack("<I", payload[:4])[0]
        elif received_length is not None:
            self.received_length = received_length
        else:
            raise ValueError("Provide payload or received_length")
    
    def pack(self):
        payload = struct.pack("<I", self.received_length)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    
    def __repr__(self):
        return f"MsgSizePacket(received_length={self.received_length}, control={self.control})"


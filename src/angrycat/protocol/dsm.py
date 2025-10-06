#!/usr/bin/env python3
import struct
from dataclasses import dataclass

from .base import Packet
from .ids import PacketType


@dataclass
class DSM_file_header:
    """
    DSM (Data Structure Monitor) file header.
    See AngryUEFI/asr/dsm.h for C structure definition.
    """
    version_info: int
    mask: int
    sel: int
    types: int
    idx_info: int
    num_items: int

    def pack(self) -> bytes:
        """Pack the header into bytes for file output."""
        return struct.pack("<6Q",
                           self.version_info,
                           self.mask,
                           self.sel,
                           self.types,
                           self.idx_info,
                           self.num_items)


class GetDsmBufferPacket(Packet):
    """
    GETDSMBUFFER request packet (ID: 0x501).
    
    Requests DSM buffer contents from the specified core.
    Responds with DSMBUFFER (possibly multiple packets).
    """
    message_type = PacketType.GETDSMBUFFER

    def __init__(self, *, payload: bytes | None = None, core_id: int | None = None):
        """
        Initialize a GETDSMBUFFER request packet.
        
        Args:
            payload: Raw packet payload (if parsing from received data)
            core_id: Core ID to get DSM buffer from
        """
        if payload is not None:
            self.core_id = struct.unpack("<Q", payload[0:8])[0]
        elif core_id is not None:
            self.core_id = core_id
        else:
            raise ValueError("Provide payload or core_id")

    def pack(self):
        payload = struct.pack("<Q", self.core_id)
        hdr = struct.pack(
            "<I4B I",
            len(payload) + 8,  # +8 for the header fields after length
            self.major, 
            self.minor, 
            self.control, 
            self.reserved,
            self.message_type.value
        )
        return hdr + payload

    def __repr__(self):
        return f"GetDsmBufferPacket(core_id=0x{self.core_id:x}, control={self.control})"


class DsmBufferPacket(Packet):
    """
    DSMBUFFER response packet (ID: 0x80000501).
    
    Response to GETDSMBUFFER.
    Contains DSM events from the specified core.
    """
    message_type = PacketType.DSMBUFFER

    def __init__(self, *, payload: bytes | None = None, **kwargs):
        if payload is None:
            raise ValueError("DSMBUFFER always comes with payload")

        # Read the file header length from the second u64 field
        if len(payload) < 16:
            raise ValueError("Payload too short to read file header length")
        
        file_header_length = struct.unpack("<Q", payload[8:16])[0]
        expected_header_length = 6 * 8  # DSM_file_header has 6 u64 fields
        
        if file_header_length != expected_header_length:
            raise ValueError(
                f"File header length mismatch: expected {expected_header_length} bytes, "
                f"but payload indicates {file_header_length} bytes"
            )
        
        # Verify we have enough data for the header
        if len(payload) < file_header_length + 2 * 8:
            raise ValueError(
                f"Payload too short: need {file_header_length + 2 * 8} bytes for header, "
                f"but only have {len(payload)} bytes"
            )

        # Parse the file header
        header_fields = struct.unpack("<6Q", payload[16:expected_header_length + 16])
        self.header = DSM_file_header(*header_fields)
        self.entries = payload[expected_header_length + 16:]

    @property
    def file_content(self) -> bytes:
        """Get the complete file content (header + entries) for writing to disk."""
        return self.header.pack() + self.entries

    def __repr__(self):
        return (f"<DsmBufferPacket(header={self.header}, "
                f"entries_len={len(self.entries)}, control={self.control})>")

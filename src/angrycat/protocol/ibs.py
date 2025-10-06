#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class IBSEvent:
    """
    Represents a single IBS (Instruction Based Sampling) event.
    Based on the IBSEvent_s struct in ibs.h.
    """
    # Data source descriptions mapping
    _DATA_SOURCE_NAMES = {
        0: "Unknown",
        1: "Reserved",
        2: "OtherCoreCache",
        3: "DRAM",
        4: "ReservedRemoteCache",
        5: "Reserved5",
        6: "Reserved6",
        7: "MMIO/Config/PCI/APIC"
    }
    
    # Size field descriptions mapping
    _SIZE_NAMES = {
        0: "Unknown",
        1: "1B",
        2: "2B",
        3: "4B",
        4: "8B",
        5: "16B"
    }

    def __init__(self, data: bytes):
        """
        Parse an IBS event from raw bytes.
        
        Args:
            data: 16 bytes of raw IBS event data
        """
        if len(data) < 16:
            raise ValueError(f"IBSEvent requires at least 16 bytes, got {len(data)}")
            
        # Unpack the two 64-bit quadwords
        self.q1 = struct.unpack("<Q", data[0:8])[0]
        self.q2 = struct.unpack("<Q", data[8:16])[0]
        
        # Parse q1 fields - updated to match ibs.h structure
        self.phys = self.q1 & 0xFFFFFFFFF  # 36 bits (was 44 bits)
        self.microcode = bool((self.q1 >> 36) & 0x1)
        self._data_source = (self.q1 >> 37) & 0x7  # 3 bits
        self._size = (self.q1 >> 40) & 0xF  # 4 bits
        self.prefetch = bool((self.q1 >> 44) & 0x1)
        self.phys_valid = bool((self.q1 >> 45) & 0x1)
        self.linear_valid = bool((self.q1 >> 46) & 0x1)
        self.uncachable = bool((self.q1 >> 47) & 0x1)
        self.store = bool((self.q1 >> 48) & 0x1)
        self.load = bool((self.q1 >> 49) & 0x1)
        self.valid = bool((self.q1 >> 50) & 0x1)
        # Remaining 13 bits are reserved (shift 51-63)
        
        # q2 contains the virtual address (if valid) or upper bits of physical address
        self.virtual = self.q2
        
    @property
    def is_load(self) -> bool:
        """Check if this is a load operation."""
        return self.load
        
    @property
    def is_store(self) -> bool:
        """Check if this is a store operation."""
        return self.store
        
    @property
    def is_memory_op(self) -> bool:
        """Check if this is a memory operation (load or store)."""
        return self.load or self.store
        
    @property
    def is_alu_op(self) -> bool:
        """Check if this is an ALU operation (not a memory operation)."""
        return not (self.load or self.store)
        
    @property
    def data_source(self) -> int:
        """Get the raw data source value (0-7)."""
        return self._data_source
        
    @property
    def size(self) -> int:
        """Get the raw size value (0-5)."""
        return self._size
        
    @property
    def size_name(self) -> str:
        """Get a human-readable description of the size."""
        return self._SIZE_NAMES.get(self._size, f"Reserved({self._size})")
        
    @property
    def data_source_name(self) -> str:
        """Get a human-readable name for the data source."""
        return self._DATA_SOURCE_NAMES.get(self._data_source, f"Unknown({self._data_source})")
        
    @property
    def physical_address(self) -> int | None:
        """
        Get the physical address for this event.
        Combines the phys field (upper bits) with the lower 12 bits of q2.
        Returns None if no valid physical address is available.
        """
        return (self.phys << 12) | (self.q2 & 0xFFF)
        
    @property
    def linear_address(self) -> int | None:
        """
        Get the linear (virtual) address for this event.
        This is the value of q2.
        Returns None if no valid linear address is available.
        """
        return self.q2
        
    def __repr__(self) -> str:
        op_type = "???"
        if self.is_load and self.is_store:
            op_type = "UPDATE"
        elif self.is_load:
            op_type = "LOAD"
        elif self.is_store:
            op_type = "STORE"
        else:
            op_type = "ALU"
        
        # Memory operation details
        details = []
        addr_str = []
        if self.is_memory_op:
            addrs = []
            addrs.append(f"lin=0x{self.linear_address:016X}")
            addrs.append(f"phys=0x{self.physical_address:016X}")
                
            addr_str = " ".join(addrs)
            details.append(f"sz={self.size_name}")
            details.append(f"src={self.data_source_name}")
                
        # Flags as short indicators
        flags = []
        if self.valid: flags.append("VA")
        if self.linear_valid: flags.append("LV")
        if self.phys_valid: flags.append("PV")
        if self.microcode: flags.append("MC")
        if self.uncachable: flags.append("UC")
        if self.prefetch: flags.append("PF")
        flags_str = "[" + "|".join(flags) + "]" if flags else ""
                
        # Combine all parts
        parts = [f"{op_type}{flags_str}"]
        if addr_str:
            parts.append(addr_str)  
        if details:
            parts.append("(" + ", ".join(details) + ")")
            
        return " ".join(parts)


class GetIbsBufferPacket(Packet):
    """
    GETIBSBUFFER request packet (ID: 0x401).
    
    Requests IBS buffer contents from the specified core.
    Responds with IBSBUFFER (possibly multiple packets).
    """
    message_type = PacketType.GETIBSBUFFER
    
    def __init__(self, *, payload: bytes | None = None, core_id: int | None = None, 
                 start_index: int = 0, entry_count: int = 0):
        """
        Initialize a GETIBSBUFFER request packet.
        
        Args:
            payload: Raw packet payload (if parsing from received data)
            core_id: Core ID to get IBS buffer from
            start_index: 0-based start index in the buffer
            entry_count: Number of entries to retrieve (0 = all from start_index)
        """
        if payload is not None:
            self.core_id = struct.unpack("<Q", payload[0:8])[0]
            self.start_index = struct.unpack("<Q", payload[8:16])[0]
            self.entry_count = struct.unpack("<Q", payload[16:24])[0]
        elif core_id is not None:
            self.core_id = core_id
            self.start_index = start_index
            self.entry_count = entry_count
        else:
            raise ValueError("Provide payload or core_id")
            
    def pack(self):
        payload = struct.pack(
            "<QQQ", 
            self.core_id, 
            self.start_index, 
            self.entry_count
        )
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
        return (
            f"GetIbsBufferPacket(core_id=0x{self.core_id:x}, "
            f"start_index={self.start_index}, entry_count={self.entry_count}, "
            f"control={self.control})"
        )


class IbsBufferPacket(Packet):
    """
    IBSBUFFER response packet (ID: 0x80000401).
    
    Response to GETIBSBUFFER.
    Contains IBS events from the specified core.
    """
    message_type = PacketType.IBSBUFFER
    
    def __init__(self, *, payload: bytes | None = None, 
                 flags: int = 0, 
                 total_stored_events: int = 0,
                 max_stored_events: int = 0,
                 entries: list[bytes] | None = None):
        """
        Initialize an IBSBUFFER response packet.
        
        Args:
            payload: Raw packet payload (if parsing from received data)
            flags: IBS buffer flags (if creating a new packet)
            total_stored_events: Total number of events in the buffer (if creating)
            max_stored_events: Maximum number of events the buffer can hold (if creating)
            entries: List of IBS buffer entries as raw bytes (if creating)
        """
        if payload is not None:
            # Parse the header fields
            if len(payload) < 32:  # 8B flags + 3x8B counts = 32B
                raise ValueError("IBS buffer packet too short for header")
                
            # Unpack header fields
            self._flags = struct.unpack("<Q", payload[0:8])[0]
            self._total_stored_events = struct.unpack("<Q", payload[8:16])[0]
            self._max_stored_events = struct.unpack("<Q", payload[16:24])[0]
            entry_count = struct.unpack("<Q", payload[24:32])[0]
            
            # Parse the entries (each entry is 16 bytes as per README)
            entry_size = 16
            expected_size = 32 + (entry_count * entry_size)
            if len(payload) < expected_size:
                raise ValueError(f"IBS buffer packet too short for {entry_count} entries")
                
            # Parse each entry into an IBSEvent object
            self.entries = [
                IBSEvent(payload[32 + i*entry_size : 32 + (i+1)*entry_size])
                for i in range(entry_count)
            ]
        else:
            self._flags = flags
            self._total_stored_events = total_stored_events
            self._max_stored_events = max_stored_events
            self.entries = entries or []
    
    @property
    def flags(self) -> int:
        """Get the IBS buffer flags."""
        return self._flags
        
    @property
    def is_ibs_initialized(self) -> bool:
        """Check if IBS is initialized (Bit 0 of flags)."""
        return bool(self._flags & 0x1)
        
    @property
    def total_stored_events(self) -> int:
        """Get the total number of events stored in the buffer."""
        return self._total_stored_events
        
    @property
    def max_stored_events(self) -> int:
        """Get the maximum number of events the buffer can hold."""
        return self._max_stored_events
    
    @property
    def entry_count(self) -> int:
        """Get the number of entries in this packet."""
        return len(self.entries)
            
    def pack(self):
        # Pack the header
        header = struct.pack(
            "<4Q",  # 4 unsigned 64-bit integers
            self._flags,
            self._total_stored_events,
            self._max_stored_events,
            len(self.entries)
        )
        
        # Concatenate all entries
        payload = header + b''.join(self.entries)
        
        # Create the packet header
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
        return (
            f"IbsBufferPacket("
            f"ibs_initialized={self.is_ibs_initialized}, "
            f"total_stored_events={self.total_stored_events}, "
            f"max_stored_events={self.max_stored_events}, "
            f"entry_count={self.entry_count}, "
            f"control={self.control})"
        )

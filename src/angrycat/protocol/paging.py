#!/usr/bin/env python3
import struct

from .base import Packet
from .ids import PacketType


class PagingEntry:
    """
    Represents a single paging structure entry (PML4, PDPT, PD, or PT entry).
    """
    def __init__(self, raw: int, position: int, level: int):
        self.raw = raw
        self.position = position  # position in table
        self.level = level        # 1=PTE,2=PDE,3=PDPT,4=PML4

        # standard IA‑32e page flags:
        self.present                = bool(raw & (1 << 0))
        self.read_write             = bool(raw & (1 << 1))
        self.user_supervisor        = bool(raw & (1 << 2))
        self.page_level_write_through = bool(raw & (1 << 3))
        self.page_level_cache_disable = bool(raw & (1 << 4))
        self.accessed               = bool(raw & (1 << 5))
        self.dirty                  = bool(raw & (1 << 6))
        self.page_size              = bool(raw & (1 << 7))
        self.global_page            = bool(raw & (1 << 8))

        # physical page number
        self.addr = raw >> 12

    @property
    def full_addr(self) -> int:
        """Get the full physical address (addr shifted back by 12 bits)."""
        return self.addr << 12

    def __repr__(self):
        return (f"<PagingEntry lvl={self.level} pos={self.position} "
                f"present={self.present} ps={self.page_size} addr=0x{self.full_addr:X}>")


class GetPagingInfoPacket(Packet):
    """
    GETPAGINGINFO request packet (ID: 0x11).
    
    Requests paging information for the specified core.
    Responds with one or more PAGINGINFO packets.
    """
    message_type = PacketType.GETPAGINGINFO

    def __init__(self, *, payload: bytes | None = None, core: int | None = None, indices: list[int] | None = None):
        # payload: 8B core, then 4×8B indices
        if payload is not None:
            off = 0
            self.core = struct.unpack("<Q", payload[off:off+8])[0]; off += 8
            self.indices = []
            for _ in range(4):
                idx = struct.unpack("<Q", payload[off:off+8])[0]
                self.indices.append(idx)
                off += 8
        elif core is not None and indices is not None and len(indices) == 4:
            self.core = core
            self.indices = indices
        else:
            raise ValueError("Must provide payload or (core + 4‑element indices list)")

    def pack(self) -> bytes:
        payload = struct.pack("<Q", self.core)
        for idx in self.indices:
            payload += struct.pack("<Q", idx)
        hdr = struct.pack("<I4B I",
                          len(payload) + 8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload

    def __repr__(self):
        return (f"GetPagingInfoPacket(core={self.core}, "
                f"indices={self.indices}, control={self.control})")


class PagingInfoPacket(Packet):
    """
    PAGINGINFO response packet (ID: 0x80000011).
    
    Response to GETPAGINGINFO.
    Contains CR3 value and paging structure entries.
    """
    message_type = PacketType.PAGINGINFO

    def __init__(self, *, payload: bytes = None, **kwargs):
        if payload is None:
            raise ValueError("PAGINGINFO always comes with payload")

        # parse fixed header
        off = 0
        flags = struct.unpack("<Q", payload[off:off+8])[0]; off += 8
        self.fresh_cr3      = bool(flags & (1 << 0))
        self.cr3_faulted    = bool(flags & (1 << 1))
        self.cr3_timed_out  = bool(flags & (1 << 2))

        self.cr3            = struct.unpack("<Q", payload[off:off+8])[0]; off += 8
        entry_count        = struct.unpack("<Q", payload[off:off+8])[0]; off += 8

        # parse each entry
        self.entries = []
        for i in range(entry_count):
            meta = payload[off:off+8]; off += 8
            position = struct.unpack("<H", meta[:2])[0]
            level    = meta[2]
            # skip 5 reserved bytes

            raw_entry = struct.unpack("<Q", payload[off:off+8])[0]; off += 8

            pe = PagingEntry(raw_entry, position=position, level=level)
            pe.index = position
            self.entries.append(pe)

    def __repr__(self):
        return (f"<PagingInfoPacket(fresh_cr3={self.fresh_cr3}, "
                f"cr3=0x{self.cr3:X}, entries={len(self.entries)}, "
                f"control={self.control})>")

    @classmethod
    def collect_entries(cls, packets: list["PagingInfoPacket"]) -> list["PagingEntry"]:
        """
        Flatten a list of PagingInfoPacket into a single list of all PagingEntry objects.
        """
        entries = []
        for pkt in packets:
            entries.extend(pkt.entries)
        return entries


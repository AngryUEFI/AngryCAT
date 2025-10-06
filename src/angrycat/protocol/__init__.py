#!/usr/bin/env python3
"""
AngryCAT Protocol Package

This package contains all packet types for the AngryUEFI protocol.
Packets are organized by functionality into separate modules.
"""

# Base classes and utilities
from .base import Packet, parse_packet
from .ids import PacketType

# Status response (used by multiple requests)
from .status import StatusPacket

# Ping and message size packets
from .ping import (
    PingPacket,
    MultipingPacket,
    GetMsgSizePacket,
    PongPacket,
    MsgSizePacket,
)

# Reboot
from .reboot import RebootPacket

# Microcode packets
from .ucode import (
    SendUcodePacket,
    FlipBitsPacket,
    ApplyUcodePacket,
    UcodeResponsePacket,
)

# MSR packets
from .msr import (
    ReadMsrPacket,
    ReadMsrOnCorePacket,
    MsrResponsePacket,
)

# Machine code execution packets
from .machine_code import (
    SendMachineCodePacket,
    ApplyUcodeExecuteTestPacket,
    ExecuteMachineCodePacket,
    UcodeExecuteTestResponsePacket,
)

# Core management packets
from .core import (
    CoreStatusFaultInfo,
    GetCoreCountPacket,
    CoreCountResponsePacket,
    StartCorePacket,
    GetCoreStatusPacket,
    GetLastTestResultPacket,
    CoreStatusResponsePacket,
)

# Paging packets
from .paging import (
    PagingEntry,
    GetPagingInfoPacket,
    PagingInfoPacket,
)

# IBS packets
from .ibs import (
    IBSEvent,
    GetIbsBufferPacket,
    IbsBufferPacket,
)

# DSM packets
from .dsm import (
    DSM_file_header,
    GetDsmBufferPacket,
    DsmBufferPacket,
)

__all__ = [
    # Base
    "Packet",
    "parse_packet",
    "PacketType",
    
    # Status
    "StatusPacket",
    
    # Ping
    "PingPacket",
    "MultipingPacket",
    "GetMsgSizePacket",
    "PongPacket",
    "MsgSizePacket",
    
    # Reboot
    "RebootPacket",
    
    # Microcode
    "SendUcodePacket",
    "FlipBitsPacket",
    "ApplyUcodePacket",
    "UcodeResponsePacket",
    
    # MSR
    "ReadMsrPacket",
    "ReadMsrOnCorePacket",
    "MsrResponsePacket",
    
    # Machine code
    "SendMachineCodePacket",
    "ApplyUcodeExecuteTestPacket",
    "ExecuteMachineCodePacket",
    "UcodeExecuteTestResponsePacket",
    
    # Core management
    "CoreStatusFaultInfo",
    "GetCoreCountPacket",
    "CoreCountResponsePacket",
    "StartCorePacket",
    "GetCoreStatusPacket",
    "GetLastTestResultPacket",
    "CoreStatusResponsePacket",
    
    # Paging
    "PagingEntry",
    "GetPagingInfoPacket",
    "PagingInfoPacket",
    
    # IBS
    "IBSEvent",
    "GetIbsBufferPacket",
    "IbsBufferPacket",
    
    # DSM
    "DSM_file_header",
    "GetDsmBufferPacket",
    "DsmBufferPacket",
]

# Register all packet types with their IDs
# This must happen after all packet classes are imported
_PACKET_CLASSES = [
    # Requests
    (PacketType.PING, PingPacket),
    (PacketType.MULTIPING, MultipingPacket),
    (PacketType.GETMSGSIZE, GetMsgSizePacket),
    (PacketType.GETPAGINGINFO, GetPagingInfoPacket),
    (PacketType.REBOOT, RebootPacket),
    (PacketType.SENDUCODE, SendUcodePacket),
    (PacketType.FLIPBITS, FlipBitsPacket),
    (PacketType.APPLYUCODE, ApplyUcodePacket),
    (PacketType.APPLYUCODEEXCUTETEST, ApplyUcodeExecuteTestPacket),
    (PacketType.READMSR, ReadMsrPacket),
    (PacketType.READMSRONCORE, ReadMsrOnCorePacket),
    (PacketType.SENDMACHINECODE, SendMachineCodePacket),
    (PacketType.EXECUTEMACHINECODE, ExecuteMachineCodePacket),
    (PacketType.GETCORECOUNT, GetCoreCountPacket),
    (PacketType.STARTCORE, StartCorePacket),
    (PacketType.GETCORESTATUS, GetCoreStatusPacket),
    (PacketType.GETLASTTESTRESULT, GetLastTestResultPacket),
    (PacketType.GETIBSBUFFER, GetIbsBufferPacket),
    (PacketType.GETDSMBUFFER, GetDsmBufferPacket),
    # Responses
    (PacketType.STATUS, StatusPacket),
    (PacketType.PONG, PongPacket),
    (PacketType.MSGSIZE, MsgSizePacket),
    (PacketType.PAGINGINFO, PagingInfoPacket),
    (PacketType.UCODERESPONSE, UcodeResponsePacket),
    (PacketType.UCODEEXECUTETESTRESPONSE, UcodeExecuteTestResponsePacket),
    (PacketType.MSRRESPONSE, MsrResponsePacket),
    (PacketType.CORECOUNTRESPONSE, CoreCountResponsePacket),
    (PacketType.CORESTATUSRESPONSE, CoreStatusResponsePacket),
    (PacketType.IBSBUFFER, IbsBufferPacket),
    (PacketType.DSMBUFFER, DsmBufferPacket),
]

# Register all packets
for packet_type, packet_class in _PACKET_CLASSES:
    Packet.registry[packet_type.value] = packet_class

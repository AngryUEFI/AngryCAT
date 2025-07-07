#!/usr/bin/env python3
import struct
import socket
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

class PacketType(Enum):
    # Request Packet Types
    PING         = 0x1
    MULTIPING    = 0x2
    GETMSGSIZE   = 0x3
    GETPAGINGINFO = 0x11
    REBOOT       = 0x21
    SENDUCODE    = 0x101
    FLIPBITS     = 0x121
    APPLYUCODE   = 0x141
    READMSR      = 0x201
    APPLYUCODEEXCUTETEST = 0x151
    SENDMACHINECODE      = 0x301
    GETCORECOUNT         = 0x211
    GETLASTTESTRESULT    = 0x152
    STARTCORE            = 0x212
    GETCORESTATUS        = 0x213
    READMSRONCORE        = 0x202
    EXECUTEMACHINECODE   = 0x153
    GETIBSBUFFER         = 0x401  # Request IBS buffer from a core

    # Response Packet Types
    STATUS        = 0x80000000
    PONG          = 0x80000001
    MSGSIZE       = 0x80000003
    PAGINGINFO    = 0x80000011
    UCODERESPONSE = 0x80000141
    MSRRESPONSE   = 0x80000201
    UCODEEXECUTETESTRESPONSE = 0x80000151
    CORECOUNTRESPONSE        = 0x80000211
    CORESTATUSRESPONSE       = 0x80000213
    IBSBUFFER               = 0x80000401  # Response containing IBS buffer data

class Packet:
    """Base class for all packets, with dynamic registry & multi‑message support."""
    major    = 1
    minor    = 0
    control  = 0  # Bit0: another message follows if set
    reserved = 0

    message_type: PacketType = None

    def pack(self) -> bytes:
        raise NotImplementedError("Subclasses must implement pack()")

    @classmethod
    def read_n_bytes(cls, sock: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise RuntimeError("Socket closed unexpectedly while reading data.")
            data += chunk
        return data

    @classmethod
    def read_from_socket(cls, sock: socket.socket) -> "Packet":
        header_first4 = cls.read_n_bytes(sock, 4)
        msg_len = struct.unpack("<I", header_first4)[0]
        remaining = cls.read_n_bytes(sock, msg_len)
        return parse_packet(header_first4 + remaining)

    @classmethod
    def read_messages(cls, sock: socket.socket) -> list["Packet"]:
        """Read until control bit0==0 (end‑of‑transmission)."""
        msgs = []
        while True:
            pkt = cls.read_from_socket(sock)
            msgs.append(pkt)
            if (pkt.control & 0x1) == 0:
                break
        return msgs

    def __repr__(self):
        return f"<{self.__class__.__name__}>"

# ======== Request Packets ========

class PingPacket(Packet):
    message_type = PacketType.PING
    def __init__(self, *, payload: bytes = None, message: bytes = None):
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
    message_type = PacketType.MULTIPING
    def __init__(self, *, payload: bytes = None, count: int = None, message: bytes = None):
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
    message_type = PacketType.GETMSGSIZE
    def __init__(self, *, payload: bytes = None, message: bytes = None):
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

class RebootPacket(Packet):
    message_type = PacketType.REBOOT
    def __init__(self, *, payload: bytes = None, warm: bool = False):
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

class SendUcodePacket(Packet):
    message_type = PacketType.SENDUCODE
    def __init__(self, *, payload: bytes = None, target_slot: int = None, ucode: bytes = None):
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
    message_type = PacketType.FLIPBITS
    def __init__(self, *, payload: bytes = None, source_slot: int = None, flips: list = None):
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
    message_type = PacketType.APPLYUCODE
    def __init__(self, *, payload: bytes = None, target_slot: int = None, apply_known_good: bool = None):
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

class ReadMsrPacket(Packet):
    message_type = PacketType.READMSR
    def __init__(self, *, payload: bytes = None, target_msr: int = None):
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
    message_type = PacketType.READMSRONCORE
    def __init__(self, *, payload: bytes = None, target_msr: int = None, target_core: int = None):
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

class GetCoreCountPacket(Packet):
    message_type = PacketType.GETCORECOUNT
    def __init__(self, *, payload: bytes = None):
        pass
    def pack(self):
        hdr = struct.pack("<I4B I",
                          8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr
    def __repr__(self):
        return "GetCoreCountPacket()"

class ApplyUcodeExecuteTestPacket(Packet):
    message_type = PacketType.APPLYUCODEEXCUTETEST
    def __init__(self, *, payload: bytes = None,
                 target_ucode_slot: int = None,
                 target_machine_code_slot: int = None,
                 target_core: int = None,
                 timeout: int = None,
                 apply_known_good: bool = None):
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
    message_type = PacketType.EXECUTEMACHINECODE
    def __init__(self, *, payload: bytes = None,
                 target_machine_code_slot: int = None,
                 target_core: int = None,
                 timeout: int = None):
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

class SendMachineCodePacket(Packet):
    message_type = PacketType.SENDMACHINECODE
    def __init__(self, *, payload: bytes = None,
                 target_slot: int = None,
                 machine_code: bytes = None):
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

class GetLastTestResultPacket(Packet):
    message_type = PacketType.GETLASTTESTRESULT
    def __init__(self, *, payload: bytes = None, core: int = None):
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Provide payload or core")
    def pack(self):
        payload = struct.pack("<Q", self.core)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    def __repr__(self):
        return f"GetLastTestResultPacket(core={self.core}, control={self.control})"

class StartCorePacket(Packet):
    message_type = PacketType.STARTCORE
    def __init__(self, *, payload: bytes = None, core: int = None):
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Provide payload or core")
    def pack(self):
        payload = struct.pack("<Q", self.core)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    def __repr__(self):
        return f"StartCorePacket(core={self.core}, control={self.control})"

class GetCoreStatusPacket(Packet):
    message_type = PacketType.GETCORESTATUS
    def __init__(self, *, payload: bytes = None, core: int = None):
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Provide payload or core")
    def pack(self):
        payload = struct.pack("<Q", self.core)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    def __repr__(self):
        return f"GetCoreStatusPacket(core={self.core}, control={self.control})"

class GetPagingInfoPacket(Packet):
    message_type = PacketType.GETPAGINGINFO

    def __init__(self, *, payload: bytes = None, core: int = None, indices: list[int] = None):
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


class GetIbsBufferPacket(Packet):
    message_type = PacketType.GETIBSBUFFER
    
    def __init__(self, *, payload: bytes = None, core_id: int = None, 
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


# ======== Response Packets ========

class StatusPacket(Packet):
    message_type = PacketType.STATUS
    def __init__(self, *, payload: bytes = None, status_code: int = None, text: str = ""):
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

class PongPacket(Packet):
    message_type = PacketType.PONG
    def __init__(self, *, payload: bytes = None, message: bytes = None):
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
    message_type = PacketType.MSGSIZE
    def __init__(self, *, payload: bytes = None, received_length: int = None):
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

class UcodeResponsePacket(Packet):
    message_type = PacketType.UCODERESPONSE
    def __init__(self, *, payload: bytes = None, rdtsc_diff: int = None, rax: int = None):
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

class UcodeExecuteTestResponsePacket(Packet):
    message_type = PacketType.UCODEEXECUTETESTRESPONSE
    def __init__(self, *, payload: bytes = None,
                 rdtsc_diff: int = None, rax: int = None,
                 flags: int = None, result_buffer: bytes = None):
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
    def timeout_reached(self): return bool(self.flags & 0x1)
    @property
    def core_faulted(self):    return bool(self.flags & 0x2)
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

class MsrResponsePacket(Packet):
    message_type = PacketType.MSRRESPONSE
    def __init__(self, *, payload: bytes = None, eax: int = None, edx: int = None):
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

class CoreCountResponsePacket(Packet):
    message_type = PacketType.CORECOUNTRESPONSE
    def __init__(self, *, payload: bytes = None, core_count: int = None):
        if payload is not None:
            self.core_count = struct.unpack("<Q", payload[:8])[0]
        elif core_count is not None:
            self.core_count = core_count
        else:
            raise ValueError("Provide payload or core_count")
    def pack(self):
        payload = struct.pack("<Q", self.core_count)
        hdr = struct.pack("<I4B I",
                          len(payload)+8,
                          self.major, self.minor, self.control, self.reserved,
                          self.message_type.value)
        return hdr + payload
    def __repr__(self):
        return f"CoreCountResponsePacket(core_count={self.core_count}, control={self.control})"

class CoreStatusFaultInfo:
    def __init__(self, data: bytes):
        if len(data) < 216:
            raise ValueError(f"Expected ≥216 bytes, got {len(data)}")
        fields = struct.unpack("<27Q", data[:216])
        (
            self.fault_occured, self.fault_number, self.error_code, self.old_rip,
            self.rax_value, self.rbx_value, self.rcx_value, self.rdx_value,
            self.rsi_value, self.rdi_value, self.rsp_value, self.rbp_value,
            self.r8_value, self.r9_value, self.r10_value, self.r11_value,
            self.r12_value, self.r13_value, self.r14_value, self.r15_value,
            self.rflags_value, self.cr0_value, self.cr2_value, self.cr3_value,
            self.cr4_value, self.cs_value, self.original_rsp
        ) = fields

    def description(self):
        return (f"Fault#=0x{self.fault_number:016X}, "
                f"Err=0x{self.error_code:016X}, RIP=0x{self.old_rip:016X}")

    def long_description(self):
        attrs = [a for a in dir(self) if a.endswith("_value") or a in ("fault_number","error_code","old_rip")]
        return "\n".join(f"{name}: 0x{getattr(self,name):016X}" for name in attrs)

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
    def physical_address(self) -> Optional[int]:
        """
        Get the physical address for this event.
        Combines the phys field (upper bits) with the lower 12 bits of q2.
        Returns None if no valid physical address is available.
        """
        return (self.phys << 12) | (self.q2 & 0xFFF)
        
    @property
    def linear_address(self) -> Optional[int]:
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


class IbsBufferPacket(Packet):
    message_type = PacketType.IBSBUFFER
    
    def __init__(self, *, payload: bytes = None, 
                 flags: int = 0, 
                 total_stored_events: int = 0,
                 max_stored_events: int = 0,
                 entries: list[bytes] = None):
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


class CoreStatusResponsePacket(Packet):
    message_type = PacketType.CORESTATUSRESPONSE
    def __init__(self, *, payload: bytes = None,
                 flags: int = None, last_heartbeat: int = None,
                 current_rdtsc: int = None, fault_info: CoreStatusFaultInfo = None):
        if payload is not None:
            self.flags = struct.unpack("<Q", payload[:8])[0]
            self.last_heartbeat = struct.unpack("<Q", payload[8:16])[0]
            self.current_rdtsc  = struct.unpack("<Q", payload[16:24])[0]
            if len(payload) > 24:
                fl = struct.unpack("<Q", payload[24:32])[0]
                self.fault_info = CoreStatusFaultInfo(payload[32:32+fl]) if fl else None
            else:
                self.fault_info = None
        elif None not in (flags, last_heartbeat, current_rdtsc):
            self.flags, self.last_heartbeat, self.current_rdtsc, self.fault_info = flags, last_heartbeat, current_rdtsc, fault_info
        else:
            raise ValueError("Provide payload or flags+heartbeat+rdtsc")
    @property
    def present(self):    return bool(self.flags & 0x1)
    @property
    def started(self):    return bool(self.flags & 0x2)
    @property
    def ready(self):      return bool(self.flags & 0x4)
    @property
    def job_queued(self): return bool(self.flags & 0x8)
    @property
    def is_locked(self):  return bool(self.flags & 0x10)
    @property
    def faulted(self):    return bool(self.flags & 0x20)
    def pack(self):
        raise NotImplementedError("For responses only")
    def __repr__(self):
        base = (f"CoreStatusResponsePacket(flags=0x{self.flags:016X} "
                f"(present={self.present},started={self.started},ready={self.ready},"
                f"queued={self.job_queued},locked={self.is_locked},faulted={self.faulted}), "
                f"hb={self.last_heartbeat}, rdtsc={self.current_rdtsc}, control={self.control})")
        if self.fault_info:
            base += "\n  Fault: " + self.fault_info.description()
        return base

class PagingEntry:
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
        return self.addr << 12

    def __repr__(self):
        return (f"<PagingEntry lvl={self.level} pos={self.position} "
                f"present={self.present} ps={self.page_size} addr=0x{self.full_addr:X}>")

class PagingInfoPacket(Packet):
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

# ======== Parser & Registry ========

def parse_packet(data: bytes) -> Packet:
    if len(data) < 12:
        raise ValueError("Data too short for valid packet")
    msg_len, maj, mino, ctrl, res, msg_type = struct.unpack("<I4B I", data[:12])
    if len(data) != 4 + msg_len:
        raise ValueError(f"Length mismatch (got {len(data)}, expected {4+msg_len})")
    payload = data[12:]
    cls = PACKET_REGISTRY.get(msg_type)
    if not cls:
        raise ValueError(f"Unknown packet type 0x{msg_type:08X}")
    pkt = cls(payload=payload)
    pkt.major, pkt.minor, pkt.control, pkt.reserved = maj, mino, ctrl, res
    return pkt

# dynamic registry of all Packet subclasses with a message_type
PACKET_REGISTRY = {
    cls.message_type.value: cls
    for cls in Packet.__subclasses__() if getattr(cls, "message_type", None)
}

if __name__ == "__main__":
    # quick sanity check
    p = PingPacket(message=b"Hi")
    data = p.pack()
    parsed = parse_packet(data)
    print(parsed)

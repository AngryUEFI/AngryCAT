#!/usr/bin/env python3
import struct
import socket
from enum import Enum

class PacketType(Enum):
    # Request Packet Types
    PING         = 0x1
    MULTIPING    = 0x2
    GETMSGSIZE   = 0x3
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

    # Response Packet Types
    STATUS       = 0x80000000
    PONG         = 0x80000001
    MSGSIZE      = 0x80000003
    UCODERESPONSE = 0x80000141
    MSRRESPONSE  = 0x80000201
    UCODEEXECUTETESTRESPONSE = 0x80000151
    CORECOUNTRESPONSE        = 0x80000211
    CORESTATUSRESPONSE       = 0x80000213

# Base class for all packets.
class Packet:
    # Default header values.
    major    = 1
    minor    = 0
    control  = 0  # Bitfield: Bit 0: 0 means end-of-transmission; 1 means another message follows.
    reserved = 0

    # Each subclass must set its own message_type as an instance of PacketType.
    message_type: PacketType = None

    def pack(self) -> bytes:
        """Return the binary representation of the packet.
           Subclasses must override this method.
        """
        raise NotImplementedError("Subclasses must implement pack()")

    @classmethod
    def read_n_bytes(cls, sock: socket.socket, n: int) -> bytes:
        """Read exactly n bytes from the socket."""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise RuntimeError("Socket closed unexpectedly while reading data.")
            data += chunk
        return data

    @classmethod
    def read_from_socket(cls, sock: socket.socket) -> "Packet":
        """
        Read a complete packet from the socket and return the corresponding Packet instance.
        It first reads 4 bytes to determine the packet's message length, then reads the remainder
        of the packet and parses it using parse_packet().
        """
        header_first4 = cls.read_n_bytes(sock, 4)
        msg_len = struct.unpack("<I", header_first4)[0]
        remaining = cls.read_n_bytes(sock, msg_len)
        full_packet = header_first4 + remaining
        return parse_packet(full_packet)

    def __repr__(self):
        return f"<{self.__class__.__name__}>"

# ======== Request Packets ========

class PingPacket(Packet):
    message_type = PacketType.PING

    def __init__(self, *, payload: bytes = None, message: bytes = None):
        if payload is not None:
            msg_len = struct.unpack("<I", payload[:4])[0]
            self.message = payload[4:4 + msg_len]
        elif message is not None:
            self.message = message
        else:
            raise ValueError("Either payload or message must be provided.")

    def pack(self) -> bytes:
        msg_bytes = self.message
        payload = struct.pack("<I", len(msg_bytes)) + msg_bytes
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"PingPacket(message={self.message}, control={self.control})"

class MultipingPacket(Packet):
    message_type = PacketType.MULTIPING

    def __init__(self, *, payload: bytes = None, count: int = None, message: bytes = None):
        if payload is not None:
            self.count = struct.unpack("<I", payload[:4])[0]
            msg_len = struct.unpack("<I", payload[4:8])[0]
            self.message = payload[8:8 + msg_len]
        elif count is not None and message is not None:
            self.count = count
            self.message = message
        else:
            raise ValueError("Either payload or both count and message must be provided.")

    def pack(self) -> bytes:
        msg_bytes = self.message
        payload = struct.pack("<I", self.count) + struct.pack("<I", len(msg_bytes)) + msg_bytes
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"MultipingPacket(count={self.count}, message={self.message}, control={self.control})"

class GetMsgSizePacket(Packet):
    message_type = PacketType.GETMSGSIZE

    def __init__(self, *, payload: bytes = None, message: bytes = None):
        if payload is not None:
            msg_len = struct.unpack("<I", payload[:4])[0]
            self.message = payload[4:4 + msg_len]
        elif message is not None:
            self.message = message
        else:
            raise ValueError("Either payload or message must be provided.")

    def pack(self) -> bytes:
        msg_bytes = self.message
        payload = struct.pack("<I", len(msg_bytes)) + msg_bytes
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"GetMsgSizePacket(message={self.message}, control={self.control})"

class SendUcodePacket(Packet):
    message_type = PacketType.SENDUCODE

    def __init__(self, *, payload: bytes = None, target_slot: int = None, ucode: bytes = None):
        # Structure: 4-byte target slot, 4-byte ucode size, then ucode bytes.
        if payload is not None:
            self.target_slot = struct.unpack("<I", payload[:4])[0]
            ucode_size = struct.unpack("<I", payload[4:8])[0]
            self.ucode = payload[8:8 + ucode_size]
        elif target_slot is not None and ucode is not None:
            self.target_slot = target_slot
            self.ucode = ucode
        else:
            raise ValueError("Either payload or both target_slot and ucode must be provided.")

    def pack(self) -> bytes:
        ucode_size = len(self.ucode)
        payload = struct.pack("<II", self.target_slot, ucode_size) + self.ucode
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"SendUcodePacket(target_slot={self.target_slot}, ucode_size={len(self.ucode)}, control={self.control})"

class FlipBitsPacket(Packet):
    message_type = PacketType.FLIPBITS

    def __init__(self, *, payload: bytes = None, source_slot: int = None, flips: list = None):
        # Structure: 4-byte source slot, 4-byte number of flips, then array of 4-byte bit positions.
        if payload is not None:
            self.source_slot = struct.unpack("<I", payload[:4])[0]
            num_flips = struct.unpack("<I", payload[4:8])[0]
            self.flip_positions = []
            for i in range(num_flips):
                start = 8 + i * 4
                self.flip_positions.append(struct.unpack("<I", payload[start:start+4])[0])
        elif source_slot is not None and flips is not None:
            self.source_slot = source_slot
            self.flip_positions = flips
        else:
            raise ValueError("Either payload or both source_slot and flips must be provided.")

    def pack(self) -> bytes:
        num_flips = len(self.flip_positions)
        payload = struct.pack("<II", self.source_slot, num_flips)
        for pos in self.flip_positions:
            payload += struct.pack("<I", pos)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"FlipBitsPacket(source_slot={self.source_slot}, num_flips={len(self.flip_positions)}, control={self.control})"

class ApplyUcodePacket(Packet):
    message_type = PacketType.APPLYUCODE

    def __init__(self, *, payload: bytes = None, target_slot: int = None, apply_known_good: bool = None):
        # Structure: 4-byte target slot, 4-byte options.
        # Bit 0 of options indicates whether to apply the known good update.
        if payload is not None:
            self.target_slot = struct.unpack("<I", payload[:4])[0]
            options = struct.unpack("<I", payload[4:8])[0]
            self.apply_known_good = bool(options & 0x1)
        elif target_slot is not None and apply_known_good is not None:
            self.target_slot = target_slot
            self.apply_known_good = apply_known_good
        else:
            raise ValueError("Either payload or both target_slot and apply_known_good must be provided.")

    def pack(self) -> bytes:
        options = 1 if self.apply_known_good else 0
        payload = struct.pack("<II", self.target_slot, options)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return (f"ApplyUcodePacket(target_slot={self.target_slot}, "
                f"apply_known_good={self.apply_known_good}, control={self.control})")

class ReadMsrPacket(Packet):
    message_type = PacketType.READMSR

    def __init__(self, *, payload: bytes = None, target_msr: int = None):
        # Structure: 4-byte target MSR.
        if payload is not None:
            self.target_msr = struct.unpack("<I", payload[:4])[0]
        elif target_msr is not None:
            self.target_msr = target_msr
        else:
            raise ValueError("Either payload or target_msr must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<I", self.target_msr)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"ReadMsrPacket(target_msr={self.target_msr}, control={self.control})"

class ReadMsrOnCorePacket(Packet):
    message_type = PacketType.READMSRONCORE
    def __init__(self, *, payload: bytes = None, target_msr: int = None, target_core: int = None):
        # Structure: 4-byte target MSR, 8-byte target core ID.
        if payload is not None:
            self.target_msr = struct.unpack("<I", payload[:4])[0]
            self.target_core = struct.unpack("<Q", payload[4:12])[0]
        elif target_msr is not None and target_core is not None:
            self.target_msr = target_msr
            self.target_core = target_core
        else:
            raise ValueError("Either payload or both target_msr and target_core must be provided.")
    def pack(self) -> bytes:
        payload = struct.pack("<I", self.target_msr) + struct.pack("<Q", self.target_core)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload
    def __repr__(self):
        return f"ReadMsrOnCorePacket(target_msr=0x{self.target_msr:X}, target_core={self.target_core}, control={self.control})"


class GetCoreCountPacket(Packet):
    message_type = PacketType.GETCORECOUNT

    def __init__(self, *, payload: bytes = None):
        # GETCORECOUNT has no payload.
        if payload is not None:
            # Even if payload is present, ignore it.
            pass

    def pack(self) -> bytes:
        payload = b""
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return "GetCoreCountPacket()"

class ApplyUcodeExecuteTestPacket(Packet):
    message_type = PacketType.APPLYUCODEEXCUTETEST

    def __init__(self, *, payload: bytes = None, target_ucode_slot: int = None, target_machine_code_slot: int = None,
                 target_core: int = None, timeout: int = None, apply_known_good: bool = None):
        # 4 bytes: target ucode slot
        # 4 bytes: target machine code slot
        # 4 bytes: target core number
        # 4 bytes: timeout (0 for unlimited)
        # 4 bytes: options (lower byte: bit 0 = apply known good update flag)
        if payload is not None:
            self.target_ucode_slot = struct.unpack("<I", payload[:4])[0]
            self.target_machine_code_slot = struct.unpack("<I", payload[4:8])[0]
            self.target_core = struct.unpack("<I", payload[8:12])[0]
            self.timeout = struct.unpack("<I", payload[12:16])[0]
            options = struct.unpack("<I", payload[16:20])[0]
            self.apply_known_good = bool(options & 0x1)
        elif (target_ucode_slot is not None and target_machine_code_slot is not None and
              target_core is not None and timeout is not None and apply_known_good is not None):
            self.target_ucode_slot = target_ucode_slot
            self.target_machine_code_slot = target_machine_code_slot
            self.target_core = target_core
            self.timeout = timeout
            self.apply_known_good = apply_known_good
        else:
            raise ValueError("Either payload or all of target_ucode_slot, target_machine_code_slot, target_core, timeout, and apply_known_good must be provided.")

    def pack(self) -> bytes:
        options = 1 if self.apply_known_good else 0
        payload = (struct.pack("<I", self.target_ucode_slot) +
                   struct.pack("<I", self.target_machine_code_slot) +
                   struct.pack("<I", self.target_core) +
                   struct.pack("<I", self.timeout) +
                   struct.pack("<I", options))
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return (f"ApplyUcodeExecuteTestPacket(target_ucode_slot={self.target_ucode_slot}, "
                f"target_machine_code_slot={self.target_machine_code_slot}, target_core={self.target_core}, "
                f"timeout={self.timeout}, apply_known_good={self.apply_known_good}, control={self.control})")

class SendMachineCodePacket(Packet):
    message_type = PacketType.SENDMACHINECODE

    def __init__(self, *, payload: bytes = None, target_slot: int = None, machine_code: bytes = None):
        # Structure: 4-byte target slot, 4-byte machine code size, then machine code bytes.
        if payload is not None:
            self.target_slot = struct.unpack("<I", payload[:4])[0]
            code_size = struct.unpack("<I", payload[4:8])[0]
            self.machine_code = payload[8:8+code_size]
        elif target_slot is not None and machine_code is not None:
            self.target_slot = target_slot
            self.machine_code = machine_code
        else:
            raise ValueError("Either payload or both target_slot and machine_code must be provided.")

    def pack(self) -> bytes:
        code_size = len(self.machine_code)
        payload = struct.pack("<II", self.target_slot, code_size) + self.machine_code
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"SendMachineCodePacket(target_slot={self.target_slot}, machine_code_size={len(self.machine_code)}, control={self.control})"

class GetLastTestResultPacket(Packet):
    message_type = PacketType.GETLASTTESTRESULT 

    def __init__(self, *, payload: bytes = None, core: int = None):
        # Payload: 8-byte unsigned LE core number.
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Either payload or core must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<Q", self.core)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"GetLastTestResultPacket(core={self.core})"

class StartCorePacket(Packet):
    message_type = PacketType.STARTCORE

    def __init__(self, *, payload: bytes = None, core: int = None):
        # Payload: 8-byte unsigned LE core number.
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Either payload or core must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<Q", self.core)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"StartCorePacket(core={self.core})"

class GetCoreStatusPacket(Packet):
    message_type = PacketType.GETCORESTATUS

    def __init__(self, *, payload: bytes = None, core: int = None):
        # Payload: 8-byte unsigned LE core number.
        if payload is not None:
            self.core = struct.unpack("<Q", payload[:8])[0]
        elif core is not None:
            self.core = core
        else:
            raise ValueError("Either payload or core must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<Q", self.core)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"GetCoreStatusPacket(core={self.core})"


# ======== Response Packets ========

class StatusPacket(Packet):
    message_type = PacketType.STATUS

    def __init__(self, *, payload: bytes = None, status_code: int = None, text: bytes = b""):
        # Structure: 4-byte status code, 4-byte text length, then text bytes.
        if payload is not None:
            self.status_code = struct.unpack("<I", payload[:4])[0]
            text_len = struct.unpack("<I", payload[4:8])[0]
            self.text = payload[8:8+text_len].decode("utf_16_le") if text_len > 0 else ""
        elif status_code is not None:
            self.status_code = status_code
            self.text = text
        else:
            raise ValueError("Either payload or status_code must be provided.")

    def pack(self) -> bytes:
        text_bytes = bytes(self.text, "utf_16_le")
        payload = struct.pack("<I", self.status_code) + struct.pack("<I", len(text_bytes)) + text_bytes
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"StatusPacket(status_code=0x{self.status_code:X}, text={self.text}, control={self.control})"

class PongPacket(Packet):
    message_type = PacketType.PONG

    def __init__(self, *, payload: bytes = None, message: bytes = None):
        # Structure: 4-byte message length, then message bytes.
        if payload is not None:
            msg_len = struct.unpack("<I", payload[:4])[0]
            self.message = payload[4:4+msg_len]
        elif message is not None:
            self.message = message
        else:
            raise ValueError("Either payload or message must be provided.")

    def pack(self) -> bytes:
        msg_bytes = self.message
        payload = struct.pack("<I", len(msg_bytes)) + msg_bytes
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"PongPacket(message={self.message}, control={self.control})"

class MsgSizePacket(Packet):
    message_type = PacketType.MSGSIZE

    def __init__(self, *, payload: bytes = None, received_length: int = None):
        # Structure: 4-byte received message length.
        if payload is not None:
            self.received_length = struct.unpack("<I", payload[:4])[0]
        elif received_length is not None:
            self.received_length = received_length
        else:
            raise ValueError("Either payload or received_length must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<I", self.received_length)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"MsgSizePacket(received_length={self.received_length}, control={self.control})"

class UcodeResponsePacket(Packet):
    message_type = PacketType.UCODERESPONSE

    def __init__(self, *, payload: bytes = None, rdtsc_diff: int = None, rax: int = None):
        # Structure: 8-byte rdtsc difference.
        if payload is not None:
            self.rdtsc_diff = struct.unpack("<Q", payload[:8])[0]
            self.rax = struct.unpack("<Q", payload[8:16])[0]
        elif rdtsc_diff is not None and rax is not None:
            self.rdtsc_diff = rdtsc_diff
            self.rax = rax
        else:
            raise ValueError("Either payload or rdtsc_diff must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<QQ", self.rdtsc_diff, self.rax)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"UcodeResponsePacket(rdtsc_diff={self.rdtsc_diff}, rax={self.rax:016X}, control={self.control})"

class MsrResponsePacket(Packet):
    message_type = PacketType.MSRRESPONSE

    def __init__(self, *, payload: bytes = None, eax: int = None, edx: int = None):
        # Structure: 4-byte EAX and 4-byte EDX.
        if payload is not None:
            self.eax = struct.unpack("<I", payload[:4])[0]
            self.edx = struct.unpack("<I", payload[4:8])[0]
        elif eax is not None and edx is not None:
            self.eax = eax
            self.edx = edx
        else:
            raise ValueError("Either payload or both eax and edx must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<II", self.eax, self.edx)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"MsrResponsePacket(eax={self.eax}, edx={self.edx}, control={self.control})"

# New Response Packet: CORECOUNTRESPONSE
class CoreCountResponsePacket(Packet):
    message_type = PacketType.CORECOUNTRESPONSE

    def __init__(self, *, payload: bytes = None, core_count: int = None):
        # Structure: 8-byte unsigned little-endian core count.
        if payload is not None:
            self.core_count = struct.unpack("<Q", payload[:8])[0]
        elif core_count is not None:
            self.core_count = core_count
        else:
            raise ValueError("Either payload or core_count must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<Q", self.core_count)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"CoreCountResponsePacket(core_count={self.core_count}, control={self.control})"

class RebootPacket(Packet):
    message_type = PacketType.REBOOT

    def __init__(self, *, payload: bytes = None, warm: bool = False):
        """
        If payload is provided, parse the 4-byte options.
        Otherwise, use the provided 'warm' flag.
        """
        if payload is not None:
            # The payload is a 4-byte unsigned little-endian integer.
            options, = struct.unpack("<I", payload[:4])
            # The lowest byte holds the flags; bit 0 indicates warm reboot.
            self.warm = bool(options & 0x1)
        else:
            self.warm = warm

    def pack(self) -> bytes:
        # Build the payload: 4-byte LE unsigned integer.
        # Upper 3 bytes are unused (0); lower byte: bit 0 set if warm reboot is desired.
        flags = 1 if self.warm else 0
        payload = struct.pack("<I", flags)
        header = struct.pack("<I4B I",
                             len(payload) + 8,  # payload + (metadata+msg_type)
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return f"RebootPacket(warm={self.warm}, control={self.control})"

class UcodeExecuteTestResponsePacket(Packet):
    message_type = PacketType.UCODEEXECUTETESTRESPONSE

    def __init__(self, *, payload: bytes = None, rdtsc_diff: int = None, rax: int = None, flags: int = None, result_buffer: bytes = None):
        # Structure:
        # 8 bytes LE unsigned - rdtsc_diff
        # 8 bytes LE unsigned - RAX
        # 8 bytes LE unsigned - flags (only lowest byte used; bit0 set if timeout reached)
        # 8 bytes LE unsigned - length of result buffer
        # up to 1024 bytes - result buffer
        if payload is not None:
            self.rdtsc_diff = struct.unpack("<Q", payload[:8])[0]
            self.rax = struct.unpack("<Q", payload[8:16])[0]
            self.flags = struct.unpack("<Q", payload[16:24])[0]
            result_len = struct.unpack("<Q", payload[24:32])[0]
            self.result_buffer = payload[32:32+result_len]
        elif rdtsc_diff is not None and rax is not None and flags is not None and result_buffer is not None:
            self.rdtsc_diff = rdtsc_diff
            self.rax = rax
            self.flags = flags
            self.result_buffer = result_buffer
        else:
            raise ValueError("Either payload or all of rdtsc_diff, rax, flags, and result_buffer must be provided.")

    def pack(self) -> bytes:
        result_len = len(self.result_buffer)
        payload = (struct.pack("<Q", self.rdtsc_diff) +
                   struct.pack("<Q", self.rax) +
                   struct.pack("<Q", self.flags) +
                   struct.pack("<Q", result_len) +
                   self.result_buffer)
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return (f"UcodeExecuteTestResponsePacket(rdtsc_diff={self.rdtsc_diff}, rax={self.rax:016X}, "
                f"flags={self.flags:#018x}, result_buffer_length={len(self.result_buffer)}, control={self.control})")

class CoreStatusResponsePacket(Packet):
    message_type = PacketType.CORESTATUSRESPONSE

    def __init__(self, *, payload: bytes = None, flags: int = None, last_heartbeat: int = None, current_rdtsc: int = None):
        # Structure: 
        # 8-byte unsigned LE flags,
        # 8-byte unsigned LE last heartbeat RDTSC,
        # 8-byte unsigned LE current RDTSC.
        if payload is not None:
            self.flags = struct.unpack("<Q", payload[:8])[0]
            self.last_heartbeat = struct.unpack("<Q", payload[8:16])[0]
            self.current_rdtsc = struct.unpack("<Q", payload[16:24])[0]
        elif flags is not None and last_heartbeat is not None and current_rdtsc is not None:
            self.flags = flags
            self.last_heartbeat = last_heartbeat
            self.current_rdtsc = current_rdtsc
        else:
            raise ValueError("Either payload or all of flags, last_heartbeat, and current_rdtsc must be provided.")

    @property
    def present(self):
        return bool(self.flags & 0x1)

    @property
    def started(self):
        return bool(self.flags & 0x2)

    @property
    def ready(self):
        return bool(self.flags & 0x4)

    @property
    def job_queued(self):
        return bool(self.flags & 0x8)

    @property
    def is_locked(self):
        return bool(self.flags & 0x10)

    def pack(self) -> bytes:
        payload = (
            struct.pack("<Q", self.flags) +
            struct.pack("<Q", self.last_heartbeat) +
            struct.pack("<Q", self.current_rdtsc)
        )
        header = struct.pack("<I4B I",
                             len(payload) + 8,
                             self.major, self.minor, self.control, self.reserved,
                             self.message_type.value)
        return header + payload

    def __repr__(self):
        return (f"CoreStatusResponsePacket(flags={self.flags:#018x} (present={self.present}, started={self.started}, "
                f"ready={self.ready}, job_queued={self.job_queued}, is_locked={self.is_locked}), "
                f"last_heartbeat={self.last_heartbeat}, current_rdtsc={self.current_rdtsc}, control={self.control})")


# ======== Packet Parser ========

def parse_packet(data: bytes) -> Packet:
    if len(data) < 12:
        raise ValueError("Data too short to be a valid packet.")
    msg_len, maj, mino, ctrl, res, msg_type = struct.unpack("<I4B I", data[:12])
    total_len = 4 + msg_len
    if len(data) != total_len:
        raise ValueError(f"Data length mismatch: expected {total_len} bytes, got {len(data)} bytes.")
    payload = data[12:]
    if msg_type == PacketType.PING.value:
        pkt = PingPacket(payload=payload)
    elif msg_type == PacketType.MULTIPING.value:
        pkt = MultipingPacket(payload=payload)
    elif msg_type == PacketType.GETMSGSIZE.value:
        pkt = GetMsgSizePacket(payload=payload)
    elif msg_type == PacketType.SENDUCODE.value:
        pkt = SendUcodePacket(payload=payload)
    elif msg_type == PacketType.FLIPBITS.value:
        pkt = FlipBitsPacket(payload=payload)
    elif msg_type == PacketType.APPLYUCODE.value:
        pkt = ApplyUcodePacket(payload=payload)
    elif msg_type == PacketType.READMSR.value:
        pkt = ReadMsrPacket(payload=payload)
    elif msg_type == PacketType.REBOOT.value:
        pkt = RebootPacket(payload=payload)
    elif msg_type == PacketType.APPLYUCODEEXCUTETEST.value:
        pkt = ApplyUcodeExecuteTestPacket(payload=payload)
    elif msg_type == PacketType.SENDMACHINECODE.value:
        pkt = SendMachineCodePacket(payload=payload)
    elif msg_type == PacketType.GETCORECOUNT.value:
        pkt = GetCoreCountPacket(payload=payload)
    elif msg_type == PacketType.GETLASTTESTRESULT.value:
        pkt = GetLastTestResultPacket(payload=payload)
    elif msg_type == PacketType.STARTCORE.value:
        pkt = StartCorePacket(payload=payload)
    elif msg_type == PacketType.GETCORESTATUS.value:
        pkt = GetCoreStatusPacket(payload=payload)
    elif msg_type == PacketType.STATUS.value:
        pkt = StatusPacket(payload=payload)
    elif msg_type == PacketType.PONG.value:
        pkt = PongPacket(payload=payload)
    elif msg_type == PacketType.MSGSIZE.value:
        pkt = MsgSizePacket(payload=payload)
    elif msg_type == PacketType.UCODERESPONSE.value:
        pkt = UcodeResponsePacket(payload=payload)
    elif msg_type == PacketType.MSRRESPONSE.value:
        pkt = MsrResponsePacket(payload=payload)
    elif msg_type == PacketType.UCODEEXECUTETESTRESPONSE.value:
        pkt = UcodeExecuteTestResponsePacket(payload=payload)
    elif msg_type == PacketType.CORECOUNTRESPONSE.value:
        pkt = CoreCountResponsePacket(payload=payload)
    elif msg_type == PacketType.CORESTATUSRESPONSE.value:
        pkt = CoreStatusResponsePacket(payload=payload)
    elif msg_type == PacketType.READMSRONCORE.value:
        pkt = ReadMsrOnCorePacket(payload=payload)
    else:
        raise ValueError(f"Unknown packet type 0x{msg_type:08X}.")
    pkt.major = maj
    pkt.minor = mino
    pkt.control = ctrl
    pkt.reserved = res
    return pkt


# ======== Example Usage ========
if __name__ == "__main__":
    # Example: Create, pack, and parse a PingPacket.
    ping = PingPacket(message=b"Hello, AngryUEFI!")
    data_ping = ping.pack()
    print("Ping packet bytes:", data_ping)
    pkt_ping = parse_packet(data_ping)
    print("Parsed packet:", pkt_ping)

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
    EXECUTEMACHINECODE   = 0x153

    # Response Packet Types
    STATUS        = 0x80000000
    PONG          = 0x80000001
    MSGSIZE       = 0x80000003
    UCODERESPONSE = 0x80000141
    MSRRESPONSE   = 0x80000201
    UCODEEXECUTETESTRESPONSE = 0x80000151
    CORECOUNTRESPONSE        = 0x80000211
    CORESTATUSRESPONSE       = 0x80000213

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
        return f"StatusPacket(code=0x{self.status_code:X}, text={self.text.decode("utf_16_le")}, control={self.control})"

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
        return f"PongPacket(message={self.message.decode("utf_16_le")}, control={self.control})"

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

class CoreStatusResponsePacket(Packet):
    message_type = PacketType.CORESTATUSRESPONSE
    def __init__(self, *, payload: bytes = None,
                 flags: int = None, last_heartbeat: int = None,
                 current_rdtsc: int = None, fault_info: CoreStatusFaultInfo = None):
        if payload is not None:
            self.flags = struct.unpack("<Q", payload[:8])[0]
            self.last_heartbeat = struct.unpack("<Q", payload[8:16])[0]
            self.current_rdtsc  = struct.unpack("<Q", payload[16:24])[0]
            fl = struct.unpack("<Q", payload[24:32])[0]
            self.fault_info = CoreStatusFaultInfo(payload[32:32+fl]) if fl else None
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

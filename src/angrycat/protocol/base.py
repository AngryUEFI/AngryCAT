from typing import Any
import socket
import struct

from .ids import PacketType


class Packet:
    """Base class for all packets"""
    major    = 1
    minor    = 0
    control  = 0  # Bit0: another message follows if set
    reserved = 0

    message_type: PacketType
    registry: dict[PacketType, Any] = {}

    @classmethod
    def register(cls, packet_id: PacketType):
        if packet_id in cls.registry:
            raise ValueError(f"Duplicate packet ID {packet_id} for {cls.__name__}")
        cls.registry[packet_id] = cls
        cls.packet_id = packet_id
        return cls

    @classmethod
    def get_class_for_type(cls, packet_id: PacketType) -> Any:
        return cls.registry.get(packet_id)

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
        """Read until control bit0==0 (end-of-transmission)."""
        msgs = []
        while True:
            pkt = cls.read_from_socket(sock)
            msgs.append(pkt)
            if (pkt.control & 0x1) == 0:
                break
        return msgs

    def __repr__(self):
        return f"<{self.__class__.__name__}>"


def parse_packet(data: bytes) -> Packet:
    if len(data) < 12:
        raise ValueError("Data too short for valid packet")
    msg_len, maj, mino, ctrl, res, msg_type = struct.unpack("<I4B I", data[:12])
    if len(data) != 4 + msg_len:
        raise ValueError(f"Length mismatch (got {len(data)}, expected {4+msg_len})")
    payload = data[12:]
    cls = Packet.get_class_for_type(msg_type)
    if not cls:
        raise ValueError(f"Unknown packet type 0x{msg_type:08X}")
    pkt = cls(payload=payload)
    pkt.major, pkt.minor, pkt.control, pkt.reserved = maj, mino, ctrl, res
    return pkt

#!/usr/bin/env python3
import struct
import socket
from enum import Enum

class PacketType(Enum):
    # Request Packet Types
    PING = 0x1
    MULTIPING = 0x2
    GETMSGSIZE = 0x3
    # Response Packet Types
    STATUS = 0x80000000
    PONG = 0x80000001
    MSGSIZE = 0x80000003

# Base class for all packets.
class Packet:
    # Default header values.
    major = 1
    minor = 0
    control = 0  # Bitfield: Bit 0: 0 means end-of-transmission; 1 means another message follows.
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

# A generic packet for unknown message types.
class UnknownPacket(Packet):
    def __init__(self, message_type, payload: bytes):
        self.message_type = message_type  # expected to be an int
        self.payload = payload

    def pack(self) -> bytes:
        header = struct.pack(
            "<I4B I",
            len(self.payload) + 8,  # payload + (metadata+msg_type)
            self.major, self.minor, self.control, self.reserved,
            self.message_type
        )
        return header + self.payload

    def __repr__(self):
        return f"UnknownPacket(message_type=0x{self.message_type:08X}, payload={self.payload})"

# ======== Request Packets ========

class PingPacket(Packet):
    message_type = PacketType.PING

    def __init__(self, *, payload: bytes = None, message: bytes = None):
        """
        If payload is given, parse the internal structure:
          - 4-byte little-endian integer (message length)
          - message (as bytes)
        Otherwise, use the provided message bytes.
        """
        if payload is not None:
            msg_len = struct.unpack("<I", payload[:4])[0]
            self.message = payload[4:4 + msg_len]
        elif message is not None:
            self.message = message
        else:
            raise ValueError("Either payload or message must be provided.")

    def pack(self) -> bytes:
        msg_bytes = self.message  # already bytes
        payload = struct.pack("<I", len(msg_bytes)) + msg_bytes
        header = struct.pack(
            "<I4B I",
            len(payload) + 8,  # payload + metadata (4) + message_type (4)
            self.major, self.minor, self.control, self.reserved,
            self.message_type.value
        )
        return header + payload

    def __repr__(self):
        return f"PingPacket(message={self.message}, control={self.control})"

class MultipingPacket(Packet):
    message_type = PacketType.MULTIPING

    def __init__(self, *, payload: bytes = None, count: int = None, message: bytes = None):
        """
        If payload is provided, parse it as:
          - 4-byte little-endian integer: count
          - 4-byte little-endian integer: message length
          - message (as bytes)
        Otherwise, use the provided count and message.
        """
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
        payload = (struct.pack("<I", self.count) +
                   struct.pack("<I", len(msg_bytes)) +
                   msg_bytes)
        header = struct.pack(
            "<I4B I",
            len(payload) + 8,
            self.major, self.minor, self.control, self.reserved,
            self.message_type.value
        )
        return header + payload

    def __repr__(self):
        return f"MultipingPacket(count={self.count}, message={self.message}, control={self.control})"

class GetMsgSizePacket(Packet):
    message_type = PacketType.GETMSGSIZE

    def __init__(self, *, payload: bytes = None, message: bytes = None):
        """
        If payload is provided, parse it as:
          - 4-byte little-endian integer: message length
          - message (as bytes)
        Otherwise, use the provided message.
        """
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
        header = struct.pack(
            "<I4B I",
            len(payload) + 8,
            self.major, self.minor, self.control, self.reserved,
            self.message_type.value
        )
        return header + payload

    def __repr__(self):
        return f"GetMsgSizePacket(message={self.message}, control={self.control})"

# ======== Response Packets ========

class StatusPacket(Packet):
    message_type = PacketType.STATUS

    def __init__(self, *, payload: bytes = None, status_code: int = None, text: bytes = b""):
        """
        If payload is provided, parse it as:
          - 4-byte little-endian integer: status code
          - 4-byte little-endian integer: text length
          - text (as bytes)
        Otherwise, use the provided status_code and text.
        """
        if payload is not None:
            self.status_code = struct.unpack("<I", payload[:4])[0]
            text_len = struct.unpack("<I", payload[4:8])[0]
            if text_len:
                self.text = payload[8:8 + text_len]
            else:
                self.text = b""
        elif status_code is not None:
            self.status_code = status_code
            self.text = text
        else:
            raise ValueError("Either payload or status_code must be provided.")

    def pack(self) -> bytes:
        text_bytes = self.text
        payload = (struct.pack("<I", self.status_code) +
                   struct.pack("<I", len(text_bytes)) +
                   text_bytes)
        header = struct.pack(
            "<I4B I",
            len(payload) + 8,
            self.major, self.minor, self.control, self.reserved,
            self.message_type.value
        )
        return header + payload

    def __repr__(self):
        return f"StatusPacket(status_code={self.status_code}, text={self.text}, control={self.control})"

class PongPacket(Packet):
    message_type = PacketType.PONG

    def __init__(self, *, payload: bytes = None, message: bytes = None):
        """
        If payload is provided, parse it as:
          - 4-byte little-endian integer: message length
          - message (as bytes)
        Otherwise, use the provided message.
        """
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
        header = struct.pack(
            "<I4B I",
            len(payload) + 8,
            self.major, self.minor, self.control, self.reserved,
            self.message_type.value
        )
        return header + payload

    def __repr__(self):
        return f"PongPacket(message={self.message}, control={self.control})"

class MsgSizePacket(Packet):
    message_type = PacketType.MSGSIZE

    def __init__(self, *, payload: bytes = None, received_length: int = None):
        if payload is not None:
            self.received_length = struct.unpack("<I", payload[:4])[0]
        elif received_length is not None:
            self.received_length = received_length
        else:
            raise ValueError("Either payload or received_length must be provided.")

    def pack(self) -> bytes:
        payload = struct.pack("<I", self.received_length)
        header = struct.pack(
            "<I4B I",
            len(payload) + 8,
            self.major, self.minor, self.control, self.reserved,
            self.message_type.value
        )
        return header + payload

    def __repr__(self):
        return f"MsgSizePacket(received_length={self.received_length}, control={self.control})"

# ======== Packet Parser ========

def parse_packet(data: bytes) -> Packet:
    """
    Given a complete binary packet (including header), parse it into the appropriate Packet subclass.
    The header is 12 bytes:
      - 4 bytes: Message Length (unsigned little-endian), which is the total length of metadata, message type, and payload.
      - 4 bytes: Metadata (Major, Minor, Control, Reserved).
      - 4 bytes: Message Type.
    The total packet length should equal 4 + Message Length.
    This function assigns the header fields (major, minor, control, reserved) to the returned packet.
    """
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
    elif msg_type == PacketType.STATUS.value:
        pkt = StatusPacket(payload=payload)
    elif msg_type == PacketType.PONG.value:
        pkt = PongPacket(payload=payload)
    elif msg_type == PacketType.MSGSIZE.value:
        pkt = MsgSizePacket(payload=payload)
    else:
        pkt = UnknownPacket(msg_type, payload)

    pkt.major = maj
    pkt.minor = mino
    pkt.control = ctrl
    pkt.reserved = res
    return pkt

# ======== Example Usage ========
if __name__ == "__main__":
    # Example: Create, pack, and parse a PingPacket.
    # Note: The message is now a bytes object.
    ping = PingPacket(message=b"Hello, AngryUEFI!")
    data_ping = ping.pack()
    print("Ping packet bytes:", data_ping)
    pkt_ping = parse_packet(data_ping)
    print("Parsed packet:", pkt_ping)

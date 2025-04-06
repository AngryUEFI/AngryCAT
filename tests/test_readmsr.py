#!/usr/bin/env python3
import os
import sys
import socket
import unittest
import time

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import ReadMsrPacket, MsrResponsePacket
from protocol import (
    GetCoreCountPacket,
    CoreCountResponsePacket,
    GetCoreStatusPacket,
    CoreStatusResponsePacket,
    StartCorePacket,
    RebootPacket,
    StatusPacket,
    PingPacket,
    Packet,
    PacketType,
    RebootPacket,
)

# Use environment variables to allow overriding host/port, with defaults.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))
ALLOW_REBOOT = os.getenv("ALLOW_REBOOT", "0") == "1"

def send_packet(packet_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet_bytes)
        return Packet.read_from_socket(sock)

def send_read_msr(target_msr: int, host=HOST, port=PORT) -> MsrResponsePacket:
    """
    Connects to AngryUEFI, sends a READMSR packet with the specified target MSR,
    and returns the parsed response as an MsrResponsePacket.
    """
    req = ReadMsrPacket(target_msr=target_msr)
    req_bytes = req.pack()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(req_bytes)
        response = Packet.read_from_socket(sock)
    return response

def send_get_core_count():
    pkt = GetCoreCountPacket()
    resp = send_packet(pkt.pack())
    if resp.message_type != PacketType.CORECOUNTRESPONSE:
        raise RuntimeError("Did not receive CORECOUNTRESPONSE")
    return resp

def send_get_core_status(core):
    pkt = GetCoreStatusPacket(core=core)
    return send_packet(pkt.pack())

def send_reboot():
    pkt = RebootPacket(warm=False)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt.pack())
    # Wait up to 60 seconds for target to reboot.
    for wait in range(30, 61, 5):
        try:
            # Try sending a ping to see if target is up.
            from protocol import PingPacket
            ping = PingPacket(message=b"test")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((HOST, PORT))
                sock.sendall(ping.pack())
                Packet.read_from_socket(sock)
            return
        except Exception:
            time.sleep(5)
    raise RuntimeError("Target did not reboot in time")

class ReadMsrTestCase(unittest.TestCase):
    def setUp(self):
        # Step 1: Check at least 2 cores present.
        core_count_resp = send_get_core_count()
        if core_count_resp.core_count < 2:
            self.skipTest("Target does not have at least 2 cores.")
        # Step 2: Check if core 1 is ready. If not, try starting it.
        status = send_get_core_status(1)
        if not status.ready:
            if ALLOW_REBOOT:
                send_reboot()
            else:
                self.skipTest("Core 1 not ready and reboot not allowed.")\

    def test_read_msr_0x10(self):
        target_msr = 0x10
        response = send_read_msr(target_msr)
        self.assertIsInstance(response, MsrResponsePacket,
                              "Response is not a MsrResponsePacket.")
        # no further checking, return is too different between emulator and real hardware

if __name__ == "__main__":
    unittest.main()

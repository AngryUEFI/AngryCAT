#!/usr/bin/env python3
import os
import sys
import socket
import unittest

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import ReadMsrPacket, MsrResponsePacket, Packet

# Use environment variables to allow overriding host/port, with defaults.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

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

class ReadMsrTestCase(unittest.TestCase):
    def test_read_msr_0x10(self):
        target_msr = 0x10
        response = send_read_msr(target_msr)
        self.assertIsInstance(response, MsrResponsePacket,
                              "Response is not a MsrResponsePacket.")
        # no further checking, return is too different between emulator and real hardware

if __name__ == "__main__":
    unittest.main()

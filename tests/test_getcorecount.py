#!/usr/bin/env python3
import os
import sys
import socket
import unittest
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
from protocol import GetCoreCountPacket, CoreCountResponsePacket, Packet, parse_packet

# Get target host and port from environment (defaults provided)
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

def send_packet(packet_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet_bytes)
        response = Packet.read_from_socket(sock)
    return response

class TestGetCoreCountPacket(unittest.TestCase):
    def test_get_core_count_network(self):
        """Send a GETCORECOUNT command and verify that the response is a CORECOUNTRESPONSE
           with a core count of at least 1."""
        pkt = GetCoreCountPacket()
        response = send_packet(pkt.pack())
        self.assertIsInstance(response, CoreCountResponsePacket, "Expected a CORECOUNTRESPONSE packet")
        self.assertGreaterEqual(response.core_count, 1, "Core count should be at least 1")

if __name__ == '__main__':
    unittest.main()

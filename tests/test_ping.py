#!/usr/bin/env python3
import os
import sys
import socket
import unittest

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import PingPacket, PongPacket, Packet

# Use environment variables to allow overriding host/port, with defaults.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

def send_ping(host=HOST, port=PORT, message=b"Hello, AngryUEFI!"):
    """
    Connects to AngryUEFI, sends a PING packet with the provided message (as bytes),
    and returns the parsed response packet using Packet.read_from_socket().
    """
    ping = PingPacket(message=message)
    ping_bytes = ping.pack()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(ping_bytes)
        response_packet = Packet.read_from_socket(sock)
    return response_packet

class PingTestCase(unittest.TestCase):
    def test_ping_pong(self):
        """Verify that sending a single PING packet returns a PONG packet with the correct payload."""
        test_message = b"Hello, AngryUEFI!"
        response_packet = send_ping(message=test_message)
        self.assertIsInstance(response_packet, PongPacket,
                              "Received packet is not a PONG packet.")
        self.assertEqual(response_packet.message, test_message,
                         "PONG payload does not match the sent message.")

    def test_ping_multiple_rounds(self):
        """Perform 3 rounds of PING and PONG exchanges, validating that each round returns a correct PONG response."""
        rounds = 3
        for i in range(rounds):
            with self.subTest(round=i+1):
                msg = b"Round Test #%d" % (i+1)
                response_packet = send_ping(message=msg)
                self.assertIsInstance(response_packet, PongPacket,
                                      f"Round {i+1}: Received packet is not a PONG packet.")
                self.assertEqual(response_packet.message, msg,
                                 f"Round {i+1}: PONG payload does not match the sent message.")

    def test_ping_large_payload(self):
        """Verify that sending a PING packet with a payload of 1020 bytes returns a PONG packet with the same payload.
           Note: 1020 bytes means exactly 1020 bytes since we are now working with raw byte strings."""
        large_payload = b"A" * 1020
        response_packet = send_ping(message=large_payload)
        self.assertIsInstance(response_packet, PongPacket,
                              "Large payload: Received packet is not a PONG packet.")
        self.assertEqual(response_packet.message, large_payload,
                         "Large payload: PONG payload does not match the sent payload.")

if __name__ == "__main__":
    unittest.main()

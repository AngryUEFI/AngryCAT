#!/usr/bin/env python3
import os
import sys
import socket
import unittest

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import MultipingPacket, PongPacket, Packet

# Use environment variables to allow overriding host/port, with defaults.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

def send_multiping(count, message, host=HOST, port=PORT):
    """
    Connects to AngryUEFI, sends a MultipingPacket with the given count and message (as bytes),
    and returns a list of response packets read using Packet.read_from_socket().
    """
    mp = MultipingPacket(count=count, message=message)
    mp_bytes = mp.pack()
    responses = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)  # Prevent hanging tests.
        sock.connect((host, port))
        sock.sendall(mp_bytes)
        for _ in range(count):
            responses.append(Packet.read_from_socket(sock))
    return responses

class MultipingTestCase(unittest.TestCase):
    def test_multiping_single(self):
        """Test that a MULTIPING request for one PONG returns a single PONG with control=0 and correct payload."""
        test_message = b"Multiping Single Test"
        responses = send_multiping(count=1, message=test_message)
        self.assertEqual(len(responses), 1, "Expected exactly 1 PONG response.")
        pkt = responses[0]
        self.assertIsInstance(pkt, PongPacket, "Response is not a PONG packet.")
        self.assertEqual(pkt.message, test_message, "PONG payload does not match the sent message.")
        # For a single response, the control bit (LSB) must be 0 (no further messages).
        self.assertEqual(pkt.control & 0x1, 0,
                         "Single PONG should have control bit 0 (no further messages).")

    def test_multiping_multiple(self):
        """Test that a MULTIPING request for 5 PONGs returns 5 responses with correct payload and control bits.
           All responses except the last should have control bit = 1, and the last should have it 0."""
        test_message = b"Multiping Multiple Test"
        count = 5
        responses = send_multiping(count=count, message=test_message)
        self.assertEqual(len(responses), count, f"Expected exactly {count} PONG responses.")
        for idx, pkt in enumerate(responses):
            self.assertIsInstance(pkt, PongPacket, f"Response {idx} is not a PONG packet.")
            self.assertEqual(pkt.message, test_message,
                             f"PONG payload in response {idx} does not match the sent message.")
            if idx < count - 1:
                self.assertEqual(pkt.control & 0x1, 1,
                                 f"Response {idx} should have control bit 1 (more messages expected).")
            else:
                self.assertEqual(pkt.control & 0x1, 0,
                                 "Last response should have control bit 0 (no further messages).")

if __name__ == "__main__":
    unittest.main()

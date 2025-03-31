#!/usr/bin/env python3
import os
import sys
import socket
import unittest

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import SendUcodePacket, StatusPacket, Packet

# Use environment variables to allow overriding host/port, with defaults.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

def send_send_ucode(target_slot: int, ucode: bytes, host=HOST, port=PORT):
    """
    Connects to AngryUEFI, sends a SENDUCODE packet with the given target slot and ucode bytes,
    and returns the parsed response packet.
    """
    pkt = SendUcodePacket(target_slot=target_slot, ucode=ucode)
    pkt_bytes = pkt.pack()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(pkt_bytes)
        response = Packet.read_from_socket(sock)
    return response

class SendUcodeTestCase(unittest.TestCase):
    def test_send_ucode_to_slot2(self):
        """
        Send a buffer of 5568 bytes to slot 2.
        The response should be a STATUS packet with status_code 0 and no text.
        """
        target_slot = 2
        # Create an arbitrary buffer of 5568 bytes.
        ucode_buffer = b'\xAA' * 5568
        response = send_send_ucode(target_slot, ucode_buffer)
        self.assertIsInstance(response, StatusPacket,
                              "Response is not a STATUS packet.")
        self.assertEqual(response.status_code, 0,
                         f"Expected status 0, got {response.status_code}.")

if __name__ == "__main__":
    unittest.main()

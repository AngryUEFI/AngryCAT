#!/usr/bin/env python3
import os
import socket
import unittest
import sys

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import (
    SendUcodePacket,
    ApplyUcodePacket,
    UcodeResponsePacket,
    StatusPacket,
    Packet,
)

# Use environment variables to allow overriding host/port, with defaults.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

def send_send_ucode(target_slot: int, ucode: bytes) -> StatusPacket:
    """
    Sends a SENDUCODE command to the given target slot with the specified ucode buffer,
    and returns the parsed response as a StatusPacket.
    """
    pkt = SendUcodePacket(target_slot=target_slot, ucode=ucode)
    pkt_bytes = pkt.pack()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt_bytes)
        response = Packet.read_from_socket(sock)
    return response

def send_apply_ucode(target_slot: int, apply_known_good: bool) -> UcodeResponsePacket:
    """
    Sends an APPLYUCODE command for the given target slot with the specified flag,
    and returns the parsed response as a UcodeResponsePacket.
    """
    pkt = ApplyUcodePacket(target_slot=target_slot, apply_known_good=apply_known_good)
    pkt_bytes = pkt.pack()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt_bytes)
        response = Packet.read_from_socket(sock)
    return response

class ApplyUcodeTestCase(unittest.TestCase):
    def test_apply_ucode(self):
        target_slot = 2
        # Create a buffer of 5568 bytes (arbitrary content, here filled with 0xAA)
        ucode_buffer = b'\xAA' * 5568

        # First, send a SENDUCODE command to load the update into slot 2.
        send_response = send_send_ucode(target_slot, ucode_buffer)
        self.assertIsInstance(send_response, StatusPacket,
                              "SENDUCODE response is not a STATUS packet.")
        self.assertEqual(send_response.status_code, 0,
                         f"SENDUCODE response status expected 0, got {send_response.status_code}.")
        self.assertEqual(send_response.text, b"",
                         "SENDUCODE response text is not empty.")

        # Now, send an APPLYUCODE command to apply the update in slot 2.
        # Here we set apply_known_good to False (i.e. do not apply a known good update afterward).
        apply_response = send_apply_ucode(target_slot, apply_known_good=False)
        self.assertIsInstance(apply_response, UcodeResponsePacket,
                              "APPLYUCODE response is not a UCODERESPONSE packet.")
        # Verify that the rdtsc difference is greater than 0.
        self.assertGreater(apply_response.rdtsc_diff, 0,
                           f"Expected rdtsc_diff > 0, got {apply_response.rdtsc_diff}.")

if __name__ == "__main__":
    unittest.main()

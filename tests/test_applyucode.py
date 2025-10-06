#!/usr/bin/env python3
import os
import socket
import unittest
import sys

from angrycat.protocol import (
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
    Sends an APPLYUCODE command for the given target slot with the specified flag.
    If apply_known_good is True, the known good update is applied after the test update.
    Returns the parsed response as a UcodeResponsePacket.
    """
    pkt = ApplyUcodePacket(target_slot=target_slot, apply_known_good=apply_known_good)
    pkt_bytes = pkt.pack()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt_bytes)
        response = Packet.read_from_socket(sock)
    return response

class ApplyUcodeTestCase(unittest.TestCase):
    def setUp(self):
        # Common target slot and ucode update buffer.
        self.target_slot = 2
        self.ucode_buffer = b'\xAA' * 5568

    def load_ucode(self):
        """Helper method to load ucode into slot 2."""
        response = send_send_ucode(self.target_slot, self.ucode_buffer)
        self.assertIsInstance(response, StatusPacket,
                              "SENDUCODE response is not a STATUS packet.")
        self.assertEqual(response.status_code, 0,
                         f"SENDUCODE response status expected 0, got {response.status_code}.")

    def test_apply_ucode(self):
        """Test applying the update in slot 2 without restoring the known good update.
           Verify that the rdtsc difference is greater than 0."""
        self.load_ucode()
        apply_response = send_apply_ucode(self.target_slot, apply_known_good=False)
        self.assertIsInstance(apply_response, UcodeResponsePacket,
                              "APPLYUCODE response is not a UCODERESPONSE packet.")
        self.assertGreater(apply_response.rdtsc_diff, 0,
                           f"Expected rdtsc_diff > 0, got {apply_response.rdtsc_diff}.")

    def test_apply_ucode_with_known_good(self):
        """Test applying the update in slot 2 and restoring the known good update afterwards.
           Verify that the rdtsc difference returned is greater than 0."""
        self.load_ucode()
        apply_response = send_apply_ucode(self.target_slot, apply_known_good=True)
        self.assertIsInstance(apply_response, UcodeResponsePacket,
                              "APPLYUCODE (with known good) response is not a UCODERESPONSE packet.")
        self.assertGreater(apply_response.rdtsc_diff, 0,
                           f"Expected rdtsc_diff > 0, got {apply_response.rdtsc_diff}.")

if __name__ == "__main__":
    unittest.main()

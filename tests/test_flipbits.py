#!/usr/bin/env python3
import os
import socket
import unittest

from angrycat.protocol import SendUcodePacket, FlipBitsPacket, StatusPacket, Packet

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

def send_flipbits(source_slot: int, flip_positions: list) -> StatusPacket:
    """
    Sends a FLIPBITS command using the specified source slot and a list of bit positions to flip.
    Returns the parsed response as a StatusPacket.
    """
    pkt = FlipBitsPacket(source_slot=source_slot, flips=flip_positions)
    pkt_bytes = pkt.pack()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt_bytes)
        response = Packet.read_from_socket(sock)
    return response

class FlipBitsTestCase(unittest.TestCase):
    def test_flipbits(self):
        # First, send a SENDUCODE command with a 5568-byte buffer to slot 2.
        target_slot = 2
        ucode_buffer = b'\xAA' * 5568
        response_ucode = send_send_ucode(target_slot, ucode_buffer)
        self.assertIsInstance(response_ucode, StatusPacket,
                              "SENDUCODE response is not a STATUS packet.")
        self.assertEqual(response_ucode.status_code, 0,
                         f"SENDUCODE response status expected 0, got {response_ucode.status_code}.")

        # Prepare the FLIPBITS command:
        # 50 bit positions less than 5568*8 (i.e. less than 44544)
        lower_positions = [100 + 10 * i for i in range(50)]
        # 10 bit positions between 5568*8 (44544) and 10000*8 (80000)
        upper_positions = [44544 + 100 + 50 * i for i in range(10)]
        flip_positions = lower_positions + upper_positions

        # Send FLIPBITS command with source slot 2 (flipping bits in the ucode loaded in slot 2).
        response_flipbits = send_flipbits(source_slot=2, flip_positions=flip_positions)
        self.assertIsInstance(response_flipbits, StatusPacket,
                              "FLIPBITS response is not a STATUS packet.")
        self.assertEqual(response_flipbits.status_code, 0,
                         f"FLIPBITS response status expected 0, got {response_flipbits.status_code}.")

if __name__ == "__main__":
    unittest.main()

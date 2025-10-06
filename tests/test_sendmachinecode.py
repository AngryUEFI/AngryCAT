#!/usr/bin/env python3
import os
import socket
import unittest

from angrycat.protocol import SendMachineCodePacket, StatusPacket, Packet, parse_packet

# Get target host and port from environment (defaults provided)
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

# mov rdx, 0xdeadbeefc0febabe; mov rax, [rax]; mov [rax], rdx; ret
# rax holds address of meta data structure
MACHINE_CODE = bytes([
    0x48, 0xBA, 0xBE, 0xBA, 0xFE, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x10, 0xC3
])

def send_packet(packet_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet_bytes)
        response = Packet.read_from_socket(sock)
    return response

class TestSendMachineCodePacket(unittest.TestCase):
    def test_send_machine_code_network(self):
        """Send a SENDMACHINECODE command to slot 1 and verify that a STATUS response with code 0 is returned."""
        pkt = SendMachineCodePacket(target_slot=1, machine_code=MACHINE_CODE)
        response = send_packet(pkt.pack())
        self.assertIsInstance(response, StatusPacket, "Expected a STATUS packet response for SENDMACHINECODE")
        self.assertEqual(response.status_code, 0, f"Expected status code 0, got {response.status_code}")

if __name__ == '__main__':
    unittest.main()

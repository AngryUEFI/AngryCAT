#!/usr/bin/env python3
import os
import socket
import unittest
import struct
import sys

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
from protocol import (
    SendMachineCodePacket,
    ApplyUcodeExecuteTestPacket,
    UcodeExecuteTestResponsePacket,
    StatusPacket,
    Packet,
    PacketType,
)

# Use environment variables for target host/port.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

def send_send_machine_code(target_slot: int, machine_code: bytes) -> StatusPacket:
    """Send a SENDMACHINECODE packet to the target and return the STATUS response."""
    pkt = SendMachineCodePacket(target_slot=target_slot, machine_code=machine_code)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt.pack())
        response = Packet.read_from_socket(sock)
    return response

def send_apply_ucode_execute_test(target_ucode_slot: int, target_machine_code_slot: int, apply_known_good: bool) -> UcodeExecuteTestResponsePacket:
    """Send an APPLYUCODEEXCUTETEST packet and return the UCODEEXECUTETESTRESPONSE."""
    pkt = ApplyUcodeExecuteTestPacket(
        target_ucode_slot=target_ucode_slot,
        target_machine_code_slot=target_machine_code_slot,
        apply_known_good=apply_known_good
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt.pack())
        response = Packet.read_from_socket(sock)
    return response

class ApplyUcodeExecuteTestNetworkTestCase(unittest.TestCase):
    def test_send_machine_code(self):
        """Send the machine code to slot 1 and verify that a STATUS response with code 0 is returned."""
        machine_code = bytes([
            0x48, 0xBA, 0xBE, 0xBA, 0xFE, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x10, 0xC3
        ])
        target_slot = 1
        response = send_send_machine_code(target_slot, machine_code)
        self.assertIsInstance(response, StatusPacket, "Expected STATUS response for SENDMACHINECODE")
        self.assertEqual(response.status_code, 0, f"Expected status code 0, got {response.status_code}")
        self.assertEqual(response.text, b"", "Expected empty text in STATUS response for SENDMACHINECODE")

    def test_apply_ucode_execute_test(self):
        """Send a SENDMACHINECODE followed by an APPLYUCODEEXCUTETEST command,
        then verify that the UCODEEXECUTETESTRESPONSE response's result buffer starts with 0xdeadbeefc0febabe."""
        # First, send the machine code test buffer to machine code slot 1.
        machine_code = bytes([
            0x48, 0xBA, 0xBE, 0xBA, 0xFE, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x10, 0xC3
        ])
        send_status = send_send_machine_code(1, machine_code)
        self.assertIsInstance(send_status, StatusPacket)
        self.assertEqual(send_status.status_code, 0)
        # Now send the APPLYUCODEEXCUTETEST command (use ucode slot 0 and machine code slot 1).
        response = send_apply_ucode_execute_test(target_ucode_slot=0, target_machine_code_slot=1, apply_known_good=False)
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "Expected UCODEEXECUTETESTRESPONSE from APPLYUCODEEXCUTETEST")
        # Check that the first 8 bytes of the result buffer equal 0xdeadbeefc0febabe.
        expected_value = 0xdeadbeefc0febabe
        expected_bytes = struct.pack("<Q", expected_value)
        self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short")
        self.assertEqual(response.result_buffer[:8], expected_bytes,
                         f"Expected first 8 bytes of result buffer to be {expected_bytes.hex()}, got {response.result_buffer[:8].hex()}")

    def test_apply_ucode_execute_test_restore(self):
        """Send a SENDMACHINECODE followed by an APPLYUCODEEXCUTETEST command,
        then verify that the UCODEEXECUTETESTRESPONSE response's result buffer starts with 0xdeadbeefc0febabe."""
        # First, send the machine code test buffer to machine code slot 1.
        machine_code = bytes([
            0x48, 0xBA, 0xBE, 0xBA, 0xFE, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x10, 0xC3
        ])
        send_status = send_send_machine_code(1, machine_code)
        self.assertIsInstance(send_status, StatusPacket)
        self.assertEqual(send_status.status_code, 0)
        # Now send the APPLYUCODEEXCUTETEST command (use ucode slot 0 and machine code slot 1).
        response = send_apply_ucode_execute_test(target_ucode_slot=0, target_machine_code_slot=1, apply_known_good=True)
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "Expected UCODEEXECUTETESTRESPONSE from APPLYUCODEEXCUTETEST")
        # Check that the first 8 bytes of the result buffer equal 0xdeadbeefc0febabe.
        expected_value = 0xdeadbeefc0febabe
        expected_bytes = struct.pack("<Q", expected_value)
        self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short")
        self.assertEqual(response.result_buffer[:8], expected_bytes,
                         f"Expected first 8 bytes of result buffer to be {expected_bytes.hex()}, got {response.result_buffer[:8].hex()}")

if __name__ == '__main__':
    unittest.main()

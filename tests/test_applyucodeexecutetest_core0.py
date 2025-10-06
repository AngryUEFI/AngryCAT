#!/usr/bin/env python3
import os
import socket
import unittest
import struct

# Add parent directory to sys.path so that protocol can be imported.
import os, sys
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from angrycat.protocol import (
    SendMachineCodePacket,
    ApplyUcodeExecuteTestPacket,
    UcodeExecuteTestResponsePacket,
    StatusPacket,
    Packet,
    PacketType
)

HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

# Test machine code buffer and expected result prefix.
MACHINE_CODE = bytes([
    0x48, 0xBA, 0xBE, 0xBA, 0xFE, 0xC0, 0xEF, 0xBE,
    0xAD, 0xDE, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x10, 0xC3
])
EXPECTED_RESULT_PREFIX = struct.pack("<Q", 0xdeadbeefc0febabe)

def send_packet(packet_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet_bytes)
        return Packet.read_from_socket(sock)

def send_machine_code(target_slot, machine_code):
    pkt = SendMachineCodePacket(target_slot=target_slot, machine_code=machine_code)
    return send_packet(pkt.pack())

def send_apply_ucode_execute_test(target_ucode_slot, target_machine_code_slot, target_core, timeout, apply_known_good):
    pkt = ApplyUcodeExecuteTestPacket(
        target_ucode_slot=target_ucode_slot,
        target_machine_code_slot=target_machine_code_slot,
        target_core=target_core,
        timeout=timeout,
        apply_known_good=apply_known_good
    )
    return send_packet(pkt.pack())

class ApplyUcodeExecuteTestCore0TestCase(unittest.TestCase):
    def test_apply_ucode_execute_test_core0(self):
        """Test APPLYUCODEEXCUTETEST on core 0 without restoring known good update."""
        send_resp = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_resp, StatusPacket, "SENDMACHINECODE response is not a STATUS packet")
        self.assertEqual(send_resp.status_code, 0, "SENDMACHINECODE did not return success")
        response = send_apply_ucode_execute_test(0, 1, 0, 0, False)
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "APPLYUCODEEXCUTETEST did not return a UCODEEXECUTETESTRESPONSE")
        self.assertEqual(response.flags, 0, "Expected flags to be 0 when timeout is 0")
        self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short")
        self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                         f"Expected result buffer prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}")

    def test_apply_ucode_execute_test_core0_with_known_good(self):
        """Test APPLYUCODEEXCUTETEST on core 0 with restoring known good update."""
        send_resp = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_resp, StatusPacket, "SENDMACHINECODE response is not a STATUS packet")
        self.assertEqual(send_resp.status_code, 0, "SENDMACHINECODE did not return success")
        response = send_apply_ucode_execute_test(0, 1, 0, 0, True)
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "APPLYUCODEEXCUTETEST did not return a UCODEEXECUTETESTRESPONSE (known good)")
        self.assertEqual(response.flags, 0, "Expected flags to be 0 when timeout is 0")
        self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short")
        self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                         f"Expected result buffer prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}")

if __name__ == '__main__':
    unittest.main()

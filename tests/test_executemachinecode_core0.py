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
    ExecuteMachineCodePacket,
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

def send_execute_machine_code(target_machine_code_slot, target_core, timeout):
    pkt = ExecuteMachineCodePacket(
        target_machine_code_slot=target_machine_code_slot,
        target_core=target_core,
        timeout=timeout
    )
    return send_packet(pkt.pack())

class ExecuteMachineCodeCore0TestCase(unittest.TestCase):
    def test_execute_machine_code_core0(self):
        """Test EXECUTEMACHINECODE on core 0.
           It runs the machine code in a specified slot.
           Expect the UCODEEXECUTETESTRESPONSE with rdtsc_diff and RAX set to 0,
           flags equal to 0, and the result buffer starting with the expected prefix.
        """
        # First, send the machine code to slot 1.
        send_resp = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_resp, StatusPacket, "SENDMACHINECODE response is not a STATUS packet.")
        self.assertEqual(send_resp.status_code, 0, "SENDMACHINECODE did not return success.")

        # Now, issue the EXECUTEMACHINECODE command for machine code slot 1 on core 0 with timeout 0.
        response = send_execute_machine_code(1, 0, 0)
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "EXECUTEMACHINECODE did not return a UCODEEXECUTETESTRESPONSE.")
        # According to the new spec, rdtsc_diff and RAX should be 0.
        self.assertEqual(response.rdtsc_diff, 0, "Expected rdtsc_diff to be 0 in EXECUTEMACHINECODE response.")
        self.assertEqual(response.rax, 0, "Expected RAX to be 0 in EXECUTEMACHINECODE response.")
        # Also verify flags are 0.
        self.assertEqual(response.flags, 0, "Expected flags to be 0 when timeout is 0.")
        self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short.")
        self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                         f"Expected result buffer prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}")

if __name__ == '__main__':
    unittest.main()

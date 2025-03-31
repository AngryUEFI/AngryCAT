#!/usr/bin/env python3
import os
import socket
import unittest
import struct

# Add parent directory to sys.path so that protocol can be imported.
import os
import sys
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import (
    SendMachineCodePacket,
    ApplyUcodeExecuteTestPacket,
    UcodeExecuteTestResponsePacket,
    StatusPacket,
    GetCoreCountPacket,
    CoreCountResponsePacket,
    Packet,
    PacketType
)

# Use environment variables to allow overriding host/port.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

# Machine code test buffer.
MACHINE_CODE = bytes([
    0x48, 0xBA, 0xBE, 0xBA, 0xFE, 0xC0, 0xEF, 0xBE,
    0xAD, 0xDE, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x10, 0xC3
])

# Expected first 8 bytes in the result buffer (little-endian encoding of 0xdeadbeefc0febabe).
EXPECTED_RESULT_PREFIX = struct.pack("<Q", 0xdeadbeefc0febabe)

def send_packet(packet_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet_bytes)
        response = Packet.read_from_socket(sock)
    return response

def send_machine_code(target_slot, machine_code):
    pkt = SendMachineCodePacket(target_slot=target_slot, machine_code=machine_code)
    response = send_packet(pkt.pack())
    return response

def send_apply_ucode_execute_test(target_ucode_slot, target_machine_code_slot, target_core, timeout, apply_known_good):
    pkt = ApplyUcodeExecuteTestPacket(
        target_ucode_slot=target_ucode_slot,
        target_machine_code_slot=target_machine_code_slot,
        target_core=target_core,
        timeout=timeout,
        apply_known_good=apply_known_good
    )
    response = send_packet(pkt.pack())
    return response

class ApplyUcodeExecuteTestNetworkTestCase(unittest.TestCase):
    def test_apply_ucode_execute_test(self):
        """Test applying ucode (without restoring known good update) on core 0.
           Use ucode slot 0, machine code slot 1, core 0 and timeout 0.
           Verify that the UCODEEXECUTETESTRESPONSE flags equal 0 and that the result buffer
           starts with 0xdeadbeefc0febabe.
        """
        send_response = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_response, StatusPacket, "SENDMACHINECODE response is not a STATUS packet.")
        self.assertEqual(send_response.status_code, 0, "SENDMACHINECODE did not return success status.")
        response = send_apply_ucode_execute_test(
            target_ucode_slot=0,
            target_machine_code_slot=1,
            target_core=0,
            timeout=0,
            apply_known_good=False
        )
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "Expected UCODEEXECUTETESTRESPONSE from APPLYUCODEEXCUTETEST.")
        # Verify flags are 0 (no timeout) and result buffer is long enough.
        self.assertEqual(response.flags, 0, "Expected flags to be 0 when timeout is 0.")
        self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short.")
        self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                         f"Expected result buffer prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}.")

    def test_apply_ucode_execute_test_with_known_good(self):
        """Test applying ucode and then restoring the known good update on core 0.
           Use ucode slot 0, machine code slot 1, core 0 and timeout 0, with apply_known_good True.
           Verify that the UCODEEXECUTETESTRESPONSE flags equal 0 and that the result buffer
           starts with 0xdeadbeefc0febabe.
        """
        send_response = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_response, StatusPacket, "SENDMACHINECODE response is not a STATUS packet.")
        self.assertEqual(send_response.status_code, 0, "SENDMACHINECODE did not return success status.")
        response = send_apply_ucode_execute_test(
            target_ucode_slot=0,
            target_machine_code_slot=1,
            target_core=0,
            timeout=0,
            apply_known_good=True
        )
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "Expected UCODEEXECUTETESTRESPONSE from APPLYUCODEEXCUTETEST with known good update.")
        self.assertEqual(response.flags, 0, "Expected flags to be 0 when timeout is 0.")
        self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short.")
        self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                         f"Expected result buffer prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}.")

    # TODO: SMP is horribly broken, emulator works, real metal works once
    # def test_apply_ucode_execute_test_on_core1(self):
    #     """If target core count is at least 2, test applying ucode on core 1 with timeout 0.
    #        Use ucode slot 0, machine code slot 1, core 1 and timeout 0.
    #        Verify that the UCODEEXECUTETESTRESPONSE flags equal 0 and that the result buffer
    #        starts with 0xdeadbeefc0febabe.
    #     """
    #     from protocol import GetCoreCountPacket
    #     pkt = GetCoreCountPacket()
    #     core_resp = send_packet(pkt.pack())
    #     self.assertEqual(core_resp.message_type, PacketType.CORECOUNTRESPONSE,
    #                      "Expected CORECOUNTRESPONSE for GETCORECOUNT request.")
    #     if core_resp.core_count < 2:
    #         self.skipTest("Target does not have at least 2 cores; skipping test on core1.")
    #     send_response = send_machine_code(1, MACHINE_CODE)
    #     self.assertIsInstance(send_response, StatusPacket, "SENDMACHINECODE response is not a STATUS packet.")
    #     self.assertEqual(send_response.status_code, 0, "SENDMACHINECODE did not return success status.")
    #     response = send_apply_ucode_execute_test(
    #         target_ucode_slot=0,
    #         target_machine_code_slot=1,
    #         target_core=1,
    #         timeout=0,
    #         apply_known_good=False
    #     )
    #     self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
    #                           "Expected UCODEEXECUTETESTRESPONSE from APPLYUCODEEXCUTETEST on core1.")
    #     self.assertEqual(response.flags, 0, "Expected flags to be 0 when timeout is 0.")
    #     self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short.")
    #     self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
    #                      f"Expected result buffer prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}.")

    # def test_apply_ucode_execute_test_on_core1_with_known_good(self):
    #     """If target core count is at least 2, test applying ucode on core 1 with timeout 0
    #        and restoring the known good update.
    #        Use ucode slot 0, machine code slot 1, core 1 and timeout 0, with apply_known_good True.
    #        Verify that the UCODEEXECUTETESTRESPONSE flags equal 0 and that the result buffer
    #        starts with 0xdeadbeefc0febabe.
    #     """
    #     from protocol import GetCoreCountPacket
    #     pkt = GetCoreCountPacket()
    #     core_resp = send_packet(pkt.pack())
    #     self.assertEqual(core_resp.message_type, PacketType.CORECOUNTRESPONSE,
    #                      "Expected CORECOUNTRESPONSE for GETCORECOUNT request.")
    #     if core_resp.core_count < 2:
    #         self.skipTest("Target does not have at least 2 cores; skipping test on core1 with known good update.")
    #     send_response = send_machine_code(1, MACHINE_CODE)
    #     self.assertIsInstance(send_response, StatusPacket, "SENDMACHINECODE response is not a STATUS packet.")
    #     self.assertEqual(send_response.status_code, 0, "SENDMACHINECODE did not return success status.")
    #     response = send_apply_ucode_execute_test(
    #         target_ucode_slot=0,
    #         target_machine_code_slot=1,
    #         target_core=1,
    #         timeout=0,
    #         apply_known_good=True
    #     )
    #     self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
    #                           "Expected UCODEEXECUTETESTRESPONSE from APPLYUCODEEXCUTETEST on core1 with known good update.")
    #     self.assertEqual(response.flags, 0, "Expected flags to be 0 when timeout is 0.")
    #     self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short.")
    #     self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
    #                      f"Expected result buffer prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}.")

if __name__ == '__main__':
    unittest.main()

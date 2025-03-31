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
    GetLastTestResultPacket,
    StatusPacket,
    CoreStatusResponsePacket,
    Packet,
    PacketType
)

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
        return Packet.read_from_socket(sock)

def send_packet_multi(packet_bytes, count):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet_bytes)
        responses = []
        for _ in range(count):
            responses.append(Packet.read_from_socket(sock))
        return responses

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

def send_get_last_test_result(core):
    pkt = GetLastTestResultPacket(core=core)
    # Expect 2 responses: first CORESTATUSRESPONSE, then UCODEEXECUTETESTRESPONSE.
    responses = send_packet_multi(pkt.pack(), 2)
    return responses

class GetLastTestResultNetworkTestCase(unittest.TestCase):
    def test_get_last_test_result_without_known_good(self):
        """Perform an APPLYUCODEEXCUTETEST on core 0 without restoring known good update,
           then request GETLASTTESTRESULT for core 0.
           Verify that the first returned message is a CORESTATUSRESPONSE with flags indicating
           present, started, ready, and not queued; and the second is a UCODEEXECUTETESTRESPONSE
           with flags 0 and a result buffer starting with 0xdeadbeefc0febabe.
        """
        # Load machine code to slot 1.
        send_resp = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_resp, StatusPacket, "SENDMACHINECODE did not return a STATUS packet")
        self.assertEqual(send_resp.status_code, 0, "SENDMACHINECODE did not succeed")
        # Execute the test.
        apply_resp = send_apply_ucode_execute_test(0, 1, 0, 0, False)
        self.assertIsInstance(apply_resp, UcodeExecuteTestResponsePacket,
                              "APPLYUCODEEXCUTETEST did not return a UCODEEXECUTETESTRESPONSE")
        # Request the last test result.
        responses = send_get_last_test_result(0)
        self.assertEqual(len(responses), 2, "Expected 2 responses from GETLASTTESTRESULT")
        status_resp, ucode_resp = responses
        # Verify the first response is CORESTATUSRESPONSE.
        self.assertEqual(status_resp.message_type, PacketType.CORESTATUSRESPONSE,
                         "First message is not a CORESTATUSRESPONSE")
        # Verify its flags indicate: present, started, ready, and not queued.
        # (Assuming the CoreStatusResponsePacket has properties: present, started, ready, job_queued)
        self.assertTrue(status_resp.present, "CoreStatus: present flag not set")
        self.assertTrue(status_resp.started, "CoreStatus: started flag not set")
        self.assertTrue(status_resp.ready, "CoreStatus: ready flag not set")
        self.assertFalse(status_resp.job_queued, "CoreStatus: job_queued flag should not be set")
        # Verify the second response is UCODEEXECUTETESTRESPONSE.
        self.assertEqual(ucode_resp.message_type, PacketType.UCODEEXECUTETESTRESPONSE,
                         "Second message is not a UCODEEXECUTETESTRESPONSE")
        self.assertEqual(ucode_resp.flags, 0, "Expected UCODEEXECUTETESTRESPONSE flags to be 0")
        self.assertGreaterEqual(len(ucode_resp.result_buffer), 8, "Result buffer is too short")
        self.assertEqual(ucode_resp.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                         "Result buffer prefix does not match expected")

    def test_get_last_test_result_with_known_good(self):
        """Perform an APPLYUCODEEXCUTETEST on core 0 with restoring the known good update,
           then request GETLASTTESTRESULT for core 0.
           Verify that the two returned messages match the expectations as above.
        """
        send_resp = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_resp, StatusPacket, "SENDMACHINECODE did not return a STATUS packet")
        self.assertEqual(send_resp.status_code, 0, "SENDMACHINECODE did not succeed")
        apply_resp = send_apply_ucode_execute_test(0, 1, 0, 0, True)
        self.assertIsInstance(apply_resp, UcodeExecuteTestResponsePacket,
                              "APPLYUCODEEXCUTETEST did not return a UCODEEXECUTETESTRESPONSE with known good update")
        responses = send_get_last_test_result(0)
        self.assertEqual(len(responses), 2, "Expected 2 responses from GETLASTTESTRESULT")
        status_resp, ucode_resp = responses
        self.assertEqual(status_resp.message_type, PacketType.CORESTATUSRESPONSE,
                         "First message is not a CORESTATUSRESPONSE")
        self.assertTrue(status_resp.present, "CoreStatus: present flag not set")
        self.assertTrue(status_resp.started, "CoreStatus: started flag not set")
        self.assertTrue(status_resp.ready, "CoreStatus: ready flag not set")
        self.assertFalse(status_resp.job_queued, "CoreStatus: job_queued flag should not be set")
        self.assertEqual(ucode_resp.message_type, PacketType.UCODEEXECUTETESTRESPONSE,
                         "Second message is not a UCODEEXECUTETESTRESPONSE")
        self.assertEqual(ucode_resp.flags, 0, "Expected UCODEEXECUTETESTRESPONSE flags to be 0")
        self.assertGreaterEqual(len(ucode_resp.result_buffer), 8, "Result buffer is too short")
        self.assertEqual(ucode_resp.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                         "Result buffer prefix does not match expected")

if __name__ == '__main__':
    unittest.main()

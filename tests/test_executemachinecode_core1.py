#!/usr/bin/env python3
import os
import socket
import unittest
import struct
import time

# Add parent directory to sys.path so that protocol can be imported.
import os, sys
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import (
    SendMachineCodePacket,
    ExecuteMachineCodePacket,
    UcodeExecuteTestResponsePacket,
    StatusPacket,
    GetCoreCountPacket,
    GetCoreStatusPacket,
    StartCorePacket,
    Packet,
    PacketType,
    RebootPacket,
)

HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))
ALLOW_REBOOT = os.getenv("ALLOW_REBOOT", "0") == "1"

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

def send_reboot():
    pkt = RebootPacket(warm=False)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt.pack())
    # Wait up to 60 seconds for target to reboot.
    for wait in range(30, 61, 5):
        try:
            # Try sending a ping to see if target is up.
            from protocol import PingPacket
            ping = PingPacket(message=b"test")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((HOST, PORT))
                sock.sendall(ping.pack())
                Packet.read_from_socket(sock)
            return
        except Exception:
            time.sleep(5)
    raise RuntimeError("Target did not reboot in time")

def send_get_core_count():
    pkt = GetCoreCountPacket()
    resp = send_packet(pkt.pack())
    if resp.message_type != PacketType.CORECOUNTRESPONSE:
        raise RuntimeError("Did not receive CORECOUNTRESPONSE")
    return resp

def send_get_core_status(core):
    from protocol import GetCoreStatusPacket
    pkt = GetCoreStatusPacket(core=core)
    return send_packet(pkt.pack())

def send_start_core(core):
    from protocol import StartCorePacket
    pkt = StartCorePacket(core=core)
    return send_packet(pkt.pack())

def ensure_core1_running():
    status = send_get_core_status(1)
    # If core 1 is not started, try to start it.
    if not status.started:
        start_resp = send_start_core(1)
        if not (isinstance(start_resp, StatusPacket) and start_resp.status_code == 0):
            raise RuntimeError("Failed to start core 1")
        time.sleep(0.1)  # Allow a short time for core 1 to come online.
        status = send_get_core_status(1)
    return status

class ExecuteMachineCodeCore1TestCase(unittest.TestCase):
    def setUp(self):
        # Step 1: Check at least 2 cores present.
        core_count_resp = send_get_core_count()
        if core_count_resp.core_count < 2:
            self.skipTest("Target does not have at least 2 cores.")
        # Step 2: Check if core 1 is ready. If not, try starting it.
        status = send_get_core_status(1)
        if not status.ready:
            start_resp = send_start_core(1)
            if not (isinstance(start_resp, StatusPacket) and start_resp.status_code == 0):
                if ALLOW_REBOOT:
                    send_reboot()
                    send_start_core(1)
                    status = send_get_core_status(1)
                    if not status.ready:
                        self.skipTest("Core 1 not ready even after reboot.")
                else:
                    self.skipTest("Core 1 not ready and reboot not allowed.")

    def test_execute_machine_code_core1(self):
        """Test EXECUTEMACHINECODE on core 1.
           - Send machine code to slot 1.
           - Issue EXECUTEMACHINECODE for machine code slot 1 on core 1 with timeout 0.
           - Verify that the UCODEEXECUTETESTRESPONSE has rdtsc_diff and RAX equal to 0,
             flags equal to 0, and that the result buffer starts with the expected prefix.
        """
        send_resp = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_resp, StatusPacket, "SENDMACHINECODE response is not a STATUS packet")
        self.assertEqual(send_resp.status_code, 0, "SENDMACHINECODE did not succeed")
        
        response = send_execute_machine_code(1, 1, 0)
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "EXECUTEMACHINECODE did not return a UCODEEXECUTETESTRESPONSE on core 1")
        # Per spec, rdtsc_diff and RAX should be 0.
        self.assertEqual(response.rdtsc_diff, 0, "Expected rdtsc_diff to be 0 in EXECUTEMACHINECODE response")
        self.assertEqual(response.rax, 0, "Expected RAX to be 0 in EXECUTEMACHINECODE response")
        # Flags should be 0.
        self.assertEqual(response.flags, 0, "Expected flags to be 0 when timeout is 0")
        self.assertGreaterEqual(len(response.result_buffer), 8, "Result buffer is too short")
        self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                         f"Expected result buffer prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}")

if __name__ == '__main__':
    unittest.main()

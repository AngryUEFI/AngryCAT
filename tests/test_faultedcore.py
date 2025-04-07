#!/usr/bin/env python3
import os
import socket
import unittest
import struct
import time

# Add parent directory to sys.path so that protocol can be imported.
import sys
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import (
    GetCoreCountPacket,
    GetCoreStatusPacket,
    StartCorePacket,
    RebootPacket,
    SendMachineCodePacket,
    ExecuteMachineCodePacket,
    UcodeExecuteTestResponsePacket,
    Packet,
    StatusPacket,
    PacketType,
)

HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))
ALLOW_REBOOT = os.getenv("ALLOW_REBOOT", "0") == "1"

# Machine code to test: two bytes [0xCC, 0xC3]
MACHINE_CODE = bytes([0xCC, 0xC3])
# (The expected fault is such that the fault_number should equal 3.)

def send_packet(packet_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet_bytes)
        return Packet.read_from_socket(sock)

def send_get_core_count():
    pkt = GetCoreCountPacket()
    resp = send_packet(pkt.pack())
    if resp.message_type != PacketType.CORECOUNTRESPONSE:
        raise RuntimeError("Did not receive CORECOUNTRESPONSE")
    return resp

def send_get_core_status(core):
    pkt = GetCoreStatusPacket(core=core)
    return send_packet(pkt.pack())

def send_start_core(core):
    pkt = StartCorePacket(core=core)
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

class ExecuteMachineCodeFaultTestCase(unittest.TestCase):
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
        self.core = 1  # We'll use core 1 for this test.

    def tearDown(self):
        # we left cores in a locked state, better clean up
        if ALLOW_REBOOT:
            send_reboot()

    def test_execute_machine_code_fault(self):
        # Step 3: Send machine code to slot 1 with byte string [0xCC, 0xC3].
        send_resp = send_machine_code(1, MACHINE_CODE)
        self.assertIsInstance(send_resp, StatusPacket, "SENDMACHINECODE response is not a STATUS packet")
        self.assertEqual(send_resp.status_code, 0, "SENDMACHINECODE did not succeed")
        # Step 4: Send an EXECUTEMACHINECODE packet for machine code slot 1, on core 1, timeout 100.
        response = send_execute_machine_code(1, self.core, 100)
        self.assertIsInstance(response, UcodeExecuteTestResponsePacket,
                              "EXECUTEMACHINECODE did not return a UCODEEXECUTETESTRESPONSE")
        # Step 5: Check that the UCODEEXECUTETESTRESPONSE has the core faulted flag set.
        self.assertTrue(response.core_faulted, "Core faulted flag not set in EXECUTEMACHINECODE response")
        # Step 6: Send a GETCORESTATUS for the same core.
        status_resp = send_get_core_status(self.core)
        # Step 7: Verify that CORESTATUSRESPONSE signals a faulted core.
        self.assertTrue(status_resp.faulted, "CORESTATUSRESPONSE does not signal a faulted core")
        # Step 8: Verify that the fault info is present and that fault_number equals 3.
        self.assertIsNotNone(status_resp.fault_info, "No fault info available in CORESTATUSRESPONSE")
        self.assertEqual(status_resp.fault_info.fault_number, 3,
                         f"Expected fault_number 3, got {status_resp.fault_info.fault_number}")

if __name__ == '__main__':
    unittest.main()

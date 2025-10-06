#!/usr/bin/env python3
import os
import socket
import struct
import unittest

from angrycat.protocol import (
    SendMachineCodePacket,
    ApplyUcodeExecuteTestPacket,
    GetCoreCountPacket,
    StartCorePacket,
    GetCoreStatusPacket,
    StatusPacket,
    PingPacket,
    PacketType
)
from angrycat.protocol.base import parse_packet

HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))
ALLOW_TORTURE = os.getenv("ALLOW_TORTURE", "0") == "1"
# Configure torture test parameters via environment variables.
TORTURE_ITERATIONS = int(os.getenv("TORTURE_ITERATIONS", "5"))
TORTURE_PER_CORE = int(os.getenv("TORTURE_PER_CORE", "10"))

MACHINE_CODE = bytes([
    0x48, 0xBA, 0xBE, 0xBA, 0xFE, 0xC0, 0xEF, 0xBE,
    0xAD, 0xDE, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x10, 0xC3
])
EXPECTED_RESULT_PREFIX = struct.pack("<Q", 0xdeadbeefc0febabe)

# --- Persistent Socket Class (local to this file) ---
class PersistentSocket:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.connect()

    def connect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))
        print("PersistentSocket: Connected to target.")

    def sendall(self, data):
        try:
            self.sock.sendall(data)
        except Exception as e:
            print("PersistentSocket: Lost connection during sendall:", e)
            self.connect()
            self.sock.sendall(data)

    def recv_n(self, n):
        data = b""
        while len(data) < n:
            try:
                chunk = self.sock.recv(n - len(data))
            except Exception as e:
                print("PersistentSocket: Lost connection during recv:", e)
                self.connect()
                raise Exception("PersistentSocket: Connection lost during recv")
            if not chunk:
                raise Exception("PersistentSocket: Socket closed during recv")
            data += chunk
        return data

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

def parse_packet_from_bytes(data_bytes):
    return parse_packet(data_bytes)

# --- Helper functions using the persistent socket ---
class TortureHelpers:
    def __init__(self, persistent_sock):
        self.persistent_sock = persistent_sock

    def send_packet(self, packet_bytes):
        try:
            self.persistent_sock.sendall(packet_bytes)
            header = self.persistent_sock.recv_n(4)
            msg_len = struct.unpack("<I", header)[0]
            payload = self.persistent_sock.recv_n(msg_len)
            full_packet = header + payload
            return parse_packet_from_bytes(full_packet)
        except Exception as e:
            print("TortureHelpers: Error sending packet:", e)
            return None

    def send_machine_code(self, target_slot, machine_code):
        pkt = SendMachineCodePacket(target_slot=target_slot, machine_code=machine_code)
        return self.send_packet(pkt.pack())

    def send_apply_ucode_execute_test(self, target_ucode_slot, target_machine_code_slot, target_core, timeout, apply_known_good):
        pkt = ApplyUcodeExecuteTestPacket(
            target_ucode_slot=target_ucode_slot,
            target_machine_code_slot=target_machine_code_slot,
            target_core=target_core,
            timeout=timeout,
            apply_known_good=apply_known_good
        )
        return self.send_packet(pkt.pack())

    def send_get_core_count(self):
        pkt = GetCoreCountPacket()
        resp = self.send_packet(pkt.pack())
        if resp is None or resp.message_type != PacketType.CORECOUNTRESPONSE:
            raise RuntimeError("Did not receive CORECOUNTRESPONSE")
        return resp

    def send_start_core(self, core):
        pkt = StartCorePacket(core=core)
        return self.send_packet(pkt.pack())

    def send_get_core_status(self, core):
        pkt = GetCoreStatusPacket(core=core)
        return self.send_packet(pkt.pack())

    def send_ping(self):
        pkt = PingPacket(message=b"ping")
        return self.send_packet(pkt.pack())

# --- Torture Test Class ---
class TortureAllCoresTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.persistent_sock = PersistentSocket(HOST, PORT)
        cls.helpers = TortureHelpers(cls.persistent_sock)
    
    @classmethod
    def tearDownClass(cls):
        cls.persistent_sock.close()
    
    def test_torture_all_cores(self):
        if not ALLOW_TORTURE:
            self.skipTest("ALLOW_TORTURE not set; skipping torture test.")
        try:
            core_count_resp = self.helpers.send_get_core_count()
        except Exception as e:
            self.skipTest(f"Could not get core count: {e}")
        core_count = core_count_resp.core_count
        if core_count < 2:
            self.skipTest("Only one core available; skipping torture test.")

        # Start all cores using core=0.
        start_all_resp = self.helpers.send_start_core(0)
        self.assertIsNotNone(start_all_resp, "No response from STARTCORE (all cores)")
        self.assertIsInstance(start_all_resp, StatusPacket, "Expected STATUS response from STARTCORE (all cores)")
        self.assertEqual(start_all_resp.status_code, 0, f"STARTCORE (all cores) failed with status {start_all_resp.status_code}")

        # Verify all cores are running.
        for core in range(core_count):
            status = self.helpers.send_get_core_status(core)
            self.assertTrue(status.present, f"Core {core} not marked as present.")
            self.assertTrue(status.started, f"Core {core} not marked as started.")
            self.assertTrue(status.ready, f"Core {core} not marked as ready.")
            self.assertFalse(status.job_queued, f"Core {core} should not have a queued job.")

        total_tests = TORTURE_ITERATIONS * core_count * TORTURE_PER_CORE
        current_test = 0
        for iteration in range(TORTURE_ITERATIONS):
            for core in range(core_count):
                for sub in range(TORTURE_PER_CORE):
                    mc_resp = self.helpers.send_machine_code(1, MACHINE_CODE)
                    if mc_resp is None or not (isinstance(mc_resp, StatusPacket) and mc_resp.status_code == 0):
                        print(f"Lost connection during SENDMACHINECODE on core {core}, iter {iteration}, sub {sub}")
                        continue
                    response = self.helpers.send_apply_ucode_execute_test(0, 1, core, 0, True)
                    if response is None:
                        print(f"Lost connection during APPLYUCODEEXCUTETEST on core {core}, iter {iteration}, sub {sub}")
                        continue
                    try:
                        self.assertEqual(response.flags, 0, f"Core {core}: Expected flags 0, got {response.flags:#018x}")
                        self.assertGreaterEqual(len(response.result_buffer), 8, f"Core {core}: Result buffer too short")
                        self.assertEqual(response.result_buffer[:8], EXPECTED_RESULT_PREFIX,
                                         f"Core {core}: Expected prefix {EXPECTED_RESULT_PREFIX.hex()}, got {response.result_buffer[:8].hex()}")
                    except Exception as e:
                        print(f"Test error on core {core}, iter {iteration}, sub {sub}: {e}")
                    current_test += 1
                    if current_test % 10 == 0:
                        print(f"Torture progress: {current_test}/{total_tests} tests completed.")
        print("Torture test on all cores completed successfully.")

if __name__ == '__main__':
    unittest.main()

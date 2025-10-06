#!/usr/bin/env python3
import os
import socket
import struct
import unittest
import time

from angrycat.protocol import (
    GetCoreCountPacket,
    CoreCountResponsePacket,
    GetCoreStatusPacket,
    CoreStatusResponsePacket,
    StartCorePacket,
    RebootPacket,
    StatusPacket,
    PingPacket,
    Packet,
    PacketType,
)

HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))
ALLOW_REBOOT = os.getenv("ALLOW_REBOOT", "0") == "1"

def send_packet(packet_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet_bytes)
        return Packet.read_from_socket(sock)

def send_reboot():
    pkt = RebootPacket(warm=False)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(pkt.pack())
    # Wait up to 60 seconds for target to reboot.
    for wait in range(30, 61, 5):
        try:
            # Try sending a ping to see if target is up.
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
    pkt = GetCoreStatusPacket(core=core)
    return send_packet(pkt.pack())

def send_start_core(core):
    pkt = StartCorePacket(core=core)
    return send_packet(pkt.pack())

def send_reboot():
    pkt = RebootPacket(warm=False)
    return send_packet(pkt.pack())

def wait_for_target(timeout=60, interval=5):
    """Wait until a PingPacket elicits a PONG response or until timeout is reached."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((HOST, PORT))
                ping_pkt = PingPacket(message=b"ping")
                sock.sendall(ping_pkt.pack())
                resp = Packet.read_from_socket(sock)
                if resp.message_type == PacketType.PONG:
                    return True
        except Exception:
            pass
        time.sleep(interval)
    return False

class StartCoreNetworkTestCase(unittest.TestCase):
    def setUp(self):
        # Step 1: Check at least 2 cores present.
        core_count_resp = send_get_core_count()
        if core_count_resp.core_count < 2:
            self.skipTest("Target does not have at least 2 cores.")
        # Step 2: Check if core 1 is ready. If not, try starting it.
        status = send_get_core_status(1)
        if not status.ready:
            if ALLOW_REBOOT:
                send_reboot()
            else:
                self.skipTest("Core 1 not ready and reboot not allowed.")

    def test_1_start_core(self):
        """
        Query available cores.
        Check non-boot cores (cores 1..) until a core that is not started is found.
        If all non-boot cores are running:
          - If ALLOW_REBOOT is not "1", skip the test.
          - Otherwise, issue a hard REBOOT, wait for the target to respond, and re-check.
        Then, send a STARTCORE command for the candidate core and verify its status.
        """
        core_count_resp = send_get_core_count()
        core_count = core_count_resp.core_count
        self.assertGreaterEqual(core_count, 1, "At least one core (core 0) must be available.")
        if core_count == 1:
            self.skipTest("Only one core available; skipping STARTCORE test.")

        candidate = None
        for core in range(1, core_count):
            status = send_get_core_status(core)
            if not status.started:
                candidate = core
                break

        if candidate is None:
            if os.getenv("ALLOW_REBOOT", "0") != "1":
                self.skipTest("All non-boot cores are running and reboot not allowed (set ALLOW_REBOOT=1).")
            send_reboot()
            self.assertTrue(wait_for_target(timeout=60, interval=5), "Target did not respond after reboot within timeout.")
            for core in range(1, core_count):
                status = send_get_core_status(core)
                if not status.started:
                    candidate = core
                    break
            if candidate is None:
                self.skipTest("After reboot, all non-boot cores appear to be running; cannot test STARTCORE.")

        start_resp = send_start_core(candidate)
        self.assertIsInstance(start_resp, StatusPacket, f"Expected STATUS response for STARTCORE on core {candidate}")
        self.assertEqual(start_resp.status_code, 0, f"STARTCORE for core {candidate} failed with status {start_resp.status_code}")
        status_after = send_get_core_status(candidate)
        self.assertEqual(status_after.message_type, PacketType.CORESTATUSRESPONSE, "Did not receive CORESTATUSRESPONSE")
        self.assertTrue(status_after.present, f"Core {candidate} not marked as present.")
        self.assertTrue(status_after.started, f"Core {candidate} not marked as started.")
        self.assertTrue(status_after.ready, f"Core {candidate} not marked as ready.")
        self.assertFalse(status_after.job_queued, f"Core {candidate} should not have a queued job.")

    def test_2_start_all_cores(self):
        """
        If at least one core is not running, then send a STARTCORE command with core=0 (to start all cores).
        If all non-boot cores are already running:
          - If ALLOW_REBOOT is not set, skip the test.
          - Otherwise, issue a reboot and wait until the target is online.
        Then send a STARTCORE command with core=0 and verify that all cores (including core 0) are present, started, ready, and not queued.
        """
        core_count_resp = send_get_core_count()
        core_count = core_count_resp.core_count
        self.assertGreaterEqual(core_count, 1, "At least one core must be available.")

        any_not_started = any(not send_get_core_status(core).started for core in range(1, core_count))
        if not any_not_started:
            if os.getenv("ALLOW_REBOOT", "0") != "1":
                self.skipTest("All non-boot cores are running and reboot not allowed (set ALLOW_REBOOT=1).")
            send_reboot()
            self.assertTrue(wait_for_target(timeout=60, interval=5), "Target did not respond after reboot within timeout.")

        start_all_resp = send_start_core(0)
        self.assertIsInstance(start_all_resp, StatusPacket, "Expected STATUS response from STARTCORE with core 0")
        self.assertEqual(start_all_resp.status_code, 0, f"STARTCORE (all cores) failed with status {start_all_resp.status_code}")

        for core in range(core_count):
            status = send_get_core_status(core)
            self.assertTrue(status.present, f"Core {core} not marked as present.")
            self.assertTrue(status.started, f"Core {core} not marked as started.")
            self.assertTrue(status.ready, f"Core {core} not marked as ready.")
            self.assertFalse(status.job_queued, f"Core {core} should not have a queued job.")

if __name__ == '__main__':
    unittest.main()

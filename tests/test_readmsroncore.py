#!/usr/bin/env python3
import os
import socket
import struct
import unittest
import time

from angrycat.protocol import (
    ReadMsrPacket,
    ReadMsrOnCorePacket,
    GetCoreCountPacket,
    CoreCountResponsePacket,
    GetCoreStatusPacket,
    StartCorePacket,
    Packet,
    PacketType,
    StatusPacket,
)

HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

TARGET_MSR = 0xc0000080 # extended feature register

def send_packet(packet):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet.pack())
        response = Packet.read_from_socket(sock)
    return response

def send_read_msr(target_msr):
    pkt = ReadMsrPacket(target_msr=target_msr)
    return send_packet(pkt)

def send_read_msr_on_core(target_msr, target_core):
    pkt = ReadMsrOnCorePacket(target_msr=target_msr, target_core=target_core)
    return send_packet(pkt)

def send_get_core_count():
    pkt = GetCoreCountPacket()
    resp = send_packet(pkt)
    if resp.message_type != PacketType.CORECOUNTRESPONSE:
        raise RuntimeError("Did not receive CORECOUNTRESPONSE")
    return resp

def send_get_core_status(core):
    pkt = GetCoreStatusPacket(core=core)
    return send_packet(pkt)

def send_start_core(core):
    pkt = StartCorePacket(core=core)
    return send_packet(pkt)

class ReadMsrOnCoreTestCase(unittest.TestCase):
    def test_read_msr_on_core0(self):
        """Step 1-3: Issue READMSR and READMSRONCORE for MSR 0xC0000103 on core 0 and verify results match."""
        resp1 = send_read_msr(TARGET_MSR)
        self.assertEqual(resp1.message_type, PacketType.MSRRESPONSE, "Expected MSRRESPONSE for READMSR")
        resp2 = send_read_msr_on_core(TARGET_MSR, 0)
        self.assertEqual(resp2.message_type, PacketType.MSRRESPONSE, "Expected MSRRESPONSE for READMSRONCORE on core 0")
        self.assertEqual(resp1.eax, resp2.eax, "EAX values do not match for core 0")
        self.assertEqual(resp1.edx, resp2.edx, "EDX values do not match for core 0")

    def test_read_msr_on_core1(self):
        """Steps 4-8: If at least 2 cores are present, ensure core 1 is running, then verify that READMSRONCORE on core 1 matches a subsequent READMSR."""
        core_count_resp = send_get_core_count()
        if core_count_resp.core_count < 2:
            self.skipTest("Target does not have at least 2 cores; skipping core 1 test.")
        # Check if core 1 is running; if not, start it.
        status1 = send_get_core_status(1)
        if not status1.started:
            start_resp = send_start_core(1)
            self.assertIsInstance(start_resp, StatusPacket, "Expected STATUS from STARTCORE")
            self.assertEqual(start_resp.status_code, 0, "STARTCORE for core 1 failed")
            time.sleep(2)  # Wait a moment for core 1 to come online.
            status1 = send_get_core_status(1)
            self.assertTrue(status1.started, "Core 1 is still not started after issuing STARTCORE")
        # Issue READMSRONCORE on core 1.
        resp_core1 = send_read_msr_on_core(TARGET_MSR, 1)
        self.assertEqual(resp_core1.message_type, PacketType.MSRRESPONSE, "Expected MSRRESPONSE for READMSRONCORE on core 1")
        # Issue another READMSR.
        resp_read = send_read_msr(TARGET_MSR)
        self.assertEqual(resp_read.message_type, PacketType.MSRRESPONSE, "Expected MSRRESPONSE for READMSR")
        # Verify that results match.
        self.assertEqual(resp_core1.eax, resp_read.eax, "EAX values do not match for core 1")
        self.assertEqual(resp_core1.edx, resp_read.edx, "EDX values do not match for core 1")

if __name__ == '__main__':
    unittest.main()

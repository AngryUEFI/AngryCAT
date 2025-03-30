#!/usr/bin/env python3
import unittest
import os
import sys

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
from protocol import SendMachineCodePacket, PacketType, parse_packet

class TestSendMachineCodePacket(unittest.TestCase):
    def test_pack_parse(self):
        # Machine code test buffer:
        machine_code = bytes([
            0x48, 0xBA, 0xBE, 0xBA, 0xFE, 0xC0, 0xEF, 0xBE,
            0xAD, 0xDE, 0x48, 0x89, 0x10, 0xC3
        ])
        target_slot = 1
        pkt = SendMachineCodePacket(target_slot=target_slot, machine_code=machine_code)
        packed = pkt.pack()
        parsed_pkt = parse_packet(packed)
        self.assertEqual(parsed_pkt.target_slot, target_slot)
        self.assertEqual(parsed_pkt.machine_code, machine_code)
        self.assertEqual(parsed_pkt.message_type, PacketType.SENDMACHINECODE)

if __name__ == '__main__':
    unittest.main()

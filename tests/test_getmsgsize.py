#!/usr/bin/env python3
import os
import sys
import socket
import unittest

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import GetMsgSizePacket, MsgSizePacket, Packet

# Use environment variables to allow overriding host/port, with defaults.
HOST = os.getenv("ANGRYUEFI_HOST", "127.0.0.1")
PORT = int(os.getenv("ANGRYUEFI_PORT", "3239"))

def send_get_msg_size(message: bytes, host=HOST, port=PORT):
    """
    Connects to AngryUEFI, sends a GETMSGSIZE packet with the provided message (as bytes),
    and returns the parsed MSGSIZE response packet using Packet.read_from_socket().
    """
    get_msg_size_pkt = GetMsgSizePacket(message=message)
    pkt_bytes = get_msg_size_pkt.pack()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(pkt_bytes)
        response = Packet.read_from_socket(sock)
    return response

class GetMsgSizeTestCase(unittest.TestCase):
    def test_get_msg_size_various_payloads(self):
        """
        For each test payload size in bytes, construct a GETMSGSIZE packet and
        verify that the MSGSIZE response returns the correct received length.
        The tested payload sizes are: 0, 4, 1024, 1400, 1600, 2048, 4096, 8192 and 1*1024*1024 bytes.
        Since we operate on byte strings directly, the message is built to have exactly the desired length.
        """
        payload_sizes = [0, 4, 1024, 1400, 1600, 2048, 4096, 8192, 1*1024*1024]
        for size in payload_sizes:
            with self.subTest(payload_size=size):
                message = b"A" * size
                response = send_get_msg_size(message)
                self.assertIsInstance(response, MsgSizePacket,
                                      f"Response for payload size {size} is not a MSGSIZE packet.")
                expected_length = len(message)
                self.assertEqual(response.received_length, expected_length,
                                 f"Expected received length {expected_length} for payload size {size}, "
                                 f"but got {response.received_length}.")

if __name__ == "__main__":
    unittest.main()

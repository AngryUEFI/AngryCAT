#!/usr/bin/env python3
import socket
import struct
import time

def tcp_client(host, port, message):
    # Create a TCP/IP socket.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to the server.
        sock.connect((host, port))
        print(f"Connected to {host}:{port}")

        for i in range(10):
            # Send the byte string message.
            sock.sendall(message)
            print(f"Sent: {message}")

            # Receive the response (up to 1024 bytes).
            response = sock.recv(1024)
            print(f"Received: {response}")
            time.sleep(0.5)

if __name__ == '__main__':
    # Configure server address and port.
    HOST = '127.0.0.1'  # Change to the server's address if needed.
    PORT = 5554        # Change to the desired port number.
    
    message = b"Hello World!"
    length = len(message)

    packed_bytes = struct.pack('<I', length)
    message = packed_bytes + message

    tcp_client(HOST, PORT, message)

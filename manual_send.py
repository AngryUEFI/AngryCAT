#!/usr/bin/env python3
import argparse
import socket
import sys
import os
import struct

from protocol import (
    PingPacket,
    SendUcodePacket,
    FlipBitsPacket,
    ApplyUcodePacket,
    ReadMsrPacket,
    RebootPacket,
    GetLastTestResultPacket,
    StartCorePacket,
    GetCoreStatusPacket,
    Packet,
    StatusPacket,
    PongPacket,
    UcodeResponsePacket,
    MsrResponsePacket,
)

def send_packet(packet, host, port):
    responses = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(packet.pack())
        # Read responses until the control field indicates end-of-transmission.
        while True:
            response = Packet.read_from_socket(sock)
            responses.append(response)
            # Check the control field: bit0 = 0 means no more messages.
            if (response.control & 0x1) == 0:
                break
    return responses

def main():
    parser = argparse.ArgumentParser(
        description="Manually send packets to AngryUEFI and print the response(s)."
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="AngryUEFI host")
    parser.add_argument("--port", type=int, default=3239, help="AngryUEFI port")
    parser.add_argument("--type", type=str, required=True,
                        choices=["PING", "SENDUCODE", "FLIPBITS", "APPLYUCODE", "READMSR", "REBOOT",
                                 "GETLASTTESTRESULT", "STARTCORE", "GETCORESTATUS"],
                        help="Type of packet to send")
    # For PING:
    parser.add_argument("--message", type=str, help="Message to send for PING")
    # For SENDUCODE:
    parser.add_argument("--target-slot", type=int, help="Target slot for SENDUCODE (or APPLYUCODE) commands")
    parser.add_argument("--file", type=str, help="Path to the update file for SENDUCODE")
    # For FLIPBITS:
    parser.add_argument("--positions", type=str, help="Comma-separated bit positions for FLIPBITS")
    # For APPLYUCODE:
    parser.add_argument("--apply-known-good", action="store_true", help="Apply known good update after test update")
    # For READMSR:
    parser.add_argument("--msr", type=str, help="MSR in hex to read (e.g. 0x10)")
    # For GETLASTTESTRESULT, STARTCORE, GETCORESTATUS:
    parser.add_argument("--core", type=int, help="Core number for GETLASTTESTRESULT, STARTCORE, or GETCORESTATUS")
    # For REBOOT:
    parser.add_argument("--reboot-warm", action="store_true", help="Perform a warm reboot if set (default is cold)")
    
    args = parser.parse_args()
    
    host = args.host
    port = args.port
    cmd_type = args.type.upper()
    
    packet = None

    try:
        if cmd_type == "PING":
            if not args.message:
                print("For PING, --message is required.")
                sys.exit(1)
            # Using utf_16_le encoding for consistency.
            packet = PingPacket(message=args.message.encode("utf_16_le"))
        elif cmd_type == "SENDUCODE":
            if args.target_slot is None or not args.file:
                print("For SENDUCODE, --target-slot and --file are required.")
                sys.exit(1)
            if not os.path.exists(args.file):
                print(f"File {args.file} does not exist.")
                sys.exit(1)
            with open(args.file, "rb") as f:
                update_bytes = f.read()
            packet = SendUcodePacket(target_slot=args.target_slot, ucode=update_bytes)
        elif cmd_type == "FLIPBITS":
            if args.target_slot is None or not args.positions:
                print("For FLIPBITS, --target-slot and --positions are required.")
                sys.exit(1)
            try:
                positions = [int(x.strip()) for x in args.positions.split(",")]
            except Exception:
                print("Error parsing --positions. They must be comma-separated integers.")
                sys.exit(1)
            packet = FlipBitsPacket(source_slot=args.target_slot, flips=positions)
        elif cmd_type == "APPLYUCODE":
            if args.target_slot is None:
                print("For APPLYUCODE, --target-slot is required.")
                sys.exit(1)
            packet = ApplyUcodePacket(target_slot=args.target_slot, apply_known_good=args.apply_known_good)
        elif cmd_type == "READMSR":
            if not args.msr:
                print("For READMSR, --msr is required (in hex, e.g. 0x10).")
                sys.exit(1)
            try:
                msr_val = int(args.msr, 16)
            except Exception:
                print("Invalid MSR value. Use hex (e.g., 0x10).")
                sys.exit(1)
            packet = ReadMsrPacket(target_msr=msr_val)
        elif cmd_type == "REBOOT":
            packet = RebootPacket(warm=args.reboot_warm)
        elif cmd_type == "GETLASTTESTRESULT":
            if args.core is None:
                print("For GETLASTTESTRESULT, --core is required.")
                sys.exit(1)
            from protocol import GetLastTestResultPacket
            packet = GetLastTestResultPacket(core=args.core)
        elif cmd_type == "STARTCORE":
            if args.core is None:
                print("For STARTCORE, --core is required.")
                sys.exit(1)
            from protocol import StartCorePacket
            packet = StartCorePacket(core=args.core)
        elif cmd_type == "GETCORESTATUS":
            if args.core is None:
                print("For GETCORESTATUS, --core is required.")
                sys.exit(1)
            from protocol import GetCoreStatusPacket
            packet = GetCoreStatusPacket(core=args.core)
        else:
            print("Unsupported packet type.")
            sys.exit(1)
    except Exception as e:
        print("Error creating packet:", e)
        sys.exit(1)
    
    try:
        responses = send_packet(packet, host, port)
    except Exception as e:
        print("Error sending packet:", e)
        sys.exit(1)
    
    if not responses:
        print("No response received.")
    else:
        print("Response(s) received:")
        for idx, response in enumerate(responses):
            print(f"\nResponse {idx+1}:")
            if isinstance(response, StatusPacket):
                print("Type: STATUS")
                print("Status Code:", response.status_code)
                if response.text:
                    print("Text:", response.text)
            elif isinstance(response, PongPacket):
                print("Type: PONG")
                print("Message:", response.message)
            elif isinstance(response, UcodeResponsePacket):
                print("Type: UCODERESPONSE")
                print("rdtsc_diff:", response.rdtsc_diff)
                print("RAX:", response.rax)
            elif isinstance(response, MsrResponsePacket):
                print("Type: MSRRESPONSE")
                print("EAX:", response.eax)
                print("EDX:", response.edx)
            else:
                print("Received response of type:", response.message_type)
                print(response)

if __name__ == "__main__":
    main()

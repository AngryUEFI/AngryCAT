#!/usr/bin/env python3
import argparse
import socket
import sys
import os

from protocol import (
    PingPacket,
    SendUcodePacket,
    FlipBitsPacket,
    ApplyUcodePacket,
    ReadMsrPacket,
    RebootPacket,
    Packet,
    StatusPacket,
    PongPacket,
    UcodeResponsePacket,
    MsrResponsePacket,
)

def send_packet(packet, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(packet.pack())
        response = Packet.read_from_socket(sock)
    return response

def main():
    parser = argparse.ArgumentParser(
        description="Manually send packets to AngryUEFI and print the response."
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="AngryUEFI host")
    parser.add_argument("--port", type=int, default=3239, help="AngryUEFI port")
    parser.add_argument("--type", type=str, required=True,
                        choices=["PING", "SENDUCODE", "FLIPBITS", "APPLYUCODE", "READMSR", "REBOOT"],
                        help="Type of packet to send")
    # Arguments for PING
    parser.add_argument("--message", type=str, help="Message to send for PING")
    # Arguments for SENDUCODE
    parser.add_argument("--target-slot", type=int, help="Target slot for SENDUCODE (or APPLYUCODE) commands")
    parser.add_argument("--file", type=str, help="Path to the update file for SENDUCODE")
    # Arguments for FLIPBITS
    parser.add_argument("--positions", type=str, help="Comma-separated bit positions for FLIPBITS")
    # Arguments for APPLYUCODE
    parser.add_argument("--apply-known-good", action="store_true", help="If present, apply known good update after test update")
    # Arguments for READMSR
    parser.add_argument("--msr", type=str, help="MSR in hex to read for READMSR (e.g. 0x10)")
    # Arguments for REBOOT
    parser.add_argument("--reboot-warm", action="store_true", help="If present, perform a warm reboot (otherwise cold)")
    
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
            # Convert message to bytes using UTF-16 BE encoding.
            packet = PingPacket(message=args.message.encode("utf_16_be"))
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
            # For REBOOT, use the --reboot-warm flag (default is cold reboot).
            packet = RebootPacket(warm=args.reboot_warm)
        else:
            print("Unsupported packet type.")
            sys.exit(1)
    except Exception as e:
        print("Error creating packet:", e)
        sys.exit(1)
    
    try:
        response = send_packet(packet, host, port)
    except Exception as e:
        print("Error sending packet:", e)
        sys.exit(1)
    
    print("Response received:")
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
    elif isinstance(response, MsrResponsePacket):
        print("Type: MSRRESPONSE")
        print("EAX:", response.eax)
        print("EDX:", response.edx)
    else:
        print("Received unknown response type:")
        print(response)

if __name__ == "__main__":
    main()

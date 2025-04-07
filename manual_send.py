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
    SendMachineCodePacket,
    ExecuteMachineCodePacket,
    # Existing packets:
    Packet,
    StatusPacket,
    PongPacket,
    UcodeResponsePacket,
    MsrResponsePacket,
    UcodeExecuteTestResponsePacket,
    CoreStatusResponsePacket,
)

def send_packet(packet, host, port):
    responses = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(packet.pack())
        while True:
            response = Packet.read_from_socket(sock)
            responses.append(response)
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
                                 "GETLASTTESTRESULT", "STARTCORE", "GETCORESTATUS",
                                 "READMSRONCORE", "APPLYUCODEEXCUTETEST", "SENDMACHINECODE", "EXECUTEMACHINECODE"],
                        help="Type of packet to send")
    # For PING:
    parser.add_argument("--message", type=str, help="Message to send for PING")
    # For SENDUCODE and SENDMACHINECODE:
    parser.add_argument("--target-slot", type=int, help="Target slot for SENDUCODE/SENDMACHINECODE (or APPLYUCODE)")
    parser.add_argument("--file", type=str, help="Path to the update file (for SENDUCODE) or machine code file (for SENDMACHINECODE)")
    # For FLIPBITS:
    parser.add_argument("--positions", type=str, help="Comma-separated bit positions for FLIPBITS")
    # For APPLYUCODE and APPLYUCODEEXCUTETEST:
    parser.add_argument("--apply-known-good", action="store_true", help="Apply known good update after test update")
    # For READMSR and READMSRONCORE:
    parser.add_argument("--msr", type=str, help="MSR in hex to read (e.g. 0x10)")
    # For GETLASTTESTRESULT, STARTCORE, GETCORESTATUS, READMSRONCORE, APPLYUCODEEXCUTETEST, and EXECUTEMACHINECODE:
    parser.add_argument("--core", type=int, help="Core number for these commands")
    # For REBOOT:
    parser.add_argument("--reboot-warm", action="store_true", help="Perform a warm reboot if set (default is cold)")
    # For APPLYUCODEEXCUTETEST:
    parser.add_argument("--machine-slot", type=int, help="Target machine code slot for APPLYUCODEEXCUTETEST")
    parser.add_argument("--timeout", type=int, default=0, help="Timeout (in ms) for APPLYUCODEEXCUTETEST or EXECUTEMACHINECODE (0 means unlimited)")
    
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
        elif cmd_type == "READMSRONCORE":
            if not args.msr:
                print("For READMSRONCORE, --msr is required (in hex, e.g. 0x10).")
                sys.exit(1)
            if args.core is None:
                print("For READMSRONCORE, --core is required.")
                sys.exit(1)
            try:
                msr_val = int(args.msr, 16)
            except Exception:
                print("Invalid MSR value. Use hex (e.g., 0x10).")
                sys.exit(1)
            from protocol import ReadMsrOnCorePacket
            packet = ReadMsrOnCorePacket(target_msr=msr_val, target_core=args.core)
        elif cmd_type == "APPLYUCODEEXCUTETEST":
            if args.target_slot is None or args.machine_slot is None or args.core is None:
                print("For APPLYUCODEEXCUTETEST, --target-slot, --machine-slot and --core are required.")
                sys.exit(1)
            from protocol import ApplyUcodeExecuteTestPacket
            packet = ApplyUcodeExecuteTestPacket(
                target_ucode_slot=args.target_slot,
                target_machine_code_slot=args.machine_slot,
                target_core=args.core,
                timeout=args.timeout,
                apply_known_good=args.apply_known_good
            )
        elif cmd_type == "SENDMACHINECODE":
            if args.target_slot is None or not args.file:
                print("For SENDMACHINECODE, --target-slot and --file are required.")
                sys.exit(1)
            if not os.path.exists(args.file):
                print(f"File {args.file} does not exist.")
                sys.exit(1)
            with open(args.file, "rb") as f:
                machine_code = f.read()
            from protocol import SendMachineCodePacket
            packet = SendMachineCodePacket(target_slot=args.target_slot, machine_code=machine_code)
        elif cmd_type == "EXECUTEMACHINECODE":
            if args.machine_slot is None or args.core is None:
                print("For EXECUTEMACHINECODE, --machine-slot and --core are required.")
                sys.exit(1)
            from protocol import ExecuteMachineCodePacket
            packet = ExecuteMachineCodePacket(
                target_machine_code_slot=args.machine_slot,
                target_core=args.core,
                timeout=args.timeout
            )
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
    
    print("Response(s) received:")
    if not responses:
        print("No response received.")
    else:
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
            elif isinstance(response, UcodeExecuteTestResponsePacket):
                # For UCODEEXECUTETESTRESPONSE, print all fields.
                print("Type: UCODEEXECUTETESTRESPONSE")
                print("rdtsc_diff:", response.rdtsc_diff)
                print("RAX:", response.rax)
                print("Flags:", f"{response.flags:#018x}")
                print("Result Buffer Length:", len(response.result_buffer))
            elif isinstance(response, CoreStatusResponsePacket):
                print("Received response of type:", response.message_type)
                print(response)
                if response.fault_info is not None:
                    print(response.fault_info.long_description())
            else:
                print("Received response of type:", response.message_type)
                print(response)

if __name__ == "__main__":
    main()

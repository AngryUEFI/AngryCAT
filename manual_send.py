#!/usr/bin/env python3
import argparse
import socket
import sys
import os

from protocol import (
    Packet,
    PacketType,
    PingPacket,
    SendUcodePacket,
    FlipBitsPacket,
    ApplyUcodePacket,
    ReadMsrPacket,
    ReadMsrOnCorePacket,
    RebootPacket,
    GetLastTestResultPacket,
    StartCorePacket,
    GetCoreStatusPacket,
    ApplyUcodeExecuteTestPacket,
    SendMachineCodePacket,
    ExecuteMachineCodePacket,
)


def hexdump(data: bytes, start_address: int = 0) -> None:
    """
    Pretty-print a bytes object in hex-editor style, 32 bytes per line,
    with an extra separator every 8 bytes in the hex column.

    Parameters:
    -----------
    data : bytes
        The data to dump.
    start_address : int, optional
        The address to display at the beginning of the first line (default is 0).
    """
    width = 32
    group_size = 8
    # Calculate total hex-column width:
    #   each byte = 2 hex chars
    #   between bytes = 1 space  → (width - 1) spaces
    #   plus (width//group_size - 1) extra spaces to separate groups
    hex_col_width = width * 2 + (width - 1) + (width // group_size - 1)

    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]

        # build a list of two-char hex strings
        hex_bytes = [f"{b:02X}" for b in chunk]
        # group into sublists of length `group_size`
        groups = [
            hex_bytes[i : i + group_size]
            for i in range(0, len(hex_bytes), group_size)
        ]
        # join bytes in each group with single spaces, then join groups with double spaces
        hex_col = "  ".join(" ".join(g) for g in groups)
        hex_col = hex_col.ljust(hex_col_width)

        # ASCII representation: printable 32–126, else dot
        ascii_col = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)

        print(f"{start_address + offset:08X}  {hex_col}  {ascii_col}")


def send_packet(packet, host, port):
    """Send one request and return all response packets."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(packet.pack())
        return Packet.read_messages(sock)

def main():
    parser = argparse.ArgumentParser(
        description="Send packets to AngryUEFI and print the response(s)."
    )
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3239)
    parser.add_argument("--type", type=str, required=True,
                        help="Packet type")
    # Note: for brevity, re‑use PacketType enum in choices:
    parser.set_defaults(type=None)
    parser._option_string_actions["--type"].choices = [pt.name for pt in PacketType]
    # Common args:
    parser.add_argument("--message", type=str)
    parser.add_argument("--target-slot", type=int)
    parser.add_argument("--file", type=str)
    parser.add_argument("--positions", type=str)
    parser.add_argument("--apply-known-good", action="store_true")
    parser.add_argument("--msr", type=str)
    parser.add_argument("--core", type=int)
    parser.add_argument("--reboot-warm", action="store_true")
    parser.add_argument("--machine-slot", type=int)
    parser.add_argument("--timeout", type=int, default=0)
    args = parser.parse_args()

    cmd = args.type.upper()
    pkt = None

    try:
        if cmd == "PING":
            if not args.message:
                raise ValueError("--message required for PING")
            pkt = PingPacket(message=args.message.encode("utf_16_le"))

        elif cmd == "SENDUCODE":
            if args.target_slot is None or not args.file:
                raise ValueError("--target-slot & --file required")
            with open(args.file, "rb") as f:
                data = f.read()
            pkt = SendUcodePacket(target_slot=args.target_slot, ucode=data)

        elif cmd == "FLIPBITS":
            if args.target_slot is None or not args.positions:
                raise ValueError("--target-slot & --positions required")
            flips = [int(x) for x in args.positions.split(",")]
            pkt = FlipBitsPacket(source_slot=args.target_slot, flips=flips)

        elif cmd == "APPLYUCODE":
            if args.target_slot is None:
                raise ValueError("--target-slot required")
            pkt = ApplyUcodePacket(target_slot=args.target_slot,
                                   apply_known_good=args.apply_known_good)

        elif cmd == "READMSR":
            if not args.msr:
                raise ValueError("--msr required")
            msr = int(args.msr, 16)
            pkt = ReadMsrPacket(target_msr=msr)

        elif cmd == "READMSRONCORE":
            if not args.msr or args.core is None:
                raise ValueError("--msr & --core required")
            msr = int(args.msr, 16)
            pkt = ReadMsrOnCorePacket(target_msr=msr, target_core=args.core)

        elif cmd == "REBOOT":
            pkt = RebootPacket(warm=args.reboot_warm)

        elif cmd == "GETLASTTESTRESULT":
            if args.core is None:
                raise ValueError("--core required")
            pkt = GetLastTestResultPacket(core=args.core)

        elif cmd == "STARTCORE":
            if args.core is None:
                raise ValueError("--core required")
            pkt = StartCorePacket(core=args.core)

        elif cmd == "GETCORESTATUS":
            if args.core is None:
                raise ValueError("--core required")
            pkt = GetCoreStatusPacket(core=args.core)

        elif cmd == "APPLYUCODEEXCUTETEST":
            if None in (args.target_slot, args.machine_slot, args.core):
                raise ValueError("--target-slot, --machine-slot & --core required")
            pkt = ApplyUcodeExecuteTestPacket(
                target_ucode_slot=args.target_slot,
                target_machine_code_slot=args.machine_slot,
                target_core=args.core,
                timeout=args.timeout,
                apply_known_good=args.apply_known_good
            )

        elif cmd == "SENDMACHINECODE":
            if args.target_slot is None or not args.file:
                raise ValueError("--target-slot & --file required")
            with open(args.file, "rb") as f:
                data = f.read()
            pkt = SendMachineCodePacket(target_slot=args.target_slot,
                                        machine_code=data)

        elif cmd == "EXECUTEMACHINECODE":
            if args.machine_slot is None or args.core is None:
                raise ValueError("--machine-slot & --core required")
            pkt = ExecuteMachineCodePacket(
                target_machine_code_slot=args.machine_slot,
                target_core=args.core,
                timeout=args.timeout
            )

        else:
            raise ValueError(f"Unknown type {cmd!r}")

    except Exception as e:
        print("Packet creation error:", e)
        sys.exit(1)

    try:
        responses = send_packet(pkt, args.host, args.port)
    except Exception as e:
        raise e
        print("Send error:", e)
        sys.exit(1)

    print("Response(s) received:")
    if not responses:
        print("  <none>")
    else:
        for i, r in enumerate(responses, 1):
            print(f"\n-- Response {i} --")
            print(r)
            if r.message_type == PacketType.CORESTATUSRESPONSE and r.faulted:
                print(r.fault_info.long_description())
            if r.message_type == PacketType.UCODEEXECUTETESTRESPONSE and len(r.result_buffer) > 0:
                hexdump(r.result_buffer)

if __name__ == "__main__":
    main()

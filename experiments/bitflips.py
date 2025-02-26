#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import socket
from enum import Enum

# Add parent directory to sys.path so that protocol can be imported.
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from protocol import (
    FlipBitsPacket,
    ApplyUcodePacket,
    UcodeResponsePacket,
    StatusPacket,
    Packet,
)

# Define an enum for reject states.
class RejectState(Enum):
    PUBMOD_REJECT = 1
    UNKNOWN_REJECT = 2
    SIGNATURE_REJECT = 3

# Configurable thresholds.
DEFAULT_PUBMOD_THRESHOLD = 30000
DEFAULT_UNKNOWN_THRESHOLD = 100000

def classify_rdtsc(rdtsc_diff, pubmod_threshold, unknown_threshold):
    """
    Classify the test result based on the rdtsc difference.
    Returns one of: RejectState.PUBMOD_REJECT, RejectState.UNKNOWN_REJECT, or RejectState.SIGNATURE_REJECT.
    """
    if rdtsc_diff < pubmod_threshold:
        return RejectState.PUBMOD_REJECT
    elif rdtsc_diff < unknown_threshold:
        return RejectState.UNKNOWN_REJECT
    else:
        return RejectState.SIGNATURE_REJECT

def send_flipbits(host, port, flip_slot, flip_positions):
    """
    Sends a FLIPBITS command using the specified flip_slot (target slot for bit flips)
    and list of bit positions to flip. Returns the parsed response packet.
    If the response is not a STATUS packet with code 0 and it is a STATUS packet,
    prints its status code and contained text before raising an exception.
    """
    pkt = FlipBitsPacket(source_slot=flip_slot, flips=flip_positions)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(pkt.pack())
        response = Packet.read_from_socket(sock)
    if not (isinstance(response, StatusPacket) and response.status_code == 0):
        if isinstance(response, StatusPacket):
            print(f"FLIPBITS STATUS response: code {response.status_code}, text: {response.text}")
        raise Exception("FLIPBITS command failed")
    return response

def send_apply_ucode(host, port, apply_slot, apply_known_good):
    """
    Sends an APPLYUCODE command using the specified apply_slot (target slot for applying update)
    with the given apply_known_good flag. Returns the parsed UcodeResponsePacket.
    If the response is not a UcodeResponsePacket and it is a STATUS packet,
    prints its status code and contained text before raising an exception.
    """
    pkt = ApplyUcodePacket(target_slot=apply_slot, apply_known_good=apply_known_good)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(pkt.pack())
        response = Packet.read_from_socket(sock)
    if not isinstance(response, UcodeResponsePacket):
        if isinstance(response, StatusPacket):
            print(f"APPLYUCODE STATUS response: code {response.status_code}, text: {response.text}")
        raise Exception("APPLYUCODE did not return UCODERESPONSE")
    return response

def load_resume(resume_file, mode):
    """Load resume state from a JSON file if it exists and matches the mode."""
    if os.path.exists(resume_file):
        with open(resume_file, "r") as f:
            try:
                data = json.load(f)
                if data.get("mode") == mode:
                    return data
            except Exception:
                pass
    return None

def save_resume(resume_file, data):
    """Save resume state to a JSON file."""
    with open(resume_file, "w") as f:
        json.dump(data, f)

def append_result(results_file, entry):
    """Append a new test result to the results JSON file."""
    if os.path.exists(results_file):
        with open(results_file, "r") as f:
            try:
                results = json.load(f)
            except Exception:
                results = []
    else:
        results = []
    results.append(entry)
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Bit Flip Tests for Ucode Update")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="AngryUEFI host")
    parser.add_argument("--port", type=int, default=3239, help="AngryUEFI port")
    parser.add_argument("--mode", type=str, choices=["single", "double"], default="single",
                        help="Test mode: single-bit flip or two-bit flip")
    parser.add_argument("--flipbits-slot", type=int, default=0,
                        help="Target slot for FLIPBITS command (ucode update location for bit flips)")
    parser.add_argument("--apply-slot", type=int, default=0,
                        help="Target slot for APPLYUCODE command")
    parser.add_argument("--update-size", type=int, default=3200, help="Ucode update size in bytes")
    parser.add_argument("--bit-start", type=int, default=0, help="Start bit position (default 0)")
    parser.add_argument("--bit-end", type=int, default=None,
                        help="End bit position (exclusive); default is update_size*8")
    parser.add_argument("--resume-file", type=str, default="resume.json", help="File for resume state")
    parser.add_argument("--results-file", type=str, default="results.json", help="File for test results")
    parser.add_argument("--pubmod-threshold", type=int, default=DEFAULT_PUBMOD_THRESHOLD,
                        help="Threshold for PubModReject")
    parser.add_argument("--unknown-threshold", type=int, default=DEFAULT_UNKNOWN_THRESHOLD,
                        help="Threshold for UnknownReject")
    args = parser.parse_args()

    total_bits = args.update_size * 8
    bit_end = args.bit_end if args.bit_end is not None else total_bits
    if bit_end > total_bits:
        bit_end = total_bits

    if args.mode == "single":
        total_tests = bit_end - args.bit_start
    else:
        n = bit_end - args.bit_start
        total_tests = n * (n - 1) // 2

    # Load resume state if available.
    if args.mode == "single":
        resume_state = load_resume(args.resume_file, "single")
        current_index = resume_state.get("current_index", args.bit_start) if resume_state else args.bit_start
    else:
        resume_state = load_resume(args.resume_file, "double")
        if resume_state:
            current_i = resume_state.get("current_i", args.bit_start)
            current_j = resume_state.get("current_j", args.bit_start + 1)
        else:
            current_i, current_j = args.bit_start, args.bit_start + 1

    # Counters for results.
    found_signature = 0
    found_unknown = 0
    test_count = 0
    last_rdtsc = 0
    start_time = time.time()

    # The ucode update is assumed to be already loaded in the flipbits slot.
    if args.mode == "single":
        for pos in range(current_index, bit_end):
            test_count += 1
            try:
                send_flipbits(args.host, args.port, args.flipbits_slot, [pos])
                apply_resp = send_apply_ucode(args.host, args.port, args.apply_slot, apply_known_good=False)
                rdtsc_diff = apply_resp.rdtsc_diff
                last_rdtsc = rdtsc_diff
                state = classify_rdtsc(rdtsc_diff, args.pubmod_threshold, args.unknown_threshold)
                if state in [RejectState.UNKNOWN_REJECT, RejectState.SIGNATURE_REJECT]:
                    entry = {
                        "mode": "single",
                        "bit_positions": [pos],
                        "rdtsc_diff": rdtsc_diff,
                        "state": state.name
                    }
                    append_result(args.results_file, entry)
                    if state == RejectState.SIGNATURE_REJECT:
                        found_signature += 1
                    elif state == RejectState.UNKNOWN_REJECT:
                        found_unknown += 1
            except Exception as e:
                sys.stdout.write(f"Test at bit {pos} failed: {e}\r")
                sys.stdout.flush()
                continue

            if test_count % 1000 == 0:
                save_resume(args.resume_file, {"mode": "single", "current_index": pos})
            elapsed = time.time() - start_time
            sys.stdout.write(f"[SINGLE] {test_count}/{total_tests} tests; current bit: {pos}; "
                             f"Last rdtsc: {last_rdtsc}; Elapsed: {elapsed:.2f}s; "
                             f"SignatureReject: {found_signature}, UnknownReject: {found_unknown}    \r")
            sys.stdout.flush()
    else:
        for i in range(current_i, bit_end):
            j_start = current_j if i == current_i else i + 1
            for j in range(j_start, bit_end):
                test_count += 1
                try:
                    send_flipbits(args.host, args.port, args.flipbits_slot, [i, j])
                    apply_resp = send_apply_ucode(args.host, args.port, args.apply_slot, apply_known_good=False)
                    rdtsc_diff = apply_resp.rdtsc_diff
                    last_rdtsc = rdtsc_diff
                    state = classify_rdtsc(rdtsc_diff, args.pubmod_threshold, args.unknown_threshold)
                    if state in [RejectState.UNKNOWN_REJECT, RejectState.SIGNATURE_REJECT]:
                        entry = {
                            "mode": "double",
                            "bit_positions": [i, j],
                            "rdtsc_diff": rdtsc_diff,
                            "state": state.name
                        }
                        append_result(args.results_file, entry)
                        if state == RejectState.SIGNATURE_REJECT:
                            found_signature += 1
                        elif state == RejectState.UNKNOWN_REJECT:
                            found_unknown += 1
                    # No need to reload update because it is persistent.
                except Exception as e:
                    sys.stdout.write(f"Test at bits ({i}, {j}) failed: {e}\r")
                    sys.stdout.flush()
                    continue

                if test_count % 1000 == 0:
                    save_resume(args.resume_file, {"mode": "double", "current_i": i, "current_j": j})
                elapsed = time.time() - start_time
                sys.stdout.write(f"[DOUBLE] {test_count}/{total_tests} tests; current pair: ({i}, {j}); "
                                 f"Last rdtsc: {last_rdtsc}; Elapsed: {elapsed:.2f}s; "
                                 f"SignatureReject: {found_signature}, UnknownReject: {found_unknown}    \r")
                sys.stdout.flush()

    # Final resume update.
    if args.mode == "single":
        save_resume(args.resume_file, {"mode": "single", "current_index": pos})
    else:
        save_resume(args.resume_file, {"mode": "double", "current_i": i, "current_j": j})
    total_elapsed = time.time() - start_time
    sys.stdout.write(f"\nCompleted {test_count} tests in {total_elapsed:.2f}s. "
                     f"SignatureReject: {found_signature}, UnknownReject: {found_unknown}.\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()

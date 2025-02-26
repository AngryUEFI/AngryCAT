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
    CONNECTION_ERROR = 4

# Configurable thresholds.
DEFAULT_PUBMOD_THRESHOLD = 30000
DEFAULT_UNKNOWN_THRESHOLD = 100000

def classify_rdtsc(rdtsc_diff, pub_threshold, unknown_threshold):
    if rdtsc_diff < pub_threshold:
        return RejectState.PUBMOD_REJECT
    elif rdtsc_diff < unknown_threshold:
        return RejectState.UNKNOWN_REJECT
    else:
        return RejectState.SIGNATURE_REJECT

class PersistentConnection:
    def __init__(self, host, port, max_retries=5):
        self.host = host
        self.port = port
        self.max_retries = max_retries
        self.sock = None
        self.connect()

    def connect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((self.host, self.port))

    def send_packet(self, packet_bytes):
        last_error = ""
        for attempt in range(self.max_retries):
            try:
                self.sock.sendall(packet_bytes)
                response = Packet.read_from_socket(self.sock)
                return response
            except Exception as e:
                last_error = str(e)
                try:
                    self.connect()
                except Exception:
                    pass
                time.sleep(0.5)
        raise Exception(f"Failed to send packet after {self.max_retries} retries: {last_error}")

def send_flipbits(pconn, flip_slot, flip_positions):
    pkt = FlipBitsPacket(source_slot=flip_slot, flips=flip_positions)
    response = pconn.send_packet(pkt.pack())
    if not (isinstance(response, StatusPacket) and response.status_code == 0):
        if isinstance(response, StatusPacket):
            print(f"FLIPBITS STATUS response: code {response.status_code}, text: {response.text}")
        raise Exception("FLIPBITS command failed")
    return response

def send_apply_ucode(pconn, apply_slot, apply_known_good):
    pkt = ApplyUcodePacket(target_slot=apply_slot, apply_known_good=apply_known_good)
    response = pconn.send_packet(pkt.pack())
    if not isinstance(response, UcodeResponsePacket):
        if isinstance(response, StatusPacket):
            print(f"APPLYUCODE STATUS response: code {response.status_code}, text: {response.text}")
        raise Exception("APPLYUCODE did not return UCODERESPONSE")
    return response

def run_single_test(pconn, flip_slot, apply_slot, pos, pub_threshold, unknown_threshold):
    retries = 0
    last_error = ""
    while retries < 5:
        try:
            send_flipbits(pconn, flip_slot, [pos])
            apply_resp = send_apply_ucode(pconn, apply_slot, apply_known_good=False)
            rdtsc_diff = apply_resp.rdtsc_diff
            state = classify_rdtsc(rdtsc_diff, pub_threshold, unknown_threshold)
            return rdtsc_diff, state, None
        except Exception as e:
            last_error = str(e)
            retries += 1
            time.sleep(0.5)
    return None, RejectState.CONNECTION_ERROR, f"Connection error after 5 retries: {last_error}"

def run_double_test(pconn, flip_slot, apply_slot, i, j, pub_threshold, unknown_threshold):
    retries = 0
    last_error = ""
    while retries < 5:
        try:
            send_flipbits(pconn, flip_slot, [i, j])
            apply_resp = send_apply_ucode(pconn, apply_slot, apply_known_good=False)
            rdtsc_diff = apply_resp.rdtsc_diff
            state = classify_rdtsc(rdtsc_diff, pub_threshold, unknown_threshold)
            return rdtsc_diff, state, None
        except Exception as e:
            last_error = str(e)
            retries += 1
            time.sleep(0.5)
    return None, RejectState.CONNECTION_ERROR, f"Connection error after 5 retries: {last_error}"

def load_resume(resume_file, mode):
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
    with open(resume_file, "w") as f:
        json.dump(data, f)

def append_result(results_file, entry):
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
                        help="Target slot for FLIPBITS command")
    parser.add_argument("--apply-slot", type=int, default=0,
                        help="Target slot for APPLYUCODE command")
    parser.add_argument("--update-size", type=int, default=3200, help="Ucode update size in bytes")
    parser.add_argument("--bit-start", type=int, default=0, help="Start bit position")
    parser.add_argument("--bit-end", type=int, default=None,
                        help="End bit position (exclusive); default is update_size*8")
    parser.add_argument("--resume-file", type=str, default="resume.json", help="File for resume state")
    parser.add_argument("--results-file", type=str, default="results.json", help="File for reject results")
    parser.add_argument("--all-results-file", type=str, default="all_results.json", help="File for all test results")
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

    found_signature = 0
    found_unknown = 0
    found_conn_error = 0
    test_count = 0
    last_rdtsc = 0
    start_time = time.time()

    # Establish a persistent connection.
    pconn = PersistentConnection(args.host, args.port, max_retries=5)

    if args.mode == "single":
        for pos in range(current_index, bit_end):
            test_count += 1
            rdtsc_diff, state, error_msg = run_single_test(pconn, args.flipbits_slot, args.apply_slot,
                                                            pos, args.pubmod_threshold, args.unknown_threshold)
            if state is not None:
                last_rdtsc = rdtsc_diff if rdtsc_diff is not None else last_rdtsc
            # Log result to all results file unconditionally.
            all_entry = {
                "mode": "single",
                "bit_positions": [pos],
                "rdtsc_diff": rdtsc_diff,
                "state": state.name if state is not None else "UNKNOWN_ERROR",
                "error": error_msg
            }
            append_result(args.all_results_file, all_entry)
            # For the normal results file, log only if it's a reject.
            if state in [RejectState.UNKNOWN_REJECT, RejectState.SIGNATURE_REJECT, RejectState.CONNECTION_ERROR]:
                entry = {
                    "mode": "single",
                    "bit_positions": [pos],
                    "rdtsc_diff": rdtsc_diff,
                    "state": state.name,
                    "error": error_msg
                }
                append_result(args.results_file, entry)
                if state == RejectState.SIGNATURE_REJECT:
                    found_signature += 1
                elif state == RejectState.UNKNOWN_REJECT:
                    found_unknown += 1
                elif state == RejectState.CONNECTION_ERROR:
                    found_conn_error += 1
            else:
                # For other states (e.g. PUBMOD_REJECT), we don't count them in the reject stats.
                pass

            if test_count % 10 == 0:
                save_resume(args.resume_file, {"mode": "single", "current_index": pos})
            elapsed = time.time() - start_time
            sys.stdout.write(f"[SINGLE] {test_count}/{total_tests} tests; current bit: {pos}; "
                             f"Last rdtsc: {last_rdtsc}; Elapsed: {elapsed:.2f}s; "
                             f"SignatureReject: {found_signature}, UnknownReject: {found_unknown}, "
                             f"ConnectionError: {found_conn_error}    \r")
            sys.stdout.flush()
    else:
        for i in range(current_i, bit_end):
            j_start = current_j if i == current_i else i + 1
            for j in range(j_start, bit_end):
                test_count += 1
                rdtsc_diff, state, error_msg = run_double_test(pconn, args.flipbits_slot, args.apply_slot,
                                                               i, j, args.pubmod_threshold, args.unknown_threshold)
                if state is not None:
                    last_rdtsc = rdtsc_diff if rdtsc_diff is not None else last_rdtsc
                all_entry = {
                    "mode": "double",
                    "bit_positions": [i, j],
                    "rdtsc_diff": rdtsc_diff,
                    "state": state.name if state is not None else "UNKNOWN_ERROR",
                    "error": error_msg
                }
                append_result(args.all_results_file, all_entry)
                if state in [RejectState.UNKNOWN_REJECT, RejectState.SIGNATURE_REJECT, RejectState.CONNECTION_ERROR]:
                    entry = {
                        "mode": "double",
                        "bit_positions": [i, j],
                        "rdtsc_diff": rdtsc_diff,
                        "state": state.name,
                        "error": error_msg
                    }
                    append_result(args.results_file, entry)
                    if state == RejectState.SIGNATURE_REJECT:
                        found_signature += 1
                    elif state == RejectState.UNKNOWN_REJECT:
                        found_unknown += 1
                    elif state == RejectState.CONNECTION_ERROR:
                        found_conn_error += 1
                if test_count % 10 == 0:
                    save_resume(args.resume_file, {"mode": "double", "current_i": i, "current_j": j})
                elapsed = time.time() - start_time
                sys.stdout.write(f"[DOUBLE] {test_count}/{total_tests} tests; current pair: ({i}, {j}); "
                                 f"Last rdtsc: {last_rdtsc}; Elapsed: {elapsed:.2f}s; "
                                 f"SignatureReject: {found_signature}, UnknownReject: {found_unknown}, "
                                 f"ConnectionError: {found_conn_error}    \r")
                sys.stdout.flush()

    if args.mode == "single":
        save_resume(args.resume_file, {"mode": "single", "current_index": pos})
    else:
        save_resume(args.resume_file, {"mode": "double", "current_i": i, "current_j": j})
    total_elapsed = time.time() - start_time
    sys.stdout.write(f"\nCompleted {test_count} tests in {total_elapsed:.2f}s. "
                     f"SignatureReject: {found_signature}, UnknownReject: {found_unknown}, "
                     f"ConnectionError: {found_conn_error}.\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()

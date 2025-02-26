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
    RebootPacket,
    PingPacket,
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
        self.sock.settimeout(1)
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
                time.sleep(1)
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

def send_reboot(pconn, warm=False):
    pkt = RebootPacket(warm=warm)
    try:
        pconn.send_packet(pkt.pack())
        print("REBOOT command sent.")
    except Exception as e:
        print("Error sending REBOOT packet:", e)

def send_ping(pconn, message="ping"):
    pkt = PingPacket(message=message.encode("utf_16_be"))
    response = pconn.send_packet(pkt.pack())
    return response

def wait_for_reboot(host, port, ping_message="ping", retry_interval=1):
    print("Waiting 30 seconds for system reboot...")
    time.sleep(30)
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((host, port))
                sock.sendall(PingPacket(message=ping_message.encode("utf_16_be")).pack())
                response = Packet.read_from_socket(sock)
                if response:
                    print("System is back online.")
                    return
        except Exception:
            print("System not up yet, retrying in", retry_interval, "seconds...")
            time.sleep(retry_interval)

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
            # No sleep here
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

# Append a JSON object to a file (each on its own line).
def append_result(results_file, entry):
    with open(results_file, "a") as f:
        f.write(json.dumps(entry) + ",\n")

def main():
    parser = argparse.ArgumentParser(description="Bit Flip Tests for Ucode Update")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="AngryUEFI host")
    parser.add_argument("--port", type=int, default=3239, help="AngryUEFI port")
    parser.add_argument("--mode", type=str, choices=["single", "double", "multi_region_double"], default="single",
                        help="Test mode: single-bit flip, two-bit flip, or multi_region_double")
    parser.add_argument("--flipbits-slot", type=int, default=0, help="Target slot for FLIPBITS command")
    parser.add_argument("--apply-slot", type=int, default=0, help="Target slot for APPLYUCODE command")
    parser.add_argument("--update-size", type=int, default=3200, help="Ucode update size in bytes")
    # For single and double modes:
    parser.add_argument("--bit-start", type=int, default=0, help="Start bit position")
    parser.add_argument("--bit-end", type=int, default=None, help="End bit position (exclusive); default is update_size*8")
    # For multi_region_double mode:
    parser.add_argument("--region1-start", type=int, default=0, help="Start bit position for region 1")
    parser.add_argument("--region1-end", type=int, default=None, help="End bit position for region 1")
    parser.add_argument("--region2-start", type=int, default=0, help="Start bit position for region 2")
    parser.add_argument("--region2-end", type=int, default=None, help="End bit position for region 2")
    parser.add_argument("--reboot-interval", type=int, default=5000,
                        help="Trigger a cold reboot every this many iterations (default 5000)")
    parser.add_argument("--resume-file", type=str, default="resume.json", help="File for resume state")
    parser.add_argument("--all-results-file", type=str, default="all_results.json", help="File for all test results")
    parser.add_argument("--pubmod-threshold", type=int, default=DEFAULT_PUBMOD_THRESHOLD,
                        help="Threshold for PubModReject")
    parser.add_argument("--unknown-threshold", type=int, default=DEFAULT_UNKNOWN_THRESHOLD,
                        help="Threshold for UnknownReject")
    args = parser.parse_args()

    total_bits = args.update_size * 8
    if args.mode in ["single", "double"]:
        bit_end = args.bit_end if args.bit_end is not None else total_bits
        if bit_end > total_bits:
            bit_end = total_bits
    if args.mode == "multi_region_double":
        region1_end = args.region1_end if args.region1_end is not None else total_bits
        region2_end = args.region2_end if args.region2_end is not None else total_bits

    if args.mode == "single":
        total_tests = (bit_end - args.bit_start)
    elif args.mode == "double":
        n = bit_end - args.bit_start
        total_tests = n * (n - 1) // 2
    else:  # multi_region_double
        total_tests = (args.region1_end - args.region1_start) * (args.region2_end - args.region2_start)

    if args.mode == "single":
        resume_state = load_resume(args.resume_file, "single")
        current_index = resume_state.get("current_index", args.bit_start) if resume_state else args.bit_start
    elif args.mode == "double":
        resume_state = load_resume(args.resume_file, "double")
        if resume_state:
            current_i = resume_state.get("current_i", args.bit_start)
            current_j = resume_state.get("current_j", args.bit_start + 1)
        else:
            current_i, current_j = args.bit_start, args.bit_start + 1
    else:
        resume_state = load_resume(args.resume_file, "multi_region_double")
        if resume_state:
            current_r1 = resume_state.get("region1_current", args.region1_start)
            current_r2 = resume_state.get("region2_current", args.region2_start)
        else:
            current_r1, current_r2 = args.region1_start, args.region2_start

    found_signature = 0
    found_unknown = 0
    found_conn_error = 0
    test_count = 0
    last_rdtsc = 0
    start_time = time.time()

    pconn = PersistentConnection(args.host, args.port, max_retries=5)

    if args.mode == "single":
        for pos in range(current_index, bit_end):
            test_count += 1
            rdtsc_diff, state, error_msg = run_single_test(pconn, args.flipbits_slot, args.apply_slot,
                                                            pos, args.pubmod_threshold, args.unknown_threshold)
            if state is not None:
                last_rdtsc = rdtsc_diff if rdtsc_diff is not None else last_rdtsc
            all_entry = {
                "mode": "single",
                "bit_positions": [pos],
                "rdtsc_diff": rdtsc_diff,
                "state": state.name if state is not None else "UNKNOWN_ERROR",
                "error": error_msg
            }
            append_result(args.all_results_file, all_entry)
            if state in [RejectState.UNKNOWN_REJECT, RejectState.SIGNATURE_REJECT, RejectState.CONNECTION_ERROR]:
                if state == RejectState.SIGNATURE_REJECT:
                    found_signature += 1
                elif state == RejectState.UNKNOWN_REJECT:
                    found_unknown += 1
                elif state == RejectState.CONNECTION_ERROR:
                    found_conn_error += 1
            if test_count % 10 == 0:
                save_resume(args.resume_file, {"mode": "single", "current_index": pos})
            elapsed = time.time() - start_time
            sys.stdout.write(f"[SINGLE] {test_count}/{total_tests} tests; current bit: {pos}; "
                             f"Last rdtsc: {last_rdtsc}; Elapsed: {elapsed:.2f}s; "
                             f"SigReject: {found_signature}, UnkReject: {found_unknown}, ConnErr: {found_conn_error}    \r")
            sys.stdout.flush()
            if test_count % args.reboot_interval == 0:
                sys.stdout.write("\nTriggering reboot...\n")
                sys.stdout.flush()
                send_reboot(pconn, warm=False)
                wait_for_reboot(args.host, args.port)
                pconn.connect()
    elif args.mode == "double":
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
                                 f"SigReject: {found_signature}, UnkReject: {found_unknown}, ConnErr: {found_conn_error}    \r")
                sys.stdout.flush()
                if test_count % args.reboot_interval == 0:
                    sys.stdout.write("\nTriggering reboot...\n")
                    sys.stdout.flush()
                    send_reboot(pconn, warm=False)
                    wait_for_reboot(args.host, args.port)
                    pconn.connect()
    else:  # multi_region_double
        for r1 in range(current_r1, args.region1_end):
            for r2 in range(current_r2, args.region2_end):
                test_count += 1
                try:
                    send_flipbits(pconn, args.flipbits_slot, [r1, r2])
                    apply_resp = send_apply_ucode(pconn, args.apply_slot, apply_known_good=False)
                    rdtsc_diff = apply_resp.rdtsc_diff
                    state = classify_rdtsc(rdtsc_diff, args.pubmod_threshold, args.unknown_threshold)
                except Exception as e:
                    rdtsc_diff, state, error_msg = None, RejectState.CONNECTION_ERROR, str(e)
                else:
                    error_msg = None
                if state is not None:
                    last_rdtsc = rdtsc_diff if rdtsc_diff is not None else last_rdtsc
                all_entry = {
                    "mode": "multi_region_double",
                    "bit_positions": [r1, r2],
                    "rdtsc_diff": rdtsc_diff,
                    "state": state.name if state is not None else "UNKNOWN_ERROR",
                    "error": error_msg
                }
                append_result(args.all_results_file, all_entry)
                if state in [RejectState.UNKNOWN_REJECT, RejectState.SIGNATURE_REJECT, RejectState.CONNECTION_ERROR]:
                    if state == RejectState.SIGNATURE_REJECT:
                        found_signature += 1
                    elif state == RejectState.UNKNOWN_REJECT:
                        found_unknown += 1
                    elif state == RejectState.CONNECTION_ERROR:
                        found_conn_error += 1
                if test_count % 10 == 0:
                    save_resume(args.resume_file, {"mode": "multi_region_double", "region1_current": r1, "region2_current": r2})
                elapsed = time.time() - start_time
                sys.stdout.write(f"[MULTI] {test_count}/{total_tests} tests; current regions: ({r1}, {r2}); "
                                 f"Last rdtsc: {last_rdtsc}; Elapsed: {elapsed:.2f}s; "
                                 f"SigReject: {found_signature}, UnkReject: {found_unknown}, ConnErr: {found_conn_error}    \r")
                sys.stdout.flush()
                if test_count % args.reboot_interval == 0:
                    sys.stdout.write("\nTriggering reboot...\n")
                    sys.stdout.flush()
                    send_reboot(pconn, warm=False)
                    wait_for_reboot(args.host, args.port)
                    pconn.connect()

    if args.mode == "single":
        save_resume(args.resume_file, {"mode": "single", "current_index": pos})
    elif args.mode == "double":
        save_resume(args.resume_file, {"mode": "double", "current_i": i, "current_j": j})
    else:
        save_resume(args.resume_file, {"mode": "multi_region_double", "region1_current": r1, "region2_current": r2})
    total_elapsed = time.time() - start_time
    sys.stdout.write(f"\nCompleted {test_count} tests in {total_elapsed:.2f}s. "
                     f"SigReject: {found_signature}, UnkReject: {found_unknown}, ConnErr: {found_conn_error}.\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()

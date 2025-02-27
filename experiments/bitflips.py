#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import socket

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

#####################################
# New Retry Logic Functions
#####################################

def run_single_test_with_retry(pconn, flip_slot, apply_slot, pos, retry_threshold, max_retry):
    attempt = 0
    rejected = []
    attempted_values = []
    while attempt < max_retry:
        attempt += 1
        try:
            send_flipbits(pconn, flip_slot, [pos])
            apply_resp = send_apply_ucode(pconn, apply_slot, apply_known_good=False)
            rdtsc = apply_resp.rdtsc_diff
        except Exception as e:
            rdtsc = float('inf')
        attempted_values.append(rdtsc)
        if retry_threshold == 0 or rdtsc <= retry_threshold:
            return rdtsc, rejected, attempt
        else:
            rejected.append(rdtsc)
    final_val = min(attempted_values) if attempted_values else None
    return final_val, rejected, attempt

def run_double_test_with_retry(pconn, flip_slot, apply_slot, i, j, retry_threshold, max_retry):
    attempt = 0
    rejected = []
    attempted_values = []
    while attempt < max_retry:
        attempt += 1
        try:
            send_flipbits(pconn, flip_slot, [i, j])
            apply_resp = send_apply_ucode(pconn, apply_slot, apply_known_good=False)
            rdtsc = apply_resp.rdtsc_diff
        except Exception as e:
            rdtsc = float('inf')
        attempted_values.append(rdtsc)
        if retry_threshold == 0 or rdtsc <= retry_threshold:
            return rdtsc, rejected, attempt
        else:
            rejected.append(rdtsc)
    final_val = min(attempted_values) if attempted_values else None
    return final_val, rejected, attempt

#####################################
# Persistent Connection Class
#####################################

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
                time.sleep(0.1)
        raise Exception(f"Failed to send packet after {self.max_retries} retries: {last_error}")

#####################################
# Packet Send Functions
#####################################

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

#####################################
# Mode-Specific Functions
#####################################

def run_single_mode(pconn, args, resume_state, start_time):
    current_index = resume_state.get("current_index", args.bit_start) if resume_state else args.bit_start
    absolute_test_count = resume_state.get("absolute_test_count", 0) if resume_state else 0
    total_retry_overall = resume_state.get("total_retry_count", 0) if resume_state else 0
    tests_since_reboot = 0
    bit_end = args.bit_end if args.bit_end is not None else args.update_size * 8
    total_tests = bit_end - args.bit_start

    for pos in range(current_index, bit_end):
        absolute_test_count += 1
        tests_since_reboot += 1
        final_rdtsc, rejected_vals, current_test_retries = run_single_test_with_retry(
            pconn, args.flipbits_slot, args.apply_slot, pos, args.retry_threshold, args.max_retry
        )
        total_retry_overall += current_test_retries - 1
        result = {
            "mode": "single",
            "bit_positions": [pos],
            "rdtsc_diff": final_rdtsc,
            "rejected_rdtsc_diffs": rejected_vals,
            "tests_since_reboot": tests_since_reboot,
            "current_test_retry_count": current_test_retries,
            "absolute_test_count": absolute_test_count,
            "runtime": time.time() - start_time,
            "total_retry_count": total_retry_overall
        }
        append_result(args.all_results_file, result)
        if args.resume_interval and absolute_test_count % args.resume_interval == 0:
            save_resume(args.resume_file, {
                "mode": "single",
                "current_index": pos,
                "absolute_test_count": absolute_test_count,
                "runtime": time.time() - start_time,
                "total_retry_count": total_retry_overall,
                "config": vars(args)
            })
        status_line = (f"[{args.project if args.project else 'SINGLE'}] {absolute_test_count}/{total_tests} tests; current bit: {pos}; "
                       f"Last rdtsc: {final_rdtsc}; Elapsed: {time.time()-start_time:.2f}s; "
                       f"Overall retries: {total_retry_overall}, current test retries: {current_test_retries}, "
                       f"Tests since reboot: {tests_since_reboot}")
        sys.stdout.write(status_line + "    \r")
        sys.stdout.flush()
        if absolute_test_count % args.reboot_interval == 0:
            sys.stdout.write("\nTriggering reboot...\n")
            sys.stdout.flush()
            send_reboot(pconn, warm=False)
            wait_for_reboot(args.host, args.port)
            pconn.connect()
            tests_since_reboot = 0

    return absolute_test_count, total_retry_overall

def run_double_mode(pconn, args, resume_state, start_time):
    if resume_state:
        current_i = resume_state.get("current_i", args.bit_start)
        current_j = resume_state.get("current_j", args.bit_start + 1)
        absolute_test_count = resume_state.get("absolute_test_count", 0)
        total_retry_overall = resume_state.get("total_retry_count", 0)
    else:
        current_i, current_j = args.bit_start, args.bit_start + 1
        absolute_test_count = 0
        total_retry_overall = 0

    tests_since_reboot = 0
    bit_end = args.bit_end if args.bit_end is not None else args.update_size * 8
    n = bit_end - args.bit_start
    total_tests = n * (n - 1) // 2

    for i in range(current_i, bit_end):
        for j in range((current_j if i == current_i else i + 1), bit_end):
            absolute_test_count += 1
            tests_since_reboot += 1
            final_rdtsc, rejected_vals, current_test_retries = run_double_test_with_retry(
                pconn, args.flipbits_slot, args.apply_slot, i, j, args.retry_threshold, args.max_retry
            )
            total_retry_overall += current_test_retries - 1
            result = {
                "mode": "double",
                "bit_positions": [i, j],
                "rdtsc_diff": final_rdtsc,
                "rejected_rdtsc_diffs": rejected_vals,
                "tests_since_reboot": tests_since_reboot,
                "current_test_retry_count": current_test_retries,
                "absolute_test_count": absolute_test_count,
                "runtime": time.time() - start_time,
                "total_retry_count": total_retry_overall
            }
            append_result(args.all_results_file, result)
            if args.resume_interval and absolute_test_count % args.resume_interval == 0:
                save_resume(args.resume_file, {
                    "mode": "double",
                    "current_i": i,
                    "current_j": j,
                    "absolute_test_count": absolute_test_count,
                    "runtime": time.time() - start_time,
                    "total_retry_count": total_retry_overall,
                    "config": vars(args)
                })
            status_line = (f"[{args.project if args.project else 'DOUBLE'}] {absolute_test_count}/{total_tests} tests; current pair: ({i}, {j}); "
                           f"Last rdtsc: {final_rdtsc}; Elapsed: {time.time()-start_time:.2f}s; "
                           f"Overall retries: {total_retry_overall}, current test retries: {current_test_retries}, "
                           f"Tests since reboot: {tests_since_reboot}")
            sys.stdout.write(status_line + "    \r")
            sys.stdout.flush()
            if absolute_test_count % args.reboot_interval == 0:
                sys.stdout.write("\nTriggering reboot...\n")
                sys.stdout.flush()
                send_reboot(pconn, warm=False)
                wait_for_reboot(args.host, args.port)
                pconn.connect()
                tests_since_reboot = 0
    return absolute_test_count, total_retry_overall

def run_multi_region_double_mode(pconn, args, resume_state, start_time):
    if resume_state:
        current_r1 = resume_state.get("region1_current", args.region1_start)
        current_r2 = resume_state.get("region2_current", args.region2_start)
        absolute_test_count = resume_state.get("absolute_test_count", 0)
        total_retry_overall = resume_state.get("total_retry_count", 0)
    else:
        current_r1, current_r2 = args.region1_start, args.region2_start
        absolute_test_count = 0
        total_retry_overall = 0

    tests_since_reboot = 0
    total_tests = (args.region1_end - args.region1_start) * (args.region2_end - args.region2_start)

    for r1 in range(current_r1, args.region1_end):
        for r2 in range(current_r2, args.region2_end):
            absolute_test_count += 1
            tests_since_reboot += 1
            try:
                send_flipbits(pconn, args.flipbits_slot, [r1, r2])
                apply_resp = send_apply_ucode(pconn, args.apply_slot, apply_known_good=False)
                rdtsc_diff = apply_resp.rdtsc_diff
                current_test_retries = 1
                rejected_vals = []
            except Exception as e:
                rdtsc_diff, current_test_retries, rejected_vals = None, 1, []
            total_retry_overall += current_test_retries - 1
            result = {
                "mode": "multi_region_double",
                "bit_positions": [r1, r2],
                "rdtsc_diff": rdtsc_diff,
                "rejected_rdtsc_diffs": rejected_vals,
                "tests_since_reboot": tests_since_reboot,
                "current_test_retry_count": current_test_retries,
                "absolute_test_count": absolute_test_count,
                "runtime": time.time() - start_time,
                "total_retry_count": total_retry_overall
            }
            append_result(args.all_results_file, result)
            if args.resume_interval and absolute_test_count % args.resume_interval == 0:
                save_resume(args.resume_file, {
                    "mode": "multi_region_double",
                    "region1_current": r1,
                    "region2_current": r2,
                    "absolute_test_count": absolute_test_count,
                    "runtime": time.time() - start_time,
                    "total_retry_count": total_retry_overall,
                    "config": vars(args)
                })
            status_line = (f"[{args.project if args.project else 'MULTI_REGION_DOUBLE'}] {absolute_test_count}/{total_tests} tests; current regions: ({r1}, {r2}); "
                           f"Last rdtsc: {rdtsc_diff}; Elapsed: {time.time()-start_time:.2f}s; "
                           f"Overall retries: {total_retry_overall}, current test retries: {current_test_retries}, "
                           f"Tests since reboot: {tests_since_reboot}")
            sys.stdout.write(status_line + "    \r")
            sys.stdout.flush()
            if absolute_test_count % args.reboot_interval == 0:
                sys.stdout.write("\nTriggering reboot...\n")
                sys.stdout.flush()
                send_reboot(pconn, warm=False)
                wait_for_reboot(args.host, args.port)
                pconn.connect()
                tests_since_reboot = 0
    return absolute_test_count, total_retry_overall

########################################
# Resume File Functions & Result Appending
########################################

def load_resume(resume_file, mode = None):
    if os.path.exists(resume_file):
        with open(resume_file, "r") as f:
            try:
                data = json.load(f)
                if mode is None:
                    return data
                if data.get("mode") == mode:
                    return data
            except Exception:
                pass
    return {}

def save_resume(resume_file, data):
    with open(resume_file, "w") as f:
        json.dump(data, f)

def append_result(results_file, entry):
    with open(results_file, "a") as f:
        f.write(json.dumps(entry) + ",\n")

########################################
# Main Test Driver
########################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bit Flip Tests for Ucode Update")
    parser.add_argument("--project", type=str, help="Project name. A folder with this name will be used for all output files.")
    parser.add_argument("--resume", action="store_true", help="If set, load test configuration parameters from the resume file in the project folder.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="AngryUEFI host")
    parser.add_argument("--port", type=int, default=3239, help="AngryUEFI port")
    parser.add_argument("--mode", type=str, choices=["single", "double", "multi_region_double"], help="Test mode: 'single', 'double', or 'multi_region_double'")
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
                        help="Trigger a cold reboot every this many tests (retries not counted)")
    parser.add_argument("--resume-file", type=str, default="resume.json", help="Resume file name")
    parser.add_argument("--all-results-file", type=str, default="all_results.json", help="Results file name")
    parser.add_argument("--retry-threshold", type=int, default=0,
                        help="If nonzero, if rdtsc_diff > threshold, retry the test (default 0 means no retry)")
    parser.add_argument("--max-retry", type=int, default=5,
                        help="Maximum number of retries per test (default 5)")
    parser.add_argument("--resume-interval", type=int, default=1,
                        help="Write resume state every this many tests (default 1 = every test)")
    args = parser.parse_args()

    # If a project is specified, create a folder and update file paths.
    if args.project:
        project_folder = args.project
        if not os.path.exists(project_folder):
            os.makedirs(project_folder)
        args.resume_file = os.path.join(project_folder, os.path.basename(args.resume_file))
        args.all_results_file = os.path.join(project_folder, os.path.basename(args.all_results_file))

    # If --resume is set, load configuration parameters from the resume file.
    if args.resume and args.project:
        resume_config = load_resume(args.resume_file)
        if resume_config and "config" in resume_config:
            for key in ["host", "port", "mode", "flipbits_slot", "apply_slot", "update_size",
                        "bit_start", "bit_end", "region1_start", "region1_end", "region2_start", "region2_end",
                        "reboot_interval", "retry_threshold", "max_retry", "resume_interval"]:
                if key in resume_config["config"]:
                    setattr(args, key, resume_config["config"][key])
            print("Loaded configuration from resume file:")
            print(json.dumps(resume_config["config"], indent=2))
        else:
            print("No resume configuration found in", args.resume_file)
            sys.exit(1)
    elif not args.mode:
        print("Test mode (--mode) must be specified if not resuming.")
        sys.exit(1)

    total_bits = args.update_size * 8
    if args.mode in ["single", "double"]:
        bit_end = args.bit_end if args.bit_end is not None else total_bits
        if bit_end > total_bits:
            bit_end = total_bits
    if args.mode == "multi_region_double":
        region1_end = args.region1_end if args.region1_end is not None else total_bits
        region2_end = args.region2_end if args.region2_end is not None else total_bits

    if args.mode == "single":
        total_tests = bit_end - args.bit_start
    elif args.mode == "double":
        n = bit_end - args.bit_start
        total_tests = n * (n - 1) // 2
    elif args.mode == "multi_region_double":
        total_tests = (args.region1_end - args.region1_start) * (args.region2_end - args.region2_start)
    else:
        print("Invalid mode specified.")
        sys.exit(1)

    # Load resume progress state.
    if args.mode == "single":
        resume_state = load_resume(args.resume_file, "single")
        current_index = resume_state.get("current_index", args.bit_start)
    elif args.mode == "double":
        resume_state = load_resume(args.resume_file, "double")
        current_i = resume_state.get("current_i", args.bit_start)
        current_j = resume_state.get("current_j", args.bit_start + 1)
    elif args.mode == "multi_region_double":
        resume_state = load_resume(args.resume_file, "multi_region_double")
        current_r1 = resume_state.get("region1_current", args.region1_start)
        current_r2 = resume_state.get("region2_current", args.region2_start)
    else:
        print("Invalid mode specified.")
        sys.exit(1)

    absolute_test_count = resume_state.get("absolute_test_count", 0) if resume_state else 0
    total_retry_overall = resume_state.get("total_retry_count", 0) if resume_state else 0

    tests_since_reboot = 0
    start_time = time.time()

    pconn = PersistentConnection(args.host, args.port, max_retries=5)

    if args.mode == "single":
        absolute_test_count, total_retry_overall = run_single_mode(pconn, args, resume_state, start_time)
    elif args.mode == "double":
        absolute_test_count, total_retry_overall = run_double_mode(pconn, args, resume_state, start_time)
    elif args.mode == "multi_region_double":
        absolute_test_count, total_retry_overall = run_multi_region_double_mode(pconn, args, resume_state, start_time)
    else:
        print("Invalid mode specified.")
        sys.exit(1)

    # Save final resume state (resume file retains the configuration).
    if args.mode == "single":
        save_resume(args.resume_file, {"mode": "single", "current_index": args.bit_end, "absolute_test_count": absolute_test_count,
                                      "runtime": time.time()-start_time, "total_retry_count": total_retry_overall,
                                      "config": vars(args)})
    elif args.mode == "double":
        save_resume(args.resume_file, {"mode": "double", "current_i": args.bit_end-1, "current_j": args.bit_end,
                                      "absolute_test_count": absolute_test_count,
                                      "runtime": time.time()-start_time, "total_retry_count": total_retry_overall,
                                      "config": vars(args)})
    else:
        save_resume(args.resume_file, {"mode": "multi_region_double", "region1_current": args.region1_end, "region2_current": args.region2_end,
                                      "absolute_test_count": absolute_test_count, "runtime": time.time()-start_time,
                                      "total_retry_count": total_retry_overall, "config": vars(args)})
    total_elapsed = time.time() - start_time
    sys.stdout.write(f"\nCompleted {absolute_test_count} tests in {total_elapsed:.2f}s. Total retries: {total_retry_overall}\n")
    sys.stdout.flush()

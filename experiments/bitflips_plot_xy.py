#!/usr/bin/env python3
import json
import argparse
import sys
import matplotlib.pyplot as plt
import numpy as np

def load_results(filename, limit):
    """
    Load results from a file that contains a JSON array of objects.
    If 'limit' is greater than 0, only process up to that many entries.
    """
    with open(filename, "r") as f:
        results = json.load(f)
    if limit > 0:
        results = results[:limit]
    return results

def filter_double_results(results, lower_threshold, upper_threshold):
    """
    Filter results to include only those entries with:
      - mode equal to "double"
      - a non-null "rdtsc_diff" value that is between lower_threshold and upper_threshold (inclusive)
      - a "bit_positions" array of length 2
    """
    filtered = []
    for entry in results:
        if entry.get("mode") != "double":
            continue
        if "rdtsc_diff" not in entry or entry["rdtsc_diff"] is None:
            continue
        rdtsc = entry["rdtsc_diff"]
        if rdtsc < lower_threshold or rdtsc > upper_threshold:
            continue
        bits = entry.get("bit_positions", [])
        if len(bits) != 2:
            continue
        filtered.append(entry)
    return filtered

def main():
    parser = argparse.ArgumentParser(
        description="Scatter Plot for Double Flip Tests (using bit_positions as [x, y] coordinates)"
    )
    parser.add_argument("results_file", type=str, help="JSON file containing double flip test results (JSON array)")
    parser.add_argument("--lower", type=int, default=22500, help="Lower threshold for rdtsc_diff (default 22500)")
    parser.add_argument("--upper", type=int, default=25000, help="Upper threshold for rdtsc_diff (default 25000)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit processing to up to this many entries from the file (0 means no limit)")
    args = parser.parse_args()

    results = load_results(args.results_file, args.limit)
    # In double flip tests, each entry should have a two-element bit_positions array.
    # For plotting we treat bit_positions as [x,y] coordinates.
    filtered = filter_double_results(results, args.lower, args.upper)
    if not filtered:
        print("No double flip results found in the specified range.")
        sys.exit(0)
    xs = [entry["bit_positions"][1] for entry in filtered]
    ys = [entry["bit_positions"][0] for entry in filtered]
    rdtsc_vals = [entry["rdtsc_diff"] for entry in filtered]

    plt.figure(figsize=(10, 6))
    scatter = plt.scatter(xs, ys, c=rdtsc_vals, cmap="viridis", alpha=0.8, edgecolors="none")
    plt.xlabel("Bit Position 1")
    plt.ylabel("Bit Position 2")
    plt.title("Double Flip Test Results (rdtsc_diff between {} and {})".format(args.lower, args.upper))
    cbar = plt.colorbar(scatter)
    cbar.set_label("rdtsc_diff")
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    main()

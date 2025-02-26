#!/usr/bin/env python3
import json
import sys
import matplotlib.pyplot as plt
import numpy as np

def load_results(filename):
    """
    Load results from a file that contains a JSON array of objects.
    Assumes the input file is valid JSON.
    """
    with open(filename, "r") as f:
        data = json.load(f)
    return data

def process_results(results):
    """
    Process results to extract x and y coordinates.
    
    - If entries have one bit position, use that value as x.
    - If entries have two bit positions, group by the tuple of bit positions.
      For each unique pair, use the last encountered entry and assign an index (starting at 1)
      as the x coordinate.
    
    Returns (xs, ys, xlabel) where xlabel is either "Bit Position" or "Entry Index".
    """
    if not results:
        print("No results loaded.")
        sys.exit(1)
    
    first_entry = results[0]
    bp = first_entry.get("bit_positions", [])
    
    if len(bp) == 1:
        xs = []
        ys = []
        for entry in results:
            if "bit_positions" in entry and "rdtsc_diff" in entry and entry["rdtsc_diff"] is not None:
                xs.append(entry["bit_positions"][0])
                ys.append(entry["rdtsc_diff"])
        xlabel = "Bit Position"
    elif len(bp) == 2:
        groups = {}
        for entry in results:
            key = tuple(entry.get("bit_positions", []))
            groups[key] = entry  # Keep the last encountered entry for each unique pair.
        sorted_keys = sorted(groups.keys())
        xs = []
        ys = []
        for idx, key in enumerate(sorted_keys, start=1):
            entry = groups[key]
            if "rdtsc_diff" in entry and entry["rdtsc_diff"] is not None:
                xs.append(idx)
                ys.append(entry["rdtsc_diff"])
        xlabel = "Entry Index"
    else:
        print("Unexpected bit_positions length:", len(bp))
        sys.exit(1)
    
    return xs, ys, xlabel

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <results_file.json>".format(sys.argv[0]))
        sys.exit(1)
    results_file = sys.argv[1]
    results = load_results(results_file)
    xs, ys, xlabel = process_results(results)
    
    plt.figure(figsize=(10, 6))
    plt.scatter(xs, ys, c='blue', alpha=0.6, edgecolors='none')
    plt.xlabel(xlabel)
    plt.ylabel("Execution Time (rdtsc_diff)")
    plt.title("Scatter Plot: {} vs. Execution Time".format(xlabel))
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    main()

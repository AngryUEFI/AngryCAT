#!/usr/bin/env python3
import json
import argparse
import sys
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LogNorm

def load_results(filename):
    """Load a JSON array of result objects from the specified file."""
    with open(filename, "r") as f:
        data = json.load(f)
    return data

def filter_double_results(results):
    """Return only those entries with mode 'double' and a two-element 'bit_positions' array."""
    return [r for r in results if len(r.get("bit_positions", [])) == 2]

def process_results(results):
    """
    Extract x and y coordinates and rdtsc_diff values.
    For double flip tests, x is the first bit position and y is the second.
    """
    xs = [entry["bit_positions"][0] for entry in results]
    ys = [entry["bit_positions"][1] for entry in results]
    rdtsc_vals = [entry["rdtsc_diff"] for entry in results]
    return xs, ys, rdtsc_vals

def main():
    parser = argparse.ArgumentParser(
        description="Scatter Plot for Double Flip Test Results with Logarithmic Color Scaling"
    )
    parser.add_argument("results_file", type=str, help="JSON file containing double flip test results (JSON array)")
    parser.add_argument("--vmin", type=int, default=20000, help="Minimum rdtsc_diff for color scaling (default 20000)")
    parser.add_argument("--vmax", type=int, default=100000, help="Maximum rdtsc_diff for color scaling (default 100000)")
    args = parser.parse_args()

    results = load_results(args.results_file)
    double_results = filter_double_results(results)
    
    if not double_results:
        print("No double flip results found in the file.")
        sys.exit(0)
    
    xs, ys, rdtsc_vals = process_results(double_results)
    
    plt.figure(figsize=(10, 6))
    scatter = plt.scatter(xs, ys, c=rdtsc_vals, cmap="viridis", norm=LogNorm(vmin=args.vmin, vmax=args.vmax), alpha=0.8, edgecolors="none")
    plt.xlabel("Bit Position 1")
    plt.ylabel("Bit Position 2")
    plt.title("Double Flip Test Results\n(rdtsc_diff with logarithmic scaling)")
    cbar = plt.colorbar(scatter)
    cbar.set_label("rdtsc_diff (log scale)")
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    main()

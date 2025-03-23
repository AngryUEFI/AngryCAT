#!/usr/bin/env python3
import json
import argparse
import sys
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans

def load_results(filename):
    """
    Load results from a file containing a JSON array of objects.
    """
    with open(filename, "r") as f:
        data = json.load(f)
    return data

def filter_results(results, min_val, max_val):
    """
    Filter results for entries that have exactly two bit positions and
    an rdtsc_diff within the specified bounds.
    
    If min_val is 0, no lower bound is applied.
    If max_val is 0, no upper bound is applied.
    """
    lower_bound = min_val if min_val > 0 else -np.inf
    upper_bound = max_val if max_val > 0 else np.inf
    
    filtered = []
    for entry in results:
        bp = entry.get("bit_positions", [])
        rdtsc = entry.get("rdtsc_diff")
        if (isinstance(bp, list) and len(bp) == 2 and rdtsc is not None 
                and lower_bound <= rdtsc <= upper_bound):
            filtered.append(entry)
    return filtered

def cluster_rdtsc(results, n_clusters):
    """
    Cluster the rdtsc_diff values (1D) into n_clusters using KMeans.
    Returns a list of cluster labels corresponding to each result.
    """
    rdtsc_vals = np.array([entry["rdtsc_diff"] for entry in results]).reshape(-1, 1)
    kmeans = KMeans(n_clusters=n_clusters, random_state=0).fit(rdtsc_vals)
    return kmeans.labels_, kmeans

def compute_cluster_stats(results, labels, n_clusters):
    """
    Compute statistics (count, min, max, std, average) for each cluster.
    Returns a dictionary mapping cluster labels to statistics.
    """
    cluster_stats = {}
    for cluster in range(n_clusters):
        cluster_vals = [entry["rdtsc_diff"] for entry, label in zip(results, labels) if label == cluster]
        if cluster_vals:
            arr = np.array(cluster_vals)
            cluster_stats[cluster] = {
                "count": int(len(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
                "std": float(np.std(arr)),
                "avg": float(np.mean(arr))
            }
        else:
            cluster_stats[cluster] = {"count": 0, "min": None, "max": None, "std": None, "avg": None}
    return cluster_stats

def create_scatter_plot(results, labels):
    """
    Create a scatter plot where the x-axis is the first bit position,
    the y-axis is the second bit position, and the dot color represents the cluster.
    """
    xs = [entry["bit_positions"][1] for entry in results]
    ys = [entry["bit_positions"][0] for entry in results]
    
    plt.figure(figsize=(10, 6))
    scatter = plt.scatter(xs, ys, c=labels, cmap="viridis", alpha=0.8, edgecolors="none")
    plt.xlabel("Bit Position 1")
    plt.ylabel("Bit Position 2")
    plt.title("Double Flip / Multi-region Double Flip Results\nClustered by rdtsc_diff")
    cbar = plt.colorbar(scatter)
    cbar.set_label("Cluster Label")
    plt.grid(True)
    plt.show()

def main():
    parser = argparse.ArgumentParser(
        description="Visualize double flip or multi-region double flip results with clustering of rdtsc_diff."
    )
    parser.add_argument("results_file", type=str, help="Path to all_results.json file")
    parser.add_argument("--min-value", type=float, default=0,
                        help="Minimum rdtsc_diff value to include (default: 0 means no lower filter)")
    parser.add_argument("--max-value", type=float, default=0,
                        help="Maximum rdtsc_diff value to include (default: 0 means no upper filter)")
    parser.add_argument("--clusters", type=int, default=3,
                        help="Number of clusters (default: 3)")
    args = parser.parse_args()

    results = load_results(args.results_file)
    if not results:
        print("No results loaded from file.")
        sys.exit(1)
    filtered_results = filter_results(results, args.min_value, args.max_value)
    if not filtered_results:
        print("No results match the filtering criteria.")
        sys.exit(1)

    labels, kmeans_model = cluster_rdtsc(filtered_results, args.clusters)
    stats = compute_cluster_stats(filtered_results, labels, args.clusters)

    print("Cluster Statistics:")
    for cluster, s in stats.items():
        print(f"Cluster {cluster}: Count: {s['count']}, Min: {s['min']}, Max: {s['max']}, "
              f"Std: {s['std']:.2f}, Avg: {s['avg']:.2f}")

    create_scatter_plot(filtered_results, labels)

if __name__ == "__main__":
    main()

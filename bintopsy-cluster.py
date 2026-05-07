#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
Script Name:   bintopsy-cluster.py
Description:   Reads one or more *enriched* JSON files (output of
               `sda-hashes.py`) and groups similar functions across all of
               them based on TLSH (default) or ssdeep distance.

               Useful for:
                 - Finding shared code between malware samples (variant
                   detection / family clustering).
                 - Spotting near-duplicate functions inside one binary
                   (often statically-linked libraries or unrolled loops).

               Output:
                 - Plain text clusters to stdout.
                 - Optional CSV with the full pairwise edge list
                   (`--csv FILE`).
                 - Optional PDF dendrogram if SciPy + Matplotlib are
                   installed (`--dendrogram FILE.pdf`).

Author:        Ricardo J. Rodríguez
Created:       2026-05-07
Version:       1.0

Requirements:  python-tlsh  (or ssdeep with --ssdeep)
               Optional: scipy, matplotlib (only for --dendrogram)
------------------------------------------------------------------------------
"""

import argparse
import json
import os
import sys
from collections import defaultdict

try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    HAS_TLSH = False

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False


def log(msg):
    sys.stderr.write(f"[+] {msg}\n")


def err(msg):
    sys.stderr.write(f"[-] {msg}\n")


def load_functions(json_paths, hash_field):
    """Returns list of {sample, name, hash} dicts (one per usable function)."""
    out = []
    for path in json_paths:
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            err(f"Skipping {path}: {e}")
            continue

        sample = data.get("metadata", {}).get("filename", os.path.basename(path))
        for fn in data.get("functions", []):
            h = fn.get("fuzzy_hashes", {}).get(hash_field, "")
            if not h or not h.startswith(("T1", "T")) and hash_field == "tlsh":
                continue
            if hash_field == "tlsh" and (not h.startswith("T1") or len(h) < 70):
                continue
            if hash_field == "ssdeep" and ":" not in h:
                continue
            out.append({
                "sample": sample,
                "name": fn.get("name", "unknown"),
                "hash": h,
                "size": fn.get("size", 0),
            })
    return out


def pairwise_distances(items, hash_field, threshold):
    """
    Return list of (i, j, distance) for pairs whose distance is below
    `threshold`. Naive O(N^2) — fine up to a few thousand functions.
    Distance semantics:
      - TLSH: smaller is more similar (0 = identical).
      - ssdeep: we convert similarity (0-100) into distance (100 - score)
        so that smaller is more similar in both modes.
    """
    n = len(items)
    edges = []
    for i in range(n):
        h1 = items[i]["hash"]
        for j in range(i + 1, n):
            h2 = items[j]["hash"]
            if hash_field == "tlsh":
                d = tlsh.diff(h1, h2)
            else:
                sim = ssdeep.compare(h1, h2)
                d = 100 - sim
            if d <= threshold:
                edges.append((i, j, d))
    return edges


def union_find_clusters(n, edges):
    """Group items into clusters by union-find over the surviving edges."""
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i, j, _ in edges:
        union(i, j)

    clusters = defaultdict(list)
    for idx in range(n):
        clusters[find(idx)].append(idx)
    return list(clusters.values())


def write_csv(path, items, edges, hash_field):
    import csv
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["sample_a", "function_a", "sample_b", "function_b",
                    "distance", "hash_field"])
        for i, j, d in edges:
            a, b = items[i], items[j]
            w.writerow([a["sample"], a["name"], b["sample"], b["name"], d, hash_field])
    log(f"Edges written to {path}")


def maybe_dendrogram(path, items, hash_field):
    """Optional: full hierarchical clustering using SciPy."""
    try:
        import numpy as np
        from scipy.cluster.hierarchy import linkage, dendrogram
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:
        err(f"--dendrogram requires scipy + matplotlib: {e}")
        return

    n = len(items)
    if n < 2:
        err("Need at least 2 functions for a dendrogram.")
        return

    log(f"Computing full {n}x{n} distance matrix for dendrogram...")
    dist = np.zeros((n * (n - 1)) // 2)
    k = 0
    for i in range(n):
        for j in range(i + 1, n):
            if hash_field == "tlsh":
                d = tlsh.diff(items[i]["hash"], items[j]["hash"])
            else:
                d = 100 - ssdeep.compare(items[i]["hash"], items[j]["hash"])
            dist[k] = d
            k += 1

    Z = linkage(dist, method="average")
    labels = [f"{x['sample']}::{x['name']}" for x in items]

    plt.figure(figsize=(max(8, n * 0.18), 6))
    dendrogram(Z, labels=labels, leaf_rotation=90, leaf_font_size=7)
    plt.title(f"BinTopsy function similarity ({hash_field})")
    plt.tight_layout()
    plt.savefig(path)
    log(f"Dendrogram written to {path}")


def main():
    parser = argparse.ArgumentParser(description="Cluster similar functions across enriched JSONs.")
    parser.add_argument("inputs", nargs='+', help="One or more *_enriched.json files")
    parser.add_argument("--ssdeep", action="store_true",
                        help="Use ssdeep instead of TLSH (requires the ssdeep library).")
    parser.add_argument("-t", "--threshold", type=int,
                        help="Max distance to consider similar. Defaults: TLSH=70, ssdeep=80 (=20 sim).")
    parser.add_argument("--min-cluster-size", type=int, default=2,
                        help="Hide clusters smaller than this in the text output (default: 2).")
    parser.add_argument("--csv", help="Also write the surviving edges as CSV.")
    parser.add_argument("--dendrogram", help="Optional PDF dendrogram (needs scipy+matplotlib).")
    args = parser.parse_args()

    hash_field = "ssdeep" if args.ssdeep else "tlsh"
    if hash_field == "tlsh" and not HAS_TLSH:
        err("python-tlsh not installed. pip install python-tlsh")
        sys.exit(1)
    if hash_field == "ssdeep" and not HAS_SSDEEP:
        err("ssdeep not installed. pip install ssdeep")
        sys.exit(1)

    if args.threshold is None:
        args.threshold = 70 if hash_field == "tlsh" else 80

    log(f"Hash: {hash_field}  |  Threshold: <= {args.threshold}")

    items = load_functions(args.inputs, hash_field)
    log(f"Loaded {len(items)} usable functions across {len(args.inputs)} files.")
    if not items:
        err("No functions with valid hashes. Did you run sda-hashes.py first?")
        sys.exit(1)

    edges = pairwise_distances(items, hash_field, args.threshold)
    log(f"Found {len(edges)} similar pairs under threshold.")

    clusters = union_find_clusters(len(items), edges)
    clusters = [c for c in clusters if len(c) >= args.min_cluster_size]
    clusters.sort(key=len, reverse=True)

    print(f"\n=== Clusters (>= {args.min_cluster_size} members) ===")
    if not clusters:
        print("(none)")
    for ci, cluster in enumerate(clusters, 1):
        # Cross-sample clusters are usually the interesting ones — flag them.
        samples = {items[i]["sample"] for i in cluster}
        cross = " (cross-sample)" if len(samples) > 1 else ""
        print(f"\n# Cluster {ci}: {len(cluster)} functions across {len(samples)} sample(s){cross}")
        for i in cluster:
            it = items[i]
            print(f"  - {it['sample']}  ::  {it['name']}  (size={it['size']})")

    if args.csv:
        write_csv(args.csv, items, edges, hash_field)
    if args.dendrogram:
        maybe_dendrogram(args.dendrogram, items, hash_field)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
Script Name:   bintopsy-diff.py
Description:   Structural diff between two binaries based on their dissector
               JSON output (`r2-dissector.py`). Reports:
                 - Added functions   (in B but not in A)
                 - Removed functions (in A but not in B)
                 - Modified         (same name, different size or entropy)
                 - Identical        (same name, same size, same entropy)

               Matching is by function name. If both inputs were enriched
               with `sda-hashes.py` (TLSH), the script will additionally
               try to match RENAMED functions: an A-function with no
               same-name match in B, but whose TLSH distance to a single
               B-function is below the threshold, is reported as a likely
               rename rather than a removal+addition.

Author:        Ricardo J. Rodríguez
Created:       2026-05-07
Version:       1.0

Requirements:  Standard Python 3.
               Optional: python-tlsh (only for the rename-detection pass).
------------------------------------------------------------------------------
"""

import argparse
import json
import os
import sys

try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    HAS_TLSH = False


# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def err(msg):
    sys.stderr.write(f"[-] {msg}\n")


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        err(f"Cannot load {path}: {e}")
        sys.exit(1)


def index_functions(data):
    """name -> {size, entropy, tlsh, addr}."""
    out = {}
    for fn in data.get("functions", []):
        name = fn.get("name")
        if not name:
            continue
        out[name] = {
            "size": fn.get("size", 0),
            "entropy": fn.get("entropy", 0.0),
            "addr": fn.get("address_hex") or hex(fn.get("address", 0)),
            "tlsh": (fn.get("fuzzy_hashes") or {}).get("tlsh", ""),
        }
    return out


def fmt_change(old, new):
    """Format an old→new arrow only if values differ."""
    return f"{old} → {new}" if old != new else str(old)


def main():
    parser = argparse.ArgumentParser(description="Diff two dissector JSONs.")
    parser.add_argument("a", help="Baseline JSON (e.g. older sample)")
    parser.add_argument("b", help="Comparison JSON (e.g. newer sample)")
    parser.add_argument("--entropy-eps", type=float, default=0.05,
                        help="Treat |Δentropy| <= eps as unchanged (default 0.05).")
    parser.add_argument("--rename-threshold", type=int, default=60,
                        help="Max TLSH distance to flag as rename (default 60).")
    parser.add_argument("--no-rename-detection", action="store_true",
                        help="Skip the optional TLSH-based rename pass.")
    parser.add_argument("--json", dest="json_out", help="Also write the diff as JSON.")
    args = parser.parse_args()

    data_a = load_json(args.a)
    data_b = load_json(args.b)

    name_a = data_a.get("metadata", {}).get("filename", os.path.basename(args.a))
    name_b = data_b.get("metadata", {}).get("filename", os.path.basename(args.b))

    idx_a = index_functions(data_a)
    idx_b = index_functions(data_b)

    only_a = set(idx_a) - set(idx_b)
    only_b = set(idx_b) - set(idx_a)
    common = set(idx_a) & set(idx_b)

    modified, identical = [], []
    for name in common:
        a, b = idx_a[name], idx_b[name]
        same_size = a["size"] == b["size"]
        same_entropy = abs(a["entropy"] - b["entropy"]) <= args.entropy_eps
        if same_size and same_entropy:
            identical.append(name)
        else:
            modified.append((name, a, b))

    # Optional rename-detection pass.
    renames = []
    if not args.no_rename_detection and HAS_TLSH:
        a_orphans = {n: idx_a[n] for n in only_a if idx_a[n]["tlsh"].startswith("T1")}
        b_orphans = {n: idx_b[n] for n in only_b if idx_b[n]["tlsh"].startswith("T1")}
        used_b = set()
        for an, ad in a_orphans.items():
            best_match, best_dist = None, args.rename_threshold + 1
            for bn, bd in b_orphans.items():
                if bn in used_b:
                    continue
                d = tlsh.diff(ad["tlsh"], bd["tlsh"])
                if d < best_dist:
                    best_dist = d
                    best_match = bn
            if best_match is not None and best_dist <= args.rename_threshold:
                renames.append((an, best_match, best_dist))
                used_b.add(best_match)

        for an, bn, _ in renames:
            only_a.discard(an)
            only_b.discard(bn)
    elif not args.no_rename_detection and not HAS_TLSH:
        sys.stderr.write(f"{YELLOW}[!] python-tlsh not installed; skipping rename detection.{RESET}\n")

    # ------- Print report -------
    print(f"\n{BOLD}=== BinTopsy diff: {name_a}  vs  {name_b} ==={RESET}")
    print(f"  Functions in A: {len(idx_a)}    in B: {len(idx_b)}")
    print(f"  {GREEN}Added:    {len(only_b)}{RESET}   "
          f"{RED}Removed:  {len(only_a)}{RESET}   "
          f"{YELLOW}Modified: {len(modified)}{RESET}   "
          f"{CYAN}Renamed:  {len(renames)}{RESET}   "
          f"Identical: {len(identical)}")

    if only_b:
        print(f"\n{GREEN}--- Added (only in {name_b}) ---{RESET}")
        for n in sorted(only_b):
            b = idx_b[n]
            print(f"  + {n}  (addr {b['addr']}, size {b['size']})")

    if only_a:
        print(f"\n{RED}--- Removed (only in {name_a}) ---{RESET}")
        for n in sorted(only_a):
            a = idx_a[n]
            print(f"  - {n}  (addr {a['addr']}, size {a['size']})")

    if modified:
        print(f"\n{YELLOW}--- Modified (same name, different bytes) ---{RESET}")
        for n, a, b in sorted(modified):
            print(f"  ~ {n}")
            print(f"      size:    {fmt_change(a['size'], b['size'])}")
            print(f"      entropy: {fmt_change(round(a['entropy'],3), round(b['entropy'],3))}")
            print(f"      addr:    {fmt_change(a['addr'], b['addr'])}")

    if renames:
        print(f"\n{CYAN}--- Likely renames (TLSH distance ≤ {args.rename_threshold}) ---{RESET}")
        for an, bn, d in sorted(renames, key=lambda x: x[2]):
            print(f"  → {an}  →  {bn}   (TLSH distance {d})")

    if args.json_out:
        out = {
            "a": name_a, "b": name_b,
            "added": sorted(only_b), "removed": sorted(only_a),
            "modified": [{"name": n,
                          "size_a": a["size"], "size_b": b["size"],
                          "entropy_a": a["entropy"], "entropy_b": b["entropy"]}
                         for n, a, b in modified],
            "renamed": [{"from": an, "to": bn, "tlsh_distance": d}
                        for an, bn, d in renames],
            "identical": sorted(identical),
        }
        with open(args.json_out, 'w') as f:
            json.dump(out, f, indent=2)
        sys.stderr.write(f"[+] Diff written to {args.json_out}\n")


if __name__ == "__main__":
    main()

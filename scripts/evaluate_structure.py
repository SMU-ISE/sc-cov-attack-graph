#!/usr/bin/env python3
"""
evaluate_structure.py

Generation-consistency evaluation for the attack-graph experiments.

For each method, this script counts the number of links produced in each of the
5 runs and reports the mean, standard deviation, and coefficient of variation
(CV) of the link counts. Lower standard deviation / CV indicates more
consistent (reproducible) generation across repeated runs.

Reproduces the "Generation Consistency (RQ1)" results (link-count mean / std /
CV per method).

Usage:
    python evaluate_structure.py --outputs-dir outputs --dataset log4j
    python evaluate_structure.py --outputs-dir outputs --dataset log4j --stddev sample

Expected directory layout:
    outputs/
        standard_prompting/
            run_1.json ... run_5.json
        few_shot_cot/
            run_1.json ... run_5.json
        self_consistency/
            run_1.json ... run_5.json      # majority-voted / final graph per run
        proposed/
            run_1.json ... run_5.json

Each JSON file must contain a top-level "links" array.

Note on standard deviation:
    --stddev population  (default): divides by n   -> matches paper Eq. (1)
    --stddev sample               : divides by n-1 -> matches the revised table
    Keep the same choice consistent with the reported values in the paper.
"""

import argparse
import json
import math
import os
import sys
from typing import List, Optional

# Method directory name -> display label. Order controls the report order.
METHODS = [
    ("standard_prompting", "Standard Prompting"),
    ("few_shot_cot", "Few-shot CoT"),
    ("self_consistency", "Self-Consistency Only"),
    ("proposed", "Proposed Framework"),
]

RUN_COUNT = 5


def count_links(json_path: str) -> int:
    """Return the number of links in a graph JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    links = data.get("links")
    if links is None:
        raise ValueError(f"No 'links' array found in {json_path}")
    return len(links)


def stddev(values: List[float], mode: str) -> float:
    """Standard deviation. mode='population' (n) or 'sample' (n-1)."""
    n = len(values)
    mu = sum(values) / n
    ss = sum((x - mu) ** 2 for x in values)
    if mode == "population":
        return math.sqrt(ss / n)
    elif mode == "sample":
        if n < 2:
            return 0.0
        return math.sqrt(ss / (n - 1))
    raise ValueError(f"Unknown stddev mode: {mode}")


def collect_link_counts(method_dir: str) -> List[int]:
    """Load run_1.json .. run_5.json from a method directory and count links."""
    counts = []
    for i in range(1, RUN_COUNT + 1):
        path = os.path.join(method_dir, f"run_{i}.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Expected run file not found: {path}")
        counts.append(count_links(path))
    return counts


def evaluate(outputs_dir: str, dataset: Optional[str], stddev_mode: str) -> None:
    # If a dataset subdirectory is used (outputs/log4j/standard_prompting/...),
    # prepend it; otherwise use outputs/standard_prompting/... directly.
    base = os.path.join(outputs_dir, dataset) if dataset else outputs_dir

    header = (
        f"{'Method':<24}"
        f"{'Run1':>6}{'Run2':>6}{'Run3':>6}{'Run4':>6}{'Run5':>6}"
        f"{'Mean':>9}{'Std':>9}{'CV(%)':>9}"
    )
    print(f"\nDataset: {dataset or '(root)'}    Std.Dev mode: {stddev_mode}")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    any_method = False
    for dir_name, label in METHODS:
        method_dir = os.path.join(base, dir_name)
        if not os.path.isdir(method_dir):
            # Skip silently-but-visibly so partial runs still work.
            print(f"{label:<24}{'(missing directory)':>54}")
            continue

        try:
            counts = collect_link_counts(method_dir)
        except FileNotFoundError as e:
            print(f"{label:<24}  ! {e}")
            continue

        any_method = True
        mu = sum(counts) / len(counts)
        sd = stddev(counts, stddev_mode)
        cv = (sd / mu * 100) if mu != 0 else 0.0

        runs_str = "".join(f"{c:>6}" for c in counts)
        print(f"{label:<24}{runs_str}{mu:>9.2f}{sd:>9.2f}{cv:>9.1f}")

    print("=" * len(header))
    if not any_method:
        print("No method directories found. Check --outputs-dir / --dataset.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate generation consistency (link-count mean/std/CV)."
    )
    parser.add_argument(
        "--outputs-dir", default="outputs",
        help="Root outputs directory (default: outputs)",
    )
    parser.add_argument(
        "--dataset", default=None,
        help="Dataset subdirectory under outputs/ (e.g., log4j). "
             "Omit if methods sit directly under outputs/.",
    )
    parser.add_argument(
        "--stddev", choices=["population", "sample"], default="population",
        help="Standard-deviation divisor: population=n (paper Eq.1), "
             "sample=n-1 (revised table). Default: population.",
    )
    args = parser.parse_args()
    evaluate(args.outputs_dir, args.dataset, args.stddev)


if __name__ == "__main__":
    main()

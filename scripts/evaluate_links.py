#!/usr/bin/env python3
"""
evaluate_links.py

Attack-link quality evaluation against the manually constructed ground truth.

Compares generated attack links with ground_truth_edges.csv and reports
TP / FP / FN, Precision, Recall, and F1-score for each method.

Reproduces the "Attack-Link Quality Evaluation (RQ2)" results
(Table 11 / Table 12 in the manuscript).

Usage:
    python evaluate_links.py --outputs-dir outputs --dataset log4j
    python evaluate_links.py --outputs-dir outputs --dataset log4j --match pair
    python evaluate_links.py --outputs-dir outputs --dataset log4j --per-run

Ground truth:
    dataset/{dataset}/ground_truth_edges.csv
    Only rows whose final_decision is ACCEPT are treated as ground-truth links.
    Rows marked REJECT are retained separately: a generated link matching a
    REJECT row is an explicitly adjudicated false positive.

Matching modes:
    pair (default) : (source, target) must match. The relationship type is
                     excluded from the TP/FP/FN decision because Standard
                     Prompting is given no relationship taxonomy and therefore
                     produces uncontrolled labels; type mismatches are reported
                     separately as classification errors by error_analysis.py.
    strict         : (source, target, relationship_type) must all match.

Note on relationship keys:
    Candidate graphs produced by the self-consistency stage store the
    relationship under the key "type", while the other methods use
    "relation_type". Both are accepted; the source files are left unmodified.
"""

import argparse
import csv
import json
import os
import sys
from typing import Dict, List, Set, Tuple

# Method directory name -> display label. Order controls the report order.
METHODS = [
    ("standard_prompting", "Standard Prompting"),
    ("few_shot_cot", "Few-shot CoT"),
    ("self_consistency", "SC Only"),
    ("proposed", "Proposed Framework"),
]

RUN_COUNT = 5

# A link is represented as (source, target, relationship_type).
Link = Tuple[str, str, str]


def normalize(value: str) -> str:
    """Normalize an identifier or relationship label for comparison."""
    return (value or "").strip().upper()


def link_key(source: str, target: str, rel: str, match_mode: str) -> Link:
    """Build the comparison key for a link under the selected matching mode."""
    if match_mode == "pair":
        return (normalize(source), normalize(target), "")
    return (normalize(source), normalize(target), normalize(rel))


def load_ground_truth(csv_path: str, match_mode: str) -> Tuple[Set[Link], Set[Link]]:
    """Load accepted and rejected links from ground_truth_edges.csv."""
    accepted: Set[Link] = set()
    rejected: Set[Link] = set()

    # utf-8-sig strips the BOM if present.
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"source_cve", "target_cve", "relationship_type", "final_decision"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"{csv_path} is missing required column(s): {sorted(missing)}"
            )

        for row in reader:
            key = link_key(
                row["source_cve"], row["target_cve"],
                row["relationship_type"], match_mode,
            )
            decision = normalize(row["final_decision"])
            if decision == "ACCEPT":
                accepted.add(key)
            elif decision == "REJECT":
                rejected.add(key)

    # A CVE pair may be adjudicated differently per relationship type: for
    # example, 45046 -> 45105 is accepted as incomplete_fix but rejected as
    # precondition_met. Under pair matching the relationship type is dropped,
    # so such a pair would otherwise land in both sets. Acceptance wins: the
    # pair is a genuine ground-truth link, and generating it is not an error.
    rejected -= accepted

    return accepted, rejected


def load_generated_links(json_path: str, match_mode: str) -> Set[Link]:
    """Load the set of links from a generated graph JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    links = data.get("links")
    if links is None:
        raise ValueError(f"No 'links' array found in {json_path}")

    result: Set[Link] = set()
    for link in links:
        source = link.get("source")
        target = link.get("target")
        # Candidate graphs use "type"; other methods use "relation_type".
        rel = link.get("relation_type") or link.get("type") or ""
        if not source or not target:
            continue
        result.add(link_key(source, target, rel, match_mode))
    return result


def score(generated: Set[Link], accepted: Set[Link]) -> Dict[str, float]:
    """Compute TP / FP / FN and the derived metrics for one run."""
    tp = len(generated & accepted)
    fp = len(generated - accepted)
    fn = len(accepted - generated)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1}


def evaluate_method(method_dir: str, accepted: Set[Link], rejected: Set[Link],
                    match_mode: str) -> Tuple[List[Dict[str, float]], int]:
    """Evaluate all runs of a method. Returns per-run scores and adjudicated FP count."""
    per_run = []
    adjudicated_fp = 0

    for i in range(1, RUN_COUNT + 1):
        path = os.path.join(method_dir, f"run_{i}.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Expected run file not found: {path}")
        generated = load_generated_links(path, match_mode)
        per_run.append(score(generated, accepted))
        adjudicated_fp += len(generated & rejected)

    return per_run, adjudicated_fp


def mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def evaluate(outputs_dir: str, dataset: str, gt_path: str,
             match_mode: str, per_run_detail: bool) -> None:
    accepted, rejected = load_ground_truth(gt_path, match_mode)

    print(f"\nDataset: {dataset}    Matching: {match_mode}")
    print(f"Ground truth: {len(accepted)} accepted link(s), "
          f"{len(rejected)} adjudicated-reject link(s)")
    print(f"Source: {gt_path}")

    base = os.path.join(outputs_dir, dataset)

    header = (f"{'Method':<22}{'TP':>7}{'FP':>7}{'FN':>7}"
              f"{'Precision':>11}{'Recall':>9}{'F1':>9}")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    any_method = False
    for dir_name, label in METHODS:
        method_dir = os.path.join(base, dir_name)
        if not os.path.isdir(method_dir):
            print(f"{label:<22}{'(missing directory)':>41}")
            continue

        try:
            per_run, adj_fp = evaluate_method(method_dir, accepted, rejected, match_mode)
        except FileNotFoundError as e:
            print(f"{label:<22}  ! {e}")
            continue

        any_method = True
        tp = mean([r["tp"] for r in per_run])
        fp = mean([r["fp"] for r in per_run])
        fn = mean([r["fn"] for r in per_run])
        p = mean([r["precision"] for r in per_run])
        r_ = mean([r["recall"] for r in per_run])
        f1 = mean([r["f1"] for r in per_run])

        print(f"{label:<22}{tp:>7.1f}{fp:>7.1f}{fn:>7.1f}"
              f"{p:>11.3f}{r_:>9.3f}{f1:>9.3f}")

        if per_run_detail:
            for i, r in enumerate(per_run, 1):
                print(f"    run_{i}          {r['tp']:>7}{r['fp']:>7}{r['fn']:>7}"
                      f"{r['precision']:>11.3f}{r['recall']:>9.3f}{r['f1']:>9.3f}")
            print(f"    (of all FPs across runs, {adj_fp} matched an "
                  f"explicitly rejected ground-truth candidate)")

    print("=" * len(header))
    print("Values are averaged over 5 runs. TP/FP/FN are shown to one decimal "
          "place because they are run averages, not integer counts.")

    if not any_method:
        print("No method directories found. Check --outputs-dir / --dataset.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate attack-link quality against the ground truth."
    )
    parser.add_argument("--outputs-dir", default="outputs",
                        help="Root outputs directory (default: outputs)")
    parser.add_argument("--dataset", required=True,
                        help="Dataset name, e.g., log4j or kaseya")
    parser.add_argument("--gt", default=None,
                        help="Path to ground_truth_edges.csv "
                             "(default: dataset/{dataset}/ground_truth_edges.csv)")
    parser.add_argument("--match", choices=["pair", "strict"], default="pair",
                        help="pair (default): source+target must match; the "
                             "relationship type is evaluated separately as a "
                             "classification error. strict: the relationship "
                             "type must match as well.")
    parser.add_argument("--per-run", action="store_true",
                        help="Also print per-run results.")
    args = parser.parse_args()

    gt_path = args.gt or os.path.join("dataset", args.dataset, "ground_truth_edges.csv")
    if not os.path.exists(gt_path):
        print(f"Ground-truth file not found: {gt_path}", file=sys.stderr)
        sys.exit(1)

    evaluate(args.outputs_dir, args.dataset, gt_path, args.match, args.per_run)


if __name__ == "__main__":
    main()

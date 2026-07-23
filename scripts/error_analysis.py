#!/usr/bin/env python3
"""
error_analysis.py

Quantitative error analysis of generated attack links.

Every generated link is assigned to exactly one category, and missing
ground-truth links are counted separately:

    direction error      The correct vulnerability pair was generated in the
                         reverse direction: (t, s) is a ground-truth link but
                         (s, t) is not.
    classification error The pair and its direction match a ground-truth link,
                         but the relationship type differs.
    hallucinated link    The pair is not supported by the ground truth in
                         either direction.
    missing link         A ground-truth link that the method did not generate.

Generated-link errors are mutually exclusive and applied in the order
direction > classification > hallucination, so no link is counted twice.
Missing links are counted separately and equal the FN column reported by
evaluate_links.py.

Reproduces the quantitative error distribution and the representative error
scenarios (Table 13 / Table 14 in the manuscript).

Usage:
    python error_analysis.py --dataset log4j
    python error_analysis.py --dataset log4j --aggregate sum
    python error_analysis.py --dataset log4j --per-run
    python error_analysis.py --dataset log4j --csv errors.csv

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
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

METHODS = [
    ("standard_prompting", "Standard Prompting"),
    ("few_shot_cot", "Few-shot CoT"),
    ("self_consistency", "SC Only"),
    ("proposed", "Proposed Framework"),
]

RUN_COUNT = 5

DIRECTION = "direction"
CLASSIFICATION = "classification"
HALLUCINATION = "hallucination"
MISSING = "missing"

ERROR_TYPES = [HALLUCINATION, MISSING, DIRECTION, CLASSIFICATION]
ERROR_LABELS = {
    HALLUCINATION: "Hallucinated",
    MISSING: "Missing",
    DIRECTION: "Direction",
    CLASSIFICATION: "Classification",
}

Pair = Tuple[str, str]


def normalize(value: str) -> str:
    return (value or "").strip().upper()


def load_ground_truth(csv_path: str) -> Dict[Pair, Set[str]]:
    """Map each accepted CVE pair to the set of accepted relationship types."""
    accepted: Dict[Pair, Set[str]] = defaultdict(set)

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"source_cve", "target_cve", "relationship_type", "final_decision"}
        missing_cols = required - set(reader.fieldnames or [])
        if missing_cols:
            raise ValueError(
                f"{csv_path} is missing required column(s): {sorted(missing_cols)}"
            )

        for row in reader:
            if normalize(row["final_decision"]) != "ACCEPT":
                continue
            pair = (normalize(row["source_cve"]), normalize(row["target_cve"]))
            accepted[pair].add(normalize(row["relationship_type"]))

    return dict(accepted)


def load_generated_links(json_path: str) -> Set[Tuple[str, str, str]]:
    """Load (source, target, relationship_type) triples from a graph file."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    links = data.get("links")
    if links is None:
        raise ValueError(f"No 'links' array found in {json_path}")

    result = set()
    for link in links:
        source = link.get("source")
        target = link.get("target")
        rel = link.get("relation_type") or link.get("type") or ""
        if not source or not target:
            continue
        result.add((normalize(source), normalize(target), normalize(rel)))
    return result


def classify_run(generated: Set[Tuple[str, str, str]],
                 gt: Dict[Pair, Set[str]]) -> Tuple[Counter, Dict[str, List]]:
    """Classify one run's links. Returns per-type counts and the offending items."""
    counts = Counter()
    items: Dict[str, List] = {t: [] for t in ERROR_TYPES}

    generated_pairs = {(s, t) for s, t, _ in generated}

    for source, target, rel in generated:
        pair = (source, target)
        if pair in gt:
            if rel in gt[pair]:
                continue  # correct link, correct type
            counts[CLASSIFICATION] += 1
            items[CLASSIFICATION].append((source, target, rel, sorted(gt[pair])))
        elif (target, source) in gt:
            counts[DIRECTION] += 1
            items[DIRECTION].append((source, target, rel, sorted(gt[(target, source)])))
        else:
            counts[HALLUCINATION] += 1
            items[HALLUCINATION].append((source, target, rel, []))

    for pair, types in gt.items():
        if pair not in generated_pairs:
            counts[MISSING] += 1
            items[MISSING].append((pair[0], pair[1], "", sorted(types)))

    return counts, items


def identity(error_type: str, source: str, target: str, rel: str) -> Tuple:
    """Identity of a distinct error, used by the 'unique' aggregation.

    Hallucination, direction and missing errors are identified by the CVE pair
    alone. A classification error also carries the generated relationship type,
    because emitting two different wrong types for the same pair is two
    distinct errors.
    """
    if error_type == CLASSIFICATION:
        return (source, target, rel)
    return (source, target)


def analyse_method(method_dir: str, gt: Dict[Pair, Set[str]]):
    """Analyse all runs of one method."""
    per_run_counts = []
    aggregated_items: Dict[str, Counter] = {t: Counter() for t in ERROR_TYPES}
    unique_errors: Dict[str, Set[Tuple]] = {t: set() for t in ERROR_TYPES}
    detail_rows = []

    for i in range(1, RUN_COUNT + 1):
        path = os.path.join(method_dir, f"run_{i}.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Expected run file not found: {path}")

        generated = load_generated_links(path)
        counts, items = classify_run(generated, gt)
        per_run_counts.append(counts)

        for etype, entries in items.items():
            for source, target, rel, gt_types in entries:
                aggregated_items[etype][(source, target, rel, tuple(gt_types))] += 1
                unique_errors[etype].add(identity(etype, source, target, rel))
                detail_rows.append({
                    "run": i,
                    "error_type": etype,
                    "source_cve": source,
                    "target_cve": target,
                    "generated_relationship": rel,
                    "ground_truth_relationship": "|".join(gt_types),
                })

    return per_run_counts, aggregated_items, unique_errors, detail_rows


def report(outputs_dir: str, dataset: str, gt_path: str, aggregate: str,
           per_run_detail: bool, examples: int, csv_path: Optional[str]) -> None:
    gt = load_ground_truth(gt_path)

    print(f"\nDataset: {dataset}    Aggregate: {aggregate} over {RUN_COUNT} runs")
    print(f"Ground truth: {len(gt)} accepted link(s)")
    print(f"Source: {gt_path}")

    base = os.path.join(outputs_dir, dataset)

    header = (f"{'Method':<22}{'Hallucinated':>14}{'Missing':>10}"
              f"{'Direction':>12}{'Classification':>16}{'Total':>9}")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    all_details = []
    all_examples = {}
    any_method = False

    for dir_name, label in METHODS:
        method_dir = os.path.join(base, dir_name)
        if not os.path.isdir(method_dir):
            print(f"{label:<22}{'(missing directory)':>61}")
            continue

        try:
            per_run_counts, agg_items, uniq, detail_rows = analyse_method(method_dir, gt)
        except FileNotFoundError as e:
            print(f"{label:<22}  ! {e}")
            continue

        any_method = True
        all_examples[label] = agg_items
        for row in detail_rows:
            row["method"] = label
        all_details.extend(detail_rows)

        values = {}
        for etype in ERROR_TYPES:
            if aggregate == "unique":
                values[etype] = len(uniq[etype])
            else:
                total = sum(c[etype] for c in per_run_counts)
                values[etype] = total if aggregate == "sum" else total / RUN_COUNT

        total_all = sum(values.values())
        fmt = "{:>14.0f}{:>10.0f}{:>12.0f}{:>16.0f}{:>9.0f}" \
            if aggregate in ("sum", "unique") \
            else "{:>14.1f}{:>10.1f}{:>12.1f}{:>16.1f}{:>9.1f}"
        print(f"{label:<22}" + fmt.format(
            values[HALLUCINATION], values[MISSING],
            values[DIRECTION], values[CLASSIFICATION], total_all))

        if per_run_detail:
            int_fmt = "{:>14.0f}{:>10.0f}{:>12.0f}{:>16.0f}{:>9.0f}"
            for i, c in enumerate(per_run_counts, 1):
                sub = f"{'  run_' + str(i):<22}"
                print(sub + int_fmt.format(
                    c[HALLUCINATION], c[MISSING], c[DIRECTION], c[CLASSIFICATION],
                    c[HALLUCINATION] + c[MISSING] + c[DIRECTION] + c[CLASSIFICATION]))

    print("=" * len(header))
    if aggregate == "mean":
        print("Values are averaged over 5 runs. Missing links equal the FN "
              "column reported by evaluate_links.py.")
    elif aggregate == "sum":
        print("Values are summed over 5 runs. An error recurring in several "
              "runs is counted once per run.")
    else:
        print("Values are counts of distinct erroneous links across the 5 runs. "
              "An error recurring in several runs is counted once, so these "
              "values use a different basis from the FN column reported by "
              "evaluate_links.py.")

    if not any_method:
        print("No method directories found. Check --outputs-dir / --dataset.")
        sys.exit(1)

    if examples > 0:
        print_examples(all_examples, examples)

    if csv_path:
        write_csv(all_details, csv_path)
        print(f"\nPer-link detail written to {csv_path} ({len(all_details)} rows).")


def print_examples(all_examples, limit: int) -> None:
    """Print the most frequently recurring error instances per type."""
    print("\n\nRepresentative error instances "
          "(most frequent across runs, per method)")
    print("=" * 78)

    for etype in ERROR_TYPES:
        print(f"\n[{ERROR_LABELS[etype]}]")
        found = False
        for label, agg in all_examples.items():
            entries = agg[etype].most_common(limit)
            if not entries:
                continue
            found = True
            print(f"  {label}")
            for (source, target, rel, gt_types), n in entries:
                arrow = f"{source} -> {target}"
                if etype == MISSING:
                    detail = f"expected [{', '.join(gt_types)}]"
                elif etype == DIRECTION:
                    detail = f"generated [{rel}]; ground truth has the reverse " \
                             f"edge as [{', '.join(gt_types)}]"
                elif etype == CLASSIFICATION:
                    detail = f"generated [{rel}] but ground truth is " \
                             f"[{', '.join(gt_types)}]"
                else:
                    detail = f"generated [{rel}]; no ground-truth support"
                print(f"    {n}/{RUN_COUNT} runs  {arrow}")
                print(f"                {detail}")
        if not found:
            print("  (none)")


def write_csv(rows: List[dict], path: str) -> None:
    cols = ["method", "run", "error_type", "source_cve", "target_cve",
            "generated_relationship", "ground_truth_relationship"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in cols})


def main():
    parser = argparse.ArgumentParser(
        description="Classify attack-link errors and surface representative cases."
    )
    parser.add_argument("--outputs-dir", default="outputs",
                        help="Root outputs directory (default: outputs)")
    parser.add_argument("--dataset", required=True,
                        help="Dataset name, e.g., log4j or kaseya")
    parser.add_argument("--gt", default=None,
                        help="Path to ground_truth_edges.csv "
                             "(default: dataset/{dataset}/ground_truth_edges.csv)")
    parser.add_argument("--aggregate", choices=["unique", "mean", "sum"],
                        default="unique",
                        help="unique (default): count distinct erroneous links "
                             "across the 5 runs. mean: per-run averages. "
                             "sum: totals over the 5 runs.")
    parser.add_argument("--per-run", action="store_true",
                        help="Also print per-run counts.")
    parser.add_argument("--examples", type=int, default=2,
                        help="Representative instances to list per error type "
                             "per method (default: 2, 0 to disable).")
    parser.add_argument("--csv", default=None,
                        help="Write per-link error detail to this CSV file.")
    args = parser.parse_args()

    gt_path = args.gt or os.path.join("dataset", args.dataset, "ground_truth_edges.csv")
    if not os.path.exists(gt_path):
        print(f"Ground-truth file not found: {gt_path}", file=sys.stderr)
        sys.exit(1)

    report(args.outputs_dir, args.dataset, gt_path, args.aggregate,
           args.per_run, args.examples, args.csv)


if __name__ == "__main__":
    main()

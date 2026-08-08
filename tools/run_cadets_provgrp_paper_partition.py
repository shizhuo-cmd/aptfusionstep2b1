from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from apt_fusion.task_detection.provgrp_paper_partition import apply_provgrp_paper_partition


def _load_components(module1_dir: Path) -> list[dict]:
    tasks = json.loads((module1_dir / "task_subgraphs.json").read_text(encoding="utf-8"))
    diagnostics = json.loads((module1_dir / "task_component_diagnostics.json").read_text(encoding="utf-8"))
    roots = {str(row["task_id"]): str(row["task_root_id"]) for row in diagnostics}
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    with (module1_dir / "process_segmentation_edges.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            parent = str(row["parent_process_id"])
            child = str(row["child_process_id"])
            adjacency[parent].append((parent, child))
    components = []
    for task in tasks:
        task_id = str(task["task_id"])
        nodes = [str(value) for value in task["process_ids"]]
        node_set = set(nodes)
        edges = [[parent, child] for node in node_set for parent, child in adjacency.get(node, []) if child in node_set]
        components.append({"task_id": task_id, "task_root": roots[task_id], "nodes": nodes, "edges": edges, "boundary_nodes": []})
    return components


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-module1", required=True)
    parser.add_argument("--source-logs", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--min-direct-children", type=int, default=10)
    parser.add_argument("--min-cluster-size", type=int, default=5)
    parser.add_argument("--min-samples", type=int, default=2)
    parser.add_argument("--max-events-per-matrix", type=int, default=512)
    args = parser.parse_args()
    components = _load_components(Path(args.baseline_module1))
    refined, summary = apply_provgrp_paper_partition(components, source_logs=args.source_logs, min_direct_children=args.min_direct_children, min_cluster_size=args.min_cluster_size, min_samples=args.min_samples, max_events_per_matrix=args.max_events_per_matrix)
    ground_truth = {line.strip() for line in Path(args.ground_truth).read_text(encoding="utf-8").splitlines() if line.strip()}
    rows = []
    for index, component in enumerate(refined):
        nodes = [str(value) for value in component["nodes"]]
        row = {"task_id": f"task_{index:04d}", "task_root_id": component["task_root"], "task_size": len(nodes), "process_gt_hit_count": sum(node in ground_truth for node in nodes)}
        for key, value in component.items():
            if key.startswith("provgrp_paper_"):
                row[key] = value
        rows.append(row)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "task_subgraphs.json").write_text(json.dumps([{"task_id": row["task_id"], "process_ids": component["nodes"]} for row, component in zip(rows, refined)], indent=2), encoding="utf-8")
    (output / "task_component_diagnostics.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    summary.update({"task_count": len(rows), "process_gt_hit_task_count": sum(row["process_gt_hit_count"] > 0 for row in rows), "large_task_count_gt_500": sum(row["task_size"] > 500 for row in rows), "large_task_count_gt_1000": sum(row["task_size"] > 1000 for row in rows)})
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

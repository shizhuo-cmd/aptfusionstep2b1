"""Summarize E5 task-graph size and root/split characteristics."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
import torch


def _quantiles(values: list[int]) -> dict[str, float]:
    array = np.asarray(values, dtype=np.float64)
    return {
        "min": float(array.min()), "median": float(np.median(array)), "mean": float(array.mean()),
        "p90": float(np.quantile(array, 0.90)), "p95": float(np.quantile(array, 0.95)),
        "p99": float(np.quantile(array, 0.99)), "max": float(array.max()),
    }


def _compact_task(meta: dict) -> dict:
    payload = {
        key: meta.get(key)
        for key in (
            "task_id", "task_size", "internal_edge_count", "label", "attacknum", "task_root_id",
            "task_root_total_children", "task_root_effective_children", "task_root_segmented",
            "task_root_parent_missing", "child_threshold", "split_mode", "count_segmented_children_upstream",
        )
    }
    payload["boundary_node_count"] = len(meta.get("boundary_node_ids", []))
    return payload


def run(bundle_path: Path, score_path: Path, output: Path) -> None:
    bundle = torch.load(bundle_path, map_location="cpu", weights_only=False)
    metas = list(bundle["selected_graph_metas"])
    sizes = [int(meta.get("task_size", 0)) for meta in metas]
    positives = [meta for meta in metas if int(meta.get("label", 0)) == 1]
    roots = Counter(str(meta.get("task_root_id", "")) for meta in metas)
    top = sorted(metas, key=lambda meta: int(meta.get("task_size", 0)), reverse=True)[:30]
    result = {
        "task_count": len(metas),
        "positive_task_count": len(positives),
        "size_distribution": _quantiles(sizes),
        "counts": {
            "gt_100": sum(size > 100 for size in sizes),
            "gt_500": sum(size > 500 for size in sizes),
            "gt_1000": sum(size > 1000 for size in sizes),
            "gt_5000": sum(size > 5000 for size in sizes),
            "root_parent_missing": sum(bool(meta.get("task_root_parent_missing", False)) for meta in metas),
            "root_segmented": sum(bool(meta.get("task_root_segmented", False)) for meta in metas),
        },
        "positive_size_distribution": _quantiles([int(meta.get("task_size", 0)) for meta in positives]),
        "positive_attacknum_distribution": _quantiles([int(meta.get("attacknum", 0)) for meta in positives]),
        "reused_roots": {
            "unique_root_count": len(roots),
            "roots_with_multiple_tasks": sum(count > 1 for count in roots.values()),
            "top": roots.most_common(20),
        },
        "largest_tasks": [_compact_task(meta) for meta in top],
        "positive_tasks": [
            _compact_task(meta)
            for meta in sorted(positives, key=lambda meta: int(meta.get("task_size", 0)), reverse=True)
        ],
    }
    if score_path.exists():
        import pandas as pd

        scores = pd.read_csv(score_path)
        score_column = "score" if "score" in scores.columns else scores.columns[-1]
        label_column = "label" if "label" in scores.columns else ("task_label" if "task_label" in scores.columns else None)
        result["score_ranking"] = {
            "columns": list(scores.columns),
            "top20": scores.sort_values(score_column, ascending=False).head(20).to_dict("records"),
            "positive_rows": (
                scores[scores[label_column] == 1].sort_values(score_column, ascending=False).to_dict("records")
                if label_column else []
            ),
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--scores", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.bundle, args.scores, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

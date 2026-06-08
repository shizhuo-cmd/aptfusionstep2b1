from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from ..common import ensure_dir, save_json
from ..config import FusionConfig
from .models import Module2Output, ProcessScore, TaskSubgraph
from .tapas_native_backend import _load_native_bundle, run_tapas_module2


def _task_row_exports(task_rows: List[dict]) -> list[dict]:
    exported = []
    for row in sorted(task_rows, key=lambda item: float(item["task_score"]), reverse=True):
        raw_threshold = row.get("threshold_used", 0.5)
        threshold_used = None if raw_threshold is None else float(raw_threshold)
        exported.append(
            {
                "task_id": row["task_id"],
                "task_score": float(row["task_score"]),
                "task_probability": float(row.get("task_probability", row["task_score"])),
                "graphsage_probability": (
                    None
                    if row.get("graphsage_probability") is None
                    else float(row.get("graphsage_probability"))
                ),
                "stats_probability": (
                    None
                    if row.get("stats_probability") is None
                    else float(row.get("stats_probability"))
                ),
                "task_label": row.get("task_label"),
                "predicted_label": int(row.get("predicted_label", 0)),
                "prediction_mode": str(row.get("prediction_mode", "argmax")),
                "task_size": int(row["task_size"]),
                "internal_edge_count": int(row.get("internal_edge_count", 0)),
                "graph_edge_source": "tapas_parent_child_edges",
                "task_score_basis": str(row.get("task_score_basis", "tapas_native_graphsage")),
                "fusion_weight_stats": float(row.get("fusion_weight_stats", 0.0)),
                "threshold_used": threshold_used,
                "is_suspicious": bool(row.get("is_suspicious", False)),
                "process_ids": [str(pid) for pid in row.get("process_ids", [])],
            }
        )
    return exported


def _normalize_ref_to_process_id(value: Any, process_ids: list[str]) -> str:
    if isinstance(value, int):
        index = int(value)
        if 0 <= index < len(process_ids):
            return process_ids[index]
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.isdigit():
        index = int(text)
        if 0 <= index < len(process_ids):
            return process_ids[index]
    if text in process_ids:
        return text
    return ""


def _edge_rows_for_graph(graph: dict[str, Any], process_ids: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for edge in graph.get("edges", []) or []:
        if not isinstance(edge, (list, tuple)) or len(edge) < 2:
            continue
        src = _normalize_ref_to_process_id(edge[0], process_ids)
        dst = _normalize_ref_to_process_id(edge[1], process_ids)
        if not src or not dst:
            continue
        rows.append({"src": src, "dst": dst})
    return rows


def _base_task_id(task_id: str) -> str:
    if "_aug" not in task_id:
        return task_id
    base, suffix = task_id.rsplit("_aug", 1)
    if base and len(suffix) == 3 and suffix.isdigit():
        return base
    return task_id


def _safe_l2(values: list[Any]) -> float:
    total = 0.0
    for value in values:
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        total += number * number
    return math.sqrt(total)


def _minmax(values: dict[str, float]) -> dict[str, float]:
    if not values:
        return {}
    min_v = min(values.values())
    max_v = max(values.values())
    if max_v - min_v <= 1e-12:
        return {key: 0.5 for key in values}
    return {key: (value - min_v) / (max_v - min_v) for key, value in values.items()}


def _task_graph_sidecars(task_rows: List[dict], module1_dir: Path) -> tuple[list[dict], dict[str, dict]]:
    bundle = _load_native_bundle(module1_dir)
    graphs = list(bundle.get("selected_graphs", []))
    metas = list(bundle.get("selected_graph_metas", []))
    meta_by_task = {
        str(meta.get("task_id", "")): (graph, meta)
        for graph, meta in zip(graphs, metas)
        if str(meta.get("task_id", "")).strip()
    }

    rich_rows: list[dict] = []
    attribution_by_task: dict[str, dict] = {}

    for row in task_rows:
        task_id = str(row["task_id"])
        pair = meta_by_task.get(task_id)
        graph_task_id = task_id
        if pair is None:
            graph_task_id = _base_task_id(task_id)
            pair = meta_by_task.get(graph_task_id)
        if pair is None:
            continue
        graph, meta = pair
        process_ids = [str(pid) for pid in meta.get("node_ids", [])]
        local_edges = _edge_rows_for_graph(graph, process_ids)
        indegree = {pid: 0 for pid in process_ids}
        outdegree = {pid: 0 for pid in process_ids}
        neighbors = {pid: set() for pid in process_ids}

        for edge in local_edges:
            src = edge["src"]
            dst = edge["dst"]
            outdegree[src] = outdegree.get(src, 0) + 1
            indegree[dst] = indegree.get(dst, 0) + 1
            neighbors.setdefault(src, set()).add(dst)
            neighbors.setdefault(dst, set()).add(src)

        root_process_ids = sorted([pid for pid in process_ids if indegree.get(pid, 0) == 0])
        leaf_process_ids = sorted([pid for pid in process_ids if outdegree.get(pid, 0) == 0])
        degree = {pid: indegree.get(pid, 0) + outdegree.get(pid, 0) for pid in process_ids}
        bridge_degree = {pid: len(neighbors.get(pid, set())) for pid in process_ids}

        raw_nodes = list(graph.get("nodes", []))
        feature_norms = {
            pid: _safe_l2(list(raw_nodes[index])) if index < len(raw_nodes) else 0.0
            for index, pid in enumerate(process_ids)
        }
        feature_norms_n = _minmax(feature_norms)
        degree_n = _minmax({pid: float(value) for pid, value in degree.items()})
        indegree_n = _minmax({pid: float(value) for pid, value in indegree.items()})
        outdegree_n = _minmax({pid: float(value) for pid, value in outdegree.items()})
        bridge_n = _minmax({pid: float(value) for pid, value in bridge_degree.items()})

        node_scores: dict[str, float] = {}
        for pid in process_ids:
            root_bonus = 1.0 if pid in root_process_ids else 0.0
            node_scores[pid] = (
                0.45 * feature_norms_n.get(pid, 0.0)
                + 0.20 * degree_n.get(pid, 0.0)
                + 0.15 * outdegree_n.get(pid, 0.0)
                + 0.10 * indegree_n.get(pid, 0.0)
                + 0.10 * max(root_bonus, bridge_n.get(pid, 0.0))
            )

        top_processes = sorted(
            [
                {
                    "process_id": pid,
                    "score": float(node_scores.get(pid, 0.0)),
                    "feature_norm": float(feature_norms.get(pid, 0.0)),
                    "degree": int(degree.get(pid, 0)),
                    "in_degree": int(indegree.get(pid, 0)),
                    "out_degree": int(outdegree.get(pid, 0)),
                    "neighbor_count": int(bridge_degree.get(pid, 0)),
                    "is_root": pid in root_process_ids,
                    "is_leaf": pid in leaf_process_ids,
                }
                for pid in process_ids
            ],
            key=lambda item: (float(item["score"]), item["process_id"]),
            reverse=True,
        )

        top_edges = sorted(
            [
                {
                    "src": edge["src"],
                    "dst": edge["dst"],
                    "score": float(
                        (node_scores.get(edge["src"], 0.0) + node_scores.get(edge["dst"], 0.0)) / 2.0
                    ),
                }
                for edge in local_edges
            ],
            key=lambda item: (float(item["score"]), item["src"], item["dst"]),
            reverse=True,
        )

        density = 0.0
        if len(process_ids) > 1:
            density = float(len(local_edges)) / float(len(process_ids) * (len(process_ids) - 1))

        rich_rows.append(
            {
                "task_id": task_id,
                "task_score": float(row["task_score"]),
                "task_probability": float(row.get("task_probability", row["task_score"])),
                "graphsage_probability": (
                    None
                    if row.get("graphsage_probability") is None
                    else float(row.get("graphsage_probability"))
                ),
                "stats_probability": (
                    None
                    if row.get("stats_probability") is None
                    else float(row.get("stats_probability"))
                ),
                "task_size": int(meta.get("task_size", len(process_ids))),
                "internal_edge_count": int(meta.get("internal_edge_count", len(local_edges))),
                "graph_task_id": graph_task_id,
                "task_root_id": str(meta.get("task_root_id", "")).strip(),
                "boundary_node_ids": [str(item) for item in meta.get("boundary_node_ids", [])],
                "process_ids": process_ids,
                "root_process_ids": root_process_ids,
                "leaf_process_ids": leaf_process_ids,
                "local_edges": local_edges,
                "graph_density": density,
                "prediction_mode": str(row.get("prediction_mode", "argmax")),
                "is_suspicious": bool(row.get("is_suspicious", False)),
            }
        )
        attribution_by_task[task_id] = {
            "task_id": task_id,
            "graph_task_id": graph_task_id,
            "top_processes": top_processes[: min(12, len(top_processes))],
            "top_edges": top_edges[: min(12, len(top_edges))],
            "root_process_ids": root_process_ids,
            "leaf_process_ids": leaf_process_ids,
            "graph_density": density,
        }

    return rich_rows, attribution_by_task


def _build_process_score_rows(task_rows: List[dict], attribution_by_task: dict[str, dict]) -> list[dict]:
    rows_by_process: dict[str, dict] = {}
    for row in task_rows:
        task_score = float(row["task_score"])
        task_prob = float(row.get("task_probability", task_score))
        is_suspicious = bool(row.get("is_suspicious", False))
        task_id = str(row["task_id"])
        attribution = attribution_by_task.get(task_id, {})
        node_scores = {
            str(item.get("process_id", "")): float(item.get("score", 0.0))
            for item in attribution.get("top_processes", [])
            if str(item.get("process_id", "")).strip()
        }
        for pid in row.get("process_ids", []):
            process_id = str(pid)
            score = float(node_scores.get(process_id, task_score))
            candidate = {
                "process_id": process_id,
                "score": score,
                "probability": task_prob,
                "is_suspicious_process": is_suspicious,
                "source_task_id": task_id,
                "_task_score": task_score,
            }
            existing = rows_by_process.get(process_id)
            if existing is None or float(candidate["score"]) > float(existing["score"]):
                rows_by_process[process_id] = candidate
    rows = list(rows_by_process.values())
    rows.sort(
        key=lambda item: (float(item["score"]), float(item["_task_score"]), item["process_id"]),
        reverse=True,
    )
    for row in rows:
        row.pop("_task_score", None)
    return rows


def _build_raised_alarm_rows(task_rows: List[dict]) -> list[dict]:
    rows: list[dict] = []
    for row in task_rows:
        if not bool(row.get("is_suspicious", False)):
            continue
        for pid in row.get("process_ids", []):
            rows.append(
                {
                    "node_uuid": str(pid),
                    "node_type": "process",
                    "Label": False,
                    "Model_prediction": True,
                    "Anomaly_score": float(row["task_score"]),
                    "Prediction_probability": float(row.get("task_probability", row["task_score"])),
                }
            )
    return rows


def _write_frame(path: Path, rows: list[dict], columns: list[str]) -> None:
    if rows:
        pd.DataFrame(rows).to_csv(path, index=False)
        return
    pd.DataFrame(columns=columns).to_csv(path, index=False)


def run_module2(
    cfg: FusionConfig,
    embeddings_path: Path,
    task_path: Path,
    segmentation_edges_path: Path | None = None,
) -> Dict[str, Path]:
    del task_path, segmentation_edges_path
    out_dir = cfg.module2_dir
    ensure_dir(out_dir)
    process_scores_path = out_dir / "process_scores.csv"
    suspicious_path = out_dir / "suspicious_tasks.json"
    threshold_summary_path = out_dir / "task_thresholds.json"
    raised_alarm_path = out_dir / "run_0_raised_alarms.csv"
    task_meta_rich_path = out_dir / "task_meta_rich.json"
    task_attribution_path = out_dir / "task_attribution.json"

    detector_out = run_tapas_module2(cfg=cfg, module1_dir=embeddings_path.parent, out_dir=out_dir)
    task_rows = detector_out["task_rows"]
    exported_tasks = _task_row_exports(task_rows)
    task_meta_rich_rows, attribution_by_task = _task_graph_sidecars(task_rows, embeddings_path.parent)
    process_rows = _build_process_score_rows(task_rows, attribution_by_task)
    raised_alarm_rows = _build_raised_alarm_rows(task_rows)

    _write_frame(
        process_scores_path,
        process_rows,
        columns=[
            "process_id",
            "score",
            "probability",
            "is_suspicious_process",
            "source_task_id",
        ],
    )
    save_json(suspicious_path, exported_tasks)
    save_json(task_meta_rich_path, task_meta_rich_rows)
    save_json(
        task_attribution_path,
        [attribution_by_task[key] for key in sorted(attribution_by_task.keys())],
    )
    save_json(
        threshold_summary_path,
        {
            "task_detection_backend": "tapas_native",
            "process_score_export": "task_attribution_priority",
            "task_attribution_export": "heuristic_graph_sidecar",
            "total_process_count": len(process_rows),
            "graph_edge_source": "tapas_parent_child_edges",
            "task_ground_truth_path": str(cfg.task_ground_truth_path) if cfg.task_ground_truth_path else "",
            "decision_threshold": float(detector_out["decision_threshold"]),
            "backend_artifacts": {name: str(path) for name, path in detector_out["paths"].items()},
            "backend_summary": detector_out["summary"],
        },
    )

    _write_frame(
        raised_alarm_path,
        raised_alarm_rows,
        columns=[
            "node_uuid",
            "node_type",
            "Label",
            "Model_prediction",
            "Anomaly_score",
            "Prediction_probability",
        ],
    )

    outputs = {
        "process_scores": process_scores_path,
        "suspicious_tasks": suspicious_path,
        "task_meta_rich": task_meta_rich_path,
        "task_attribution": task_attribution_path,
        "task_thresholds": threshold_summary_path,
        "raised_alarms": raised_alarm_path,
    }
    for name, path in detector_out["paths"].items():
        outputs[name] = path
    return outputs


def load_module2_output(suspicious_path: Path, process_scores_path: Path) -> Module2Output:
    suspicious_raw = json.loads(suspicious_path.read_text(encoding="utf-8"))
    process_df = pd.read_csv(process_scores_path)
    process_scores = {
        str(row["process_id"]): ProcessScore(
            process_id=str(row["process_id"]),
            score=float(row["score"]),
            probability=float(row["probability"]),
        )
        for _, row in process_df.iterrows()
    }
    suspicious_tasks = [
        TaskSubgraph(task_id=str(row["task_id"]), process_ids=[str(p) for p in row["process_ids"]])
        for row in suspicious_raw
        if bool(row.get("is_suspicious", False))
    ]
    threshold_candidates = []
    for row in suspicious_raw:
        if not row.get("is_suspicious"):
            continue
        raw_threshold = row.get("threshold_used", row.get("task_score", 0.0))
        if raw_threshold is None:
            continue
        threshold_candidates.append(float(raw_threshold))
    threshold = min(threshold_candidates, default=0.0)
    return Module2Output(
        suspicious_tasks=suspicious_tasks,
        process_scores=process_scores,
        threshold=threshold,
    )


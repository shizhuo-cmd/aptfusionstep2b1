from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.common import ensure_dir
from apt_fusion.config import load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.module3_evidence_recover import (
    _edge_rows_for_graph,
    _load_module1_native_bundle,
    _safe_l2,
    _task_root_leaf_ids,
    run_module3_evidence,
)
from apt_fusion.path_reason.module4_semantic_compact import run_module4_compact
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_plus240_baseline_20260628.yaml"
)
MODULE1_SOURCE_ROOT = (
    REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_plus240_step2j_cleanup_deleteonly_20260628"
)
TARGET_ROOT = (
    REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_plus240_step8a_objecthit_taskunion_20260630"
)
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
GT_TIME_OFFSET_MINUTES = 240
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"
ANALYSIS_SCRIPT = REPO_ROOT / "debug" / "remote_ops" / "analyze_path_reason_behavior_capture_20260624.py"
ANALYSIS_OUTPUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "cadets_behavior_capture_step8a_objecthit_taskunion_20260630"
OBJECT_HIT_WINDOW_IDS = [
    "CADETS_20180406_1121_1208_01",
    "CADETS_20180411_1508_1515_02",
]
OBJECT_HIT_MIN_EVENTS_PER_TASK = 100
OBJECT_HIT_MIN_DISTINCT_GT_OBJECTS = 5
OBJECT_HIT_MAX_TASK_SIZE = 5000


def _clean_dir(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()


def _symlink_dir(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists() or target.is_symlink():
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
    os.symlink(source, target, target_is_directory=True)


def _git_text(*args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip()


def _working_tree_fingerprint() -> dict[str, Any]:
    status_lines = [line for line in _git_text("status", "--short").splitlines() if line.strip()]
    return {
        "code_baseline": "local_working_tree_snapshot",
        "head_commit": _git_text("rev-parse", "HEAD"),
        "git_status_short": status_lines,
        "git_status_count": len(status_lines),
    }


def _save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _prepare_target_root() -> None:
    _clean_dir(TARGET_ROOT)
    TARGET_ROOT.mkdir(parents=True, exist_ok=True)
    _symlink_dir(MODULE1_SOURCE_ROOT / "module1", TARGET_ROOT / "module1")


def _load_object_hit_windows() -> list[tuple[str, float, float]]:
    strict_windows, _, _ = load_gt_reference(GT_JSON_PATH, host_filter="CADETS")
    apply_gt_time_offset(strict_windows, minutes=GT_TIME_OFFSET_MINUTES)
    out: list[tuple[str, float, float]] = []
    for item in strict_windows:
        window_id = str(getattr(item, "window_id", "")).strip()
        if window_id not in OBJECT_HIT_WINDOW_IDS:
            continue
        start_dt = getattr(item, "start_time", None)
        end_dt = getattr(item, "end_time", None)
        if not isinstance(start_dt, datetime) or not isinstance(end_dt, datetime):
            continue
        out.append(
            (
                window_id,
                start_dt.astimezone(timezone.utc).timestamp(),
                end_dt.astimezone(timezone.utc).timestamp(),
            )
        )
    return out


def _scan_object_hit_task_stats(cfg, task_id_to_processes: dict[str, list[str]]) -> dict[str, dict[str, Any]]:
    gt_ids = {
        line.strip().upper()
        for line in Path(cfg.task_ground_truth_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    process_to_tasks: dict[str, set[str]] = {}
    for task_id, process_ids in task_id_to_processes.items():
        for process_id in process_ids:
            process_to_tasks.setdefault(str(process_id).upper(), set()).add(task_id)

    windows = _load_object_hit_windows()
    stats: dict[str, dict[str, Any]] = {}
    for log_file in sorted(Path(cfg.source_logs).glob("*.json")):
        with log_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                if "com.bbn.tc.schema.avro.cdm18.Event" not in line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event = (payload.get("datum") or {}).get("com.bbn.tc.schema.avro.cdm18.Event")
                if not isinstance(event, dict):
                    continue
                nanos = event.get("timestampNanos")
                if nanos in (None, ""):
                    continue
                try:
                    event_ts = float(nanos) / 1_000_000_000.0
                except (TypeError, ValueError):
                    continue
                if not any(start_ts <= event_ts <= end_ts for _, start_ts, end_ts in windows):
                    continue
                subject_uuid = str((event.get("subject") or {}).get("com.bbn.tc.schema.avro.cdm18.UUID") or "").strip().upper()
                if not subject_uuid:
                    continue
                object_hits = [
                    oid
                    for oid in [
                        str((event.get("predicateObject") or {}).get("com.bbn.tc.schema.avro.cdm18.UUID") or "").strip().upper(),
                        str((event.get("predicateObject2") or {}).get("com.bbn.tc.schema.avro.cdm18.UUID") or "").strip().upper(),
                    ]
                    if oid and oid in gt_ids
                ]
                if not object_hits:
                    continue
                for task_id in process_to_tasks.get(subject_uuid, set()):
                    entry = stats.setdefault(
                        task_id,
                        {
                            "event_count": 0,
                            "gt_object_ids": set(),
                            "subject_ids": set(),
                        },
                    )
                    entry["event_count"] = int(entry.get("event_count", 0) or 0) + 1
                    entry["gt_object_ids"].update(object_hits)
                    entry["subject_ids"].add(subject_uuid)
    return stats


def _build_selection_sidecars(cfg) -> tuple[Path, Path, Path, dict[str, Any]]:
    bundle = _load_module1_native_bundle(cfg.module1_dir)
    graphs = list(bundle.get("selected_graphs", []))
    metas = list(bundle.get("selected_graph_metas", []))
    graph_rows = []
    task_id_to_processes: dict[str, list[str]] = {}
    meta_lookup: dict[str, dict[str, Any]] = {}
    for graph, meta in zip(graphs, metas):
        task_id = str(meta.get("task_id", "")).strip()
        if not task_id or task_id.endswith("_aug"):
            continue
        process_ids = [str(node) for node in meta.get("node_ids", [])]
        graph_rows.append((task_id, graph, meta, process_ids))
        task_id_to_processes[task_id] = process_ids
        meta_lookup[task_id] = meta

    object_hit_stats = _scan_object_hit_task_stats(cfg, task_id_to_processes)
    object_hit_selected: set[str] = set()
    for task_id, stats in object_hit_stats.items():
        meta = meta_lookup.get(task_id, {})
        task_size = int(meta.get("task_size", len(task_id_to_processes.get(task_id, []))) or 0)
        if int(stats.get("event_count", 0) or 0) < OBJECT_HIT_MIN_EVENTS_PER_TASK:
            continue
        if len(stats.get("gt_object_ids", set())) < OBJECT_HIT_MIN_DISTINCT_GT_OBJECTS:
            continue
        if task_size > OBJECT_HIT_MAX_TASK_SIZE:
            continue
        object_hit_selected.add(task_id)

    sidecar_dir = TARGET_ROOT / "module3_evidence" / "_module1_gt_objecthit_taskunion_sidecars"
    ensure_dir(sidecar_dir)
    suspicious_rows: list[dict[str, Any]] = []
    meta_rows: list[dict[str, Any]] = []
    attribution_rows: list[dict[str, Any]] = []
    base_positive_count = 0

    for task_id, graph, meta, process_ids in graph_rows:
        label = int(meta.get("label", graph.get("label", 0)) or 0)
        selected_by_base_gt = label == 1 and not task_id.endswith("_aug")
        selected_by_object_hit = task_id in object_hit_selected
        if not (selected_by_base_gt or selected_by_object_hit):
            continue
        if selected_by_base_gt:
            base_positive_count += 1

        local_edges = _edge_rows_for_graph(graph, process_ids)
        root_process_ids, leaf_process_ids, indegree, outdegree, neighbors = _task_root_leaf_ids(
            process_ids,
            local_edges,
        )
        degree = {pid: indegree.get(pid, 0) + outdegree.get(pid, 0) for pid in process_ids}
        bridge_degree = {pid: len(neighbors.get(pid, set())) for pid in process_ids}
        raw_nodes = list(graph.get("nodes", []) or [])
        feature_norms = {
            pid: _safe_l2(raw_nodes[index]) if index < len(raw_nodes) else 0.0
            for index, pid in enumerate(process_ids)
        }
        max_feature_norm = max(feature_norms.values(), default=0.0) or 1.0
        max_degree = max(degree.values(), default=0) or 1
        max_bridge = max(bridge_degree.values(), default=0) or 1
        node_scores: dict[str, float] = {}
        for pid in process_ids:
            root_bonus = 1.0 if pid in root_process_ids else 0.0
            node_scores[pid] = (
                0.45 * (feature_norms.get(pid, 0.0) / max_feature_norm)
                + 0.25 * (float(degree.get(pid, 0)) / float(max_degree))
                + 0.15 * (float(bridge_degree.get(pid, 0)) / float(max_bridge))
                + 0.15 * root_bonus
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
        task_root_id = str(meta.get("task_root_id", "")).strip() or (root_process_ids[0] if root_process_ids else "")
        graph_density = 0.0
        if len(process_ids) > 1:
            graph_density = float(len(local_edges)) / float(len(process_ids) * (len(process_ids) - 1))

        object_stats = object_hit_stats.get(task_id, {})
        object_hit_event_count = int(object_stats.get("event_count", 0) or 0)
        object_hit_gt_ids = sorted(object_stats.get("gt_object_ids", set()))
        selection_sources = []
        if selected_by_base_gt:
            selection_sources.append("module1_ground_truth_positive_base")
        if selected_by_object_hit:
            selection_sources.append("cadets_window_gt_object_hit")
        suspicious_rows.append(
            {
                "task_id": task_id,
                "task_score": 1.0,
                "task_probability": 1.0,
                "graphsage_probability": 1.0,
                "stats_probability": None,
                "task_label": 1 if selected_by_base_gt else 0,
                "predicted_label": 1,
                "prediction_mode": "ground_truth_plus_object_hit_union",
                "task_size": int(meta.get("task_size", len(process_ids))),
                "internal_edge_count": int(meta.get("internal_edge_count", len(local_edges))),
                "graph_edge_source": "tapas_parent_child_edges",
                "task_score_basis": "module1_ground_truth_plus_cadets_object_hit_union",
                "fusion_weight_stats": 0.0,
                "threshold_used": None,
                "is_suspicious": True,
                "process_ids": process_ids,
                "selection_sources": selection_sources,
                "object_hit_event_count": object_hit_event_count,
                "object_hit_distinct_gt_object_count": len(object_hit_gt_ids),
                "object_hit_gt_object_ids": object_hit_gt_ids,
            }
        )
        meta_rows.append(
            {
                "task_id": task_id,
                "task_score": 1.0,
                "task_probability": 1.0,
                "graphsage_probability": 1.0,
                "stats_probability": None,
                "task_size": int(meta.get("task_size", len(process_ids))),
                "internal_edge_count": int(meta.get("internal_edge_count", len(local_edges))),
                "graph_task_id": task_id,
                "task_root_id": task_root_id,
                "boundary_node_ids": [str(item) for item in meta.get("boundary_node_ids", [])],
                "process_ids": process_ids,
                "root_process_ids": root_process_ids,
                "leaf_process_ids": leaf_process_ids,
                "local_edges": local_edges,
                "graph_density": graph_density,
                "prediction_mode": "ground_truth_plus_object_hit_union",
                "is_suspicious": True,
                "selection_sources": selection_sources,
                "object_hit_event_count": object_hit_event_count,
                "object_hit_distinct_gt_object_count": len(object_hit_gt_ids),
                "object_hit_gt_object_ids": object_hit_gt_ids,
            }
        )
        attribution_rows.append(
            {
                "task_id": task_id,
                "graph_task_id": task_id,
                "top_processes": top_processes[: min(12, len(top_processes))],
                "top_edges": top_edges[: min(12, len(top_edges))],
                "root_process_ids": root_process_ids,
                "leaf_process_ids": leaf_process_ids,
                "graph_density": graph_density,
                "selection_sources": selection_sources,
                "object_hit_event_count": object_hit_event_count,
                "object_hit_distinct_gt_object_count": len(object_hit_gt_ids),
            }
        )

    suspicious_path = sidecar_dir / "suspicious_tasks.json"
    task_meta_rich_path = sidecar_dir / "task_meta_rich.json"
    task_attribution_path = sidecar_dir / "task_attribution.json"
    summary_path = sidecar_dir / "summary.json"
    _save_json(suspicious_path, suspicious_rows)
    _save_json(task_meta_rich_path, meta_rows)
    _save_json(task_attribution_path, attribution_rows)
    sidecar_summary = {
        "selection_mode": "module1_gt_positive_plus_cadets_object_hit_union",
        "task_count": len(suspicious_rows),
        "base_positive_task_count": base_positive_count,
        "object_hit_selected_task_count": len(object_hit_selected),
        "object_hit_selected_task_ids": sorted(object_hit_selected),
        "object_hit_thresholds": {
            "min_events_per_task": OBJECT_HIT_MIN_EVENTS_PER_TASK,
            "min_distinct_gt_objects": OBJECT_HIT_MIN_DISTINCT_GT_OBJECTS,
            "max_task_size": OBJECT_HIT_MAX_TASK_SIZE,
        },
        "module1_dir": str(cfg.module1_dir),
        "source_logs": str(cfg.source_logs),
        "task_ground_truth_path": str(cfg.task_ground_truth_path),
    }
    _save_json(summary_path, sidecar_summary)
    return suspicious_path, task_meta_rich_path, task_attribution_path, sidecar_summary


def _evaluate(cfg) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, _ = load_gt_reference(GT_JSON_PATH, host_filter=cfg.host.upper())
    apply_gt_time_offset(strict_windows, minutes=GT_TIME_OFFSET_MINUTES)
    output_dir = cfg.artifacts_dir / EVAL_DIR_NAME
    outputs = run_evaluation(
        artifacts_dir=cfg.artifacts_dir,
        strict_windows=strict_windows,
        technique_defs=technique_defs,
        output_dir=output_dir,
        host=cfg.host.upper(),
        match_top_n=5,
        pad_minutes=5,
        near_miss_minutes=5,
    )
    metrics = json.loads(Path(outputs["metrics_summary"]).read_text(encoding="utf-8"))
    return metrics, outputs


def _run_behavior_capture_analysis() -> None:
    _clean_dir(ANALYSIS_OUTPUT_DIR)
    ANALYSIS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            str(ANALYSIS_SCRIPT),
            "--artifacts-dir",
            str(TARGET_ROOT),
            "--gt-json-path",
            str(GT_JSON_PATH),
            "--host",
            "CADETS",
            "--gt-time-offset-minutes",
            str(GT_TIME_OFFSET_MINUTES),
            "--output-dir",
            str(ANALYSIS_OUTPUT_DIR),
        ],
        check=True,
    )


def main() -> None:
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir = TARGET_ROOT
    _prepare_target_root()

    suspicious_tasks_path, task_meta_rich_path, task_attribution_path, sidecar_summary = _build_selection_sidecars(cfg)

    for folder in [cfg.module3_evidence_dir, cfg.module4_compact_dir, cfg.module5_paths_dir, cfg.module6_reason_dir, cfg.artifacts_dir / EVAL_DIR_NAME]:
        _clean_dir(folder)
    _symlink_dir(MODULE1_SOURCE_ROOT / "module1", cfg.module1_dir)

    module3_outputs = run_module3_evidence(
        cfg,
        suspicious_tasks_path=suspicious_tasks_path,
        task_meta_rich_path=task_meta_rich_path,
        task_attribution_path=task_attribution_path,
    )
    module4_outputs = run_module4_compact(cfg)
    module5_outputs = run_module5_paths(cfg)
    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)
    _run_behavior_capture_analysis()

    provenance = {
        "experiment_step": "step8a_objecthit_taskunion_20260630",
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "config_template_path": str(CONFIG_PATH),
        "artifacts_dir": str(cfg.artifacts_dir),
        "gt_json_path": str(GT_JSON_PATH),
        "gt_time_offset_minutes_applied": GT_TIME_OFFSET_MINUTES,
        "rerun_modules": ["module3_evidence", "module4_compact", "module5_paths", "module6_reason", "path_reason_eval"],
        "analysis_script": str(ANALYSIS_SCRIPT),
        "analysis_output_dir": str(ANALYSIS_OUTPUT_DIR),
        "module1_source_root": str(MODULE1_SOURCE_ROOT),
        "module3_selection_summary": sidecar_summary,
        "module3_outputs": {key: str(value) for key, value in module3_outputs.items()},
        "module4_outputs": {key: str(value) for key, value in module4_outputs.items()},
        "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "metrics": metrics,
    }
    _save_json(cfg.artifacts_dir / "provenance_summary.json", provenance)
    _save_json(cfg.artifacts_dir / "working_tree_fingerprint.json", _working_tree_fingerprint())
    print(json.dumps(provenance, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

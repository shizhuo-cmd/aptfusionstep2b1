from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

_THIS_FILE = Path(__file__).resolve()
REPO_ROOT = _THIS_FILE.parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apt_fusion.config import FusionConfig, load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.module3_evidence_recover import run_module3_evidence
from apt_fusion.path_reason.module4_semantic_compact import run_module4_compact
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason
from apt_fusion.task_detection.module1_online_graph import run_module1
from apt_fusion.task_detection.module2_online_detection import run_module2

TRACE_CONFIG = REPO_ROOT / "configs" / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_ablation_predpos_base_20260706.yaml"
CADETS_CONFIG = REPO_ROOT / "configs" / "fusion_cloud_cadets_train_stats_latefusion_llama31_ablation_predpos_base_20260706.yaml"
TRACE_LOGS_DIR = Path("/root/autodl-tmp/data/trace_train/logs")
TRACE_ARCHIVE_PATH = Path("/root/autodl-tmp/data/trace_train/logs_archive_20260609.tar.gz")
CADETS_DIR = Path("/root/autodl-tmp/data/cadets")
CADETS_LOGS_DIR = CADETS_DIR / "logs"
CADETS_LOGS_RAR = CADETS_DIR / "logs.rar"
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
OUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "tc3_ablation_matrix_20260706"
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"
DATE_TAG = "20260706"


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
        "code_baseline": "local_working_tree_snapshot_sync_20260706",
        "head_commit": _git_text("rev-parse", "HEAD"),
        "git_status_short": status_lines,
        "git_status_count": len(status_lines),
    }


def _ensure_trace_logs_ready() -> dict[str, Any]:
    existed = TRACE_LOGS_DIR.exists() and any(TRACE_LOGS_DIR.iterdir())
    extracted = False
    if not existed:
        if not TRACE_ARCHIVE_PATH.exists():
            raise FileNotFoundError(f"trace archive not found: {TRACE_ARCHIVE_PATH}")
        TRACE_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with tarfile.open(TRACE_ARCHIVE_PATH, "r:gz") as tar:
            tar.extractall(path=TRACE_LOGS_DIR.parent)
        extracted = True
    ready = TRACE_LOGS_DIR.exists() and any(TRACE_LOGS_DIR.iterdir())
    if not ready:
        raise RuntimeError(f"trace logs dir is empty: {TRACE_LOGS_DIR}")
    return {
        "trace_logs_dir": str(TRACE_LOGS_DIR),
        "trace_logs_preexisting": existed,
        "trace_logs_extracted_this_run": extracted,
    }


def _ensure_cadets_logs_ready() -> dict[str, Any]:
    existed = CADETS_LOGS_DIR.exists() and any(CADETS_LOGS_DIR.iterdir())
    extracted = False
    extract_tool = ""
    if not existed:
        if not CADETS_LOGS_RAR.exists():
            raise FileNotFoundError(f"cadets archive not found: {CADETS_LOGS_RAR}")
        for cmd in (["unrar", "x", "-o+", str(CADETS_LOGS_RAR), str(CADETS_DIR)], ["7z", "x", "-y", str(CADETS_LOGS_RAR), f"-o{CADETS_DIR}"]):
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                extracted = True
                extract_tool = cmd[0]
                break
        if not extracted:
            raise RuntimeError("failed to extract cadets logs with unrar/7z")
    ready = CADETS_LOGS_DIR.exists() and any(CADETS_LOGS_DIR.iterdir())
    if not ready:
        raise RuntimeError(f"cadets logs dir is empty: {CADETS_LOGS_DIR}")
    return {
        "cadets_logs_dir": str(CADETS_LOGS_DIR),
        "cadets_logs_preexisting": existed,
        "cadets_logs_extracted_this_run": extracted,
        "cadets_extract_tool": extract_tool,
    }


def _ensure_logs_for_host(host: str) -> dict[str, Any]:
    text = str(host).strip().lower()
    if text == "trace":
        return _ensure_trace_logs_ready()
    if text == "cadets":
        return _ensure_cadets_logs_ready()
    return {}


def _set_cfg_paths(cfg: FusionConfig, artifact_name: str) -> None:
    cfg.artifacts_dir = REPO_ROOT / artifact_name
    cfg.ocr_runtime_root = REPO_ROOT / "runtime" / "darpa_tc3" / artifact_name / "experiments"
    cfg.task_detector_model_output = cfg.module2_dir / "tapas_native_model.pt"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def _snapshot_module2_fit_predict(cfg: FusionConfig) -> Path:
    snapshot_dir = cfg.artifacts_dir / "module2_fit_predict_snapshot"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    for name in [
        "task_scores.csv",
        "task_subgraph_summary.json",
        "suspicious_tasks.json",
        "task_meta_rich.json",
        "task_attribution.json",
        "process_scores.csv",
        "tapas_native_model.pt",
        "tapas_native_model.graph_stats.joblib",
    ]:
        src = cfg.module2_dir / name
        if src.exists():
            _copy_file(src, snapshot_dir / name)
    return snapshot_dir


def _load_module1_summary(cfg: FusionConfig) -> dict[str, Any]:
    for name in ["tapas_native_module1_summary.json", "module1_summary.json", "summary.json"]:
        path = cfg.module1_dir / name
        if path.exists():
            return _load_json(path)
    return {}


def _load_module2_summary(path: Path) -> dict[str, Any]:
    summary_path = path / "task_subgraph_summary.json"
    return _load_json(summary_path) if summary_path.exists() else {}


def _load_module5_summary(cfg: FusionConfig) -> dict[str, Any]:
    path = cfg.module5_paths_dir / "summary.json"
    return _load_json(path) if path.exists() else {}


def _selected_positive_task_ids(suspicious_path: Path) -> list[str]:
    if not suspicious_path.exists():
        return []
    rows = json.loads(suspicious_path.read_text(encoding="utf-8"))
    return sorted(
        str(row.get("task_id", "")).strip()
        for row in rows
        if str(row.get("task_id", "")).strip() and bool(row.get("is_suspicious", False))
    )


def _load_existing_summary(artifact_root: Path) -> dict[str, Any] | None:
    summary_path = artifact_root / "ablation_summary.json"
    if summary_path.exists():
        return _load_json(summary_path)
    return None


def _copy_module1_outputs(src_artifact_root: Path, dst_module1_dir: Path) -> dict[str, Path]:
    src_module1 = src_artifact_root / "module1"
    if not src_module1.exists():
        raise FileNotFoundError(f"baseline module1 dir not found: {src_module1}")
    _copy_tree(src_module1, dst_module1_dir)
    return {
        "process_embeddings": dst_module1_dir / "process_embeddings.csv",
        "task_subgraphs": dst_module1_dir / "task_subgraphs.json",
        "process_segmentation_edges": dst_module1_dir / "process_segmentation_edges.csv",
    }


def _evaluate(cfg: FusionConfig) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, _ = load_gt_reference(GT_JSON_PATH, host_filter=cfg.host.upper())
    apply_gt_time_offset(strict_windows, minutes=int(cfg.path_reason_gt_time_offset_minutes))
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
    return _load_json(Path(outputs["metrics_summary"])), outputs


def _prune_heavy_outputs(cfg: FusionConfig) -> None:
    heavy_paths = [
        cfg.module1_dir / "tapas_native_workspace",
        cfg.module1_dir / "process_embeddings.csv",
        cfg.module3_evidence_dir,
        cfg.module4_compact_dir,
        cfg.module5_paths_dir / "candidate_paths",
        cfg.module5_paths_dir / "bridge_edges",
        cfg.module6_reason_dir / "llm_inputs",
        cfg.module6_reason_dir / "dossiers",
        cfg.module6_reason_dir / "markdown",
        cfg.module6_reason_dir / "claim_graphs",
    ]
    for path in heavy_paths:
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            path.unlink(missing_ok=True)


def _should_run_full_downstream(item_id: str) -> bool:
    return str(item_id).strip() == "1.3"


def _run_one_experiment(
    *,
    base_config_path: Path,
    artifact_name: str,
    item_id: str,
    experiment_name: str,
    description: str,
    overrides: dict[str, Any],
    log_state: dict[str, Any],
    fingerprint: dict[str, Any],
    baseline_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = load_config(base_config_path)
    _set_cfg_paths(cfg, artifact_name)
    for key, value in overrides.items():
        setattr(cfg, key, value)
    if cfg.artifacts_dir.exists():
        shutil.rmtree(cfg.artifacts_dir)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)

    if baseline_summary and str(item_id).strip() in {"1.1", "1.2"}:
        baseline_root = Path(str(baseline_summary["artifact_root"]))
        module1_outputs = _copy_module1_outputs(baseline_root, cfg.module1_dir)
    else:
        module1_outputs = run_module1(cfg)
    fit_outputs = run_module2(
        cfg=cfg,
        embeddings_path=module1_outputs["process_embeddings"],
        task_path=module1_outputs["task_subgraphs"],
        segmentation_edges_path=module1_outputs["process_segmentation_edges"],
    )
    fit_snapshot = _snapshot_module2_fit_predict(cfg)
    fit_summary = _load_module2_summary(fit_snapshot)

    cfg_load = copy.deepcopy(cfg)
    cfg_load.task_detector_mode = "load_and_predict"
    cfg_load.task_detector_model_input = cfg.module2_dir / "tapas_native_model.pt"
    run_module2(
        cfg=cfg_load,
        embeddings_path=module1_outputs["process_embeddings"],
        task_path=module1_outputs["task_subgraphs"],
        segmentation_edges_path=module1_outputs["process_segmentation_edges"],
    )

    module1_summary = _load_module1_summary(cfg_load)
    module2_full_summary = _load_module2_summary(cfg_load.module2_dir)
    selected_task_ids = _selected_positive_task_ids(cfg_load.module2_dir / "suspicious_tasks.json")
    baseline_selected_task_ids = []
    if baseline_summary is not None:
        baseline_selected_task_ids = _selected_positive_task_ids(
            Path(str(baseline_summary["artifact_root"])) / "module2" / "suspicious_tasks.json"
        )

    downstream_reused = False
    downstream_reuse_reason = ""
    if (
        baseline_summary is not None
        and str(item_id).strip() in {"1.1", "1.2"}
        and selected_task_ids == baseline_selected_task_ids
    ):
        downstream_reused = True
        downstream_reuse_reason = "selected_positive_task_ids_identical_to_baseline"
        module5_summary = copy.deepcopy(baseline_summary.get("module5_summary", {}))
        eval_metrics = copy.deepcopy(baseline_summary.get("path_reason_eval_metrics", {}))
        eval_outputs = copy.deepcopy(baseline_summary.get("eval_outputs", {}))
    else:
        if _should_run_full_downstream(item_id) or str(item_id).strip() in {"1.1", "1.2"}:
            run_module3_evidence(
                cfg_load,
                suspicious_tasks_path=cfg_load.module2_dir / "suspicious_tasks.json",
                task_meta_rich_path=cfg_load.module2_dir / "task_meta_rich.json",
                task_attribution_path=cfg_load.module2_dir / "task_attribution.json",
            )
            run_module4_compact(cfg_load)
            run_module5_paths(cfg_load)
            run_module6_reason(cfg_load)
            eval_metrics, eval_outputs = _evaluate(cfg_load)
            module5_summary = _load_module5_summary(cfg_load)
        else:
            module5_summary = {}
            eval_metrics = {}
            eval_outputs = {}
    summary = {
        "item_id": item_id,
        "experiment_name": experiment_name,
        "description": description,
        "artifact_root": str(cfg_load.artifacts_dir),
        "overrides": copy.deepcopy(overrides),
        "module1_summary": module1_summary,
        "module2_fit_predict_summary": fit_summary,
        "module2_loadpredict_summary": module2_full_summary,
        "selected_positive_task_ids": selected_task_ids,
        "baseline_selected_positive_task_ids": baseline_selected_task_ids,
        "downstream_reused_from_baseline": downstream_reused,
        "downstream_reuse_reason": downstream_reuse_reason,
        "module5_summary": module5_summary,
        "path_reason_eval_metrics": eval_metrics,
        "log_state": copy.deepcopy(log_state),
        "working_tree_fingerprint": copy.deepcopy(fingerprint),
        "eval_outputs": eval_outputs,
    }
    summary_path = cfg_load.artifacts_dir / "ablation_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    provenance = {
        "item_id": item_id,
        "experiment_name": experiment_name,
        "description": description,
        "base_config_path": str(base_config_path),
        "gt_json_path": str(GT_JSON_PATH),
        "rerun_flow": [
            "module1",
            "module2_fit_predict",
            "module2_load_and_predict_all_tasks",
            "module3_evidence(predicted_positive)_conditional",
            "module4_compact_conditional",
            "module5_paths_conditional",
            "module6_reason_conditional",
            "path_reason_eval_conditional",
        ],
        "task_tapas_augmentation_before_split": bool(cfg_load.task_tapas_augmentation_before_split),
        "task_graph_stat_late_fusion_enabled": bool(cfg_load.task_graph_stat_late_fusion_enabled),
        "task_graph_stat_fusion_weight": float(cfg_load.task_graph_stat_fusion_weight),
        "use_sequence_embeddings": bool(cfg_load.use_sequence_embeddings),
        "use_ocr_stat_features": bool(cfg_load.use_ocr_stat_features),
        "graphsage_append_ocr_stat_features": bool(cfg_load.graphsage_append_ocr_stat_features),
        "task_component_split_mode": str(cfg_load.task_component_split_mode),
        "task_component_child_threshold": int(cfg_load.task_component_child_threshold),
        "task_component_count_segmented_children_upstream": bool(cfg_load.task_component_count_segmented_children_upstream),
        "path_reason_gt_time_offset_minutes": int(cfg_load.path_reason_gt_time_offset_minutes),
        "fit_snapshot_dir": str(fit_snapshot),
        "summary_path": str(summary_path),
        "selected_positive_task_ids": selected_task_ids,
        "baseline_selected_positive_task_ids": baseline_selected_task_ids,
        "downstream_reused_from_baseline": downstream_reused,
        "downstream_reuse_reason": downstream_reuse_reason,
    }
    (cfg_load.artifacts_dir / "provenance_summary.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    _prune_heavy_outputs(cfg_load)
    return summary


def _mark_failed(root: Path) -> Path:
    failed_root = root.with_name(f"{root.name}_failed_")
    if failed_root.exists():
        shutil.rmtree(failed_root, ignore_errors=True)
    if root.exists():
        root.rename(failed_root)
    return failed_root


def _artifact_name(host: str, tag: str) -> str:
    return f"artifacts_{host.lower()}_train_stats_latefusion_llama31_ablation_{tag}_{DATE_TAG}"


EXPERIMENTS: list[dict[str, Any]] = [
    {
        "item_id": "1.1",
        "tag": "baseline_current",
        "name": "late_fusion_on_current",
        "description": "Current scheme: sequence embeddings + graph-stat late fusion, fanout>2 exclude segmented, augment-before-split.",
        "overrides": {},
    },
    {
        "item_id": "1.1",
        "tag": "latefusion_off",
        "name": "late_fusion_off",
        "description": "Disable graph-stat late fusion while keeping sequence backbone and downstream unchanged.",
        "overrides": {
            "task_graph_stat_late_fusion_enabled": False,
        },
    },
    {
        "item_id": "1.2",
        "tag": "early_concat",
        "name": "early_concat_no_latefusion",
        "description": "Append OCR/stat features into GraphSAGE node input, disable late fusion.",
        "overrides": {
            "task_graph_stat_late_fusion_enabled": False,
            "graphsage_append_ocr_stat_features": True,
        },
    },
    {
        "item_id": "1.2",
        "tag": "seq_only",
        "name": "sequence_only",
        "description": "Use sequence embeddings only; disable OCR/stat features and late fusion.",
        "overrides": {
            "task_graph_stat_late_fusion_enabled": False,
            "use_ocr_stat_features": False,
            "graphsage_append_ocr_stat_features": False,
        },
    },
    {
        "item_id": "1.3",
        "tag": "fanout_gt2_include",
        "name": "fanout_threshold2_include_segmented",
        "description": "Fanout split with threshold 2, segmented children still count upstream.",
        "overrides": {
            "task_component_split_mode": "fanout",
            "task_component_child_threshold": 2,
            "task_component_count_segmented_children_upstream": True,
        },
    },
    {
        "item_id": "1.3",
        "tag": "fanout_gt3_exclude",
        "name": "fanout_threshold3_exclude_segmented",
        "description": "Fanout split with threshold 3, segmented children excluded upstream.",
        "overrides": {
            "task_component_split_mode": "fanout",
            "task_component_child_threshold": 3,
            "task_component_count_segmented_children_upstream": False,
        },
    },
    {
        "item_id": "1.3",
        "tag": "fanout_gt3_include",
        "name": "fanout_threshold3_include_segmented",
        "description": "Fanout split with threshold 3, segmented children still count upstream.",
        "overrides": {
            "task_component_split_mode": "fanout",
            "task_component_child_threshold": 3,
            "task_component_count_segmented_children_upstream": True,
        },
    },
    {
        "item_id": "1.3",
        "tag": "connected",
        "name": "connected_components",
        "description": "Connected split baseline with the same detector/downstream settings.",
        "overrides": {
            "task_component_split_mode": "connected",
        },
    },
]


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fingerprint = _working_tree_fingerprint()
    trace_log_state = _ensure_logs_for_host("trace")
    cadets_log_state = _ensure_logs_for_host("cadets")
    all_results: dict[str, list[dict[str, Any]]] = {"trace": [], "cadets": []}

    dataset_specs = [
        ("trace", TRACE_CONFIG, trace_log_state),
        ("cadets", CADETS_CONFIG, cadets_log_state),
    ]
    for host, config_path, log_state in dataset_specs:
        baseline_summary: dict[str, Any] | None = None
        for exp in EXPERIMENTS:
            artifact_name = _artifact_name(host, exp["tag"])
            root = REPO_ROOT / artifact_name
            if exp["tag"] == "baseline_current":
                existing = _load_existing_summary(root)
                if existing is not None:
                    baseline_summary = existing
                    all_results[host].append(existing)
                    (OUT_DIR / f"{host}_{exp['tag']}.json").write_text(
                        json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8"
                    )
                    continue
            try:
                result = _run_one_experiment(
                    base_config_path=config_path,
                    artifact_name=artifact_name,
                    item_id=str(exp["item_id"]),
                    experiment_name=str(exp["name"]),
                    description=str(exp["description"]),
                    overrides=copy.deepcopy(exp["overrides"]),
                    log_state=log_state,
                    fingerprint=fingerprint,
                    baseline_summary=baseline_summary,
                )
                all_results[host].append(result)
                (OUT_DIR / f"{host}_{exp['tag']}.json").write_text(
                    json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                if exp["tag"] == "baseline_current":
                    baseline_summary = result
            except Exception as exc:
                failed_root = _mark_failed(root)
                failure = {
                    "host": host,
                    "item_id": exp["item_id"],
                    "experiment_name": exp["name"],
                    "description": exp["description"],
                    "artifact_root_failed": str(failed_root),
                    "error": repr(exc),
                }
                all_results[host].append({"failed": failure})
                (OUT_DIR / f"{host}_{exp['tag']}_failed.json").write_text(
                    json.dumps(failure, ensure_ascii=False, indent=2), encoding="utf-8"
                )

    matrix_summary = {
        "gt_json_path": str(GT_JSON_PATH),
        "working_tree_fingerprint": fingerprint,
        "experiments": EXPERIMENTS,
        "results": all_results,
    }
    (OUT_DIR / "matrix_summary.json").write_text(
        json.dumps(matrix_summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(matrix_summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

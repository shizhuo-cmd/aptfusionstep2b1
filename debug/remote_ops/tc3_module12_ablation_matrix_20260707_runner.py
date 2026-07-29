from __future__ import annotations

import copy
import json
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

from apt_fusion.config import FusionConfig, load_config
from apt_fusion.task_detection.module1_online_graph import run_module1
from apt_fusion.task_detection.module2_online_detection import run_module2

TRACE_CONFIG = REPO_ROOT / "configs" / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_module12_ablation_base_20260707.yaml"
CADETS_CONFIG = REPO_ROOT / "configs" / "fusion_cloud_cadets_train_stats_latefusion_llama31_module12_ablation_base_20260707.yaml"
TRACE_LOGS_DIR = Path("/root/autodl-tmp/data/trace_train/logs")
TRACE_ARCHIVE_PATH = Path("/root/autodl-tmp/data/trace_train/logs_archive_20260609.tar.gz")
CADETS_DIR = Path("/root/autodl-tmp/data/cadets")
CADETS_LOGS_DIR = CADETS_DIR / "logs"
CADETS_LOGS_RAR = CADETS_DIR / "logs.rar"
OUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "tc3_module12_ablation_matrix_20260707"
DATE_TAG = "20260707"


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
        "code_baseline": "local_working_tree_snapshot_sync_20260707",
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
        for cmd in (
            ["unrar", "x", "-o+", str(CADETS_LOGS_RAR), str(CADETS_DIR)],
            ["7z", "x", "-y", str(CADETS_LOGS_RAR), f"-o{CADETS_DIR}"],
        ):
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
            dst = snapshot_dir / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
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


def _selected_positive_task_ids(suspicious_path: Path) -> list[str]:
    if not suspicious_path.exists():
        return []
    rows = json.loads(suspicious_path.read_text(encoding="utf-8"))
    return sorted(
        str(row.get("task_id", "")).strip()
        for row in rows
        if str(row.get("task_id", "")).strip() and bool(row.get("is_suspicious", False))
    )


def _prune_heavy_outputs(cfg: FusionConfig) -> None:
    heavy_paths = [
        cfg.module1_dir / "tapas_native_workspace",
        cfg.module1_dir / "process_embeddings.csv",
        cfg.module1_dir / "task_subgraphs.json",
        cfg.module1_dir / "process_segmentation_edges.csv",
    ]
    for path in heavy_paths:
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            path.unlink(missing_ok=True)


def _mark_failed(root: Path) -> Path:
    failed_root = root.with_name(f"{root.name}_failed_")
    if failed_root.exists():
        shutil.rmtree(failed_root, ignore_errors=True)
    if root.exists():
        root.rename(failed_root)
    return failed_root


def _artifact_name(host: str, tag: str) -> str:
    return f"artifacts_{host.lower()}_train_stats_latefusion_llama31_module12_ablation_{tag}_{DATE_TAG}"


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
) -> dict[str, Any]:
    cfg = load_config(base_config_path)
    _set_cfg_paths(cfg, artifact_name)
    for key, value in overrides.items():
        setattr(cfg, key, value)
    if cfg.artifacts_dir.exists():
        shutil.rmtree(cfg.artifacts_dir)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)

    module1_outputs = run_module1(cfg)
    run_module2(
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
        "log_state": copy.deepcopy(log_state),
        "working_tree_fingerprint": copy.deepcopy(fingerprint),
    }
    summary_path = cfg_load.artifacts_dir / "ablation_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    provenance = {
        "item_id": item_id,
        "experiment_name": experiment_name,
        "description": description,
        "base_config_path": str(base_config_path),
        "rerun_flow": [
            "module1",
            "module2_fit_predict",
            "module2_load_and_predict_all_tasks",
        ],
        "task_tapas_augmentation_before_split": bool(cfg_load.task_tapas_augmentation_before_split),
        "task_tapas_augmentation_divisor": int(cfg_load.task_tapas_augmentation_divisor),
        "task_tapas_trace_augmentation_bonus": int(getattr(cfg_load, "task_tapas_trace_augmentation_bonus", 0)),
        "task_graph_stat_late_fusion_enabled": bool(cfg_load.task_graph_stat_late_fusion_enabled),
        "task_graph_stat_fusion_weight": float(cfg_load.task_graph_stat_fusion_weight),
        "use_sequence_embeddings": bool(cfg_load.use_sequence_embeddings),
        "use_ocr_stat_features": bool(cfg_load.use_ocr_stat_features),
        "graphsage_append_ocr_stat_features": bool(cfg_load.graphsage_append_ocr_stat_features),
        "task_component_split_mode": str(cfg_load.task_component_split_mode),
        "task_component_child_threshold": int(cfg_load.task_component_child_threshold),
        "task_component_count_segmented_children_upstream": bool(cfg_load.task_component_count_segmented_children_upstream),
        "fit_snapshot_dir": str(fit_snapshot),
        "summary_path": str(summary_path),
        "selected_positive_task_ids": selected_task_ids,
    }
    (cfg_load.artifacts_dir / "provenance_summary.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    _prune_heavy_outputs(cfg_load)
    return summary


EXPERIMENTS: list[dict[str, Any]] = [
    {
        "item_id": "1.1",
        "tag": "baseline_current",
        "name": "late_fusion_on_current",
        "description": "Current scheme: sequence embeddings + graph-stat late fusion (1:1), fanout>2 exclude segmented, augment-before-split with count//1000.",
        "overrides": {},
    },
    {
        "item_id": "1.1",
        "tag": "latefusion_off",
        "name": "late_fusion_off",
        "description": "Disable graph-stat late fusion while keeping sequence backbone unchanged.",
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
        "description": "Connected split baseline with the same detector settings.",
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
        for exp in EXPERIMENTS:
            artifact_name = _artifact_name(host, exp["tag"])
            root = REPO_ROOT / artifact_name
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
                )
                all_results[host].append(result)
                (OUT_DIR / f"{host}_{exp['tag']}.json").write_text(
                    json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
                )
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
        "experiments": EXPERIMENTS,
        "results": all_results,
        "working_tree_fingerprint": fingerprint,
    }
    (OUT_DIR / "matrix_summary.json").write_text(
        json.dumps(matrix_summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(matrix_summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

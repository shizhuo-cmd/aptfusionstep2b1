
from __future__ import annotations

import contextlib
import copy
import csv
import ast
import importlib.util
import math
import os
import pickle
import random
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Sequence

import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import StratifiedKFold, StratifiedShuffleSplit
from sklearn.cluster import MiniBatchKMeans
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from torch_geometric.loader import DataLoader

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover - optional dependency
    XGBClassifier = None

from ..common import ensure_dir, ensure_parent, save_json
from ..config import FusionConfig
from .ocr_stat_features import (
    extract_process_stat_features,
    extract_process_stat_features_from_tc3_action_counts,
    extract_process_stat_features_from_tc3_event_count,
)
from .semantic_sequence import fit_benign_semantic_sequence_encoder
from .normal_only_gnn import run_normal_only_gin_autoencoder
from .provgrp_paper_partition import apply_provgrp_paper_partition_to_edge_list

_WORKSPACE_DIRNAME = "tapas_native_workspace"
_NATIVE_GRAPH_FILENAME = "tapas_native_graphs.pt"
_MODULE1_SUMMARY_FILENAME = "tapas_native_module1_summary.json"
_MODULE1_TASK_COMPONENT_DIAGNOSTICS_FILENAME = "task_component_diagnostics.json"
_TASK_SCORE_FILENAME = "task_scores.csv"
_TASK_SUMMARY_FILENAME = "task_subgraph_summary.json"
_MODEL_FILENAME = "tapas_native_model.pkl"
_DEFAULT_FEATURE_DIM = 42
_OFFICIAL_OPTC_HOSTS = ["0201", "0051", "0501"]
_GRAPH_STAT_FALLBACK_MODEL_NAME = "hist_gradient_boosting"
_GRAPH_STAT_XGBOOST_MODEL_NAME = "xgboost"


def _graph_stat_model_name(stats_model: Any | None) -> str:
    if stats_model is None:
        return ""
    if XGBClassifier is not None and isinstance(stats_model, XGBClassifier):
        return _GRAPH_STAT_XGBOOST_MODEL_NAME
    if isinstance(stats_model, HistGradientBoostingClassifier):
        return _GRAPH_STAT_FALLBACK_MODEL_NAME
    return type(stats_model).__name__


def _build_graph_stat_sidecar_model(cfg: FusionConfig, labels: np.ndarray) -> tuple[Any, np.ndarray, str]:
    sample_weight = compute_sample_weight(class_weight="balanced", y=labels)
    if XGBClassifier is not None:
        model = XGBClassifier(
            objective="binary:logistic",
            eval_metric="logloss",
            n_estimators=300,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=1.0,
            min_child_weight=1.0,
            random_state=cfg.random_seed,
            n_jobs=1,
        )
        return model, sample_weight, _GRAPH_STAT_XGBOOST_MODEL_NAME
    model = HistGradientBoostingClassifier(
        learning_rate=0.05,
        max_depth=3,
        max_iter=200,
        min_samples_leaf=20,
        l2_regularization=0.1,
        random_state=cfg.random_seed,
    )
    return model, sample_weight, _GRAPH_STAT_FALLBACK_MODEL_NAME


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _vendor_tapas_root() -> Path:
    return _repo_root() / "vendor" / "tapas"


def _workspace_dir(base_dir: Path) -> Path:
    return base_dir / _WORKSPACE_DIRNAME


def _module1_graph_path(module1_dir: Path) -> Path:
    return module1_dir / _NATIVE_GRAPH_FILENAME


def _module1_summary_path(module1_dir: Path) -> Path:
    return module1_dir / _MODULE1_SUMMARY_FILENAME


def _model_output_path(cfg: FusionConfig, out_dir: Path) -> Path:
    override = cfg.task_detector_model_output
    return Path(override) if override else out_dir / _MODEL_FILENAME


def _model_input_path(cfg: FusionConfig, out_dir: Path) -> Path:
    override = cfg.task_detector_model_input
    return Path(override) if override else out_dir / _MODEL_FILENAME


def _stats_model_sidecar_path(model_path: Path) -> Path:
    return model_path.with_name(f"{model_path.stem}_stats.pkl")


def _late_fusion_requested(cfg: FusionConfig) -> bool:
    return bool(
        cfg.task_graph_stat_late_fusion_enabled
        and cfg.use_sequence_embeddings
        and cfg.use_ocr_stat_features
    )


def _graphsage_uses_stat_features(cfg: FusionConfig) -> bool:
    return bool(cfg.use_ocr_stat_features and (cfg.graphsage_append_ocr_stat_features or not cfg.use_sequence_embeddings))


def _graphsage_node_feature_sources(cfg: FusionConfig) -> dict[str, bool]:
    return {
        "sequence_embeddings": bool(cfg.use_sequence_embeddings),
        "ocr_stat_features": bool(_graphsage_uses_stat_features(cfg)),
        "tc3_full_event_stats": bool(
            cfg.dataset_family == "tc3"
            and cfg.task_tc3_event_stats_mode in {"core", "extended", "security_semantic"}
            and _graphsage_uses_stat_features(cfg)
        ),
    }


def _tc3_supported_hosts() -> set[str]:
    return {"trace", "cadets", "fivedirections", "theia", "theia_e5"}


def _optc_eval_dataset_name(host: str) -> str:
    text = str(host).strip().lower()
    if text in {"all", "data_all", "optc_all"}:
        return "data_all"
    match = re.search(r"(\d{4})", str(host))
    if not match:
        raise ValueError(
            "Exact TAPAS OpTC mode expects host to be one of SysClient0051 / SysClient0201 / SysClient0501 or 'data_all'."
        )
    return match.group(1)


def _expected_optc_filename(host_id: str) -> str:
    return f"SysClient{host_id}.systemia.com.txt"


def _load_vendor_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load vendor module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def _temporary_cwd(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _torch_load(path: Path) -> Any:
    try:
        return torch.load(path, map_location="cpu", weights_only=False)
    except TypeError:
        return torch.load(path, map_location="cpu")


def _copy_vendor_support_files(workspace: Path, cfg: FusionConfig) -> None:
    data_dir = workspace / "data"
    model_dir = workspace / "model"
    groundtruth_dir = workspace / "groundtruth"
    ensure_dir(data_dir)
    ensure_dir(model_dir)
    ensure_dir(groundtruth_dir)

    vendor_root = _vendor_tapas_root()
    for source in (vendor_root / "data").glob("*"):
        if source.is_file():
            shutil.copy2(source, data_dir / source.name)
    for source in (vendor_root / "model").glob("*"):
        if source.is_file():
            shutil.copy2(source, model_dir / source.name)
    if cfg.task_sequence_model_path is not None:
        if not cfg.task_sequence_model_path.exists():
            raise FileNotFoundError(f"Configured task sequence model does not exist: {cfg.task_sequence_model_path}")
        # Vendor parsers load this fixed filename from the isolated module1 workspace.
        shutil.copy2(cfg.task_sequence_model_path, model_dir / "stackedlstm_tc.pt")

    if cfg.task_ground_truth_path is not None and cfg.task_ground_truth_path.exists():
        if cfg.dataset_family == "optc":
            target = groundtruth_dir / "optc.txt"
        else:
            target = groundtruth_dir / f"{cfg.host}.txt"
        shutil.copy2(cfg.task_ground_truth_path, target)


def _ensure_workspace(base_dir: Path, cfg: FusionConfig) -> Path:
    workspace = _workspace_dir(base_dir)
    _copy_vendor_support_files(workspace, cfg)
    return workspace


def _normalize_tc3_source_logs(source_logs: Path) -> str:
    if not source_logs.is_dir():
        raise ValueError("Exact TAPAS tc3 mode expects source_logs to point to a logs directory")
    text = str(source_logs)
    if text.endswith(("/", "\\")):
        return text
    return text + os.sep


def _load_ground_truth(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    if path.suffix.lower() == ".csv":
        # ORTHRUS E5 node exports place the original CDM UUID in column zero.
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return {
                row[0].strip()
                for row in csv.reader(handle)
                if row and row[0].strip()
            }
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def _load_theia_e5_ground_truth_entity_types(path: Path | None) -> dict[str, str]:
    """Read ORTHRUS node exports without treating non-Subject UUIDs as processes."""
    if path is None or not path.exists() or path.suffix.lower() != ".csv":
        return {}
    entity_types: dict[str, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(handle):
            if not row or not row[0].strip():
                continue
            attributes: dict[str, Any] = {}
            if len(row) > 1:
                try:
                    value = ast.literal_eval(row[1])
                    if isinstance(value, dict):
                        attributes = value
                except (SyntaxError, ValueError):
                    pass
            # ORTHRUS exports use the entity family as the attribute key,
            # e.g. {"subject": "/usr/sbin/sshd"}, rather than a type value.
            entity_type = next(
                (
                    key
                    for key in ("subject", "file", "netflow")
                    if key in attributes
                ),
                "",
            )
            entity_types[row[0].strip()] = entity_type or "unknown"
    return entity_types


def _vector_rows_to_map(raw_vectors: Any) -> dict[str, list[float]]:
    if isinstance(raw_vectors, dict):
        return {
            str(key): [float(value) for value in values]
            for key, values in raw_vectors.items()
        }
    result: dict[str, list[float]] = {}
    for row in raw_vectors:
        if not row:
            continue
        result[str(row[0])] = [float(value) for value in row[1:]]
    return result


def _feature_dim_from_map(vector_map: dict[str, list[float]]) -> int:
    if not vector_map:
        return _DEFAULT_FEATURE_DIM
    return max(len(values) for values in vector_map.values())


def _build_segmentation_frame(edge_list: Sequence[Sequence[Any]]) -> pd.DataFrame:
    rows = []
    seen: set[tuple[str, str]] = set()
    for edge in edge_list:
        if len(edge) < 2:
            continue
        parent = str(edge[0]).strip()
        child = str(edge[1]).strip()
        if not child or not parent:
            continue
        key = (parent, child)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "parent_process_id": parent,
                "child_process_id": child,
                "relation_type": "parent_to_child",
                "use_for_segmentation": True,
            }
        )
    if not rows:
        return pd.DataFrame(
            columns=["child_process_id", "parent_process_id", "relation_type", "use_for_segmentation"]
        )
    return pd.DataFrame(rows).sort_values(["parent_process_id", "child_process_id"]).reset_index(drop=True)


def _score_summary(rows: Sequence[dict[str, Any]]) -> dict[str, float | None]:
    if not rows:
        return {"score_min": None, "score_max": None, "score_median": None}
    scores = np.asarray([float(row["task_score"]) for row in rows], dtype=np.float64)
    return {
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
        "score_median": float(np.median(scores)),
    }


def _metrics_dict(labels: Sequence[int], probs: Sequence[float], preds: Sequence[int]) -> dict[str, Any]:
    if not labels:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "positive_count": 0,
            "negative_count": 0,
            "average_mode": "macro",
            "roc_auc": None,
            "pr_auc": None,
        }
    y_true = np.asarray(labels, dtype=np.int64)
    y_prob = np.asarray(probs, dtype=np.float64)
    y_pred = np.asarray(preds, dtype=np.int64)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="macro",
        zero_division=0,
    )
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "positive_count": int(y_true.sum()),
        "negative_count": int((y_true == 0).sum()),
        "average_mode": "macro",
        "roc_auc": None,
        "pr_auc": None,
    }
    if len(set(y_true.tolist())) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        metrics["pr_auc"] = float(average_precision_score(y_true, y_prob))
    return metrics


def _bundle_stat_embeddings_for_sidecar(bundle: dict[str, Any]) -> dict[str, list[float]]:
    selected_stats = bundle.get("selected_stat_embeddings", {})
    if isinstance(selected_stats, dict) and selected_stats:
        return {
            str(process_id): [float(value) for value in vector]
            for process_id, vector in selected_stats.items()
        }

    stat_feature_dim = len(bundle.get("stat_feature_columns", []))
    if stat_feature_dim <= 0:
        return {}

    base_feature_dim = int(bundle.get("base_sequence_feature_dim", bundle.get("sequence_feature_dim", 0)))
    if bundle.get("family") != "optc":
        merged_embeddings = {
            str(process_id): [float(value) for value in vector]
            for process_id, vector in bundle.get("selected_embeddings", {}).items()
        }
    else:
        merged_embeddings: dict[str, list[float]] = {}
        for host_id in bundle.get("host_order", []):
            for process_id, vector in bundle.get("embeddings_by_host", {}).get(host_id, {}).items():
                merged_embeddings[str(process_id)] = [float(value) for value in vector]
        for process_id, vector in bundle.get("selected_embeddings", {}).items():
            merged_embeddings[str(process_id)] = [float(value) for value in vector]

    stats_map: dict[str, list[float]] = {}
    for process_id, vector in merged_embeddings.items():
        stats = [float(value) for value in vector[base_feature_dim : base_feature_dim + stat_feature_dim]]
        if len(stats) < stat_feature_dim:
            stats.extend([0.0] * (stat_feature_dim - len(stats)))
        elif len(stats) > stat_feature_dim:
            stats = stats[:stat_feature_dim]
        stats_map[str(process_id)] = stats
    return stats_map


def _graph_stat_feature_dim(stat_dim: int) -> int:
    if stat_dim <= 0:
        return 0
    return (stat_dim * 3) + 3


def _graph_stat_feature_vector(
    process_ids: Sequence[Any],
    stat_embeddings_map: dict[str, list[float]],
    stat_feature_dim: int,
    stat_overrides: dict[str, list[float]] | None = None,
) -> np.ndarray:
    feature_dim = _graph_stat_feature_dim(stat_feature_dim)
    if feature_dim <= 0:
        return np.zeros((0,), dtype=np.float64)

    node_stats: list[list[float]] = []
    active_nodes = 0
    nonzero_entries = 0
    total_entries = 0
    stat_overrides = stat_overrides or {}
    for process_id in process_ids:
        raw_stats = stat_overrides.get(str(process_id), stat_embeddings_map.get(str(process_id), []))
        stats = _normalize_stat_vector(raw_stats, stat_feature_dim)
        node_stats.append(stats)
        if any(abs(value) > 1e-12 for value in stats):
            active_nodes += 1
        nonzero_entries += sum(1 for value in stats if abs(value) > 1e-12)
        total_entries += stat_feature_dim

    if not node_stats:
        return np.zeros((feature_dim,), dtype=np.float64)

    matrix = np.asarray(node_stats, dtype=np.float64)
    mean_vec = matrix.mean(axis=0)
    max_vec = matrix.max(axis=0)
    std_vec = matrix.std(axis=0)
    active_node_ratio = float(active_nodes) / float(len(node_stats))
    nonzero_entry_ratio = float(nonzero_entries) / float(total_entries) if total_entries else 0.0
    log_node_count = float(np.log1p(len(node_stats)))
    return np.concatenate(
        [
            mean_vec,
            max_vec,
            std_vec,
            np.asarray([active_node_ratio, nonzero_entry_ratio, log_node_count], dtype=np.float64),
        ]
    )


def _rows_to_graph_stat_matrix(
    rows: Sequence[dict[str, Any]],
    stat_embeddings_map: dict[str, list[float]],
    stat_feature_dim: int,
) -> np.ndarray:
    feature_dim = _graph_stat_feature_dim(stat_feature_dim)
    if not rows or feature_dim <= 0:
        return np.zeros((0, feature_dim), dtype=np.float64)
    matrix = [
        _graph_stat_feature_vector(
            row.get("process_ids", []),
            stat_embeddings_map,
            stat_feature_dim,
            row.get("process_stat_overrides"),
        )
        for row in rows
    ]
    return np.asarray(matrix, dtype=np.float64)


def _rows_metrics(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return _metrics_dict(
        [int(row.get("task_label", 0)) for row in rows],
        [float(row.get("task_probability", row.get("task_score", 0.0))) for row in rows],
        [int(row.get("predicted_label", 0)) for row in rows],
    )


def _fit_graph_stat_sidecar_model(
    cfg: FusionConfig,
    bundle: dict[str, Any],
    train_rows: Sequence[dict[str, Any]],
    model_path: Path,
) -> tuple[Any | None, dict[str, Any]]:
    info: dict[str, Any] = {
        "requested": _late_fusion_requested(cfg),
        "active": False,
        "model": "",
        "feature_dim": 0,
        "path": "",
        "reason": "",
    }
    if not info["requested"]:
        info["reason"] = "not_requested"
        return None, info

    stat_feature_dim = len(bundle.get("stat_feature_columns", []))
    feature_dim = _graph_stat_feature_dim(stat_feature_dim)
    info["feature_dim"] = feature_dim
    if stat_feature_dim <= 0 or feature_dim <= 0:
        info["reason"] = "missing_stat_features"
        return None, info

    stat_embeddings_map = _bundle_stat_embeddings_for_sidecar(bundle)
    train_matrix = _rows_to_graph_stat_matrix(train_rows, stat_embeddings_map, stat_feature_dim)
    labels = np.asarray([int(row.get("task_label", 0)) for row in train_rows], dtype=np.int64)
    if len(train_matrix) == 0:
        info["reason"] = "empty_training_rows"
        return None, info
    if len(np.unique(labels)) < 2:
        info["reason"] = "single_class_training_rows"
        return None, info

    model, sample_weight, model_name = _build_graph_stat_sidecar_model(cfg, labels)
    model.fit(train_matrix, labels, sample_weight=sample_weight)

    stats_model_path = _stats_model_sidecar_path(model_path)
    ensure_parent(stats_model_path)
    with stats_model_path.open("wb") as fh:
        pickle.dump(model, fh)

    info.update(
        {
            "active": True,
            "model": model_name,
            "path": str(stats_model_path),
            "reason": "",
        }
    )
    return model, info


def _load_graph_stat_sidecar_model(model_path: Path) -> Any | None:
    stats_model_path = _stats_model_sidecar_path(model_path)
    if not stats_model_path.exists():
        return None
    try:
        with stats_model_path.open("rb") as fh:
            loaded = pickle.load(fh)
    except Exception:
        return None
    if XGBClassifier is not None and isinstance(loaded, XGBClassifier):
        return loaded
    return loaded if isinstance(loaded, HistGradientBoostingClassifier) else None


def _apply_graph_stat_late_fusion(
    cfg: FusionConfig,
    bundle: dict[str, Any],
    rows: Sequence[dict[str, Any]],
    stats_model: Any | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if stats_model is None or not rows:
        copied_rows = [copy.deepcopy(row) for row in rows]
        return copied_rows, _rows_metrics(copied_rows)

    stat_feature_dim = len(bundle.get("stat_feature_columns", []))
    stat_embeddings_map = _bundle_stat_embeddings_for_sidecar(bundle)
    matrix = _rows_to_graph_stat_matrix(rows, stat_embeddings_map, stat_feature_dim)
    if len(matrix) == 0:
        copied_rows = [copy.deepcopy(row) for row in rows]
        return copied_rows, _rows_metrics(copied_rows)

    stats_probs = stats_model.predict_proba(matrix)[:, 1]
    fused_rows: list[dict[str, Any]] = []
    weight = float(cfg.task_graph_stat_fusion_weight)
    for row, stats_prob in zip(rows, stats_probs.tolist()):
        base_prob = float(row.get("task_probability", row.get("task_score", 0.0)))
        fused_prob = ((1.0 - weight) * base_prob) + (weight * float(stats_prob))
        fused = copy.deepcopy(row)
        fused["graphsage_probability"] = base_prob
        fused["stats_probability"] = float(stats_prob)
        fused["fusion_weight_stats"] = weight
        fused["task_probability"] = fused_prob
        fused["task_score"] = fused_prob
        fused["predicted_label"] = int(fused_prob >= 0.5)
        fused["threshold_used"] = 0.5
        fused["is_suspicious"] = bool(fused["predicted_label"])
        fused["task_score_basis"] = "tapas_graphsage_plus_graph_stats"
        fused_rows.append(fused)
    fused_rows.sort(key=lambda row: (float(row["task_score"]), row["task_id"]), reverse=True)
    return fused_rows, _rows_metrics(fused_rows)


def _write_backend_outputs(out_dir: Path, rows: Sequence[dict[str, Any]], summary: dict[str, Any]) -> dict[str, Path]:
    task_scores_path = out_dir / _TASK_SCORE_FILENAME
    task_summary_path = out_dir / _TASK_SUMMARY_FILENAME
    ensure_parent(task_scores_path)
    pd.DataFrame(list(rows)).to_csv(task_scores_path, index=False)
    save_json(task_summary_path, summary)
    return {
        "task_scores": task_scores_path,
        "task_subgraph_summary": task_summary_path,
    }


def _decompose_tc3_metadata(
    edge_list: Sequence[Sequence[Any]],
    ground_truth: set[str],
) -> list[dict[str, Any]]:
    if isinstance(edge_list, dict) and "task_components" in edge_list:
        data = []
        diagnostics = list(edge_list.get("task_component_diagnostics", []))
        task_index = 0
        for component in edge_list.get("task_components", []):
            node_ids = [str(node) for node in component.get("nodes", [])]
            if len(node_ids) < 2:
                continue
            original_node_ids = [str(node) for node in component.get("original_nodes", node_ids)]
            attacknum = sum(1 for node in original_node_ids if str(node) in ground_truth)
            payload = {
                "task_id": f"task_{task_index:04d}",
                "node_ids": node_ids,
                "label": 1 if attacknum > 0 else 0,
                "attacknum": attacknum,
                "task_size": len(node_ids),
                "original_task_size": len(original_node_ids),
                "original_node_ids": original_node_ids,
                "internal_edge_count": len(component.get("edges", [])),
                "task_root_id": str(component.get("task_root", "")),
                "boundary_node_ids": [str(node) for node in component.get("boundary_nodes", [])],
            }
            if task_index < len(diagnostics) and isinstance(diagnostics[task_index], dict):
                diag = diagnostics[task_index]
                payload.update(
                    {
                        "task_root_total_children": int(diag.get("task_root_total_children", 0) or 0),
                        "task_root_effective_children": int(diag.get("task_root_effective_children", 0) or 0),
                        "task_root_segmented": bool(diag.get("task_root_segmented", False)),
                        "task_root_parent_missing": bool(diag.get("task_root_parent_missing", False)),
                        "child_threshold": int(diag.get("child_threshold", edge_list.get("child_threshold", 0)) or 0),
                        "split_mode": str(diag.get("split_mode", edge_list.get("split_mode", ""))),
                        "count_segmented_children_upstream": bool(
                            diag.get(
                                "count_segmented_children_upstream",
                                edge_list.get("count_segmented_children_upstream", False),
                            )
                        ),
                    }
                )
            for key in [
                "temporal_split_applied",
                "temporal_split_parent_task_root",
                "temporal_split_cluster_index",
                "temporal_split_cluster_count",
                "temporal_split_child_roots",
                "temporal_component_first_timestamp_sec",
                "temporal_component_last_timestamp_sec",
                "temporal_component_span_minutes",
                "temporal_component_root_retained",
                "root_temporal_split_applied",
                "root_temporal_parent_task_root",
                "root_temporal_cluster_index",
                "root_temporal_cluster_count",
                "root_temporal_child_roots",
                "root_temporal_component_first_timestamp_sec",
                "root_temporal_component_last_timestamp_sec",
                "root_temporal_component_span_minutes",
                "root_temporal_root_retained",
                "temporal_episode_split_applied",
                "temporal_episode_parent_task_root",
                "temporal_episode_index",
                "temporal_episode_count",
                "temporal_episode_child_roots",
                "temporal_episode_first_child_timestamp_sec",
                "temporal_episode_last_child_timestamp_sec",
                "temporal_episode_child_span_minutes",
                "temporal_episode_root_retained",
                "synthetic_root_isolation_applied",
                "synthetic_root_isolation_parent_root",
                "synthetic_root_isolation_child_root",
                "synthetic_root_isolation_direct_child_count",
                "synthetic_root_isolation_parent_task_size",
                "branch_object_overlap_split_applied",
                "branch_object_overlap_parent_task_root",
                "branch_object_overlap_group_index",
                "branch_object_overlap_group_count",
                "branch_object_overlap_child_roots",
                "provgrp_paper_partition_applied",
                "provgrp_paper_parent_task_root",
                "provgrp_paper_partition_index",
                "provgrp_paper_partition_count",
                "provgrp_paper_incoming_cluster_id",
                "provgrp_paper_outgoing_cluster_id",
                "provgrp_paper_incoming_event_count",
                "provgrp_paper_outgoing_event_count",
                "provgrp_paper_member_child_roots",
                "provgrp_paper_member_child_count",
                "provgrp_paper_original_root_child_count",
            ]:
                if key in component:
                    payload[key] = copy.deepcopy(component[key])
                elif task_index < len(diagnostics) and isinstance(diagnostics[task_index], dict) and key in diagnostics[task_index]:
                    payload[key] = copy.deepcopy(diagnostics[task_index][key])
            data.append(payload)
            task_index += 1
        return data
    # Sidecar metadata only. Training/evaluation graphs come directly from the
    # official TAPAS decompose() output; this helper exists so the later
    # investigation/reporting stages can still export task ids and process ids.
    node_list = set()
    for line in edge_list:
        node_list.add(line[0])
        node_list.add(line[1])
    father = {}
    for node in node_list:
        father[node] = node

    def find(x):
        root = x
        while root != father[root]:
            root = father[root]
        while x != root:
            next_node = father[x]
            father[x] = root
            x = next_node
        return root

    def union(x, y):
        father[find(x)] = find(y)

    for edge in edge_list:
        union(edge[0], edge[1])

    node_map = {}
    edge_map = {}
    for node in node_list:
        root = find(node)
        node_map.setdefault(root, []).append(node)
    for edge in edge_list:
        root = find(edge[0])
        edge_map.setdefault(root, []).append(edge)

    graph_list = []
    for key in node_map:
        if len(edge_map.get(key, [])) == 0:
            continue
        graph_list.append([node_map[key], edge_map[key]])

    data = []
    task_index = 0
    for graph in graph_list:
        label = 0
        attacknum = 0
        node_ids = []

        for node in graph[0]:
            if str(node) in ground_truth:
                attacknum += 1
                label = 1
            node_ids.append(str(node))
        if len(node_ids) < 2:
            continue
        data.append(
            {
                "task_id": f"task_{task_index:04d}",
                "node_ids": node_ids,
                "label": label,
                "attacknum": attacknum,
                "task_size": len(node_ids),
                "internal_edge_count": len(graph[1]),
            }
        )
        task_index += 1
    return data


def _semantic_sequence_train_subject_ids(cfg: FusionConfig, graph_metas: Sequence[dict[str, Any]]) -> set[str]:
    """Mirror normal-only temporal splitting before fitting the sequence encoder."""
    benign_metas = [meta for meta in graph_metas if int(meta.get("label", 0)) == 0]
    benign_metas.sort(
        key=lambda meta: (
            _normal_only_timestamp(meta) is None,
            _normal_only_timestamp(meta) or 0.0,
            str(meta.get("task_id", "")),
        )
    )
    train_count = max(1, int(np.floor(len(benign_metas) * float(cfg.task_normal_only_train_fraction))))
    subjects: set[str] = set()
    for meta in benign_metas[:train_count]:
        subjects.update(str(node) for node in meta.get("node_ids", []))
    return subjects


def _canonicalize_ground_truth_nodes(
    ground_truth: set[str],
    parser_metadata: dict[str, Any] | None,
) -> set[str]:
    if not ground_truth:
        return set()
    if not isinstance(parser_metadata, dict):
        return {str(node).strip() for node in ground_truth if str(node).strip()}
    mapping = parser_metadata.get("raw_subject_to_canonical_node")
    if not isinstance(mapping, dict) or not mapping:
        return {str(node).strip() for node in ground_truth if str(node).strip()}
    canonical = set()
    for node in ground_truth:
        text = str(node).strip()
        if not text:
            continue
        canonical.add(str(mapping.get(text, text)).strip())
    return {node for node in canonical if node}


def _decompose_optc_metadata(
    edge_list: Sequence[Sequence[Any]],
    ground_truth: set[str],
    task_prefix: str,
) -> list[dict[str, Any]]:
    # Sidecar metadata only; see _decompose_tc3_metadata().
    node_list = set()
    for line in edge_list:
        node_list.add(line[0])
        node_list.add(line[1])

    father = {}
    for node in node_list:
        father[node] = node

    def find(x):
        root = x
        while root != father[root]:
            root = father[root]
        while x != root:
            next_node = father[x]
            father[x] = root
            x = next_node
        return root

    def union(x, y):
        father[find(x)] = find(y)

    for edge in edge_list:
        union(edge[0], edge[1])

    node_map = {}
    edge_map = {}
    for node in node_list:
        root = find(node)
        node_map.setdefault(root, []).append(node)
    for edge in edge_list:
        root = find(edge[0])
        edge_map.setdefault(root, []).append(edge)

    graph_list = []
    for key in node_map:
        if len(edge_map.get(key, [])) == 0 or len(node_map[key]) == 1:
            continue
        graph_list.append([node_map[key], edge_map[key]])

    data = []
    task_index = 0
    for graph in graph_list:
        label = 0
        attacknum = 0
        node_ids = []

        for node in graph[0]:
            if str(node) in ground_truth:
                label = 1
            node_ids.append(str(node))
        if len(node_ids) < 2:
            continue
        data.append(
            {
                "task_id": f"{task_prefix}{task_index:04d}",
                "node_ids": node_ids,
                "label": label,
                "attacknum": attacknum,
                "task_size": len(node_ids),
                "internal_edge_count": len(graph[1]),
            }
        )
        task_index += 1
    return data


def _validate_graph_meta_alignment(
    graphs: Sequence[dict[str, Any]],
    graph_metas: Sequence[dict[str, Any]],
    context: str,
) -> None:
    if len(graphs) != len(graph_metas):
        raise ValueError(
            f"Official TAPAS graph count and export metadata count differ for {context}: "
            f"{len(graphs)} != {len(graph_metas)}"
        )
    for index, (graph, meta) in enumerate(zip(graphs, graph_metas)):
        node_count = len(graph.get("nodes", []))
        edge_count = len(graph.get("edges", []))
        label = int(graph.get("label", 0))
        attacknum = int(graph.get("attacknum", 0))
        if node_count != int(meta.get("task_size", len(meta.get('node_ids', [])))):
            raise ValueError(f"Node count mismatch at {context} graph {index}")
        if edge_count != int(meta.get("internal_edge_count", edge_count)):
            raise ValueError(f"Edge count mismatch at {context} graph {index}")
        if label != int(meta.get("label", label)):
            raise ValueError(f"Label mismatch at {context} graph {index}")
        if attacknum != int(meta.get("attacknum", attacknum)):
            raise ValueError(f"Attack count mismatch at {context} graph {index}")


def _float_or_none(value: Any) -> float | None:
    try:
        if value in ("", None):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _component_node_time_range(
    node_ids: Sequence[Any],
    subject_time_ranges: dict[str, Any],
) -> tuple[float | None, float | None]:
    first_seen: float | None = None
    last_seen: float | None = None
    for node_id in node_ids:
        row = subject_time_ranges.get(str(node_id))
        if not isinstance(row, dict):
            continue
        first_value = _float_or_none(row.get("first_timestamp_sec"))
        last_value = _float_or_none(row.get("last_timestamp_sec"))
        if first_value is None or last_value is None:
            continue
        if first_seen is None or first_value < first_seen:
            first_seen = first_value
        if last_seen is None or last_value > last_seen:
            last_seen = last_value
    return first_seen, last_seen


def _component_children_map(component: dict[str, Any]) -> dict[str, list[str]]:
    children_map: dict[str, list[str]] = {}
    for edge in component.get("edges", []):
        if not isinstance(edge, (list, tuple)) or len(edge) < 2:
            continue
        # Vendor task components store process edges as [parent, child].
        parent = str(edge[0])
        child = str(edge[1])
        children_map.setdefault(parent, []).append(child)
    for parent in list(children_map):
        children_map[parent] = sorted({str(child) for child in children_map[parent]})
    return children_map


def _collect_component_subtree(root: str, children_map: dict[str, list[str]]) -> set[str]:
    visited: set[str] = set()
    stack = [str(root)]
    while stack:
        node = stack.pop()
        if node in visited:
            continue
        visited.add(node)
        for child in reversed(children_map.get(node, [])):
            if child not in visited:
                stack.append(child)
    return visited


def _build_task_component_diagnostics_from_components(
    components: Sequence[dict[str, Any]],
    *,
    child_threshold: int,
    split_mode: str,
    count_segmented_children_upstream: bool,
) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    for component in components:
        children_map = _component_children_map(component)
        task_root = str(component.get("task_root", "")).strip()
        children = children_map.get(task_root, [])
        row = {
            "task_root": task_root,
            "task_size": len(component.get("nodes", [])),
            "internal_edge_count": len(component.get("edges", [])),
            "boundary_node_count": len(component.get("boundary_nodes", [])),
            "task_root_total_children": len(children),
            "task_root_effective_children": len(children),
            "task_root_segmented": bool(task_root and task_root in set(component.get("boundary_nodes", []))),
            "task_root_parent_missing": False,
            "child_threshold": int(child_threshold),
            "split_mode": str(split_mode),
            "count_segmented_children_upstream": bool(count_segmented_children_upstream),
        }
        for key in [
            "temporal_split_applied",
            "temporal_split_parent_task_root",
            "temporal_split_cluster_index",
            "temporal_split_cluster_count",
            "temporal_split_child_roots",
            "temporal_component_first_timestamp_sec",
            "temporal_component_last_timestamp_sec",
            "temporal_component_span_minutes",
            "temporal_component_root_retained",
            "root_temporal_split_applied",
            "root_temporal_parent_task_root",
            "root_temporal_cluster_index",
            "root_temporal_cluster_count",
            "root_temporal_child_roots",
            "root_temporal_component_first_timestamp_sec",
            "root_temporal_component_last_timestamp_sec",
            "root_temporal_component_span_minutes",
            "root_temporal_root_retained",
            "temporal_episode_split_applied",
            "temporal_episode_parent_task_root",
            "temporal_episode_index",
            "temporal_episode_count",
            "temporal_episode_child_roots",
            "temporal_episode_first_child_timestamp_sec",
            "temporal_episode_last_child_timestamp_sec",
            "temporal_episode_child_span_minutes",
            "temporal_episode_root_retained",
            "synthetic_root_isolation_applied",
            "synthetic_root_isolation_parent_root",
            "synthetic_root_isolation_child_root",
            "synthetic_root_isolation_direct_child_count",
            "synthetic_root_isolation_parent_task_size",
            "branch_object_overlap_split_applied",
            "branch_object_overlap_parent_task_root",
            "branch_object_overlap_group_index",
            "branch_object_overlap_group_count",
            "branch_object_overlap_child_roots",
            "provgrp_paper_partition_applied",
            "provgrp_paper_parent_task_root",
            "provgrp_paper_partition_index",
            "provgrp_paper_partition_count",
            "provgrp_paper_incoming_cluster_id",
            "provgrp_paper_outgoing_cluster_id",
            "provgrp_paper_incoming_event_count",
            "provgrp_paper_outgoing_event_count",
            "provgrp_paper_member_child_roots",
            "provgrp_paper_member_child_count",
            "provgrp_paper_original_root_child_count",
        ]:
            if key in component:
                row[key] = copy.deepcopy(component[key])
        if "root_temporal_task_root_parent_missing" in component:
            row["task_root_parent_missing"] = bool(component["root_temporal_task_root_parent_missing"])
        diagnostics.append(row)
    return diagnostics


def _maybe_temporally_split_theia_component(
    component: dict[str, Any],
    subject_time_ranges: dict[str, Any],
    *,
    max_span_minutes: int,
    branch_gap_minutes: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = str(component.get("task_root", "")).strip()
    nodes = [str(node) for node in component.get("nodes", [])]
    component_first, component_last = _component_node_time_range(nodes, subject_time_ranges)
    span_seconds = None
    if component_first is not None and component_last is not None:
        span_seconds = max(0.0, component_last - component_first)
    summary = {
        "applied": False,
        "task_root": root,
        "component_span_minutes": (span_seconds / 60.0) if span_seconds is not None else None,
        "cluster_count": 0,
        "reason": "component_not_eligible",
    }
    if root == "":
        summary["reason"] = "missing_task_root"
        return [component], summary
    if span_seconds is None:
        summary["reason"] = "missing_component_time_range"
        return [component], summary
    if span_seconds <= float(max_span_minutes) * 60.0:
        summary["reason"] = "within_max_span"
        return [component], summary

    children_map = _component_children_map(component)
    direct_children = children_map.get(root, [])
    if len(direct_children) < 2:
        summary["reason"] = "insufficient_direct_children"
        return [component], summary

    branch_infos: list[dict[str, Any]] = []
    for child in direct_children:
        subtree_nodes = _collect_component_subtree(child, children_map)
        first_seen, last_seen = _component_node_time_range(sorted(subtree_nodes), subject_time_ranges)
        branch_infos.append(
            {
                "child_root": child,
                "nodes": subtree_nodes,
                "first_timestamp_sec": first_seen,
                "last_timestamp_sec": last_seen,
            }
        )

    timed_infos = [info for info in branch_infos if info["first_timestamp_sec"] is not None and info["last_timestamp_sec"] is not None]
    if len(timed_infos) < 2:
        summary["reason"] = "insufficient_timed_children"
        return [component], summary

    timed_infos.sort(
        key=lambda info: (
            float(info["first_timestamp_sec"]),
            float(info["last_timestamp_sec"]),
            str(info["child_root"]),
        )
    )
    clusters: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_last = None
    gap_seconds = max(0, int(branch_gap_minutes)) * 60.0
    for info in timed_infos:
        if not current:
            current = [info]
            current_last = float(info["last_timestamp_sec"])
            continue
        branch_first = float(info["first_timestamp_sec"])
        branch_last = float(info["last_timestamp_sec"])
        if current_last is not None and branch_first - current_last >= gap_seconds:
            clusters.append(current)
            current = [info]
            current_last = branch_last
            continue
        current.append(info)
        if current_last is None or branch_last > current_last:
            current_last = branch_last
    if current:
        clusters.append(current)
    if len(clusters) < 2:
        summary["reason"] = "single_temporal_cluster"
        return [component], summary

    untimed_infos = [info for info in branch_infos if info["first_timestamp_sec"] is None or info["last_timestamp_sec"] is None]
    for index, info in enumerate(untimed_infos):
        clusters[index % len(clusters)].append(info)

    original_boundary_nodes = {str(node) for node in component.get("boundary_nodes", [])}
    original_edges = [
        [str(edge[0]), str(edge[1])]
        for edge in component.get("edges", [])
        if isinstance(edge, (list, tuple)) and len(edge) >= 2
    ]
    new_components: list[dict[str, Any]] = []
    for cluster_index, cluster_infos in enumerate(clusters):
        cluster_nodes: set[str] = set()
        cluster_child_roots: list[str] = []
        timed_first_values: list[float] = []
        timed_last_values: list[float] = []
        for info in cluster_infos:
            cluster_nodes.update(str(node) for node in info["nodes"])
            cluster_child_roots.append(str(info["child_root"]))
            if info["first_timestamp_sec"] is not None and info["last_timestamp_sec"] is not None:
                timed_first_values.append(float(info["first_timestamp_sec"]))
                timed_last_values.append(float(info["last_timestamp_sec"]))

        cluster_edges = [
            [parent, child]
            for parent, child in original_edges
            if parent in cluster_nodes and child in cluster_nodes
        ]
        root_retained = False
        if not cluster_edges:
            nodes_with_root = set(cluster_nodes)
            nodes_with_root.add(root)
            fallback_edges = [
                [parent, child]
                for parent, child in original_edges
                if parent in nodes_with_root and child in nodes_with_root
            ]
            if not fallback_edges:
                continue
            cluster_nodes = nodes_with_root
            cluster_edges = fallback_edges
            root_retained = True

        cluster_component = {
            "task_root": str(cluster_child_roots[0]).strip() if cluster_child_roots else root,
            "nodes": sorted(cluster_nodes),
            "edges": cluster_edges,
            "boundary_nodes": sorted(original_boundary_nodes | {root}),
            "temporal_split_applied": True,
            "temporal_split_parent_task_root": root,
            "temporal_split_cluster_index": int(cluster_index),
            "temporal_split_cluster_count": int(len(clusters)),
            "temporal_split_child_roots": cluster_child_roots,
            "temporal_component_first_timestamp_sec": min(timed_first_values) if timed_first_values else None,
            "temporal_component_last_timestamp_sec": max(timed_last_values) if timed_last_values else None,
            "temporal_component_span_minutes": (
                (max(timed_last_values) - min(timed_first_values)) / 60.0
                if timed_first_values and timed_last_values
                else None
            ),
            "temporal_component_root_retained": bool(root_retained),
        }
        if len(cluster_component["nodes"]) < 2 or len(cluster_component["edges"]) == 0:
            continue
        new_components.append(cluster_component)

    if len(new_components) < 2:
        summary["reason"] = "split_components_not_viable"
        return [component], summary

    summary.update(
        {
            "applied": True,
            "cluster_count": len(new_components),
            "reason": "split_applied",
        }
    )
    return new_components, summary


def _apply_theia_temporal_split(
    edge_list: Any,
    *,
    max_span_minutes: int,
    branch_gap_minutes: int,
) -> Any:
    if not isinstance(edge_list, dict):
        return edge_list
    task_components = list(edge_list.get("task_components", []))
    subject_time_ranges = edge_list.get("subject_time_ranges", {})
    if not task_components or not isinstance(subject_time_ranges, dict):
        return edge_list

    new_components: list[dict[str, Any]] = []
    split_summaries: list[dict[str, Any]] = []
    applied_count = 0
    for component in task_components:
        component_splits, split_summary = _maybe_temporally_split_theia_component(
            component,
            subject_time_ranges,
            max_span_minutes=max_span_minutes,
            branch_gap_minutes=branch_gap_minutes,
        )
        if split_summary.get("applied"):
            applied_count += 1
        new_components.extend(component_splits)
        split_summaries.append(split_summary)

    if applied_count == 0:
        updated = dict(edge_list)
        updated["theia_temporal_split_summary"] = {
            "enabled": True,
            "max_span_minutes": int(max_span_minutes),
            "branch_gap_minutes": int(branch_gap_minutes),
            "input_component_count": len(task_components),
            "output_component_count": len(task_components),
            "split_component_count": 0,
            "component_summaries": split_summaries,
        }
        return updated

    rebuilt_edges: list[list[str]] = []
    edge_seen: set[tuple[str, str]] = set()
    for component in new_components:
        for edge in component.get("edges", []):
            if not isinstance(edge, (list, tuple)) or len(edge) < 2:
                continue
            edge_key = (str(edge[0]), str(edge[1]))
            if edge_key in edge_seen:
                continue
            edge_seen.add(edge_key)
            rebuilt_edges.append([edge_key[0], edge_key[1]])

    updated = dict(edge_list)
    updated["edge_list"] = rebuilt_edges
    updated["task_components"] = new_components
    updated["task_component_diagnostics"] = _build_task_component_diagnostics_from_components(
        new_components,
        child_threshold=int(edge_list.get("child_threshold", 0) or 0),
        split_mode=str(edge_list.get("split_mode", "fanout") or "fanout"),
        count_segmented_children_upstream=bool(edge_list.get("count_segmented_children_upstream", False)),
    )
    updated["theia_temporal_split_summary"] = {
        "enabled": True,
        "max_span_minutes": int(max_span_minutes),
        "branch_gap_minutes": int(branch_gap_minutes),
        "input_component_count": len(task_components),
        "output_component_count": len(new_components),
        "split_component_count": int(applied_count),
        "component_summaries": split_summaries,
    }
    return updated


def _maybe_temporally_split_root_component(
    component: dict[str, Any],
    subject_time_ranges: dict[str, Any],
    *,
    task_root_parent_missing: bool,
    min_task_nodes: int,
    min_direct_children: int,
    max_span_minutes: int,
    branch_gap_minutes: int,
    session_max_minutes: int,
    max_sessions: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Split only a large parent-missing root into time-local child-branch sessions."""
    root = str(component.get("task_root", "")).strip()
    nodes = [str(node) for node in component.get("nodes", [])]
    component_first, component_last = _component_node_time_range(nodes, subject_time_ranges)
    span_seconds = (
        max(0.0, component_last - component_first)
        if component_first is not None and component_last is not None
        else None
    )
    summary = {
        "applied": False,
        "task_root": root,
        "component_span_minutes": (span_seconds / 60.0) if span_seconds is not None else None,
        "cluster_count": 0,
        "reason": "component_not_eligible",
    }
    if not task_root_parent_missing:
        summary["reason"] = "root_has_known_parent"
        return [component], summary
    if root == "":
        summary["reason"] = "missing_task_root"
        return [component], summary
    if len(nodes) < int(min_task_nodes):
        summary["reason"] = "below_min_task_nodes"
        return [component], summary
    if span_seconds is None:
        summary["reason"] = "missing_component_time_range"
        return [component], summary
    if span_seconds <= float(max_span_minutes) * 60.0:
        summary["reason"] = "within_max_span"
        return [component], summary

    children_map = _component_children_map(component)
    direct_children = children_map.get(root, [])
    if len(direct_children) < int(min_direct_children):
        summary["reason"] = "below_min_direct_children"
        return [component], summary

    branch_infos: list[dict[str, Any]] = []
    for child in direct_children:
        subtree_nodes = _collect_component_subtree(child, children_map)
        first_seen, last_seen = _component_node_time_range(sorted(subtree_nodes), subject_time_ranges)
        branch_infos.append(
            {
                "child_root": str(child),
                "nodes": subtree_nodes,
                "first_timestamp_sec": first_seen,
                "last_timestamp_sec": last_seen,
            }
        )

    timed_infos = [
        info
        for info in branch_infos
        if info["first_timestamp_sec"] is not None and info["last_timestamp_sec"] is not None
    ]
    if len(timed_infos) < 2:
        summary["reason"] = "insufficient_timed_children"
        return [component], summary
    timed_infos.sort(
        key=lambda info: (
            float(info["first_timestamp_sec"]),
            float(info["last_timestamp_sec"]),
            str(info["child_root"]),
        )
    )

    gap_seconds = max(0, int(branch_gap_minutes)) * 60.0
    session_cap_seconds = max(0, int(session_max_minutes)) * 60.0
    clusters: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_first: float | None = None
    current_last: float | None = None
    for info in timed_infos:
        branch_first = float(info["first_timestamp_sec"])
        branch_last = float(info["last_timestamp_sec"])
        if not current:
            current = [info]
            current_first = branch_first
            current_last = branch_last
            continue
        split_on_gap = gap_seconds > 0 and current_last is not None and branch_first - current_last >= gap_seconds
        split_on_cap = (
            session_cap_seconds > 0
            and current_first is not None
            and branch_first - current_first > session_cap_seconds
        )
        if split_on_gap or split_on_cap:
            clusters.append(current)
            current = [info]
            current_first = branch_first
            current_last = branch_last
            continue
        current.append(info)
        current_last = max(float(current_last or branch_last), branch_last)
    if current:
        clusters.append(current)
    if len(clusters) < 2:
        summary["reason"] = "single_temporal_session"
        return [component], summary

    initial_cluster_count = len(clusters)
    if max_sessions > 0 and len(clusters) > int(max_sessions):
        # Preserve temporal order while bounding fragmentation of a synthetic root.
        # This is intentionally post-clustering: a session boundary is never crossed
        # by reordering branches, only adjacent sessions are coalesced.
        cluster_width = math.ceil(len(clusters) / int(max_sessions))
        clusters = [
            [info for session in clusters[index:index + cluster_width] for info in session]
            for index in range(0, len(clusters), cluster_width)
        ]

    # Preserve branches without event times in a deterministic session instead of discarding them.
    untimed_infos = [
        info
        for info in branch_infos
        if info["first_timestamp_sec"] is None or info["last_timestamp_sec"] is None
    ]
    for index, info in enumerate(untimed_infos):
        clusters[index % len(clusters)].append(info)

    original_boundary_nodes = {str(node) for node in component.get("boundary_nodes", [])}
    original_edges = [
        [str(edge[0]), str(edge[1])]
        for edge in component.get("edges", [])
        if isinstance(edge, (list, tuple)) and len(edge) >= 2
    ]
    new_components: list[dict[str, Any]] = []
    for cluster_index, cluster_infos in enumerate(clusters):
        cluster_nodes = {root}
        cluster_child_roots: list[str] = []
        timed_first_values: list[float] = []
        timed_last_values: list[float] = []
        for info in cluster_infos:
            cluster_nodes.update(str(node) for node in info["nodes"])
            cluster_child_roots.append(str(info["child_root"]))
            if info["first_timestamp_sec"] is not None and info["last_timestamp_sec"] is not None:
                timed_first_values.append(float(info["first_timestamp_sec"]))
                timed_last_values.append(float(info["last_timestamp_sec"]))
        cluster_edges = [
            [parent, child]
            for parent, child in original_edges
            if parent in cluster_nodes and child in cluster_nodes
        ]
        if len(cluster_nodes) < 2 or not cluster_edges:
            continue
        new_components.append(
            {
                "task_root": root,
                "nodes": sorted(cluster_nodes),
                "edges": cluster_edges,
                "boundary_nodes": sorted(original_boundary_nodes | {root}),
                "root_temporal_split_applied": True,
                "root_temporal_parent_task_root": root,
                "root_temporal_cluster_index": int(cluster_index),
                "root_temporal_cluster_count": int(len(clusters)),
                "root_temporal_child_roots": cluster_child_roots,
                "root_temporal_component_first_timestamp_sec": min(timed_first_values) if timed_first_values else None,
                "root_temporal_component_last_timestamp_sec": max(timed_last_values) if timed_last_values else None,
                "root_temporal_component_span_minutes": (
                    (max(timed_last_values) - min(timed_first_values)) / 60.0
                    if timed_first_values and timed_last_values
                    else None
                ),
                "root_temporal_root_retained": True,
                "root_temporal_task_root_parent_missing": True,
            }
        )
    if len(new_components) < 2:
        summary["reason"] = "split_components_not_viable"
        return [component], summary
    summary.update(
        {
            "applied": True,
            "cluster_count": len(new_components),
            "initial_cluster_count": int(initial_cluster_count),
            "reason": "split_applied",
        }
    )
    return new_components, summary


def _apply_root_temporal_split(
    edge_list: Any,
    *,
    min_task_nodes: int,
    min_direct_children: int,
    max_span_minutes: int,
    branch_gap_minutes: int,
    session_max_minutes: int,
    max_sessions: int = 0,
) -> Any:
    """Apply root-aware session splitting to TC3 parent-missing task components."""
    if not isinstance(edge_list, dict):
        return edge_list
    task_components = list(edge_list.get("task_components", []))
    subject_time_ranges = edge_list.get("subject_time_ranges", {})
    diagnostics = list(edge_list.get("task_component_diagnostics", []))
    if not task_components or not isinstance(subject_time_ranges, dict):
        return edge_list
    parent_missing_by_root = {
        str(row.get("task_root", "")): bool(row.get("task_root_parent_missing", False))
        for row in diagnostics
        if isinstance(row, dict)
    }
    new_components: list[dict[str, Any]] = []
    split_summaries: list[dict[str, Any]] = []
    applied_count = 0
    for component in task_components:
        root = str(component.get("task_root", ""))
        component_splits, split_summary = _maybe_temporally_split_root_component(
            component,
            subject_time_ranges,
            task_root_parent_missing=parent_missing_by_root.get(root, False),
            min_task_nodes=min_task_nodes,
            min_direct_children=min_direct_children,
            max_span_minutes=max_span_minutes,
            branch_gap_minutes=branch_gap_minutes,
            session_max_minutes=session_max_minutes,
            max_sessions=max_sessions,
        )
        if split_summary.get("applied"):
            applied_count += 1
        new_components.extend(component_splits)
        split_summaries.append(split_summary)
    updated = dict(edge_list)
    updated["root_temporal_split_summary"] = {
        "enabled": True,
        "min_task_nodes": int(min_task_nodes),
        "min_direct_children": int(min_direct_children),
        "max_span_minutes": int(max_span_minutes),
        "branch_gap_minutes": int(branch_gap_minutes),
        "session_max_minutes": int(session_max_minutes),
        "max_sessions": int(max_sessions),
        "input_component_count": len(task_components),
        "output_component_count": len(new_components),
        "split_component_count": int(applied_count),
        "component_summaries": split_summaries,
    }
    if applied_count == 0:
        return updated
    rebuilt_edges: list[list[str]] = []
    edge_seen: set[tuple[str, str]] = set()
    for component in new_components:
        for edge in component.get("edges", []):
            if not isinstance(edge, (list, tuple)) or len(edge) < 2:
                continue
            edge_key = (str(edge[0]), str(edge[1]))
            if edge_key in edge_seen:
                continue
            edge_seen.add(edge_key)
            rebuilt_edges.append([edge_key[0], edge_key[1]])
    updated["edge_list"] = rebuilt_edges
    updated["task_components"] = new_components
    updated["task_component_diagnostics"] = _build_task_component_diagnostics_from_components(
        new_components,
        child_threshold=int(edge_list.get("child_threshold", 0) or 0),
        split_mode=str(edge_list.get("split_mode", "fanout") or "fanout"),
        count_segmented_children_upstream=bool(edge_list.get("count_segmented_children_upstream", False)),
    )
    return updated


def _temporal_episode_gap_seconds(
    timestamps: Sequence[float],
    *,
    mode: str,
    fixed_gap_minutes: int,
    gap_quantile: float,
    mad_multiplier: float,
) -> float | None:
    """Return a robust child-start gap threshold for one parent task component."""
    if len(timestamps) < 2:
        return None
    gaps = [
        max(0.0, float(timestamps[index + 1]) - float(timestamps[index]))
        for index in range(len(timestamps) - 1)
    ]
    positive_gaps = [gap for gap in gaps if gap > 0.0]
    if not positive_gaps:
        return None
    normalized_mode = str(mode or "median_mad").strip().lower()
    if normalized_mode == "fixed":
        return max(0.0, float(fixed_gap_minutes) * 60.0)
    if normalized_mode == "quantile":
        return float(np.quantile(np.asarray(positive_gaps, dtype=np.float64), np.clip(gap_quantile, 0.0, 1.0)))
    median_gap = float(np.median(np.asarray(positive_gaps, dtype=np.float64)))
    mad_gap = float(np.median(np.abs(np.asarray(positive_gaps, dtype=np.float64) - median_gap)))
    return median_gap + max(0.0, float(mad_multiplier)) * mad_gap


def _coalesce_temporal_episode_groups(
    groups: list[list[dict[str, Any]]],
    *,
    min_children_per_episode: int,
    max_episodes: int,
    budget_strategy: str,
) -> list[list[dict[str, Any]]]:
    """Merge only adjacent groups so temporal order and task locality are preserved."""
    output = [list(group) for group in groups if group]
    minimum = max(1, int(min_children_per_episode))
    while len(output) > 1:
        small_index = next((index for index, group in enumerate(output) if len(group) < minimum), None)
        if small_index is None:
            break
        if small_index == 0:
            output[1] = output[0] + output[1]
            del output[0]
        else:
            output[small_index - 1].extend(output[small_index])
            del output[small_index]
    if max_episodes > 0 and len(output) > int(max_episodes):
        if str(budget_strategy or "adjacent_greedy").strip().lower() == "balanced_child_count":
            # When a burst yields thousands of tiny time clusters, preserve the
            # child-start order but distribute branches evenly across the fixed
            # episode budget.  This avoids one residual giant task.
            ordered = [info for group in output for info in group]
            width = max(1, math.ceil(len(ordered) / int(max_episodes)))
            return [ordered[index:index + width] for index in range(0, len(ordered), width)]
        while len(output) > int(max_episodes):
            merge_index = min(
                range(len(output) - 1),
                key=lambda index: len(output[index]) + len(output[index + 1]),
            )
            output[merge_index].extend(output[merge_index + 1])
            del output[merge_index + 1]
    return output


def _maybe_temporally_split_component_by_child_start(
    component: dict[str, Any],
    subject_time_ranges: dict[str, Any],
    *,
    task_root_parent_missing: bool,
    parent_missing_only: bool,
    min_task_nodes: int,
    min_direct_children: int,
    min_span_minutes: int,
    gap_mode: str,
    fixed_gap_minutes: int,
    gap_quantile: float,
    mad_multiplier: float,
    min_children_per_episode: int,
    max_episodes: int,
    budget_strategy: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Partition a high-fanout task by direct-child start episodes.

    Unlike the older root-session experiment, clustering uses each direct
    child's own first observed event.  Descendant activity is intentionally
    excluded from the clustering clock so a long-lived child cannot bridge two
    independent parent episodes.
    """
    root = str(component.get("task_root", "")).strip()
    nodes = [str(node) for node in component.get("nodes", [])]
    summary: dict[str, Any] = {
        "applied": False,
        "task_root": root,
        "input_task_size": len(nodes),
        "reason": "component_not_eligible",
    }
    if not root:
        summary["reason"] = "missing_task_root"
        return [component], summary
    if parent_missing_only and not task_root_parent_missing:
        summary["reason"] = "root_has_known_parent"
        return [component], summary
    if len(nodes) < int(min_task_nodes):
        summary["reason"] = "below_min_task_nodes"
        return [component], summary

    children_map = _component_children_map(component)
    direct_children = list(dict.fromkeys(children_map.get(root, [])))
    if len(direct_children) < int(min_direct_children):
        summary["reason"] = "below_min_direct_children"
        return [component], summary

    timed_infos: list[dict[str, Any]] = []
    untimed_infos: list[dict[str, Any]] = []
    for child in direct_children:
        child_id = str(child)
        row = subject_time_ranges.get(child_id)
        child_start = _float_or_none(row.get("first_timestamp_sec")) if isinstance(row, dict) else None
        info = {
            "child_root": child_id,
            "nodes": _collect_component_subtree(child_id, children_map),
            "first_timestamp_sec": child_start,
        }
        if child_start is None:
            untimed_infos.append(info)
        else:
            timed_infos.append(info)
    if len(timed_infos) < 2:
        summary["reason"] = "insufficient_timed_children"
        return [component], summary

    timed_infos.sort(key=lambda info: (float(info["first_timestamp_sec"]), str(info["child_root"])))
    timestamps = [float(info["first_timestamp_sec"]) for info in timed_infos]
    span_seconds = timestamps[-1] - timestamps[0]
    summary["timed_direct_child_count"] = len(timed_infos)
    summary["untimed_direct_child_count"] = len(untimed_infos)
    summary["child_start_span_minutes"] = span_seconds / 60.0
    if span_seconds < max(0, int(min_span_minutes)) * 60.0:
        summary["reason"] = "within_min_child_start_span"
        return [component], summary

    gap_seconds = _temporal_episode_gap_seconds(
        timestamps,
        mode=gap_mode,
        fixed_gap_minutes=fixed_gap_minutes,
        gap_quantile=gap_quantile,
        mad_multiplier=mad_multiplier,
    )
    if gap_seconds is None or gap_seconds <= 0.0:
        summary["reason"] = "no_positive_gap_threshold"
        return [component], summary

    raw_groups: list[list[dict[str, Any]]] = [[timed_infos[0]]]
    for previous, current in zip(timed_infos, timed_infos[1:]):
        gap = float(current["first_timestamp_sec"]) - float(previous["first_timestamp_sec"])
        if gap > gap_seconds:
            raw_groups.append([current])
        else:
            raw_groups[-1].append(current)
    if len(raw_groups) < 2:
        summary.update({"reason": "single_temporal_episode", "gap_threshold_minutes": gap_seconds / 60.0})
        return [component], summary

    # Keep missing timestamps in one deterministic group and coalesce it below;
    # this preserves every branch without using a fabricated time value.
    if untimed_infos:
        raw_groups.append(untimed_infos)
    groups = _coalesce_temporal_episode_groups(
        raw_groups,
        min_children_per_episode=min_children_per_episode,
        max_episodes=max_episodes,
        budget_strategy=budget_strategy,
    )
    if len(groups) < 2:
        summary.update({"reason": "groups_coalesced_to_one", "gap_threshold_minutes": gap_seconds / 60.0})
        return [component], summary

    original_boundary_nodes = {str(node) for node in component.get("boundary_nodes", [])}
    original_edges = [
        [str(edge[0]), str(edge[1])]
        for edge in component.get("edges", [])
        if isinstance(edge, (list, tuple)) and len(edge) >= 2
    ]
    output: list[dict[str, Any]] = []
    for episode_index, infos in enumerate(groups):
        episode_nodes = {root}
        child_roots: list[str] = []
        child_times: list[float] = []
        for info in infos:
            episode_nodes.update(str(node) for node in info["nodes"])
            child_roots.append(str(info["child_root"]))
            if info["first_timestamp_sec"] is not None:
                child_times.append(float(info["first_timestamp_sec"]))
        episode_edges = [
            [parent, child]
            for parent, child in original_edges
            if parent in episode_nodes and child in episode_nodes
        ]
        if len(episode_nodes) < 2 or not episode_edges:
            continue
        output.append(
            {
                "task_root": root,
                "nodes": sorted(episode_nodes),
                "edges": episode_edges,
                "boundary_nodes": sorted(original_boundary_nodes | {root}),
                "temporal_episode_split_applied": True,
                "temporal_episode_parent_task_root": root,
                "temporal_episode_index": int(episode_index),
                "temporal_episode_count": int(len(groups)),
                "temporal_episode_child_roots": child_roots,
                "temporal_episode_first_child_timestamp_sec": min(child_times) if child_times else None,
                "temporal_episode_last_child_timestamp_sec": max(child_times) if child_times else None,
                "temporal_episode_child_span_minutes": (
                    (max(child_times) - min(child_times)) / 60.0 if len(child_times) >= 2 else 0.0
                ),
                "temporal_episode_root_retained": True,
            }
        )
    if len(output) < 2:
        summary["reason"] = "split_components_not_viable"
        return [component], summary
    summary.update(
        {
            "applied": True,
            "reason": "split_applied",
            "gap_threshold_minutes": gap_seconds / 60.0,
            "raw_episode_count": len(raw_groups),
            "episode_count": len(output),
        }
    )
    return output, summary


def _apply_temporal_episode_split(
    edge_list: Any,
    *,
    parent_missing_only: bool,
    min_task_nodes: int,
    min_direct_children: int,
    min_span_minutes: int,
    gap_mode: str,
    fixed_gap_minutes: int,
    gap_quantile: float,
    mad_multiplier: float,
    min_children_per_episode: int,
    max_episodes: int,
    budget_strategy: str,
) -> Any:
    """Apply bounded LogKernel-inspired child-start segmentation to TC3 tasks."""
    if not isinstance(edge_list, dict):
        return edge_list
    task_components = list(edge_list.get("task_components", []))
    subject_time_ranges = edge_list.get("subject_time_ranges", {})
    diagnostics = list(edge_list.get("task_component_diagnostics", []))
    if not task_components or not isinstance(subject_time_ranges, dict):
        return edge_list
    parent_missing_by_root = {
        str(row.get("task_root", "")): bool(row.get("task_root_parent_missing", False))
        for row in diagnostics
        if isinstance(row, dict)
    }
    output: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    applied_count = 0
    for component in task_components:
        root = str(component.get("task_root", ""))
        splits, summary = _maybe_temporally_split_component_by_child_start(
            component,
            subject_time_ranges,
            task_root_parent_missing=parent_missing_by_root.get(root, False),
            parent_missing_only=parent_missing_only,
            min_task_nodes=min_task_nodes,
            min_direct_children=min_direct_children,
            min_span_minutes=min_span_minutes,
            gap_mode=gap_mode,
            fixed_gap_minutes=fixed_gap_minutes,
            gap_quantile=gap_quantile,
            mad_multiplier=mad_multiplier,
            min_children_per_episode=min_children_per_episode,
            max_episodes=max_episodes,
            budget_strategy=budget_strategy,
        )
        if summary.get("applied"):
            applied_count += 1
        output.extend(splits)
        summaries.append(summary)
    updated = dict(edge_list)
    updated["temporal_episode_split_summary"] = {
        "enabled": True,
        "parent_missing_only": bool(parent_missing_only),
        "min_task_nodes": int(min_task_nodes),
        "min_direct_children": int(min_direct_children),
        "min_span_minutes": int(min_span_minutes),
        "gap_mode": str(gap_mode),
        "fixed_gap_minutes": int(fixed_gap_minutes),
        "gap_quantile": float(gap_quantile),
        "mad_multiplier": float(mad_multiplier),
        "min_children_per_episode": int(min_children_per_episode),
        "max_episodes": int(max_episodes),
        "budget_strategy": str(budget_strategy),
        "input_component_count": len(task_components),
        "output_component_count": len(output),
        "split_component_count": int(applied_count),
        "component_summaries": summaries,
    }
    if applied_count == 0:
        return updated
    rebuilt_edges: list[list[str]] = []
    edge_seen: set[tuple[str, str]] = set()
    for component in output:
        for edge in component.get("edges", []):
            if not isinstance(edge, (list, tuple)) or len(edge) < 2:
                continue
            edge_key = (str(edge[0]), str(edge[1]))
            if edge_key not in edge_seen:
                edge_seen.add(edge_key)
                rebuilt_edges.append([edge_key[0], edge_key[1]])
    updated["edge_list"] = rebuilt_edges
    updated["task_components"] = output
    updated["task_component_diagnostics"] = _build_task_component_diagnostics_from_components(
        output,
        child_threshold=int(edge_list.get("child_threshold", 0) or 0),
        split_mode=str(edge_list.get("split_mode", "fanout") or "fanout"),
        count_segmented_children_upstream=bool(edge_list.get("count_segmented_children_upstream", False)),
    )
    return updated


def _maybe_isolate_synthetic_root_component(
    component: dict[str, Any],
    *,
    task_root_parent_missing: bool,
    subject_start_timestamps: dict[str, Any],
    min_task_nodes: int,
    min_direct_children: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Replace an oversized parent-missing collector root with child tasks.

    TC3 CADETS contains parentless, zero-start synthetic subjects that collect
    many unrelated services.  They are ingestion boundaries, not processes
    that coordinate a common task, so their direct child subtrees are emitted
    independently while retaining the root as a boundary-only node.
    """
    root = str(component.get("task_root", "")).strip()
    children_map = _component_children_map(component)
    direct_children = list(dict.fromkeys(children_map.get(root, [])))
    summary = {
        "task_root": root,
        "input_task_size": len(component.get("nodes", [])),
        "direct_child_count": len(direct_children),
        "applied": False,
        "reason": "not_parent_missing",
    }
    if not task_root_parent_missing:
        return [component], summary
    root_start_timestamp = subject_start_timestamps.get(root)
    try:
        is_synthetic_start = int(root_start_timestamp) == 0
    except (TypeError, ValueError):
        is_synthetic_start = False
    if not is_synthetic_start:
        summary["reason"] = "root_start_not_zero"
        return [component], summary
    if len(component.get("nodes", [])) < int(min_task_nodes):
        summary["reason"] = "below_min_task_nodes"
        return [component], summary
    if len(direct_children) < int(min_direct_children):
        summary["reason"] = "below_min_direct_children"
        return [component], summary

    original_edges = [
        [str(edge[0]), str(edge[1])]
        for edge in component.get("edges", [])
        if isinstance(edge, (list, tuple)) and len(edge) >= 2
    ]
    original_boundary_nodes = {str(node) for node in component.get("boundary_nodes", [])}
    new_components: list[dict[str, Any]] = []
    skipped_boundary_children = 0
    for child in direct_children:
        # A segmented child already has its own component.  Do not create a
        # root-only duplicate of that component.
        if child in original_boundary_nodes:
            skipped_boundary_children += 1
            continue
        branch_nodes = _collect_component_subtree(child, children_map)
        branch_nodes.add(root)
        branch_edges = [
            [parent, descendant]
            for parent, descendant in original_edges
            if parent in branch_nodes and descendant in branch_nodes
        ]
        if len(branch_nodes) < 2 or not branch_edges:
            continue
        new_components.append(
            {
                "task_root": child,
                "nodes": sorted(branch_nodes),
                "edges": branch_edges,
                "boundary_nodes": sorted(original_boundary_nodes | {root}),
                "synthetic_root_isolation_applied": True,
                "synthetic_root_isolation_parent_root": root,
                "synthetic_root_isolation_child_root": child,
                "synthetic_root_isolation_direct_child_count": len(direct_children),
                "synthetic_root_isolation_parent_task_size": len(component.get("nodes", [])),
            }
        )
    if len(new_components) < 2:
        summary["reason"] = "isolated_components_not_viable"
        return [component], summary
    summary.update(
        {
            "applied": True,
            "reason": "synthetic_root_isolated",
            "output_component_count": len(new_components),
            "skipped_existing_boundary_children": skipped_boundary_children,
        }
    )
    return new_components, summary


def _apply_synthetic_root_isolation(
    edge_list: Any,
    *,
    min_task_nodes: int,
    min_direct_children: int,
) -> Any:
    """Isolate direct child branches beneath synthetic CADETS collector roots."""
    if not isinstance(edge_list, dict):
        return edge_list
    task_components = list(edge_list.get("task_components", []))
    diagnostics = list(edge_list.get("task_component_diagnostics", []))
    subject_start_timestamps = edge_list.get("subject_start_timestamps", {})
    if not task_components:
        return edge_list
    if not isinstance(subject_start_timestamps, dict):
        return edge_list
    parent_missing_by_root = {
        str(row.get("task_root", "")): bool(row.get("task_root_parent_missing", False))
        for row in diagnostics
        if isinstance(row, dict)
    }
    new_components: list[dict[str, Any]] = []
    component_summaries: list[dict[str, Any]] = []
    applied_count = 0
    for component in task_components:
        root = str(component.get("task_root", ""))
        isolated_components, summary = _maybe_isolate_synthetic_root_component(
            component,
            task_root_parent_missing=parent_missing_by_root.get(root, False),
            subject_start_timestamps=subject_start_timestamps,
            min_task_nodes=min_task_nodes,
            min_direct_children=min_direct_children,
        )
        if summary.get("applied"):
            applied_count += 1
        new_components.extend(isolated_components)
        component_summaries.append(summary)

    updated = dict(edge_list)
    updated["synthetic_root_isolation_summary"] = {
        "enabled": True,
        "min_task_nodes": int(min_task_nodes),
        "min_direct_children": int(min_direct_children),
        "input_component_count": len(task_components),
        "output_component_count": len(new_components),
        "split_component_count": int(applied_count),
        "component_summaries": component_summaries,
    }
    if applied_count == 0:
        return updated

    rebuilt_edges: list[list[str]] = []
    edge_seen: set[tuple[str, str]] = set()
    for component in new_components:
        for edge in component.get("edges", []):
            if not isinstance(edge, (list, tuple)) or len(edge) < 2:
                continue
            edge_key = (str(edge[0]), str(edge[1]))
            if edge_key not in edge_seen:
                edge_seen.add(edge_key)
                rebuilt_edges.append([edge_key[0], edge_key[1]])
    updated["edge_list"] = rebuilt_edges
    updated["task_components"] = new_components
    updated["task_component_diagnostics"] = _build_task_component_diagnostics_from_components(
        new_components,
        child_threshold=int(edge_list.get("child_threshold", 0) or 0),
        split_mode=str(edge_list.get("split_mode", "fanout") or "fanout"),
        count_segmented_children_upstream=bool(edge_list.get("count_segmented_children_upstream", False)),
    )
    return updated


_SYSTEM_EXECUTABLE_PREFIXES = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/local/libexec/",
    "/lib/",
    "/lib64/",
)


def _is_rare_non_system_execute_target(path: str) -> bool:
    """Keep executable targets outside common operating-system binary locations."""
    normalized = str(path or "").strip()
    return bool(normalized) and normalized.lower() != "unknow" and not normalized.startswith(
        _SYSTEM_EXECUTABLE_PREFIXES
    )


def _apply_selective_synthetic_root_isolation(
    edge_list: Any,
    *,
    min_task_nodes: int,
    min_direct_children: int,
    max_exec_target_frequency: int,
) -> Any:
    """Extract rare executable branches while retaining the synthetic-root remainder.

    The all-child split is intentionally avoided: CADETS collector roots contain
    large numbers of unrelated normal service branches.  Only a direct subtree
    that executes a rare target outside normal system binary locations becomes a
    separate candidate task.
    """
    if not isinstance(edge_list, dict):
        return edge_list
    task_components = list(edge_list.get("task_components", []))
    diagnostics = list(edge_list.get("task_component_diagnostics", []))
    subject_starts = edge_list.get("subject_start_timestamps", {})
    execute_targets = edge_list.get("canonical_execute_targets", {})
    if not task_components or not isinstance(subject_starts, dict) or not isinstance(execute_targets, dict):
        return edge_list
    parent_missing_by_root = {
        str(row.get("task_root", "")): bool(row.get("task_root_parent_missing", False))
        for row in diagnostics
        if isinstance(row, dict)
    }
    output_components: list[dict[str, Any]] = []
    component_summaries: list[dict[str, Any]] = []
    applied_count = 0
    for component in task_components:
        root = str(component.get("task_root", "")).strip()
        children_map = _component_children_map(component)
        direct_children = list(dict.fromkeys(children_map.get(root, [])))
        summary: dict[str, Any] = {
            "task_root": root,
            "input_task_size": len(component.get("nodes", [])),
            "direct_child_count": len(direct_children),
            "applied": False,
            "reason": "not_parent_missing",
        }
        try:
            root_is_synthetic = int(subject_starts.get(root)) == 0
        except (TypeError, ValueError):
            root_is_synthetic = False
        if (
            not parent_missing_by_root.get(root, False)
            or not root_is_synthetic
            or len(component.get("nodes", [])) < int(min_task_nodes)
            or len(direct_children) < int(min_direct_children)
        ):
            if not parent_missing_by_root.get(root, False):
                summary["reason"] = "not_parent_missing"
            elif not root_is_synthetic:
                summary["reason"] = "root_start_not_zero"
            elif len(component.get("nodes", [])) < int(min_task_nodes):
                summary["reason"] = "below_min_task_nodes"
            else:
                summary["reason"] = "below_min_direct_children"
            output_components.append(component)
            component_summaries.append(summary)
            continue

        branch_nodes_by_child = {
            child: _collect_component_subtree(child, children_map) for child in direct_children
        }
        target_frequency: dict[str, int] = {}
        for branch_nodes in branch_nodes_by_child.values():
            for node in branch_nodes:
                for target, count in dict(execute_targets.get(str(node), {})).items():
                    target = str(target)
                    if _is_rare_non_system_execute_target(target):
                        target_frequency[target] = target_frequency.get(target, 0) + int(count)
        boundary_nodes = {str(node) for node in component.get("boundary_nodes", [])}
        selected: list[tuple[str, set[str], list[str]]] = []
        for child, branch_nodes in branch_nodes_by_child.items():
            if child in boundary_nodes:
                continue
            targets = sorted(
                {
                    str(target)
                    for node in branch_nodes
                    for target in dict(execute_targets.get(str(node), {}))
                    if _is_rare_non_system_execute_target(str(target))
                    and target_frequency.get(str(target), 0) <= int(max_exec_target_frequency)
                }
            )
            if targets:
                selected.append((child, branch_nodes, targets))
        if not selected:
            summary["reason"] = "no_rare_non_system_execute_branch"
            output_components.append(component)
            component_summaries.append(summary)
            continue

        original_edges = [
            [str(edge[0]), str(edge[1])]
            for edge in component.get("edges", [])
            if isinstance(edge, (list, tuple)) and len(edge) >= 2
        ]
        selected_nodes = set().union(*(nodes for _, nodes, _ in selected))
        remaining_nodes = {str(node) for node in component.get("nodes", [])} - selected_nodes
        remaining_nodes.add(root)
        remaining_edges = [edge for edge in original_edges if edge[0] in remaining_nodes and edge[1] in remaining_nodes]
        emitted: list[dict[str, Any]] = []
        if len(remaining_nodes) >= 2 and remaining_edges:
            remainder = dict(component)
            remainder["nodes"] = sorted(remaining_nodes)
            remainder["edges"] = remaining_edges
            remainder["synthetic_root_selective_isolation_applied"] = True
            remainder["synthetic_root_selective_isolation_role"] = "remainder"
            emitted.append(remainder)
        for child, branch_nodes, targets in selected:
            branch_with_root = set(branch_nodes)
            branch_with_root.add(root)
            branch_edges = [edge for edge in original_edges if edge[0] in branch_with_root and edge[1] in branch_with_root]
            if len(branch_with_root) >= 2 and branch_edges:
                emitted.append(
                    {
                        "task_root": child,
                        "nodes": sorted(branch_with_root),
                        "edges": branch_edges,
                        "boundary_nodes": sorted(boundary_nodes | {root}),
                        "synthetic_root_selective_isolation_applied": True,
                        "synthetic_root_selective_isolation_role": "rare_execute_branch",
                        "synthetic_root_selective_isolation_parent_root": root,
                        "synthetic_root_selective_isolation_targets": targets,
                    }
                )
        if len(emitted) < 2:
            summary["reason"] = "selective_components_not_viable"
            output_components.append(component)
        else:
            summary.update(
                {
                    "applied": True,
                    "reason": "rare_non_system_execute_branch_isolated",
                    "selected_branch_count": len(emitted) - 1,
                    "selected_targets": sorted({target for _, _, targets in selected for target in targets}),
                }
            )
            output_components.extend(emitted)
            applied_count += 1
        component_summaries.append(summary)

    updated = dict(edge_list)
    updated["synthetic_root_selective_isolation_summary"] = {
        "enabled": True,
        "max_exec_target_frequency": int(max_exec_target_frequency),
        "input_component_count": len(task_components),
        "output_component_count": len(output_components),
        "split_component_count": int(applied_count),
        "component_summaries": component_summaries,
    }
    if applied_count == 0:
        return updated
    rebuilt_edges: list[list[str]] = []
    seen_edges: set[tuple[str, str]] = set()
    for component in output_components:
        for edge in component.get("edges", []):
            if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                edge_key = (str(edge[0]), str(edge[1]))
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    rebuilt_edges.append([edge_key[0], edge_key[1]])
    updated["edge_list"] = rebuilt_edges
    updated["task_components"] = output_components
    updated["task_component_diagnostics"] = _build_task_component_diagnostics_from_components(
        output_components,
        child_threshold=int(edge_list.get("child_threshold", 0) or 0),
        split_mode=str(edge_list.get("split_mode", "fanout") or "fanout"),
        count_segmented_children_upstream=bool(edge_list.get("count_segmented_children_upstream", False)),
    )
    return updated


def _apply_branch_object_overlap_split(edge_list: Any) -> Any:
    """Split root child subtrees unless they share at least one observed object.

    An inverted object-to-branch index drives union-find connectivity, so each
    branch object is visited once instead of comparing every pair of branches.
    """
    if not isinstance(edge_list, dict):
        return edge_list
    task_components = list(edge_list.get("task_components", []))
    subject_object_ids = edge_list.get("canonical_subject_object_ids", {})
    if not task_components or not isinstance(subject_object_ids, dict):
        return edge_list

    output_components: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    split_component_count = 0
    for component in task_components:
        root = str(component.get("task_root", "")).strip()
        children_map = _component_children_map(component)
        direct_children = list(dict.fromkeys(children_map.get(root, [])))
        summary: dict[str, Any] = {
            "task_root": root,
            "input_task_size": len(component.get("nodes", [])),
            "direct_child_count": len(direct_children),
            "applied": False,
        }
        if len(direct_children) < 2:
            summary["reason"] = "fewer_than_two_direct_branches"
            output_components.append(component)
            summaries.append(summary)
            continue

        branch_nodes = [_collect_component_subtree(child, children_map) for child in direct_children]
        parent = list(range(len(direct_children)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(left: int, right: int) -> None:
            left_root = find(left)
            right_root = find(right)
            if left_root != right_root:
                parent[right_root] = left_root

        object_owner: dict[str, int] = {}
        branch_object_count = 0
        for branch_index, nodes in enumerate(branch_nodes):
            objects = {
                str(object_id)
                for node in nodes
                for object_id in subject_object_ids.get(str(node), [])
                if str(object_id)
            }
            branch_object_count += len(objects)
            for object_id in objects:
                previous_owner = object_owner.get(object_id)
                if previous_owner is None:
                    object_owner[object_id] = branch_index
                else:
                    union(branch_index, previous_owner)

        groups: dict[int, list[int]] = {}
        for branch_index in range(len(direct_children)):
            groups.setdefault(find(branch_index), []).append(branch_index)
        if len(groups) < 2:
            summary.update(
                {
                    "reason": "all_direct_branches_connected_by_objects",
                    "object_association_count": branch_object_count,
                }
            )
            output_components.append(component)
            summaries.append(summary)
            continue

        original_edges = [
            [str(edge[0]), str(edge[1])]
            for edge in component.get("edges", [])
            if isinstance(edge, (list, tuple)) and len(edge) >= 2
        ]
        original_nodes = {str(node) for node in component.get("nodes", [])}
        branch_node_union = set().union(*branch_nodes)
        unassigned_nodes = original_nodes - branch_node_union - {root}
        boundary_nodes = {str(node) for node in component.get("boundary_nodes", [])}
        emitted: list[dict[str, Any]] = []
        for group_index, branch_indexes in enumerate(groups.values()):
            nodes = {root}
            for branch_index in branch_indexes:
                nodes.update(branch_nodes[branch_index])
            # Preserve any atypical node that is not beneath a direct child.
            if group_index == 0:
                nodes.update(unassigned_nodes)
            edges = [edge for edge in original_edges if edge[0] in nodes and edge[1] in nodes]
            if len(nodes) < 2 or not edges:
                continue
            emitted.append(
                {
                    "task_root": root,
                    "nodes": sorted(nodes),
                    "edges": edges,
                    "boundary_nodes": sorted(boundary_nodes | {root}),
                    "branch_object_overlap_split_applied": True,
                    "branch_object_overlap_parent_task_root": root,
                    "branch_object_overlap_group_index": group_index,
                    "branch_object_overlap_group_count": len(groups),
                    "branch_object_overlap_child_roots": [direct_children[index] for index in branch_indexes],
                }
            )
        if len(emitted) < 2:
            summary["reason"] = "split_components_not_viable"
            output_components.append(component)
        else:
            summary.update(
                {
                    "applied": True,
                    "reason": "disconnected_direct_branches_split",
                    "output_component_count": len(emitted),
                    "object_association_count": branch_object_count,
                    "distinct_object_count": len(object_owner),
                }
            )
            output_components.extend(emitted)
            split_component_count += 1
        summaries.append(summary)

    updated = dict(edge_list)
    updated["branch_object_overlap_split_summary"] = {
        "enabled": True,
        "input_component_count": len(task_components),
        "output_component_count": len(output_components),
        "split_component_count": split_component_count,
        "component_summaries": summaries,
    }
    if split_component_count == 0:
        return updated
    seen_edges: set[tuple[str, str]] = set()
    rebuilt_edges: list[list[str]] = []
    for component in output_components:
        for edge in component.get("edges", []):
            if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                edge_key = (str(edge[0]), str(edge[1]))
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    rebuilt_edges.append([edge_key[0], edge_key[1]])
    updated["edge_list"] = rebuilt_edges
    updated["task_components"] = output_components
    updated["task_component_diagnostics"] = _build_task_component_diagnostics_from_components(
        output_components,
        child_threshold=int(edge_list.get("child_threshold", 0) or 0),
        split_mode=str(edge_list.get("split_mode", "fanout") or "fanout"),
        count_segmented_children_upstream=bool(edge_list.get("count_segmented_children_upstream", False)),
    )
    return updated


def _stage_optc_logs_exact(cfg: FusionConfig, workspace: Path, vendor_module: ModuleType, require_all_hosts: bool) -> None:
    optc_root = workspace / "data" / "optc"
    logs_root = optc_root / "logs"
    ensure_dir(optc_root)
    ensure_dir(logs_root)
    vendor_module.data_path = str(optc_root) + os.sep
    source = cfg.source_logs

    copied_gz = False

    def copy_extracted(candidate: Path) -> None:
        if candidate.is_file() and "SysClient" in candidate.name:
            shutil.copy2(candidate, optc_root / candidate.name)

    if source.is_dir():
        for candidate in source.iterdir():
            if not candidate.is_file():
                continue
            lower_name = candidate.name.lower()
            if lower_name.endswith(".json.gz"):
                shutil.copy2(candidate, logs_root / candidate.name)
                copied_gz = True
            elif lower_name.endswith(".txt") or lower_name.endswith(".json"):
                copy_extracted(candidate)
    elif source.is_file():
        lower_name = source.name.lower()
        if lower_name.endswith(".json.gz"):
            if require_all_hosts:
                raise ValueError(
                    "Exact TAPAS OpTC fit_predict mode requires the full official log directory, not a single .json.gz file."
                )
            shutil.copy2(source, logs_root / source.name)
            copied_gz = True
        elif lower_name.endswith(".txt") or lower_name.endswith(".json"):
            if require_all_hosts:
                raise ValueError(
                    "Exact TAPAS OpTC fit_predict mode requires all three official hosts. Please point source_logs to the full log directory."
                )
            copy_extracted(source)
        else:
            raise ValueError("Exact TAPAS OpTC mode expects source_logs to be a directory, .json.gz, .txt, or .json.")
    else:
        raise FileNotFoundError(f"source_logs not found: {source}")

    if copied_gz:
        with _temporary_cwd(workspace):
            vendor_module.Extract_logs()

    required_hosts = _OFFICIAL_OPTC_HOSTS if require_all_hosts else [_optc_eval_dataset_name(cfg.host)]
    for host_id in required_hosts:
        if host_id == "data_all":
            continue
        expected = optc_root / _expected_optc_filename(host_id)
        if not expected.exists():
            raise FileNotFoundError(
                f"Exact TAPAS OpTC mode expected {expected} after staging logs, but it was not found."
            )


def _build_tc3_bundle(cfg: FusionConfig, module1_dir: Path) -> dict[str, Any]:
    if cfg.host not in _tc3_supported_hosts():
        raise ValueError(
            f"Unsupported TAPAS tc3 host '{cfg.host}'. Expected one of {sorted(_tc3_supported_hosts())}."
        )

    workspace = _ensure_workspace(module1_dir, cfg)
    vendor = _load_vendor_module("tapas_vendor_darpa_exact_module1", _vendor_tapas_root() / "darpa.py")
    vendor.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ground_truth = _load_ground_truth(cfg.task_ground_truth_path)
    theia_e5_entity_types = _load_theia_e5_ground_truth_entity_types(cfg.task_ground_truth_path) if cfg.host == "theia_e5" else {}
    task_component_kwargs = {
        "child_threshold": int(cfg.task_component_child_threshold),
        "split_mode": str(cfg.task_component_split_mode),
        "count_segmented_children_upstream": bool(cfg.task_component_count_segmented_children_upstream),
    }
    use_release_legacy_cut = bool(cfg.task_tapas_release_legacy_cut_logic)

    with _temporary_cwd(workspace):
        source_logs = _normalize_tc3_source_logs(cfg.source_logs)
        parser_metadata: dict[str, Any] = {}
        # THEIA filters() returns embeddings directly and has no parser-level
        # event-count sidecar.  Keep the generic stats fallback available.
        event_count: dict[object, object] | None = None
        if cfg.host == "cadets":
            subject_list, object_list, event_count, parser_metadata = vendor.parser_cadets(
                source_logs,
                collect_subject_object_ids=bool(cfg.task_component_branch_object_overlap_split_enabled),
            )
            subject_node = vendor.encode_cadets(subject_list, object_list, event_count)
            if use_release_legacy_cut:
                edge_list = vendor.cut_task(subject_list, use_release_legacy=True)
            else:
                edge_list = vendor.cut_task(subject_list, return_task_components=True, **task_component_kwargs)
            raw_vectors = vendor.get_node_vec(subject_node)
        elif cfg.host == "fivedirections":
            subject_list, object_list, event_count, parser_metadata = vendor.parser_fivedirections(source_logs)
            subject_node = vendor.encode_fivedirections(subject_list, object_list, event_count)
            edge_list = vendor.cut_task(subject_list, return_task_components=True, **task_component_kwargs)
            raw_vectors = vendor.get_node_vec(subject_node)
        elif cfg.host == "trace":
            subject_list, object_list, event_count, parser_metadata = vendor.parser_trace(
                source_logs,
                collect_subject_object_ids=bool(cfg.task_component_branch_object_overlap_split_enabled),
            )
            subject_node = vendor.encode_trace(subject_list, object_list, event_count)
            edge_list = vendor.cut_task(subject_list, return_task_components=True, **task_component_kwargs)
            raw_vectors = vendor.get_node_vec(subject_node)
        elif cfg.host == "theia":
            edge_list, raw_vectors = vendor.filters(source_logs, return_task_components=True, **task_component_kwargs)
            parser_metadata = copy.deepcopy(edge_list.get("parser_metadata", {}))
            if bool(cfg.task_component_theia_temporal_split_enabled):
                edge_list = _apply_theia_temporal_split(
                    edge_list,
                    max_span_minutes=int(cfg.task_component_theia_max_span_minutes),
                    branch_gap_minutes=int(cfg.task_component_theia_branch_gap_minutes),
                )
        elif cfg.host == "theia_e5":
            direct_subject_ground_truth = {
                uuid
                for uuid, entity_type in theia_e5_entity_types.items()
                if entity_type == "subject"
            }
            object_ground_truth = {
                uuid
                for uuid, entity_type in theia_e5_entity_types.items()
                if entity_type in {"file", "netflow"}
            }
            edge_list, raw_vectors = vendor.filters_theia_e5(
                source_logs,
                return_task_components=True,
                ground_truth_object_uuids=object_ground_truth,
                **task_component_kwargs,
            )
            parser_metadata = copy.deepcopy(edge_list.get("parser_metadata", {}))
            ground_truth = direct_subject_ground_truth
        else:
            edge_list, raw_vectors = vendor.filters(source_logs, **task_component_kwargs)
    if bool(cfg.task_component_provgrp_behavior_partition_enabled):
        if cfg.host not in {"cadets", "trace", "theia"}:
            raise ValueError("ProvGRP paper partition currently supports tc3/cadets, trace, and theia")
        if not isinstance(edge_list, dict) or "task_components" not in edge_list:
            raise ValueError(
                "ProvGRP paper partition requires TAPAS task components; "
                "disable task_tapas_release_legacy_cut_logic."
            )
        edge_list = apply_provgrp_paper_partition_to_edge_list(
            edge_list,
            source_logs=source_logs,
            raw_subject_to_canonical_node=parser_metadata.get("raw_subject_to_canonical_node", {}),
            min_direct_children=int(cfg.task_component_provgrp_min_direct_children),
            min_cluster_size=int(cfg.task_component_provgrp_min_cluster_size),
            min_samples=int(cfg.task_component_provgrp_min_samples),
            max_events_per_matrix=int(cfg.task_component_provgrp_max_events_per_matrix),
            batch_overlap_events=int(cfg.task_component_provgrp_batch_overlap_events),
        )
    subject_time_ranges = parser_metadata.pop("canonical_subject_time_ranges", {})
    if (
        cfg.host in {"cadets", "trace"}
        and bool(cfg.task_component_root_temporal_split_enabled)
        and isinstance(edge_list, dict)
    ):
        edge_list = dict(edge_list)
        edge_list["subject_time_ranges"] = subject_time_ranges
        edge_list = _apply_root_temporal_split(
            edge_list,
            min_task_nodes=int(cfg.task_component_root_temporal_min_task_nodes),
            min_direct_children=int(cfg.task_component_root_temporal_min_direct_children),
            max_span_minutes=int(cfg.task_component_root_temporal_max_span_minutes),
            branch_gap_minutes=int(cfg.task_component_root_temporal_branch_gap_minutes),
            session_max_minutes=int(cfg.task_component_root_temporal_session_max_minutes),
            max_sessions=int(cfg.task_component_root_temporal_max_sessions),
        )
    if (
        cfg.host in {"cadets", "trace"}
        and bool(cfg.task_component_temporal_episode_split_enabled)
        and isinstance(edge_list, dict)
    ):
        edge_list = dict(edge_list)
        edge_list["subject_time_ranges"] = subject_time_ranges
        edge_list = _apply_temporal_episode_split(
            edge_list,
            parent_missing_only=bool(cfg.task_component_temporal_episode_parent_missing_only),
            min_task_nodes=int(cfg.task_component_temporal_episode_min_task_nodes),
            min_direct_children=int(cfg.task_component_temporal_episode_min_direct_children),
            min_span_minutes=int(cfg.task_component_temporal_episode_min_span_minutes),
            gap_mode=str(cfg.task_component_temporal_episode_gap_mode),
            fixed_gap_minutes=int(cfg.task_component_temporal_episode_fixed_gap_minutes),
            gap_quantile=float(cfg.task_component_temporal_episode_gap_quantile),
            mad_multiplier=float(cfg.task_component_temporal_episode_mad_multiplier),
            min_children_per_episode=int(cfg.task_component_temporal_episode_min_children_per_episode),
            max_episodes=int(cfg.task_component_temporal_episode_max_episodes),
            budget_strategy=str(cfg.task_component_temporal_episode_budget_strategy),
        )
    if (
        cfg.host == "cadets"
        and bool(cfg.task_component_synthetic_root_isolation_enabled)
        and isinstance(edge_list, dict)
    ):
        edge_list = dict(edge_list)
        edge_list["subject_start_timestamps"] = parser_metadata.get(
            "canonical_subject_start_timestamps", {}
        )
        edge_list = _apply_synthetic_root_isolation(
            edge_list,
            min_task_nodes=int(cfg.task_component_synthetic_root_isolation_min_task_nodes),
            min_direct_children=int(cfg.task_component_synthetic_root_isolation_min_direct_children),
        )
    if (
        cfg.host == "cadets"
        and bool(cfg.task_component_synthetic_root_selective_isolation_enabled)
        and isinstance(edge_list, dict)
    ):
        edge_list = dict(edge_list)
        edge_list["subject_start_timestamps"] = parser_metadata.get(
            "canonical_subject_start_timestamps", {}
        )
        edge_list["canonical_execute_targets"] = parser_metadata.get("canonical_execute_targets", {})
        edge_list = _apply_selective_synthetic_root_isolation(
            edge_list,
            min_task_nodes=int(cfg.task_component_synthetic_root_isolation_min_task_nodes),
            min_direct_children=int(cfg.task_component_synthetic_root_isolation_min_direct_children),
            max_exec_target_frequency=int(
                cfg.task_component_synthetic_root_selective_max_exec_target_frequency
            ),
        )
    if (
        cfg.host in {"cadets", "trace"}
        and bool(cfg.task_component_branch_object_overlap_split_enabled)
        and isinstance(edge_list, dict)
    ):
        edge_list = dict(edge_list)
        # Parser UUIDs keep this pass independent of later object-key normalization.
        edge_list["canonical_subject_object_ids"] = parser_metadata.pop(
            "canonical_subject_object_ids", {}
        )
        edge_list = _apply_branch_object_overlap_split(edge_list)
    else:
        parser_metadata.pop("canonical_subject_object_ids", None)
    canonical_ground_truth = _canonicalize_ground_truth_nodes(ground_truth, parser_metadata)
    parser_full_event_action_counts = parser_metadata.pop("canonical_event_action_counts", {})
    if cfg.host == "theia_e5":
        object_linked_ground_truth = {
            str(node).strip()
            for node in parser_metadata.get("gt_object_event_canonical_subjects", [])
            if str(node).strip()
        }
        parser_metadata["ground_truth_entity_type_counts"] = {
            entity_type: sum(1 for value in theia_e5_entity_types.values() if value == entity_type)
            for entity_type in sorted(set(theia_e5_entity_types.values()))
        }
        parser_metadata["direct_subject_ground_truth_canonical_count"] = len(canonical_ground_truth)
        parser_metadata["object_linked_ground_truth_canonical_count"] = len(object_linked_ground_truth)
        canonical_ground_truth |= object_linked_ground_truth
        parser_metadata["combined_ground_truth_canonical_count"] = len(canonical_ground_truth)
    graph_metas = _decompose_tc3_metadata(edge_list, canonical_ground_truth)
    semantic_sequence_scores_path: Path | None = None
    if cfg.task_sequence_encoder_mode == "semantic_v1":
        semantic_histories = parser_metadata.pop("canonical_semantic_event_histories", {})
        if not isinstance(semantic_histories, dict) or not semantic_histories:
            raise ValueError(
                f"{cfg.host} parser did not provide canonical semantic histories required by task_sequence_encoder_mode=semantic_v1"
            )
        train_subject_ids = _semantic_sequence_train_subject_ids(cfg, graph_metas)
        semantic_model_path = (
            cfg.task_semantic_sequence_pretrained_path
            if cfg.task_semantic_sequence_pretrained_path is not None and cfg.task_semantic_sequence_pretrained_path.exists()
            else module1_dir / "semantic_sequence_encoder.pt"
        )
        semantic_result = fit_benign_semantic_sequence_encoder(
            semantic_histories,
            train_subject_ids,
            semantic_model_path,
            epochs=int(cfg.task_semantic_sequence_epochs),
            batch_size=int(cfg.task_semantic_sequence_batch_size),
            learning_rate=float(cfg.task_semantic_sequence_learning_rate),
            seed=int(cfg.random_seed),
            pretrained_path=cfg.task_semantic_sequence_pretrained_path,
        )
        raw_vectors = semantic_result.vectors
        semantic_sequence_scores_path = module1_dir / "semantic_sequence_prediction_errors.json"
        save_json(semantic_sequence_scores_path, semantic_result.prediction_errors)
        parser_metadata["semantic_sequence_encoder"] = semantic_result.metadata
        parser_metadata["semantic_sequence_prediction_errors_path"] = str(semantic_sequence_scores_path)
        parser_metadata["semantic_sequence_train_subject_count"] = len(train_subject_ids)
    else:
        # Avoid storing a large unused history sidecar in legacy module1 bundles.
        parser_metadata.pop("canonical_semantic_event_histories", None)

    raw_graphs = vendor.decompose(
        edge_list,
        raw_vectors,
        cfg.host,
        canonical_ground_truth=canonical_ground_truth,
    )

    embeddings_map = _vector_rows_to_map(raw_vectors)
    _validate_graph_meta_alignment(raw_graphs, graph_metas, f"tc3/{cfg.host}")
    base_edge_rows = edge_list.get("edge_list", edge_list) if isinstance(edge_list, dict) else edge_list
    selected_edge_list = [list(edge) for edge in base_edge_rows]
    return {
        "family": "tc3",
        "dataset_name": cfg.host,
        "selected_dataset_name": cfg.host,
        "selected_graphs": raw_graphs,
        "selected_graph_metas": graph_metas,
        "selected_edge_list": selected_edge_list,
        "selected_embeddings": embeddings_map,
        "sequence_feature_dim": _feature_dim_from_map(embeddings_map),
        "thread_merge_metadata": copy.deepcopy(parser_metadata),
        "parser_event_count": event_count if cfg.use_ocr_stat_features else None,
        "parser_full_event_action_counts": parser_full_event_action_counts if cfg.use_ocr_stat_features else None,
        "semantic_sequence_prediction_errors_path": str(semantic_sequence_scores_path) if semantic_sequence_scores_path else "",
        "theia_temporal_split_summary": copy.deepcopy(edge_list.get("theia_temporal_split_summary", {}))
        if isinstance(edge_list, dict)
        else {},
        "root_temporal_split_summary": copy.deepcopy(edge_list.get("root_temporal_split_summary", {}))
        if isinstance(edge_list, dict)
        else {},
        "temporal_episode_split_summary": copy.deepcopy(edge_list.get("temporal_episode_split_summary", {}))
        if isinstance(edge_list, dict)
        else {},
        "provgrp_paper_partition_summary": copy.deepcopy(edge_list.get("provgrp_paper_partition_summary", {}))
        if isinstance(edge_list, dict)
        else {},
        "synthetic_root_isolation_summary": copy.deepcopy(edge_list.get("synthetic_root_isolation_summary", {}))
        if isinstance(edge_list, dict)
        else {},
        "synthetic_root_selective_isolation_summary": copy.deepcopy(
            edge_list.get("synthetic_root_selective_isolation_summary", {})
        )
        if isinstance(edge_list, dict)
        else {},
        "branch_object_overlap_split_summary": copy.deepcopy(
            edge_list.get("branch_object_overlap_split_summary", {})
        )
        if isinstance(edge_list, dict)
        else {},
    }

def _build_optc_bundle(cfg: FusionConfig, module1_dir: Path) -> dict[str, Any]:
    workspace = _ensure_workspace(module1_dir, cfg)
    vendor = _load_vendor_module("tapas_vendor_optc_exact_module1", _vendor_tapas_root() / "optc.py")
    vendor.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    require_all_hosts = cfg.task_detector_mode == "fit_predict"
    _stage_optc_logs_exact(cfg, workspace, vendor, require_all_hosts=require_all_hosts)
    ground_truth = _load_ground_truth(cfg.task_ground_truth_path)

    raw_graphs_by_host: dict[str, list[dict[str, Any]]] = {}
    raw_graph_metas_by_host: dict[str, list[dict[str, Any]]] = {}
    edge_lists_by_host: dict[str, list[list[str]]] = {}
    embeddings_by_host: dict[str, dict[str, list[float]]] = {}

    with _temporary_cwd(workspace):
        for host_id in _OFFICIAL_OPTC_HOSTS:
            expected = workspace / "data" / "optc" / _expected_optc_filename(host_id)
            if not expected.exists():
                continue
            subject_list, object_list, event_count = vendor.parser_logs(host_id)
            subject_node = vendor.encode(subject_list, object_list, event_count)
            edge_list = vendor.cut_task(subject_list)
            subject_vec = vendor.get_node_vec(subject_node)
            raw_graphs_by_host[host_id] = vendor.decompose(subject_vec, edge_list)
            raw_graph_metas_by_host[host_id] = _decompose_optc_metadata(edge_list, ground_truth, f"{host_id}_task_")
            _validate_graph_meta_alignment(raw_graphs_by_host[host_id], raw_graph_metas_by_host[host_id], f"optc/{host_id}")
            edge_lists_by_host[host_id] = [list(edge) for edge in edge_list]
            embeddings_by_host[host_id] = _vector_rows_to_map(subject_vec)

    if require_all_hosts:
        missing = [host_id for host_id in _OFFICIAL_OPTC_HOSTS if host_id not in raw_graphs_by_host]
        if missing:
            raise FileNotFoundError(
                f"Exact TAPAS OpTC fit_predict mode requires all official hosts. Missing staged hosts: {missing}"
            )

    selected_name = _optc_eval_dataset_name(cfg.host)
    if selected_name == "data_all":
        selected_graphs = []
        selected_graph_metas = []
        selected_edge_list: list[list[str]] = []
        selected_embeddings: dict[str, list[float]] = {}
        for host_id in _OFFICIAL_OPTC_HOSTS:
            selected_graphs.extend(copy.deepcopy(raw_graphs_by_host.get(host_id, [])))
            selected_graph_metas.extend(copy.deepcopy(raw_graph_metas_by_host.get(host_id, [])))
            selected_edge_list.extend(copy.deepcopy(edge_lists_by_host.get(host_id, [])))
            selected_embeddings.update(copy.deepcopy(embeddings_by_host.get(host_id, {})))
    else:
        if selected_name not in raw_graphs_by_host:
            raise FileNotFoundError(
                f"Selected OpTC host '{selected_name}' is not available in staged TAPAS logs."
            )
        selected_graphs = copy.deepcopy(raw_graphs_by_host[selected_name])
        selected_graph_metas = copy.deepcopy(raw_graph_metas_by_host[selected_name])
        selected_edge_list = copy.deepcopy(edge_lists_by_host[selected_name])
        selected_embeddings = copy.deepcopy(embeddings_by_host[selected_name])

    return {
        "family": "optc",
        "dataset_name": "optc",
        "selected_dataset_name": selected_name,
        "selected_graphs": selected_graphs,
        "selected_graph_metas": selected_graph_metas,
        "selected_edge_list": selected_edge_list,
        "selected_embeddings": selected_embeddings,
        "raw_graphs_by_host": raw_graphs_by_host,
        "raw_graph_metas_by_host": raw_graph_metas_by_host,
        "edge_lists_by_host": edge_lists_by_host,
        "embeddings_by_host": embeddings_by_host,
        "host_order": list(_OFFICIAL_OPTC_HOSTS),
        "sequence_feature_dim": _feature_dim_from_map(selected_embeddings),
    }


def _build_bundle(cfg: FusionConfig, module1_dir: Path) -> dict[str, Any]:
    if cfg.dataset_family == "tc3":
        return _build_tc3_bundle(cfg, module1_dir)
    if cfg.dataset_family == "optc":
        return _build_optc_bundle(cfg, module1_dir)
    raise ValueError("Exact TAPAS module1/module2 currently support dataset_family 'tc3' and 'optc' only")


def _extract_stat_embeddings_for_graphs(
    cfg: FusionConfig,
    graph_metas: list[dict[str, Any]],
    parser_event_count: dict[object, object] | None = None,
    parser_full_event_action_counts: dict[object, object] | None = None,
    parser_metadata: dict[str, object] | None = None,
) -> tuple[dict[str, list[float]], list[str]]:
    process_ids = {str(node) for meta in graph_metas for node in meta.get("node_ids", [])}
    if not process_ids:
        return {}, []

    if (
        cfg.dataset_family == "tc3"
        and cfg.task_tc3_event_stats_mode in {"core", "extended", "security_semantic"}
        and parser_full_event_action_counts is not None
    ):
        stats_df = extract_process_stat_features_from_tc3_action_counts(
            cfg,
            process_ids,
            parser_full_event_action_counts,
            cfg.task_tc3_event_stats_mode,
        )
    elif cfg.dataset_family == "tc3" and parser_event_count is not None:
        stats_df = extract_process_stat_features_from_tc3_event_count(
            cfg,
            process_ids,
            parser_event_count,
            parser_metadata,
        )
    else:
        stats_df = extract_process_stat_features(cfg, process_ids)
    stat_columns = [column for column in stats_df.columns if column != "process_id"]
    if not stat_columns:
        return {}, []

    stats_map = {
        str(row["process_id"]): [float(row[column]) for column in stat_columns]
        for row in stats_df.to_dict(orient="records")
    }
    return stats_map, stat_columns


def _compose_graphsage_embeddings(
    base_embeddings: dict[str, list[float]],
    base_dim: int,
    stat_embeddings: dict[str, list[float]],
    stat_feature_dim: int,
) -> dict[str, list[float]]:
    combined_embeddings: dict[str, list[float]] = {}
    zero_stats = [0.0] * stat_feature_dim
    all_process_ids = set(base_embeddings.keys()) | set(stat_embeddings.keys())
    for process_id in all_process_ids:
        base_vector = [float(value) for value in base_embeddings.get(process_id, [0.0] * base_dim)]
        if len(base_vector) < base_dim:
            base_vector.extend([0.0] * (base_dim - len(base_vector)))
        elif len(base_vector) > base_dim:
            base_vector = base_vector[:base_dim]
        stats_vector = [float(value) for value in stat_embeddings.get(process_id, zero_stats)]
        if len(stats_vector) < stat_feature_dim:
            stats_vector.extend([0.0] * (stat_feature_dim - len(stats_vector)))
        elif len(stats_vector) > stat_feature_dim:
            stats_vector = stats_vector[:stat_feature_dim]
        combined_embeddings[process_id] = base_vector + stats_vector
    return combined_embeddings


def _materialize_graph_node_vectors(
    graphs: list[dict[str, Any]],
    graph_metas: list[dict[str, Any]],
    embeddings_map: dict[str, list[float]],
) -> list[dict[str, Any]]:
    feature_dim = _feature_dim_from_map(embeddings_map)
    updated_graphs = copy.deepcopy(graphs)
    for graph, meta in zip(updated_graphs, graph_metas):
        graph["nodes"] = [
            [float(value) for value in embeddings_map.get(str(node_id), [0.0] * feature_dim)]
            for node_id in meta.get("node_ids", [])
        ]
    return updated_graphs


def _apply_graphsage_feature_policy(
    cfg: FusionConfig,
    embeddings_map: dict[str, list[float]],
    graphs: list[dict[str, Any]],
    graph_metas: list[dict[str, Any]],
    stat_embeddings: dict[str, list[float]],
    stat_columns: list[str],
) -> tuple[dict[str, list[float]], list[dict[str, Any]], int]:
    base_dim = _feature_dim_from_map(embeddings_map) if cfg.use_sequence_embeddings else 0
    stat_dim = len(stat_columns)
    if cfg.use_sequence_embeddings:
        graphsage_embeddings = {
            str(process_id): [float(value) for value in vector]
            for process_id, vector in embeddings_map.items()
        }
        if _graphsage_uses_stat_features(cfg) and stat_dim > 0:
            graphsage_embeddings = _compose_graphsage_embeddings(graphsage_embeddings, base_dim, stat_embeddings, stat_dim)
    else:
        graphsage_embeddings = {
            str(process_id): [float(value) for value in vector]
            for process_id, vector in stat_embeddings.items()
        }

    updated_graphs = _materialize_graph_node_vectors(graphs, graph_metas, graphsage_embeddings)
    return graphsage_embeddings, updated_graphs, base_dim


def _append_stats_to_bundle(cfg: FusionConfig, bundle: dict[str, Any]) -> dict[str, Any]:
    updated = dict(bundle)
    updated["base_sequence_feature_dim"] = int(bundle["sequence_feature_dim"]) if cfg.use_sequence_embeddings else 0
    updated["stat_feature_columns"] = []
    updated["selected_stat_embeddings"] = {}
    updated["stat_feature_source"] = "disabled"
    parser_event_count = updated.pop("parser_event_count", None)
    parser_full_event_action_counts = updated.pop("parser_full_event_action_counts", None)
    parser_metadata_for_stats = updated.get("thread_merge_metadata", {})
    if not cfg.use_sequence_embeddings:
        if updated["family"] == "tc3":
            updated["selected_embeddings"] = {}
        else:
            updated["embeddings_by_host"] = {host_id: {} for host_id in updated["host_order"]}
            updated["selected_embeddings"] = {}
    if not cfg.use_ocr_stat_features:
        return updated

    if updated["family"] == "tc3":
        stat_embeddings, stat_columns = _extract_stat_embeddings_for_graphs(
            cfg,
            updated["selected_graph_metas"],
            parser_event_count=parser_event_count if isinstance(parser_event_count, dict) else None,
            parser_full_event_action_counts=(
                parser_full_event_action_counts if isinstance(parser_full_event_action_counts, dict) else None
            ),
            parser_metadata=parser_metadata_for_stats if isinstance(parser_metadata_for_stats, dict) else None,
        )
        embeddings, graphs, base_dim = _apply_graphsage_feature_policy(
            cfg,
            updated["selected_embeddings"],
            updated["selected_graphs"],
            updated["selected_graph_metas"],
            stat_embeddings,
            stat_columns,
        )
        updated["selected_stat_embeddings"] = stat_embeddings
        updated["selected_embeddings"] = embeddings
        updated["selected_graphs"] = graphs
        updated["base_sequence_feature_dim"] = base_dim
        updated["stat_feature_columns"] = stat_columns
        updated["stat_feature_source"] = (
            f"parser_full_action_counts_{cfg.task_tc3_event_stats_mode}"
            if cfg.task_tc3_event_stats_mode in {"core", "extended", "security_semantic"}
            and isinstance(parser_full_event_action_counts, dict)
            else "legacy_parser_event_aggregate"
        )
        return updated

    updated_embeddings_by_host: dict[str, dict[str, list[float]]] = {}
    updated_graphs_by_host: dict[str, list[dict[str, Any]]] = {}
    updated_stat_embeddings_by_host: dict[str, dict[str, list[float]]] = {}
    stat_columns: list[str] = []
    base_dim = int(updated["base_sequence_feature_dim"])
    for host_id in updated["host_order"]:
        host_cfg = copy.copy(cfg)
        host_cfg.host = f"SysClient{host_id}"
        host_stat_embeddings, host_stat_columns = _extract_stat_embeddings_for_graphs(
            host_cfg,
            updated["raw_graph_metas_by_host"].get(host_id, []),
        )
        embeddings, graphs, host_base_dim = _apply_graphsage_feature_policy(
            host_cfg,
            updated["embeddings_by_host"].get(host_id, {}),
            updated["raw_graphs_by_host"].get(host_id, []),
            updated["raw_graph_metas_by_host"].get(host_id, []),
            host_stat_embeddings,
            host_stat_columns,
        )
        updated_embeddings_by_host[host_id] = embeddings
        updated_graphs_by_host[host_id] = graphs
        updated_stat_embeddings_by_host[host_id] = host_stat_embeddings
        if host_stat_columns:
            stat_columns = host_stat_columns
        base_dim = host_base_dim
    updated["embeddings_by_host"] = updated_embeddings_by_host
    updated["raw_graphs_by_host"] = updated_graphs_by_host
    updated["stat_embeddings_by_host"] = updated_stat_embeddings_by_host
    updated["base_sequence_feature_dim"] = base_dim
    updated["stat_feature_columns"] = stat_columns

    selected_name = updated["selected_dataset_name"]
    if selected_name == "data_all":
        selected_graphs: list[dict[str, Any]] = []
        selected_graph_metas: list[dict[str, Any]] = []
        selected_embeddings: dict[str, list[float]] = {}
        selected_stat_embeddings: dict[str, list[float]] = {}
        for host_id in updated["host_order"]:
            selected_graphs.extend(copy.deepcopy(updated_graphs_by_host.get(host_id, [])))
            selected_graph_metas.extend(copy.deepcopy(updated["raw_graph_metas_by_host"].get(host_id, [])))
            selected_embeddings.update(copy.deepcopy(updated_embeddings_by_host.get(host_id, {})))
            selected_stat_embeddings.update(copy.deepcopy(updated_stat_embeddings_by_host.get(host_id, {})))
        updated["selected_graphs"] = selected_graphs
        updated["selected_graph_metas"] = selected_graph_metas
        updated["selected_embeddings"] = selected_embeddings
        updated["selected_stat_embeddings"] = selected_stat_embeddings
    else:
        updated["selected_graphs"] = copy.deepcopy(updated_graphs_by_host[selected_name])
        updated["selected_graph_metas"] = copy.deepcopy(updated["raw_graph_metas_by_host"][selected_name])
        updated["selected_embeddings"] = copy.deepcopy(updated_embeddings_by_host[selected_name])
        updated["selected_stat_embeddings"] = copy.deepcopy(updated_stat_embeddings_by_host.get(selected_name, {}))
    return updated


def _save_module1_exports(cfg: FusionConfig, out_dir: Path, bundle: dict[str, Any]) -> dict[str, Path]:
    ensure_dir(out_dir)
    embeddings_path = out_dir / "process_embeddings.csv"
    task_path = out_dir / "task_subgraphs.json"
    segmentation_edges_path = out_dir / "process_segmentation_edges.csv"
    task_component_diagnostics_path = out_dir / _MODULE1_TASK_COMPONENT_DIAGNOSTICS_FILENAME
    native_graph_path = _module1_graph_path(out_dir)
    summary_path = _module1_summary_path(out_dir)

    embeddings_rows = []
    embeddings_map = bundle["selected_embeddings"]
    feature_dim = _feature_dim_from_map(embeddings_map)
    for process_id in sorted(embeddings_map):
        row = {"process_id": str(process_id)}
        vector = list(embeddings_map[process_id])
        for index in range(feature_dim):
            row[f"emb_{index}"] = float(vector[index]) if index < len(vector) else 0.0
        embeddings_rows.append(row)
    pd.DataFrame(embeddings_rows).to_csv(embeddings_path, index=False)

    save_json(
        task_path,
        [
            {
                "task_id": str(meta.get("task_id", "")),
                "process_ids": [str(node) for node in meta.get("node_ids", [])],
            }
            for meta in bundle["selected_graph_metas"]
        ],
    )
    task_component_diagnostics = []
    for meta in bundle["selected_graph_metas"]:
        row = {
            "task_id": str(meta.get("task_id", "")),
            "task_root_id": str(meta.get("task_root_id", "")).strip(),
            "task_size": int(meta.get("task_size", len(meta.get("node_ids", [])))),
            "internal_edge_count": int(meta.get("internal_edge_count", 0)),
            "boundary_node_count": len(meta.get("boundary_node_ids", [])),
            "task_root_total_children": int(meta.get("task_root_total_children", 0) or 0),
            "task_root_effective_children": int(meta.get("task_root_effective_children", 0) or 0),
            "task_root_segmented": bool(meta.get("task_root_segmented", False)),
            "task_root_parent_missing": bool(meta.get("task_root_parent_missing", False)),
            "child_threshold": int(meta.get("child_threshold", 0) or 0),
            "split_mode": str(meta.get("split_mode", "")),
            "count_segmented_children_upstream": bool(
                meta.get("count_segmented_children_upstream", False)
            ),
        }
        for key in [
            "temporal_split_applied",
            "temporal_split_parent_task_root",
            "temporal_split_cluster_index",
            "temporal_split_cluster_count",
            "temporal_split_child_roots",
            "temporal_component_first_timestamp_sec",
            "temporal_component_last_timestamp_sec",
            "temporal_component_span_minutes",
            "temporal_component_root_retained",
            "temporal_episode_split_applied",
            "temporal_episode_parent_task_root",
            "temporal_episode_index",
            "temporal_episode_count",
            "temporal_episode_child_roots",
            "temporal_episode_first_child_timestamp_sec",
            "temporal_episode_last_child_timestamp_sec",
            "temporal_episode_child_span_minutes",
            "temporal_episode_root_retained",
            "provgrp_paper_partition_applied",
            "provgrp_paper_parent_task_root",
            "provgrp_paper_partition_index",
            "provgrp_paper_partition_count",
            "provgrp_paper_incoming_cluster_id",
            "provgrp_paper_outgoing_cluster_id",
            "provgrp_paper_incoming_event_count",
            "provgrp_paper_outgoing_event_count",
            "provgrp_paper_member_child_roots",
            "provgrp_paper_member_child_count",
            "provgrp_paper_original_root_child_count",
        ]:
            if key in meta:
                row[key] = copy.deepcopy(meta[key])
        task_component_diagnostics.append(row)
    save_json(task_component_diagnostics_path, task_component_diagnostics)
    _build_segmentation_frame(bundle["selected_edge_list"]).to_csv(segmentation_edges_path, index=False)
    torch.save(bundle, native_graph_path)

    large_task_gt_500 = sum(1 for row in task_component_diagnostics if int(row.get("task_size", 0) or 0) > 500)
    large_task_gt_1000 = sum(1 for row in task_component_diagnostics if int(row.get("task_size", 0) or 0) > 1000)
    summary = {
        "backend": "tapas_exact_vendor",
        "dataset_family": cfg.dataset_family,
        "host": cfg.host,
        "tapas_dataset_name": bundle["dataset_name"],
        "selected_dataset_name": bundle["selected_dataset_name"],
        "task_count": len(bundle["selected_graph_metas"]),
        "process_count": len(embeddings_map),
        "segmentation_edge_count": len(bundle["selected_edge_list"]),
        "use_sequence_embeddings": bool(cfg.use_sequence_embeddings),
        "use_ocr_stat_features": bool(cfg.use_ocr_stat_features),
        "graphsage_append_ocr_stat_features": bool(cfg.graphsage_append_ocr_stat_features),
        "task_tc3_event_stats_mode": str(cfg.task_tc3_event_stats_mode),
        "stat_feature_source": str(bundle.get("stat_feature_source", "disabled")),
        "graphsage_node_feature_sources": _graphsage_node_feature_sources(cfg),
        "graph_stat_sidecar_sources": {
            "ocr_stat_features": bool(cfg.use_ocr_stat_features),
        },
        "graphsage_feature_dim": int(feature_dim),
        "sequence_feature_dim": int(bundle.get("base_sequence_feature_dim", feature_dim)),
        "stat_feature_dim": len(bundle.get("stat_feature_columns", [])),
        "stat_feature_columns": list(bundle.get("stat_feature_columns", [])),
        "graph_min_nodes": 2,
        "tapas_exact": True,
        "source_chain": "official_parser_to_decompose",
        "graph_metadata_sidecar_export_only": True,
        "task_component_split_mode": str(cfg.task_component_split_mode),
        "task_component_child_threshold": int(cfg.task_component_child_threshold),
        "task_component_count_segmented_children_upstream": bool(
            cfg.task_component_count_segmented_children_upstream
        ),
        "task_component_diagnostics_path": str(task_component_diagnostics_path),
        "large_task_count_gt_500": int(large_task_gt_500),
        "large_task_count_gt_1000": int(large_task_gt_1000),
    }
    if cfg.dataset_family == "optc":
        summary["official_optc_training_hosts"] = list(bundle.get("host_order", []))
    if cfg.host == "theia":
        summary["task_component_theia_temporal_split_enabled"] = bool(
            cfg.task_component_theia_temporal_split_enabled
        )
        summary["task_component_theia_max_span_minutes"] = int(cfg.task_component_theia_max_span_minutes)
        summary["task_component_theia_branch_gap_minutes"] = int(cfg.task_component_theia_branch_gap_minutes)
        summary["theia_temporal_split_summary"] = copy.deepcopy(bundle.get("theia_temporal_split_summary", {}))
    if cfg.host in {"cadets", "trace"}:
        summary["task_component_provgrp_behavior_partition_enabled"] = bool(
            cfg.task_component_provgrp_behavior_partition_enabled
        )
        summary["provgrp_paper_partition_summary"] = copy.deepcopy(
            bundle.get("provgrp_paper_partition_summary", {})
        )
        summary["task_component_root_temporal_split_enabled"] = bool(
            cfg.task_component_root_temporal_split_enabled
        )
        summary["task_component_root_temporal_min_task_nodes"] = int(
            cfg.task_component_root_temporal_min_task_nodes
        )
        summary["task_component_root_temporal_min_direct_children"] = int(
            cfg.task_component_root_temporal_min_direct_children
        )
        summary["task_component_root_temporal_max_span_minutes"] = int(
            cfg.task_component_root_temporal_max_span_minutes
        )
        summary["task_component_root_temporal_branch_gap_minutes"] = int(
            cfg.task_component_root_temporal_branch_gap_minutes
        )
        summary["task_component_root_temporal_session_max_minutes"] = int(
            cfg.task_component_root_temporal_session_max_minutes
        )
        summary["task_component_root_temporal_max_sessions"] = int(
            cfg.task_component_root_temporal_max_sessions
        )
        summary["root_temporal_split_summary"] = copy.deepcopy(bundle.get("root_temporal_split_summary", {}))
        summary["task_component_temporal_episode_split_enabled"] = bool(
            cfg.task_component_temporal_episode_split_enabled
        )
        summary["temporal_episode_split_summary"] = copy.deepcopy(
            bundle.get("temporal_episode_split_summary", {})
        )
        summary["task_component_branch_object_overlap_split_enabled"] = bool(
            cfg.task_component_branch_object_overlap_split_enabled
        )
        summary["branch_object_overlap_split_summary"] = copy.deepcopy(
            bundle.get("branch_object_overlap_split_summary", {})
        )
    if cfg.host == "cadets":
        summary["task_component_synthetic_root_isolation_enabled"] = bool(
            cfg.task_component_synthetic_root_isolation_enabled
        )
        summary["task_component_synthetic_root_isolation_min_task_nodes"] = int(
            cfg.task_component_synthetic_root_isolation_min_task_nodes
        )
        summary["task_component_synthetic_root_isolation_min_direct_children"] = int(
            cfg.task_component_synthetic_root_isolation_min_direct_children
        )
        summary["synthetic_root_isolation_summary"] = copy.deepcopy(
            bundle.get("synthetic_root_isolation_summary", {})
        )
        summary["task_component_synthetic_root_selective_isolation_enabled"] = bool(
            cfg.task_component_synthetic_root_selective_isolation_enabled
        )
        summary["task_component_synthetic_root_selective_max_exec_target_frequency"] = int(
            cfg.task_component_synthetic_root_selective_max_exec_target_frequency
        )
        summary["synthetic_root_selective_isolation_summary"] = copy.deepcopy(
            bundle.get("synthetic_root_selective_isolation_summary", {})
        )
    save_json(summary_path, summary)

    return {
        "process_embeddings": embeddings_path,
        "task_subgraphs": task_path,
        "process_segmentation_edges": segmentation_edges_path,
        "task_component_diagnostics": task_component_diagnostics_path,
        "tapas_native_graphs": native_graph_path,
        "tapas_native_summary": summary_path,
    }


def run_tapas_module1(cfg: FusionConfig, out_dir: Path) -> dict[str, Path]:
    bundle = _append_stats_to_bundle(cfg, _build_bundle(cfg, out_dir))
    return _save_module1_exports(cfg, out_dir, bundle)


def _load_native_bundle(module1_dir: Path) -> dict[str, Any]:
    graph_path = _module1_graph_path(module1_dir)
    if not graph_path.exists():
        raise FileNotFoundError(
            f"Exact TAPAS module1 bundle not found: {graph_path}. Run module1 before module2."
        )
    bundle = _torch_load(graph_path)
    if not isinstance(bundle, dict) or "family" not in bundle:
        raise ValueError(f"Invalid TAPAS module1 bundle: {graph_path}")
    return bundle


def _load_vendor_for_family(family: str) -> ModuleType:
    if family == "tc3":
        return _load_vendor_module("tapas_vendor_darpa_exact_module2", _vendor_tapas_root() / "darpa.py")
    if family == "optc":
        return _load_vendor_module("tapas_vendor_optc_exact_module2", _vendor_tapas_root() / "optc.py")
    raise ValueError(f"Unsupported exact TAPAS family: {family}")


def _shuffle_dataset_with_graphs(
    dataset,
    graphs: Sequence[dict[str, Any]],
    graph_metas: Sequence[dict[str, Any]],
    seed: int,
):
    torch.manual_seed(seed)
    try:
        shuffled_dataset, perm = dataset.shuffle(return_perm=True)
        permutation = [int(index) for index in perm.tolist()]
    except TypeError:
        shuffled_dataset = dataset.shuffle()
        permutation = list(range(len(graphs)))
    shuffled_graphs = [graphs[index] for index in permutation]
    shuffled_graph_metas = [graph_metas[index] for index in permutation]
    return shuffled_dataset, shuffled_graphs, shuffled_graph_metas


def _split_graphs_with_metas(
    cfg: FusionConfig,
    graphs: Sequence[dict[str, Any]],
    graph_metas: Sequence[dict[str, Any]],
    test_fraction: float = 0.2,
) -> dict[str, Any]:
    count = len(graphs)
    labels = np.asarray(
        [int(graph.get("label", meta.get("label", 0))) for graph, meta in zip(graphs, graph_metas)],
        dtype=np.int64,
    )


def _normal_only_label(graph: dict[str, Any], meta: dict[str, Any]) -> int:
    return int(graph.get("label", meta.get("label", 0)))


def _normal_only_timestamp(meta: dict[str, Any]) -> float | None:
    for key in (
        "first_timestamp_sec",
        "temporal_component_first_timestamp_sec",
        "first_timestamp",
    ):
        value = _float_or_none(meta.get(key))
        if value is not None:
            return value
    return None


def _normal_only_temporal_split(
    cfg: FusionConfig,
    graphs: Sequence[dict[str, Any]],
    graph_metas: Sequence[dict[str, Any]],
) -> dict[str, list[int] | dict[str, Any]]:
    """Keep attacks out of fitting and pick the threshold from benign graphs only."""
    benign_indices = [
        index
        for index, (graph, meta) in enumerate(zip(graphs, graph_metas))
        if _normal_only_label(graph, meta) == 0
    ]
    positive_indices = [
        index
        for index, (graph, meta) in enumerate(zip(graphs, graph_metas))
        if _normal_only_label(graph, meta) == 1
    ]
    benign_indices.sort(
        key=lambda index: (
            _normal_only_timestamp(graph_metas[index]) is None,
            _normal_only_timestamp(graph_metas[index]) or 0.0,
            str(graph_metas[index].get("task_id", f"task_{index:04d}")),
        )
    )
    benign_count = len(benign_indices)
    if benign_count < 3:
        raise ValueError("normal-only detection requires at least three benign task graphs")

    train_count = max(1, int(np.floor(benign_count * float(cfg.task_normal_only_train_fraction))))
    validation_count = max(1, int(np.floor(benign_count * float(cfg.task_normal_only_validation_fraction))))
    if train_count + validation_count >= benign_count:
        validation_count = max(1, benign_count - train_count - 1)
    if validation_count <= 0:
        raise ValueError("normal-only detection requires a held-out benign validation partition")

    train_indices = benign_indices[:train_count]
    validation_indices = benign_indices[train_count : train_count + validation_count]
    eval_benign_indices = benign_indices[train_count + validation_count :]
    if not eval_benign_indices:
        eval_benign_indices = validation_indices[-1:]
        validation_indices = validation_indices[:-1]
    if not validation_indices:
        raise ValueError("normal-only validation partition became empty")

    return {
        "train_indices": train_indices,
        "validation_indices": validation_indices,
        "evaluation_indices": eval_benign_indices + positive_indices,
        "summary": {
            "strategy": "temporal_benign_split_with_all_known_attacks_held_out",
            "train_benign_count": len(train_indices),
            "validation_benign_count": len(validation_indices),
            "evaluation_benign_count": len(eval_benign_indices),
            "evaluation_known_attack_count": len(positive_indices),
            "positive_graphs_used_for_training": 0,
            "positive_graphs_used_for_threshold_selection": 0,
        },
    }


def _normal_only_graph_feature(graph: dict[str, Any], meta: dict[str, Any]) -> np.ndarray:
    nodes = np.asarray(graph.get("nodes", []), dtype=np.float64)
    if nodes.ndim != 2 or nodes.shape[0] == 0:
        raise ValueError(f"task {meta.get('task_id', '')} has no usable node features")
    root_id = str(meta.get("task_root_id", ""))
    node_ids = [str(node) for node in meta.get("node_ids", [])]
    try:
        root_index = node_ids.index(root_id)
    except ValueError:
        root_index = 0
    root = nodes[min(root_index, len(nodes) - 1)]
    mean = nodes.mean(axis=0)
    maximum = nodes.max(axis=0)
    structure = np.asarray(
        [
            np.log1p(len(nodes)),
            np.log1p(len(graph.get("edges", []))),
            float(root_index == 0),
        ],
        dtype=np.float64,
    )
    return np.concatenate([root, mean, maximum, structure])


def _normal_only_graph_matrix(
    graphs: Sequence[dict[str, Any]],
    graph_metas: Sequence[dict[str, Any]],
    indices: Sequence[int],
) -> np.ndarray:
    return np.asarray(
        [_normal_only_graph_feature(graphs[index], graph_metas[index]) for index in indices],
        dtype=np.float64,
    )


def _normal_only_node_matrix(graphs: Sequence[dict[str, Any]], indices: Sequence[int]) -> np.ndarray:
    matrices = [
        np.asarray(graphs[index].get("nodes", []), dtype=np.float64)
        for index in indices
        if len(graphs[index].get("nodes", [])) > 0
    ]
    if not matrices:
        raise ValueError("normal-only detection found no process-node features in benign training tasks")
    return np.concatenate(matrices, axis=0)


def _normal_only_sample_rows(matrix: np.ndarray, limit: int, seed: int) -> np.ndarray:
    if len(matrix) <= limit:
        return matrix
    rng = np.random.default_rng(seed)
    indices = rng.choice(len(matrix), size=limit, replace=False)
    return matrix[np.sort(indices)]


def _normal_only_fit_kmeans(matrix: np.ndarray, requested_clusters: int, seed: int) -> MiniBatchKMeans:
    cluster_count = max(1, min(int(requested_clusters), len(matrix)))
    return MiniBatchKMeans(
        n_clusters=cluster_count,
        random_state=int(seed),
        batch_size=min(4096, max(64, len(matrix))),
        n_init=10,
    ).fit(matrix)


def _normal_only_local_keep_count(cfg: FusionConfig, node_count: int) -> int:
    mode = str(getattr(cfg, "task_normal_only_local_top_k_mode", "fixed"))
    if mode == "sqrt":
        requested = int(np.ceil(np.sqrt(max(1, node_count))))
        requested = min(requested, int(getattr(cfg, "task_normal_only_local_top_k_max", 16)))
    else:
        requested = int(cfg.task_normal_only_local_top_k)
    return min(max(1, requested), max(1, node_count))


def _normal_only_node_local_scores(
    cfg: FusionConfig,
    graphs: Sequence[dict[str, Any]],
    indices: Sequence[int],
    node_scaler: StandardScaler,
    node_model: MiniBatchKMeans,
) -> np.ndarray:
    scores: list[float] = []
    for index in indices:
        nodes = np.asarray(graphs[index].get("nodes", []), dtype=np.float64)
        if nodes.ndim != 2 or len(nodes) == 0:
            scores.append(0.0)
            continue
        distances = node_model.transform(node_scaler.transform(nodes)).min(axis=1)
        keep = _normal_only_local_keep_count(cfg, len(distances))
        scores.append(float(np.partition(distances, len(distances) - keep)[-keep:].mean()))
    return np.asarray(scores, dtype=np.float64)


def _normal_only_fit_global_model(
    matrix: np.ndarray,
    cfg: FusionConfig,
) -> tuple[MiniBatchKMeans | NearestNeighbors, str]:
    mode = str(getattr(cfg, "task_normal_only_global_model", "kmeans"))
    if mode == "knn":
        neighbors = min(max(1, int(getattr(cfg, "task_normal_only_global_knn_neighbors", 5))), len(matrix))
        return NearestNeighbors(n_neighbors=neighbors, metric="euclidean").fit(matrix), mode
    return _normal_only_fit_kmeans(matrix, int(cfg.task_normal_only_task_prototypes), int(cfg.random_seed)), "kmeans"


def _normal_only_global_scores(
    graph_matrix: np.ndarray,
    graph_scaler: StandardScaler,
    graph_model: MiniBatchKMeans | NearestNeighbors,
    graph_model_mode: str,
) -> np.ndarray:
    transformed = graph_scaler.transform(graph_matrix)
    if graph_model_mode == "knn":
        distances, _ = graph_model.kneighbors(transformed)
        return distances.mean(axis=1).astype(np.float64)
    return graph_model.transform(transformed).min(axis=1).astype(np.float64)


def _normal_only_robust_scale(reference: np.ndarray) -> tuple[float, float]:
    center = float(np.median(reference))
    mad = float(np.median(np.abs(reference - center)))
    return center, max(1e-8, 1.4826 * mad)


def _normal_only_combine_scores(
    local_scores: np.ndarray,
    global_scores: np.ndarray,
    local_center: float,
    local_scale: float,
    global_center: float,
    global_scale: float,
    global_weight: float,
) -> np.ndarray:
    local_normalized = np.maximum(0.0, (local_scores - local_center) / local_scale)
    global_normalized = np.maximum(0.0, (global_scores - global_center) / global_scale)
    return ((1.0 - float(global_weight)) * local_normalized) + (float(global_weight) * global_normalized)


def _run_normal_only_tc3(
    cfg: FusionConfig,
    bundle: dict[str, Any],
    model_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    graphs = copy.deepcopy(bundle["selected_graphs"])
    metas = copy.deepcopy(bundle["selected_graph_metas"])
    split = _normal_only_temporal_split(cfg, graphs, metas)
    if getattr(cfg, "task_normal_only_detector", "prototype") == "gin_autoencoder":
        result = run_normal_only_gin_autoencoder(cfg, graphs, metas, split, model_path)
        return result.rows, _rows_metrics(result.rows), result.info
    train_indices = list(split["train_indices"])
    validation_indices = list(split["validation_indices"])
    evaluation_indices = list(split["evaluation_indices"])

    train_nodes = _normal_only_sample_rows(
        _normal_only_node_matrix(graphs, train_indices),
        int(cfg.task_normal_only_node_sample_limit),
        int(cfg.random_seed),
    )
    node_scaler = StandardScaler().fit(train_nodes)
    node_model = _normal_only_fit_kmeans(
        node_scaler.transform(train_nodes),
        int(cfg.task_normal_only_node_prototypes),
        int(cfg.random_seed),
    )

    train_graph_matrix = _normal_only_graph_matrix(graphs, metas, train_indices)
    graph_scaler = StandardScaler().fit(train_graph_matrix)
    graph_model, graph_model_mode = _normal_only_fit_global_model(
        graph_scaler.transform(train_graph_matrix),
        cfg,
    )

    validation_local = _normal_only_node_local_scores(
        cfg, graphs, validation_indices, node_scaler, node_model
    )
    validation_global = _normal_only_global_scores(
        _normal_only_graph_matrix(graphs, metas, validation_indices), graph_scaler, graph_model, graph_model_mode
    )
    local_center, local_scale = _normal_only_robust_scale(validation_local)
    global_center, global_scale = _normal_only_robust_scale(validation_global)
    validation_scores = _normal_only_combine_scores(
        validation_local,
        validation_global,
        local_center,
        local_scale,
        global_center,
        global_scale,
        float(cfg.task_normal_only_global_weight),
    )
    threshold = float(np.quantile(validation_scores, 1.0 - float(cfg.task_normal_only_validation_fpr)))

    evaluation_local = _normal_only_node_local_scores(
        cfg, graphs, evaluation_indices, node_scaler, node_model
    )
    evaluation_global = _normal_only_global_scores(
        _normal_only_graph_matrix(graphs, metas, evaluation_indices), graph_scaler, graph_model, graph_model_mode
    )
    evaluation_scores = _normal_only_combine_scores(
        evaluation_local,
        evaluation_global,
        local_center,
        local_scale,
        global_center,
        global_scale,
        float(cfg.task_normal_only_global_weight),
    )

    rows: list[dict[str, Any]] = []
    for index, local_score, global_score, final_score in zip(
        evaluation_indices,
        evaluation_local.tolist(),
        evaluation_global.tolist(),
        evaluation_scores.tolist(),
    ):
        graph = graphs[index]
        meta = metas[index]
        label = _normal_only_label(graph, meta)
        predicted = int(final_score >= threshold)
        rows.append(
            {
                "task_id": str(meta.get("task_id", f"task_{index:04d}")),
                "task_score": float(final_score),
                "task_probability": float(final_score),
                "graphsage_probability": None,
                "stats_probability": None,
                "normal_only_local_score": float(local_score),
                "normal_only_global_score": float(global_score),
                "fusion_weight_stats": 0.0,
                "task_label": label,
                "predicted_label": predicted,
                "prediction_mode": "normal_only_validation_threshold",
                "task_score_basis": "normal_process_topk_plus_task_prototype_distance",
                "threshold_used": threshold,
                "is_suspicious": bool(predicted),
                "task_size": int(meta.get("task_size", len(graph.get("nodes", [])))),
                "internal_edge_count": int(meta.get("internal_edge_count", len(graph.get("edges", [])))),
                "process_ids": [str(node) for node in meta.get("node_ids", [])],
                "process_stat_overrides": copy.deepcopy(meta.get("process_stat_overrides", {})),
            }
        )
    rows.sort(key=lambda row: (float(row["task_score"]), row["task_id"]), reverse=True)

    model = {
        "mode": "normal_only_multimodal_prototype",
        "node_scaler": node_scaler,
        "node_model": node_model,
        "graph_scaler": graph_scaler,
        "graph_model": graph_model,
        "local_center": local_center,
        "local_scale": local_scale,
        "global_center": global_center,
        "global_scale": global_scale,
        "threshold": threshold,
        "config": {
            "task_prototypes": int(node_model.n_clusters),
            "graph_prototypes": int(graph_model.n_clusters) if graph_model_mode == "kmeans" else 0,
            "global_model": graph_model_mode,
            "global_knn_neighbors": int(getattr(graph_model, "n_neighbors", 0)),
            "local_top_k": int(cfg.task_normal_only_local_top_k),
            "local_top_k_mode": str(getattr(cfg, "task_normal_only_local_top_k_mode", "fixed")),
            "local_top_k_max": int(getattr(cfg, "task_normal_only_local_top_k_max", 16)),
            "global_weight": float(cfg.task_normal_only_global_weight),
            "validation_fpr": float(cfg.task_normal_only_validation_fpr),
        },
    }
    ensure_parent(model_path)
    with model_path.open("wb") as fh:
        pickle.dump(model, fh)
    return rows, _rows_metrics(rows), {
        **copy.deepcopy(split["summary"]),
        "node_training_sample_count": int(len(train_nodes)),
        "node_prototype_count": int(node_model.n_clusters),
        "task_prototype_count": int(graph_model.n_clusters) if graph_model_mode == "kmeans" else 0,
        "global_model": graph_model_mode,
        "global_knn_neighbors": int(getattr(graph_model, "n_neighbors", 0)),
        "local_top_k_mode": str(getattr(cfg, "task_normal_only_local_top_k_mode", "fixed")),
        "local_top_k_max": int(getattr(cfg, "task_normal_only_local_top_k_max", 16)),
        "threshold": threshold,
        "threshold_source": "benign_validation_quantile",
        "validation_fpr_target": float(cfg.task_normal_only_validation_fpr),
        "validation_score_min": float(validation_scores.min()),
        "validation_score_max": float(validation_scores.max()),
        "validation_score_median": float(np.median(validation_scores)),
    }
    unique_labels, label_counts = np.unique(labels, return_counts=True) if len(labels) else (np.asarray([]), np.asarray([]))
    stratified = bool(len(unique_labels) >= 2 and int(label_counts.min()) >= 2 and count >= 3)

    requested_strategy = str(getattr(cfg, "task_fit_split_strategy", "stratified_shuffle_split"))
    fallback_reason = ""

    if count <= 1:
        train_indices = list(range(count))
        eval_indices: list[int] = []
        split_mode = "degenerate_all_train"
    else:
        can_use_kfold = (
            requested_strategy == "stratified_kfold"
            and stratified
            and count >= int(cfg.task_fit_kfold_splits)
            and int(label_counts.min()) >= int(cfg.task_fit_kfold_splits)
        )
        if can_use_kfold:
            splitter = StratifiedKFold(
                n_splits=int(cfg.task_fit_kfold_splits),
                shuffle=True,
                random_state=int(cfg.random_seed),
            )
            fold_splits = list(splitter.split(np.zeros((count, 1)), labels))
            fold_index = int(cfg.task_fit_kfold_index) % len(fold_splits)
            train_idx, eval_idx = fold_splits[fold_index]
            train_indices = [int(index) for index in train_idx.tolist()]
            eval_indices = [int(index) for index in eval_idx.tolist()]
            split_mode = "stratified_kfold"
        elif stratified:
            if requested_strategy == "stratified_kfold":
                fallback_reason = "kfold_not_feasible_for_class_counts_or_task_count"
            splitter = StratifiedShuffleSplit(
                n_splits=1,
                test_size=float(test_fraction),
                random_state=int(cfg.random_seed),
            )
            train_idx, eval_idx = next(splitter.split(np.zeros((count, 1)), labels))
            train_indices = [int(index) for index in train_idx.tolist()]
            eval_indices = [int(index) for index in eval_idx.tolist()]
            split_mode = "stratified_shuffle_split"
        else:
            if requested_strategy == "stratified_kfold":
                fallback_reason = "kfold_requires_stratifiable_labels"
            rng = random.Random(int(cfg.random_seed))
            indices = list(range(count))
            rng.shuffle(indices)
            eval_count = max(1, int(round(count * float(test_fraction))))
            if eval_count >= count:
                eval_count = max(0, count - 1)
            eval_indices = sorted(indices[:eval_count])
            train_indices = sorted(indices[eval_count:]) if eval_count > 0 else sorted(indices)
            split_mode = "random_shuffle_fallback"

    train_graphs = [copy.deepcopy(graphs[index]) for index in train_indices]
    train_graph_metas = [copy.deepcopy(graph_metas[index]) for index in train_indices]
    eval_graphs = [copy.deepcopy(graphs[index]) for index in eval_indices]
    eval_graph_metas = [copy.deepcopy(graph_metas[index]) for index in eval_indices]

    return {
        "mode": split_mode,
        "requested_strategy": requested_strategy,
        "stratified": stratified,
        "seed": int(cfg.random_seed),
        "test_fraction": float(test_fraction),
        "kfold_splits": int(cfg.task_fit_kfold_splits),
        "kfold_index": int(cfg.task_fit_kfold_index),
        "fallback_reason": fallback_reason,
        "raw_task_count": int(count),
        "raw_positive_count": int(labels.sum()) if len(labels) else 0,
        "raw_negative_count": int(count - labels.sum()) if len(labels) else 0,
        "train_task_count_raw": int(len(train_graphs)),
        "train_positive_count_raw": int(sum(int(graph.get("label", meta.get("label", 0))) for graph, meta in zip(train_graphs, train_graph_metas))),
        "train_negative_count_raw": int(
            len(train_graphs)
            - sum(int(graph.get("label", meta.get("label", 0))) for graph, meta in zip(train_graphs, train_graph_metas))
        ),
        "eval_task_count": int(len(eval_graphs)),
        "eval_positive_count": int(sum(int(graph.get("label", meta.get("label", 0))) for graph, meta in zip(eval_graphs, eval_graph_metas))),
        "eval_negative_count": int(
            len(eval_graphs)
            - sum(int(graph.get("label", meta.get("label", 0))) for graph, meta in zip(eval_graphs, eval_graph_metas))
        ),
        "train_graphs": train_graphs,
        "train_graph_metas": train_graph_metas,
        "eval_graphs": eval_graphs,
        "eval_graph_metas": eval_graph_metas,
    }


def _predict_rows(
    model,
    loader,
    graphs: Sequence[dict[str, Any]],
    graph_metas: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.eval()
    model.to(device)
    rows: list[dict[str, Any]] = []
    labels: list[int] = []
    probs: list[float] = []
    preds: list[int] = []
    offset = 0
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            _, logits = model(batch.x, batch.edge_index, batch.batch)
            batch_probs = torch.softmax(logits, dim=1)[:, 1].detach().cpu().numpy()
            batch_preds = logits.argmax(dim=1).detach().cpu().numpy()
            batch_size = len(batch_preds)
            for local_idx in range(batch_size):
                graph = graphs[offset + local_idx]
                graph_meta = graph_metas[offset + local_idx]
                prob = float(batch_probs[local_idx])
                pred = int(batch_preds[local_idx])
                label = int(graph.get("label", graph_meta.get("label", 0)))
                rows.append(
                    {
                        "task_id": str(graph_meta.get("task_id", f"task_{offset + local_idx:04d}")),
                        "task_score": prob,
                        "task_probability": prob,
                        "graphsage_probability": prob,
                        "stats_probability": None,
                        "fusion_weight_stats": 0.0,
                        "task_label": label,
                        "predicted_label": pred,
                        "prediction_mode": "argmax",
                        "task_score_basis": "tapas_graphsage",
                        "threshold_used": None,
                        "is_suspicious": bool(pred),
                        "task_size": int(graph_meta.get("task_size", len(graph.get("nodes", [])))),
                        "internal_edge_count": int(graph_meta.get("internal_edge_count", len(graph.get("edges", [])))),
                        "process_ids": [str(node) for node in graph_meta.get("node_ids", [])],
                        "process_stat_overrides": copy.deepcopy(graph_meta.get("process_stat_overrides", {})),
                    }
                )
                labels.append(label)
                probs.append(prob)
                preds.append(pred)
            offset += batch_size
    rows.sort(key=lambda row: (float(row["task_score"]), row["task_id"]), reverse=True)
    return rows, _metrics_dict(labels, probs, preds)

def _vendor_model_path(workspace: Path, family: str, dataset_name: str) -> Path:
    if family == "tc3":
        return workspace / "model" / f"{dataset_name}.pkl"
    return workspace / "model" / "optc.pkl"


def _copy_model_to_output(source: Path, target: Path) -> Path:
    ensure_parent(target)
    if source.resolve() != target.resolve():
        shutil.copy2(source, target)
    return target


def _augment_graph_metas(
    graph_metas: list[dict[str, Any]],
    divisor: int,
    bonus: int = 0,
) -> list[dict[str, Any]]:
    if divisor <= 0:
        return copy.deepcopy(graph_metas)
    augmented: list[dict[str, Any]] = []
    count = len(graph_metas)
    for meta in copy.deepcopy(graph_metas):
        if int(meta.get("label", 0)) == 1:
            needadd = max(0, (count // divisor) + bonus)
            augmented.append(meta)
            for aug_index in range(needadd):
                extra = copy.deepcopy(meta)
                extra["task_id"] = f"{meta.get('task_id', 'task')}_aug{aug_index + 1:03d}"
                augmented.append(extra)
        else:
            augmented.append(meta)
    return augmented


def _normalize_stat_vector(values: Sequence[Any], stat_feature_dim: int) -> list[float]:
    vector = [float(value) for value in values[:stat_feature_dim]]
    if len(vector) < stat_feature_dim:
        vector.extend([0.0] * (stat_feature_dim - len(vector)))
    return vector


def _collect_benign_stat_prototypes(
    graph_metas: Sequence[dict[str, Any]],
    stat_embeddings_map: dict[str, list[float]],
    stat_feature_dim: int,
    *,
    limit: int = 10,
) -> list[list[float]]:
    if stat_feature_dim <= 0 or not stat_embeddings_map:
        return []
    prototypes: list[list[float]] = []
    seen: set[tuple[float, ...]] = set()
    for meta in graph_metas:
        if int(meta.get("label", 0)) != 0:
            continue
        for process_id in meta.get("node_ids", []):
            raw = stat_embeddings_map.get(str(process_id))
            if not raw:
                continue
            vector = _normalize_stat_vector(raw, stat_feature_dim)
            if not any(abs(value) > 1e-12 for value in vector):
                continue
            key = tuple(round(value, 12) for value in vector)
            if key in seen:
                continue
            seen.add(key)
            prototypes.append(vector)
            if len(prototypes) >= limit:
                return prototypes
    if prototypes:
        return prototypes
    fallback_ids = sorted(stat_embeddings_map.keys())[:limit]
    return [
        _normalize_stat_vector(stat_embeddings_map[process_id], stat_feature_dim)
        for process_id in fallback_ids
    ]


def _augment_positive_graph_with_stat_overrides(
    vendor: ModuleType,
    graph: dict[str, Any],
    graph_meta: dict[str, Any],
    dataset_name: str,
    *,
    needadd: int,
    base_feature_dim: int,
    stat_feature_dim: int,
    benign_stat_prototypes: Sequence[Sequence[float]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if needadd <= 0:
        return [], []

    if graph.get("nodes"):
        graph_has_embedded_stats = len(graph["nodes"][0]) > base_feature_dim
        if graph_has_embedded_stats:
            seq_nodes = [list(node[:base_feature_dim]) for node in graph["nodes"]]
            stat_suffix = [
                _normalize_stat_vector(node[base_feature_dim:], stat_feature_dim)
                for node in graph["nodes"]
            ]
        else:
            seq_nodes = [list(node[:base_feature_dim]) for node in graph["nodes"]]
            stat_suffix = [[0.0] * stat_feature_dim for _ in graph["nodes"]]
    else:
        graph_has_embedded_stats = False
        seq_nodes = []
        stat_suffix = []

    augmented_seq_nodes = vendor.dataenhance(
        copy.deepcopy(seq_nodes),
        needadd,
        dataset_name,
        return_metadata=True,
    )
    augmented_graphs: list[dict[str, Any]] = []
    augmented_metas: list[dict[str, Any]] = []
    node_ids = [str(node) for node in graph_meta.get("node_ids", [])]

    for aug_index, seq_variant_info in enumerate(augmented_seq_nodes):
        seq_variant = copy.deepcopy(seq_variant_info.get("nodes", []))
        replaced_index = int(seq_variant_info.get("replaced_index", -1))
        merged_graph = copy.deepcopy(graph)
        stat_variant = copy.deepcopy(stat_suffix)
        process_stat_overrides: dict[str, list[float]] = {}

        if (
            0 <= replaced_index < len(node_ids)
            and stat_feature_dim > 0
            and benign_stat_prototypes
            and replaced_index < len(stat_variant)
        ):
            chosen_stats = _normalize_stat_vector(
                benign_stat_prototypes[random.randrange(len(benign_stat_prototypes))],
                stat_feature_dim,
            )
            stat_variant[replaced_index] = chosen_stats
            process_stat_overrides[node_ids[replaced_index]] = chosen_stats

        if graph_has_embedded_stats and stat_feature_dim > 0 and len(stat_variant) == len(seq_variant):
            merged_graph["nodes"] = [
                [float(value) for value in seq_variant[idx][:base_feature_dim]] + list(stat_variant[idx])
                for idx in range(len(seq_variant))
            ]
        else:
            merged_graph["nodes"] = [
                [float(value) for value in node[:base_feature_dim]]
                for node in seq_variant
            ]
        augmented_graphs.append(merged_graph)

        merged_meta = copy.deepcopy(graph_meta)
        merged_meta["task_id"] = f"{graph_meta.get('task_id', 'task')}_aug{aug_index + 1:03d}"
        if process_stat_overrides:
            merged_meta["process_stat_overrides"] = process_stat_overrides
        augmented_metas.append(merged_meta)

    return augmented_graphs, augmented_metas


def _tc3_trace_augmentation_bonus(cfg: FusionConfig) -> int:
    if cfg.dataset_family == "tc3" and cfg.host.lower() == "trace":
        return max(0, int(cfg.task_tapas_trace_augmentation_bonus))
    return 0


def _tc3_augmentation_divisor(cfg: FusionConfig) -> int:
    if not bool(cfg.task_tapas_augmentation_enabled):
        return 0
    return max(0, int(cfg.task_tapas_augmentation_divisor))


def _augment_graphs_preserve_stats_tc3(
    cfg: FusionConfig,
    vendor: ModuleType,
    graphs: list[dict[str, Any]],
    graph_metas: list[dict[str, Any]],
    dataset_name: str,
    base_feature_dim: int,
    stat_embeddings_map: dict[str, list[float]],
    stat_feature_dim: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if base_feature_dim <= 0:
        return copy.deepcopy(graphs), copy.deepcopy(graph_metas)
    if not graphs:
        return [], []
    divisor = _tc3_augmentation_divisor(cfg)
    trace_bonus = _tc3_trace_augmentation_bonus(cfg)
    benign_stat_prototypes = _collect_benign_stat_prototypes(
        graph_metas,
        stat_embeddings_map,
        stat_feature_dim,
    )

    data_pro: list[dict[str, Any]] = []
    meta_pro: list[dict[str, Any]] = []
    count = len(graphs)
    for graph, graph_meta in zip(copy.deepcopy(graphs), copy.deepcopy(graph_metas)):
        if int(graph.get("label", 0)) == 1:
            needadd = max(0, (count // divisor) + trace_bonus) if divisor > 0 else 0
            data_pro.append(graph)
            meta_pro.append(graph_meta)
            if needadd <= 0:
                continue
            augmented_graphs, augmented_metas = _augment_positive_graph_with_stat_overrides(
                vendor,
                graph,
                graph_meta,
                dataset_name,
                needadd=needadd,
                base_feature_dim=base_feature_dim,
                stat_feature_dim=stat_feature_dim,
                benign_stat_prototypes=benign_stat_prototypes,
            )
            data_pro.extend(augmented_graphs)
            meta_pro.extend(augmented_metas)
        else:
            data_pro.append(graph)
            meta_pro.append(graph_meta)
    return data_pro, meta_pro


def _augment_graphs_preserve_stats_optc(
    vendor: ModuleType,
    graphs: list[dict[str, Any]],
    graph_metas: list[dict[str, Any]],
    host_id: str,
    base_feature_dim: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if base_feature_dim <= 0:
        return copy.deepcopy(graphs), copy.deepcopy(graph_metas)
    if not graphs:
        return [], []
    if not graphs[0].get("nodes") or len(graphs[0]["nodes"][0]) <= base_feature_dim:
        return vendor.data_deal(copy.deepcopy(graphs), host_id), _augment_graph_metas(graph_metas, 60)

    data_pro: list[dict[str, Any]] = []
    meta_pro: list[dict[str, Any]] = []
    count = len(graphs)
    for graph, graph_meta in zip(copy.deepcopy(graphs), copy.deepcopy(graph_metas)):
        if int(graph.get("label", 0)) == 1:
            needadd = count // 60
            data_pro.append(graph)
            meta_pro.append(graph_meta)
            seq_nodes = [list(node[:base_feature_dim]) for node in graph["nodes"]]
            stat_suffix = [list(node[base_feature_dim:]) for node in graph["nodes"]]
            augmented_seq_nodes = vendor.dataenhance(copy.deepcopy(seq_nodes), host_id, needadd)
            for aug_index, seq_variant in enumerate(augmented_seq_nodes):
                merged_graph = copy.deepcopy(graph)
                merged_graph["nodes"] = [
                    [float(value) for value in seq_variant[idx][:base_feature_dim]] + list(stat_suffix[idx])
                    for idx in range(len(seq_variant))
                ]
                data_pro.append(merged_graph)
                merged_meta = copy.deepcopy(graph_meta)
                merged_meta["task_id"] = f"{graph_meta.get('task_id', 'task')}_aug{aug_index + 1:03d}"
                meta_pro.append(merged_meta)
        else:
            data_pro.append(graph)
            meta_pro.append(graph_meta)
    return data_pro, meta_pro


def _train_tc3_exact(
    cfg: FusionConfig,
    vendor: ModuleType,
    workspace: Path,
    bundle: dict[str, Any],
    model_path: Path,
) -> dict[str, Any]:
    data_path = workspace / "data" / bundle["dataset_name"] / "data.pt"
    ensure_parent(data_path)
    base_graphs = copy.deepcopy(bundle["selected_graphs"])
    base_graph_metas = copy.deepcopy(bundle["selected_graph_metas"])
    base_feature_dim = int(bundle.get("base_sequence_feature_dim", bundle["sequence_feature_dim"]))
    split_before_augment = not bool(cfg.task_tapas_augmentation_before_split)

    with _temporary_cwd(workspace):
        random.seed(int(cfg.random_seed))
        np.random.seed(int(cfg.random_seed))
        torch.manual_seed(int(cfg.random_seed))
        if split_before_augment:
            raw_split = _split_graphs_with_metas(cfg, base_graphs, base_graph_metas)
            final_train_graphs, final_train_graph_metas = _augment_graphs_preserve_stats_tc3(
                cfg,
                vendor,
                copy.deepcopy(raw_split["train_graphs"]),
                copy.deepcopy(raw_split["train_graph_metas"]),
                bundle["dataset_name"],
                base_feature_dim,
                bundle.get("selected_stat_embeddings", {}),
                len(bundle.get("stat_feature_columns", [])),
            )
            eval_graphs = copy.deepcopy(raw_split["eval_graphs"])
            eval_graph_metas = copy.deepcopy(raw_split["eval_graph_metas"])
            split_mode = "split_before_augment"
            split_summary = raw_split
        else:
            augmented_graphs, augmented_graph_metas = _augment_graphs_preserve_stats_tc3(
                cfg,
                vendor,
                base_graphs,
                base_graph_metas,
                bundle["dataset_name"],
                base_feature_dim,
                bundle.get("selected_stat_embeddings", {}),
                len(bundle.get("stat_feature_columns", [])),
            )
            augmented_split = _split_graphs_with_metas(cfg, augmented_graphs, augmented_graph_metas)
            final_train_graphs = copy.deepcopy(augmented_split["train_graphs"])
            final_train_graph_metas = copy.deepcopy(augmented_split["train_graph_metas"])
            eval_graphs = copy.deepcopy(augmented_split["eval_graphs"])
            eval_graph_metas = copy.deepcopy(augmented_split["eval_graph_metas"])
            split_mode = "augment_before_split"
            split_summary = augmented_split
        torch.save(final_train_graphs, data_path)
        vendor.train(
            [0.001, 100, 500],
            bundle["dataset_name"],
            class_weight_w0=1.0,
            class_weight_w1=2.0,
            dropout_p=0.0,
            seed=int(cfg.random_seed),
            train_eval_split=False,
        )
    workspace_model = _vendor_model_path(workspace, "tc3", bundle["dataset_name"])
    _copy_model_to_output(workspace_model, model_path)
    return {
        "train_graphs": final_train_graphs,
        "train_graph_metas": final_train_graph_metas,
        "eval_graphs": eval_graphs,
        "eval_graph_metas": eval_graph_metas,
        "split_mode": split_mode,
        "split_summary": {
            key: value
            for key, value in split_summary.items()
            if key not in {"train_graphs", "train_graph_metas", "eval_graphs", "eval_graph_metas"}
        },
    }


def _train_optc_exact(
    vendor: ModuleType,
    workspace: Path,
    bundle: dict[str, Any],
    model_path: Path,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    optc_root = workspace / "data" / "optc"
    ensure_dir(optc_root)
    augmented_by_host: dict[str, list[dict[str, Any]]] = {}
    augmented_metas_by_host: dict[str, list[dict[str, Any]]] = {}
    data_all: list[dict[str, Any]] = []
    data_all_metas: list[dict[str, Any]] = []
    with _temporary_cwd(workspace):
        random.seed(202520252025)
        for host_id in bundle["host_order"]:
            host_graphs = copy.deepcopy(bundle["raw_graphs_by_host"].get(host_id, []))
            if not host_graphs:
                raise FileNotFoundError(f"Exact TAPAS OpTC training is missing host {host_id} in the module1 bundle.")
            host_graph_metas = copy.deepcopy(bundle["raw_graph_metas_by_host"].get(host_id, []))
            augmented, augmented_metas = _augment_graphs_preserve_stats_optc(
                vendor,
                host_graphs,
                host_graph_metas,
                host_id,
                int(bundle.get("base_sequence_feature_dim", bundle["sequence_feature_dim"])),
            )
            augmented_by_host[host_id] = augmented
            augmented_metas_by_host[host_id] = augmented_metas
            torch.save(augmented, optc_root / f"{host_id}.pt")
            data_all += augmented
            data_all_metas += augmented_metas
        torch.save(data_all, optc_root / "data_all.pt")
        vendor.train([0.001, 200, 500], seed=2025, train_eval_split=False)
    workspace_model = _vendor_model_path(workspace, "optc", bundle["dataset_name"])
    _copy_model_to_output(workspace_model, model_path)
    return data_all, data_all_metas, augmented_by_host, augmented_metas_by_host


def _evaluate_tc3_exact(
    model_path: Path,
    vendor: ModuleType,
    train_graphs: list[dict[str, Any]],
    train_graph_metas: list[dict[str, Any]],
    eval_graphs: list[dict[str, Any]],
    eval_graph_metas: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    model = _torch_load(model_path)
    train_loader = DataLoader(vendor.MyOwnDataset(train_graphs), batch_size=500, shuffle=False)
    train_rows, train_metrics = _predict_rows(model, train_loader, train_graphs, train_graph_metas)
    if eval_graphs:
        test_loader = DataLoader(vendor.MyOwnDataset(eval_graphs), shuffle=False)
        eval_rows, eval_metrics = _predict_rows(model, test_loader, eval_graphs, eval_graph_metas)
    else:
        eval_rows, eval_metrics = [], {}
    return train_rows, train_metrics, eval_rows, eval_metrics


def _evaluate_optc_exact(
    model_path: Path,
    vendor: ModuleType,
    training_graphs: list[dict[str, Any]],
    training_graph_metas: list[dict[str, Any]],
    evaluation_graphs: list[dict[str, Any]],
    evaluation_graph_metas: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    train_dataset = vendor.MyOwnDataset(training_graphs)
    shuffled_train_dataset, shuffled_train_graphs, shuffled_train_graph_metas = _shuffle_dataset_with_graphs(
        train_dataset,
        training_graphs,
        training_graph_metas,
        seed=2024,
    )
    index = int(0.8 * len(shuffled_train_dataset))
    train_data = shuffled_train_dataset[:index]
    train_graphs = shuffled_train_graphs[:index]
    train_graph_metas = shuffled_train_graph_metas[:index]

    eval_dataset = vendor.MyOwnDataset(evaluation_graphs)
    shuffled_eval_dataset, shuffled_eval_graphs, shuffled_eval_graph_metas = _shuffle_dataset_with_graphs(
        eval_dataset,
        evaluation_graphs,
        evaluation_graph_metas,
        seed=2024,
    )

    model = _torch_load(model_path)
    train_loader = DataLoader(train_data, batch_size=500, shuffle=False)
    eval_loader = DataLoader(shuffled_eval_dataset, shuffle=False)
    train_rows, train_metrics = _predict_rows(model, train_loader, train_graphs, train_graph_metas)
    eval_rows, eval_metrics = _predict_rows(model, eval_loader, shuffled_eval_graphs, shuffled_eval_graph_metas)
    return train_rows, train_metrics, eval_rows, eval_metrics


def _predict_all_graphs(
    model_path: Path,
    vendor: ModuleType,
    graphs: list[dict[str, Any]],
    graph_metas: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    dataset = vendor.MyOwnDataset(graphs)
    model = _torch_load(model_path)
    loader = DataLoader(dataset, shuffle=False)
    return _predict_rows(model, loader, graphs, graph_metas)


def _summary_common(cfg: FusionConfig, bundle: dict[str, Any], model_path: Path) -> dict[str, Any]:
    return {
        "backend": "tapas_exact_vendor",
        "mode": cfg.task_detector_mode,
        "dataset_family": cfg.dataset_family,
        "host": cfg.host,
        "tapas_dataset_name": bundle["dataset_name"],
        "selected_dataset_name": bundle["selected_dataset_name"],
        "prediction_mode": "argmax",
        "average_mode": "macro",
        "tapas_exact": True,
        "source_chain": "official_parser_encode_cut_task_decompose_data_deal_train",
        "node_feature_sources": _graphsage_node_feature_sources(cfg),
        "graph_stat_sidecar_sources": {
            "ocr_stat_features": bool(cfg.use_ocr_stat_features),
        },
        "graphsage_append_ocr_stat_features": bool(cfg.graphsage_append_ocr_stat_features),
        "task_tc3_event_stats_mode": str(cfg.task_tc3_event_stats_mode),
        "stat_feature_source": str(bundle.get("stat_feature_source", "disabled")),
        "decision_threshold": 0.5,
        "decision_threshold_mode": "argmax",
        "decision_threshold_selection": {
            "mode": "argmax_not_used",
            "reason": "prediction_mode_argmax",
            "selected_threshold": 0.5,
        },
        "task_graph_stat_late_fusion_requested": bool(_late_fusion_requested(cfg)),
        "task_graph_stat_late_fusion_active": False,
        "task_graph_stat_fusion_weight": float(cfg.task_graph_stat_fusion_weight) if _late_fusion_requested(cfg) else 0.0,
        "task_graph_stat_model": "",
        "task_graph_stat_feature_dim": 0,
        "task_graph_stat_model_path": "",
        "task_graph_stat_late_fusion_reason": "",
        "task_score_basis": "tapas_graphsage",
        "task_min_graph_nodes": 2,
        "task_graph_bidirectional_edges": False,
        "task_graph_self_loops": False,
        "tapas_augmentation_enabled": bool(cfg.task_tapas_augmentation_enabled),
        "tapas_augmentation_divisor": int(cfg.task_tapas_augmentation_divisor),
        "tapas_trace_augmentation_bonus": int(cfg.task_tapas_trace_augmentation_bonus),
        "tapas_augmentation_before_split": bool(cfg.task_tapas_augmentation_before_split),
        "tapas_faithful_mode": True,
        "model_input": str(_model_input_path(cfg, model_path.parent)) if cfg.task_detector_mode == "load_and_predict" else "",
        "model_output": str(model_path),
        "feature_dim": _feature_dim_from_map(bundle["selected_embeddings"]),
        "sequence_feature_dim": int(bundle.get("base_sequence_feature_dim", bundle["sequence_feature_dim"])),
        "stat_feature_dim": len(bundle.get("stat_feature_columns", [])),
        "stat_feature_columns": list(bundle.get("stat_feature_columns", [])),
        "stats_only_mode": bool(cfg.use_ocr_stat_features and not cfg.use_sequence_embeddings),
        "graph_metadata_sidecar_export_only": True,
    }


def run_tapas_module2(cfg: FusionConfig, module1_dir: Path, out_dir: Path) -> dict[str, Any]:
    ensure_dir(out_dir)
    bundle = _load_native_bundle(module1_dir)

    if cfg.task_detector_mode == "normal_only":
        if bundle["family"] != "tc3":
            raise ValueError("normal_only task detection currently supports tc3 task graphs only")
        model_path = _model_output_path(cfg, out_dir)
        normal_rows, normal_metrics, normal_info = _run_normal_only_tc3(cfg, bundle, model_path)
        summary = _summary_common(cfg, bundle, model_path)
        summary.update(
            {
                "prediction_mode": "normal_only_validation_threshold",
                "decision_threshold": float(normal_info["threshold"]),
                "decision_threshold_mode": "benign_validation_quantile",
                "decision_threshold_selection": {
                    "mode": "benign_validation_quantile",
                    "reason": "only benign validation task graphs select the alert threshold",
                    "selected_threshold": float(normal_info["threshold"]),
                    "target_false_positive_rate": float(cfg.task_normal_only_validation_fpr),
                },
                "task_graph_stat_late_fusion_active": False,
                "task_graph_stat_model": "",
                "task_graph_stat_feature_dim": 0,
                "task_graph_stat_model_path": "",
                "task_graph_stat_late_fusion_reason": "normal_only_detector_replaces_binary_late_fusion",
                "task_score_basis": "normal_process_topk_plus_task_prototype_distance",
                "normal_only": normal_info,
                "task_count": len(normal_rows),
                "evaluation_metrics": normal_metrics,
                "train_metrics": {},
                "train_task_count": int(normal_info["train_benign_count"]),
                "train_positive_count": 0,
                "train_negative_count": int(normal_info["train_benign_count"]),
                "evaluation_positive_count": int(sum(int(row["task_label"]) for row in normal_rows)),
                "evaluation_negative_count": int(
                    len(normal_rows) - sum(int(row["task_label"]) for row in normal_rows)
                ),
            }
        )
        summary.update(_score_summary(normal_rows))
        paths = _write_backend_outputs(out_dir, normal_rows, summary)
        paths["task_model"] = model_path
        return {
            "task_rows": normal_rows,
            "train_rows": [],
            "summary": summary,
            "decision_threshold": float(normal_info["threshold"]),
            "paths": paths,
        }

    workspace = _ensure_workspace(module1_dir, cfg)
    vendor = _load_vendor_for_family(bundle["family"])
    vendor.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if cfg.task_detector_mode == "fit_predict":
        model_path = _model_output_path(cfg, out_dir)
        if bundle["family"] == "tc3":
            tc3_fit = _train_tc3_exact(cfg, vendor, workspace, bundle, model_path)
            train_rows, train_metrics, eval_rows, eval_metrics = _evaluate_tc3_exact(
                model_path,
                vendor,
                tc3_fit["train_graphs"],
                tc3_fit["train_graph_metas"],
                tc3_fit["eval_graphs"],
                tc3_fit["eval_graph_metas"],
            )
            eval_dataset_name = bundle["dataset_name"]
            train_dataset_name = bundle["dataset_name"]
        else:
            training_graphs, training_graph_metas, augmented_by_host, augmented_metas_by_host = _train_optc_exact(
                vendor,
                workspace,
                bundle,
                model_path,
            )
            eval_dataset_name = bundle["selected_dataset_name"]
            evaluation_graphs = training_graphs if eval_dataset_name == "data_all" else augmented_by_host[eval_dataset_name]
            evaluation_graph_metas = (
                training_graph_metas
                if eval_dataset_name == "data_all"
                else augmented_metas_by_host[eval_dataset_name]
            )
            train_rows, train_metrics, eval_rows, eval_metrics = _evaluate_optc_exact(
                model_path,
                vendor,
                training_graphs,
                training_graph_metas,
                evaluation_graphs,
                evaluation_graph_metas,
            )
            train_dataset_name = "data_all"

        stats_model, fusion_info = _fit_graph_stat_sidecar_model(cfg, bundle, train_rows, model_path)
        if bool(fusion_info.get("active", False)) and stats_model is not None:
            train_rows, train_metrics = _apply_graph_stat_late_fusion(cfg, bundle, train_rows, stats_model)
            eval_rows, eval_metrics = _apply_graph_stat_late_fusion(cfg, bundle, eval_rows, stats_model)

        summary = _summary_common(cfg, bundle, model_path)
        summary.update(
            {
                "task_graph_stat_late_fusion_active": bool(fusion_info.get("active", False)),
                "task_graph_stat_model": str(fusion_info.get("model", "")),
                "task_graph_stat_feature_dim": int(fusion_info.get("feature_dim", 0)),
                "task_graph_stat_model_path": str(fusion_info.get("path", "")),
                "task_graph_stat_late_fusion_reason": str(fusion_info.get("reason", "")),
                "task_score_basis": "tapas_graphsage_plus_graph_stats"
                if bool(fusion_info.get("active", False))
                else "tapas_graphsage",
            }
        )
        if bundle["family"] == "tc3":
            summary.update(
                {
                    "fit_split_mode": str(tc3_fit.get("split_mode", "")),
                    "fit_split_summary": copy.deepcopy(tc3_fit.get("split_summary", {})),
                }
            )
        summary.update(_score_summary(eval_rows))
        summary.update(
            {
                "task_count": len(eval_rows),
                "evaluation_metrics": eval_metrics,
                "train_metrics": train_metrics,
                "train_task_count": len(train_rows),
                "train_positive_count": int(sum(int(row["task_label"]) for row in train_rows)),
                "train_negative_count": int(len(train_rows) - sum(int(row["task_label"]) for row in train_rows)),
                "evaluation_positive_count": int(sum(int(row["task_label"]) for row in eval_rows)),
                "evaluation_negative_count": int(len(eval_rows) - sum(int(row["task_label"]) for row in eval_rows)),
                "train_dataset_name": train_dataset_name,
                "evaluation_dataset_name": eval_dataset_name,
            }
        )
        paths = _write_backend_outputs(out_dir, eval_rows, summary)
        paths["task_model"] = model_path
        if bool(fusion_info.get("active", False)):
            paths["task_graph_stat_model"] = _stats_model_sidecar_path(model_path)
        return {
            "task_rows": eval_rows,
            "train_rows": train_rows,
            "summary": summary,
            "decision_threshold": 0.5,
            "paths": paths,
        }

    model_path = _model_input_path(cfg, out_dir)
    selected_graphs = bundle["selected_graphs"]
    selected_graph_metas = bundle["selected_graph_metas"]
    prediction_rows, prediction_metrics = _predict_all_graphs(model_path, vendor, selected_graphs, selected_graph_metas)
    loaded_stats_model = _load_graph_stat_sidecar_model(model_path) if _late_fusion_requested(cfg) else None
    if loaded_stats_model is not None:
        prediction_rows, prediction_metrics = _apply_graph_stat_late_fusion(cfg, bundle, prediction_rows, loaded_stats_model)
    summary = _summary_common(cfg, bundle, model_path)
    summary.update(
        {
            "task_graph_stat_late_fusion_active": loaded_stats_model is not None,
            "task_graph_stat_model": _graph_stat_model_name(loaded_stats_model) if loaded_stats_model is not None else "",
            "task_graph_stat_feature_dim": _graph_stat_feature_dim(len(bundle.get("stat_feature_columns", [])))
            if loaded_stats_model is not None
            else 0,
            "task_graph_stat_model_path": str(_stats_model_sidecar_path(model_path)) if loaded_stats_model is not None else "",
            "task_graph_stat_late_fusion_reason": ""
            if loaded_stats_model is not None
            else ("sidecar_model_not_found" if _late_fusion_requested(cfg) else "not_requested"),
            "task_score_basis": "tapas_graphsage_plus_graph_stats" if loaded_stats_model is not None else "tapas_graphsage",
        }
    )
    summary.update(_score_summary(prediction_rows))
    summary.update(
        {
            "task_count": len(prediction_rows),
            "evaluation_metrics": prediction_metrics,
            "train_metrics": {},
            "prediction_adapter_mode": "all_graphs_no_split",
        }
    )
    paths = _write_backend_outputs(out_dir, prediction_rows, summary)
    paths["task_model"] = model_path
    if loaded_stats_model is not None:
        paths["task_graph_stat_model"] = _stats_model_sidecar_path(model_path)
    return {
        "task_rows": prediction_rows,
        "train_rows": [],
        "summary": summary,
        "decision_threshold": 0.5,
        "paths": paths,
    }


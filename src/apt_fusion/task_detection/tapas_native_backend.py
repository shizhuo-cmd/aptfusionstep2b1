
from __future__ import annotations

import contextlib
import copy
import importlib.util
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
from sklearn.utils.class_weight import compute_sample_weight
from torch_geometric.loader import DataLoader

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover - optional dependency
    XGBClassifier = None

from ..common import ensure_dir, ensure_parent, save_json
from ..config import FusionConfig
from .ocr_stat_features import extract_process_stat_features

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
    }


def _tc3_supported_hosts() -> set[str]:
    return {"trace", "cadets", "fivedirections", "theia"}


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
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


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
        child = str(edge[0]).strip()
        parent = str(edge[1]).strip()
        if not child or not parent:
            continue
        key = (child, parent)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "child_process_id": child,
                "parent_process_id": parent,
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
) -> np.ndarray:
    feature_dim = _graph_stat_feature_dim(stat_feature_dim)
    if feature_dim <= 0:
        return np.zeros((0,), dtype=np.float64)

    node_stats: list[list[float]] = []
    active_nodes = 0
    nonzero_entries = 0
    total_entries = 0
    for process_id in process_ids:
        stats = [float(value) for value in stat_embeddings_map.get(str(process_id), [])]
        if len(stats) < stat_feature_dim:
            stats.extend([0.0] * (stat_feature_dim - len(stats)))
        elif len(stats) > stat_feature_dim:
            stats = stats[:stat_feature_dim]
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
        _graph_stat_feature_vector(row.get("process_ids", []), stat_embeddings_map, stat_feature_dim)
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
            attacknum = sum(1 for node in node_ids if str(node) in ground_truth)
            payload = {
                "task_id": f"task_{task_index:04d}",
                "node_ids": node_ids,
                "label": 1 if attacknum > 0 else 0,
                "attacknum": attacknum,
                "task_size": len(node_ids),
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
    task_component_kwargs = {
        "child_threshold": int(cfg.task_component_child_threshold),
        "split_mode": str(cfg.task_component_split_mode),
        "count_segmented_children_upstream": bool(cfg.task_component_count_segmented_children_upstream),
    }

    with _temporary_cwd(workspace):
        source_logs = _normalize_tc3_source_logs(cfg.source_logs)
        if cfg.host == "cadets":
            subject_list, object_list, event_count = vendor.parser_cadets(source_logs)
            subject_node = vendor.encode_cadets(subject_list, object_list, event_count)
            edge_list = vendor.cut_task(subject_list, return_task_components=True, **task_component_kwargs)
            raw_vectors = vendor.get_node_vec(subject_node)
        elif cfg.host == "fivedirections":
            subject_list, object_list, event_count = vendor.parser_fivedirections(source_logs)
            subject_node = vendor.encode_fivedirections(subject_list, object_list, event_count)
            edge_list = vendor.cut_task(subject_list, **task_component_kwargs)
            raw_vectors = vendor.get_node_vec(subject_node)
        elif cfg.host == "trace":
            subject_list, object_list, event_count = vendor.parser_trace(source_logs)
            subject_node = vendor.encode_trace(subject_list, object_list, event_count)
            edge_list = vendor.cut_task(subject_list, return_task_components=True, **task_component_kwargs)
            raw_vectors = vendor.get_node_vec(subject_node)
        elif cfg.host == "theia":
            edge_list, raw_vectors = vendor.filters(source_logs, return_task_components=True, **task_component_kwargs)
        else:
            edge_list, raw_vectors = vendor.filters(source_logs, **task_component_kwargs)
        raw_graphs = vendor.decompose(edge_list, raw_vectors, cfg.host)

    embeddings_map = _vector_rows_to_map(raw_vectors)
    graph_metas = _decompose_tc3_metadata(edge_list, ground_truth)
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
) -> tuple[dict[str, list[float]], list[str]]:
    process_ids = {str(node) for meta in graph_metas for node in meta.get("node_ids", [])}
    if not process_ids:
        return {}, []

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
    updated = copy.deepcopy(bundle)
    updated["base_sequence_feature_dim"] = int(bundle["sequence_feature_dim"]) if cfg.use_sequence_embeddings else 0
    updated["stat_feature_columns"] = []
    updated["selected_stat_embeddings"] = {}
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
        task_component_diagnostics.append(
            {
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
        )
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
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if base_feature_dim <= 0:
        return copy.deepcopy(graphs), copy.deepcopy(graph_metas)
    if not graphs:
        return [], []
    divisor = _tc3_augmentation_divisor(cfg)
    trace_bonus = _tc3_trace_augmentation_bonus(cfg)
    if not graphs[0].get("nodes") or len(graphs[0]["nodes"][0]) <= base_feature_dim:
        if divisor <= 0:
            return copy.deepcopy(graphs), copy.deepcopy(graph_metas)
        return vendor.data_deal(copy.deepcopy(graphs), dataset_name, divisor=divisor, bonus=trace_bonus), _augment_graph_metas(
            graph_metas,
            divisor,
            bonus=trace_bonus,
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
            seq_nodes = [list(node[:base_feature_dim]) for node in graph["nodes"]]
            stat_suffix = [list(node[base_feature_dim:]) for node in graph["nodes"]]
            augmented_seq_nodes = vendor.dataenhance(copy.deepcopy(seq_nodes), needadd, dataset_name)
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
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    data_path = workspace / "data" / bundle["dataset_name"] / "data.pt"
    ensure_parent(data_path)
    with _temporary_cwd(workspace):
        random.seed(173)
        train_graphs, train_graph_metas = _augment_graphs_preserve_stats_tc3(
            cfg,
            vendor,
            copy.deepcopy(bundle["selected_graphs"]),
            copy.deepcopy(bundle["selected_graph_metas"]),
            bundle["dataset_name"],
            int(bundle.get("base_sequence_feature_dim", bundle["sequence_feature_dim"])),
        )
        torch.save(train_graphs, data_path)
        vendor.train([0.001, 100, 500], bundle["dataset_name"])
    workspace_model = _vendor_model_path(workspace, "tc3", bundle["dataset_name"])
    _copy_model_to_output(workspace_model, model_path)
    return train_graphs, train_graph_metas


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
        vendor.train([0.001, 200, 500])
    workspace_model = _vendor_model_path(workspace, "optc", bundle["dataset_name"])
    _copy_model_to_output(workspace_model, model_path)
    return data_all, data_all_metas, augmented_by_host, augmented_metas_by_host


def _evaluate_tc3_exact(
    model_path: Path,
    vendor: ModuleType,
    graphs: list[dict[str, Any]],
    graph_metas: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    dataset = vendor.MyOwnDataset(graphs)
    shuffled_dataset, shuffled_graphs, shuffled_graph_metas = _shuffle_dataset_with_graphs(dataset, graphs, graph_metas, seed=2025)
    index = int(0.8 * len(shuffled_dataset))
    train_data = shuffled_dataset[:index]
    test_data = shuffled_dataset[index:]
    train_graphs = shuffled_graphs[:index]
    train_graph_metas = shuffled_graph_metas[:index]
    test_graphs = shuffled_graphs[index:]
    test_graph_metas = shuffled_graph_metas[index:]
    model = _torch_load(model_path)
    train_loader = DataLoader(train_data, batch_size=500, shuffle=False)
    test_loader = DataLoader(test_data, shuffle=False)
    train_rows, train_metrics = _predict_rows(model, train_loader, train_graphs, train_graph_metas)
    eval_rows, eval_metrics = _predict_rows(model, test_loader, test_graphs, test_graph_metas)
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
    workspace = _ensure_workspace(module1_dir, cfg)
    vendor = _load_vendor_for_family(bundle["family"])
    vendor.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if cfg.task_detector_mode == "fit_predict":
        model_path = _model_output_path(cfg, out_dir)
        if bundle["family"] == "tc3":
            training_graphs, training_graph_metas = _train_tc3_exact(cfg, vendor, workspace, bundle, model_path)
            train_rows, train_metrics, eval_rows, eval_metrics = _evaluate_tc3_exact(
                model_path,
                vendor,
                training_graphs,
                training_graph_metas,
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
        summary.update(_score_summary(eval_rows))
        summary.update(
            {
                "task_count": len(eval_rows),
                "evaluation_metrics": eval_metrics,
                "train_metrics": train_metrics,
                "train_task_count": len(train_rows),
                "train_positive_count": int(sum(int(row["task_label"]) for row in train_rows)),
                "train_negative_count": int(len(train_rows) - sum(int(row["task_label"]) for row in train_rows)),
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


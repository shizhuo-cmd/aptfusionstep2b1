"""Compare the shipped TAPAS sequence checkpoint with paper-aligned retraining.

The runner performs module1/module2 only.  It first creates the same normal-only
baseline used by E1, then trains a compatible LSTM-GRU on the benign training
processes and reruns module1/module2 with that checkpoint.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
import traceback
from pathlib import Path

import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_trace_tapas_aligned_sequence_matrix_20260802"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


BASE_CONFIGS = {
    "cadets": REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
    "trace": REPO / "configs" / "fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
}
INPUTS = {
    "cadets": (Path("/root/autodl-tmp/data/cadets/logs"), Path("/root/autodl-tmp/data/cadets/cadets.txt")),
    "trace": (Path("/root/autodl-tmp/data/trace/logs"), Path("/root/autodl-tmp/data/trace/trace.txt")),
}


def _load_pretrainer():
    path = REPO / "scripts" / "train_tc3_stackedlstm_pretrain_20260707.py"
    spec = importlib.util.spec_from_file_location("tapas_aligned_pretrainer_20260802", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to import sequence pretrainer: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _json_ready(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _configure(dataset: str, route: str, checkpoint: Path | None = None):
    cfg = copy.copy(load_config(BASE_CONFIGS[dataset]))
    source_logs, ground_truth = INPUTS[dataset]
    cfg.host = dataset
    cfg.source_logs = source_logs
    cfg.task_ground_truth_path = ground_truth
    cfg.artifacts_dir = REPO / f"artifacts_{dataset}_normal_only_{route}_20260802"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"{dataset}_normal_only_{route}_20260802" / "experiments"
    cfg.ocr_model_name = f"normal_only_{dataset}_{route}_20260802.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_sequence_model_path = checkpoint
    cfg.task_sequence_encoder_mode = "legacy"
    cfg.task_tapas_augmentation_enabled = False
    cfg.task_component_root_temporal_split_enabled = False
    cfg.task_normal_only_train_fraction = 0.70
    cfg.task_normal_only_validation_fraction = 0.15
    cfg.task_normal_only_validation_fpr = 0.02
    cfg.task_normal_only_global_model = "kmeans"
    cfg.task_normal_only_local_top_k_mode = "sqrt"
    cfg.task_normal_only_local_top_k_max = 16
    cfg.task_tc3_event_stats_mode = "security_semantic"
    cfg.use_sequence_embeddings = True
    cfg.use_ocr_stat_features = True
    cfg.graphsage_append_ocr_stat_features = True
    cfg.task_graph_stat_late_fusion_enabled = False
    cfg.path_reason_enabled = False
    return cfg


def _normal_train_subject_ids(cfg) -> set[str]:
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    benign = [meta for meta in bundle["selected_graph_metas"] if int(meta.get("label", 0)) == 0]
    benign.sort(key=lambda meta: str(meta.get("task_id", "")))
    train_count = max(1, int(len(benign) * float(cfg.task_normal_only_train_fraction)))
    return {str(node) for meta in benign[:train_count] for node in meta.get("node_ids", [])}


def _details(cfg, outputs: dict) -> dict:
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    rows = json.loads(Path(outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    predicted = [row for row in rows if int(row.get("predicted_label", 0)) == 1]
    return {
        "task_count": len(bundle["selected_graph_metas"]),
        "gt_positive_task_ids": [str(meta["task_id"]) for meta in bundle["selected_graph_metas"] if int(meta.get("label", 0)) == 1],
        "feature_dim": int(bundle.get("sequence_feature_dim", 0)) + len(bundle.get("stat_feature_columns", [])),
        "module2_metrics": backend.get("evaluation_metrics", {}),
        "threshold": backend.get("decision_threshold"),
        "normal_only": backend.get("normal_only", {}),
        "true_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 1],
        "false_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 0],
        "missed_positive_task_ids": [
            row["task_id"] for row in rows if int(row.get("task_label", 0)) == 1 and int(row.get("predicted_label", 0)) == 0
        ],
    }


def _mark_failed(path: Path) -> str | None:
    if not path.exists():
        return None
    target = path.with_name(f"{path.name}_failed_runtime_error")
    if target.exists():
        shutil.rmtree(target)
    path.rename(target)
    return str(target)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pretrainer = _load_pretrainer()
    records: list[dict] = []
    for dataset in ("cadets", "trace"):
        baseline_cfg = _configure(dataset, "tapas_paper_baseline")
        try:
            print(f"[START] {dataset}/baseline: module1 -> module2; module0 disabled", flush=True)
            baseline_module1 = run_module1(baseline_cfg)
            baseline_module2 = run_module2(
                baseline_cfg,
                baseline_module1["process_embeddings"],
                baseline_module1["task_subgraphs"],
                baseline_module1["process_segmentation_edges"],
            )
            baseline_details = _details(baseline_cfg, baseline_module2)
            allowed_subject_ids = _normal_train_subject_ids(baseline_cfg)
            allowed_path = baseline_cfg.artifacts_dir / "module1" / "sequence_pretrain_normal_subject_ids.json"
            allowed_path.write_text(json.dumps(sorted(allowed_subject_ids), indent=2), encoding="utf-8")
            records.append({
                "dataset": dataset,
                "route": "baseline_shipped_checkpoint",
                "status": "completed",
                "module0_called": False,
                "details": baseline_details,
            })
            print(f"[DONE] {dataset}/baseline", flush=True)
        except Exception as exc:
            traceback.print_exc()
            records.append({
                "dataset": dataset,
                "route": "baseline_shipped_checkpoint",
                "status": "failed",
                "module0_called": False,
                "error": repr(exc),
                "failed_artifact_dir": _mark_failed(baseline_cfg.artifacts_dir),
            })
            continue

        retrained_cfg = _configure(dataset, "tapas_paper_aligned_retrained")
        pretrain_dir = retrained_cfg.artifacts_dir / "sequence_pretrain"
        try:
            print(f"[START] {dataset}/paper-aligned pretraining then module1 -> module2; module0 disabled", flush=True)
            manifest = pretrainer.run_pretraining(
                trace_logs=INPUTS["trace"][0],
                cadets_logs=INPUTS["cadets"][0],
                output_dir=pretrain_dir,
                hosts=(dataset,),
                allowed_subject_ids_by_host={dataset: allowed_subject_ids},
                epochs=24,
                batch_size=256,
                lr=0.1,
                lr_decay_factor=0.1,
                lr_decay_rate=500,
                max_optimizer_steps=1500,
                max_seq_len=128,
                val_fraction=0.10,
                max_trace_sequences=None,
                max_cadets_sequences=None,
                seed=173,
            )
            checkpoint = Path(manifest["best_model_path"])
            retrained_cfg = _configure(dataset, "tapas_paper_aligned_retrained", checkpoint)
            retrained_module1 = run_module1(retrained_cfg)
            retrained_module2 = run_module2(
                retrained_cfg,
                retrained_module1["process_embeddings"],
                retrained_module1["task_subgraphs"],
                retrained_module1["process_segmentation_edges"],
            )
            records.append({
                "dataset": dataset,
                "route": "paper_aligned_retrained_checkpoint",
                "status": "completed",
                "module0_called": False,
                "pretraining": manifest,
                "details": _details(retrained_cfg, retrained_module2),
            })
            print(f"[DONE] {dataset}/paper-aligned", flush=True)
        except Exception as exc:
            traceback.print_exc()
            records.append({
                "dataset": dataset,
                "route": "paper_aligned_retrained_checkpoint",
                "status": "failed",
                "module0_called": False,
                "error": repr(exc),
                "failed_artifact_dir": _mark_failed(retrained_cfg.artifacts_dir),
            })
        (OUT_DIR / "matrix_summary.json").write_text(
            json.dumps({"experiment": "cadets_trace_tapas_aligned_sequence_matrix_20260802", "routes": records}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    print(json.dumps({"experiment": "cadets_trace_tapas_aligned_sequence_matrix_20260802", "routes": records}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()

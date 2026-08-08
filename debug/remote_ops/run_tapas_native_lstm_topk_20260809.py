"""Evaluate frozen TAPAS LSTM-GRU process vectors with benign-only Top-K scoring."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config
from apt_fusion.task_detection.module2_online_detection import run_module2


SPECS = {
    "cadets": {
        "config": REPO / "configs/fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
        "logs": Path("/root/autodl-tmp/data/cadets/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/cadets/cadets.txt"),
        "module1": REPO / "artifacts_cadets_provgrp_g0_20260808/module1",
    },
    "trace": {
        "config": REPO / "configs/fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
        "logs": Path("/root/autodl-tmp/data/trace/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/trace/trace.txt"),
        "module1": REPO / "artifacts_trace_provgrp_g0_retry20260808/module1",
    },
    "theia": {
        "config": REPO / "configs/fusion_cloud_theia_train_stats_latefusion_llama31_taskcomponents.yaml",
        "logs": Path("/root/autodl-tmp/data/theia/logs"),
        "ground_truth": Path("/root/autodl-tmp/data/theia/theia_ground_truth.txt"),
        "module1": REPO / "artifacts_theia_provgrp_g0_retry20260808/module1",
    },
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=sorted(SPECS))
    parser.add_argument("--top-k-mode", choices=("fixed", "sqrt"), default="sqrt")
    parser.add_argument("--global-weight", type=float, choices=(0.0, 0.4), default=0.0)
    parser.add_argument("--node-feature-mode", choices=("sequence_only", "all"), default="sequence_only")
    parser.add_argument("--suffix", default="lstm_topk_20260809")
    args = parser.parse_args()

    spec = SPECS[args.dataset]
    module1 = spec["module1"]
    required = [
        module1 / "process_embeddings.csv",
        module1 / "task_subgraphs.json",
        module1 / "process_segmentation_edges.csv",
        module1 / "tapas_native_graphs.pt",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError(f"module1 artifacts are unavailable: {missing}")

    cfg = copy.copy(load_config(spec["config"]))
    cfg.host = args.dataset
    cfg.source_logs = spec["logs"]
    cfg.task_ground_truth_path = spec["ground_truth"]
    cfg.artifacts_dir = REPO / (
        f"artifacts_{args.dataset}_{args.suffix}_{args.node_feature_mode}_{args.top_k_mode}_gw{args.global_weight:g}"
    )
    cfg.task_detector_mode = "normal_only"
    cfg.task_normal_only_detector = "prototype"
    cfg.task_normal_only_node_feature_mode = args.node_feature_mode
    cfg.task_normal_only_node_audit_enabled = True
    cfg.task_normal_only_local_top_k_mode = args.top_k_mode
    cfg.task_normal_only_global_weight = args.global_weight
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"

    outputs = run_module2(
        cfg,
        module1 / "process_embeddings.csv",
        module1 / "task_subgraphs.json",
        module1 / "process_segmentation_edges.csv",
    )
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    node_audit = cfg.artifacts_dir / "module2" / "normal_only_node_audit.json"
    result = {
        "dataset": args.dataset,
        "status": "completed",
        "node_feature_mode": args.node_feature_mode,
        "local_top_k_mode": args.top_k_mode,
        "global_weight": args.global_weight,
        "module1": str(module1),
        "module2_metrics": thresholds.get("backend_summary", {}).get("evaluation_metrics", {}),
        "node_audit_path": str(node_audit),
        "node_audit": json.loads(node_audit.read_text(encoding="utf-8")).get("metrics", {}),
    }
    output_dir = REPO / "debug" / "remote_ops" / "out" / "tapas_native_lstm_topk_20260809"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / (
        f"{args.dataset}_{args.node_feature_mode}_{args.top_k_mode}_gw{args.global_weight:g}.json"
    )
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

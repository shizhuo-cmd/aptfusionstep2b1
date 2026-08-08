from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

import torch


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config
from apt_fusion.task_detection.module1_online_graph import run_module1
from apt_fusion.task_detection.module2_online_detection import run_module2


SPECS = {
    "cadets": (
        REPO / "configs/fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml",
        Path("/root/autodl-tmp/data/cadets/logs"),
        Path("/root/autodl-tmp/data/cadets/cadets.txt"),
    ),
    "trace": (
        REPO / "configs/fusion_cloud_trace_normal_only_multimodal_20260730.yaml",
        Path("/root/autodl-tmp/data/trace/logs"),
        Path("/root/autodl-tmp/data/trace/trace.txt"),
    ),
    "theia": (
        REPO / "configs/fusion_cloud_theia_train_stats_latefusion_llama31_taskcomponents.yaml",
        Path("/root/autodl-tmp/data/theia/logs"),
        Path("/root/autodl-tmp/data/theia/theia_ground_truth.txt"),
    ),
}


def _quantiles(values: list[int]) -> dict[str, int]:
    values = sorted(values)
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "min": values[0],
        "median": values[len(values) // 2],
        "p90": values[min(len(values) - 1, round((len(values) - 1) * 0.9))],
        "max": values[-1],
        "le2": sum(value <= 2 for value in values),
        "gt1000": sum(value > 1000 for value in values),
    }


def _config(dataset: str, route: str, suffix: str):
    base, logs, ground_truth = SPECS[dataset]
    config = copy.copy(load_config(base))
    config.host = dataset
    config.source_logs = logs
    config.task_ground_truth_path = ground_truth
    config.artifacts_dir = REPO / f"artifacts_{dataset}_provgrp_{route}_{suffix}"
    config.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"{dataset}_provgrp_{route}_{suffix}" / "experiments"
    config.ocr_model_name = f"{dataset}_provgrp_{route}_{suffix}.pkl"
    config.task_detector_model_output = config.artifacts_dir / "module2" / "normal_only_model.pkl"
    config.task_detector_mode = "normal_only"
    config.task_tapas_augmentation_enabled = False
    config.path_reason_enabled = False

    # Isolate the paper-faithful ProvGRP partition from prior exploratory splitters.
    config.task_component_provgrp_behavior_partition_enabled = True
    config.task_component_provgrp_min_direct_children = 10
    config.task_component_provgrp_min_cluster_size = 5
    config.task_component_provgrp_min_samples = 2
    config.task_component_provgrp_max_events_per_matrix = 512
    config.task_component_provgrp_batch_overlap_events = 64
    config.task_component_root_temporal_split_enabled = False
    config.task_component_temporal_episode_split_enabled = False
    config.task_component_theia_temporal_split_enabled = False
    config.task_component_synthetic_root_isolation_enabled = False
    config.task_component_synthetic_root_selective_isolation_enabled = False
    config.task_component_branch_object_overlap_split_enabled = False

    config.task_normal_only_train_fraction = 0.70
    config.task_normal_only_validation_fraction = 0.15
    config.task_normal_only_validation_fpr = 0.02
    config.task_normal_only_global_model = "kmeans"
    config.task_normal_only_local_top_k_mode = "sqrt"
    config.task_normal_only_local_top_k_max = 16
    config.task_normal_only_global_weight = 0.40

    if route == "g0":
        config.task_normal_only_detector = "prototype"
    else:
        config.task_normal_only_detector = "gin_autoencoder"
        config.task_normal_only_gnn_direction_mode = route
        config.task_normal_only_gnn_hidden_dim = 64
        config.task_normal_only_gnn_num_layers = 2
        config.task_normal_only_gnn_dropout = 0.1
        config.task_normal_only_gnn_epochs = 20
        config.task_normal_only_gnn_batch_size = 4
        config.task_normal_only_gnn_learning_rate = 0.001
        config.task_normal_only_gnn_weight_decay = 0.0001
    return config


def _details(config, outputs: dict[str, Path], module1_reused: bool) -> dict:
    bundle = torch.load(
        config.module1_dir / "tapas_native_graphs.pt",
        map_location="cpu",
        weights_only=False,
    )
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    metas = bundle["selected_graph_metas"]
    positive = [meta for meta in metas if int(meta.get("label", 0))]
    return {
        "module1_reused": module1_reused,
        "task_count": len(metas),
        "gt_task_count": len(positive),
        "all_size": _quantiles([len(meta.get("node_ids", [])) for meta in metas]),
        "gt_size": _quantiles([len(meta.get("node_ids", [])) for meta in positive]),
        "module2_metrics": thresholds.get("backend_summary", {}).get("evaluation_metrics", {}),
        "provgrp": bundle.get("provgrp_paper_partition_summary", {}),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=sorted(SPECS))
    parser.add_argument("--route", choices=("g0", "undirected", "directed"))
    parser.add_argument("--suffix", default="retry20260808")
    parser.add_argument("--reuse-module1", type=Path)
    args = parser.parse_args()

    config = _config(args.dataset, args.route, args.suffix)
    if args.route == "g0":
        module1_outputs = run_module1(config)
        outputs = run_module2(
            config,
            module1_outputs["process_embeddings"],
            module1_outputs["task_subgraphs"],
            module1_outputs["process_segmentation_edges"],
        )
        reused = False
    else:
        if args.reuse_module1 is None:
            raise ValueError("--reuse-module1 is required for G1 routes")
        source = args.reuse_module1.resolve()
        target = config.artifacts_dir / "module1"
        config.artifacts_dir.mkdir(parents=True, exist_ok=True)
        target.symlink_to(source, target_is_directory=True)
        outputs = run_module2(
            config,
            target / "process_embeddings.csv",
            target / "task_subgraphs.json",
            target / "process_segmentation_edges.csv",
        )
        reused = True

    result = {
        "dataset": args.dataset,
        "route": f"g0_prototype" if args.route == "g0" else f"g1_{args.route}",
        "status": "completed",
        "details": _details(config, outputs, reused),
    }
    output_dir = REPO / "debug" / "remote_ops" / "out" / "provgrp_tc3_isolated_20260808"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{args.dataset}_{args.route}_{args.suffix}.json"
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()

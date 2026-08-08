"""Run CADETS normal-only task detection input-coverage ablations without module0.

Every route reparses CADETS and reruns module1 plus module2.  The only intended
input difference is whether the task-graph node vector receives no statistics,
core-event statistics, or the broader canonical event-family statistics.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_event_coverage_normal_only_matrix_20260731"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


EXPERIMENTS = [
    ("legacy_sequence_only", REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_legacy_20260731.yaml"),
    ("core_event_statistics", REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml"),
    ("extended_event_statistics", REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_extended_20260731.yaml"),
]


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records = []
    for name, config_path in EXPERIMENTS:
        cfg = load_config(config_path)
        print(f"[START] {name}: module1 -> module2; module0 is disabled", flush=True)
        module1_outputs = run_module1(cfg)
        module2_outputs = run_module2(
            cfg,
            module1_outputs["process_embeddings"],
            module1_outputs["task_subgraphs"],
            module1_outputs["process_segmentation_edges"],
        )
        module1_summary = _load_json(cfg.module1_dir / "tapas_native_module1_summary.json")
        thresholds = _load_json(module2_outputs["task_thresholds"])
        backend_summary = thresholds.get("backend_summary", {})
        record = {
            "name": name,
            "config_path": str(config_path),
            "artifacts_dir": str(cfg.artifacts_dir),
            "module0_called": False,
            "module1": {
                "task_count": module1_summary.get("task_count"),
                "process_count": module1_summary.get("process_count"),
                "graphsage_feature_dim": module1_summary.get("graphsage_feature_dim"),
                "sequence_feature_dim": module1_summary.get("sequence_feature_dim"),
                "stat_feature_dim": module1_summary.get("stat_feature_dim"),
                "stat_feature_source": module1_summary.get("stat_feature_source"),
                "event_stats_mode": module1_summary.get("task_tc3_event_stats_mode"),
            },
            "module2": {
                "threshold": backend_summary.get("decision_threshold"),
                "evaluation_metrics": backend_summary.get("evaluation_metrics", {}),
                "normal_only": backend_summary.get("normal_only", {}),
                "evaluation_positive_count": backend_summary.get("evaluation_positive_count"),
                "evaluation_negative_count": backend_summary.get("evaluation_negative_count"),
            },
        }
        records.append(record)
        (OUT_DIR / f"{name}_summary.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(record, ensure_ascii=False), flush=True)
        print(f"[DONE] {name}", flush=True)

    matrix = {
        "experiment": "cadets_normal_only_event_coverage_matrix_20260731",
        "module0_called": False,
        "routes": records,
    }
    (OUT_DIR / "matrix_summary.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(matrix, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()

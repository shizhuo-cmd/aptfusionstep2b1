"""Compare CADETS synthetic-root isolation against the fixed G0 module1 baseline.

The isolation route reruns module1 and module2 without module0.  The baseline
route re-evaluates the immutable paper-aligned module1 bundle with the same
module2 configuration, so task formation is the only experimental variable.
"""

from __future__ import annotations

import copy
import json
import shutil
import sys
import traceback
from pathlib import Path

import torch


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_synthetic_root_isolation_20260803"
BASE_CONFIG = REPO / "configs" / "fusion_cloud_cadets_normal_only_eventstats_core_20260731.yaml"
BASE_ARTIFACT = REPO / "artifacts_cadets_normal_only_tapas_paper_baseline_20260802"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


def _configure(route: str):
    cfg = copy.copy(load_config(BASE_CONFIG))
    cfg.host = "cadets"
    cfg.source_logs = Path("/root/autodl-tmp/data/cadets/logs")
    cfg.task_ground_truth_path = Path("/root/autodl-tmp/data/cadets/cadets.txt")
    cfg.artifacts_dir = REPO / f"artifacts_cadets_synthetic_root_isolation_{route}_20260803"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"cadets_synthetic_root_isolation_{route}_20260803" / "experiments"
    cfg.ocr_model_name = f"normal_only_cadets_synthetic_root_isolation_{route}_20260803.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    cfg.task_tapas_augmentation_enabled = False
    cfg.path_reason_enabled = False
    cfg.task_component_root_temporal_split_enabled = False
    cfg.task_component_synthetic_root_isolation_enabled = route == "synthetic_root_isolation"
    cfg.task_component_synthetic_root_isolation_min_task_nodes = 500
    cfg.task_component_synthetic_root_isolation_min_direct_children = 64
    return cfg


def _prepare_baseline_module1(cfg) -> Path:
    source = BASE_ARTIFACT / "module1"
    if not (source / "tapas_native_graphs.pt").exists():
        raise FileNotFoundError(f"Missing fixed G0 module1 bundle: {source}")
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    target = cfg.artifacts_dir / "module1"
    if not target.exists():
        target.symlink_to(source, target_is_directory=True)
    return target


def _details(cfg, outputs: dict, *, module1_reused: bool) -> dict:
    bundle = torch.load(cfg.module1_dir / "tapas_native_graphs.pt", map_location="cpu", weights_only=False)
    summary = json.loads((cfg.module1_dir / "tapas_native_module1_summary.json").read_text(encoding="utf-8"))
    thresholds = json.loads(Path(outputs["task_thresholds"]).read_text(encoding="utf-8"))
    backend = thresholds.get("backend_summary", {})
    rows = json.loads(Path(outputs["suspicious_tasks"]).read_text(encoding="utf-8"))
    predicted = [row for row in rows if int(row.get("predicted_label", 0)) == 1]
    task_sizes = [int(meta.get("task_size", 0)) for meta in bundle.get("selected_graph_metas", [])]
    return {
        "module1_reused": module1_reused,
        "task_count": len(task_sizes),
        "gt_positive_task_count": sum(int(meta.get("label", 0)) == 1 for meta in bundle.get("selected_graph_metas", [])),
        "gt_positive_task_ids": [str(meta.get("task_id")) for meta in bundle.get("selected_graph_metas", []) if int(meta.get("label", 0)) == 1],
        "task_size_max": max(task_sizes, default=0),
        "task_size_p95": sorted(task_sizes)[int(0.95 * (len(task_sizes) - 1))] if task_sizes else 0,
        "module1_summary": {
            "process_count": summary.get("process_count"),
            "synthetic_root_isolation_summary": summary.get("synthetic_root_isolation_summary", {}),
        },
        "threshold": backend.get("decision_threshold"),
        "metrics": backend.get("evaluation_metrics", {}),
        "normal_only": backend.get("normal_only", {}),
        "true_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 1],
        "false_positive_task_ids": [row["task_id"] for row in predicted if int(row.get("task_label", 0)) == 0],
        "missed_positive_task_ids": [
            row["task_id"] for row in rows if int(row.get("task_label", 0)) == 1 and int(row.get("predicted_label", 0)) == 0
        ],
    }


def _mark_failed(path: Path) -> str | None:
    if not path.exists() or path.is_symlink():
        return None
    failed = path.with_name(f"{path.name}_failed_runtime_error")
    if failed.exists():
        shutil.rmtree(failed)
    path.rename(failed)
    return str(failed)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records = []
    for route in ("baseline_g0", "synthetic_root_isolation"):
        cfg = _configure(route)
        try:
            if route == "baseline_g0":
                module1_dir = _prepare_baseline_module1(cfg)
                module1_reused = True
                print("[START] baseline_g0: reuse module1, run module2; module0 disabled", flush=True)
            else:
                print("[START] synthetic_root_isolation: module1 -> module2; module0 disabled", flush=True)
                run_module1(cfg)
                module1_dir = cfg.module1_dir
                module1_reused = False
            outputs = run_module2(
                cfg,
                module1_dir / "process_embeddings.csv",
                module1_dir / "task_subgraphs.json",
                module1_dir / "process_segmentation_edges.csv",
            )
            record = {
                "route": route,
                "status": "completed",
                "module0_called": False,
                "details": _details(cfg, outputs, module1_reused=module1_reused),
            }
            print(f"[DONE] {route}", flush=True)
        except Exception as exc:
            traceback.print_exc()
            record = {
                "route": route,
                "status": "failed",
                "module0_called": False,
                "error": repr(exc),
                "failed_artifact_dir": _mark_failed(cfg.artifacts_dir),
            }
            print(f"[FAILED] {route}: {exc!r}", flush=True)
        records.append(record)
        (OUT_DIR / "matrix_summary.json").write_text(
            json.dumps({"experiment": "cadets_synthetic_root_isolation_20260803", "routes": records}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()

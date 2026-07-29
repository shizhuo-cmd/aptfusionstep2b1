from __future__ import annotations

import copy
import json
import shutil
import sys
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

CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_cadets_train_stats_latefusion_llama31_module12_baseline_tapasreleasecut_20260710.yaml"
)
OUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out"
SUMMARY_PATH = OUT_DIR / "cadets_tapasreleasecut_module12_20260710_summary.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_module1_summary(cfg: FusionConfig) -> dict[str, Any]:
    for name in ("tapas_native_module1_summary.json", "module1_summary.json", "summary.json"):
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


def _snapshot_module2_fit_predict(cfg: FusionConfig) -> Path:
    snapshot_dir = cfg.artifacts_dir / "module2_fit_predict_snapshot"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "task_scores.csv",
        "task_subgraph_summary.json",
        "suspicious_tasks.json",
        "task_meta_rich.json",
        "task_attribution.json",
        "process_scores.csv",
        "tapas_native_model.pt",
        "tapas_native_model.graph_stats.joblib",
    ):
        src = cfg.module2_dir / name
        if src.exists():
            shutil.copy2(src, snapshot_dir / name)
    return snapshot_dir


def main() -> int:
    cfg = load_config(CONFIG_PATH)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
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

    summary = {
        "config_path": str(CONFIG_PATH),
        "artifact_root": str(cfg.artifacts_dir),
        "module1_summary": _load_module1_summary(cfg_load),
        "module2_fit_predict_summary": fit_summary,
        "module2_loadpredict_summary": _load_module2_summary(cfg_load.module2_dir),
        "selected_positive_task_ids": _selected_positive_task_ids(cfg_load.module2_dir / "suspicious_tasks.json"),
        "task_tapas_release_legacy_cut_logic": bool(cfg.task_tapas_release_legacy_cut_logic),
    }
    SUMMARY_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

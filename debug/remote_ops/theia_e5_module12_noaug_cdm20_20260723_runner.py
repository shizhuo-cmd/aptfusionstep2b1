"""Run THEIA E5 module1 and module2 without invoking module0."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = REPO_ROOT / "configs" / "fusion_cloud_theia_e5_module12_noaug_cdm20_20260723.yaml"
OUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_e5_module12_noaug_cdm20_20260723"


def main() -> int:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from apt_fusion.common import ensure_dir, save_json
    from apt_fusion.config import load_config
    from apt_fusion.task_detection.module1_online_graph import run_module1
    from apt_fusion.task_detection.module2_online_detection import run_module2

    cfg = load_config(CONFIG_PATH)
    ensure_dir(OUT_DIR)
    save_json(
        OUT_DIR / "run_provenance.json",
        {
            "config_path": str(CONFIG_PATH),
            "source_logs": str(cfg.source_logs),
            "ground_truth_path": str(cfg.task_ground_truth_path),
            "stages": ["module1", "module2"],
            "module0_run": False,
            "augmentation_enabled": bool(cfg.task_tapas_augmentation_enabled),
            "graph_stat_late_fusion_enabled": bool(cfg.task_graph_stat_late_fusion_enabled),
        },
    )
    module1 = run_module1(cfg)
    module2 = run_module2(
        cfg,
        embeddings_path=module1["process_embeddings"],
        task_path=module1["task_subgraphs"],
        segmentation_edges_path=module1["process_segmentation_edges"],
    )
    payload = {
        "status": "ok",
        "module1": {key: str(value) for key, value in module1.items()},
        "module2": {key: str(value) for key, value in module2.items()},
    }
    save_json(OUT_DIR / "run_summary.json", payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

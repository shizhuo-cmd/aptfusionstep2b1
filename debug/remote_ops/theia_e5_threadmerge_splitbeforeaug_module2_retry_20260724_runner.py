"""Retry only THEIA E5's post-split augmentation module2 after module1 succeeds."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = REPO_ROOT / "configs" / "fusion_cloud_theia_e5_module12_threadmerge_splitbeforeaug_20260724.yaml"
OUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_e5_threadmerge_module12_20260724" / "threadmerge_splitbeforeaug_retry"


def main() -> int:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from apt_fusion.common import ensure_dir, save_json
    from apt_fusion.config import load_config
    from apt_fusion.task_detection.module2_online_detection import run_module2

    cfg = load_config(CONFIG_PATH)
    module1_dir = Path(cfg.artifacts_dir) / "module1"
    ensure_dir(OUT_DIR)
    save_json(
        OUT_DIR / "provenance.json",
        {
            "config_path": str(CONFIG_PATH),
            "reused_module1_dir": str(module1_dir),
            "stages": ["module2"],
            "module0_run": False,
            "module1_rerun": False,
            "augmentation_enabled": bool(cfg.task_tapas_augmentation_enabled),
            "augmentation_before_split": bool(cfg.task_tapas_augmentation_before_split),
            "e5_template_dataset": "theia",
        },
    )
    module2 = run_module2(
        cfg,
        embeddings_path=module1_dir / "process_embeddings.csv",
        task_path=module1_dir / "task_subgraphs.json",
        segmentation_edges_path=module1_dir / "process_segmentation_edges.csv",
    )
    payload = {"status": "ok", "module2": {key: str(value) for key, value in module2.items()}}
    save_json(OUT_DIR / "run_summary.json", payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

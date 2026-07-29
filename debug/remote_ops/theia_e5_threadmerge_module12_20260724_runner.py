"""Run THEIA E5 thread-merge module1/module2 baselines without module0."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
RUNS = (
    "threadmerge_noaug",
    "threadmerge_splitbeforeaug",
)


def main() -> int:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from apt_fusion.common import ensure_dir, save_json
    from apt_fusion.config import load_config
    from apt_fusion.task_detection.module1_online_graph import run_module1
    from apt_fusion.task_detection.module2_online_detection import run_module2

    output_root = REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_e5_threadmerge_module12_20260724"
    ensure_dir(output_root)
    results = {}
    for name in RUNS:
        config_path = REPO_ROOT / "configs" / f"fusion_cloud_theia_e5_module12_{name}_20260724.yaml"
        cfg = load_config(config_path)
        run_out = output_root / name
        ensure_dir(run_out)
        save_json(
            run_out / "provenance.json",
            {
                "config_path": str(config_path),
                "source_logs": str(cfg.source_logs),
                "ground_truth_path": str(cfg.task_ground_truth_path),
                "stages": ["module1", "module2"],
                "module0_run": False,
                "thread_merge_rule": "parent_subject_known_and_same_tgid",
                "augmentation_enabled": bool(cfg.task_tapas_augmentation_enabled),
                "augmentation_divisor": int(cfg.task_tapas_augmentation_divisor),
                "augmentation_before_split": bool(cfg.task_tapas_augmentation_before_split),
            },
        )
        module1 = run_module1(cfg)
        module2 = run_module2(
            cfg,
            embeddings_path=module1["process_embeddings"],
            task_path=module1["task_subgraphs"],
            segmentation_edges_path=module1["process_segmentation_edges"],
        )
        results[name] = {
            "status": "ok",
            "module1": {key: str(value) for key, value in module1.items()},
            "module2": {key: str(value) for key, value in module2.items()},
        }
        save_json(run_out / "run_summary.json", results[name])

    save_json(output_root / "matrix_summary.json", results)
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Train an E5 next-event encoder, then rerun E5 module1/module2 without module0."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
PYTHON = Path("/root/miniconda3/envs/fusion/bin/python")


def main() -> int:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from apt_fusion.common import ensure_dir, save_json
    from apt_fusion.config import load_config
    from apt_fusion.task_detection.module1_online_graph import run_module1
    from apt_fusion.task_detection.module2_online_detection import run_module2

    output_root = REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_e5_retrain_then_module12_20260725"
    training_dir = REPO_ROOT / "runtime" / "theia_e5_next_event_20260725"
    ensure_dir(output_root)
    command = [
        str(PYTHON), str(REPO_ROOT / "scripts" / "train_theia_e5_stackedlstm_next_event_20260725.py"),
        "--logs", "/root/autodl-tmp/data/theia_e5/logs",
        "--output-dir", str(training_dir),
        "--epochs", "5",
        "--batch-size", "256",
        "--max-sequences", "250000",
        "--max-seq-len", "128",
        "--seed", "173",
    ]
    save_json(output_root / "provenance.json", {
        "module0_run": False,
        "training_objective": "same_process_event_t_predicts_event_t_plus_1",
        "training_command": command,
        "module12_config": str(REPO_ROOT / "configs" / "fusion_cloud_theia_e5_module12_threadmerge_objectlinked_e5pretrain_noaug_20260725.yaml"),
    })
    subprocess.run(command, check=True, cwd=REPO_ROOT)
    cfg = load_config(REPO_ROOT / "configs" / "fusion_cloud_theia_e5_module12_threadmerge_objectlinked_e5pretrain_noaug_20260725.yaml")
    module1 = run_module1(cfg)
    module2 = run_module2(cfg, embeddings_path=module1["process_embeddings"], task_path=module1["task_subgraphs"], segmentation_edges_path=module1["process_segmentation_edges"])
    result = {"status": "ok", "module1": {key: str(value) for key, value in module1.items()}, "module2": {key: str(value) for key, value in module2.items()}}
    save_json(output_root / "run_summary.json", result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

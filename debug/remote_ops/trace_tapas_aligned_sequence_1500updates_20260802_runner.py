"""Finish the TRACE TAPAS-aligned sequence schedule through 1,500 updates.

The first paper-aligned TRACE run reached only 552 updates in 24 epochs.  This
controlled follow-up keeps all data, detector, and paper hyperparameters fixed
while allowing enough epochs to exercise the same three decay milestones used
for CADETS.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import torch

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "trace_tapas_aligned_sequence_1500updates_20260802"
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    matrix = _load_module(
        "tapas_aligned_matrix_20260802",
        REPO / "debug" / "remote_ops" / "cadets_trace_tapas_aligned_sequence_matrix_20260802_runner.py",
    )
    pretrainer = matrix._load_pretrainer()
    baseline_cfg = matrix._configure("trace", "tapas_paper_baseline")
    allowed_subject_ids = matrix._normal_train_subject_ids(baseline_cfg)
    route = "tapas_paper_aligned_retrained_1500updates"
    cfg = matrix._configure("trace", route)
    pretrain_dir = cfg.artifacts_dir / "sequence_pretrain"
    manifest = pretrainer.run_pretraining(
        trace_logs=matrix.INPUTS["trace"][0],
        cadets_logs=matrix.INPUTS["cadets"][0],
        output_dir=pretrain_dir,
        hosts=("trace",),
        allowed_subject_ids_by_host={"trace": allowed_subject_ids},
        epochs=70,
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
    cfg = matrix._configure("trace", route, checkpoint)
    module1 = run_module1(cfg)
    module2 = run_module2(
        cfg,
        module1["process_embeddings"],
        module1["task_subgraphs"],
        module1["process_segmentation_edges"],
    )
    result = {
        "experiment": "trace_tapas_aligned_sequence_1500updates_20260802",
        "status": "completed",
        "module0_called": False,
        "pretraining": manifest,
        "details": matrix._details(cfg, module2),
    }
    (OUT_DIR / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()

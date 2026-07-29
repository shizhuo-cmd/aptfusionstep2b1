from __future__ import annotations

import json
import sys
from pathlib import Path

from apt_fusion.config import load_config
from apt_fusion.task_detection.module2_online_detection import run_module2


REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
BASE_ARTIFACTS = REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_module12_stataug_20260706"


def _clean_dir(path: Path) -> None:
    if path.exists():
        import shutil

        shutil.rmtree(path)


def _base_module1_dir() -> Path:
    module1_dir = BASE_ARTIFACTS / "module1"
    if not module1_dir.exists():
        raise FileNotFoundError(f"missing upstream module1 dir: {module1_dir}")
    return module1_dir


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: trace_module2_reuse_module1_20260706_runner.py <config_path>")
    config_path = Path(sys.argv[1])
    cfg = load_config(config_path)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    base_module1_dir = _base_module1_dir()
    _clean_dir(cfg.module2_dir)

    out2 = run_module2(
        cfg=cfg,
        embeddings_path=base_module1_dir / "process_embeddings.csv",
        task_path=base_module1_dir / "task_subgraphs.json",
        segmentation_edges_path=base_module1_dir / "process_segmentation_edges.csv",
    )
    provenance = {
        "code_baseline": "local_working_tree_snapshot_sync_20260706",
        "repo_root": str(REPO_ROOT),
        "config_path": str(config_path),
        "base_artifacts": str(BASE_ARTIFACTS),
        "base_module1_dir": str(base_module1_dir),
        "reused_dirs": [],
        "rerun_modules": ["module2"],
        "task_tapas_augmentation_before_split": cfg.task_tapas_augmentation_before_split,
        "task_fit_split_strategy": cfg.task_fit_split_strategy,
        "task_fit_kfold_splits": cfg.task_fit_kfold_splits,
        "task_fit_kfold_index": cfg.task_fit_kfold_index,
        "stat_augmentation_mode": "replace_process_embedding_and_process_stats_with_random_benign_templates",
        "outputs": {key: str(value) for key, value in out2.items()},
    }
    (cfg.artifacts_dir / "provenance_summary.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(provenance, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

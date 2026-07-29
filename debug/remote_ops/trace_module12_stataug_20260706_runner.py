from __future__ import annotations

import json
import tarfile
from pathlib import Path

from apt_fusion.config import load_config
from apt_fusion.pipeline import run_pipeline


REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = REPO_ROOT / "configs" / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_module12_stataug_20260706.yaml"
TRACE_DIR = Path("/root/autodl-tmp/data/trace_train")
TRACE_LOGS_DIR = TRACE_DIR / "logs"
TRACE_ARCHIVE_PATH = TRACE_DIR / "logs_archive_20260609.tar.gz"


def _ensure_trace_logs_ready() -> dict[str, object]:
    existed = TRACE_LOGS_DIR.exists() and any(TRACE_LOGS_DIR.iterdir())
    extracted = False
    if not existed:
        if not TRACE_ARCHIVE_PATH.exists():
            raise FileNotFoundError(f"trace archive not found: {TRACE_ARCHIVE_PATH}")
        TRACE_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with tarfile.open(TRACE_ARCHIVE_PATH, "r:gz") as tar:
            tar.extractall(path=TRACE_DIR)
        extracted = True
    ready = TRACE_LOGS_DIR.exists() and any(TRACE_LOGS_DIR.iterdir())
    if not ready:
        raise RuntimeError(f"trace logs dir is empty: {TRACE_LOGS_DIR}")
    return {
        "trace_logs_dir": str(TRACE_LOGS_DIR),
        "trace_archive_path": str(TRACE_ARCHIVE_PATH),
        "trace_logs_preexisting": existed,
        "trace_logs_extracted_this_run": extracted,
        "trace_logs_ready": ready,
    }


def main() -> int:
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    log_state = _ensure_trace_logs_ready()
    outputs = run_pipeline(cfg, "module2")

    provenance = {
        "code_baseline": "local_working_tree_snapshot_sync_20260706",
        "repo_root": str(REPO_ROOT),
        "config_path": str(CONFIG_PATH),
        "stage": "module2",
        "stat_augmentation_mode": "replace_process_embedding_and_process_stats_with_random_benign_templates",
        "task_tapas_augmentation_enabled": cfg.task_tapas_augmentation_enabled,
        "task_tapas_augmentation_divisor": cfg.task_tapas_augmentation_divisor,
        "task_tapas_trace_augmentation_bonus": cfg.task_tapas_trace_augmentation_bonus,
        "task_tapas_augmentation_before_split": cfg.task_tapas_augmentation_before_split,
        "task_graph_stat_late_fusion_enabled": cfg.task_graph_stat_late_fusion_enabled,
        "task_graph_stat_fusion_weight": cfg.task_graph_stat_fusion_weight,
        **log_state,
        "outputs": outputs,
    }
    provenance_path = cfg.artifacts_dir / "provenance_summary.json"
    provenance_path.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(provenance, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

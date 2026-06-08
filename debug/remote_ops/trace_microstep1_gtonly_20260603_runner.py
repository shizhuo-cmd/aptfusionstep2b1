from __future__ import annotations

import json
import shutil
from pathlib import Path

from apt_fusion.config import load_config
from apt_fusion.path_reason.module3_evidence_recover import run_module3_evidence
from apt_fusion.path_reason.module4_semantic_compact import run_module4_compact
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason
from apt_fusion.task_detection.module2_online_detection import run_module2


CONFIG_PATH = Path("configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep1_gtonly_20260603.yaml")
BASE_ARTIFACTS = Path("/root/autodl-tmp/APT-Fusion/artifacts_trace_train_stats_latefusion_bonus1")


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _ensure_module1(cfg_module1_dir: Path) -> None:
    if cfg_module1_dir.exists():
        return
    source = BASE_ARTIFACTS / "module1"
    if not source.exists():
        raise FileNotFoundError(f"base module1 dir not found: {source}")
    shutil.copytree(source, cfg_module1_dir)


def main() -> None:
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    _ensure_module1(cfg.module1_dir)
    for stale_dir in [
        cfg.module2_dir,
        cfg.module3_evidence_dir,
        cfg.module4_compact_dir,
        cfg.module5_paths_dir,
        cfg.module6_reason_dir,
    ]:
        _clean_dir(stale_dir)

    module1_dir = cfg.module1_dir
    outputs: dict[str, str] = {}

    out2 = run_module2(
        cfg=cfg,
        embeddings_path=module1_dir / "process_embeddings.csv",
        task_path=module1_dir / "task_subgraphs.json",
        segmentation_edges_path=module1_dir / "process_segmentation_edges.csv",
    )
    outputs.update({f"module2.{key}": str(value) for key, value in out2.items()})

    out3 = run_module3_evidence(
        cfg,
        suspicious_tasks_path=out2["suspicious_tasks"],
        task_meta_rich_path=cfg.module2_dir / "task_meta_rich.json",
        task_attribution_path=cfg.module2_dir / "task_attribution.json",
    )
    outputs.update({f"module3_evidence.{key}": str(value) for key, value in out3.items()})

    out4 = run_module4_compact(cfg)
    outputs.update({f"module4_compact.{key}": str(value) for key, value in out4.items()})

    out5 = run_module5_paths(cfg)
    outputs.update({f"module5_paths.{key}": str(value) for key, value in out5.items()})

    out6 = run_module6_reason(cfg)
    outputs.update({f"module6_reason.{key}": str(value) for key, value in out6.items()})

    print(json.dumps(outputs, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

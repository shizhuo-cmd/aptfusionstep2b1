from __future__ import annotations

import json
import shutil
from pathlib import Path

from apt_fusion.config import load_config
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason


CONFIG_PATH = Path(
    "configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_gtonly_20260603.yaml"
)
SOURCE_ARTIFACTS = Path(
    "/root/autodl-tmp/APT-Fusion/artifacts_trace_train_stats_latefusion_bonus1_microstep1_gtonly_20260603"
)
MODULE_DIR_NAMES = [
    "module1",
    "module2",
    "module3_evidence",
    "module4_compact",
]


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_required_modules(target_artifacts_dir: Path) -> None:
    for name in MODULE_DIR_NAMES:
        source = SOURCE_ARTIFACTS / name
        if not source.exists():
            raise FileNotFoundError(f"required source module dir not found: {source}")
        target = target_artifacts_dir / name
        _clean_dir(target)
        shutil.copytree(source, target)


def main() -> None:
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    _copy_required_modules(cfg.artifacts_dir)
    _clean_dir(cfg.module5_paths_dir)
    _clean_dir(cfg.module6_reason_dir)
    out5 = run_module5_paths(cfg)
    out6 = run_module6_reason(cfg)
    outputs = {
        **{f"module5_paths.{key}": str(value) for key, value in out5.items()},
        **{f"module6_reason.{key}": str(value) for key, value in out6.items()},
    }
    print(json.dumps(outputs, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import json
import shutil
from pathlib import Path

from apt_fusion.config import load_config
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason


CONFIG_PATH = Path(
    "configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2a_gtonly_20260603.yaml"
)
SOURCE_ARTIFACTS = Path(
    "/root/autodl-tmp/APT-Fusion/artifacts_trace_train_stats_latefusion_bonus1_microstep1_gtonly_20260603"
)
MODULE_DIR_NAMES = [
    "module1",
    "module2",
    "module3_evidence",
    "module4_compact",
    "module5_paths",
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
    _clean_dir(cfg.module6_reason_dir)
    out6 = run_module6_reason(cfg)
    print(json.dumps({f"module6_reason.{key}": str(value) for key, value in out6.items()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

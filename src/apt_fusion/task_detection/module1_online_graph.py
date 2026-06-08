from __future__ import annotations

from pathlib import Path
from typing import Dict

from ..config import FusionConfig
from .tapas_native_backend import run_tapas_module1


def run_module1(cfg: FusionConfig) -> Dict[str, Path]:
    return run_tapas_module1(cfg, cfg.module1_dir)


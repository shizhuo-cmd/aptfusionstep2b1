"""Run THEIA G0/G1 after replacing the legacy sibling-alias merge rule.

This wrapper keeps the prior G0/G1 settings unchanged.  It only redirects the
artifacts so module1 is rebuilt with the parent-known, same-tgid thread rule.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
sys.path.insert(0, str(REPO / "debug" / "remote_ops"))

import theia_g0_g1_normal_only_20260804_runner as baseline


baseline.OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "theia_threadmerge_g0_g1_normal_only_20260805"
baseline.G0_ARTIFACTS = REPO / "artifacts_theia_normal_only_g0_tapas_paper_baseline_threadmerge_paper_rule_20260805"
_baseline_configure = baseline._configure


def _configure(route: str):
    cfg = _baseline_configure(route)
    cfg.artifacts_dir = REPO / f"artifacts_theia_normal_only_{route}_threadmerge_paper_rule_20260805"
    cfg.ocr_runtime_root = REPO / "runtime" / "darpa_tc3" / f"theia_{route}_threadmerge_paper_rule_20260805" / "experiments"
    cfg.ocr_model_name = f"normal_only_theia_{route}_threadmerge_paper_rule_20260805.pkl"
    cfg.task_detector_model_output = cfg.artifacts_dir / "module2" / "normal_only_model.pkl"
    return cfg


baseline._configure = _configure


if __name__ == "__main__":
    baseline.main()

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.config import load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.module3_evidence_recover import run_module3_evidence
from apt_fusion.path_reason.module4_semantic_compact import run_module4_compact
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason
from apt_fusion.task_detection.module1_online_graph import run_module1

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_20260624.yaml"
)
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"
TARGET_ROOT_TEMPLATE = (
    "/root/autodl-tmp/APT-Fusionstep2b1/"
    "artifacts_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_"
    "fanout_gt2_e3gt_offset{offset}_20260624"
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run THEIA module1-GT-direct path-reason baseline.")
    parser.add_argument("--gt-time-offset-minutes", type=int, default=0)
    return parser.parse_args()


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _git_text(*args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip()


def _working_tree_fingerprint() -> dict[str, Any]:
    status_lines = [line for line in _git_text("status", "--short").splitlines() if line.strip()]
    return {
        "code_baseline": "local_working_tree_snapshot",
        "head_commit": _git_text("rev-parse", "HEAD"),
        "git_status_short": status_lines,
        "git_status_count": len(status_lines),
    }


def _evaluate(cfg, *, gt_time_offset_minutes: int) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, _ = load_gt_reference(GT_JSON_PATH, host_filter=cfg.host.upper())
    if gt_time_offset_minutes:
        apply_gt_time_offset(strict_windows, minutes=gt_time_offset_minutes)
    output_dir = cfg.artifacts_dir / EVAL_DIR_NAME
    outputs = run_evaluation(
        artifacts_dir=cfg.artifacts_dir,
        strict_windows=strict_windows,
        technique_defs=technique_defs,
        output_dir=output_dir,
        host=cfg.host.upper(),
        match_top_n=5,
        pad_minutes=5,
        near_miss_minutes=5,
    )
    metrics = json.loads(Path(outputs["metrics_summary"]).read_text(encoding="utf-8"))
    return metrics, outputs


def main() -> None:
    args = _parse_args()
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir = Path(TARGET_ROOT_TEMPLATE.format(offset=int(args.gt_time_offset_minutes)))

    _clean_dir(cfg.artifacts_dir)

    module1_outputs = run_module1(cfg)
    module3_outputs = run_module3_evidence(cfg)
    module4_outputs = run_module4_compact(cfg)
    module5_outputs = run_module5_paths(cfg)
    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg, gt_time_offset_minutes=int(args.gt_time_offset_minutes))

    provenance = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "config_template_path": str(CONFIG_PATH),
        "artifacts_dir": str(cfg.artifacts_dir),
        "gt_json_path": str(GT_JSON_PATH),
        "gt_time_offset_minutes_applied": int(args.gt_time_offset_minutes),
        "rerun_modules": [
            "module1",
            "module3_evidence",
            "module4_compact",
            "module5_paths",
            "module6_reason",
            "path_reason_eval",
        ],
        "module1_outputs": {key: str(value) for key, value in module1_outputs.items()},
        "module3_outputs": {key: str(value) for key, value in module3_outputs.items()},
        "module4_outputs": {key: str(value) for key, value in module4_outputs.items()},
        "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "metrics": metrics,
    }
    (cfg.artifacts_dir / "provenance_summary.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (cfg.artifacts_dir / "working_tree_fingerprint.json").write_text(
        json.dumps(_working_tree_fingerprint(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(provenance, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

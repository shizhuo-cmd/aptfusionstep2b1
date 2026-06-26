from __future__ import annotations

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
from apt_fusion.path_reason.module3_evidence_recover import run_module3_evidence
from apt_fusion.task_detection.module1_online_graph import run_module1

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_20260624.yaml"
)
TARGET_ROOT = (
    REPO_ROOT
    / (
        "artifacts_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_overlap_fanout_gt2_"
        "e3gt_offset240_step4_temporalsplit_20260625"
    )
)
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
GT_NODE_PATH = Path("/root/autodl-tmp/data/theia/theia_ground_truth.txt")
GT_TIME_OFFSET_MINUTES = 240
OVERLAP_SCRIPT = REPO_ROOT / "debug" / "remote_ops" / "analyze_theia_gt_task_window_overlap_20260625.py"
OVERLAP_OUTPUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_gt_task_overlap_step4_temporalsplit_20260625"


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


def _run_overlap_analysis() -> None:
    _clean_dir(OVERLAP_OUTPUT_DIR)
    OVERLAP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            str(OVERLAP_SCRIPT),
            "--artifacts-root",
            str(TARGET_ROOT),
            "--gt-json",
            str(GT_JSON_PATH),
            "--gt-node-path",
            str(GT_NODE_PATH),
            "--host",
            "THEIA",
            "--gt-time-offset-minutes",
            str(GT_TIME_OFFSET_MINUTES),
            "--output-dir",
            str(OVERLAP_OUTPUT_DIR),
        ],
        check=True,
    )


def main() -> None:
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir = TARGET_ROOT
    cfg.task_component_theia_temporal_split_enabled = True
    cfg.task_component_theia_max_span_minutes = 45
    cfg.task_component_theia_branch_gap_minutes = 10
    _clean_dir(cfg.artifacts_dir)

    module1_outputs = run_module1(cfg)
    module3_outputs = run_module3_evidence(cfg)
    _run_overlap_analysis()

    provenance = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "config_template_path": str(CONFIG_PATH),
        "artifacts_dir": str(cfg.artifacts_dir),
        "gt_json_path": str(GT_JSON_PATH),
        "gt_node_path": str(GT_NODE_PATH),
        "gt_time_offset_minutes_applied": GT_TIME_OFFSET_MINUTES,
        "task_component_theia_temporal_split_enabled": True,
        "task_component_theia_max_span_minutes": int(cfg.task_component_theia_max_span_minutes),
        "task_component_theia_branch_gap_minutes": int(cfg.task_component_theia_branch_gap_minutes),
        "rerun_modules": ["module1", "module3_evidence", "theia_gt_task_window_overlap"],
        "overlap_script": str(OVERLAP_SCRIPT),
        "overlap_output_dir": str(OVERLAP_OUTPUT_DIR),
        "module1_outputs": {key: str(value) for key, value in module1_outputs.items()},
        "module3_outputs": {key: str(value) for key, value in module3_outputs.items()},
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

from __future__ import annotations

import json
import os
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
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_windowgate_20260624.yaml"
)
REUSED_SOURCE_ROOT = (
    REPO_ROOT
    / "artifacts_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_windowgate_step4m_windowcontinuation_offset240_20260626"
)
TARGET_ROOT = (
    REPO_ROOT
    / "artifacts_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_windowgate_step5i_cadets_followupwindow300_payloadelevate_offset240_20260628"
)
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
GT_TIME_OFFSET_MINUTES = 240
REUSED_DIR_NAMES = ["module1", "module3_evidence", "module4_compact"]
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"
ANALYSIS_SCRIPT = REPO_ROOT / "debug" / "remote_ops" / "analyze_path_reason_behavior_capture_20260624.py"
ANALYSIS_OUTPUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_behavior_capture_step5i_cadets_followupwindow300_payloadelevate_20260628"


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _symlink_dir(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists() or target.is_symlink():
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
    os.symlink(source, target, target_is_directory=True)


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


def _inspect_module3_task_index(module3_dir: Path) -> dict[str, Any]:
    task_index_path = module3_dir / "task_index.json"
    rows = json.loads(task_index_path.read_text(encoding="utf-8"))
    return {
        "task_index_path": str(task_index_path),
        "task_count": len(rows),
        "rewrite_mode": "reused_source_symlink",
        "rewritten_field_count": 0,
    }


def _prepare_reused_artifacts(target_root: Path) -> dict[str, Any]:
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    for name in REUSED_DIR_NAMES:
        _symlink_dir(REUSED_SOURCE_ROOT / name, target_root / name)
    task_index_rewrite = _inspect_module3_task_index(REUSED_SOURCE_ROOT / "module3_evidence")
    return {
        "reused_source_root": str(REUSED_SOURCE_ROOT),
        "reused_dir_names": list(REUSED_DIR_NAMES),
        "task_index_rewrite": task_index_rewrite,
    }


def _evaluate(cfg) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, _ = load_gt_reference(GT_JSON_PATH, host_filter=cfg.host.upper())
    apply_gt_time_offset(strict_windows, minutes=GT_TIME_OFFSET_MINUTES)
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


def _run_behavior_capture_analysis() -> None:
    _clean_dir(ANALYSIS_OUTPUT_DIR)
    ANALYSIS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            str(ANALYSIS_SCRIPT),
            "--artifacts-dir",
            str(TARGET_ROOT),
            "--gt-json-path",
            str(GT_JSON_PATH),
            "--host",
            "THEIA",
            "--gt-time-offset-minutes",
            str(GT_TIME_OFFSET_MINUTES),
            "--output-dir",
            str(ANALYSIS_OUTPUT_DIR),
        ],
        check=True,
    )


def main() -> None:
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir = TARGET_ROOT
    reuse_provenance = _prepare_reused_artifacts(cfg.artifacts_dir)

    _clean_dir(cfg.module5_paths_dir)
    _clean_dir(cfg.module6_reason_dir)
    _clean_dir(cfg.artifacts_dir / EVAL_DIR_NAME)

    module5_outputs = run_module5_paths(cfg)
    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)
    _run_behavior_capture_analysis()

    provenance = {
        "experiment_step": "step5i_cadets_followupwindow300_payloadelevate_20260628",
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "config_template_path": str(CONFIG_PATH),
        "artifacts_dir": str(cfg.artifacts_dir),
        "gt_json_path": str(GT_JSON_PATH),
        "gt_time_offset_minutes_applied": GT_TIME_OFFSET_MINUTES,
        **reuse_provenance,
        "rerun_modules": ["module5_paths", "module6_reason", "path_reason_eval"],
        "analysis_script": str(ANALYSIS_SCRIPT),
        "analysis_output_dir": str(ANALYSIS_OUTPUT_DIR),
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

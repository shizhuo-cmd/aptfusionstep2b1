from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from analyze_cadets_eventid_fix_20260615 import run_cadets_eventid_fix_diagnostics
from apt_fusion.config import load_config
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason
from cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_common_20260615 import (
    CADETS_LOGS_DIR,
    GT_JSON_PATH,
    LOCAL_REPO_ROOT,
    REMOTE_REPO_ROOT,
    _evaluate,
    _load_metrics,
    _resolve_metrics_summary,
    _resolve_repo_path,
    _write_json,
    ensure_cadets_logs_ready,
)

CONFIG_PATH = Path(
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_step2_claimtight_20260617.yaml"
)
GT_NODE_PATH = Path("/root/autodl-tmp/data/cadets/cadets.txt")
BASELINE_ROOT = (
    REMOTE_REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_ruletight1_20260616"
)
REUSED_DIR_NAMES = ["module1", "module2", "module3_evidence", "module4_compact"]
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"
TARGET_WINDOW_IDS = {
    "CADETS_20180412_1400_1438_03",
    "CADETS_20180413_0904_0915_04",
}


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _prepare_reused_artifacts(target_root: Path) -> dict[str, Any]:
    missing = [str(BASELINE_ROOT / name) for name in REUSED_DIR_NAMES if not (BASELINE_ROOT / name).exists()]
    if missing:
        raise FileNotFoundError("Missing required reused artifact directories: " + ", ".join(missing))
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    for name in REUSED_DIR_NAMES:
        _copy_tree(BASELINE_ROOT / name, target_root / name)
    return {
        "reused_source_root": str(BASELINE_ROOT),
        "reused_dir_names": list(REUSED_DIR_NAMES),
    }


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_tactic_diff_rows(root: Path) -> list[dict[str, Any]]:
    path = root / "cadets_eventid_fix_diagnostics" / "tactic_diff_by_window.json"
    return list(_load_json(path))


def _metric_drop_failures(current: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key in ("strict_tactic_recall_macro", "strict_tactic_precision_macro"):
        current_value = float(current.get(key, 0.0) or 0.0)
        baseline_value = float(baseline.get(key, 0.0) or 0.0)
        if current_value < baseline_value - 0.05:
            failures.append(f"{key} dropped from {baseline_value:.4f} to {current_value:.4f}")
    current_off = float(current.get("off_window_high_risk_rate", 0.0) or 0.0)
    baseline_off = float(baseline.get("off_window_high_risk_rate", 0.0) or 0.0)
    if current_off > baseline_off + 0.05:
        failures.append(f"off_window_high_risk_rate increased from {baseline_off:.4f} to {current_off:.4f}")
    return failures


def _extra_tactic_failures(current_rows: list[dict[str, Any]], baseline_rows: list[dict[str, Any]]) -> list[str]:
    current_map = {str(row.get("window_id", "")).strip(): row for row in current_rows}
    baseline_map = {str(row.get("window_id", "")).strip(): row for row in baseline_rows}
    failures: list[str] = []
    for window_id in sorted(TARGET_WINDOW_IDS):
        current_extra = len(current_map.get(window_id, {}).get("extra_tactics", []) or [])
        baseline_extra = len(baseline_map.get(window_id, {}).get("extra_tactics", []) or [])
        if current_extra > baseline_extra:
            failures.append(f"{window_id} extra_tactics increased from {baseline_extra} to {current_extra}")
    return failures


def main() -> None:
    config_path = _resolve_repo_path(CONFIG_PATH)
    logs_provenance = ensure_cadets_logs_ready()
    cfg = load_config(config_path)
    reuse_provenance = _prepare_reused_artifacts(cfg.artifacts_dir)

    _clean_dir(cfg.module5_paths_dir)
    _clean_dir(cfg.module6_reason_dir)
    _clean_dir(cfg.artifacts_dir / EVAL_DIR_NAME)

    module5_outputs = run_module5_paths(cfg)
    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)
    diagnostic_outputs = run_cadets_eventid_fix_diagnostics(
        artifacts_root=cfg.artifacts_dir,
        gt_node_path=GT_NODE_PATH,
        source_logs=CADETS_LOGS_DIR,
        gt_json_path=GT_JSON_PATH,
    )
    baseline_metrics = _load_metrics(_resolve_metrics_summary(BASELINE_ROOT / EVAL_DIR_NAME))
    current_rows = _load_tactic_diff_rows(cfg.artifacts_dir)
    baseline_rows = _load_tactic_diff_rows(BASELINE_ROOT)
    gate_failures = _metric_drop_failures(metrics, baseline_metrics) + _extra_tactic_failures(current_rows, baseline_rows)
    can_continue_to_step3 = not gate_failures

    provenance = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REMOTE_REPO_ROOT),
        "config_path": str(config_path),
        "artifacts_dir": str(cfg.artifacts_dir),
        "baseline_root": str(BASELINE_ROOT),
        "claim_attack_prior_mode": str(cfg.claim_attack_prior_mode),
        "attack_mapping_scope": str(cfg.attack_mapping_scope),
        "tactic_mapping_mode": str(cfg.tactic_mapping_mode),
        "gt_node_path": str(GT_NODE_PATH),
        "gt_json_path": str(GT_JSON_PATH),
        "cadets_logs_dir": str(CADETS_LOGS_DIR),
        **logs_provenance,
        **reuse_provenance,
        "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "diagnostic_outputs": diagnostic_outputs,
    }
    provenance_path = cfg.artifacts_dir / "provenance_summary.json"
    comparison_path = cfg.artifacts_dir / "comparison_summary.json"
    decision_path = cfg.artifacts_dir / "decision_summary.json"
    step_decision_path = cfg.artifacts_dir / "step_decision_summary.json"
    _write_json(provenance_path, provenance)
    summary = {
        "provenance_summary": str(provenance_path),
        "baseline_metrics": baseline_metrics,
        "metrics": metrics,
        "gate_failures": gate_failures,
        "can_continue_to_step3": can_continue_to_step3,
        "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "diagnostic_outputs": diagnostic_outputs,
    }
    _write_json(comparison_path, summary)
    _write_json(decision_path, summary)
    _write_json(step_decision_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

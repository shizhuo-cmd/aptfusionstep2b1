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
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_ruletight1_20260616.yaml"
)
GT_NODE_PATH = Path("/root/autodl-tmp/data/cadets/cadets.txt")
BASELINE_ROOT = (
    REMOTE_REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_eventid_fix_20260615"
)
REUSED_DIR_NAMES = ["module1", "module2", "module3_evidence", "module4_compact", "module5_paths"]


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


def main() -> None:
    config_path = _resolve_repo_path(CONFIG_PATH)
    logs_provenance = ensure_cadets_logs_ready()
    cfg = load_config(config_path)
    reuse_provenance = _prepare_reused_artifacts(cfg.artifacts_dir)

    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)
    diagnostic_outputs = run_cadets_eventid_fix_diagnostics(
        artifacts_root=cfg.artifacts_dir,
        gt_node_path=GT_NODE_PATH,
        source_logs=CADETS_LOGS_DIR,
        gt_json_path=GT_JSON_PATH,
    )
    baseline_metrics = _load_metrics(_resolve_metrics_summary(BASELINE_ROOT / "path_reason_eval_tactics_only_llm"))

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
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "diagnostic_outputs": diagnostic_outputs,
    }
    provenance_path = cfg.artifacts_dir / "provenance_summary.json"
    decision_path = cfg.artifacts_dir / "decision_summary.json"
    _write_json(provenance_path, provenance)
    summary = {
        "provenance_summary": str(provenance_path),
        "baseline_metrics": baseline_metrics,
        "metrics": metrics,
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "diagnostic_outputs": diagnostic_outputs,
    }
    _write_json(decision_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

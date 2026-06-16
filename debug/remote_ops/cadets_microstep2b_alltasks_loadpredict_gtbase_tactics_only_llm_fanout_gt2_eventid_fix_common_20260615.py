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
from apt_fusion.config import FusionConfig, load_config
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
    build_split_meta_compare,
    ensure_cadets_logs_ready,
)


GT_NODE_PATH = Path("/root/autodl-tmp/data/cadets/cadets.txt")
OLD_EXCLUDE_ROOT = (
    REMOTE_REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_20260615"
)
OLD_INCLUDE_ROOT = (
    REMOTE_REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_include_segmented_20260615"
)
REUSED_DIR_NAMES = [
    "module1",
    "module2",
    "module3_evidence",
    "module4_compact",
    "module5_paths",
]


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _source_root_for_cfg(cfg: FusionConfig) -> Path:
    if bool(cfg.task_component_count_segmented_children_upstream):
        return OLD_INCLUDE_ROOT
    return OLD_EXCLUDE_ROOT


def _prepare_reused_artifacts(source_root: Path, target_root: Path) -> dict[str, Any]:
    missing = [str(source_root / name) for name in REUSED_DIR_NAMES if not (source_root / name).exists()]
    if missing:
        raise FileNotFoundError("Missing required reused artifact directories: " + ", ".join(missing))
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    for name in REUSED_DIR_NAMES:
        _copy_tree(source_root / name, target_root / name)
    return {
        "reused_source_root": str(source_root),
        "reused_dir_names": list(REUSED_DIR_NAMES),
    }


def run_eventid_fix_experiment(config_path: str | Path) -> dict[str, Any]:
    config_path = _resolve_repo_path(config_path)
    logs_provenance = ensure_cadets_logs_ready()
    cfg = load_config(config_path)
    source_root = _source_root_for_cfg(cfg)
    reuse_provenance = _prepare_reused_artifacts(source_root, cfg.artifacts_dir)

    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)
    diagnostic_outputs = run_cadets_eventid_fix_diagnostics(
        artifacts_root=cfg.artifacts_dir,
        gt_node_path=GT_NODE_PATH,
        source_logs=CADETS_LOGS_DIR,
        gt_json_path=GT_JSON_PATH,
    )

    provenance = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REMOTE_REPO_ROOT),
        "config_path": str(config_path),
        "artifacts_dir": str(cfg.artifacts_dir),
        "module6_bug_fix": "normalize event_id evidence_claim_ids into claim_id references before mapping validation",
        "claim_attack_prior_mode": str(cfg.claim_attack_prior_mode),
        "attack_mapping_scope": str(cfg.attack_mapping_scope),
        "tactic_mapping_mode": str(cfg.tactic_mapping_mode),
        "task_component_count_segmented_children_upstream": bool(cfg.task_component_count_segmented_children_upstream),
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
        "metrics": metrics,
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "diagnostic_outputs": diagnostic_outputs,
    }
    _write_json(decision_path, summary)
    return summary


def build_old_vs_new_comparison(
    *,
    old_exclude_root: Path,
    new_exclude_root: Path,
    old_include_root: Path,
    new_include_root: Path,
) -> dict[str, Any]:
    return {
        "exclude_segmented_old": {
            "artifacts_root": str(old_exclude_root),
            "metrics": _load_metrics(_resolve_metrics_summary(old_exclude_root / "path_reason_eval_tactics_only_llm")),
        },
        "exclude_segmented_eventid_fix": {
            "artifacts_root": str(new_exclude_root),
            "metrics": _load_metrics(_resolve_metrics_summary(new_exclude_root / "path_reason_eval_tactics_only_llm")),
        },
        "include_segmented_old": {
            "artifacts_root": str(old_include_root),
            "metrics": _load_metrics(_resolve_metrics_summary(old_include_root / "path_reason_eval_tactics_only_llm")),
        },
        "include_segmented_eventid_fix": {
            "artifacts_root": str(new_include_root),
            "metrics": _load_metrics(_resolve_metrics_summary(new_include_root / "path_reason_eval_tactics_only_llm")),
        },
    }


def print_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


__all__ = [
    "LOCAL_REPO_ROOT",
    "REMOTE_REPO_ROOT",
    "OLD_EXCLUDE_ROOT",
    "OLD_INCLUDE_ROOT",
    "build_old_vs_new_comparison",
    "build_split_meta_compare",
    "print_json",
    "run_eventid_fix_experiment",
]

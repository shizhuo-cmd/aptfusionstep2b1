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

from apt_fusion.config import load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_TEMPLATE = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_llm_worktree_e3gt_gtonly_20260624.yaml"
)
SOURCE_ROOT = (
    REPO_ROOT
    / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_ablation_baseline_current_e3gt_plus240_gtonly_20260707"
)
ARTIFACT_ROOT = (
    REPO_ROOT
    / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_"
    "baseline_current_relaxedcap_e3gt_plus240_gtonly_20260708"
)
GT_TIME_OFFSET_MINUTES = 240


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing source artifact directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _evaluate(cfg) -> tuple[dict[str, Any], dict[str, str]]:
    gt_path = resolve_attack_eval_gt_json(REPO_ROOT, cfg.attack_eval_gt_json_path)
    strict_windows, technique_defs, _ = load_gt_reference(gt_path, host_filter=cfg.host.upper())
    apply_gt_time_offset(strict_windows, minutes=GT_TIME_OFFSET_MINUTES)
    output_dir = cfg.artifacts_dir / "path_reason_eval_tactics_only_llm"
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
    cfg = load_config(CONFIG_TEMPLATE)
    cfg.artifacts_dir = ARTIFACT_ROOT
    cfg.attack_eval_gt_json_path = resolve_attack_eval_gt_json(REPO_ROOT, cfg.attack_eval_gt_json_path)
    cfg.path_reason_gt_time_offset_minutes = GT_TIME_OFFSET_MINUTES
    cfg.claim_attack_prior_mode = "disabled"
    cfg.attack_mapping_scope = "tactics_only"
    cfg.tactic_mapping_mode = "llm"

    # Roll back the 20260707 TRACE runtime cap and return to the default path rules
    # used by the wider step7-era search space.
    cfg.path_reason_rules_path = REPO_ROOT / "configs" / "path_reason_default.yaml"
    cfg.path_top_k = 20
    setattr(cfg, "path_split_parent_label_inheritance_enabled", True)
    setattr(cfg, "path_family_preserve_enabled", True)

    _clean_dir(cfg.artifacts_dir)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    for dirname in ["module1", "module2", "module3_evidence", "module4_compact"]:
        _copy_tree(SOURCE_ROOT / dirname, cfg.artifacts_dir / dirname)

    module5_outputs = run_module5_paths(cfg)
    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)

    provenance = {
        "variant": "baseline_current_relaxedcap",
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "config_template_path": str(CONFIG_TEMPLATE),
        "source_root": str(SOURCE_ROOT),
        "reused_dir_names": ["module1", "module2", "module3_evidence", "module4_compact"],
        "artifacts_dir": str(cfg.artifacts_dir),
        "gt_json_path": str(cfg.attack_eval_gt_json_path),
        "gt_time_offset_minutes_applied": GT_TIME_OFFSET_MINUTES,
        "claim_attack_prior_mode": cfg.claim_attack_prior_mode,
        "attack_mapping_scope": cfg.attack_mapping_scope,
        "tactic_mapping_mode": cfg.tactic_mapping_mode,
        "path_reason_rules_path": str(cfg.path_reason_rules_path),
        "path_top_k": int(cfg.path_top_k),
        "path_split_parent_label_inheritance_enabled": True,
        "path_family_preserve_enabled": True,
        "rerun_modules": ["module5_paths", "module6_reason", "path_reason_eval"],
        "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "metrics": metrics,
    }
    (cfg.artifacts_dir / "provenance_summary.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

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

from apt_fusion.common import load_json, load_jsonl, save_json
from apt_fusion.config import load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.module5_path_finder import (
    _augment_candidate_support,
    _load_object_states,
    _load_object_versions,
    _load_process_states,
)
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason
from apt_fusion.path_reason.path_report import build_path_dossier
from apt_fusion.path_reason.path_schemas import CandidatePath

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_windowgate_20260624.yaml"
)
REUSED_SOURCE_ROOT = (
    REPO_ROOT
    / "artifacts_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_windowgate_step3f_cleanupplaceholder_offset240_20260626"
)
TARGET_ROOT = (
    REPO_ROOT
    / "artifacts_theia_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_windowgate_step4j_cleanupdossierrefresh_offset240_20260626"
)
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
GT_TIME_OFFSET_MINUTES = 240
REUSED_DIR_NAMES = ["module1", "module3_evidence", "module4_compact"]
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"


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


def _prepare_reused_artifacts(target_root: Path) -> dict[str, Any]:
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    for name in REUSED_DIR_NAMES:
        source = REUSED_SOURCE_ROOT / name
        target = target_root / name
        if not source.exists():
            raise FileNotFoundError(f"Missing reused artifact directory: {source}")
        target.symlink_to(source, target_is_directory=True)
    return {
        "reused_source_root": str(REUSED_SOURCE_ROOT),
        "reused_dir_names": list(REUSED_DIR_NAMES),
        "reuse_mode": "symlink",
    }


def _refresh_candidate_paths(cfg) -> dict[str, Any]:
    source_dir = REUSED_SOURCE_ROOT / "module5_paths" / "candidate_paths"
    target_dir = cfg.module5_paths_dir / "candidate_paths"
    target_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {"task_count": 0, "path_count": 0}
    for source_file in sorted(source_dir.glob("*.json")):
        task_id = source_file.stem
        process_states = _load_process_states(cfg.module4_compact_dir / "process_states_prepath" / f"{task_id}.json")
        object_states = _load_object_states(cfg.module4_compact_dir / "object_states" / f"{task_id}.json")
        object_versions = _load_object_versions(cfg.module4_compact_dir / "object_versions" / f"{task_id}.json")
        retained_events = load_jsonl(cfg.module4_compact_dir / "retained_events" / f"{task_id}.jsonl")
        raw_items = load_json(source_file)
        refreshed_items: list[dict[str, Any]] = []
        for payload in raw_items if isinstance(raw_items, list) else []:
            if not isinstance(payload, dict):
                continue
            path = CandidatePath.from_dict(payload)
            _augment_candidate_support(path, process_states, object_states, object_versions, retained_events)
            dossier = build_path_dossier(cfg, path, process_states, object_states, retained_events)
            refreshed = path.to_dict()
            refreshed["dossier"] = dossier
            refreshed_items.append(refreshed)
            summary["path_count"] += 1
        save_json(target_dir / source_file.name, refreshed_items)
        summary["task_count"] += 1
    return summary


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


def _focus_summary(cfg) -> dict[str, Any]:
    focus: dict[str, Any] = {}
    for path_id in ("task_5608_path_005", "task_3099_path_003", "task_3099_path_004"):
        report_path = cfg.module6_reason_dir / "reports" / f"{path_id}.report.json"
        if not report_path.exists():
            continue
        report = load_json(report_path)
        focus[path_id] = {
            "attack_candidate_tactics": [
                str(item.get("external_id", "")).strip()
                for item in report.get("attack_candidates", {}).get("tactics", [])
                if isinstance(item, dict)
            ],
            "claim_behaviors": [
                str(item.get("behavior_type", "")).strip()
                for item in report.get("claims", [])
                if isinstance(item, dict)
            ],
            "mapped_tactics": [
                str(item.get("tactic_id", "")).strip()
                for item in report.get("attack_mappings", [])
                if isinstance(item, dict)
            ],
        }
    return focus


def main() -> None:
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir = TARGET_ROOT
    reuse_provenance = _prepare_reused_artifacts(cfg.artifacts_dir)

    _clean_dir(cfg.module5_paths_dir)
    _clean_dir(cfg.module6_reason_dir)
    _clean_dir(cfg.artifacts_dir / EVAL_DIR_NAME)

    refresh_summary = _refresh_candidate_paths(cfg)
    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)
    focus_summary = _focus_summary(cfg)

    provenance = {
        "experiment_step": "step4j_cleanupdossierrefresh",
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "config_template_path": str(CONFIG_PATH),
        "artifacts_dir": str(cfg.artifacts_dir),
        "gt_json_path": str(GT_JSON_PATH),
        "gt_time_offset_minutes_applied": GT_TIME_OFFSET_MINUTES,
        **reuse_provenance,
        "rerun_modules": ["module5_paths_refresh_only", "module6_reason", "path_reason_eval"],
        "refresh_summary": refresh_summary,
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "metrics": metrics,
        "focus_summary": focus_summary,
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

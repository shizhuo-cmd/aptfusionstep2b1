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
from apt_fusion.config import load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.module4_semantic_compact import run_module4_compact
from apt_fusion.path_reason.module5_path_finder import run_module5_paths
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason
from cadets_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_common_20260615 import (
    CADETS_LOGS_DIR,
    ensure_cadets_logs_ready,
)

LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = Path(
    "configs/fusion_cloud_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_step2_claimtight_20260617.yaml"
)
REUSED_SOURCE_ROOT = (
    REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_step3_objecttransfer_20260617"
)
TARGET_ROOT = (
    REPO_ROOT
    / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_alltasks_loadpredict_gtbase_tactics_only_llm_fanout_gt2_exclude_segmented_currentcode_replay_from_step3_upstream_e3gt_plus240_20260623"
)
GT_NODE_PATH = Path("/root/autodl-tmp/data/cadets/cadets.txt")
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
GT_TIME_OFFSET_MINUTES = 240
REUSED_DIR_NAMES = ["module1", "module2", "module3_evidence"]
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)


def _rewrite_module3_task_index_paths(module3_dir: Path) -> dict[str, Any]:
    task_index_path = module3_dir / "task_index.json"
    rows = json.loads(task_index_path.read_text(encoding="utf-8"))
    remapped_fields = [
        "normalized_events_path",
        "entity_index_path",
        "process_event_index_path",
        "object_event_index_path",
        "task_evidence_frontier_path",
        "task_local_evidence_graph_path",
    ]
    rewritten = 0
    for row in rows:
        task_id = str(row.get("task_id", "")).strip()
        if not task_id:
            continue
        for field in remapped_fields:
            original = str(row.get(field, "")).strip()
            if not original:
                continue
            suffix = Path(original).suffix or (".jsonl" if "normalized_events" in field else ".json")
            dirname = field.removesuffix("_path")
            remapped = module3_dir / dirname / f"{task_id}{suffix}"
            row[field] = str(remapped)
            rewritten += 1
    task_index_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "task_index_path": str(task_index_path),
        "task_count": len(rows),
        "rewritten_field_count": rewritten,
    }


def _prepare_reused_artifacts(target_root: Path) -> dict[str, Any]:
    missing = [str(REUSED_SOURCE_ROOT / name) for name in REUSED_DIR_NAMES if not (REUSED_SOURCE_ROOT / name).exists()]
    if missing:
        raise FileNotFoundError("Missing required reused artifact directories: " + ", ".join(missing))
    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)
    for name in REUSED_DIR_NAMES:
        _copy_tree(REUSED_SOURCE_ROOT / name, target_root / name)
    task_index_rewrite = _rewrite_module3_task_index_paths(target_root / "module3_evidence")
    return {
        "reused_source_root": str(REUSED_SOURCE_ROOT),
        "reused_dir_names": list(REUSED_DIR_NAMES),
        "task_index_rewrite": task_index_rewrite,
    }


def _load_metrics(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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
    return _load_metrics(Path(outputs["metrics_summary"])), outputs


def main() -> None:
    logs_provenance = ensure_cadets_logs_ready()
    cfg = load_config(CONFIG_PATH)
    cfg.artifacts_dir = TARGET_ROOT
    reuse_provenance = _prepare_reused_artifacts(cfg.artifacts_dir)

    _clean_dir(cfg.module4_compact_dir)
    _clean_dir(cfg.module5_paths_dir)
    _clean_dir(cfg.module6_reason_dir)
    _clean_dir(cfg.artifacts_dir / EVAL_DIR_NAME)

    module4_outputs = run_module4_compact(cfg)
    module5_outputs = run_module5_paths(cfg)
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
        "remote_repo_root": str(REPO_ROOT),
        "config_template_path": str(CONFIG_PATH),
        "artifacts_dir": str(cfg.artifacts_dir),
        "gt_json_path": str(GT_JSON_PATH),
        "gt_node_path": str(GT_NODE_PATH),
        "cadets_logs_dir": str(CADETS_LOGS_DIR),
        "gt_time_offset_minutes_applied": GT_TIME_OFFSET_MINUTES,
        **logs_provenance,
        **reuse_provenance,
        "rerun_modules": ["module4_compact", "module5_paths", "module6_reason", "path_reason_eval"],
        "module4_outputs": {key: str(value) for key, value in module4_outputs.items()},
        "module5_outputs": {key: str(value) for key, value in module5_outputs.items()},
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "diagnostic_outputs": diagnostic_outputs,
        "metrics": metrics,
    }
    provenance_path = cfg.artifacts_dir / "provenance_summary.json"
    provenance_path.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(provenance, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

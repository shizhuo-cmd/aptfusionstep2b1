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

from apt_fusion.config import FusionConfig, load_config
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason


LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
CONFIG_PATH = Path(
    "configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_llm_gtonly_20260608.yaml"
)
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
DETERMINISTIC_ROOT = REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_deterministic_gtonly_20260608"
GT_JSON_PATH = REPO_ROOT / "docs/darpa_attack_eval_ground_truth_2026-05-26.json"
ALIGNMENT_MD_PATH = REPO_ROOT / "docs/trace_report_task_alignment_2026-05-19.md"
TRUTH_GAP_SCRIPT = REPO_ROOT / "debug/remote_ops/analyze_trace_truth_gap_20260608.py"
EVAL_DIR_NAME = "path_reason_eval_tactics_only_llm"
REQUIRED_SHARED_DIRS = ["module4_compact"]


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_tree(source: Path, target: Path) -> None:
    _clean_dir(target)
    shutil.copytree(source, target)


def _resolve_metrics_summary(root: Path) -> Path:
    direct = root / "metrics_summary.json"
    if direct.exists():
        return direct
    candidates = sorted(root.rglob("metrics_summary.json"), key=lambda path: (len(path.parts), str(path)))
    if not candidates:
        raise FileNotFoundError(f"metrics_summary.json not found under: {root}")
    return candidates[0]


def _load_metrics(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _module5_outputs_from_disk(cfg: FusionConfig) -> dict[str, str]:
    return {
        "summary": str(cfg.module5_paths_dir / "summary.json"),
        "process_summary": str(cfg.module5_paths_dir / "process_summary.json"),
        "object_summary": str(cfg.module5_paths_dir / "object_summary.json"),
    }


def _module6_outputs_from_disk(cfg: FusionConfig) -> dict[str, str]:
    return {
        "summary": str(cfg.module6_reason_dir / "summary.json"),
        "report_index": str(cfg.module6_reason_dir / "report_index.json"),
        "reports_dir": str(cfg.module6_reason_dir / "reports"),
    }


def _eval_outputs_from_disk(cfg: FusionConfig) -> dict[str, str]:
    output_dir = cfg.artifacts_dir / EVAL_DIR_NAME
    return {
        "metrics_summary": str(output_dir / "metrics_summary.json"),
        "window_level_metrics": str(output_dir / "window_level_metrics.json"),
        "technique_comparison": str(output_dir / "technique_comparison.json"),
        "tactic_comparison": str(output_dir / "tactic_comparison.json"),
        "tactic_diff_by_task": str(output_dir / "tactic_diff_by_task.json"),
        "candidate_tactic_coverage_by_task": str(output_dir / "candidate_tactic_coverage_by_task.json"),
    }


def _truth_gap_outputs_from_disk(cfg: FusionConfig) -> dict[str, str]:
    output_dir = cfg.artifacts_dir / "truth_gap_analysis"
    return {
        "output_dir": str(output_dir),
        "raw_log_chain_truth": str(output_dir / "raw_log_chain_truth.json"),
        "task_truth_gap_summary": str(output_dir / "task_truth_gap_summary.json"),
        "per_task_truth_gap": str(output_dir / "per_task_truth_gap.md"),
    }


def _module5_ready(cfg: FusionConfig) -> bool:
    paths = _module5_outputs_from_disk(cfg)
    return all(Path(path).exists() for path in paths.values()) and (cfg.module5_paths_dir / "candidate_paths").exists()


def _module6_ready(cfg: FusionConfig) -> bool:
    paths = _module6_outputs_from_disk(cfg)
    return all(Path(path).exists() for path in paths.values())


def _eval_ready(cfg: FusionConfig) -> bool:
    paths = _eval_outputs_from_disk(cfg)
    return all(Path(path).exists() for path in paths.values())


def _truth_gap_ready(cfg: FusionConfig) -> bool:
    paths = _truth_gap_outputs_from_disk(cfg)
    return all(Path(path).exists() for key, path in paths.items() if key != "output_dir")


def _ensure_shared_artifacts(cfg: FusionConfig) -> None:
    for name in REQUIRED_SHARED_DIRS:
        target = cfg.artifacts_dir / name
        if target.exists():
            continue
        source = DETERMINISTIC_ROOT / name
        if not source.exists():
            raise FileNotFoundError(f"required shared artifact dir not found: {source}")
        _copy_tree(source, target)


def _load_gt(host: str) -> tuple[list[Any], dict[str, list[str]]]:
    strict_windows, technique_defs, gt_metadata = load_gt_reference(GT_JSON_PATH, host_filter=host)
    offsets = gt_metadata.get("recommended_gt_time_offset_minutes_by_host", {})
    if isinstance(offsets, dict):
        offset = offsets.get(host)
        if offset:
            apply_gt_time_offset(strict_windows, minutes=int(offset))
    return strict_windows, technique_defs


def _evaluate(cfg: FusionConfig) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs = _load_gt(cfg.host.upper())
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


def _run_truth_gap_analysis(cfg: FusionConfig) -> dict[str, str]:
    output_dir = cfg.artifacts_dir / "truth_gap_analysis"
    command = [
        sys.executable,
        str(TRUTH_GAP_SCRIPT),
        "--artifacts-dir",
        str(cfg.artifacts_dir),
        "--source-logs",
        str(cfg.source_logs),
        "--gt-json-path",
        str(GT_JSON_PATH),
        "--alignment-md-path",
        str(ALIGNMENT_MD_PATH),
        "--output-dir",
        str(output_dir),
    ]
    subprocess.run(command, check=True)
    return {
        "output_dir": str(output_dir),
        "raw_log_chain_truth": str(output_dir / "raw_log_chain_truth.json"),
        "task_truth_gap_summary": str(output_dir / "task_truth_gap_summary.json"),
        "per_task_truth_gap": str(output_dir / "per_task_truth_gap.md"),
    }


def _ensure_module5(cfg: FusionConfig) -> dict[str, str]:
    if _module5_ready(cfg):
        return _module5_outputs_from_disk(cfg)
    if not (DETERMINISTIC_ROOT / "module5_paths").exists():
        raise FileNotFoundError(f"deterministic module5_paths not found: {DETERMINISTIC_ROOT / 'module5_paths'}")
    _copy_tree(DETERMINISTIC_ROOT / "module5_paths", cfg.module5_paths_dir)
    return _module5_outputs_from_disk(cfg)


def _ensure_module6(cfg: FusionConfig) -> dict[str, str]:
    if _module6_ready(cfg):
        return _module6_outputs_from_disk(cfg)
    _clean_dir(cfg.module6_reason_dir)
    return {key: str(value) for key, value in run_module6_reason(cfg).items()}


def _ensure_eval(cfg: FusionConfig) -> tuple[dict[str, Any], dict[str, str]]:
    outputs = _eval_outputs_from_disk(cfg)
    if _eval_ready(cfg):
        return _load_metrics(Path(outputs["metrics_summary"])), outputs
    return _evaluate(cfg)


def _ensure_truth_gap(cfg: FusionConfig) -> dict[str, str]:
    if _truth_gap_ready(cfg):
        return _truth_gap_outputs_from_disk(cfg)
    return _run_truth_gap_analysis(cfg)


def main() -> None:
    cfg = load_config(CONFIG_PATH)
    baseline_metrics_path = _resolve_metrics_summary(DETERMINISTIC_ROOT / "path_reason_eval_tactics_only_deterministic")

    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    _ensure_shared_artifacts(cfg)

    _ensure_module5(cfg)
    module6_outputs = _ensure_module6(cfg)
    metrics, eval_outputs = _ensure_eval(cfg)
    truth_gap_outputs = _ensure_truth_gap(cfg)

    provenance = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "config_path": str(CONFIG_PATH),
        "reused_module5_root": str(DETERMINISTIC_ROOT),
        "baseline_metrics_path": str(baseline_metrics_path),
        "claim_attack_prior_mode": cfg.claim_attack_prior_mode,
        "attack_mapping_scope": cfg.attack_mapping_scope,
        "tactic_mapping_mode": cfg.tactic_mapping_mode,
    }
    provenance_path = cfg.artifacts_dir / "provenance_summary.json"
    provenance_path.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = {
        "provenance_summary": str(provenance_path),
        "baseline_metrics": _load_metrics(baseline_metrics_path),
        "metrics": metrics,
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "truth_gap_outputs": truth_gap_outputs,
    }
    summary_path = cfg.artifacts_dir / "decision_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

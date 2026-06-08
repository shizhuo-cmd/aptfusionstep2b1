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
BASE_CONFIG_PATH = Path(
    "configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_no_attack_priors_gtonly_20260608.yaml"
)
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
EXPERIMENT_ROOT = REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_holmes_full_priors_gtonly_20260608"
NO_PRIOR_ROOT = REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_no_attack_priors_gtonly_20260608"
GT_JSON_PATH = REPO_ROOT / "docs/darpa_attack_eval_ground_truth_2026-05-26.json"
COMPARE_SCRIPT = REPO_ROOT / "debug/remote_ops/analyze_attack_prior_effect_20260608.py"
FULL_PRIOR_ROOT_CANDIDATES = [
    Path("/root/autodl-tmp/APT-Fusionstep2b1/artifacts_trace_train_stats_latefusion_bonus1_microstep2b_gtonly_20260603"),
    Path("/root/autodl-tmp/APT-Fusion/artifacts_trace_train_stats_latefusion_bonus1_microstep2b_gtonly_20260603"),
]


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


def _resolve_full_prior_root() -> Path:
    for candidate in FULL_PRIOR_ROOT_CANDIDATES:
        if (candidate / "module5_paths").exists():
            _resolve_metrics_summary(candidate)
            return candidate
    joined = ", ".join(str(path) for path in FULL_PRIOR_ROOT_CANDIDATES)
    raise FileNotFoundError(f"explicit step2b1 baseline artifacts not found in any candidate path: {joined}")


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
    output_dir = cfg.artifacts_dir / "path_reason_eval_holmes_full_priors"
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


def _run_compare(full_prior_root: Path, no_prior_root: Path) -> dict[str, str]:
    output_dir = full_prior_root / "prior_effect_analysis_against_holmes_no_prior"
    command = [
        sys.executable,
        str(COMPARE_SCRIPT),
        "--full-prior-experiment-dir",
        str(full_prior_root),
        "--no-prior-experiment-dir",
        str(no_prior_root),
        "--gt-json-path",
        str(GT_JSON_PATH),
        "--output-dir",
        str(output_dir),
    ]
    subprocess.run(command, check=True)
    return {
        "output_dir": str(output_dir),
        "tactic_diff_by_task": str(output_dir / "tactic_diff_by_task.json"),
        "technique_diff_by_task": str(output_dir / "technique_diff_by_task.json"),
        "candidate_tactic_coverage_by_task": str(output_dir / "candidate_tactic_coverage_by_task.json"),
        "prior_effect_summary": str(output_dir / "prior_effect_summary.md"),
    }


def main() -> None:
    cfg = load_config(BASE_CONFIG_PATH)
    cfg.artifacts_dir = EXPERIMENT_ROOT
    cfg.claim_attack_prior_mode = "full"

    full_prior_root = _resolve_full_prior_root()
    full_prior_metrics_path = _resolve_metrics_summary(full_prior_root)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)

    _copy_tree(full_prior_root / "module5_paths", cfg.module5_paths_dir)
    _clean_dir(cfg.module6_reason_dir)

    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)
    compare_outputs = _run_compare(cfg.artifacts_dir, NO_PRIOR_ROOT)

    provenance = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "base_config_path": str(BASE_CONFIG_PATH),
        "claim_attack_prior_mode": cfg.claim_attack_prior_mode,
        "full_prior_baseline_root": str(full_prior_root),
        "full_prior_metrics_path": str(full_prior_metrics_path),
        "holmes_no_prior_root": str(NO_PRIOR_ROOT),
        "reused_dirs": ["module5_paths"],
    }
    provenance_path = cfg.artifacts_dir / "provenance_summary.json"
    provenance_path.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")

    decision_summary = {
        "provenance_summary": str(provenance_path),
        "full_prior_baseline_root": str(full_prior_root),
        "full_prior_baseline_metrics_path": str(full_prior_metrics_path),
        "full_prior_baseline_metrics": _load_metrics(full_prior_metrics_path),
        "holmes_full_prior_root": str(cfg.artifacts_dir),
        "holmes_full_prior_metrics": metrics,
        "holmes_no_prior_root": str(NO_PRIOR_ROOT),
        "holmes_no_prior_metrics": _load_metrics(_resolve_metrics_summary(NO_PRIOR_ROOT / "path_reason_eval_no_attack_priors")),
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
        "compare_outputs": compare_outputs,
    }
    summary_path = cfg.artifacts_dir / "decision_summary.json"
    summary_path.write_text(json.dumps(decision_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(decision_summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

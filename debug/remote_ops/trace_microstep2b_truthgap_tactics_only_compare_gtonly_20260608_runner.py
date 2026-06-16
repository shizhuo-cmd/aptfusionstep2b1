from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]

REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
DET_ROOT = REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_deterministic_gtonly_20260608"
LLM_ROOT = REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_llm_gtonly_20260608"
OUTPUT_DIR = REPO_ROOT / "debug/remote_ops/trace_microstep2b_truthgap_tactics_only_compare_gtonly_20260608_outputs"
BASELINE_ROOT_CANDIDATES = [
    REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_no_attack_priors_gtonly_20260608",
    REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_gtonly_20260603",
    Path("/root/autodl-tmp/APT-Fusion/artifacts_trace_train_stats_latefusion_bonus1_microstep2b_gtonly_20260603"),
]
DET_RUNNER = REPO_ROOT / "debug/remote_ops/trace_microstep2b_truthgap_tactics_only_deterministic_gtonly_20260608_runner.py"
LLM_RUNNER = REPO_ROOT / "debug/remote_ops/trace_microstep2b_truthgap_tactics_only_llm_gtonly_20260608_runner.py"


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


def _resolve_existing_root(candidates: list[Path], required_dir: str) -> Path:
    for candidate in candidates:
        if (candidate / required_dir).exists():
            return candidate
    joined = ", ".join(str(item) for item in candidates)
    raise FileNotFoundError(f"required artifact dir {required_dir!r} not found in any candidate path: {joined}")


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def _metric_float(metrics: dict[str, Any], key: str, default: float) -> float:
    value = metrics.get(key, default)
    if value is None:
        return float(default)
    if isinstance(value, str) and not value.strip():
        return float(default)
    return float(value)


def _passes_acceptance(metrics: dict[str, Any]) -> bool:
    return (
        _metric_float(metrics, "confirmed_window_recall", 0.0) >= 0.5
        and _metric_float(metrics, "strict_tactic_recall_macro", 0.0) >= 0.25
        and _metric_float(metrics, "off_window_high_risk_rate", 1.0) <= 0.125
    )


def _select_mode(det_metrics: dict[str, Any], llm_metrics: dict[str, Any]) -> str:
    det_pass = _passes_acceptance(det_metrics)
    llm_pass = _passes_acceptance(llm_metrics)
    if det_pass and llm_pass:
        return "deterministic_tactics_only"
    if det_pass:
        return "deterministic_tactics_only"
    if llm_pass:
        return "llm_tactics_only"
    det_score = (
        _metric_float(det_metrics, "strict_tactic_recall_macro", 0.0),
        -_metric_float(det_metrics, "off_window_high_risk_rate", 1.0),
    )
    llm_score = (
        _metric_float(llm_metrics, "strict_tactic_recall_macro", 0.0),
        -_metric_float(llm_metrics, "off_window_high_risk_rate", 1.0),
    )
    return "deterministic_tactics_only" if det_score >= llm_score else "llm_tactics_only"


def main() -> None:
    _run([sys.executable, str(DET_RUNNER)])
    _run([sys.executable, str(LLM_RUNNER)])
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    baseline_root = _resolve_existing_root(BASELINE_ROOT_CANDIDATES, "module5_paths")
    baseline_metrics_path = _resolve_metrics_summary(baseline_root)
    det_metrics_path = _resolve_metrics_summary(DET_ROOT / "path_reason_eval_tactics_only_deterministic")
    llm_metrics_path = _resolve_metrics_summary(LLM_ROOT / "path_reason_eval_tactics_only_llm")

    baseline_metrics = _load_metrics(baseline_metrics_path)
    det_metrics = _load_metrics(det_metrics_path)
    llm_metrics = _load_metrics(llm_metrics_path)

    provenance = {
        "deterministic_root": str(DET_ROOT),
        "llm_root": str(LLM_ROOT),
        "baseline_root": str(baseline_root),
        "baseline_metrics_path": str(baseline_metrics_path),
        "deterministic_metrics_path": str(det_metrics_path),
        "llm_metrics_path": str(llm_metrics_path),
    }
    provenance_path = OUTPUT_DIR / "provenance_summary.json"
    provenance_path.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = {
        "provenance_summary": str(provenance_path),
        "baseline_metrics": baseline_metrics,
        "deterministic_metrics": det_metrics,
        "llm_metrics": llm_metrics,
        "selected_mode": _select_mode(det_metrics, llm_metrics),
        "deterministic_acceptance": _passes_acceptance(det_metrics),
        "llm_acceptance": _passes_acceptance(llm_metrics),
    }
    summary_path = OUTPUT_DIR / "comparison_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

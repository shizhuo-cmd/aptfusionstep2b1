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
from apt_fusion.path_reason.module6_attack_reason import run_module6_reason


LOCAL_REPO_ROOT = Path(r"D:\daima\APT-Fusionstep2b1")
REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")
CONFIG_PATH = Path(
    "configs/fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_truthgap_tactics_only_llm_ruletight1_gtonly_20260616.yaml"
)
BASELINE_ROOT = REPO_ROOT / "artifacts_trace_train_stats_latefusion_bonus1_microstep2b_truthgap_tactics_only_llm_gtonly_20260608"
GT_JSON_PATH = resolve_attack_eval_gt_json(REPO_ROOT)
REUSED_DIR_NAMES = ["module4_compact", "module5_paths"]
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


def _load_metrics(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_metrics_summary(root: Path) -> Path:
    direct = root / "metrics_summary.json"
    if direct.exists():
        return direct
    candidates = sorted(root.rglob("metrics_summary.json"), key=lambda path: (len(path.parts), str(path)))
    if not candidates:
        raise FileNotFoundError(f"metrics_summary.json not found under: {root}")
    return candidates[0]


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


def _evaluate(cfg) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, gt_metadata = load_gt_reference(GT_JSON_PATH, host_filter=cfg.host.upper())
    offsets = gt_metadata.get("recommended_gt_time_offset_minutes_by_host", {})
    if isinstance(offsets, dict):
        offset = offsets.get(cfg.host.upper())
        if offset:
            apply_gt_time_offset(strict_windows, minutes=int(offset))
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
    cfg = load_config(CONFIG_PATH)
    reuse_provenance = _prepare_reused_artifacts(cfg.artifacts_dir)
    module6_outputs = run_module6_reason(cfg)
    metrics, eval_outputs = _evaluate(cfg)
    baseline_metrics = _load_metrics(_resolve_metrics_summary(BASELINE_ROOT / EVAL_DIR_NAME))

    provenance = {
        "local_repo_root": str(LOCAL_REPO_ROOT),
        "remote_repo_root": str(REPO_ROOT),
        "config_path": str(CONFIG_PATH),
        "artifacts_dir": str(cfg.artifacts_dir),
        "baseline_root": str(BASELINE_ROOT),
        "claim_attack_prior_mode": cfg.claim_attack_prior_mode,
        "attack_mapping_scope": cfg.attack_mapping_scope,
        "tactic_mapping_mode": cfg.tactic_mapping_mode,
        **reuse_provenance,
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
    }
    provenance_path = cfg.artifacts_dir / "provenance_summary.json"
    decision_path = cfg.artifacts_dir / "decision_summary.json"
    provenance_path.write_text(json.dumps(provenance, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {
        "provenance_summary": str(provenance_path),
        "baseline_metrics": baseline_metrics,
        "metrics": metrics,
        "module6_outputs": {key: str(value) for key, value in module6_outputs.items()},
        "eval_outputs": eval_outputs,
    }
    decision_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import os
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

from apt_fusion.config import load_config, resolve_attack_eval_gt_json
from apt_fusion.evaluation.path_reason_eval import apply_gt_time_offset, load_gt_reference, run_evaluation


def _clean_dir(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()


def _symlink_dir(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing reused artifact directory: {source}")
    _clean_dir(target)
    os.symlink(source, target, target_is_directory=True)


def _copy_tree(source: Path, target: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Missing copied artifact directory: {source}")
    _clean_dir(target)
    shutil.copytree(source, target)


def _git_text(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip()


def _working_tree_fingerprint(repo_root: Path, code_baseline: str) -> dict[str, Any]:
    status_lines = [line for line in _git_text(repo_root, "status", "--short").splitlines() if line.strip()]
    return {
        "code_baseline": code_baseline,
        "head_commit": _git_text(repo_root, "rev-parse", "HEAD"),
        "git_status_short": status_lines,
        "git_status_count": len(status_lines),
    }


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _report_tactic_ids(report_path: Path) -> set[str]:
    payload = _load_json(report_path)
    return {
        str(item.get("tactic_id", "")).strip().upper()
        for item in payload.get("attack_mappings", []) or []
        if isinstance(item, dict) and str(item.get("tactic_id", "")).strip()
    }


def _patch_candidate_path_scores(
    *,
    candidate_dir: Path,
    reports_dir: Path,
    collection_bonus: float,
    defense_evasion_bonus: float,
) -> dict[str, Any]:
    patched_paths: list[str] = []
    collection_bonus_paths: list[str] = []
    defense_evasion_bonus_paths: list[str] = []
    for task_path in sorted(candidate_dir.glob("*.json")):
        payload = _load_json(task_path)
        if not isinstance(payload, list):
            continue
        changed = False
        for item in payload:
            if not isinstance(item, dict):
                continue
            path_id = str(item.get("path_id", "")).strip()
            if not path_id:
                continue
            report_path = reports_dir / f"{path_id}.report.json"
            if not report_path.exists():
                continue
            tactic_ids = _report_tactic_ids(report_path)
            base_score = float(item.get("risk_score", 0.0) or 0.0)
            new_score = base_score
            if "TA0009" in tactic_ids:
                new_score += float(collection_bonus)
                collection_bonus_paths.append(path_id)
            if "TA0005" in tactic_ids:
                new_score += float(defense_evasion_bonus)
                defense_evasion_bonus_paths.append(path_id)
            if new_score != base_score:
                item["risk_score"] = new_score
                changed = True
        if changed:
            payload.sort(key=lambda item: float(item.get("risk_score", 0.0) or 0.0), reverse=True)
            _save_json(task_path, payload)
            patched_paths.append(str(task_path))
    return {
        "patched_task_file_count": len(patched_paths),
        "patched_task_files": patched_paths,
        "collection_bonus": float(collection_bonus),
        "defense_evasion_bonus": float(defense_evasion_bonus),
        "collection_bonus_path_count": len(collection_bonus_paths),
        "defense_evasion_bonus_path_count": len(defense_evasion_bonus_paths),
        "collection_bonus_paths": collection_bonus_paths,
        "defense_evasion_bonus_paths": defense_evasion_bonus_paths,
    }


def _evaluate(cfg, gt_json_path: Path, gt_time_offset_minutes: int, host: str, eval_dir_name: str) -> tuple[dict[str, Any], dict[str, str]]:
    strict_windows, technique_defs, _ = load_gt_reference(gt_json_path, host_filter=str(host).upper())
    apply_gt_time_offset(strict_windows, minutes=int(gt_time_offset_minutes))
    output_dir = cfg.artifacts_dir / eval_dir_name
    outputs = run_evaluation(
        artifacts_dir=cfg.artifacts_dir,
        strict_windows=strict_windows,
        technique_defs=technique_defs,
        output_dir=output_dir,
        host=str(host).upper(),
        match_top_n=5,
        pad_minutes=5,
        near_miss_minutes=5,
    )
    metrics = _load_json(Path(outputs["metrics_summary"]))
    return metrics, outputs


def _run_behavior_capture_analysis(
    *,
    python_exe: str,
    analysis_script: Path | None,
    artifacts_dir: Path,
    gt_json_path: Path,
    host: str,
    gt_time_offset_minutes: int,
    output_dir: Path | None,
) -> None:
    if analysis_script is None or output_dir is None:
        return
    _clean_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            python_exe,
            str(analysis_script),
            "--artifacts-dir",
            str(artifacts_dir),
            "--gt-json-path",
            str(gt_json_path),
            "--host",
            str(host).upper(),
            "--gt-time-offset-minutes",
            str(int(gt_time_offset_minutes)),
            "--output-dir",
            str(output_dir),
        ],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a candidate-path risk-score patch over existing module5/module6 outputs.")
    parser.add_argument("--config-path", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--gt-json-path", default="")
    parser.add_argument("--gt-time-offset-minutes", type=int, default=0)
    parser.add_argument("--eval-dir-name", default="path_reason_eval_tactics_only_llm")
    parser.add_argument("--analysis-script", default="")
    parser.add_argument("--analysis-output-dir", default="")
    parser.add_argument("--python-exe", default=sys.executable)
    parser.add_argument("--code-baseline", default="local_working_tree_snapshot")
    parser.add_argument("--reuse-dir", action="append", default=[])
    parser.add_argument("--copy-dir", action="append", default=["module5_paths", "module6_reason"])
    parser.add_argument("--collection-bonus", type=float, default=0.0)
    parser.add_argument("--defense-evasion-bonus", type=float, default=0.0)
    args = parser.parse_args()

    config_path = Path(args.config_path)
    source_root = Path(args.source_root)
    target_root = Path(args.target_root)
    configured_gt_path = Path(args.gt_json_path) if str(args.gt_json_path).strip() else None
    gt_json_path = resolve_attack_eval_gt_json(Path(__file__).resolve().parents[2], configured_gt_path)
    analysis_script = Path(args.analysis_script) if str(args.analysis_script).strip() else None
    analysis_output_dir = Path(args.analysis_output_dir) if str(args.analysis_output_dir).strip() else None

    cfg = load_config(config_path)
    cfg.artifacts_dir = target_root

    _clean_dir(target_root)
    target_root.mkdir(parents=True, exist_ok=True)

    for name in args.reuse_dir:
        _symlink_dir(source_root / name, target_root / name)
    for name in args.copy_dir:
        _copy_tree(source_root / name, target_root / name)

    patch_summary = _patch_candidate_path_scores(
        candidate_dir=target_root / "module5_paths" / "candidate_paths",
        reports_dir=target_root / "module6_reason" / "reports",
        collection_bonus=float(args.collection_bonus),
        defense_evasion_bonus=float(args.defense_evasion_bonus),
    )
    metrics, eval_outputs = _evaluate(
        cfg,
        gt_json_path=gt_json_path,
        gt_time_offset_minutes=args.gt_time_offset_minutes,
        host=args.host,
        eval_dir_name=args.eval_dir_name,
    )
    _run_behavior_capture_analysis(
        python_exe=args.python_exe,
        analysis_script=analysis_script,
        artifacts_dir=target_root,
        gt_json_path=gt_json_path,
        host=args.host,
        gt_time_offset_minutes=args.gt_time_offset_minutes,
        output_dir=analysis_output_dir,
    )

    provenance = {
        "replay_mode": "candidate_path_score_patch",
        "config_path": str(config_path),
        "source_root": str(source_root),
        "target_root": str(target_root),
        "reuse_dirs": list(args.reuse_dir),
        "copy_dirs": list(args.copy_dir),
        "host": str(args.host).upper(),
        "gt_json_path": str(gt_json_path),
        "gt_time_offset_minutes_applied": int(args.gt_time_offset_minutes),
        "patch_summary": patch_summary,
        "eval_outputs": eval_outputs,
        "metrics": metrics,
    }
    _save_json(target_root / "provenance_summary.json", provenance)
    _save_json(
        target_root / "working_tree_fingerprint.json",
        _working_tree_fingerprint(Path(__file__).resolve().parents[2], args.code_baseline),
    )
    print(json.dumps(provenance, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

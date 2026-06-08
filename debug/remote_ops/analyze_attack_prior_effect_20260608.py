from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


TASK_WINDOW_IDS = {
    "task_0345": "TRACE_20180413_1243_1253_04",
    "task_0546": "TRACE_20180413_1350_1428_05",
    "task_0557": "TRACE_20180413_1350_1428_05",
    "task_0558": "TRACE_20180413_1350_1428_05",
}

TACTIC_ID_TO_GT_NAME = {
    "TA0001": "INITIAL_ACCESS",
    "TA0002": "EXECUTION",
    "TA0003": "PERSISTENCE",
    "TA0005": "DEFENSE_EVASION",
    "TA0006": "CREDENTIAL_ACCESS",
    "TA0008": "LATERAL_MOVEMENT",
    "TA0009": "COLLECTION",
    "TA0010": "EXFILTRATION",
    "TA0011": "COMMAND_AND_CONTROL",
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _normalize_tactic_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    upper = text.upper()
    if upper in TACTIC_ID_TO_GT_NAME:
        return TACTIC_ID_TO_GT_NAME[upper]
    return re.sub(r"[^A-Z0-9]+", "_", upper).strip("_")


def _normalize_technique_id(value: str) -> str:
    return str(value or "").strip().upper().replace("/", ".")


def _resolve_metrics_summary(root: Path) -> Path:
    direct = root / "metrics_summary.json"
    if direct.exists():
        return direct
    candidates = sorted(root.rglob("metrics_summary.json"), key=lambda item: (len(item.parts), str(item)))
    if not candidates:
        raise FileNotFoundError(f"metrics_summary.json not found under {root}")
    return candidates[0]


def _resolve_selected_artifacts_dir(experiment_root: Path) -> Path:
    decision_path = experiment_root / "decision_summary.json"
    if decision_path.exists():
        decision = _load_json(decision_path)
        selected_mode = str(decision.get("selected_mode", "")).strip()
        if selected_mode == "subgraph_projected_candidate":
            phase_b = decision.get("phase_b", {}) if isinstance(decision.get("phase_b", {}), dict) else {}
            artifacts_dir = str(phase_b.get("artifacts_dir", "")).strip()
            if artifacts_dir:
                return Path(artifacts_dir)
        phase_a = decision.get("phase_a", {}) if isinstance(decision.get("phase_a", {}), dict) else {}
        artifacts_dir = str(phase_a.get("artifacts_dir", "")).strip()
        if artifacts_dir:
            return Path(artifacts_dir)
    phase_a_root = experiment_root / "phase_a"
    if (phase_a_root / "module6_reason" / "reports").exists():
        return phase_a_root
    return experiment_root


def _collect_task_outputs(artifacts_root: Path) -> dict[str, dict[str, Any]]:
    reports_dir = artifacts_root / "module6_reason" / "reports"
    outputs: dict[str, dict[str, Any]] = {}
    if not reports_dir.exists():
        return outputs
    for path in sorted(reports_dir.glob("*.report.json")):
        report = _load_json(path)
        if not isinstance(report, dict):
            continue
        task_id = str(report.get("task_id", "")).strip()
        if task_id not in TASK_WINDOW_IDS:
            continue
        item = outputs.setdefault(
            task_id,
            {
                "report_count": 0,
                "path_ids": [],
                "predicted_tactics": set(),
                "predicted_techniques": set(),
                "candidate_tactics": set(),
                "candidate_techniques": set(),
            },
        )
        item["report_count"] += 1
        path_id = str(report.get("path_id", "")).strip()
        if path_id:
            item["path_ids"].append(path_id)
        for mapping in report.get("attack_mappings", []) or []:
            if not isinstance(mapping, dict):
                continue
            tactic = _normalize_tactic_name(
                str(mapping.get("tactic_id", "")).strip() or str(mapping.get("tactic", "")).strip()
            )
            technique = _normalize_technique_id(str(mapping.get("technique_id", "")).strip())
            if tactic:
                item["predicted_tactics"].add(tactic)
            if technique:
                item["predicted_techniques"].add(technique)
        candidates = report.get("attack_candidates", {}) if isinstance(report.get("attack_candidates", {}), dict) else {}
        for tactic in candidates.get("tactics", []) or []:
            if not isinstance(tactic, dict):
                continue
            tactic_name = _normalize_tactic_name(
                str(tactic.get("external_id", "")).strip() or str(tactic.get("name", "")).strip()
            )
            if tactic_name:
                item["candidate_tactics"].add(tactic_name)
        for technique in candidates.get("techniques", []) or []:
            if not isinstance(technique, dict):
                continue
            technique_id = _normalize_technique_id(str(technique.get("external_id", "")).strip())
            if technique_id:
                item["candidate_techniques"].add(technique_id)
    return outputs


def _load_gt(gt_json_path: Path) -> dict[str, dict[str, Any]]:
    payload = _load_json(gt_json_path)
    windows = payload.get("windows", []) if isinstance(payload, dict) else []
    output: dict[str, dict[str, Any]] = {}
    for window in windows:
        if not isinstance(window, dict):
            continue
        window_id = str(window.get("window_id", "")).strip()
        if not window_id:
            continue
        output[window_id] = {
            "confirmed_tactics": sorted(
                {
                    _normalize_tactic_name(value)
                    for value in window.get("confirmed_tactics", []) or []
                    if _normalize_tactic_name(value)
                }
            ),
            "confirmed_techniques": sorted(
                {
                    _normalize_technique_id(value)
                    for value in window.get("confirmed_techniques", []) or []
                    if _normalize_technique_id(value)
                }
            ),
        }
    return output


def _sorted(values: set[str]) -> list[str]:
    return sorted(str(value).strip() for value in values if str(value).strip())


def _tactic_diff_for_task(
    task_id: str,
    gt_windows: dict[str, dict[str, Any]],
    full_outputs: dict[str, dict[str, Any]],
    no_outputs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    window_id = TASK_WINDOW_IDS[task_id]
    gt_tactics = gt_windows.get(window_id, {}).get("confirmed_tactics", [])
    full_task = full_outputs.get(task_id, {})
    no_task = no_outputs.get(task_id, {})
    full_pred = _sorted(set(full_task.get("predicted_tactics", set())))
    no_pred = _sorted(set(no_task.get("predicted_tactics", set())))
    gt_set = set(gt_tactics)
    full_set = set(full_pred)
    no_set = set(no_pred)
    return {
        "task_id": task_id,
        "gt_window_id": window_id,
        "gt_tactics": gt_tactics,
        "full_prior_predicted_tactics": full_pred,
        "no_prior_predicted_tactics": no_pred,
        "full_prior_hits": sorted(full_set.intersection(gt_set)),
        "full_prior_missed": sorted(gt_set - full_set),
        "full_prior_extra": sorted(full_set - gt_set),
        "no_prior_hits": sorted(no_set.intersection(gt_set)),
        "no_prior_missed": sorted(gt_set - no_set),
        "no_prior_extra": sorted(no_set - gt_set),
        "full_prior_path_ids": sorted(full_task.get("path_ids", [])),
        "no_prior_path_ids": sorted(no_task.get("path_ids", [])),
    }


def _technique_diff_for_task(
    task_id: str,
    gt_windows: dict[str, dict[str, Any]],
    full_outputs: dict[str, dict[str, Any]],
    no_outputs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    window_id = TASK_WINDOW_IDS[task_id]
    gt_techniques = gt_windows.get(window_id, {}).get("confirmed_techniques", [])
    full_task = full_outputs.get(task_id, {})
    no_task = no_outputs.get(task_id, {})
    full_pred = _sorted(set(full_task.get("predicted_techniques", set())))
    no_pred = _sorted(set(no_task.get("predicted_techniques", set())))
    gt_set = set(gt_techniques)
    full_set = set(full_pred)
    no_set = set(no_pred)
    return {
        "task_id": task_id,
        "gt_window_id": window_id,
        "gt_techniques": gt_techniques,
        "full_prior_predicted_techniques": full_pred,
        "no_prior_predicted_techniques": no_pred,
        "full_prior_hits": sorted(full_set.intersection(gt_set)),
        "full_prior_missed": sorted(gt_set - full_set),
        "full_prior_extra": sorted(full_set - gt_set),
        "no_prior_hits": sorted(no_set.intersection(gt_set)),
        "no_prior_missed": sorted(gt_set - no_set),
        "no_prior_extra": sorted(no_set - gt_set),
    }


def _candidate_tactic_coverage_for_task(
    task_id: str,
    gt_windows: dict[str, dict[str, Any]],
    full_outputs: dict[str, dict[str, Any]],
    no_outputs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    window_id = TASK_WINDOW_IDS[task_id]
    gt_tactics = gt_windows.get(window_id, {}).get("confirmed_tactics", [])
    gt_set = set(gt_tactics)
    full_candidates = _sorted(set(full_outputs.get(task_id, {}).get("candidate_tactics", set())))
    no_candidates = _sorted(set(no_outputs.get(task_id, {}).get("candidate_tactics", set())))
    full_set = set(full_candidates)
    no_set = set(no_candidates)
    return {
        "task_id": task_id,
        "gt_window_id": window_id,
        "gt_tactics": gt_tactics,
        "full_prior_candidate_tactics": full_candidates,
        "no_prior_candidate_tactics": no_candidates,
        "full_prior_covered_gt_tactics": sorted(full_set.intersection(gt_set)),
        "full_prior_missing_gt_tactics": sorted(gt_set - full_set),
        "no_prior_covered_gt_tactics": sorted(no_set.intersection(gt_set)),
        "no_prior_missing_gt_tactics": sorted(gt_set - no_set),
    }


def _build_summary_markdown(
    *,
    full_metrics: dict[str, Any],
    no_metrics: dict[str, Any],
    tactic_diff: dict[str, dict[str, Any]],
) -> str:
    lines = [
        "# ATT&CK Prior Effect Summary",
        "",
        "## Metrics",
        f"- full-prior confirmed_window_recall: `{float(full_metrics.get('confirmed_window_recall', 0.0)):.4f}`",
        f"- no-prior confirmed_window_recall: `{float(no_metrics.get('confirmed_window_recall', 0.0)):.4f}`",
        f"- full-prior strict_technique_recall_macro: `{float(full_metrics.get('strict_technique_recall_macro', 0.0)):.4f}`",
        f"- no-prior strict_technique_recall_macro: `{float(no_metrics.get('strict_technique_recall_macro', 0.0)):.4f}`",
        f"- full-prior off_window_high_risk_rate: `{float(full_metrics.get('off_window_high_risk_rate', 0.0)):.4f}`",
        f"- no-prior off_window_high_risk_rate: `{float(no_metrics.get('off_window_high_risk_rate', 0.0)):.4f}`",
        "",
        "## Questions",
    ]

    task_0345 = tactic_diff["task_0345"]
    recovered_0345 = sorted(
        set(task_0345["no_prior_hits"]) - set(task_0345["full_prior_hits"])
    )
    lines.append(
        f"- `0345` 是否补回 `DISCOVERY / DEFENSE_EVASION`："
        f" full=`{','.join(task_0345['full_prior_hits']) or 'none'}`"
        f", no-prior=`{','.join(task_0345['no_prior_hits']) or 'none'}`"
        f", 新增命中=`{','.join(recovered_0345) or 'none'}`"
    )

    task_0546 = tactic_diff["task_0546"]
    full_0546_bias = sorted(set(task_0546["full_prior_predicted_tactics"]).intersection({"CREDENTIAL_ACCESS", "COLLECTION"}))
    no_0546_bias = sorted(set(task_0546["no_prior_predicted_tactics"]).intersection({"CREDENTIAL_ACCESS", "COLLECTION"}))
    lines.append(
        f"- `0546` 是否不再被压向 `Credential Access / Collection`："
        f" full_bias=`{','.join(full_0546_bias) or 'none'}`"
        f", no_bias=`{','.join(no_0546_bias) or 'none'}`"
    )

    for task_id in ("task_0557", "task_0558"):
        item = tactic_diff[task_id]
        preserved = {"COMMAND_AND_CONTROL", "EXECUTION"}.issubset(set(item["no_prior_predicted_tactics"]))
        lines.append(
            f"- `{task_id[-4:]}` 是否仍保住 `COMMAND_AND_CONTROL / EXECUTION`："
            f" no-prior=`{','.join(item['no_prior_predicted_tactics']) or 'none'}`"
            f", preserved=`{str(preserved).lower()}`"
        )

    better_technique = "no-prior" if float(no_metrics.get("strict_technique_recall_macro", 0.0)) > float(full_metrics.get("strict_technique_recall_macro", 0.0)) else "full-prior"
    lower_noise = "no-prior" if float(no_metrics.get("off_window_high_risk_rate", 0.0)) < float(full_metrics.get("off_window_high_risk_rate", 0.0)) else "full-prior"
    lines.append(
        f"- technique recall 更高的是 `{better_technique}`，off-window 噪声更低的是 `{lower_noise}`。"
    )
    return "\n".join(lines).strip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare full-prior and no-prior ATT&CK mapping outputs.")
    parser.add_argument("--full-prior-experiment-dir", required=True)
    parser.add_argument("--no-prior-experiment-dir", required=True)
    parser.add_argument("--gt-json-path", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    full_experiment_root = Path(args.full_prior_experiment_dir)
    no_experiment_root = Path(args.no_prior_experiment_dir)
    gt_json_path = Path(args.gt_json_path)
    output_dir = Path(args.output_dir)
    _ensure_dir(output_dir)

    full_artifacts_root = _resolve_selected_artifacts_dir(full_experiment_root)
    no_artifacts_root = _resolve_selected_artifacts_dir(no_experiment_root)
    full_metrics = _load_json(_resolve_metrics_summary(full_experiment_root))
    no_metrics = _load_json(_resolve_metrics_summary(no_experiment_root))
    gt_windows = _load_gt(gt_json_path)
    full_outputs = _collect_task_outputs(full_artifacts_root)
    no_outputs = _collect_task_outputs(no_artifacts_root)

    tactic_diff = {
        task_id: _tactic_diff_for_task(task_id, gt_windows, full_outputs, no_outputs)
        for task_id in TASK_WINDOW_IDS
    }
    technique_diff = {
        task_id: _technique_diff_for_task(task_id, gt_windows, full_outputs, no_outputs)
        for task_id in TASK_WINDOW_IDS
    }
    candidate_coverage = {
        task_id: _candidate_tactic_coverage_for_task(task_id, gt_windows, full_outputs, no_outputs)
        for task_id in TASK_WINDOW_IDS
    }

    (output_dir / "tactic_diff_by_task.json").write_text(
        json.dumps(tactic_diff, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_dir / "technique_diff_by_task.json").write_text(
        json.dumps(technique_diff, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_dir / "candidate_tactic_coverage_by_task.json").write_text(
        json.dumps(candidate_coverage, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_dir / "prior_effect_summary.md").write_text(
        _build_summary_markdown(
            full_metrics=full_metrics,
            no_metrics=no_metrics,
            tactic_diff=tactic_diff,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

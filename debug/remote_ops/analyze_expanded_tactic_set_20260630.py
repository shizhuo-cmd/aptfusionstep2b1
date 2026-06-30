from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _sorted_unique(values: list[str]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def analyze(
    *,
    gt_json_path: Path,
    tactic_comparison_path: Path,
    output_dir: Path,
    host: str | None = None,
) -> dict[str, Any]:
    gt_payload = _load_json(gt_json_path)
    tactic_rows = _load_json(tactic_comparison_path)
    host_upper = str(host or "").strip().upper()

    gt_by_window: dict[str, dict[str, Any]] = {}
    for window in gt_payload.get("windows", []) or []:
        if not isinstance(window, dict):
            continue
        if host_upper and str(window.get("host", "")).strip().upper() != host_upper:
            continue
        gt_by_window[str(window.get("window_id", "")).strip()] = window

    rows_out: list[dict[str, Any]] = []
    recall_values: list[float] = []
    precision_values: list[float] = []
    relieved_extra_total = 0
    raw_extra_total = 0

    for row in tactic_rows:
        if not isinstance(row, dict):
            continue
        window_id = str(row.get("window_id", "")).strip()
        gt = gt_by_window.get(window_id, {})
        confirmed_tactics = _sorted_unique(list(gt.get("confirmed_tactics", []) or []))
        attempted_tactics = _sorted_unique(list(gt.get("attempted_tactics", []) or []))
        expanded_tactics = _sorted_unique(confirmed_tactics + attempted_tactics)
        predicted_tactics = _sorted_unique(list(row.get("predicted_tactics_union_top_n", []) or []))

        matched_confirmed = [item for item in predicted_tactics if item in confirmed_tactics]
        matched_expanded = [item for item in predicted_tactics if item in expanded_tactics]
        extra_vs_confirmed = [item for item in predicted_tactics if item not in confirmed_tactics]
        extra_vs_expanded = [item for item in predicted_tactics if item not in expanded_tactics]
        relieved_extras = [item for item in extra_vs_confirmed if item in expanded_tactics]

        raw_extra_total += len(extra_vs_confirmed)
        relieved_extra_total += len(relieved_extras)

        expanded_recall = len(matched_expanded) / max(1, len(expanded_tactics))
        expanded_precision = len(matched_expanded) / max(1, len(predicted_tactics))
        recall_values.append(expanded_recall)
        precision_values.append(expanded_precision)

        rows_out.append(
            {
                "window_id": window_id,
                "host": gt.get("host", row.get("host", "")),
                "status": gt.get("status", ""),
                "confirmed_tactics": confirmed_tactics,
                "attempted_tactics": attempted_tactics,
                "expanded_tactics": expanded_tactics,
                "predicted_tactics_union_top_n": predicted_tactics,
                "matched_confirmed_tactics": matched_confirmed,
                "matched_expanded_tactics": matched_expanded,
                "missed_confirmed_tactics": [item for item in confirmed_tactics if item not in matched_confirmed],
                "missed_expanded_tactics": [item for item in expanded_tactics if item not in matched_expanded],
                "extra_vs_confirmed": extra_vs_confirmed,
                "extra_vs_expanded": extra_vs_expanded,
                "relieved_extras_from_attempted": relieved_extras,
                "expanded_tactic_recall": expanded_recall,
                "expanded_tactic_precision": expanded_precision,
            }
        )

    summary = {
        "host": host_upper,
        "window_count": len(rows_out),
        "expanded_tactic_recall_macro": _mean(recall_values),
        "expanded_tactic_precision_macro": _mean(precision_values),
        "raw_extra_tactic_count_vs_confirmed": raw_extra_total,
        "relieved_extra_tactic_count_by_expanded_set": relieved_extra_total,
    }

    _save_json(output_dir / "expanded_tactic_set_summary.json", summary)
    _save_json(output_dir / "expanded_tactic_set_by_window.json", rows_out)
    return {
        "summary_path": str(output_dir / "expanded_tactic_set_summary.json"),
        "detail_path": str(output_dir / "expanded_tactic_set_by_window.json"),
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze an expanded tactic set (confirmed U attempted).")
    parser.add_argument("--gt-json-path", required=True)
    parser.add_argument("--tactic-comparison-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--host", default="")
    return parser


def main() -> None:
    args = _build_arg_parser().parse_args()
    outputs = analyze(
        gt_json_path=Path(args.gt_json_path),
        tactic_comparison_path=Path(args.tactic_comparison_path),
        output_dir=Path(args.output_dir),
        host=args.host,
    )
    print(json.dumps(outputs, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

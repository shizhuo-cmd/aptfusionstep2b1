from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TARGET_TASKS = {
    "task_0345": ["initial_or_drop_exec", "callback_c2", "scan_discovery", "cleanup_delete"],
    "task_0546": ["short_lived_precursor", "mail_browser_context_tail"],
    "task_0557": ["attachment_or_tcexec_exec", "callback_c2", "scan_discovery"],
    "task_0558": ["attachment_or_tcexec_exec", "callback_c2", "scan_discovery"],
}

PRECURSOR_MARKERS = ("tcexec", "command-not-found", "/dev/pts/3", "python3", "chmod", "bash")
ATTACHMENT_MARKERS = ("attachment", "tcexec", "pine", "mail", "rimapd")
MAIL_BROWSER_MARKERS = ("firefox", "thunderbird", "pine", "mail", "browser")
TEMP_MARKERS = ("/tmp/", "/var/tmp/", "/dev/shm/", "ztmp")
DELETE_EVENT_TYPES = {"DELETE", "UNLINK", "RENAME"}
NETWORK_EVENT_TYPES = {"CONNECT", "SEND", "RECV"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _normalize_text(*values: Any) -> str:
    return " ".join(str(value or "").strip() for value in values if str(value or "").strip()).lower()


def _event_text(event: dict[str, Any]) -> str:
    return _normalize_text(
        event.get("description"),
        event.get("object_key"),
        event.get("object_class"),
        event.get("process_name"),
        event.get("process_exe"),
        event.get("process_cmdline"),
    )


def _event_labels(event: dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for key in ("path_labels_triggered", "labels_triggered"):
        for value in event.get(key, []) or []:
            text = str(value).strip()
            if text:
                labels.add(text)
    return labels


def _line_candidate_families(line: str, expected_families: set[str]) -> set[str]:
    families: set[str] = set()
    if "attachment_or_tcexec_exec" in expected_families and any(marker in line for marker in ATTACHMENT_MARKERS):
        families.add("attachment_or_tcexec_exec")
    if "short_lived_precursor" in expected_families and any(marker in line for marker in PRECURSOR_MARKERS):
        families.add("short_lived_precursor")
    if "mail_browser_context_tail" in expected_families and any(marker in line for marker in MAIL_BROWSER_MARKERS):
        families.add("mail_browser_context_tail")
    if "initial_or_drop_exec" in expected_families and (
        any(marker in line for marker in TEMP_MARKERS)
        or any(label in line for label in ("b_exec_temp", "b_exec_downloaded", "b_exec_uploaded", "b_exec_suspect_written"))
    ):
        families.add("initial_or_drop_exec")
    if "callback_c2" in expected_families and (
        "external_ip" in line or "b_external_send" in line or "b_external_recv" in line
    ):
        families.add("callback_c2")
    if "scan_discovery" in expected_families and (
        "internal_ip" in line or "b_lateral_connect" in line
    ):
        families.add("scan_discovery")
    if "cleanup_delete" in expected_families and (
        ("delete" in line or "unlink" in line or "rename" in line or "b_delete_log" in line)
        and (any(marker in line for marker in TEMP_MARKERS) or '"log"' in line or "b_delete_log" in line)
    ):
        families.add("cleanup_delete")
    return families


def _family_hits_from_jsonl(path: Path, expected_families: list[str]) -> dict[str, dict[str, Any]]:
    hits: dict[str, dict[str, Any]] = {}
    remaining = set(expected_families)

    def note(family: str, event: dict[str, Any]) -> None:
        event_id = str(event.get("event_id", "")).strip()
        object_key = str(event.get("object_key", "")).strip()
        process_name = str(event.get("process_name", "")).strip()
        row = hits.setdefault(
            family,
            {
                "event_ids": [],
                "object_keys": [],
                "process_names": [],
            },
        )
        if event_id and event_id not in row["event_ids"] and len(row["event_ids"]) < 12:
            row["event_ids"].append(event_id)
        if object_key and object_key not in row["object_keys"] and len(row["object_keys"]) < 12:
            row["object_keys"].append(object_key)
        if process_name and process_name not in row["process_names"] and len(row["process_names"]) < 12:
            row["process_names"].append(process_name)
        remaining.discard(family)

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            text = str(raw_line).strip()
            if not text:
                continue
            lowered = text.lower()
            matched = _line_candidate_families(lowered, remaining or set(expected_families))
            if not matched:
                continue
            event = json.loads(text)
            for family in matched:
                note(family, event)
            if not remaining:
                break
    return hits


def _task_rows_by_id(task_index_path: Path) -> dict[str, dict[str, Any]]:
    payload = _load_json(task_index_path)
    if not isinstance(payload, list):
        return {}
    return {
        str(item.get("task_id", "")).strip(): item
        for item in payload
        if isinstance(item, dict) and str(item.get("task_id", "")).strip()
    }


def _load_predicted_families(candidate_paths_path: Path) -> dict[str, Any]:
    if not candidate_paths_path.exists():
        return {"predicted_families": [], "top_paths": []}
    with candidate_paths_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        return {"predicted_families": [], "top_paths": []}
    families: list[str] = []
    top_paths: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        family_tags = [str(value).strip() for value in item.get("family_tags", []) if str(value).strip()]
        for family in family_tags:
            if family not in families:
                families.append(family)
        top_paths.append(
            {
                "path_id": str(item.get("path_id", "")).strip(),
                "risk_score": float(item.get("risk_score", 0.0) or 0.0),
                "family_tags": family_tags,
                "precursor_event_ids": [str(value).strip() for value in item.get("precursor_event_ids", []) if str(value).strip()],
                "followup_event_ids": [str(value).strip() for value in item.get("followup_event_ids", []) if str(value).strip()],
            }
        )
    return {"predicted_families": families, "top_paths": top_paths[:8]}


def build_truth_gap_summary(
    *,
    artifacts_dir: Path,
    source_logs: Path,
    gt_json_path: Path,
    alignment_md_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    task_index_path = artifacts_dir / "module4_compact" / "task_index.json"
    candidate_dir = artifacts_dir / "module5_paths" / "candidate_paths"
    rows_by_task = _task_rows_by_id(task_index_path)
    raw_truth: dict[str, Any] = {
        "source_logs": str(source_logs),
        "gt_json_path": str(gt_json_path),
        "alignment_md_path": str(alignment_md_path),
        "tasks": {},
    }
    summary: dict[str, Any] = {
        "artifacts_dir": str(artifacts_dir),
        "tasks": {},
    }
    markdown_lines = ["# TRACE Truth Gap Summary", ""]
    for task_id, expected_families in TARGET_TASKS.items():
        row = rows_by_task.get(task_id, {})
        retained_events_path = Path(str(row.get("retained_events_path", "")).strip()) if row else Path("")
        family_hits = _family_hits_from_jsonl(retained_events_path, expected_families) if retained_events_path.exists() else {}
        truth_families = [family for family in expected_families if family in family_hits]
        if not truth_families:
            truth_families = list(expected_families)
        predicted = _load_predicted_families(candidate_dir / f"{task_id}.json")
        predicted_families = predicted.get("predicted_families", [])
        raw_truth["tasks"][task_id] = {
            "expected_families": list(expected_families),
            "observed_truth_families": truth_families,
            "family_hits": family_hits,
            "retained_events_path": str(retained_events_path),
        }
        missing = [family for family in truth_families if family not in predicted_families]
        extra = [family for family in predicted_families if family not in truth_families]
        summary["tasks"][task_id] = {
            "truth_families": truth_families,
            "predicted_families": predicted_families,
            "missing_families": missing,
            "extra_families": extra,
            "top_paths": predicted.get("top_paths", []),
        }
        markdown_lines.extend(
            [
                f"## {task_id}",
                "",
                f"- truth_families: `{', '.join(truth_families) or 'none'}`",
                f"- predicted_families: `{', '.join(predicted_families) or 'none'}`",
                f"- missing_families: `{', '.join(missing) or 'none'}`",
                f"- extra_families: `{', '.join(extra) or 'none'}`",
                "",
            ]
        )
    return raw_truth, summary, "\n".join(markdown_lines).strip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze TRACE truth-gap families for target tasks.")
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--source-logs", required=True)
    parser.add_argument("--gt-json-path", required=True)
    parser.add_argument("--alignment-md-path", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    output_dir = Path(args.output_dir)
    _ensure_dir(output_dir)
    raw_truth, summary, markdown = build_truth_gap_summary(
        artifacts_dir=artifacts_dir,
        source_logs=Path(args.source_logs),
        gt_json_path=Path(args.gt_json_path),
        alignment_md_path=Path(args.alignment_md_path),
    )
    raw_truth_path = output_dir / "raw_log_chain_truth.json"
    summary_path = output_dir / "task_truth_gap_summary.json"
    markdown_path = output_dir / "per_task_truth_gap.md"
    raw_truth_path.write_text(json.dumps(raw_truth, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(markdown, encoding="utf-8")
    print(
        json.dumps(
            {
                "raw_log_chain_truth": str(raw_truth_path),
                "task_truth_gap_summary": str(summary_path),
                "per_task_truth_gap": str(markdown_path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

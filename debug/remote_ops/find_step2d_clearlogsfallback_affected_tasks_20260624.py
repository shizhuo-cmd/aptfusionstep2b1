from __future__ import annotations

import argparse
import json
from pathlib import Path

from apt_fusion.path_reason.holmes_claims import build_holmes_claim_graph
from apt_fusion.path_reason.module6_attack_reason import _slugify


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-root", required=True)
    parser.add_argument("--output-path", required=True)
    args = parser.parse_args()

    root = Path(args.artifacts_root)
    candidate_dir = root / "module5_paths" / "candidate_paths"
    reports_dir = root / "module6_reason" / "reports"

    affected: list[dict[str, object]] = []
    per_task: dict[str, dict[str, object]] = {}

    for candidate_file in sorted(candidate_dir.glob("*.json")):
        payload = _load_json(candidate_file)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            dossier = item.get("dossier", {})
            if not isinstance(dossier, dict):
                continue
            task_id = str(dossier.get("task_id", "")).strip()
            path_id = str(dossier.get("path_id", "")).strip()
            if not task_id or not path_id:
                continue
            slug = _slugify(path_id)
            report_path = reports_dir / f"{slug}.report.json"
            if not report_path.exists():
                continue
            report = _load_json(report_path)
            old_behavior_types = {
                str(claim.get("behavior_type", "")).strip()
                for claim in report.get("claims", [])
                if isinstance(claim, dict) and str(claim.get("behavior_type", "")).strip()
            }
            new_behavior_types = {
                str(claim.get("behavior_type", "")).strip()
                for claim in build_holmes_claim_graph(dossier).get("claims", [])
                if isinstance(claim, dict) and str(claim.get("behavior_type", "")).strip()
            }
            if "clear_logs" in new_behavior_types and "clear_logs" not in old_behavior_types:
                family_tags = [str(tag) for tag in dossier.get("family_tags", []) if str(tag).strip()]
                record = {
                    "task_id": task_id,
                    "path_id": path_id,
                    "candidate_file": str(candidate_file),
                    "report_path": str(report_path),
                    "family_tags": family_tags,
                    "followup_event_count": len([x for x in dossier.get("followup_event_ids", []) if str(x).strip()]),
                    "cleanup_object_summary": str(dossier.get("cleanup_object_summary", "")).strip(),
                    "object_lineage_summary": str(dossier.get("object_lineage_summary", "")).strip(),
                }
                affected.append(record)
                task_bucket = per_task.setdefault(
                    task_id,
                    {"task_id": task_id, "candidate_file": str(candidate_file), "path_ids": []},
                )
                task_bucket["path_ids"].append(path_id)

    output = {
        "artifacts_root": str(root),
        "affected_path_count": len(affected),
        "affected_task_count": len(per_task),
        "affected_tasks": list(per_task.values()),
        "affected_paths": affected,
    }
    output_path = Path(args.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

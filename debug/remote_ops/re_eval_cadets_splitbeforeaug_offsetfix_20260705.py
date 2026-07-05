from __future__ import annotations

import json
import sys
from pathlib import Path

repo_root = Path("/root/autodl-tmp/APT-Fusionstep2b1")
sys.path.insert(0, str(repo_root / "src"))

from apt_fusion.evaluation.path_reason_eval import (  # noqa: E402
    apply_gt_time_offset,
    load_gt_reference,
    run_evaluation,
)


GT_JSON_PATH = repo_root / "docs" / "darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json"
GT_TIME_OFFSET_MINUTES = 240
MATCH_TOP_N = 5
PAD_MINUTES = 5
NEAR_MISS_MINUTES = 5
HOST = "CADETS"
RUN_TAGS = [
    "cadets_splitbeforeaug_aug2_seed173_run1_20260705",
    "cadets_splitbeforeaug_aug2_seed271_run2_20260705",
    "cadets_splitbeforeaug_aug2_seed509_run3_20260705",
]
EVAL_DIR_NAME = "path_reason_eval_e3gt_plus240_offsetfix"


def main() -> int:
    out_dir = repo_root / "debug" / "remote_ops" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "cadets_splitbeforeaug_offsetfix_20260705_summary.json"
    rows: list[dict[str, object]] = []

    for run_tag in RUN_TAGS:
        artifacts_dir = repo_root / f"artifacts_{run_tag}"
        strict_windows, technique_defs, _ = load_gt_reference(GT_JSON_PATH, host_filter=HOST)
        apply_gt_time_offset(strict_windows, minutes=GT_TIME_OFFSET_MINUTES)
        output_dir = artifacts_dir / EVAL_DIR_NAME
        eval_outputs = run_evaluation(
            artifacts_dir=artifacts_dir,
            strict_windows=strict_windows,
            technique_defs=technique_defs,
            output_dir=output_dir,
            host=HOST,
            match_top_n=MATCH_TOP_N,
            pad_minutes=PAD_MINUTES,
            near_miss_minutes=NEAR_MISS_MINUTES,
        )
        metrics = json.loads((output_dir / "metrics_summary.json").read_text(encoding="utf-8"))
        rows.append(
            {
                "run_tag": run_tag,
                "artifacts_dir": str(artifacts_dir),
                "gt_json_path": str(GT_JSON_PATH),
                "gt_time_offset_minutes_applied": GT_TIME_OFFSET_MINUTES,
                "eval_dir_name": EVAL_DIR_NAME,
                "metrics": metrics,
                "eval_outputs": eval_outputs,
            }
        )
        summary_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[offsetfix] done {run_tag}", flush=True)

    print("all_runs_finished", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

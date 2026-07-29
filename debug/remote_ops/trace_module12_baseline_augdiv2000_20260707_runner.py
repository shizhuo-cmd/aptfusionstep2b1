from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

_THIS_FILE = Path(__file__).resolve()
REPO_ROOT = _THIS_FILE.parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from debug.remote_ops.tc3_module12_ablation_matrix_20260707_runner import (  # type: ignore
    _artifact_name,
    _ensure_logs_for_host,
    _mark_failed,
    _run_one_experiment,
    _working_tree_fingerprint,
)


CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_module12_baseline_augdiv2000_20260707.yaml"
)
OUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "trace_module12_baseline_augdiv2000_20260707"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fingerprint = _working_tree_fingerprint()
    log_state = _ensure_logs_for_host("trace")
    tag = "baseline_augdiv2000"
    artifact_name = _artifact_name("trace", tag)
    root = REPO_ROOT / artifact_name
    if OUT_DIR.exists():
        for child in OUT_DIR.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        result = _run_one_experiment(
            base_config_path=CONFIG_PATH,
            artifact_name=artifact_name,
            item_id="single",
            experiment_name="trace_baseline_augdiv2000",
            description="TRACE baseline rerun with module1+module2 only; augmentation divisor changed to count//2000.",
            overrides={},
            log_state=log_state,
            fingerprint=fingerprint,
        )
        (OUT_DIR / "trace_baseline_augdiv2000.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (OUT_DIR / "summary.json").write_text(
            json.dumps(
                {
                    "status": "completed",
                    "artifact_root": result["artifact_root"],
                    "result_path": str(OUT_DIR / "trace_baseline_augdiv2000.json"),
                    "working_tree_fingerprint": fingerprint,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        failed_root = _mark_failed(root)
        failure = {
            "status": "failed",
            "artifact_root_failed": str(failed_root),
            "error": repr(exc),
            "working_tree_fingerprint": fingerprint,
        }
        (OUT_DIR / "trace_baseline_augdiv2000_failed.json").write_text(
            json.dumps(failure, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (OUT_DIR / "summary.json").write_text(
            json.dumps(failure, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(failure, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

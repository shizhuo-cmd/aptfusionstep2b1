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
    _ensure_cadets_logs_ready,
    _ensure_trace_logs_ready,
    _mark_failed,
    _run_one_experiment,
    _working_tree_fingerprint,
)
from scripts.train_tc3_stackedlstm_pretrain_20260707 import run_pretraining  # type: ignore


DATE_TAG = "20260707"
CONFIG_PATH = (
    REPO_ROOT
    / "configs"
    / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_module12_baseline_augdiv2000_20260707.yaml"
)
OUT_DIR = REPO_ROOT / "debug" / "remote_ops" / "out" / "tc3_lstm_retrain_trace_cadets_then_trace_baseline_augdiv2000_20260707"
TRAINING_DIR = OUT_DIR / "training"
SUMMARY_PATH = OUT_DIR / "summary.json"
VENDOR_MODEL_PATH = REPO_ROOT / "vendor" / "tapas" / "model" / "stackedlstm_tc.pt"


def main() -> int:
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR, ignore_errors=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    fingerprint = _working_tree_fingerprint()
    trace_log_state = _ensure_trace_logs_ready()
    cadets_log_state = _ensure_cadets_logs_ready()

    artifact_name = _artifact_name("trace", "baseline_augdiv2000_lstmretrain_tracecadets")
    target_root = REPO_ROOT / artifact_name
    backup_model_path = VENDOR_MODEL_PATH.with_name(f"stackedlstm_tc_before_lstmretrain_{DATE_TAG}.pt")

    try:
        training_summary = run_pretraining(
            trace_logs=Path(trace_log_state["trace_logs_dir"]),
            cadets_logs=Path(cadets_log_state["cadets_logs_dir"]),
            output_dir=TRAINING_DIR,
            epochs=8,
            batch_size=256,
            lr=1e-3,
            weight_decay=1e-4,
            max_seq_len=128,
            val_fraction=0.1,
            max_trace_sequences=None,
            max_cadets_sequences=50000,
            seed=173,
        )

        trained_model_path = Path(training_summary["best_model_path"])
        shutil.copy2(VENDOR_MODEL_PATH, backup_model_path)
        shutil.copy2(trained_model_path, VENDOR_MODEL_PATH)
        try:
            experiment_summary = _run_one_experiment(
                base_config_path=CONFIG_PATH,
                artifact_name=artifact_name,
                item_id="single",
                experiment_name="trace_baseline_augdiv2000_after_tc3_lstm_retrain",
                description=(
                    "TRACE baseline module1+module2 rerun after retraining the shared TC3 stacked LSTM-GRU "
                    "encoder on TRACE and CADETS self-supervised next-step prediction."
                ),
                overrides={},
                log_state={
                    "trace": trace_log_state,
                    "cadets": cadets_log_state,
                },
                fingerprint=fingerprint,
            )
        finally:
            if backup_model_path.exists():
                shutil.copy2(backup_model_path, VENDOR_MODEL_PATH)

        summary = {
            "status": "completed",
            "training_summary_path": str(TRAINING_DIR / "training_summary.json"),
            "trained_model_path": str(trained_model_path),
            "backup_model_path": str(backup_model_path),
            "trace_result": experiment_summary,
            "working_tree_fingerprint": fingerprint,
        }
        SUMMARY_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        failed_root = _mark_failed(target_root)
        failure = {
            "status": "failed",
            "error": repr(exc),
            "artifact_root_failed": str(failed_root),
            "working_tree_fingerprint": fingerprint,
        }
        SUMMARY_PATH.write_text(json.dumps(failure, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(failure, ensure_ascii=False, indent=2))
        return 1
    finally:
        if backup_model_path.exists():
            backup_model_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())

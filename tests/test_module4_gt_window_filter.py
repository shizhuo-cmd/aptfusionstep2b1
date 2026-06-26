from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from apt_fusion.path_reason.module4_semantic_compact import _filter_task_index_by_gt_windows


def _make_cfg(
    gt_path: Path,
    *,
    mode: str = "confirmed_only",
    pad_minutes: int = 0,
    offset_minutes: int = 0,
    host: str = "theia",
) -> SimpleNamespace:
    return SimpleNamespace(
        host=host,
        attack_eval_gt_json_path=gt_path,
        path_reason_gt_window_filter_mode=mode,
        path_reason_gt_window_filter_pad_minutes=pad_minutes,
        path_reason_gt_time_offset_minutes=offset_minutes,
    )


def test_gt_window_filter_none_keeps_all(tmp_path: Path) -> None:
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(json.dumps({"windows": []}), encoding="utf-8")
    cfg = _make_cfg(gt_path, mode="none")
    task_index = [
        {"task_id": "task_1", "first_timestamp": "2026-01-01T10:00:00", "last_timestamp": "2026-01-01T10:10:00"},
        {"task_id": "task_2", "first_timestamp": "2026-01-01T11:00:00", "last_timestamp": "2026-01-01T11:05:00"},
    ]

    filtered, meta = _filter_task_index_by_gt_windows(cfg, task_index)

    assert [row["task_id"] for row in filtered] == ["task_1", "task_2"]
    assert meta["kept_task_count"] == 2
    assert meta["filtered_out_task_count"] == 0


def test_gt_window_filter_confirmed_only_respects_offset_and_pad(tmp_path: Path) -> None:
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(
        json.dumps(
            {
                "windows": [
                    {
                        "window_id": "THEIA_1",
                        "host": "THEIA",
                        "status": "confirmed",
                        "start_time": "2026-01-01T10:00:00",
                        "end_time": "2026-01-01T10:10:00",
                    },
                    {
                        "window_id": "THEIA_ATTEMPT",
                        "host": "THEIA",
                        "status": "attempted_failed",
                        "start_time": "2026-01-01T14:00:00",
                        "end_time": "2026-01-01T14:10:00",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    cfg = _make_cfg(gt_path, pad_minutes=5, offset_minutes=240)
    task_index = [
        {
            "task_id": "task_keep_overlap",
            "first_timestamp": "2026-01-01T14:09:00",
            "last_timestamp": "2026-01-01T14:12:00",
        },
        {
            "task_id": "task_drop_attempt_only",
            "first_timestamp": "2026-01-01T14:16:00",
            "last_timestamp": "2026-01-01T14:17:00",
        },
        {
            "task_id": "task_drop_missing_time",
            "first_timestamp": "",
            "last_timestamp": "2026-01-01T14:04:00",
        },
    ]

    filtered, meta = _filter_task_index_by_gt_windows(cfg, task_index)

    assert [row["task_id"] for row in filtered] == ["task_keep_overlap"]
    assert filtered[0]["gt_overlap_window_ids"] == ["THEIA_1"]
    assert meta["window_overlap_counts"] == {"THEIA_1": 1}
    assert meta["filtered_out_reasons"]["task_drop_attempt_only"] == "no_confirmed_window_overlap"
    assert meta["filtered_out_reasons"]["task_drop_missing_time"] == "missing_task_time_range"

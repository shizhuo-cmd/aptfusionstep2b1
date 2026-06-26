from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

from apt_fusion.task_detection.tapas_native_backend import _apply_theia_temporal_split


def test_theia_temporal_split_breaks_apart_wide_root_component() -> None:
    edge_list = {
        "edge_list": [
            ["B", "A"],
            ["D", "B"],
            ["C", "A"],
            ["E", "C"],
            ["F", "C"],
        ],
        "task_components": [
            {
                "task_root": "A",
                "nodes": ["A", "B", "C", "D", "E", "F"],
                "edges": [
                    ["B", "A"],
                    ["D", "B"],
                    ["C", "A"],
                    ["E", "C"],
                    ["F", "C"],
                ],
                "boundary_nodes": [],
            }
        ],
        "task_component_diagnostics": [],
        "subject_time_ranges": {
            "A": {"first_timestamp_sec": 0.0, "last_timestamp_sec": 7200.0, "event_count": 10},
            "B": {"first_timestamp_sec": 0.0, "last_timestamp_sec": 60.0, "event_count": 2},
            "D": {"first_timestamp_sec": 120.0, "last_timestamp_sec": 240.0, "event_count": 3},
            "C": {"first_timestamp_sec": 4200.0, "last_timestamp_sec": 4260.0, "event_count": 2},
            "E": {"first_timestamp_sec": 4320.0, "last_timestamp_sec": 4380.0, "event_count": 3},
            "F": {"first_timestamp_sec": 4440.0, "last_timestamp_sec": 4500.0, "event_count": 3},
        },
        "child_threshold": 2,
        "split_mode": "fanout",
        "count_segmented_children_upstream": False,
    }

    updated = _apply_theia_temporal_split(
        edge_list,
        max_span_minutes=45,
        branch_gap_minutes=10,
    )

    components = updated["task_components"]
    assert len(components) == 2
    assert updated["theia_temporal_split_summary"]["split_component_count"] == 1
    assert all(component.get("temporal_split_applied") for component in components)
    assert {component["task_root"] for component in components} == {"B", "C"}
    assert all("A" not in component["nodes"] for component in components)

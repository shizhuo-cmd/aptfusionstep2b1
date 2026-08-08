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

from apt_fusion.task_detection.tapas_native_backend import (
    _apply_temporal_episode_split,
)


def test_temporal_episode_split_uses_direct_child_start_and_merges_small_groups() -> None:
    edge_list = {
        "task_components": [
            {
                "task_root": "R",
                "nodes": ["R", "A", "A1", "B", "C", "D", "E", "F"],
                "edges": [
                    ["R", "A"], ["A", "A1"], ["R", "B"], ["R", "C"],
                    ["R", "D"], ["R", "E"], ["R", "F"],
                ],
                "boundary_nodes": [],
            }
        ],
        "task_component_diagnostics": [{"task_root": "R", "task_root_parent_missing": False}],
        "subject_time_ranges": {
            "A": {"first_timestamp_sec": 0.0, "last_timestamp_sec": 9999.0},
            "B": {"first_timestamp_sec": 10.0, "last_timestamp_sec": 20.0},
            "C": {"first_timestamp_sec": 20.0, "last_timestamp_sec": 30.0},
            "D": {"first_timestamp_sec": 1000.0, "last_timestamp_sec": 1010.0},
            "E": {"first_timestamp_sec": 1010.0, "last_timestamp_sec": 1020.0},
            "F": {"first_timestamp_sec": 1020.0, "last_timestamp_sec": 1030.0},
            "A1": {"first_timestamp_sec": 5000.0, "last_timestamp_sec": 9999.0},
        },
        "child_threshold": 2,
        "split_mode": "fanout",
        "count_segmented_children_upstream": False,
    }

    updated = _apply_temporal_episode_split(
        edge_list,
        parent_missing_only=False,
        min_task_nodes=2,
        min_direct_children=2,
        min_span_minutes=1,
        gap_mode="fixed",
        fixed_gap_minutes=5,
        gap_quantile=0.9,
        mad_multiplier=3.0,
        min_children_per_episode=3,
        max_episodes=4,
        budget_strategy="adjacent_greedy",
    )

    components = updated["task_components"]
    assert len(components) == 2
    assert all(component["task_root"] == "R" for component in components)
    assert all("R" in component["nodes"] for component in components)
    assert all(component["temporal_episode_split_applied"] for component in components)
    assert components[0]["temporal_episode_child_roots"] == ["A", "B", "C"]
    assert components[1]["temporal_episode_child_roots"] == ["D", "E", "F"]
    assert updated["temporal_episode_split_summary"]["split_component_count"] == 1


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

from apt_fusion.task_detection.tapas_native_backend import _apply_root_temporal_split


def test_root_temporal_split_keeps_parent_to_child_edges_and_shared_root() -> None:
    edge_list = {
        "edge_list": [["R", "A"], ["A", "A1"], ["R", "B"], ["B", "B1"], ["R", "C"], ["C", "C1"]],
        "task_components": [
            {
                "task_root": "R",
                "nodes": ["R", "A", "A1", "B", "B1", "C", "C1"],
                "edges": [["R", "A"], ["A", "A1"], ["R", "B"], ["B", "B1"], ["R", "C"], ["C", "C1"]],
                "boundary_nodes": [],
            }
        ],
        "task_component_diagnostics": [{"task_root": "R", "task_root_parent_missing": True}],
        "subject_time_ranges": {
            "A": {"first_timestamp_sec": 0.0, "last_timestamp_sec": 30.0},
            "A1": {"first_timestamp_sec": 40.0, "last_timestamp_sec": 60.0},
            "B": {"first_timestamp_sec": 100.0, "last_timestamp_sec": 130.0},
            "B1": {"first_timestamp_sec": 140.0, "last_timestamp_sec": 160.0},
            "C": {"first_timestamp_sec": 900.0, "last_timestamp_sec": 930.0},
            "C1": {"first_timestamp_sec": 940.0, "last_timestamp_sec": 960.0},
        },
        "child_threshold": 2,
        "split_mode": "fanout",
        "count_segmented_children_upstream": False,
    }

    updated = _apply_root_temporal_split(
        edge_list,
        min_task_nodes=2,
        min_direct_children=2,
        max_span_minutes=5,
        branch_gap_minutes=5,
        session_max_minutes=0,
    )

    components = updated["task_components"]
    assert len(components) == 2
    assert updated["root_temporal_split_summary"]["split_component_count"] == 1
    assert all(component["task_root"] == "R" for component in components)
    assert all("R" in component["nodes"] for component in components)
    assert all(component["root_temporal_split_applied"] for component in components)
    assert all(
        parent in component["nodes"] and child in component["nodes"]
        for component in components
        for parent, child in component["edges"]
    )
    assert any(["R", "A"] in component["edges"] for component in components)
    assert any(["R", "C"] in component["edges"] for component in components)


def test_root_temporal_split_bounds_the_number_of_sessions_without_reordering() -> None:
    edge_list = {
        "task_components": [
            {
                "task_root": "R",
                "nodes": ["R", "A", "B", "C", "D", "E"],
                "edges": [["R", "A"], ["R", "B"], ["R", "C"], ["R", "D"], ["R", "E"]],
            }
        ],
        "task_component_diagnostics": [{"task_root": "R", "task_root_parent_missing": True}],
        "subject_time_ranges": {
            node: {"first_timestamp_sec": float(index * 600), "last_timestamp_sec": float(index * 600 + 30)}
            for index, node in enumerate(["A", "B", "C", "D", "E"])
        },
    }
    updated = _apply_root_temporal_split(
        edge_list,
        min_task_nodes=2,
        min_direct_children=2,
        max_span_minutes=5,
        branch_gap_minutes=5,
        session_max_minutes=0,
        max_sessions=2,
    )
    components = updated["task_components"]
    assert len(components) == 2
    assert components[0]["root_temporal_child_roots"] == ["A", "B", "C"]
    assert components[1]["root_temporal_child_roots"] == ["D", "E"]


def test_root_temporal_split_does_not_split_a_non_root_component() -> None:
    edge_list = {
        "task_components": [{"task_root": "R", "nodes": ["R", "A", "B"], "edges": [["R", "A"], ["R", "B"]]}],
        "task_component_diagnostics": [{"task_root": "R", "task_root_parent_missing": False}],
        "subject_time_ranges": {
            "A": {"first_timestamp_sec": 0.0, "last_timestamp_sec": 0.0},
            "B": {"first_timestamp_sec": 900.0, "last_timestamp_sec": 900.0},
        },
    }
    updated = _apply_root_temporal_split(
        edge_list,
        min_task_nodes=2,
        min_direct_children=2,
        max_span_minutes=5,
        branch_gap_minutes=5,
        session_max_minutes=0,
    )
    assert updated["task_components"] == edge_list["task_components"]
    assert updated["root_temporal_split_summary"]["split_component_count"] == 0

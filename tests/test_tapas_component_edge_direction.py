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
    _build_task_component_diagnostics_from_components,
    _component_children_map,
)


def test_component_children_map_uses_parent_to_child_edges() -> None:
    component = {
        "task_root": "A",
        "nodes": ["A", "B", "C", "D"],
        "edges": [["A", "B"], ["A", "C"], ["B", "D"]],
        "boundary_nodes": [],
    }

    children_map = _component_children_map(component)

    assert children_map == {
        "A": ["B", "C"],
        "B": ["D"],
    }


def test_component_diagnostics_count_root_children_from_parent_to_child_edges() -> None:
    component = {
        "task_root": "A",
        "nodes": ["A", "B", "C", "D"],
        "edges": [["A", "B"], ["A", "C"], ["B", "D"]],
        "boundary_nodes": [],
    }

    diagnostics = _build_task_component_diagnostics_from_components(
        [component],
        child_threshold=2,
        split_mode="fanout",
        count_segmented_children_upstream=False,
    )

    assert len(diagnostics) == 1
    assert diagnostics[0]["task_root_total_children"] == 2
    assert diagnostics[0]["task_root_effective_children"] == 2

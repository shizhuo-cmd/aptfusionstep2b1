from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apt_fusion.task_detection.module2_online_detection import _task_graph_sidecars, _task_root_leaf_ids


class Module2TaskGraphSidecarsTests(unittest.TestCase):
    def test_child_to_parent_edges_produce_expected_root_and_leaf_ids(self) -> None:
        process_ids = ["P0", "P1", "P2"]
        local_edges = [
            {"src": "P1", "dst": "P0"},
            {"src": "P2", "dst": "P1"},
        ]

        root_ids, leaf_ids, indegree, outdegree, _neighbors = _task_root_leaf_ids(process_ids, local_edges)

        self.assertEqual(root_ids, ["P0"])
        self.assertEqual(leaf_ids, ["P2"])
        self.assertEqual(outdegree["P0"], 0)
        self.assertEqual(indegree["P2"], 0)

    def test_task_sidecars_export_correct_root_and_leaf_flags(self) -> None:
        task_rows = [
            {
                "task_id": "task_0001",
                "task_score": 0.9,
                "task_probability": 0.9,
                "is_suspicious": True,
            }
        ]
        bundle = {
            "selected_graphs": [
                {
                    "edges": [[1, 0], [2, 1]],
                    "nodes": [[0.1], [0.2], [0.3]],
                }
            ],
            "selected_graph_metas": [
                {
                    "task_id": "task_0001",
                    "node_ids": ["P0", "P1", "P2"],
                    "task_root_id": "P0",
                    "boundary_node_ids": [],
                    "task_size": 3,
                    "internal_edge_count": 2,
                }
            ],
        }

        with patch("apt_fusion.task_detection.module2_online_detection._load_native_bundle", return_value=bundle):
            rich_rows, attribution_by_task = _task_graph_sidecars(task_rows, Path("unused"))

        self.assertEqual(len(rich_rows), 1)
        self.assertEqual(rich_rows[0]["root_process_ids"], ["P0"])
        self.assertEqual(rich_rows[0]["leaf_process_ids"], ["P2"])

        top_processes = {
            str(item["process_id"]): item
            for item in attribution_by_task["task_0001"]["top_processes"]
        }
        self.assertTrue(top_processes["P0"]["is_root"])
        self.assertFalse(top_processes["P0"]["is_leaf"])
        self.assertFalse(top_processes["P2"]["is_root"])
        self.assertTrue(top_processes["P2"]["is_leaf"])


if __name__ == "__main__":
    unittest.main()

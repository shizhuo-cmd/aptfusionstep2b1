from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apt_fusion.config import FusionConfig
from apt_fusion.path_reason.module3_evidence_recover import _prepare_module1_gt_selection_sidecars


class Module3Module1GTDirectTests(unittest.TestCase):
    def test_prepare_module1_gt_selection_sidecars_uses_positive_base_tasks_only(self) -> None:
        bundle = {
            "selected_graphs": [
                {"edges": [[1, 0], [2, 1]], "nodes": [[0.1], [0.2], [0.3]], "label": 1},
                {"edges": [[1, 0]], "nodes": [[0.4], [0.5]], "label": 0},
                {"edges": [[1, 0]], "nodes": [[0.6], [0.7]], "label": 1},
            ],
            "selected_graph_metas": [
                {
                    "task_id": "task_0001",
                    "label": 1,
                    "node_ids": ["P0", "P1", "P2"],
                    "task_root_id": "P0",
                    "boundary_node_ids": ["B1"],
                    "task_size": 3,
                    "internal_edge_count": 2,
                },
                {
                    "task_id": "task_0002",
                    "label": 0,
                    "node_ids": ["Q0", "Q1"],
                    "task_root_id": "Q0",
                    "boundary_node_ids": [],
                    "task_size": 2,
                    "internal_edge_count": 1,
                },
                {
                    "task_id": "task_0003_aug001",
                    "label": 1,
                    "node_ids": ["R0", "R1"],
                    "task_root_id": "R0",
                    "boundary_node_ids": [],
                    "task_size": 2,
                    "internal_edge_count": 1,
                },
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg = FusionConfig(
                ocr_apt_root=None,
                tapas_root=None,
                dataset_family="tc3",
                host="theia",
                source_logs=root / "logs",
                artifacts_dir=root / "artifacts",
                ocr_runtime_root=root / "runtime",
                ocr_exp_name="exp",
                ocr_model_name="model",
                ocr_inv_exp_name="inv",
                module3_task_selection_mode="module1_ground_truth_positive_base_only",
            )
            cfg.module1_dir.mkdir(parents=True, exist_ok=True)

            with patch(
                "apt_fusion.path_reason.module3_evidence_recover._load_module1_native_bundle",
                return_value=bundle,
            ):
                suspicious_path, meta_path, attribution_path = _prepare_module1_gt_selection_sidecars(cfg)

            suspicious_rows = json.loads(suspicious_path.read_text(encoding="utf-8"))
            meta_rows = json.loads(meta_path.read_text(encoding="utf-8"))
            attribution_rows = json.loads(attribution_path.read_text(encoding="utf-8"))

        self.assertEqual([row["task_id"] for row in suspicious_rows], ["task_0001"])
        self.assertEqual(suspicious_rows[0]["task_label"], 1)
        self.assertEqual(meta_rows[0]["root_process_ids"], ["P0"])
        self.assertEqual(meta_rows[0]["leaf_process_ids"], ["P2"])
        self.assertEqual(meta_rows[0]["boundary_node_ids"], ["B1"])
        self.assertEqual(attribution_rows[0]["root_process_ids"], ["P0"])
        self.assertEqual(attribution_rows[0]["leaf_process_ids"], ["P2"])


if __name__ == "__main__":
    unittest.main()

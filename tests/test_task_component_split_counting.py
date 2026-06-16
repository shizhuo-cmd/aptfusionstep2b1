from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apt_fusion.config import load_config


def _load_vendor_module():
    vendor_path = REPO_ROOT / "vendor" / "tapas" / "darpa.py"
    spec = importlib.util.spec_from_file_location("tapas_vendor_darpa_test_split_counting", vendor_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load vendor module from {vendor_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TaskComponentSplitCountingTests(unittest.TestCase):
    def test_existing_config_defaults_to_excluding_segmented_children(self) -> None:
        cfg = load_config(
            Path("D:/daima/APT-Fusionstep2b1/configs/fusion_cloud_cadets_train_stats_latefusion_llama31_taskcomponents.yaml")
        )
        self.assertFalse(cfg.task_component_count_segmented_children_upstream)

    def test_explicit_config_can_enable_counting_segmented_children(self) -> None:
        source = Path(
            "D:/daima/APT-Fusionstep2b1/configs/fusion_cloud_cadets_train_stats_latefusion_llama31_taskcomponents.yaml"
        )
        text = source.read_text(encoding="utf-8") + "\ntask_component_count_segmented_children_upstream: true\n"
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix="_split_counting.yaml",
            delete=False,
            dir="D:/daima/APT-Fusionstep2b1",
        ) as handle:
            handle.write(text)
            temp_path = Path(handle.name)
        try:
            cfg = load_config(temp_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()
        self.assertTrue(cfg.task_component_count_segmented_children_upstream)

    def test_counting_segmented_children_changes_ancestor_split_decision(self) -> None:
        vendor = _load_vendor_module()
        padict = {
            "A": ["B", "C", "D"],
            "B": ["E", "F", "G"],
        }
        chdict = {
            "A": "root",
            "B": "A",
            "C": "A",
            "D": "A",
            "E": "B",
            "F": "B",
            "G": "B",
        }
        exclude_segmented = vendor._resolve_segmented_nodes(
            padict,
            chdict,
            child_threshold=2,
            split_mode="fanout",
            count_segmented_children_upstream=False,
        )
        include_segmented = vendor._resolve_segmented_nodes(
            padict,
            chdict,
            child_threshold=2,
            split_mode="fanout",
            count_segmented_children_upstream=True,
        )
        self.assertEqual(exclude_segmented, {"B"})
        self.assertEqual(include_segmented, {"A", "B"})

if __name__ == "__main__":
    unittest.main()

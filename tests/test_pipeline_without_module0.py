from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from apt_fusion.cli import _ACTIVE_STAGES
from apt_fusion.pipeline import run_pipeline


def test_module3_stage_does_not_require_module0_or_detection_stages() -> None:
    cfg = SimpleNamespace(
        module1_dir=Path("module1"),
        module2_dir=Path("module2"),
        module3_task_selection_mode="module1_ground_truth_positive_base_only",
    )
    expected = {"normalized_events": "module3_evidence/normalized_events"}

    with patch("apt_fusion.pipeline.run_module3_evidence", return_value=expected) as module3:
        outputs = run_pipeline(cfg, "module3_evidence")

    module3.assert_called_once_with(cfg)
    assert outputs == {"module3_evidence.normalized_events": "module3_evidence/normalized_events"}


def test_module0_is_not_an_active_cli_stage() -> None:
    assert "module0" not in _ACTIVE_STAGES


def test_full_path_reason_keeps_the_module1_to_module6_handoff() -> None:
    cfg = SimpleNamespace(
        module1_dir=Path("module1"),
        module2_dir=Path("module2"),
        module3_task_selection_mode="predicted_positive",
    )
    module1_outputs = {
        "process_embeddings": Path("module1/process_embeddings.csv"),
        "task_subgraphs": Path("module1/task_subgraphs.json"),
        "process_segmentation_edges": Path("module1/process_segmentation_edges.csv"),
    }
    module2_outputs = {
        "suspicious_tasks": Path("module2/suspicious_tasks.json"),
    }

    with (
        patch("apt_fusion.pipeline.run_module1", return_value=module1_outputs) as module1,
        patch("apt_fusion.pipeline.run_module2", return_value=module2_outputs) as module2,
        patch("apt_fusion.pipeline.run_module3_evidence", return_value={"events": Path("module3/events")}) as module3,
        patch("apt_fusion.pipeline.run_module4_compact", return_value={"compact": Path("module4/compact")}) as module4,
        patch("apt_fusion.pipeline.run_module5_paths", return_value={"paths": Path("module5/paths")}) as module5,
        patch("apt_fusion.pipeline.run_module6_reason", return_value={"reason": Path("module6/reason")}) as module6,
    ):
        outputs = run_pipeline(cfg, "full_path_reason")

    module1.assert_called_once_with(cfg)
    module2.assert_called_once_with(
        cfg=cfg,
        embeddings_path=module1_outputs["process_embeddings"],
        task_path=module1_outputs["task_subgraphs"],
        segmentation_edges_path=module1_outputs["process_segmentation_edges"],
    )
    module3.assert_called_once_with(
        cfg,
        suspicious_tasks_path=module2_outputs["suspicious_tasks"],
        task_meta_rich_path=cfg.module2_dir / "task_meta_rich.json",
        task_attribution_path=cfg.module2_dir / "task_attribution.json",
    )
    module4.assert_called_once_with(cfg)
    module5.assert_called_once_with(cfg)
    module6.assert_called_once_with(cfg)
    assert "module0.process_events" not in outputs
    assert Path(outputs["module6_reason.reason"]) == Path("module6/reason")

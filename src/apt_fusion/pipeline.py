from __future__ import annotations

from pathlib import Path
from typing import Dict

from .config import FusionConfig
from .path_reason.module3_evidence_recover import run_module3_evidence
from .path_reason.module4_semantic_compact import run_module4_compact
from .path_reason.module5_path_finder import run_module5_paths
from .path_reason.module6_attack_reason import run_module6_reason
from .task_detection.module0_preprocess import run_module0
from .task_detection.module1_online_graph import run_module1
from .task_detection.module2_online_detection import run_module2

PATH_REASON_PIPELINE_MESSAGE = (
    "[path_reason] stage 'full_path_reason' uses the active route: "
    "module3_evidence -> module4_compact -> module5_paths -> module6_reason."
)


def _default_module1_paths(cfg: FusionConfig) -> Dict[str, Path]:
    return {
        "process_embeddings": cfg.module1_dir / "process_embeddings.csv",
        "task_subgraphs": cfg.module1_dir / "task_subgraphs.json",
        "process_segmentation_edges": cfg.module1_dir / "process_segmentation_edges.csv",
    }


def _default_module2_paths(cfg: FusionConfig) -> Dict[str, Path]:
    return {
        "process_scores": cfg.module2_dir / "process_scores.csv",
        "suspicious_tasks": cfg.module2_dir / "suspicious_tasks.json",
        "raised_alarms": cfg.module2_dir / "run_0_raised_alarms.csv",
    }


def run_pipeline(cfg: FusionConfig, stage: str) -> Dict[str, str]:
    stage = stage.lower()
    allowed = {
        "module0",
        "module1",
        "module2",
        "module3_evidence",
        "module4_compact",
        "module5_paths",
        "module6_reason",
        "full_path_reason",
    }
    if stage not in allowed:
        raise ValueError(f"stage must be one of {sorted(allowed)}")

    outputs: Dict[str, str] = {}
    module1_outputs = _default_module1_paths(cfg)
    module2_outputs = _default_module2_paths(cfg)
    module3_gt_direct = str(cfg.module3_task_selection_mode).strip() == "module1_ground_truth_positive_base_only"

    if stage == "full_path_reason":
        print(PATH_REASON_PIPELINE_MESSAGE)

    if stage in {"module0", "module1", "module2", "full_path_reason"}:
        out = run_module0(cfg)
        outputs.update({f"module0.{k}": str(v) for k, v in out.items()})

    if stage in {"module1", "module2", "full_path_reason"}:
        module1_outputs = run_module1(cfg)
        outputs.update({f"module1.{k}": str(v) for k, v in module1_outputs.items()})

    if stage in {"module2", "full_path_reason"} and not (stage == "full_path_reason" and module3_gt_direct):
        out = run_module2(
            cfg=cfg,
            embeddings_path=module1_outputs["process_embeddings"],
            task_path=module1_outputs["task_subgraphs"],
            segmentation_edges_path=module1_outputs["process_segmentation_edges"],
        )
        module2_outputs = out
        outputs.update({f"module2.{k}": str(v) for k, v in out.items()})

    if stage in {"module3_evidence", "module4_compact", "module5_paths", "module6_reason", "full_path_reason"}:
        if module3_gt_direct:
            out = run_module3_evidence(cfg)
        else:
            out = run_module3_evidence(
                cfg,
                suspicious_tasks_path=module2_outputs["suspicious_tasks"],
                task_meta_rich_path=cfg.module2_dir / "task_meta_rich.json",
                task_attribution_path=cfg.module2_dir / "task_attribution.json",
            )
        outputs.update({f"module3_evidence.{k}": str(v) for k, v in out.items()})

    if stage in {"module4_compact", "module5_paths", "module6_reason", "full_path_reason"}:
        out = run_module4_compact(cfg)
        outputs.update({f"module4_compact.{k}": str(v) for k, v in out.items()})

    if stage in {"module5_paths", "module6_reason", "full_path_reason"}:
        out = run_module5_paths(cfg)
        outputs.update({f"module5_paths.{k}": str(v) for k, v in out.items()})

    if stage in {"module6_reason", "full_path_reason"}:
        out = run_module6_reason(cfg)
        outputs.update({f"module6_reason.{k}": str(v) for k, v in out.items()})

    return outputs

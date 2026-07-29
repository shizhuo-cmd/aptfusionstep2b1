"""Run task-graph detection without module0 for the normal-only prototype baseline."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
sys.path.insert(0, str(REPO / "src"))

from apt_fusion.config import load_config  # noqa: E402
from apt_fusion.task_detection.module1_online_graph import run_module1  # noqa: E402
from apt_fusion.task_detection.module2_online_detection import run_module2  # noqa: E402


TRACE_MODULE1 = REPO / "artifacts_trace_train_stats_latefusion_bonus1_module12_stataug_20260706" / "module1"


def run_module2_only(config_path: Path, module1_dir: Path) -> dict:
    cfg = load_config(config_path)
    if not (module1_dir / "tapas_native_graphs.pt").exists():
        raise FileNotFoundError(f"missing reusable module1 bundle: {module1_dir}")
    return run_module2(
        cfg,
        module1_dir / "process_embeddings.csv",
        module1_dir / "task_subgraphs.json",
        module1_dir / "process_segmentation_edges.csv",
    )


def main() -> None:
    trace_config = REPO / "configs" / "fusion_cloud_trace_normal_only_multimodal_20260730.yaml"
    cadets_config = REPO / "configs" / "fusion_cloud_cadets_normal_only_multimodal_20260730.yaml"

    trace_outputs = run_module2_only(trace_config, TRACE_MODULE1)

    cadets_cfg = load_config(cadets_config)
    # Call module1 directly so the pipeline never invokes module0.
    cadets_module1 = run_module1(cadets_cfg)
    cadets_outputs = run_module2(
        cadets_cfg,
        cadets_module1["process_embeddings"],
        cadets_module1["task_subgraphs"],
        cadets_module1["process_segmentation_edges"],
    )

    print(
        json.dumps(
            {
                "trace": {key: str(value) for key, value in trace_outputs.items()},
                "cadets_module1": {key: str(value) for key, value in cadets_module1.items()},
                "cadets_module2": {key: str(value) for key, value in cadets_outputs.items()},
                "module0_called": False,
                "trace_input": "reused migrated module1 bundle because TRACE raw archive/log directory is absent",
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

"""Rebuild E5 task labels by tracing ORTHRUS File/NetFlow GT through Event subjects."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path("/root/autodl-tmp/APT-Fusionstep2b1")


def main() -> int:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from apt_fusion.common import ensure_dir, save_json
    from apt_fusion.config import load_config
    from apt_fusion.task_detection.module1_online_graph import run_module1
    from apt_fusion.task_detection.module2_online_detection import run_module2

    config_path = REPO_ROOT / "configs" / "fusion_cloud_theia_e5_module12_threadmerge_objectlinked_noaug_20260725.yaml"
    output_root = REPO_ROOT / "debug" / "remote_ops" / "out" / "theia_e5_objectlinked_module12_20260725"
    ensure_dir(output_root)
    cfg = load_config(config_path)
    save_json(output_root / "provenance.json", {
        "config_path": str(config_path),
        "stages": ["module1", "module2"],
        "module0_run": False,
        "direct_gt_entity_rule": "Subject UUID only",
        "object_gt_entity_rule": "FileObject/NetFlowObject UUID -> Event.subject -> canonical process Subject",
        "thread_merge_rule": "parent_subject_known_and_same_tgid",
        "augmentation_enabled": False,
    })
    module1 = run_module1(cfg)
    module2 = run_module2(
        cfg,
        embeddings_path=module1["process_embeddings"],
        task_path=module1["task_subgraphs"],
        segmentation_edges_path=module1["process_segmentation_edges"],
    )
    result = {
        "status": "ok",
        "module1": {key: str(value) for key, value in module1.items()},
        "module2": {key: str(value) for key, value in module2.items()},
    }
    save_json(output_root / "run_summary.json", result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from pathlib import Path
from types import SimpleNamespace

from apt_fusion.task_detection.tapas_native_backend import _run_normal_only_tc3


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        task_normal_only_train_fraction=0.60,
        task_normal_only_validation_fraction=0.20,
        task_normal_only_node_sample_limit=1000,
        task_normal_only_node_prototypes=3,
        task_normal_only_task_prototypes=3,
        task_normal_only_local_top_k=2,
        task_normal_only_global_weight=0.40,
        task_normal_only_validation_fpr=0.05,
        random_seed=173,
    )


def _graph(index: int, label: int) -> tuple[dict, dict]:
    base = float(index % 5) * 0.02
    if label:
        base += 8.0
    node_ids = [f"p{index}_root", f"p{index}_child"]
    return (
        {
            "nodes": [[base, 0.1, 0.2], [base + 0.01, 0.2, 0.3]],
            "edges": [[0, 1]],
            "label": label,
        },
        {
            "task_id": f"task_{index:04d}",
            "node_ids": node_ids,
            "task_root_id": node_ids[0],
            "task_size": 2,
            "internal_edge_count": 1,
            "first_timestamp_sec": float(index),
            "label": label,
        },
    )


def test_normal_only_detector_uses_no_positive_graph_for_fit_or_threshold(tmp_path: Path) -> None:
    pairs = [_graph(index, 0) for index in range(24)] + [_graph(100, 1), _graph(101, 1)]
    graphs = [pair[0] for pair in pairs]
    metas = [pair[1] for pair in pairs]

    rows, metrics, info = _run_normal_only_tc3(
        _config(),
        {"selected_graphs": graphs, "selected_graph_metas": metas},
        tmp_path / "normal_only.pkl",
    )

    assert info["positive_graphs_used_for_training"] == 0
    assert info["positive_graphs_used_for_threshold_selection"] == 0
    assert info["evaluation_known_attack_count"] == 2
    assert (tmp_path / "normal_only.pkl").exists()
    assert metrics["positive_count"] == 2
    assert all(row["prediction_mode"] == "normal_only_validation_threshold" for row in rows)

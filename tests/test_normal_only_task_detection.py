from pathlib import Path
from types import SimpleNamespace

from apt_fusion.task_detection.tapas_native_backend import (
    _apply_branch_object_overlap_split,
    _apply_selective_synthetic_root_isolation,
    _apply_synthetic_root_isolation,
    _run_normal_only_tc3,
)


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        task_normal_only_train_fraction=0.60,
        task_normal_only_validation_fraction=0.20,
        task_normal_only_node_sample_limit=1000,
        task_normal_only_node_feature_mode="all",
        task_normal_only_node_audit_enabled=False,
        task_normal_only_node_prototypes=3,
        task_normal_only_task_prototypes=3,
        task_normal_only_local_top_k=2,
        task_normal_only_local_top_k_mode="fixed",
        task_normal_only_local_top_k_max=16,
        task_normal_only_global_model="kmeans",
        task_normal_only_global_knn_neighbors=3,
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


def test_normal_only_detector_supports_size_aware_local_scores_and_graph_knn(tmp_path: Path) -> None:
    pairs = [_graph(index, 0) for index in range(24)] + [_graph(100, 1), _graph(101, 1)]
    graphs = [pair[0] for pair in pairs]
    metas = [pair[1] for pair in pairs]
    cfg = _config()
    cfg.task_normal_only_local_top_k_mode = "sqrt"
    cfg.task_normal_only_global_model = "knn"

    _, _, info = _run_normal_only_tc3(
        cfg,
        {"selected_graphs": graphs, "selected_graph_metas": metas},
        tmp_path / "normal_only_knn.pkl",
    )

    assert info["global_model"] == "knn"
    assert info["local_top_k_mode"] == "sqrt"


def test_normal_only_sequence_only_audit_exports_process_level_scores(tmp_path: Path) -> None:
    pairs = [_graph(index, 0) for index in range(24)] + [_graph(100, 1), _graph(101, 1)]
    graphs = [pair[0] for pair in pairs]
    metas = [pair[1] for pair in pairs]
    ground_truth = tmp_path / "ground_truth.txt"
    ground_truth.write_text("p100_root\np101_root\n", encoding="utf-8")
    cfg = _config()
    cfg.task_normal_only_node_feature_mode = "sequence_only"
    cfg.task_normal_only_node_audit_enabled = True
    cfg.task_ground_truth_path = ground_truth

    rows, _, info = _run_normal_only_tc3(
        cfg,
        {
            "selected_graphs": graphs,
            "selected_graph_metas": metas,
            "base_sequence_feature_dim": 2,
            "thread_merge_metadata": {},
        },
        tmp_path / "normal_only_sequence.pkl",
    )

    assert info["node_feature_mode"] == "sequence_only"
    assert info["node_feature_dim"] == 2
    assert info["node_audit_enabled"] is True
    assert (tmp_path / "normal_only_node_audit.json").exists()
    assert any(row["top_processes"] for row in rows)


def test_synthetic_root_isolation_emits_direct_child_tasks_without_parent_shell() -> None:
    edge_list = {
        "child_threshold": 2,
        "split_mode": "fanout",
        "count_segmented_children_upstream": False,
        "task_components": [
            {
                "task_root": "synthetic",
                "nodes": ["synthetic", "a", "a1", "b", "c"],
                "edges": [["synthetic", "a"], ["a", "a1"], ["synthetic", "b"], ["synthetic", "c"]],
                "boundary_nodes": [],
            }
        ],
        "task_component_diagnostics": [
            {"task_root": "synthetic", "task_root_parent_missing": True}
        ],
        "subject_start_timestamps": {"synthetic": 0, "a": 1, "a1": 2, "b": 3, "c": 4},
    }

    isolated = _apply_synthetic_root_isolation(
        edge_list,
        min_task_nodes=5,
        min_direct_children=3,
    )

    components = isolated["task_components"]
    assert isolated["synthetic_root_isolation_summary"]["split_component_count"] == 1
    assert {component["task_root"] for component in components} == {"a", "b", "c"}
    assert all("synthetic" in component["boundary_nodes"] for component in components)
    assert all(component["task_root"] != "synthetic" for component in components)


def test_selective_synthetic_root_isolation_preserves_normal_remainder() -> None:
    edge_list = {
        "child_threshold": 2,
        "split_mode": "fanout",
        "count_segmented_children_upstream": False,
        "task_components": [
            {
                "task_root": "synthetic",
                "nodes": ["synthetic", "attack", "attack_child", "mail", "imap"],
                "edges": [
                    ["synthetic", "attack"],
                    ["attack", "attack_child"],
                    ["synthetic", "mail"],
                    ["mail", "imap"],
                ],
                "boundary_nodes": [],
            }
        ],
        "task_component_diagnostics": [
            {"task_root": "synthetic", "task_root_parent_missing": True}
        ],
        "subject_start_timestamps": {"synthetic": 0},
        "canonical_execute_targets": {
            "attack": {"/tmp/payload": 1},
            "imap": {"/usr/local/libexec/imapd": 1},
        },
    }

    isolated = _apply_selective_synthetic_root_isolation(
        edge_list,
        min_task_nodes=5,
        min_direct_children=2,
        max_exec_target_frequency=3,
    )

    components = isolated["task_components"]
    assert isolated["synthetic_root_selective_isolation_summary"]["split_component_count"] == 1
    assert len(components) == 2
    extracted = next(item for item in components if item["task_root"] == "attack")
    remainder = next(item for item in components if item["task_root"] == "synthetic")
    assert extracted["synthetic_root_selective_isolation_role"] == "rare_execute_branch"
    assert extracted["synthetic_root_selective_isolation_targets"] == ["/tmp/payload"]
    assert "attack" not in remainder["nodes"]
    assert "mail" in remainder["nodes"]


def test_branch_object_overlap_split_keeps_only_object_connected_root_branches() -> None:
    edge_list = {
        "child_threshold": 2,
        "split_mode": "fanout",
        "count_segmented_children_upstream": False,
        "task_components": [
            {
                "task_root": "root",
                "nodes": ["root", "a", "a1", "b", "b1", "c", "c1"],
                "edges": [
                    ["root", "a"],
                    ["a", "a1"],
                    ["root", "b"],
                    ["b", "b1"],
                    ["root", "c"],
                    ["c", "c1"],
                ],
                "boundary_nodes": [],
            }
        ],
        "task_component_diagnostics": [{"task_root": "root"}],
        "canonical_subject_object_ids": {
            "a1": ["shared-file"],
            "b1": ["shared-file"],
            "c1": ["other-file"],
        },
    }

    split = _apply_branch_object_overlap_split(edge_list)

    components = split["task_components"]
    assert split["branch_object_overlap_split_summary"]["split_component_count"] == 1
    assert len(components) == 2
    assert all("root" in component["nodes"] for component in components)
    connected = next(component for component in components if "a" in component["nodes"])
    isolated = next(component for component in components if "c" in component["nodes"])
    assert {"a", "a1", "b", "b1"}.issubset(connected["nodes"])
    assert "c" not in connected["nodes"]
    assert {"c", "c1"}.issubset(isolated["nodes"])
    assert isolated["branch_object_overlap_group_count"] == 2

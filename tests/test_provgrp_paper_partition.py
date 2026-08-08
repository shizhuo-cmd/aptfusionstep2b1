from __future__ import annotations

import sys
import types

import numpy as np

from apt_fusion.task_detection.provgrp_paper_partition import (
    _cluster_events,
    _execution_groups,
    apply_provgrp_paper_partition_to_edge_list,
)


def test_provgrp_is_a_no_op_when_no_root_reaches_the_threshold(tmp_path):
    edge_list = {
        "edge_list": [["root", "child-a"], ["root", "child-b"]],
        "task_components": [
            {
                "task_root": "root",
                "nodes": ["root", "child-a", "child-b"],
                "edges": [["root", "child-a"], ["root", "child-b"]],
                "boundary_nodes": ["root"],
            }
        ],
    }

    result = apply_provgrp_paper_partition_to_edge_list(
        edge_list,
        source_logs=tmp_path,
        min_direct_children=100_000,
        min_cluster_size=5,
        min_samples=2,
        max_events_per_matrix=512,
    )

    assert result["task_components"] == edge_list["task_components"]
    assert result["edge_list"] == edge_list["edge_list"]
    assert result["provgrp_paper_partition_summary"]["eligible_root_count"] == 0


def test_overlapping_batches_merge_clusters_that_share_original_events(monkeypatch):
    class FakeClusterer:
        def fit_predict(self, distances):
            if len(distances) == 2:
                return np.array([0, 0])
            return np.array([0, 0, 1, 1])

    fake_hdbscan = types.SimpleNamespace(HDBSCAN=lambda **kwargs: FakeClusterer())
    monkeypatch.setitem(sys.modules, "hdbscan", fake_hdbscan)
    events = [
        {
            "event_id": f"event-{index}",
            "timestamp_ns": index,
            "event_type": "EVENT_FORK",
            "entity_kind": "process",
            "entity_name": f"child-{index}",
            "fork_child": f"child-{index}",
        }
        for index in range(6)
    ]

    clusters = _cluster_events(
        events,
        min_cluster_size=2,
        min_samples=1,
        max_events_per_matrix=4,
        batch_overlap_events=2,
        prefix="out_",
    )

    assert sorted(len(cluster["events"]) for cluster in clusters) == [2, 2, 2]
    assert sorted(event["event_id"] for cluster in clusters for event in cluster["events"]) == [
        f"event-{index}" for index in range(6)
    ]


def test_unmatched_child_uses_first_event_time_to_join_nearest_outgoing_cluster():
    outgoing = [
        {
            "cluster_id": "out_0_0",
            "start_ns": 100,
            "end_ns": 110,
            "events": [{"fork_child": "child-a"}],
        },
        {
            "cluster_id": "out_0_1",
            "start_ns": 200,
            "end_ns": 210,
            "events": [],
        },
    ]

    groups = _execution_groups(
        incoming=[],
        outgoing=outgoing,
        direct_children=["child-a", "child-b", "child-c"],
        child_first_event_timestamps={"child-b": 205},
    )
    groups_by_id = {group["outgoing_cluster_id"]: group for group in groups}

    assert groups_by_id["out_0_0"]["child_roots"] == ["child-a"]
    assert groups_by_id["out_0_0"]["child_assignment_counts"] == {"fork_clone": 1}
    assert groups_by_id["out_0_1"]["child_roots"] == ["child-b"]
    assert groups_by_id["out_0_1"]["child_assignment_counts"] == {"first_event_nearest_cluster": 1}
    assert groups_by_id["unmatched_fork_clone"]["child_roots"] == ["child-c"]

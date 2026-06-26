from __future__ import annotations

import unittest
from datetime import datetime
from types import SimpleNamespace

from apt_fusion.path_reason.path_report import build_path_dossier
from apt_fusion.path_reason.path_schemas import BridgeEdge, CandidatePath


class PathReportTimelineTests(unittest.TestCase):
    def test_preserves_payload_clone_followup_for_staged_path(self) -> None:
        cfg = SimpleNamespace(reason_max_timeline_items_per_path=3, reason_max_bridge_edges_per_path=5)
        path = CandidatePath(
            path_id="task_3099_path_001",
            task_id="task_3099",
            process_chain=["p1"],
            bridge_edges=[
                BridgeEdge(
                    task_id="task_3099",
                    src_process_guid="p0",
                    dst_process_guid="p1",
                    object_key="FILE_OBJECT_BLOCK",
                    object_labels={"O_SUSPECT_WRITTEN_EXECUTABLE"},
                    write_event_id="e1",
                    read_or_exec_event_id="e2",
                    write_time=None,
                    read_or_exec_time=None,
                    bridge_type="file_exec",
                    confidence=0.9,
                    reason="staged payload",
                )
            ],
            stage_coverage=["ExecutionStrong"],
            labels=[],
            risk_score=90.0,
            risk_level="HIGH",
            path_type="core",
            time_range=(datetime.fromisoformat("2018-04-10T18:56:20"), datetime.fromisoformat("2018-04-10T18:57:00")),
            evidence_timeline=[],
            summary="",
        )
        retained_events = [
            {
                "event_id": "e1",
                "process_guid": "p1",
                "process_name": "profile",
                "event_type": "WRITE",
                "object_key": "FILE_OBJECT_BLOCK",
                "object_class": "file",
                "description": "write staged payload",
                "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                "order_index": 1,
                "timestamp": "2018-04-10T18:56:20",
            },
            {
                "event_id": "e2",
                "process_guid": "p1",
                "process_name": "profile",
                "event_type": "EXEC",
                "object_key": "FILE_OBJECT_BLOCK",
                "object_class": "file",
                "description": "exec staged payload",
                "labels_triggered": ["B_EXEC_SUSPECT_WRITTEN"],
                "order_index": 2,
                "timestamp": "2018-04-10T18:56:39",
            },
            {
                "event_id": "e3",
                "process_guid": "p1",
                "process_name": "profile",
                "event_type": "RECV",
                "object_key": "10.0.0.5:40000->161.116.88.72:80",
                "object_class": "external_ip",
                "description": "recv callback response",
                "labels_triggered": ["B_EXTERNAL_RECV"],
                "order_index": 3,
                "timestamp": "2018-04-10T18:56:45",
            },
            {
                "event_id": "e4",
                "process_guid": "p1",
                "process_name": "profile",
                "event_type": "SEND",
                "object_key": "10.0.0.5:40000->161.116.88.72:80",
                "object_class": "external_ip",
                "description": "send callback data",
                "labels_triggered": ["B_EXTERNAL_SEND"],
                "order_index": 4,
                "timestamp": "2018-04-10T18:56:46",
            },
            {
                "event_id": "e5",
                "process_guid": "p1",
                "process_name": "profile",
                "event_type": "CLONE",
                "object_key": "/home/admin/profile",
                "object_class": "process",
                "description": "spawn follow-up payload process",
                "order_index": 5,
                "timestamp": "2018-04-10T18:56:54",
            },
        ]
        dossier = build_path_dossier(cfg, path, {}, {}, retained_events)
        timeline_ids = [str(item.get("event_id", "")).strip() for item in dossier["evidence_timeline"]]
        self.assertIn("e5", timeline_ids)

    def test_cleanup_summary_skips_placeholder_block_delete(self) -> None:
        cfg = SimpleNamespace(reason_max_timeline_items_per_path=6, reason_max_bridge_edges_per_path=5)
        path = CandidatePath(
            path_id="task_5572_path_001",
            task_id="task_5572",
            process_chain=["p1"],
            bridge_edges=[],
            stage_coverage=["ExecutionStrong"],
            labels=[],
            risk_score=50.0,
            risk_level="MEDIUM",
            path_type="core",
            time_range=(datetime.fromisoformat("2018-04-10T18:53:20"), datetime.fromisoformat("2018-04-10T18:53:40")),
            evidence_timeline=[],
            summary="",
        )
        retained_events = [
            {
                "event_id": "e1",
                "process_guid": "p1",
                "process_name": "firefox",
                "event_type": "DELETE",
                "object_key": "FILE_OBJECT_BLOCK",
                "object_class": "file",
                "description": "delete placeholder staged block",
                "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                "order_index": 1,
                "timestamp": "2018-04-10T18:53:40",
            },
        ]
        dossier = build_path_dossier(cfg, path, {}, {}, retained_events)
        self.assertEqual(dossier["cleanup_object_summary"], "")

    def test_preserves_offpath_cleanup_followup_in_timeline(self) -> None:
        cfg = SimpleNamespace(reason_max_timeline_items_per_path=3, reason_max_bridge_edges_per_path=5)
        path = CandidatePath(
            path_id="task_0345_path_001",
            task_id="task_0345",
            process_chain=["p1"],
            bridge_edges=[],
            stage_coverage=["ExecutionStrong", "FollowUp"],
            labels=[],
            risk_score=88.0,
            risk_level="HIGH",
            path_type="core",
            time_range=(datetime.fromisoformat("2018-04-13T12:43:20"), datetime.fromisoformat("2018-04-13T12:53:00")),
            evidence_timeline=[],
            summary="",
            support_event_ids=["e1", "e2", "e3"],
            followup_event_ids=["e3"],
            support_object_keys=["/tmp/ztmp"],
            family_tags=["cleanup_delete"],
        )
        retained_events = [
            {
                "event_id": "e1",
                "process_guid": "p1",
                "process_name": "payload",
                "event_type": "WRITE",
                "object_key": "/tmp/ztmp",
                "object_class": "temp_file",
                "description": "write staged payload",
                "object_labels": ["O_FILE_TEMP"],
                "order_index": 1,
                "timestamp": "2018-04-13T12:43:20",
            },
            {
                "event_id": "e2",
                "process_guid": "p1",
                "process_name": "payload",
                "event_type": "EXEC",
                "object_key": "/tmp/ztmp",
                "object_class": "temp_file",
                "description": "exec staged payload",
                "object_labels": ["O_FILE_TEMP"],
                "labels_triggered": ["B_EXEC_TEMP"],
                "order_index": 2,
                "timestamp": "2018-04-13T12:43:30",
            },
            {
                "event_id": "e3",
                "process_guid": "p2",
                "parent_process_guid": "p1",
                "process_name": "gtcache",
                "event_type": "UNLINK",
                "object_key": "/tmp/ztmp",
                "object_class": "temp_file",
                "description": "remove staged payload",
                "object_labels": ["O_FILE_TEMP"],
                "order_index": 3,
                "timestamp": "2018-04-13T12:53:00",
            },
        ]
        dossier = build_path_dossier(cfg, path, {}, {}, retained_events)
        timeline_ids = [str(item.get("event_id", "")).strip() for item in dossier["evidence_timeline"]]
        self.assertIn("e3", timeline_ids)
        self.assertIn("staged_cleanup=/tmp/ztmp", dossier["cleanup_object_summary"])


if __name__ == "__main__":
    unittest.main()

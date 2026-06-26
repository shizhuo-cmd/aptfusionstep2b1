from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from apt_fusion.path_reason.module5_path_finder import (
    _augment_candidate_support,
    _candidate_from_precursor_cluster,
    _family_tags_from_path,
    _select_family_preserved_paths,
)
from apt_fusion.path_reason.path_rules import load_path_rules
from apt_fusion.path_reason.path_schemas import CandidatePath, ProcessState


class Module5FamilyPreservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        cfg = SimpleNamespace(
            path_reason_rules_path=repo_root / "configs" / "path_reason_default.yaml",
            host="trace",
        )
        cls.rules = load_path_rules(cfg)

    def _candidate(self, path_id: str, score: float, families: list[str]) -> CandidatePath:
        return CandidatePath(
            path_id=path_id,
            task_id="task_0546",
            process_chain=[path_id],
            bridge_edges=[],
            stage_coverage=["ExecutionWeak"] if families else [],
            labels=[],
            risk_score=score,
            risk_level="LOW",
            path_type="test",
            time_range=(datetime.fromisoformat("2018-04-13T12:00:00"), datetime.fromisoformat("2018-04-13T12:01:00")),
            evidence_timeline=[],
            summary="",
            family_tags=families,
        )

    def test_select_family_preserved_paths_keeps_low_score_precursor(self) -> None:
        candidates = [
            self._candidate("high_tail", 90.0, ["mail_browser_context_tail"]),
            self._candidate("high_scan", 88.0, ["scan_discovery"]),
            self._candidate("low_precursor", 30.0, ["short_lived_precursor"]),
            self._candidate("mid_callback", 70.0, ["callback_c2"]),
        ]
        selected = _select_family_preserved_paths(candidates, limit=3)
        selected_ids = {item.path_id for item in selected}
        self.assertIn("low_precursor", selected_ids)
        self.assertIn("high_scan", selected_ids)
        self.assertIn("mid_callback", selected_ids)

    def test_select_family_preserved_paths_keeps_privilege_family_slot(self) -> None:
        candidates = [
            self._candidate("high_tail", 91.0, ["mail_browser_context_tail"]),
            self._candidate("high_scan", 89.0, ["scan_discovery"]),
            self._candidate("mid_callback", 70.0, ["callback_c2"]),
            self._candidate("low_priv", 25.0, ["privilege_escalation_followup"]),
        ]
        selected = _select_family_preserved_paths(candidates, limit=4)
        selected_ids = {item.path_id for item in selected}
        self.assertIn("low_priv", selected_ids)

    def test_precursor_cluster_builder_recovers_short_lived_branch(self) -> None:
        p1 = ProcessState(
            "task_0546",
            "p1",
            "bash",
            None,
            None,
            datetime.fromisoformat("2018-04-13T13:50:00"),
            datetime.fromisoformat("2018-04-13T13:51:00"),
            parent_process_guid="shell_parent",
        )
        p2 = ProcessState(
            "task_0546",
            "p2",
            "python3",
            None,
            None,
            datetime.fromisoformat("2018-04-13T13:51:00"),
            datetime.fromisoformat("2018-04-13T13:52:00"),
            parent_process_guid="shell_parent",
        )
        retained_events = [
            {
                "event_id": "e1",
                "process_guid": "p1",
                "process_name": "bash",
                "event_type": "EXEC",
                "object_key": "/usr/bin/command-not-found -- tcexec",
                "description": "command-not-found -- tcexec on /dev/pts/3",
                "timestamp": "2018-04-13T13:50:30",
                "order_index": 1,
            },
            {
                "event_id": "e2",
                "process_guid": "p2",
                "process_name": "python3",
                "event_type": "EXEC",
                "object_key": "/home/admin/Desktop/tcexec",
                "description": "python3 executed tcexec",
                "timestamp": "2018-04-13T13:51:00",
                "order_index": 2,
            },
        ]
        candidate = _candidate_from_precursor_cluster(
            "task_0546",
            {"p1": p1, "p2": p2},
            retained_events,
            self.rules,
            [],
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertIn("short_lived_precursor", candidate.family_tags)
        self.assertEqual(candidate.precursor_event_ids, ["e1", "e2"])

    def test_precursor_cluster_builder_ignores_weak_service_markers_without_exec_staging(self) -> None:
        p1 = ProcessState(
            "task_0005",
            "p1",
            "smtpd",
            None,
            None,
            datetime.fromisoformat("2018-04-12T14:00:00"),
            datetime.fromisoformat("2018-04-12T14:01:00"),
            parent_process_guid="svc_parent",
        )
        retained_events = [
            {
                "event_id": "e1",
                "process_guid": "p1",
                "process_name": "smtpd",
                "event_type": "CHMOD",
                "object_key": "/var/spool/postfix/public/pickup",
                "description": "chmod postfix pickup socket",
                "timestamp": "2018-04-12T14:00:10",
                "order_index": 1,
            },
            {
                "event_id": "e2",
                "process_guid": "p1",
                "process_name": "smtpd",
                "event_type": "EXEC",
                "object_key": "/usr/bin/bash",
                "description": "bash service helper",
                "timestamp": "2018-04-12T14:00:20",
                "order_index": 2,
            },
        ]
        candidate = _candidate_from_precursor_cluster(
            "task_0005",
            {"p1": p1},
            retained_events,
            self.rules,
            [],
        )
        self.assertIsNone(candidate)

    def test_precursor_cluster_builder_accepts_weak_markers_with_temp_staging(self) -> None:
        p1 = ProcessState(
            "task_0546",
            "p1",
            "bash",
            None,
            None,
            datetime.fromisoformat("2018-04-13T13:50:00"),
            datetime.fromisoformat("2018-04-13T13:51:00"),
            parent_process_guid="shell_parent",
        )
        retained_events = [
            {
                "event_id": "e1",
                "process_guid": "p1",
                "process_name": "bash",
                "event_type": "WRITE",
                "object_key": "/tmp/ztmp",
                "description": "write staged payload to /tmp/ztmp",
                "timestamp": "2018-04-13T13:50:00",
                "order_index": 1,
            },
            {
                "event_id": "e2",
                "process_guid": "p1",
                "process_name": "bash",
                "event_type": "CHMOD",
                "object_key": "/tmp/ztmp",
                "description": "chmod +x /tmp/ztmp",
                "timestamp": "2018-04-13T13:50:20",
                "order_index": 2,
            },
            {
                "event_id": "e3",
                "process_guid": "p1",
                "process_name": "bash",
                "event_type": "EXEC",
                "object_key": "/tmp/ztmp",
                "description": "bash exec /tmp/ztmp",
                "timestamp": "2018-04-13T13:50:40",
                "order_index": 3,
            },
        ]
        candidate = _candidate_from_precursor_cluster(
            "task_0546",
            {"p1": p1},
            retained_events,
            self.rules,
            [],
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertIn("short_lived_precursor", candidate.family_tags)

    def test_cleanup_family_ignores_placeholder_block_delete(self) -> None:
        candidate = self._candidate("cleanup_test", 40.0, [])
        events = [
            {
                "event_id": "e1",
                "process_guid": "cleanup_test",
                "process_name": "firefox",
                "event_type": "DELETE",
                "object_key": "FILE_OBJECT_BLOCK",
                "object_class": "file",
                "description": "delete placeholder staged block",
                "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                "order_index": 1,
                "timestamp": "2018-04-10T18:53:40",
            }
        ]
        tags = _family_tags_from_path(candidate, events, {})
        self.assertNotIn("cleanup_delete", tags)

    def test_augment_candidate_support_recovers_concrete_temp_cleanup_followup(self) -> None:
        candidate = self._candidate("cleanup_test", 40.0, ["initial_or_drop_exec"])
        candidate.process_chain = ["proc_a"]
        process_state = ProcessState(
            task_id="task_0345",
            process_guid="proc_a",
            process_name="payload",
            process_exe="/tmp/ztmp",
            process_cmdline="/tmp/ztmp",
            start_time=datetime.fromisoformat("2018-04-13T12:43:00"),
            end_time=datetime.fromisoformat("2018-04-13T12:53:00"),
            evidence_event_ids=["e1", "e2"],
            important_objects={"/tmp/ztmp"},
        )
        retained_events = [
            {
                "event_id": "e1",
                "process_guid": "proc_a",
                "process_name": "payload",
                "event_type": "WRITE",
                "object_key": "/tmp/ztmp",
                "object_labels": ["O_FILE_TEMP"],
                "labels_triggered": ["B_EXEC_TEMP"],
                "order_index": 1,
                "timestamp": "2018-04-13T12:43:10",
            },
            {
                "event_id": "e2",
                "process_guid": "proc_a",
                "process_name": "payload",
                "event_type": "EXEC",
                "object_key": "/tmp/ztmp",
                "object_labels": ["O_FILE_TEMP"],
                "labels_triggered": ["B_EXEC_TEMP"],
                "order_index": 2,
                "timestamp": "2018-04-13T12:43:20",
            },
            {
                "event_id": "e3",
                "process_guid": "proc_child",
                "parent_process_guid": "proc_a",
                "process_name": "gtcache",
                "event_type": "UNLINK",
                "object_key": "/tmp/ztmp",
                "object_labels": ["O_FILE_TEMP"],
                "labels_triggered": [],
                "order_index": 3,
                "timestamp": "2018-04-13T12:53:00",
            },
        ]
        _augment_candidate_support(
            candidate,
            {"proc_a": process_state},
            {},
            {},
            retained_events,
        )
        self.assertIn("e3", candidate.support_event_ids)
        self.assertIn("e3", candidate.followup_event_ids)
        event_lookup = {event["event_id"]: event for event in retained_events}
        support_events = [event_lookup[event_id] for event_id in candidate.support_event_ids]
        tags = _family_tags_from_path(candidate, support_events, {"proc_a": process_state})
        self.assertIn("cleanup_delete", tags)

    def test_augment_candidate_support_prioritizes_cleanup_followup_under_cap(self) -> None:
        candidate = self._candidate("cleanup_priority_test", 40.0, ["initial_or_drop_exec"])
        candidate.process_chain = ["proc_a"]
        process_state = ProcessState(
            task_id="task_0345",
            process_guid="proc_a",
            process_name="payload",
            process_exe="/tmp/ztmp",
            process_cmdline="/tmp/ztmp",
            start_time=datetime.fromisoformat("2018-04-13T12:43:00"),
            end_time=datetime.fromisoformat("2018-04-13T12:53:00"),
            evidence_event_ids=["e1", "e2"],
            important_objects={"/tmp/ztmp"},
        )
        retained_events = [
            {
                "event_id": "e1",
                "process_guid": "proc_a",
                "process_name": "payload",
                "event_type": "WRITE",
                "object_key": "/tmp/ztmp",
                "object_labels": ["O_FILE_TEMP"],
                "labels_triggered": ["B_EXEC_TEMP"],
                "order_index": 1,
                "timestamp": "2018-04-13T12:43:10",
            },
            {
                "event_id": "e2",
                "process_guid": "proc_a",
                "process_name": "payload",
                "event_type": "EXEC",
                "object_key": "/tmp/ztmp",
                "object_labels": ["O_FILE_TEMP"],
                "labels_triggered": ["B_EXEC_TEMP"],
                "order_index": 2,
                "timestamp": "2018-04-13T12:43:20",
            },
        ]
        for idx in range(3, 12):
            retained_events.append(
                {
                    "event_id": f"n{idx}",
                    "process_guid": "proc_a",
                    "process_name": "payload",
                    "event_type": "SEND",
                    "object_key": f"10.0.0.5:40000->161.116.88.{idx}:80",
                    "object_class": "external_ip",
                    "labels_triggered": ["B_EXTERNAL_SEND"],
                    "order_index": idx,
                    "timestamp": f"2018-04-13T12:43:{idx:02d}",
                }
            )
        retained_events.append(
            {
                "event_id": "e_cleanup",
                "process_guid": "proc_child",
                "parent_process_guid": "proc_a",
                "process_name": "gtcache",
                "event_type": "UNLINK",
                "object_key": "/tmp/ztmp",
                "object_labels": ["O_FILE_TEMP"],
                "labels_triggered": [],
                "order_index": 20,
                "timestamp": "2018-04-13T12:53:00",
            }
        )
        _augment_candidate_support(
            candidate,
            {"proc_a": process_state},
            {},
            {},
            retained_events,
        )
        self.assertIn("e_cleanup", candidate.support_event_ids)
        self.assertIn("e_cleanup", candidate.followup_event_ids)


if __name__ == "__main__":
    unittest.main()

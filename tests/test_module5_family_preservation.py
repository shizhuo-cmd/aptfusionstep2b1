from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from apt_fusion.path_reason.module5_path_finder import (
    _candidate_from_precursor_cluster,
    _select_family_preserved_paths,
)
from apt_fusion.path_reason.path_rules import load_path_rules
from apt_fusion.path_reason.path_schemas import CandidatePath, ProcessState


class Module5FamilyPreservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cfg = SimpleNamespace(
            path_reason_rules_path=Path("D:/daima/APT-Fusionstep2b1/configs/path_reason_default.yaml"),
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


if __name__ == "__main__":
    unittest.main()

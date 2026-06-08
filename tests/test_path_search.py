from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from apt_fusion.path_reason.path_rules import load_path_rules
from apt_fusion.path_reason.path_schemas import ProcessState
from apt_fusion.path_reason.path_search import search_candidate_paths


class PathSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cfg = SimpleNamespace(path_reason_rules_path=Path("D:/daima/APT-Fusion/configs/path_reason_default.yaml"), host="trace")
        cls.rules = load_path_rules(cfg)

    def test_entry_execution_followup_forms_candidate(self) -> None:
        p1 = ProcessState("task_1", "p1", "nginx", None, None, datetime.fromisoformat("2026-05-25T10:00:00"), datetime.fromisoformat("2026-05-25T10:01:00"))
        p1.status_labels.add("P_WEB_CTX")
        p1.behavior_labels.add("B_EXTERNAL_RECV")
        p2 = ProcessState("task_1", "p2", "bash", None, None, datetime.fromisoformat("2026-05-25T10:01:00"), datetime.fromisoformat("2026-05-25T10:02:00"), parent_process_guid="p1")
        p2.behavior_labels.add("B_EXEC_DOWNLOADED")
        p3 = ProcessState("task_1", "p3", "curl", None, None, datetime.fromisoformat("2026-05-25T10:02:00"), datetime.fromisoformat("2026-05-25T10:03:00"), parent_process_guid="p2")
        p3.behavior_labels.add("B_EXTERNAL_SEND")
        paths = search_candidate_paths("task_1", {"p1": p1, "p2": p2, "p3": p3}, [], self.rules)
        self.assertTrue(paths)
        self.assertIn("Entry", paths[0].stage_coverage)
        self.assertIn("ExecutionStrong", paths[0].stage_coverage)
        self.assertIn("FollowUp", paths[0].stage_coverage)


if __name__ == "__main__":
    unittest.main()


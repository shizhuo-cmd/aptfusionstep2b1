from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from apt_fusion.path_reason.bridge_builder import build_bridge_edges
from apt_fusion.path_reason.path_rules import load_path_rules
from apt_fusion.path_reason.path_schemas import ObjectAccessRecord, ObjectState, ProcessState


class BridgeBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cfg = SimpleNamespace(path_reason_rules_path=Path("D:/daima/APT-Fusion/configs/path_reason_default.yaml"), host="trace")
        cls.rules = load_path_rules(cfg)

    def test_downloaded_exec_builds_bridge(self) -> None:
        obj = ObjectState(task_id="task_1", object_key="/tmp/a.sh", object_type="file", object_class="temp_file")
        obj.labels.update({"O_FILE_TEMP", "O_FILE_DOWNLOADED"})
        obj.access_records = [
            ObjectAccessRecord(
                task_id="task_1",
                object_key="/tmp/a.sh",
                object_type="file",
                object_class="temp_file",
                process_guid="writer",
                process_name="curl",
                event_type="WRITE",
                timestamp=datetime.fromisoformat("2026-05-25T10:00:00"),
                order_index=1,
                event_id="e1",
                raw_log_id="r1",
                syscall_direction="P_TO_O",
                semantic_flow_direction="P_TO_O",
                process_label_signature_before="",
                process_label_signature_after="",
                object_label_signature_before="O_FILE_TEMP|O_FILE_DOWNLOADED",
                object_label_signature_after="O_FILE_TEMP|O_FILE_DOWNLOADED",
                object_semantic_epoch_before=0,
                object_semantic_epoch_after=1,
                process_control_epoch_before=0,
                process_control_epoch_after=0,
            ),
            ObjectAccessRecord(
                task_id="task_1",
                object_key="/tmp/a.sh",
                object_type="file",
                object_class="temp_file",
                process_guid="reader",
                process_name="bash",
                event_type="EXEC",
                timestamp=datetime.fromisoformat("2026-05-25T10:01:00"),
                order_index=2,
                event_id="e2",
                raw_log_id="r2",
                syscall_direction="P_TO_O",
                semantic_flow_direction="O_TO_P",
                process_label_signature_before="",
                process_label_signature_after="",
                object_label_signature_before="O_FILE_TEMP|O_FILE_DOWNLOADED",
                object_label_signature_after="O_FILE_TEMP|O_FILE_DOWNLOADED",
                object_semantic_epoch_before=1,
                object_semantic_epoch_after=1,
                process_control_epoch_before=0,
                process_control_epoch_after=1,
            ),
        ]
        edges = build_bridge_edges(
            "task_1",
            {" /tmp/a.sh ".strip(): obj},
            {"writer": ProcessState("task_1", "writer", "curl", None, None, None, None), "reader": ProcessState("task_1", "reader", "bash", None, None, None, None)},
            self.rules,
        )
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].bridge_type, "write_to_exec")


if __name__ == "__main__":
    unittest.main()


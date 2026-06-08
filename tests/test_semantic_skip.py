from __future__ import annotations

import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from apt_fusion.path_reason.path_rules import load_path_rules
from apt_fusion.path_reason.semantic_skip import LatestSemanticTable, make_semantic_key, should_skip_semantically


class SemanticSkipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cfg = SimpleNamespace(path_reason_rules_path=Path("D:/daima/APT-Fusion/configs/path_reason_default.yaml"), host="trace")
        cls.rules = load_path_rules(cfg)

    def test_repeated_semantics_skip_within_ttl(self) -> None:
        table = LatestSemanticTable(100)
        key = make_semantic_key(
            task_id="task_1",
            process_guid="p1",
            event_type="READ",
            object_key="/usr/lib/a.so",
            object_class="system_library",
            semantic_flow_direction="O_TO_P",
        )
        now = datetime.utcnow()
        table.remember(
            key,
            timestamp=now,
            process_guid="p1",
            object_key="/usr/lib/a.so",
            process_label_signature="P_NET_CTX",
            object_label_signature="",
            object_semantic_epoch=0,
            process_control_epoch=0,
        )
        self.assertTrue(
            should_skip_semantically(
                table,
                semantic_key=key,
                timestamp=now + timedelta(seconds=10),
                process_label_signature="P_NET_CTX",
                object_label_signature="",
                object_semantic_epoch=0,
                process_control_epoch=0,
                ttl_seconds=600,
                ignore_if_timestamp_missing=False,
            )
        )

    def test_object_invalidation_breaks_skip(self) -> None:
        table = LatestSemanticTable(100)
        key = make_semantic_key(
            task_id="task_1",
            process_guid="p1",
            event_type="READ",
            object_key="/tmp/x",
            object_class="temp_file",
            semantic_flow_direction="O_TO_P",
        )
        now = datetime.utcnow()
        table.remember(
            key,
            timestamp=now,
            process_guid="p1",
            object_key="/tmp/x",
            process_label_signature="",
            object_label_signature="O_FILE_TEMP",
            object_semantic_epoch=0,
            process_control_epoch=0,
        )
        table.invalidate_object("/tmp/x")
        self.assertFalse(
            should_skip_semantically(
                table,
                semantic_key=key,
                timestamp=now + timedelta(seconds=10),
                process_label_signature="",
                object_label_signature="O_FILE_TEMP",
                object_semantic_epoch=1,
                process_control_epoch=0,
                ttl_seconds=600,
                ignore_if_timestamp_missing=False,
            )
        )


if __name__ == "__main__":
    unittest.main()


from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path

from apt_fusion.path_reason.label_provenance import LabelProvenanceBuilder, load_label_provenance_records
from apt_fusion.path_reason.module5_path_finder import _score_path_support_quality
from apt_fusion.path_reason.path_schemas import CandidatePath


class LabelProvenanceTests(unittest.TestCase):
    def _build_path(
        self,
        *,
        support_event_ids: list[str],
        support_object_keys: list[str],
        support_relations: list[str],
        labels: list[str],
    ) -> CandidatePath:
        return CandidatePath(
            path_id="task_1_path_001",
            task_id="task_1",
            process_chain=["proc_a", "proc_b"],
            bridge_edges=[],
            stage_coverage=["Entry", "ExecutionStrong"],
            labels=labels,
            risk_score=80.0,
            risk_level="HIGH",
            path_type="Entry-ExecutionStrong",
            time_range=(
                datetime(2026, 6, 3, 10, 0, tzinfo=timezone.utc),
                datetime(2026, 6, 3, 10, 5, tzinfo=timezone.utc),
            ),
            evidence_timeline=[],
            summary="test",
            support_event_ids=support_event_ids,
            support_object_keys=support_object_keys,
            support_relations=support_relations,
            context_ids=["ctx:web", "ctx:remote"],
            chain_kind="entry_exec",
        )

    def test_trace_back_returns_stable_ancestry_chain(self) -> None:
        builder = LabelProvenanceBuilder()
        label_a = builder.add(
            task_id="task_1",
            label="P_WEB_CTX",
            label_type="context",
            holder_entity_type="process",
            holder_entity_id="proc_a",
            created_at=datetime(2026, 6, 3, 10, 0, tzinfo=timezone.utc),
            source_type="event_rule",
            event_id="task_1:00000001",
            event_type="CONNECT",
            rule_id="rule.web",
        )
        label_b = builder.add(
            task_id="task_1",
            label="B_EXEC",
            label_type="behavior",
            holder_entity_type="process",
            holder_entity_id="proc_b",
            created_at=datetime(2026, 6, 3, 10, 1, tzinfo=timezone.utc),
            source_type="inherit",
            source_entity_type="process",
            source_entity_id="proc_a",
            event_id="task_1:00000002",
            event_type="FORK",
            rule_id="rule.exec",
            prev_label_ids=[label_a],
        )
        label_c = builder.add(
            task_id="task_1",
            label="A_CHILD_SUSPICIOUS",
            label_type="aggregate",
            holder_entity_type="process",
            holder_entity_id="proc_c",
            created_at=datetime(2026, 6, 3, 10, 2, tzinfo=timezone.utc),
            source_type="inherit",
            source_entity_type="process",
            source_entity_id="proc_b",
            event_id="task_1:00000003",
            event_type="FORK",
            rule_id="rule.child",
            prev_label_ids=[label_b],
        )

        trace = builder.trace_back(label_c)
        self.assertEqual([record.label_id for record in trace], [label_a, label_b, label_c])
        self.assertEqual([record.label for record in trace], ["P_WEB_CTX", "B_EXEC", "A_CHILD_SUSPICIOUS"])

    def test_candidate_path_round_trip_preserves_support_fields(self) -> None:
        path = CandidatePath(
            path_id="task_1_path_001",
            task_id="task_1",
            process_chain=["proc_a", "proc_b"],
            bridge_edges=[],
            stage_coverage=["Entry", "ExecutionStrong"],
            labels=["P_WEB_CTX", "B_EXEC"],
            risk_score=0.75,
            risk_level="HIGH",
            path_type="Entry-ExecutionStrong",
            time_range=(
                datetime(2026, 6, 3, 10, 0, tzinfo=timezone.utc),
                datetime(2026, 6, 3, 10, 5, tzinfo=timezone.utc),
            ),
            evidence_timeline=[],
            summary="test",
            support_event_ids=["task_1:00000001", "task_1:00000003"],
            support_object_keys=["/tmp/a.sh", "/var/www/html/a.sh"],
            support_relations=["bridge: proc_a -> proc_b via /tmp/a.sh [write_to_exec]"],
            context_ids=["ctx:web", "ctx:remote"],
            chain_kind="entry_exec",
        )

        payload = path.to_dict()
        self.assertEqual(payload["support_event_ids"], ["task_1:00000001", "task_1:00000003"])
        self.assertEqual(payload["support_object_keys"], ["/tmp/a.sh", "/var/www/html/a.sh"])
        self.assertEqual(payload["support_relations"], ["bridge: proc_a -> proc_b via /tmp/a.sh [write_to_exec]"])
        self.assertEqual(payload["context_ids"], ["ctx:web", "ctx:remote"])
        self.assertEqual(payload["chain_kind"], "entry_exec")

        restored = CandidatePath.from_dict(payload)
        self.assertEqual(restored.support_event_ids, ["task_1:00000001", "task_1:00000003"])
        self.assertEqual(restored.support_object_keys, ["/tmp/a.sh", "/var/www/html/a.sh"])
        self.assertEqual(restored.support_relations, ["bridge: proc_a -> proc_b via /tmp/a.sh [write_to_exec]"])
        self.assertEqual(restored.context_ids, ["ctx:web", "ctx:remote"])
        self.assertEqual(restored.chain_kind, "entry_exec")

    def test_load_label_provenance_records_returns_empty_for_missing_path(self) -> None:
        self.assertEqual(load_label_provenance_records(Path("Z:/missing/provenance.jsonl")), [])

    def test_support_quality_score_prefers_compact_and_supported_path(self) -> None:
        builder = LabelProvenanceBuilder()
        builder.add(
            task_id="task_1",
            label="P_UNTRUSTED_CTX",
            label_type="context",
            holder_entity_type="process",
            holder_entity_id="proc_a",
            created_at=datetime(2026, 6, 3, 10, 0, tzinfo=timezone.utc),
            source_type="event_rule",
            event_id="e1",
            event_type="CONNECT",
            rule_id="rule.net",
        )
        builder.add(
            task_id="task_1",
            label="B_EXEC_DOWNLOADED",
            label_type="behavior",
            holder_entity_type="process",
            holder_entity_id="proc_b",
            created_at=datetime(2026, 6, 3, 10, 1, tzinfo=timezone.utc),
            source_type="event_rule",
            event_id="e2",
            event_type="EXECUTE",
            rule_id="rule.exec",
        )
        compact_path = self._build_path(
            support_event_ids=["e1", "e2", "e3"],
            support_object_keys=["/tmp/a.sh"],
            support_relations=["bridge: proc_a -> proc_b via /tmp/a.sh [write_to_exec]"],
            labels=["P_UNTRUSTED_CTX", "B_EXEC_DOWNLOADED"],
        )
        weak_path = self._build_path(
            support_event_ids=["e1", "e2", "e3"],
            support_object_keys=["/tmp/a.sh", "/tmp/b.sh", "/tmp/c.sh", "/tmp/d.sh", "/tmp/e.sh", "/tmp/f.sh"],
            support_relations=[],
            labels=["P_UNTRUSTED_CTX", "B_EXEC_DOWNLOADED", "B_EXTERNAL_SEND"],
        )
        retained_events = [
            {"event_id": "e1", "timestamp": "2026-06-03T10:00:00+00:00"},
            {"event_id": "e2", "timestamp": "2026-06-03T10:02:00+00:00"},
            {"event_id": "e3", "timestamp": "2026-06-03T10:03:00+00:00"},
        ]
        compact_score, compact_reasons = _score_path_support_quality(compact_path, builder.records, retained_events)
        weak_score, weak_reasons = _score_path_support_quality(weak_path, builder.records, retained_events)
        self.assertGreater(compact_score, weak_score)
        self.assertTrue(any("provenance_density" in reason for reason in compact_reasons))
        self.assertTrue(any("support_coherence" in reason for reason in weak_reasons))

    def test_support_quality_score_penalizes_scattered_support(self) -> None:
        path = self._build_path(
            support_event_ids=["e1", "e2", "e3"],
            support_object_keys=["/tmp/a.sh"],
            support_relations=["bridge: proc_a -> proc_b via /tmp/a.sh [write_to_exec]"],
            labels=["P_UNTRUSTED_CTX", "B_EXEC_DOWNLOADED"],
        )
        builder = LabelProvenanceBuilder()
        builder.add(
            task_id="task_1",
            label="B_EXEC_DOWNLOADED",
            label_type="behavior",
            holder_entity_type="process",
            holder_entity_id="proc_b",
            created_at=datetime(2026, 6, 3, 10, 0, tzinfo=timezone.utc),
            source_type="event_rule",
            event_id="e2",
            event_type="EXECUTE",
            rule_id="rule.exec",
        )
        compact_events = [
            {"event_id": "e1", "timestamp": "2026-06-03T10:00:00+00:00"},
            {"event_id": "e2", "timestamp": "2026-06-03T10:02:00+00:00"},
            {"event_id": "e3", "timestamp": "2026-06-03T10:03:00+00:00"},
        ]
        scattered_events = [
            {"event_id": "e1", "timestamp": "2026-06-03T10:00:00+00:00"},
            {"event_id": "e2", "timestamp": "2026-06-03T11:45:00+00:00"},
            {"event_id": "e3", "timestamp": "2026-06-03T12:30:00+00:00"},
        ]
        compact_score, _ = _score_path_support_quality(path, builder.records, compact_events)
        scattered_score, scattered_reasons = _score_path_support_quality(path, builder.records, scattered_events)
        self.assertGreater(compact_score, scattered_score)
        self.assertTrue(any("support_compactness" in reason for reason in scattered_reasons))


if __name__ == "__main__":
    unittest.main()

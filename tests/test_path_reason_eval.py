from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from apt_fusion.evaluation.path_reason_eval import (
    GTWindow,
    PredictedPath,
    apply_gt_time_offset,
    assign_paths_to_windows,
    build_gt_reference,
    evaluate_path_reason,
    load_gt_reference,
    parse_gt_windows_strict,
    time_match_for_window,
)


class PathReasonEvalTests(unittest.TestCase):
    def _temp_dir(self) -> str:
        return str(Path(tempfile.gettempdir()))

    def test_strict_markdown_parser_splits_confirmed_and_attempted(self) -> None:
        markdown = """# 3. TRACE

## 3.1 纭鏄犲皠

| 鏃堕棿绐?| 寮曠敤 | 鎻忚堪 | 鎶€鏈?| 璇存槑 |
|---|---|---|---|---|
| 2018-04-13 12:43-12:53 | 搂3.15 | 娴忚鍣ㄩ摼璺?| **T1203**锛?*T1071.001**锛?*T1057**锛?*T1105**锛?*T1046**锛?*T1070.004** | Confirmed |
| 2018-04-12 13:36 | 搂3.12 | 娴忚鍣ㄦ墿灞曞皾璇?| **T1203** | Attempted / Failed |
| 2018-04-10 09:46-11:09 | 搂3.2 | 鍥炶繛涓庢彁鏉?| **T1189**锛?*T1203**锛?*T1071.001**锛?*T1105**锛?*T1055** | T1055 attempted / failed; others confirmed |

## 1. 鏈枃浠朵娇鐢ㄧ殑 ATT&CK 鎶€鏈畾涔夋牳鏌ヨ〃
| T1203 | Exploitation for Client Execution | EXECUTION | desc | url |
| T1071.001 | Application Layer Protocol:Web Protocols | COMMAND_AND_CONTROL | desc | url |
| T1057 | Process Discovery | DISCOVERY | desc | url |
| T1105 | Ingress Tool Transfer | COMMAND_AND_CONTROL | desc | url |
| T1046 | Network Service Discovery | DISCOVERY | desc | url |
| T1070.004 | Indicator Removal:File Deletion | DEFENSE_EVASION | desc | url |
| T1189 | Drive-by Compromise | INITIAL_ACCESS | desc | url |
| T1055 | Process Injection | DEFENSE_EVASION/PRIVILEGE_ESCALATION | desc | url |
"""
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix="_path_reason_eval_strict.md",
            delete=False,
            dir=self._temp_dir(),
        ) as handle:
            handle.write(markdown)
            temp_name = handle.name
        path = Path(temp_name)
        try:
            windows, technique_defs = parse_gt_windows_strict(path)
        finally:
            try:
                if path.exists():
                    os.remove(path)
            except PermissionError:
                pass
        self.assertIn("T1203", technique_defs)
        self.assertEqual(len(windows), 3)
        confirmed = next(item for item in windows if item.source_ref == "搂3.15")
        attempted = next(item for item in windows if item.source_ref == "搂3.12")
        mixed = next(item for item in windows if item.source_ref == "搂3.2")
        self.assertEqual(confirmed.status, "confirmed")
        self.assertIn("T1071.001", confirmed.confirmed_techniques)
        self.assertEqual(attempted.status, "attempted_failed")
        self.assertEqual(attempted.confirmed_techniques, [])
        self.assertEqual(attempted.attempted_techniques, ["T1203"])
        self.assertEqual(mixed.status, "confirmed")
        self.assertIn("T1055", mixed.attempted_techniques)
        self.assertNotIn("T1055", mixed.confirmed_techniques)

    def test_time_match_uses_padding_and_ratio_thresholds(self) -> None:
        window = GTWindow(
            window_id="TRACE_01",
            host="TRACE",
            source_doc="strict.md",
            source_ref="搂3.15",
            status="confirmed",
            time_precision="minute_window",
            start_time=datetime.fromisoformat("2018-04-13T12:43:00"),
            end_time=datetime.fromisoformat("2018-04-13T12:53:00"),
            confirmed_techniques=["T1203"],
            attempted_techniques=[],
            confirmed_tactics=["EXECUTION"],
            attempted_tactics=[],
            coarse_chain_tags=[],
            notes="",
            broad_techniques=[],
        )
        inside = PredictedPath(
            host="TRACE",
            task_id="task_1",
            path_id="p1",
            risk_score=90.0,
            risk_level="HIGH",
            start_time=datetime.fromisoformat("2018-04-13T12:44:00"),
            end_time=datetime.fromisoformat("2018-04-13T12:49:00"),
            stage_coverage=["Entry"],
            process_chain=["a"],
            bridge_objects=[],
            candidate_tactics=[],
            predicted_tactics=[],
            predicted_techniques=[],
            attack_mapping_scope="full",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        partial = PredictedPath(
            host="TRACE",
            task_id="task_1",
            path_id="p2",
            risk_score=60.0,
            risk_level="MEDIUM",
            start_time=datetime.fromisoformat("2018-04-13T12:53:00"),
            end_time=datetime.fromisoformat("2018-04-13T13:01:00"),
            stage_coverage=["Entry"],
            process_chain=["b"],
            bridge_objects=[],
            candidate_tactics=[],
            predicted_tactics=[],
            predicted_techniques=[],
            attack_mapping_scope="full",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        off = PredictedPath(
            host="TRACE",
            task_id="task_1",
            path_id="p3",
            risk_score=50.0,
            risk_level="LOW",
            start_time=datetime.fromisoformat("2018-04-13T13:20:00"),
            end_time=datetime.fromisoformat("2018-04-13T13:25:00"),
            stage_coverage=["Entry"],
            process_chain=["c"],
            bridge_objects=[],
            candidate_tactics=[],
            predicted_tactics=[],
            predicted_techniques=[],
            attack_mapping_scope="full",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        inside_match = time_match_for_window(inside, window, pad_minutes=5, near_miss_minutes=5)
        partial_match = time_match_for_window(partial, window, pad_minutes=5, near_miss_minutes=5)
        off_match = time_match_for_window(off, window, pad_minutes=5, near_miss_minutes=5)
        self.assertTrue(inside_match.strict_time_match)
        self.assertTrue(inside_match.primary_time_match)
        self.assertTrue(partial_match.primary_time_match)
        self.assertFalse(partial_match.strict_time_match)
        self.assertFalse(off_match.primary_time_match)

    def test_point_event_inside_window_is_not_marked_off_window(self) -> None:
        window = GTWindow(
            window_id="THEIA_01",
            host="THEIA",
            source_doc="strict.md",
            source_ref="point",
            status="confirmed",
            time_precision="minute_window",
            start_time=datetime.fromisoformat("2018-04-10T17:41:00"),
            end_time=datetime.fromisoformat("2018-04-10T18:55:00"),
            confirmed_techniques=[],
            attempted_techniques=[],
            confirmed_tactics=["COMMAND_AND_CONTROL"],
            attempted_tactics=[],
            coarse_chain_tags=[],
            notes="",
            broad_techniques=[],
        )
        point_path = PredictedPath(
            host="THEIA",
            task_id="task_point",
            path_id="task_point_path_001",
            risk_score=70.0,
            risk_level="HIGH",
            start_time=datetime.fromisoformat("2018-04-10T18:11:15"),
            end_time=datetime.fromisoformat("2018-04-10T18:11:15"),
            stage_coverage=["Entry"],
            process_chain=["gconf-helper"],
            bridge_objects=[],
            candidate_tactics=["COMMAND_AND_CONTROL"],
            predicted_tactics=["COMMAND_AND_CONTROL"],
            predicted_techniques=[],
            attack_mapping_scope="tactics_only",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        match = time_match_for_window(point_path, window, pad_minutes=5, near_miss_minutes=5)
        self.assertTrue(match.strict_time_match)
        self.assertTrue(match.primary_time_match)
        self.assertTrue(match.loose_time_match)
        self.assertGreaterEqual(match.path_in_window_ratio, 1.0)

    def test_gt_reference_roundtrip_filters_by_host(self) -> None:
        windows = [
            GTWindow(
                window_id="TRACE_01",
                host="TRACE",
                source_doc="strict.md",
                source_ref="搂3.15 / Report Page 28-30",
                status="confirmed",
                time_precision="minute_window",
                start_time=datetime.fromisoformat("2018-04-13T12:43:00"),
                end_time=datetime.fromisoformat("2018-04-13T12:53:00"),
                confirmed_techniques=["T1203", "T1071.001"],
                attempted_techniques=[],
                confirmed_tactics=["EXECUTION", "COMMAND_AND_CONTROL"],
                attempted_tactics=[],
                coarse_chain_tags=["browser_compromise"],
                notes="Confirmed",
                broad_techniques=["T1203", "T1071.001", "T1189"],
                attack_summary="browser exploit to shell and callback",
                source_report_pages=[28, 29, 30],
            ),
            GTWindow(
                window_id="THEIA_01",
                host="THEIA",
                source_doc="strict.md",
                source_ref="搂3.11 / Report Page 20-22",
                status="confirmed",
                time_precision="minute_window",
                start_time=datetime.fromisoformat("2018-04-12T12:44:00"),
                end_time=datetime.fromisoformat("2018-04-12T13:26:00"),
                confirmed_techniques=["T1203"],
                attempted_techniques=[],
                confirmed_tactics=["EXECUTION"],
                attempted_tactics=[],
                coarse_chain_tags=["callback"],
                notes="Confirmed",
                broad_techniques=["T1203"],
            ),
        ]
        reference = build_gt_reference(
            strict_windows=windows,
            technique_to_tactics={"T1203": ["EXECUTION"], "T1071.001": ["COMMAND_AND_CONTROL"]},
            strict_md_path=Path("D:/download/ALL_HOSTS_ATTCK_STRICT_MAPPING.md"),
            broad_md_path=Path("D:/download/ALL_HOSTS_ATTACK_ATTCK_MAPPING.md"),
            primary_report_name="TC_Ground_Truth_Report_E3_Update.pdf",
            primary_report_path="D:/download/TC_Ground_Truth_Report_E3_Update.pdf",
        )
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix="_path_reason_eval_gt.json",
            delete=False,
            dir=self._temp_dir(),
        ) as handle:
            handle.write(__import__("json").dumps(reference, ensure_ascii=False, indent=2))
            temp_name = handle.name
        path = Path(temp_name)
        try:
            filtered_windows, technique_defs, metadata = load_gt_reference(path, host_filter="TRACE")
        finally:
            try:
                if path.exists():
                    os.remove(path)
            except PermissionError:
                pass
        self.assertEqual(len(filtered_windows), 1)
        self.assertEqual(filtered_windows[0].host, "TRACE")
        self.assertEqual(filtered_windows[0].attack_summary, "browser exploit to shell and callback")
        self.assertEqual(filtered_windows[0].source_report_pages, [28, 29, 30])
        self.assertIn("T1203", technique_defs)
        self.assertEqual(metadata.get("schema_version"), "darpa_attack_eval_gt.v1")

    def test_apply_gt_time_offset_shifts_window_times(self) -> None:
        window = GTWindow(
            window_id="TRACE_01",
            host="TRACE",
            source_doc="strict.md",
            source_ref="搂3.15 / Report Page 28-30",
            status="confirmed",
            time_precision="minute_window",
            start_time=datetime.fromisoformat("2018-04-13T12:43:00"),
            end_time=datetime.fromisoformat("2018-04-13T12:53:00"),
            confirmed_techniques=["T1203"],
            attempted_techniques=[],
            confirmed_tactics=["EXECUTION"],
            attempted_tactics=[],
            coarse_chain_tags=[],
            notes="",
            broad_techniques=[],
        )
        apply_gt_time_offset([window], minutes=240)
        self.assertEqual(window.start_time, datetime.fromisoformat("2018-04-13T16:43:00"))
        self.assertEqual(window.end_time, datetime.fromisoformat("2018-04-13T16:53:00"))

    def test_confirmed_window_uses_unique_assigned_paths_for_tactic_union(self) -> None:
        broad = GTWindow(
            window_id="THEIA_BROAD",
            host="THEIA",
            source_doc="strict.md",
            source_ref="broad",
            status="confirmed",
            time_precision="minute_window",
            start_time=datetime.fromisoformat("2018-04-10T13:41:00"),
            end_time=datetime.fromisoformat("2018-04-10T14:55:00"),
            confirmed_techniques=[],
            attempted_techniques=[],
            confirmed_tactics=["INITIAL_ACCESS", "EXECUTION", "PRIVILEGE_ESCALATION"],
            attempted_tactics=[],
            coarse_chain_tags=[],
            notes="",
            broad_techniques=[],
        )
        nested = GTWindow(
            window_id="THEIA_NESTED",
            host="THEIA",
            source_doc="strict.md",
            source_ref="nested",
            status="confirmed",
            time_precision="minute_window",
            start_time=datetime.fromisoformat("2018-04-10T13:42:00"),
            end_time=datetime.fromisoformat("2018-04-10T13:44:00"),
            confirmed_techniques=[],
            attempted_techniques=[],
            confirmed_tactics=["INITIAL_ACCESS", "EXECUTION", "CREDENTIAL_ACCESS"],
            attempted_tactics=[],
            coarse_chain_tags=[],
            notes="",
            broad_techniques=[],
        )
        broad_path = PredictedPath(
            host="THEIA",
            task_id="task_broad",
            path_id="task_broad_path_001",
            risk_score=80.0,
            risk_level="HIGH",
            start_time=datetime.fromisoformat("2018-04-10T14:10:00"),
            end_time=datetime.fromisoformat("2018-04-10T14:20:00"),
            stage_coverage=["Entry"],
            process_chain=["payload"],
            bridge_objects=[],
            candidate_tactics=["EXECUTION", "PRIVILEGE_ESCALATION"],
            predicted_tactics=["EXECUTION", "PRIVILEGE_ESCALATION"],
            predicted_techniques=[],
            attack_mapping_scope="tactics_only",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        nested_path = PredictedPath(
            host="THEIA",
            task_id="task_nested",
            path_id="task_nested_path_001",
            risk_score=70.0,
            risk_level="HIGH",
            start_time=datetime.fromisoformat("2018-04-10T13:42:10"),
            end_time=datetime.fromisoformat("2018-04-10T13:43:20"),
            stage_coverage=["Entry"],
            process_chain=["browser"],
            bridge_objects=[],
            candidate_tactics=["INITIAL_ACCESS", "EXECUTION", "CREDENTIAL_ACCESS"],
            predicted_tactics=["INITIAL_ACCESS", "EXECUTION", "CREDENTIAL_ACCESS"],
            predicted_techniques=[],
            attack_mapping_scope="tactics_only",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        predicted_paths = [broad_path, nested_path]
        assignments = assign_paths_to_windows(
            predicted_paths,
            [broad, nested],
            pad_minutes=5,
            near_miss_minutes=5,
        )
        assignment_by_path = {str(item["path_id"]): item for item in assignments}
        self.assertEqual(assignment_by_path["task_nested_path_001"]["assigned_window_id"], "THEIA_NESTED")
        self.assertEqual(assignment_by_path["task_nested_path_001"]["match_type"], "CONFIRMED_MATCH")
        summary, _window_level, _technique_cmp, tactic_cmp, candidate_cov = evaluate_path_reason(
            strict_windows=[broad, nested],
            predicted_paths=predicted_paths,
            path_assignments=assignments,
            match_top_n=5,
            pad_minutes=5,
            near_miss_minutes=5,
        )
        self.assertEqual(summary["confirmed_window_recall"], 1.0)
        tactic_by_window = {str(item["window_id"]): item for item in tactic_cmp}
        coverage_by_window = {str(item["window_id"]): item for item in candidate_cov}
        self.assertEqual(
            tactic_by_window["THEIA_BROAD"]["predicted_tactics_union_top_n"],
            ["EXECUTION", "PRIVILEGE_ESCALATION"],
        )
        self.assertEqual(
            coverage_by_window["THEIA_BROAD"]["candidate_tactics_union_top_n"],
            ["EXECUTION", "PRIVILEGE_ESCALATION"],
        )
        self.assertEqual(
            tactic_by_window["THEIA_NESTED"]["predicted_tactics_union_top_n"],
            ["INITIAL_ACCESS", "EXECUTION", "CREDENTIAL_ACCESS"],
        )

    def test_off_window_suffix_is_reattached_as_confirmed_continuation(self) -> None:
        window = GTWindow(
            window_id="THEIA_CHAIN",
            host="THEIA",
            source_doc="strict.md",
            source_ref="chain",
            status="confirmed",
            time_precision="minute_window",
            start_time=datetime.fromisoformat("2018-04-10T17:41:00"),
            end_time=datetime.fromisoformat("2018-04-10T18:55:00"),
            confirmed_techniques=[],
            attempted_techniques=[],
            confirmed_tactics=["INITIAL_ACCESS", "EXECUTION", "COMMAND_AND_CONTROL", "PRIVILEGE_ESCALATION"],
            attempted_tactics=[],
            coarse_chain_tags=[],
            notes="",
            broad_techniques=[],
        )
        anchor = PredictedPath(
            host="THEIA",
            task_id="task_chain",
            path_id="task_chain_path_001",
            risk_score=250.0,
            risk_level="HIGH",
            start_time=datetime.fromisoformat("2018-04-10T18:44:27"),
            end_time=datetime.fromisoformat("2018-04-10T19:06:58"),
            stage_coverage=["Entry", "ExecutionStrong", "FollowUp"],
            process_chain=["payload_parent", "payload_child", "/home/admin/profile"],
            bridge_objects=["FILE_OBJECT_BLOCK"],
            candidate_tactics=["EXECUTION", "COMMAND_AND_CONTROL", "DISCOVERY", "INITIAL_ACCESS", "PRIVILEGE_ESCALATION"],
            predicted_tactics=["EXECUTION", "COMMAND_AND_CONTROL", "DISCOVERY", "INITIAL_ACCESS", "PRIVILEGE_ESCALATION"],
            predicted_techniques=[],
            attack_mapping_scope="tactics_only",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        suffix = PredictedPath(
            host="THEIA",
            task_id="task_chain",
            path_id="task_chain_path_003",
            risk_score=206.5,
            risk_level="HIGH",
            start_time=datetime.fromisoformat("2018-04-10T18:56:39"),
            end_time=datetime.fromisoformat("2018-04-10T19:06:58"),
            stage_coverage=["Entry", "ExecutionStrong", "FollowUp"],
            process_chain=["payload_child", "/home/admin/profile"],
            bridge_objects=[],
            candidate_tactics=["INITIAL_ACCESS", "COMMAND_AND_CONTROL", "PRIVILEGE_ESCALATION", "EXECUTION"],
            predicted_tactics=["COMMAND_AND_CONTROL", "PRIVILEGE_ESCALATION"],
            predicted_techniques=[],
            attack_mapping_scope="tactics_only",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        unrelated = PredictedPath(
            host="THEIA",
            task_id="task_other",
            path_id="task_other_path_001",
            risk_score=190.0,
            risk_level="HIGH",
            start_time=datetime.fromisoformat("2018-04-10T19:20:00"),
            end_time=datetime.fromisoformat("2018-04-10T19:25:00"),
            stage_coverage=["Entry"],
            process_chain=["other_process"],
            bridge_objects=[],
            candidate_tactics=["COMMAND_AND_CONTROL"],
            predicted_tactics=["COMMAND_AND_CONTROL"],
            predicted_techniques=[],
            attack_mapping_scope="tactics_only",
            warnings=[],
            candidate_paths_path="",
            report_path="",
        )
        assignments = assign_paths_to_windows(
            [anchor, suffix, unrelated],
            [window],
            pad_minutes=5,
            near_miss_minutes=5,
        )
        by_path = {str(item["path_id"]): item for item in assignments}
        self.assertEqual(by_path["task_chain_path_001"]["assigned_status"], "CONFIRMED_MATCH")
        self.assertEqual(by_path["task_chain_path_003"]["assigned_status"], "CONFIRMED_CONTINUATION")
        self.assertEqual(by_path["task_chain_path_003"]["assigned_window_id"], "THEIA_CHAIN")
        self.assertFalse(by_path["task_chain_path_003"]["primary_time_match"])
        self.assertEqual(by_path["task_chain_path_003"]["continuation_anchor_path_id"], "task_chain_path_001")
        self.assertEqual(by_path["task_other_path_001"]["assigned_status"], "OFF_WINDOW")
        summary, window_level, _technique_cmp, tactic_cmp, _candidate_cov = evaluate_path_reason(
            strict_windows=[window],
            predicted_paths=[anchor, suffix, unrelated],
            path_assignments=assignments,
            match_top_n=5,
            pad_minutes=5,
            near_miss_minutes=5,
        )
        self.assertEqual(summary["confirmed_window_recall"], 1.0)
        self.assertEqual(summary["off_window_high_risk_count"], 1)
        by_window = {str(item["window_id"]): item for item in tactic_cmp}
        self.assertEqual(
            by_window["THEIA_CHAIN"]["predicted_tactics_union_top_n"],
            ["EXECUTION", "COMMAND_AND_CONTROL", "DISCOVERY", "INITIAL_ACCESS", "PRIVILEGE_ESCALATION"],
        )


if __name__ == "__main__":
    unittest.main()


from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path

from apt_fusion.evaluation.path_reason_eval import (
    GTWindow,
    PredictedPath,
    apply_gt_time_offset,
    build_gt_reference,
    load_gt_reference,
    parse_gt_windows_strict,
    time_match_for_window,
)


class PathReasonEvalTests(unittest.TestCase):
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
        path = Path("D:/daima/APT-Fusion/.tmp_path_reason_eval_strict.md")
        try:
            path.write_text(markdown, encoding="utf-8")
            windows, technique_defs = parse_gt_windows_strict(path)
        finally:
            path.unlink(missing_ok=True)
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
            predicted_tactics=[],
            predicted_techniques=[],
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
            predicted_tactics=[],
            predicted_techniques=[],
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
            predicted_tactics=[],
            predicted_techniques=[],
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
        path = Path("D:/daima/APT-Fusion/.tmp_path_reason_eval_gt.json")
        try:
            path.write_text(__import__("json").dumps(reference, ensure_ascii=False, indent=2), encoding="utf-8")
            filtered_windows, technique_defs, metadata = load_gt_reference(path, host_filter="TRACE")
        finally:
            path.unlink(missing_ok=True)
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


if __name__ == "__main__":
    unittest.main()


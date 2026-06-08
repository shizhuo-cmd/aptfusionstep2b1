from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from apt_fusion.path_reason.object_classifier import classify_object, classify_process_type
from apt_fusion.path_reason.path_rules import load_path_rules


class ObjectClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cfg = SimpleNamespace(path_reason_rules_path=Path("D:/daima/APT-Fusion/configs/path_reason_default.yaml"), host="trace")
        cls.rules = load_path_rules(cfg)

    def test_temp_file_is_classified(self) -> None:
        self.assertEqual(classify_object("file", "/tmp/run.sh", self.rules), "temp_file")

    def test_business_glob_is_classified(self) -> None:
        self.assertEqual(classify_object("file", "/srv/data/report.xlsx", self.rules), "business_file")

    def test_external_flow_is_classified(self) -> None:
        self.assertEqual(classify_object("flow", "10.0.0.4:43210->8.8.8.8:53", self.rules), "external_ip")

    def test_process_type_shell(self) -> None:
        self.assertEqual(classify_process_type("bash", "/bin/bash", self.rules), "shell")


if __name__ == "__main__":
    unittest.main()


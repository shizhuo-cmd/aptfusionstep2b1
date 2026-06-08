from __future__ import annotations

import unittest

from apt_fusion.path_reason.holmes_claims import build_holmes_claim_graph


class HolmesClaimGraphTests(unittest.TestCase):
    def test_detects_attachment_c2_and_scan_atoms(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "READ",
                    "object_key": "/var/mail/pine/tcexec",
                    "object_class": "mail_attachment",
                    "description": "pine READ attachment tcexec",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                },
                {
                    "event_id": "e2",
                    "event_type": "EXEC",
                    "object_key": "/home/admin/Desktop/tcexec",
                    "object_class": "file",
                    "description": "bash EXEC tcexec",
                    "labels_triggered": ["B_EXEC_DOWNLOADED"],
                },
                {
                    "event_id": "e3",
                    "event_type": "CONNECT",
                    "object_key": "10.0.0.5:40000->162.66.239.75:443",
                    "object_class": "external_ip",
                    "description": "bash CONNECT remote c2",
                    "labels_triggered": ["B_EXTERNAL_SEND"],
                },
                {
                    "event_id": "e4",
                    "event_type": "CONNECT",
                    "object_key": "10.0.0.5:40001->10.0.0.7:22",
                    "object_class": "internal_ip",
                    "description": "bash CONNECT internal scan target 1",
                    "labels_triggered": ["B_LATERAL_CONNECT"],
                },
                {
                    "event_id": "e5",
                    "event_type": "CONNECT",
                    "object_key": "10.0.0.5:40002->10.0.0.8:80",
                    "object_class": "internal_ip",
                    "description": "bash CONNECT internal scan target 2",
                    "labels_triggered": ["B_LATERAL_CONNECT"],
                },
            ],
            "core_processes": [{"name": "pine", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [
                {
                    "object_key": "/home/admin/Desktop/tcexec",
                    "object_labels": ["O_FILE_DOWNLOADED", "O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "write_event_id": "e1",
                    "read_or_exec_event_id": "e2",
                    "reason": "attachment opened then executed",
                }
            ],
            "support_object_keys": ["/home/admin/Desktop/tcexec"],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("attachment_user_exec", atoms)
        self.assertIn("cnc_communication", atoms)
        self.assertIn("network_service_discovery", atoms)

    def test_preserves_precursor_chain(self) -> None:
        dossier = {
            "precursor_event_ids": ["p1", "p2", "p3"],
            "evidence_timeline": [
                {
                    "event_id": "p1",
                    "event_type": "EXEC",
                    "object_key": "/home/admin/Desktop/tcexec",
                    "object_class": "file",
                    "description": "bash EXEC tcexec",
                    "labels_triggered": [],
                },
                {
                    "event_id": "p2",
                    "event_type": "CHMOD",
                    "object_key": "/home/admin/Desktop/tcexec",
                    "object_class": "file",
                    "description": "chmod +x tcexec",
                    "labels_triggered": [],
                },
                {
                    "event_id": "p3",
                    "event_type": "EXEC",
                    "object_key": "/usr/bin/command-not-found",
                    "object_class": "file",
                    "description": "command-not-found -- tcexec on /dev/pts/3",
                    "labels_triggered": [],
                },
            ],
            "core_processes": [{"name": "bash", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("interpreter_precursor_chain", atoms)


if __name__ == "__main__":
    unittest.main()

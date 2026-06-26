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

    def test_service_chmod_does_not_trigger_make_file_exec(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "CHMOD",
                    "object_key": "/var/spool/postfix/public/pickup",
                    "object_class": "file",
                    "description": "chmod postfix pickup socket",
                    "labels_triggered": [],
                },
                {
                    "event_id": "e2",
                    "event_type": "RECV",
                    "object_key": "10.0.0.5:25->198.51.100.10:443",
                    "object_class": "external_ip",
                    "description": "smtpd received remote content",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                },
            ],
            "core_processes": [{"name": "smtpd", "labels": ["P_REMOTE_CTX", "P_NET_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertNotIn("make_file_exec", atoms)
        self.assertNotIn("interpreter_precursor_chain", atoms)

    def test_weak_precursor_requires_real_exec_staging(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "EXEC",
                    "object_key": "/usr/bin/bash",
                    "object_class": "file",
                    "description": "bash spawned helper",
                    "labels_triggered": [],
                },
                {
                    "event_id": "e2",
                    "event_type": "EXEC",
                    "object_key": "/usr/bin/python3",
                    "object_class": "file",
                    "description": "python3 helper script",
                    "labels_triggered": [],
                },
            ],
            "core_processes": [{"name": "systemd", "labels": ["P_REMOTE_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertNotIn("interpreter_precursor_chain", atoms)

    def test_temp_exec_staging_allows_make_file_exec(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "WRITE",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "write staged payload",
                    "labels_triggered": [],
                    "order_index": 1,
                    "timestamp": "2018-04-13T13:50:00",
                },
                {
                    "event_id": "e2",
                    "event_type": "CHMOD",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "chmod +x /tmp/ztmp",
                    "labels_triggered": [],
                    "order_index": 2,
                    "timestamp": "2018-04-13T13:51:00",
                },
                {
                    "event_id": "e3",
                    "event_type": "EXEC",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "bash exec /tmp/ztmp",
                    "labels_triggered": ["B_EXEC_TEMP"],
                    "order_index": 3,
                    "timestamp": "2018-04-13T13:52:00",
                },
            ],
            "core_processes": [{"name": "bash", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("make_file_exec", atoms)
        self.assertIn("interpreter_precursor_chain", atoms)

    def test_service_system_business_read_does_not_trigger_sensitive_read(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "EXEC",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "bash exec /tmp/ztmp",
                    "labels_triggered": ["B_EXEC_TEMP"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-12T14:00:00",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "READ",
                    "object_key": "/etc/group",
                    "object_class": "business_file",
                    "description": "bash read /etc/group",
                    "labels_triggered": ["B_READ_BUSINESS"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-12T14:01:00",
                    "order_index": 2,
                },
                {
                    "event_id": "e3",
                    "event_type": "SEND",
                    "object_key": "10.0.0.5:25->198.51.100.10:443",
                    "object_class": "external_ip",
                    "description": "bash sent remote data",
                    "labels_triggered": ["B_EXTERNAL_SEND"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-12T14:02:00",
                    "order_index": 3,
                },
            ],
            "core_processes": [{"name": "smtpd", "labels": ["P_REMOTE_CTX", "P_NET_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertNotIn("sensitive_read", atoms)
        self.assertNotIn("sensitive_leak", atoms)

    def test_browser_mail_context_prefers_credential_submit_over_c2(self) -> None:
        dossier = {
            "family_tags": ["mail_browser_context_tail", "initial_or_drop_exec"],
            "network_support_summary": "external_recv=23; external_send=7; remote_targets=1",
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "RECV",
                    "object_key": "10.0.0.5:443->203.0.113.10:443",
                    "object_class": "external_ip",
                    "description": "firefox recv remote login page",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                    "process_guid": "p_firefox",
                    "timestamp": "2018-04-10T17:31:11",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "WRITE",
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_class": "file",
                    "description": "firefox write file_object_block",
                    "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "process_guid": "p_firefox",
                    "timestamp": "2018-04-10T17:31:11",
                    "order_index": 2,
                },
                {
                    "event_id": "e3",
                    "event_type": "READ",
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_class": "file",
                    "description": "fluxbox read file_object_block",
                    "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "process_guid": "p_fluxbox",
                    "timestamp": "2018-04-10T17:31:11",
                    "order_index": 3,
                },
                {
                    "event_id": "e4",
                    "event_type": "SEND",
                    "object_key": "10.0.0.5:444->203.0.113.10:443",
                    "object_class": "external_ip",
                    "description": "fluxbox send submitted browser form",
                    "labels_triggered": ["B_EXTERNAL_SEND"],
                    "process_guid": "p_fluxbox",
                    "timestamp": "2018-04-10T17:31:12",
                    "order_index": 4,
                },
                {
                    "event_id": "e5",
                    "event_type": "RECV",
                    "object_key": "10.0.0.5:443->203.0.113.10:443",
                    "object_class": "external_ip",
                    "description": "fluxbox recv browser response",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                    "process_guid": "p_fluxbox",
                    "timestamp": "2018-04-10T17:31:13",
                    "order_index": 5,
                },
            ],
            "core_processes": [
                {"name": "firefox", "labels": ["P_UNTRUSTED_CTX", "P_NET_CTX"]},
                {"name": "fluxbox", "labels": ["P_UNTRUSTED_CTX", "P_NET_CTX"]},
            ],
            "bridge_edges": [
                {
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "write_event_id": "e2",
                    "read_or_exec_event_id": "e3",
                    "reason": "browser object promoted into UI context",
                }
            ],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("credential_submit", atoms)
        self.assertNotIn("cnc_communication", atoms)

    def test_truncated_timeline_with_large_network_summary_does_not_trigger_credential_submit(self) -> None:
        dossier = {
            "family_tags": ["mail_browser_context_tail", "initial_or_drop_exec"],
            "network_support_summary": "external_recv=220; external_send=10; remote_targets=2",
            "evidence_timeline": [
                {
                    "event_id": "recv_1",
                    "event_type": "RECV",
                    "object_key": "10.0.0.5:443->203.0.113.10:443",
                    "object_class": "external_ip",
                    "description": "firefox recv remote exploit content",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                    "process_guid": "p_firefox",
                    "timestamp": "2018-04-10T18:53:22",
                    "order_index": 1,
                },
                {
                    "event_id": "recv_2",
                    "event_type": "RECV",
                    "object_key": "10.0.0.5:443->203.0.113.10:443",
                    "object_class": "external_ip",
                    "description": "firefox recv remote exploit content",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                    "process_guid": "p_firefox",
                    "timestamp": "2018-04-10T18:53:27",
                    "order_index": 2,
                },
                {
                    "event_id": "recv_3",
                    "event_type": "RECV",
                    "object_key": "10.0.0.5:443->203.0.113.10:443",
                    "object_class": "external_ip",
                    "description": "firefox recv remote exploit content",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                    "process_guid": "p_firefox",
                    "timestamp": "2018-04-10T18:53:31",
                    "order_index": 3,
                },
                {
                    "event_id": "send_1",
                    "event_type": "SEND",
                    "object_key": "10.0.0.5:444->203.0.113.10:443",
                    "object_class": "external_ip",
                    "description": "firefox send remote response",
                    "labels_triggered": ["B_EXTERNAL_SEND"],
                    "process_guid": "p_firefox",
                    "timestamp": "2018-04-10T18:53:36",
                    "order_index": 4,
                },
            ],
            "core_processes": [
                {"name": "firefox", "labels": ["P_UNTRUSTED_CTX", "P_NET_CTX"]},
                {"name": "fluxbox", "labels": ["P_UNTRUSTED_CTX", "P_NET_CTX"]},
            ],
            "bridge_edges": [
                {
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "write_event_id": "recv_1",
                    "read_or_exec_event_id": "recv_2",
                    "reason": "browser object promoted into UI context",
                }
            ],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertNotIn("credential_submit", atoms)

    def test_long_noisy_browser_session_does_not_trigger_credential_submit(self) -> None:
        timeline = []
        for index in range(81):
            minute = 31 + ((index * 2) // 60)
            second = (index * 2) % 60
            timeline.append(
                {
                    "event_id": f"recv_{index}",
                    "event_type": "RECV",
                    "object_key": "10.0.0.5:443->203.0.113.10:443",
                    "object_class": "external_ip",
                    "description": "firefox recv long browser session",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                    "process_guid": "p_firefox",
                    "timestamp": f"2018-04-10T17:{minute:02d}:{second:02d}",
                    "order_index": index + 1,
                }
            )
        timeline.append(
            {
                "event_id": "send_1",
                "event_type": "SEND",
                "object_key": "10.0.0.5:444->203.0.113.10:443",
                "object_class": "external_ip",
                "description": "firefox send browser data after a long noisy session",
                "labels_triggered": ["B_EXTERNAL_SEND"],
                "process_guid": "p_firefox",
                "timestamp": "2018-04-10T17:34:45",
                "order_index": 100,
            }
        )
        dossier = {
            "family_tags": ["mail_browser_context_tail", "initial_or_drop_exec"],
            "evidence_timeline": timeline,
            "core_processes": [
                {"name": "firefox", "labels": ["P_UNTRUSTED_CTX", "P_NET_CTX"]},
            ],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertNotIn("credential_submit", atoms)

    def test_placeholder_block_delete_does_not_trigger_clear_logs(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "DELETE",
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_class": "file",
                    "description": "delete placeholder staged block",
                    "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "labels_triggered": [],
                    "process_guid": "p_firefox",
                    "timestamp": "2018-04-10T18:53:40",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "EXEC",
                    "object_key": "/home/admin/profile",
                    "object_class": "file",
                    "description": "exec staged profile payload",
                    "labels_triggered": ["B_EXEC_SUSPECT_WRITTEN"],
                    "process_guid": "p_firefox",
                    "timestamp": "2018-04-10T18:53:20",
                    "order_index": 0,
                },
            ],
            "core_processes": [{"name": "firefox", "labels": ["P_UNTRUSTED_CTX", "P_NET_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertNotIn("clear_logs", atoms)

    def test_business_read_requires_extra_support_but_can_still_leak(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "WRITE",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "write staged payload",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:50:00",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "CHMOD",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "chmod +x /tmp/ztmp",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:51:00",
                    "order_index": 2,
                },
                {
                    "event_id": "e3",
                    "event_type": "EXEC",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "bash exec /tmp/ztmp",
                    "labels_triggered": ["B_EXEC_TEMP"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:52:00",
                    "order_index": 3,
                },
                {
                    "event_id": "e4",
                    "event_type": "READ",
                    "object_key": "/home/admin/customer.csv",
                    "object_class": "business_file",
                    "description": "bash read customer export",
                    "labels_triggered": ["B_READ_BUSINESS"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:53:00",
                    "order_index": 4,
                },
                {
                    "event_id": "e5",
                    "event_type": "SEND",
                    "object_key": "10.0.0.5:40001->203.0.113.9:443",
                    "object_class": "external_ip",
                    "description": "bash exfiltrated export",
                    "labels_triggered": ["B_EXTERNAL_SEND"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:55:00",
                    "order_index": 5,
                },
            ],
            "core_processes": [{"name": "bash", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("sensitive_read", atoms)
        self.assertIn("sensitive_leak", atoms)

    def test_sensitive_leak_requires_real_external_send(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "EXEC",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "bash exec /tmp/ztmp",
                    "labels_triggered": ["B_EXEC_TEMP"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:52:00",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "READ",
                    "object_key": "/home/admin/customer.csv",
                    "object_class": "business_file",
                    "description": "bash read customer export",
                    "labels_triggered": ["B_READ_BUSINESS"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:53:00",
                    "order_index": 2,
                },
                {
                    "event_id": "e3",
                    "event_type": "RECV",
                    "object_key": "10.0.0.5:40001->203.0.113.9:443",
                    "object_class": "external_ip",
                    "description": "bash received external response",
                    "labels_triggered": ["B_EXTERNAL_RECV"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:55:00",
                    "order_index": 3,
                },
            ],
            "core_processes": [{"name": "bash", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("sensitive_read", atoms)
        self.assertNotIn("sensitive_leak", atoms)

    def test_clear_logs_accepts_staged_temp_cleanup(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "WRITE",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "write staged payload",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:50:00",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "CHMOD",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "chmod +x /tmp/ztmp",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:50:20",
                    "order_index": 2,
                },
                {
                    "event_id": "e3",
                    "event_type": "EXEC",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "bash exec /tmp/ztmp",
                    "labels_triggered": ["B_EXEC_TEMP"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:50:40",
                    "order_index": 3,
                },
                {
                    "event_id": "e4",
                    "event_type": "DELETE",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "remove staged payload",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T13:51:00",
                    "order_index": 4,
                },
            ],
            "core_processes": [{"name": "bash", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("clear_logs", atoms)

    def test_payload_elevate_matches_non_temp_staged_payload(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "WRITE",
                    "object_key": "/home/admin/clean",
                    "object_class": "file",
                    "description": "putfile clean",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-10T14:35:00",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "EXEC",
                    "object_key": "/home/admin/clean",
                    "object_class": "file",
                    "description": "exec clean payload",
                    "labels_triggered": ["B_EXEC_SUSPECT_WRITTEN"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-10T14:35:20",
                    "order_index": 2,
                },
                {
                    "event_id": "e3",
                    "event_type": "EXEC",
                    "object_key": "/home/admin/clean",
                    "object_class": "file",
                    "description": "elevate clean as root",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-10T14:35:40",
                    "order_index": 3,
                },
            ],
            "core_processes": [{"name": "drakon", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [
                {
                    "object_key": "/home/admin/clean",
                    "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "write_event_id": "e1",
                    "read_or_exec_event_id": "e2",
                }
            ],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("payload_elevate", atoms)

    def test_payload_elevate_ignores_temp_elevate_attempt(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "WRITE",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "write ztmp",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T12:46:00",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "EXEC",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "exec ztmp",
                    "labels_triggered": ["B_EXEC_TEMP"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T12:46:20",
                    "order_index": 2,
                },
                {
                    "event_id": "e3",
                    "event_type": "EXEC",
                    "object_key": "/tmp/ztmp",
                    "object_class": "temp_file",
                    "description": "elevate ztmp",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-13T12:46:40",
                    "order_index": 3,
                },
            ],
            "core_processes": [{"name": "micro", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertNotIn("payload_elevate", atoms)

    def test_payload_elevate_matches_staged_exec_clone_followup(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "WRITE",
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_class": "file",
                    "description": "write staged payload",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-10T18:56:20",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "EXEC",
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_class": "file",
                    "description": "exec staged payload",
                    "labels_triggered": ["B_EXEC_SUSPECT_WRITTEN"],
                    "process_guid": "p1",
                    "timestamp": "2018-04-10T18:56:39",
                    "order_index": 2,
                    "raw_event": {
                        "datum": {
                            "com.bbn.tc.schema.avro.cdm18.Event": {
                                "properties": {"map": {"cmdLine": "/home/admin/profile"}}
                            }
                        }
                    },
                },
                {
                    "event_id": "e3",
                    "event_type": "CLONE",
                    "object_key": "/home/admin/profile",
                    "object_class": "process",
                    "description": "spawn follow-up payload process",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "timestamp": "2018-04-10T18:56:54",
                    "order_index": 3,
                },
            ],
            "core_processes": [{"name": "profile", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [
                {
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "write_event_id": "e1",
                    "read_or_exec_event_id": "e2",
                }
            ],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("payload_elevate", atoms)

    def test_payload_elevate_matches_placeholder_exec_via_process_name_clone_followup(self) -> None:
        dossier = {
            "evidence_timeline": [
                {
                    "event_id": "e1",
                    "event_type": "WRITE",
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_class": "file",
                    "description": "write staged payload",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "process_name": "profile",
                    "timestamp": "2018-04-10T18:56:20",
                    "order_index": 1,
                },
                {
                    "event_id": "e2",
                    "event_type": "EXEC",
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_class": "file",
                    "description": "exec staged payload",
                    "labels_triggered": ["B_EXEC_SUSPECT_WRITTEN"],
                    "process_guid": "p1",
                    "process_name": "profile",
                    "timestamp": "2018-04-10T18:56:39",
                    "order_index": 2,
                },
                {
                    "event_id": "e3",
                    "event_type": "CLONE",
                    "object_key": "/home/admin/profile",
                    "object_class": "process",
                    "description": "spawn follow-up payload process",
                    "labels_triggered": [],
                    "process_guid": "p1",
                    "process_name": "profile",
                    "timestamp": "2018-04-10T18:56:54",
                    "order_index": 3,
                },
            ],
            "core_processes": [{"name": "profile", "labels": ["P_UNTRUSTED_CTX"]}],
            "bridge_edges": [
                {
                    "object_key": "FILE_OBJECT_BLOCK",
                    "object_labels": ["O_SUSPECT_WRITTEN_EXECUTABLE"],
                    "write_event_id": "e1",
                    "read_or_exec_event_id": "e2",
                }
            ],
        }
        graph = build_holmes_claim_graph(dossier)
        atoms = {item["behavior_type"] for item in graph["claims"]}
        self.assertIn("payload_elevate", atoms)

if __name__ == "__main__":
    unittest.main()

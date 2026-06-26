from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from apt_fusion.config import load_config
from apt_fusion.path_reason.module6_attack_reason import (
    _apply_behavior_prior_mappings,
    _claim_supports_mapping,
    _prune_attack_candidates_for_claim_context,
    _render_compact_mapping_context,
    _render_compact_path_dossier,
    _synthetic_bundle_for_attack_kb,
    _validate_mappings,
    _user_prompt_extract,
    _user_prompt_map,
)


class AttackReasonContextTests(unittest.TestCase):
    def test_synthetic_bundle_comes_from_dossier(self) -> None:
        dossier = {
            "evidence_timeline": [
                {"description": "nginx received remote request"},
                {"description": "bash executed /tmp/a.sh"},
            ],
            "core_processes": [{"name": "nginx"}, {"name": "bash"}],
            "bridge_edges": [{"object_key": "/tmp/a.sh"}],
        }
        bundle = _synthetic_bundle_for_attack_kb(dossier)
        self.assertGreaterEqual(len(bundle["events"]), 2)
        self.assertEqual(bundle["events"][0]["action"], "PATH_EVENT")
        self.assertEqual(bundle["events"][1]["action"], "PATH_EVENT")
        self.assertIn("/tmp/a.sh", bundle["ioc_candidates"]["paths"])

    def test_extract_prompt_uses_compact_dossier_text(self) -> None:
        dossier = {
            "task_id": "task_1",
            "path_id": "task_1_path_0",
            "path_type": "linear",
            "risk_level": "high",
            "risk_score": 0.91,
            "stage_coverage": ["Execution", "Command and Control"],
            "chain_kind": "entry_exec",
            "context_ids": ["ctx:web", "ctx:remote"],
            "support_object_keys": ["/tmp/a.sh", "128.55.12.73:80"],
            "support_relations": [
                "bridge: p1 -> p2 via /tmp/a.sh [write_to_exec]",
                "version: /tmp/a.sh@v0002 writers=1 readers=0 executors=1",
            ],
            "support_event_ids": ["e1", "e2", "e3"],
            "service_context_summary": "service_processes=nginx; system_objects=/etc/hosts",
            "sensitive_object_summary": "weak=/srv/share/customer.csv",
            "cleanup_object_summary": "staged_cleanup=/tmp/a.sh",
            "core_processes": [
                {"process_guid": "p1", "name": "nginx", "labels": ["P_WEB_CTX"]},
                {"process_guid": "p2", "name": "bash", "labels": ["P_UNTRUSTED_CTX"]},
            ],
            "bridge_edges": [
                {
                    "src": "p1",
                    "dst": "p2",
                    "object_key": "/tmp/a.sh",
                    "object_labels": ["O_FILE_DOWNLOADED"],
                    "write_event_id": "e1",
                    "read_or_exec_event_id": "e2",
                    "reason": "downloaded file executed",
                }
            ],
            "evidence_timeline": [
                {
                    "timestamp": "2026-05-27T10:00:00+00:00",
                    "event_id": "e1",
                    "event_type": "WRITE",
                    "object_class": "temp_file",
                    "object_key": "/tmp/a.sh",
                    "object_labels": ["O_FILE_DOWNLOADED"],
                    "process_guid": "p1",
                    "process_name": "nginx",
                    "labels_triggered": ["O_FILE_DOWNLOADED"],
                    "description": "nginx WRITE a.sh",
                }
            ],
        }
        compact = _render_compact_path_dossier(dossier)
        prompt = _user_prompt_extract(dossier)
        self.assertIn("TIMELINE", compact)
        self.assertIn("PROCESSES", compact)
        self.assertIn("BRIDGES", compact)
        self.assertIn("SUPPORT", compact)
        self.assertIn("SERVICE_CONTEXT", compact)
        self.assertIn("SENSITIVE_OBJECTS", compact)
        self.assertIn("CLEANUP_OBJECTS", compact)
        self.assertIn("chain_kind=entry_exec", compact)
        self.assertIn("contexts=ctx:web,ctx:remote", compact)
        self.assertIn("support_objects=/tmp/a.sh,128.55.12.73:80", compact)
        self.assertIn("support_relations", compact)
        self.assertIn("support_events=e1,e2,e3", compact)
        self.assertIn("Reasoning unit:", prompt)
        self.assertIn("PREMATCHED_TTP_ATOMS", prompt)
        self.assertIn("SUPPORT", prompt)
        self.assertIn("TIMELINE", prompt)
        self.assertNotIn("\"event_type\"", prompt)
        self.assertNotIn("\"bridge_edges\"", prompt)

    def test_mapping_context_accepts_list_hints(self) -> None:
        context = {
            "path_dossier": {
                "task_id": "task_1",
                "path_id": "task_1_path_0",
                "path_type": "linear",
                "risk_level": "high",
                "risk_score": 0.91,
                "stage_coverage": ["Execution"],
                "core_processes": [{"process_guid": "p1", "name": "bash", "labels": ["P_UNTRUSTED_CTX"]}],
                "bridge_edges": [],
                "evidence_timeline": [],
            },
            "claims": [
                {
                    "claim_id": "c1",
                    "behavior_type": "download_and_exec",
                    "confidence": 0.9,
                    "evidence_event_ids": ["e1", "e2"],
                    "statement": "bash executed a file written by nginx",
                }
            ],
            "claim_graph": {
                "edges": [{"src_claim_id": "c0", "dst_claim_id": "c1", "relation": "prerequisite"}],
                "diagnostics": {"matched_atoms": ["download_and_exec"]},
            },
            "claim_attack_hints": [
                {
                    "claim_id": "c1",
                    "behavior_type": "download_and_exec",
                    "allowed_tactic_ids": ["TA0001", "TA0002"],
                    "preferred_tactic_id": "TA0002",
                    "preferred_technique_id": "T1059",
                }
            ],
            "attack_candidates": {
                "tactics": [{"external_id": "TA0002", "name": "Execution", "score": 0.9, "tactic_ids": ["TA0002"]}],
                "techniques": [{"external_id": "T1059", "name": "Command and Scripting Interpreter", "score": 0.8}],
            },
        }
        compact = _render_compact_mapping_context(context)
        prompt = _user_prompt_map(context)
        self.assertIn("CLAIM_HINTS", compact)
        self.assertIn("prefer_tactic=TA0002", compact)
        self.assertIn("allow_tactics=TA0001,TA0002", compact)
        self.assertIn("CAUSAL_RELATIONS", prompt)
        self.assertIn("TACTIC_CANDIDATES", prompt)
        self.assertNotIn("\"claim_attack_hints\"", prompt)

    def test_mapping_prompt_omits_claim_hints_when_disabled(self) -> None:
        context = {
            "path_dossier": {
                "task_id": "task_1",
                "path_id": "task_1_path_0",
                "path_type": "linear",
                "risk_level": "high",
                "risk_score": 0.88,
                "stage_coverage": ["Execution"],
                "core_processes": [{"process_guid": "p1", "name": "bash", "labels": ["P_UNTRUSTED_CTX"]}],
                "bridge_edges": [],
                "evidence_timeline": [],
            },
            "claims": [
                {
                    "claim_id": "c1",
                    "behavior_type": "credential_read",
                    "confidence": 0.8,
                    "evidence_event_ids": ["e1"],
                    "statement": "bash read credential material",
                }
            ],
            "claim_attack_hints": [],
            "attack_candidates": {
                "tactics": [{"external_id": "TA0006", "name": "Credential Access", "score": 0.9, "tactic_ids": ["TA0006"]}],
                "techniques": [],
            },
        }
        compact = _render_compact_mapping_context(context)
        prompt = _user_prompt_map(context, include_claim_attack_hints=False)
        self.assertNotIn("CLAIM_HINTS", compact)
        self.assertNotIn("claim_attack_hints", prompt)
        self.assertIn("TACTIC_CANDIDATES", prompt)

    def test_claim_supports_mapping_can_bypass_behavior_priors(self) -> None:
        claim = {"claim_id": "c1", "behavior_type": "credential_read", "statement": "read credentials"}
        tactic_choice = {"external_id": "TA0002", "name": "Execution"}
        self.assertFalse(_claim_supports_mapping({}, claim, tactic_choice, None))
        self.assertTrue(
            _claim_supports_mapping(
                {},
                claim,
                tactic_choice,
                None,
                enforce_behavior_priors=False,
            )
        )

    def test_apply_behavior_prior_mappings_is_noop_when_disabled(self) -> None:
        cfg = SimpleNamespace(claim_attack_prior_mode="disabled")
        mappings = [
            {
                "tactic_id": "TA0002",
                "tactic": "Execution",
                "technique_id": "T1059",
                "technique": "Command and Scripting Interpreter",
                "evidence_claim_ids": ["c1"],
                "confidence": 0.81,
                "gaps": [],
            }
        ]
        result = _apply_behavior_prior_mappings(cfg, {}, [], {}, mappings)
        self.assertEqual(result, mappings)

    def test_claim_attack_prior_mode_loads_default_and_disabled(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        full_cfg = load_config(
            repo_root / "configs" / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_gtonly_20260603.yaml"
        )
        disabled_cfg = load_config(
            repo_root
            / "configs"
            / "fusion_cloud_trace_train_stats_latefusion_bonus1_llama31_microstep2b_no_attack_priors_gtonly_20260608.yaml"
        )
        self.assertEqual(full_cfg.claim_attack_prior_mode, "full")
        self.assertEqual(disabled_cfg.claim_attack_prior_mode, "disabled")

    def test_tactics_only_prompt_omits_technique_candidates(self) -> None:
        context = {
            "attack_mapping_scope": "tactics_only",
            "path_dossier": {
                "task_id": "task_1",
                "path_id": "task_1_path_0",
                "path_type": "linear",
                "risk_level": "high",
                "risk_score": 0.91,
                "stage_coverage": ["Execution"],
                "family_tags": ["callback_c2"],
                "core_processes": [{"process_guid": "p1", "name": "bash", "labels": ["P_UNTRUSTED_CTX"]}],
                "bridge_edges": [],
                "evidence_timeline": [],
            },
            "claims": [
                {
                    "claim_id": "c1",
                    "behavior_type": "cnc_communication",
                    "confidence": 0.9,
                    "evidence_event_ids": ["e1"],
                    "statement": "bash repeatedly connected to a remote endpoint",
                }
            ],
            "claim_graph": {"edges": [], "diagnostics": {"matched_atoms": ["cnc_communication"]}},
            "claim_attack_hints": [],
            "attack_candidates": {
                "tactics": [{"external_id": "TA0011", "name": "Command and Control", "score": 0.9, "tactic_ids": ["TA0011"]}],
                "techniques": [{"external_id": "T1071.001", "name": "Web Protocols", "score": 0.8}],
            },
        }
        compact = _render_compact_mapping_context(context)
        prompt = _user_prompt_map(context, include_claim_attack_hints=False)
        self.assertIn("TACTIC_CANDIDATES", compact)
        self.assertNotIn("TECHNIQUE_CANDIDATES", compact)
        self.assertNotIn("TECHNIQUE_CANDIDATES", prompt)
        self.assertIn("tactic-only", prompt.lower())

    def test_validate_mappings_normalizes_event_ids_to_claim_ids(self) -> None:
        cfg = SimpleNamespace(
            claim_attack_prior_mode="disabled",
            attack_mapping_scope="tactics_only",
            attack_kb_stix_path=None,
            attack_kb_embedding_model_name="sentence-transformers/all-MiniLM-L6-v2",
            attack_kb_enable_vector=False,
        )
        claims = [
            {
                "claim_id": "c1",
                "behavior_type": "cnc_communication",
                "statement": "bash talked to a remote endpoint",
                "evidence_event_ids": ["e1", "e2"],
                "confidence": 0.9,
            }
        ]
        attack_candidates = {
            "tactics": [{"external_id": "TA0011", "name": "Command and Control", "tactic_ids": ["TA0011"]}],
            "techniques": [],
        }
        mappings, summary = _validate_mappings(
            cfg,
            {},
            [
                {
                    "tactic_id": "TA0011",
                    "tactic": "Command and Control",
                    "technique_id": "",
                    "technique": "",
                    "evidence_claim_ids": ["e1"],
                    "confidence": 0.88,
                    "gaps": [],
                }
            ],
            attack_candidates,
            claims,
        )
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["evidence_claim_ids"], ["c1"])
        self.assertEqual(summary["raw_event_id_ref_count"], 1)
        self.assertEqual(summary["normalized_event_id_claim_ref_count"], 1)
        self.assertEqual(summary["kept_mapping_count"], 1)

    def test_validate_mappings_deduplicates_claim_and_event_refs(self) -> None:
        cfg = SimpleNamespace(
            claim_attack_prior_mode="disabled",
            attack_mapping_scope="tactics_only",
            attack_kb_stix_path=None,
            attack_kb_embedding_model_name="sentence-transformers/all-MiniLM-L6-v2",
            attack_kb_enable_vector=False,
        )
        claims = [
            {
                "claim_id": "c1",
                "behavior_type": "cnc_communication",
                "statement": "bash talked to a remote endpoint",
                "evidence_event_ids": ["e1"],
                "confidence": 0.9,
            }
        ]
        attack_candidates = {
            "tactics": [{"external_id": "TA0011", "name": "Command and Control", "tactic_ids": ["TA0011"]}],
            "techniques": [],
        }
        mappings, summary = _validate_mappings(
            cfg,
            {},
            [
                {
                    "tactic_id": "TA0011",
                    "tactic": "Command and Control",
                    "technique_id": "",
                    "technique": "",
                    "evidence_claim_ids": ["c1", "e1", "c1", "missing"],
                    "confidence": 0.88,
                    "gaps": [],
                }
            ],
            attack_candidates,
            claims,
        )
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["evidence_claim_ids"], ["c1"])
        self.assertEqual(summary["raw_claim_id_ref_count"], 2)
        self.assertEqual(summary["raw_event_id_ref_count"], 1)
        self.assertEqual(summary["raw_unknown_id_ref_count"], 1)
        self.assertEqual(summary["mappings_with_unknown_id_refs_count"], 1)

    def test_validate_mappings_tracks_normalized_empty_mappings(self) -> None:
        cfg = SimpleNamespace(
            claim_attack_prior_mode="disabled",
            attack_mapping_scope="tactics_only",
            attack_kb_stix_path=None,
            attack_kb_embedding_model_name="sentence-transformers/all-MiniLM-L6-v2",
            attack_kb_enable_vector=False,
        )
        claims = [
            {
                "claim_id": "c1",
                "behavior_type": "cnc_communication",
                "statement": "bash talked to a remote endpoint",
                "evidence_event_ids": ["e1"],
                "confidence": 0.9,
            }
        ]
        attack_candidates = {
            "tactics": [{"external_id": "TA0011", "name": "Command and Control", "tactic_ids": ["TA0011"]}],
            "techniques": [],
        }
        mappings, summary = _validate_mappings(
            cfg,
            {},
            [
                {
                    "tactic_id": "TA0011",
                    "tactic": "Command and Control",
                    "technique_id": "",
                    "technique": "",
                    "evidence_claim_ids": ["unknown_event_id"],
                    "confidence": 0.88,
                    "gaps": [],
                }
            ],
            attack_candidates,
            claims,
        )
        self.assertEqual(mappings, [])
        self.assertEqual(summary["mappings_normalized_to_empty_count"], 1)
        self.assertEqual(summary["kept_mapping_count"], 0)

    def test_browser_credential_submit_context_prunes_candidate_tactics(self) -> None:
        cfg = SimpleNamespace(attack_mapping_scope="tactics_only")
        dossier = {
            "family_tags": ["mail_browser_context_tail", "initial_or_drop_exec"],
            "core_processes": [{"name": "firefox"}, {"name": "fluxbox"}],
        }
        claims = [
            {"claim_id": "c1", "behavior_type": "credential_submit"},
            {"claim_id": "c2", "behavior_type": "untrusted_read"},
            {"claim_id": "c3", "behavior_type": "untrusted_file_exec"},
        ]
        attack_candidates = {
            "tactics": [
                {"external_id": "TA0001", "name": "Initial Access", "tactic_ids": ["TA0001"]},
                {"external_id": "TA0002", "name": "Execution", "tactic_ids": ["TA0002"]},
                {"external_id": "TA0006", "name": "Credential Access", "tactic_ids": ["TA0006"]},
                {"external_id": "TA0007", "name": "Discovery", "tactic_ids": ["TA0007"]},
                {"external_id": "TA0003", "name": "Persistence", "tactic_ids": ["TA0003"]},
            ],
            "techniques": [
                {"external_id": "T1110", "name": "Brute Force", "tactic_ids": ["TA0006"]},
                {"external_id": "T1176.001", "name": "Browser Extensions", "tactic_ids": ["TA0003"]},
            ],
        }
        pruned, reason = _prune_attack_candidates_for_claim_context(cfg, dossier, claims, attack_candidates)
        self.assertEqual(reason, "browser_credential_submit_context")
        self.assertEqual(
            [item["external_id"] for item in pruned["tactics"]],
            ["TA0001", "TA0002", "TA0006"],
        )
        self.assertEqual([item["external_id"] for item in pruned["techniques"]], ["T1110"])

    def test_non_browser_context_does_not_prune_candidate_tactics(self) -> None:
        cfg = SimpleNamespace(attack_mapping_scope="tactics_only")
        dossier = {
            "family_tags": ["initial_or_drop_exec", "callback_c2"],
            "core_processes": [{"name": "bash"}],
        }
        claims = [
            {"claim_id": "c1", "behavior_type": "credential_submit"},
            {"claim_id": "c2", "behavior_type": "untrusted_read"},
            {"claim_id": "c3", "behavior_type": "untrusted_file_exec"},
        ]
        attack_candidates = {
            "tactics": [
                {"external_id": "TA0001", "name": "Initial Access", "tactic_ids": ["TA0001"]},
                {"external_id": "TA0007", "name": "Discovery", "tactic_ids": ["TA0007"]},
            ],
            "techniques": [],
        }
        pruned, reason = _prune_attack_candidates_for_claim_context(cfg, dossier, claims, attack_candidates)
        self.assertEqual(reason, "")
        self.assertEqual(pruned, attack_candidates)


if __name__ == "__main__":
    unittest.main()


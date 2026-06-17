from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from apt_fusion.common import ensure_dir, load_json, save_json
from apt_fusion.config import FusionConfig
from apt_fusion.path_reason.attack_kb import retrieve_attack_candidates
from apt_fusion.path_reason.holmes_claims import build_holmes_claim_graph
from apt_fusion.path_reason.module6_attack_reason import (
    _apply_behavior_prior_mappings,
    _attack_mapping_scope,
    _behavior_prior_hints_for_claims,
    _claim_attack_priors_enabled,
    _claim_graphs_dir,
    _deterministic_tactic_mapping_enabled,
    _deterministic_tactic_mappings,
    _dossiers_dir,
    _empty_mapping_validation_summary,
    _evidence_support_rate,
    _fallback_claims,
    _filter_attack_candidates_for_scope,
    _llm_inputs_dir,
    _markdown_dir,
    _render_claim_graph_markdown,
    _render_markdown,
    _reports_dir,
    _report_index_path,
    _slugify,
    _summary_path,
    _synthetic_bundle_for_attack_kb,
    _tactic_mapping_mode,
    _validate_claims,
    _validate_iocs,
    _validate_mappings,
)


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def replay_module6_reason(cfg: FusionConfig, baseline_root: Path) -> dict[str, str]:
    baseline_module6_root = baseline_root / "module6_reason"
    baseline_report_index_path = baseline_module6_root / "report_index.json"
    if not baseline_report_index_path.exists():
        raise FileNotFoundError(f"baseline report_index missing: {baseline_report_index_path}")
    baseline_report_index = load_json(baseline_report_index_path)
    if not isinstance(baseline_report_index, list):
        raise ValueError(f"baseline report_index is not a list: {baseline_report_index_path}")

    ensure_dir(cfg.module6_reason_dir)
    for folder in [_reports_dir(cfg), _dossiers_dir(cfg), _markdown_dir(cfg), _llm_inputs_dir(cfg), _claim_graphs_dir(cfg)]:
        ensure_dir(folder)

    report_index: list[dict[str, Any]] = []
    report_count = 0
    for item in baseline_report_index:
        if not isinstance(item, dict):
            continue
        dossier_path = Path(str(item.get("dossier_path", "")).strip())
        llm_input_path = Path(str(item.get("llm_input_path", "")).strip())
        if not dossier_path.exists() or not llm_input_path.exists():
            continue

        dossier = load_json(dossier_path)
        llm_inputs = load_json(llm_input_path)
        if not isinstance(dossier, dict) or not isinstance(llm_inputs, dict):
            continue

        task_id = str(dossier.get("task_id", "")).strip()
        path_id = str(dossier.get("path_id", "")).strip()
        if not task_id or not path_id:
            continue

        raw_extract = dict((((llm_inputs.get("extract", {}) or {}).get("response", {}) or {})))
        raw_mapping = dict((((llm_inputs.get("mapping", {}) or {}).get("response", {}) or {})))

        claim_graph = build_holmes_claim_graph(dossier)
        claims = _fallback_claims(dossier, _validate_claims(list(raw_extract.get("claims", [])), dossier))
        claim_graph = {
            **claim_graph,
            "claims": claims,
            "edges": [edge for edge in claim_graph.get("edges", []) if isinstance(edge, dict)],
        }
        iocs = _validate_iocs(list(raw_extract.get("iocs", [])))
        attack_candidates = retrieve_attack_candidates(cfg, _synthetic_bundle_for_attack_kb(dossier), claims)
        if _claim_attack_priors_enabled(cfg):
            attack_candidates = _augment_candidates(cfg, dossier, attack_candidates, claims)
            claim_attack_hints = _behavior_prior_hints_for_claims(cfg, dossier, claims)
        else:
            claim_attack_hints = []
        attack_candidates = _filter_attack_candidates_for_scope(cfg, attack_candidates)

        mapping_context = {
            "path_dossier": dossier,
            "claims": claims,
            "claim_graph": claim_graph,
            "claim_attack_hints": claim_attack_hints,
            "attack_candidates": attack_candidates,
            "attack_mapping_scope": _attack_mapping_scope(cfg),
        }
        if _deterministic_tactic_mapping_enabled(cfg):
            mappings = _deterministic_tactic_mappings(cfg, claims, attack_candidates)
            mapping_validation_summary = _empty_mapping_validation_summary()
        else:
            mappings, mapping_validation_summary = _validate_mappings(
                cfg,
                dossier,
                list(raw_mapping.get("attack_mappings", [])),
                attack_candidates,
                claims,
            )
            mappings = _apply_behavior_prior_mappings(cfg, dossier, claims, attack_candidates, mappings)

        report = {
            "task_id": task_id,
            "path_id": path_id,
            "path_type": dossier.get("path_type", ""),
            "risk_level": dossier.get("risk_level", ""),
            "risk_score": dossier.get("risk_score", 0.0),
            "stage_coverage": dossier.get("stage_coverage", []),
            "family_tags": dossier.get("family_tags", []),
            "summary": str(raw_extract.get("summary", "")).strip() or str(dossier.get("summary", "")).strip(),
            "claims": claims,
            "claim_graph": claim_graph,
            "extracted_behaviors": claims,
            "iocs": iocs,
            "attack_candidates": attack_candidates,
            "attack_mappings": mappings,
            "attack_mapping_scope": _attack_mapping_scope(cfg),
            "tactic_mapping_mode": _tactic_mapping_mode(cfg),
            "mapping_validation_summary": mapping_validation_summary,
            "gaps": [
                *[str(value).strip() for value in raw_extract.get("gaps", []) if str(value).strip()],
                *[str(value).strip() for value in raw_mapping.get("gaps", []) if str(value).strip()],
            ],
            "source_candidate_paths_path": str(item.get("source_candidate_paths_path", "")),
            "evidence_support_rate": _evidence_support_rate(claims, mappings),
        }

        llm_inputs_out = json.loads(json.dumps(llm_inputs))
        llm_inputs_out.setdefault("replay", {})
        llm_inputs_out["replay"] = {
            "baseline_root": str(baseline_root),
            "replayed": True,
        }
        mapping_record = llm_inputs_out.get("mapping", {})
        if isinstance(mapping_record, dict):
            mapping_record["validation_summary"] = mapping_validation_summary

        slug = _slugify(path_id)
        out_dossier_path = _dossiers_dir(cfg) / f"{slug}.json"
        report_path = _reports_dir(cfg) / f"{slug}.report.json"
        markdown_path = _markdown_dir(cfg) / f"{slug}.md"
        llm_input_out_path = _llm_inputs_dir(cfg) / f"{slug}.input.json"
        claim_graph_path = _claim_graphs_dir(cfg) / f"{slug}.claim_graph.json"
        claim_graph_markdown_path = _claim_graphs_dir(cfg) / f"{slug}.claim_graph.md"

        save_json(out_dossier_path, dossier)
        save_json(report_path, report)
        _write_text(markdown_path, _render_markdown(report))
        save_json(llm_input_out_path, llm_inputs_out)
        save_json(claim_graph_path, claim_graph)
        _write_text(claim_graph_markdown_path, _render_claim_graph_markdown(claim_graph))
        report_index.append(
            {
                "task_id": task_id,
                "path_id": path_id,
                "report_path": str(report_path),
                "dossier_path": str(out_dossier_path),
                "markdown_path": str(markdown_path),
                "llm_input_path": str(llm_input_out_path),
                "claim_graph_path": str(claim_graph_path),
                "source_candidate_paths_path": str(item.get("source_candidate_paths_path", "")),
            }
        )
        report_count += 1

    save_json(_report_index_path(cfg), report_index)
    save_json(
        _summary_path(cfg),
        {
            "report_count": report_count,
            "claim_attack_prior_mode": cfg.claim_attack_prior_mode,
            "attack_mapping_scope": _attack_mapping_scope(cfg),
            "tactic_mapping_mode": _tactic_mapping_mode(cfg),
            "replayed_from_baseline_root": str(baseline_root),
            "reports_dir": str(_reports_dir(cfg)),
            "dossiers_dir": str(_dossiers_dir(cfg)),
            "markdown_dir": str(_markdown_dir(cfg)),
            "llm_inputs_dir": str(_llm_inputs_dir(cfg)),
            "claim_graphs_dir": str(_claim_graphs_dir(cfg)),
        },
    )
    return {
        "summary": str(_summary_path(cfg)),
        "report_index": str(_report_index_path(cfg)),
        "reports_dir": str(_reports_dir(cfg)),
        "dossiers_dir": str(_dossiers_dir(cfg)),
        "markdown_dir": str(_markdown_dir(cfg)),
        "llm_inputs_dir": str(_llm_inputs_dir(cfg)),
        "claim_graphs_dir": str(_claim_graphs_dir(cfg)),
    }


def _augment_candidates(cfg: FusionConfig, dossier: dict[str, Any], attack_candidates: dict[str, Any], claims: list[dict[str, Any]]) -> dict[str, Any]:
    from apt_fusion.path_reason.module6_attack_reason import _augment_attack_candidates_with_behavior_priors

    return _augment_attack_candidates_with_behavior_priors(cfg, dossier, attack_candidates, claims)


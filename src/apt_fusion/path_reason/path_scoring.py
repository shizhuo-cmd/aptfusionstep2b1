from __future__ import annotations

from typing import Any

from .path_schemas import CandidatePath, TaskPrior


def score_candidate_paths(paths: list[CandidatePath], prior: TaskPrior, rules: Any) -> list[CandidatePath]:
    for path in paths:
        label_score = sum(float(rules.get(f"scoring.labels.{label}", 0.0) or 0.0) for label in path.labels)
        combo_score = _combo_score(path, rules)
        stage_score = 12.0 * len(path.stage_coverage)
        bridge_score = sum(edge.confidence * 12.0 for edge in path.bridge_edges)
        prior_score = _prior_score(path, prior, rules)
        penalties = _penalty_score(path, rules)
        path.risk_score = max(0.0, label_score + combo_score + stage_score + bridge_score + prior_score - penalties)
        path.risk_level = _risk_level(path, rules)
    paths.sort(key=lambda item: (-item.risk_score, -len(item.stage_coverage), item.path_id))
    return paths


def _combo_score(path: CandidatePath, rules: Any) -> float:
    combos = rules.get("scoring.combos", {}) or {}
    labels = set(path.labels)
    score = 0.0
    if {"B_EXTERNAL_RECV", "B_EXEC_TEMP"} <= labels or {"B_EXTERNAL_RECV", "B_EXEC_DOWNLOADED"} <= labels:
        score += float(combos.get("external_plus_temp_exec", 0.0) or 0.0)
    if {"B_EXTERNAL_RECV", "B_SHELL_SPAWN"} <= labels:
        score += float(combos.get("external_plus_shell", 0.0) or 0.0)
    if {"B_EXEC_DOWNLOADED", "B_READ_CRED"} <= labels or {"B_EXEC_SUSPECT_WRITTEN", "B_READ_CRED"} <= labels:
        score += float(combos.get("suspicious_exec_plus_sensitive_read", 0.0) or 0.0)
    if {"B_READ_CRED", "B_EXTERNAL_SEND"} <= labels or {"B_READ_BUSINESS", "B_EXTERNAL_SEND"} <= labels:
        score += float(combos.get("sensitive_read_plus_external_send", 0.0) or 0.0)
    if {"B_EXEC_DOWNLOADED", "B_WRITE_PERSISTENCE"} <= labels or {"B_EXEC_SUSPECT_WRITTEN", "B_WRITE_PERSISTENCE"} <= labels:
        score += float(combos.get("suspicious_exec_plus_persistence", 0.0) or 0.0)
    if {"B_EXEC_DOWNLOADED", "B_LATERAL_CONNECT"} <= labels or {"B_EXEC_SUSPECT_WRITTEN", "B_LATERAL_CONNECT"} <= labels:
        score += float(combos.get("suspicious_exec_plus_lateral", 0.0) or 0.0)
    if len(path.process_chain) >= 3 and len(path.stage_coverage) >= 3:
        score += float(combos.get("continuous_labeled_chain", 0.0) or 0.0)
    return score


def _prior_score(path: CandidatePath, prior: TaskPrior, rules: Any) -> float:
    score_rules = rules.get("scoring.apt_fusion_prior", {}) or {}
    total = float(prior.task_score) * float(score_rules.get("graph_task_score_weight", 20.0) or 20.0)
    rank_weight = float(score_rules.get("top_process_rank_weight", 10.0) or 10.0)
    top_process_rank = {
        str(item.get("process_id", "")).strip(): idx
        for idx, item in enumerate(prior.top_processes)
        if str(item.get("process_id", "")).strip()
    }
    for process_guid in path.process_chain:
        if process_guid in top_process_rank:
            total += max(1.0, rank_weight - float(top_process_rank[process_guid]))
    top_edge_rank = {
        (str(item.get("src", "")).strip(), str(item.get("dst", "")).strip()): idx
        for idx, item in enumerate(prior.top_edges)
        if str(item.get("src", "")).strip() and str(item.get("dst", "")).strip()
    }
    edge_weight = float(score_rules.get("top_edge_rank_weight", 10.0) or 10.0)
    for src, dst in zip(path.process_chain, path.process_chain[1:]):
        if (src, dst) in top_edge_rank:
            total += max(1.0, edge_weight - float(top_edge_rank[(src, dst)]))
    if prior.first_event and prior.last_event and path.time_range[0] and path.time_range[1]:
        if path.time_range[0] >= prior.first_event and path.time_range[1] <= prior.last_event:
            total += float(score_rules.get("in_task_time_range_bonus", 8.0) or 8.0)
        else:
            total -= float(score_rules.get("out_of_task_time_range_penalty", 12.0) or 12.0)
    return total


def _penalty_score(path: CandidatePath, rules: Any) -> float:
    penalties = rules.get("scoring.penalties", {}) or {}
    total = 0.0
    labels = set(path.labels)
    if "ExecutionStrong" not in path.stage_coverage and "ExecutionWeak" in path.stage_coverage:
        total += float(penalties.get("weak_execution_only", 0.0) or 0.0)
    if len(path.bridge_edges) >= 4:
        total += float(penalties.get("high_reuse_object", 0.0) or 0.0)
    if len(path.stage_coverage) == 1 and labels.intersection({"B_READ_CRED", "B_READ_HISTORY", "B_READ_BUSINESS"}):
        total += float(penalties.get("single_point_sensitive_read", 0.0) or 0.0)
    return total


def _risk_level(path: CandidatePath, rules: Any) -> str:
    risk_levels = rules.get("path_search.risk_levels", {}) or {}
    if path.risk_score >= float(risk_levels.get("high", 80.0) or 80.0):
        return "HIGH"
    if path.risk_score >= float(risk_levels.get("medium", 50.0) or 50.0):
        return "MEDIUM"
    if path.risk_score >= float(risk_levels.get("low", 30.0) or 30.0):
        return "LOW"
    return "INFO"


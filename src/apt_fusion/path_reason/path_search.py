from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from .path_schemas import BridgeEdge, CandidatePath, ProcessState

_STAGE_ORDER = ["Entry", "ExecutionWeak", "ExecutionStrong", "TargetAccess", "FollowUp"]


def search_candidate_paths(
    task_id: str,
    process_states: dict[str, ProcessState],
    bridge_edges: list[BridgeEdge],
    rules: Any,
) -> list[CandidatePath]:
    adjacency: dict[str, list[tuple[str, BridgeEdge | None]]] = defaultdict(list)
    bridge_by_pair: dict[tuple[str, str], list[BridgeEdge]] = defaultdict(list)
    for state in process_states.values():
        parent = str(state.parent_process_guid or "").strip()
        if parent and parent in process_states:
            adjacency[parent].append((state.process_guid, None))
    for edge in bridge_edges:
        adjacency[edge.src_process_guid].append((edge.dst_process_guid, edge))
        bridge_by_pair[(edge.src_process_guid, edge.dst_process_guid)].append(edge)

    seeds = [guid for guid, state in process_states.items() if _is_seed_state(state)]
    max_depth = int(rules.get("path_search.max_depth", 6))
    max_span_minutes = float(rules.get("path_search.max_total_span_minutes", 180))
    max_gap_minutes = float(rules.get("path_search.max_time_gap_minutes", 120))
    top_k = int(rules.get("path_search.top_k", 20))
    pre_rank_limit = max(top_k, int(rules.get("path_search.pre_rank_limit", max(top_k * 6, top_k))))
    discovered: dict[tuple[str, ...], CandidatePath] = {}
    for seed in seeds:
        _dfs(
            seed,
            adjacency,
            bridge_by_pair,
            process_states,
            rules,
            max_depth,
            max_span_minutes,
            max_gap_minutes,
            discovered,
            current=[seed],
            current_bridges=[],
            start_time=process_states[seed].start_time,
            last_time=process_states[seed].start_time,
        )

    results = list(discovered.values())
    results.sort(key=lambda item: (-len(item.stage_coverage), len(item.process_chain), item.path_id))
    trimmed = results[:pre_rank_limit]
    for index, item in enumerate(trimmed):
        item.path_id = f"{task_id}_candidate_{index + 1:03d}"
    return trimmed


def _dfs(
    node: str,
    adjacency: dict[str, list[tuple[str, BridgeEdge | None]]],
    bridge_by_pair: dict[tuple[str, str], list[BridgeEdge]],
    process_states: dict[str, ProcessState],
    rules: Any,
    max_depth: int,
    max_span_minutes: float,
    max_gap_minutes: float,
    discovered: dict[tuple[str, ...], CandidatePath],
    *,
    current: list[str],
    current_bridges: list[BridgeEdge],
    start_time: datetime | None,
    last_time: datetime | None,
) -> None:
    candidate = _candidate_from_chain(current, current_bridges, process_states, rules)
    if candidate is not None:
        key = tuple(candidate.process_chain)
        existing = discovered.get(key)
        if existing is None or len(candidate.stage_coverage) > len(existing.stage_coverage):
            discovered[key] = candidate
    if len(current) >= max_depth:
        return
    for neighbor, bridge in adjacency.get(node, []):
        if neighbor in current:
            continue
        edge_time = _edge_time(process_states.get(neighbor), bridge)
        if not _time_is_valid(start_time, last_time, edge_time, max_span_minutes, max_gap_minutes):
            continue
        _dfs(
            neighbor,
            adjacency,
            bridge_by_pair,
            process_states,
            rules,
            max_depth,
            max_span_minutes,
            max_gap_minutes,
            discovered,
            current=current + [neighbor],
            current_bridges=current_bridges + ([bridge] if bridge is not None else []),
            start_time=start_time or edge_time,
            last_time=edge_time or last_time,
        )


def _candidate_from_chain(
    chain: list[str],
    bridges: list[BridgeEdge],
    process_states: dict[str, ProcessState],
    rules: Any,
) -> CandidatePath | None:
    labels: set[str] = set()
    stages: list[str] = []
    for guid in chain:
        state = process_states.get(guid)
        if state is None:
            continue
        labels.update(state.all_labels())
        for stage in _stages_for_labels(state.all_labels(), rules):
            if stage not in stages:
                stages.append(stage)
    if not _stages_make_candidate(stages, rules):
        return None
    warnings: list[str] = []
    if "ExecutionStrong" not in stages and "ExecutionWeak" in stages:
        warnings.append("Path is driven by weak execution evidence only.")
    return CandidatePath(
        path_id="",
        task_id=process_states[chain[0]].task_id if chain and chain[0] in process_states else "",
        process_chain=list(chain),
        bridge_edges=list(bridges),
        stage_coverage=sorted(stages, key=lambda item: _STAGE_ORDER.index(item) if item in _STAGE_ORDER else 99),
        labels=sorted(labels),
        risk_score=0.0,
        risk_level="LOW",
        path_type="-".join(sorted(stages, key=lambda item: _STAGE_ORDER.index(item) if item in _STAGE_ORDER else 99)),
        time_range=(_chain_start(chain, process_states), _chain_end(chain, process_states, bridges)),
        evidence_timeline=[],
        summary="",
        warnings=warnings,
    )


def _is_seed_state(state: ProcessState) -> bool:
    return bool(state.behavior_labels or state.status_labels.intersection({"P_WEB_CTX", "P_REMOTE_CTX", "P_UNTRUSTED_CTX", "P_SUSPECT_CTRL_CTX"}))


def _stages_for_labels(labels: set[str], rules: Any) -> list[str]:
    stages: list[str] = []
    label_meta = rules.get("labels", {})
    for label in sorted(labels):
        meta = label_meta.get(label, {}) if isinstance(label_meta, dict) else {}
        stage = str(meta.get("stage_mapping", "")).strip()
        if stage and stage != "None" and stage not in stages:
            stages.append(stage)
    return stages


def _stages_make_candidate(stages: list[str], rules: Any) -> bool:
    stage_set = set(stages)
    for group in rules.get("path_search.strong_stage_sets", []):
        if set(group).issubset(stage_set):
            return True
    for group in rules.get("path_search.medium_upgrade_rules", []):
        if set(group).issubset(stage_set):
            return True
    for group in rules.get("path_search.weak_stage_sets", []):
        if set(group).issubset(stage_set):
            return True
    return False


def _edge_time(state: ProcessState | None, bridge: BridgeEdge | None) -> datetime | None:
    if bridge is not None:
        return bridge.read_or_exec_time or bridge.write_time
    return state.start_time if state is not None else None


def _time_is_valid(
    start_time: datetime | None,
    last_time: datetime | None,
    edge_time: datetime | None,
    max_span_minutes: float,
    max_gap_minutes: float,
) -> bool:
    if edge_time is None:
        return True
    if last_time is not None and edge_time < last_time:
        return False
    if start_time is not None and (edge_time - start_time).total_seconds() > max_span_minutes * 60.0:
        return False
    if last_time is not None and (edge_time - last_time).total_seconds() > max_gap_minutes * 60.0:
        return False
    return True


def _chain_start(chain: list[str], process_states: dict[str, ProcessState]) -> datetime | None:
    values = [process_states[guid].start_time for guid in chain if guid in process_states and process_states[guid].start_time]
    return min(values) if values else None


def _chain_end(chain: list[str], process_states: dict[str, ProcessState], bridges: list[BridgeEdge]) -> datetime | None:
    values = [process_states[guid].end_time for guid in chain if guid in process_states and process_states[guid].end_time]
    values.extend([edge.read_or_exec_time for edge in bridges if edge.read_or_exec_time is not None])
    return max(values) if values else None


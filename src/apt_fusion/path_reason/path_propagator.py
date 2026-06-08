from __future__ import annotations

from collections import deque
from typing import Any

from .object_classifier import classify_process_type
from .path_schemas import ProcessState


def propagate_status_labels(process_states: dict[str, ProcessState], rules: Any) -> None:
    child_map: dict[str, list[str]] = {}
    for process_guid, state in process_states.items():
        parent = str(state.parent_process_guid or "").strip()
        if parent:
            child_map.setdefault(parent, []).append(process_guid)

    allowed_labels = {str(item).strip() for item in rules.get("propagation.status_labels", [])}
    max_depth_by_label = {
        str(key): int(value)
        for key, value in (rules.get("propagation.max_depth_by_label", {}) or {}).items()
    }
    common_daemons = {str(item).lower() for item in rules.get("process_names.common_daemons", [])}
    allowed_child_types = {str(item).strip() for item in rules.get("propagation.daemon_child_allow_types", [])}

    for process_guid, state in process_states.items():
        for label in sorted(state.status_labels):
            if label not in allowed_labels:
                continue
            max_depth = max_depth_by_label.get(label, 0)
            if max_depth <= 0:
                continue
            queue = deque([(process_guid, 0)])
            visited = {process_guid}
            while queue:
                current_guid, depth = queue.popleft()
                if depth >= max_depth:
                    continue
                for child_guid in child_map.get(current_guid, []):
                    if child_guid in visited:
                        continue
                    visited.add(child_guid)
                    child_state = process_states.get(child_guid)
                    if child_state is None:
                        continue
                    current_state = process_states.get(current_guid)
                    parent_name = (current_state.process_name or "").lower() if current_state else ""
                    child_type = classify_process_type(
                        child_state.process_name,
                        child_state.process_exe,
                        rules,
                    )
                    if parent_name in common_daemons and child_type not in allowed_child_types:
                        continue
                    child_state.status_labels.add(label)
                    queue.append((child_guid, depth + 1))

    for parent_guid, children in child_map.items():
        parent_state = process_states.get(parent_guid)
        if parent_state is None:
            continue
        for child_guid in children:
            child_state = process_states.get(child_guid)
            if child_state is None:
                continue
            if child_state.behavior_labels or child_state.status_labels.intersection({"P_UNTRUSTED_CTX", "P_SUSPECT_CTRL_CTX"}):
                parent_state.aggregate_labels.add("A_CHILD_SUSPICIOUS")
                break


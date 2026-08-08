"""Read-only audit of CADETS GT task branches below synthetic roots.

This is intentionally a diagnostic, not a task-splitting implementation.  It
joins the fixed module1 graph, the GT process list, step7b candidate chains and
the raw CDM18 records to establish whether a conservative synthetic-root split
can retain attack evidence while separating unrelated process branches.
"""

from __future__ import annotations

import collections
import json
import subprocess
from pathlib import Path
from typing import Any

import torch


REPO = Path("/root/autodl-tmp/APT-Fusionstep2b1")
LOG_DIR = Path("/root/autodl-tmp/data/cadets/logs")
GT_PATH = Path("/root/autodl-tmp/data/cadets/cadets.txt")
MODULE1 = REPO / "artifacts_cadets_normal_only_tapas_paper_baseline_20260802" / "module1" / "tapas_native_graphs.pt"
STEP7B = REPO / "artifacts_cadets_train_stats_latefusion_llama31_microstep2b_module1_gtbase_tactics_only_llm_fanout_gt2_e3gt_plus240_step7b_privcred_guard_20260630"
OUT_DIR = REPO / "debug" / "remote_ops" / "out" / "cadets_gt_root_branch_audit_20260803"

MARKERS = ("drakon", "micro", "grain", "xim", "sendmail", "libdrakon", "nginx")
STAGED_PATH_TOKENS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/var/log/")
NETWORK_ACTIONS = {"EVENT_CONNECT", "EVENT_ACCEPT", "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_RECVFROM", "EVENT_RECVMSG"}


def _uuid(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    return str(value.get("com.bbn.tc.schema.avro.cdm18.UUID", "")).strip().upper()


def _datum(record: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    datum = record.get("datum", {})
    if not isinstance(datum, dict):
        return "", {}
    for key, value in datum.items():
        if isinstance(value, dict):
            return str(key), value
    return "", {}


def _string_path(event: dict[str, Any]) -> str:
    for key in ("predicateObjectPath", "predicateObject2Path"):
        value = event.get(key)
        if isinstance(value, dict):
            text = value.get("string")
            if text:
                return str(text)
    return ""


def _record_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False).lower()


def _read_gt() -> set[str]:
    return {line.strip().upper() for line in GT_PATH.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()}


def _positive_tasks() -> list[dict[str, Any]]:
    bundle = torch.load(MODULE1, map_location="cpu", weights_only=False)
    rows: list[dict[str, Any]] = []
    for graph, meta in zip(bundle["selected_graphs"], bundle["selected_graph_metas"]):
        if int(meta.get("label", 0)) != 1:
            continue
        rows.append({"graph": graph, "meta": meta})
    return rows


def _task_branches(graph: dict[str, Any], meta: dict[str, Any]) -> tuple[str, dict[str, str], dict[str, set[str]]]:
    nodes = [str(node).upper() for node in meta.get("node_ids", [])]
    root = str(meta.get("task_root_id", nodes[0] if nodes else "")).upper()
    children: dict[str, list[str]] = collections.defaultdict(list)
    for edge in graph.get("edges", []):
        if not isinstance(edge, (list, tuple)) or len(edge) < 2:
            continue
        parent_index, child_index = int(edge[0]), int(edge[1])
        if 0 <= parent_index < len(nodes) and 0 <= child_index < len(nodes):
            children[nodes[parent_index]].append(nodes[child_index])
    roots = list(dict.fromkeys(children.get(root, [])))
    branch_by_node: dict[str, str] = {root: root}
    nodes_by_branch: dict[str, set[str]] = {branch: set() for branch in roots}
    for branch in roots:
        stack = [branch]
        while stack:
            node = stack.pop()
            if node in branch_by_node:
                continue
            branch_by_node[node] = branch
            nodes_by_branch[branch].add(node)
            stack.extend(children.get(node, []))
    for node in nodes:
        if node not in branch_by_node:
            branch_by_node[node] = node
            nodes_by_branch.setdefault(node, set()).add(node)
    return root, branch_by_node, nodes_by_branch


def _step7b_chains() -> dict[str, list[dict[str, Any]]]:
    index_path = STEP7B / "module6_reason" / "report_index.json"
    if not index_path.exists():
        return {}
    grouped: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for row in json.loads(index_path.read_text(encoding="utf-8")):
        if not isinstance(row, dict):
            continue
        task_id = str(row.get("task_id", "")).strip()
        report_path = Path(str(row.get("report_path", "")))
        dossier_path = Path(str(row.get("dossier_path", "")))
        if not task_id or not report_path.exists():
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        dossier = json.loads(dossier_path.read_text(encoding="utf-8")) if dossier_path.exists() else {}
        grouped[task_id].append(
            {
                "path_id": str(row.get("path_id", "")),
                "risk_score": float(report.get("risk_score", 0.0) or 0.0),
                "attack_mappings": report.get("attack_mappings", []),
                "claims": dossier.get("claims", []),
                "path_nodes": dossier.get("path_nodes", []),
                "family_tags": dossier.get("family_tags", []),
            }
        )
    for task_id in grouped:
        grouped[task_id].sort(key=lambda item: (-item["risk_score"], item["path_id"]))
    return grouped


def _rg_matches(patterns: set[str]) -> list[dict[str, Any]]:
    if not patterns:
        return []
    pattern_file = OUT_DIR / "patterns.txt"
    pattern_file.write_text("\n".join(sorted(patterns)), encoding="utf-8")
    # The cloud image does not guarantee ripgrep.  GNU grep's fixed-pattern
    # file mode still performs one streaming pass without decoding all logs.
    log_files = [str(path) for path in sorted(LOG_DIR.glob("*.json"))]
    command = ["grep", "-h", "-F", "-f", str(pattern_file), *log_files]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    assert process.stdout is not None
    records: list[dict[str, Any]] = []
    for line in process.stdout:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    stderr = process.stderr.read() if process.stderr is not None else ""
    status = process.wait()
    if status not in (0, 1):
        raise RuntimeError(f"ripgrep audit pass failed ({status}): {stderr[-1000:]}")
    return records


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    gt = _read_gt()
    tasks = _positive_tasks()
    chains = _step7b_chains()
    task_by_node: dict[str, list[str]] = collections.defaultdict(list)
    task_state: dict[str, dict[str, Any]] = {}
    all_nodes: set[str] = set()
    for item in tasks:
        graph, meta = item["graph"], item["meta"]
        task_id = str(meta["task_id"])
        root, branch_by_node, nodes_by_branch = _task_branches(graph, meta)
        task_nodes = {str(node).upper() for node in meta.get("node_ids", [])}
        all_nodes |= task_nodes
        for node in task_nodes:
            task_by_node[node].append(task_id)
        task_state[task_id] = {
            "task_id": task_id,
            "task_root_id": root,
            "task_size": len(task_nodes),
            "root_direct_branch_count": len(nodes_by_branch),
            "node_ids": task_nodes,
            "branch_by_node": branch_by_node,
            "nodes_by_branch": nodes_by_branch,
            "gt_nodes": sorted(task_nodes & gt),
            "subject_rows": {},
            "event_rows": collections.defaultdict(list),
        }

    first_pass = _rg_matches(all_nodes)
    for record in first_pass:
        kind, data = _datum(record)
        if kind.endswith(".Subject"):
            node = str(data.get("uuid", "")).upper()
            for task_id in task_by_node.get(node, []):
                task_state[task_id]["subject_rows"][node] = data
        elif kind.endswith(".Event"):
            node = _uuid(data.get("subject"))
            if node not in task_by_node:
                continue
            event = {
                "type": str(data.get("type", "")),
                "timestamp_nanos": data.get("timestampNanos"),
                "object_uuid": _uuid(data.get("predicateObject")),
                "object_path": _string_path(data),
            }
            for task_id in task_by_node[node]:
                task_state[task_id]["event_rows"][node].append(event)

    output_tasks: list[dict[str, Any]] = []
    for state in task_state.values():
        branches: list[dict[str, Any]] = []
        for branch, nodes in state["nodes_by_branch"].items():
            action_counts: collections.Counter[str] = collections.Counter()
            path_counts: collections.Counter[str] = collections.Counter()
            action_path_counts: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
            paths: set[str] = set()
            network_objects: set[str] = set()
            marker_hits: set[str] = set()
            timestamps: list[int] = []
            for node in nodes:
                subject_text = _record_text(state["subject_rows"].get(node, {}))
                marker_hits.update(marker for marker in MARKERS if marker in subject_text)
                for event in state["event_rows"].get(node, []):
                    action_counts[event["type"]] += 1
                    timestamp = event.get("timestamp_nanos")
                    if isinstance(timestamp, int):
                        timestamps.append(timestamp)
                    path = str(event["object_path"] or "")
                    if path:
                        paths.add(path)
                        path_counts[path] += 1
                        action_path_counts[event["type"]][path] += 1
                        lower = path.lower()
                        marker_hits.update(marker for marker in MARKERS if marker in lower)
                    object_id = event["object_uuid"]
                    if event["type"] in NETWORK_ACTIONS and object_id:
                        network_objects.add(object_id)
            staged_paths = sorted(path for path in paths if any(token in path.lower() for token in STAGED_PATH_TOKENS))
            has_execution = action_counts["EVENT_EXECUTE"] > 0
            has_network = any(action_counts[action] > 0 for action in NETWORK_ACTIONS)
            # This is a validation-only operational seed.  It deliberately does
            # not use a GT UUID: a real split rule may use marker/staging/network
            # evidence but must never use the attack list at runtime.
            operational_seed = bool(marker_hits) or (has_execution and (has_network or bool(staged_paths)))
            branches.append(
                {
                    "branch_root_id": branch,
                    "node_count": len(nodes),
                    "gt_node_ids": sorted(nodes & gt),
                    "event_type_counts": dict(action_counts.most_common()),
                    "first_timestamp_nanos": min(timestamps) if timestamps else None,
                    "last_timestamp_nanos": max(timestamps) if timestamps else None,
                    "path_counts": path_counts.most_common(50),
                    "execution_path_counts": action_path_counts["EVENT_EXECUTE"].most_common(50),
                    "write_path_counts": action_path_counts["EVENT_WRITE"].most_common(50),
                    "unlink_path_counts": action_path_counts["EVENT_UNLINK"].most_common(50),
                    "marker_hits": sorted(marker_hits),
                    "staged_paths": staged_paths[:20],
                    # Event records already give the action; resolving every
                    # referenced object would turn this read-only audit into an
                    # unbounded second full-log join.  Preserve UUID samples
                    # and reserve exact flow resolution for selected branches.
                    "network_object_uuid_samples": sorted(network_objects)[:20],
                    "operational_seed_without_gt": operational_seed,
                }
            )
        gt_branches = [branch for branch in branches if branch["gt_node_ids"]]
        seeded_branches = [branch for branch in branches if branch["operational_seed_without_gt"]]
        output_tasks.append(
            {
                "task_id": state["task_id"],
                "task_root_id": state["task_root_id"],
                "task_size": state["task_size"],
                "root_direct_branch_count": state["root_direct_branch_count"],
                "gt_node_ids": state["gt_nodes"],
                "gt_branch_count": len(gt_branches),
                "gt_branch_node_count": sum(branch["node_count"] for branch in gt_branches),
                "operational_seed_branch_count": len(seeded_branches),
                "operational_seed_node_count": sum(branch["node_count"] for branch in seeded_branches),
                "candidate_reduction_if_keep_seeded_branches": state["task_size"] - sum(branch["node_count"] for branch in seeded_branches) - 1,
                "step7b_candidate_chains": chains.get(state["task_id"], []),
                "branches": sorted(
                    branches,
                    key=lambda branch: (
                        -bool(branch["gt_node_ids"]),
                        -bool(branch["operational_seed_without_gt"]),
                        -branch["node_count"],
                        branch["branch_root_id"],
                    ),
                ),
            }
        )
    output_tasks.sort(key=lambda row: row["task_id"])
    summary = {
        "task_count": len(output_tasks),
        "total_gt_node_count": sum(len(row["gt_node_ids"]) for row in output_tasks),
        "total_task_nodes": sum(row["task_size"] for row in output_tasks),
        "total_gt_branch_nodes": sum(row["gt_branch_node_count"] for row in output_tasks),
        "total_seed_branch_nodes": sum(row["operational_seed_node_count"] for row in output_tasks),
    }
    output = {"summary": summary, "tasks": output_tasks}
    (OUT_DIR / "cadets_gt_root_branch_audit.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

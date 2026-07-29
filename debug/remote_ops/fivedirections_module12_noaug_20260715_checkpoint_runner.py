from __future__ import annotations

import gc
import copy
import json
import os
import pickle
import shutil
import sys
import time
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import torch


REPO_ROOT = Path(os.environ.get("FIVEDIRECTIONS_REPO_ROOT", "/root/autodl-tmp/APT-Fusionstep2b1"))
CONFIG_PATH = Path(
    os.environ.get(
        "FIVEDIRECTIONS_CONFIG_PATH",
        str(REPO_ROOT / "configs" / "fusion_cloud_fivedirections_train_stats_latefusion_noaug_module12_20260715.yaml"),
    )
)
OUT_DIR = Path(
    os.environ.get(
        "FIVEDIRECTIONS_OUT_DIR",
        str(REPO_ROOT / "debug" / "remote_ops" / "out" / "fivedirections_noaug_module12_20260715"),
    )
)
CHECKPOINT_DIR = OUT_DIR / "checkpoints"
RUN_STATE_PATH = OUT_DIR / "checkpoint_run_state.json"


def _rss_gb() -> float:
    try:
        with open("/proc/self/status", "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    kb = float(line.split()[1])
                    return kb / 1024.0 / 1024.0
    except Exception:
        pass
    return -1.0


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _load_state() -> dict[str, Any]:
    if RUN_STATE_PATH.exists():
        return json.loads(RUN_STATE_PATH.read_text(encoding="utf-8"))
    return {"steps": []}


def _save_state(state: dict[str, Any]) -> None:
    _write_json(RUN_STATE_PATH, state)


def _record_step(state: dict[str, Any], name: str, status: str, **extra: Any) -> None:
    state.setdefault("steps", []).append(
        {
            "name": name,
            "status": status,
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "rss_gb": round(_rss_gb(), 3),
            **extra,
        }
    )
    _save_state(state)


@contextmanager
def _timed_step(state: dict[str, Any], name: str, **extra: Any):
    start = time.time()
    _record_step(state, name, "start", **extra)
    try:
        yield
    except BaseException as exc:
        _record_step(
            state,
            name,
            "failed",
            elapsed_sec=round(time.time() - start, 3),
            error=repr(exc),
            traceback=traceback.format_exc()[-8000:],
        )
        raise
    else:
        _record_step(state, name, "done", elapsed_sec=round(time.time() - start, 3))


def _dump_pickle(name: str, obj: Any) -> Path:
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    path = CHECKPOINT_DIR / f"{name}.pkl"
    tmp = path.with_suffix(".pkl.tmp")
    with tmp.open("wb") as handle:
        pickle.dump(obj, handle, protocol=pickle.HIGHEST_PROTOCOL)
    tmp.replace(path)
    return path


def _load_pickle(name: str) -> Any:
    path = CHECKPOINT_DIR / f"{name}.pkl"
    with path.open("rb") as handle:
        return pickle.load(handle)


def _checkpoint_exists(name: str) -> bool:
    return (CHECKPOINT_DIR / f"{name}.pkl").exists()


def _component_summary(edge_list: Any) -> dict[str, Any]:
    if not isinstance(edge_list, dict):
        return {"edge_list_type": type(edge_list).__name__, "edge_count": len(edge_list) if hasattr(edge_list, "__len__") else None}
    components = list(edge_list.get("task_components", []))
    sizes = [len(component.get("nodes", [])) for component in components]
    return {
        "edge_count": len(edge_list.get("edge_list", [])),
        "task_component_count": len(components),
        "task_component_min_size": min(sizes) if sizes else 0,
        "task_component_max_size": max(sizes) if sizes else 0,
        "task_component_total_nodes_with_overlap": int(sum(sizes)),
        "large_task_count_gt_500": sum(1 for size in sizes if size > 500),
        "large_task_count_gt_1000": sum(1 for size in sizes if size > 1000),
    }


def main() -> int:
    os.chdir(REPO_ROOT)
    sys.path.insert(0, str(REPO_ROOT / "src"))

    from apt_fusion.config import load_config
    from apt_fusion.task_detection.module2_online_detection import run_module2
    from apt_fusion.task_detection import tapas_native_backend as tnb

    state = _load_state()
    state["runner"] = str(Path(__file__).resolve())
    state["config_path"] = str(CONFIG_PATH)
    state["repo_root"] = str(REPO_ROOT)
    state["pid"] = os.getpid()
    _save_state(state)

    cfg = load_config(CONFIG_PATH)
    if cfg.host != "fivedirections":
        raise ValueError(f"Expected host=fivedirections, got {cfg.host!r}")
    if cfg.task_tapas_augmentation_enabled:
        raise ValueError("This runner is for no-augmentation experiments only.")
    if os.environ.get("FIVEDIRECTIONS_DISABLE_STATS_ON_RESUME", "").strip() == "1":
        cfg.use_ocr_stat_features = False
        cfg.task_graph_stat_late_fusion_enabled = False
        state["forced_disable_stats_on_resume"] = True
        _save_state(state)

    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    cfg.module1_dir.mkdir(parents=True, exist_ok=True)
    cfg.module2_dir.mkdir(parents=True, exist_ok=True)

    workspace = tnb._ensure_workspace(cfg.module1_dir, cfg)
    vendor = tnb._load_vendor_module("tapas_vendor_darpa_exact_module1_checkpoint", tnb._vendor_tapas_root() / "darpa.py")
    vendor.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ground_truth = tnb._load_ground_truth(cfg.task_ground_truth_path)
    source_logs = tnb._normalize_tc3_source_logs(cfg.source_logs)
    task_component_kwargs = {
        "child_threshold": int(cfg.task_component_child_threshold),
        "split_mode": str(cfg.task_component_split_mode),
        "count_segmented_children_upstream": bool(cfg.task_component_count_segmented_children_upstream),
    }

    with tnb._temporary_cwd(workspace):
        if _checkpoint_exists("parser"):
            subject_list, object_list, event_count, parser_metadata = _load_pickle("parser")
            _record_step(
                state,
                "parser",
                "loaded_checkpoint",
                subject_count=len(subject_list),
                object_count=len(object_list),
                event_count=len(event_count) if hasattr(event_count, "__len__") else None,
            )
        else:
            with _timed_step(state, "parser"):
                subject_list, object_list, event_count, parser_metadata = vendor.parser_fivedirections(source_logs)
                _dump_pickle("parser", (subject_list, object_list, event_count, parser_metadata))
                _write_json(
                    CHECKPOINT_DIR / "parser_summary.json",
                    {
                        "subject_count": len(subject_list),
                        "object_count": len(object_list),
                        "event_count_size": len(event_count) if hasattr(event_count, "__len__") else None,
                        "parser_metadata_keys": sorted(parser_metadata.keys()) if isinstance(parser_metadata, dict) else [],
                    },
                )

        if _checkpoint_exists("subject_node"):
            subject_node = _load_pickle("subject_node")
            _record_step(state, "encode_fivedirections", "loaded_checkpoint", subject_node_count=len(subject_node))
        else:
            with _timed_step(state, "encode_fivedirections"):
                subject_node = vendor.encode_fivedirections(subject_list, object_list, event_count)
                _dump_pickle("subject_node", subject_node)
                _write_json(CHECKPOINT_DIR / "subject_node_summary.json", {"subject_node_count": len(subject_node)})

        if _checkpoint_exists("edge_list"):
            edge_list = _load_pickle("edge_list")
            _record_step(state, "cut_task", "loaded_checkpoint", **_component_summary(edge_list))
        else:
            with _timed_step(state, "cut_task", **task_component_kwargs):
                edge_list = vendor.cut_task(subject_list, return_task_components=True, **task_component_kwargs)
                _dump_pickle("edge_list", edge_list)
                _write_json(CHECKPOINT_DIR / "edge_list_summary.json", _component_summary(edge_list))

        if _checkpoint_exists("raw_vectors"):
            raw_vectors = _load_pickle("raw_vectors")
            _record_step(state, "get_node_vec", "loaded_checkpoint", vector_rows=len(raw_vectors))
        else:
            with _timed_step(state, "get_node_vec"):
                raw_vectors = vendor.get_node_vec(subject_node)
                _dump_pickle("raw_vectors", raw_vectors)
                _write_json(CHECKPOINT_DIR / "raw_vectors_summary.json", {"vector_rows": len(raw_vectors)})

        canonical_ground_truth = tnb._canonicalize_ground_truth_nodes(ground_truth, parser_metadata)
        _write_json(
            CHECKPOINT_DIR / "ground_truth_summary.json",
            {
                "ground_truth_count": len(ground_truth),
                "canonical_ground_truth_count": len(canonical_ground_truth),
            },
        )

        if _checkpoint_exists("raw_graphs"):
            raw_graphs = _load_pickle("raw_graphs")
            _record_step(state, "decompose", "loaded_checkpoint", raw_graph_count=len(raw_graphs))
        else:
            with _timed_step(state, "decompose"):
                raw_graphs = vendor.decompose(edge_list, raw_vectors, cfg.host, canonical_ground_truth=canonical_ground_truth)
                _dump_pickle("raw_graphs", raw_graphs)
                graph_sizes = [len(graph.get("nodes", [])) if isinstance(graph, dict) else len(graph[0]) for graph in raw_graphs]
                _write_json(
                    CHECKPOINT_DIR / "raw_graphs_summary.json",
                    {
                        "raw_graph_count": len(raw_graphs),
                        "raw_graph_min_size": min(graph_sizes) if graph_sizes else 0,
                        "raw_graph_max_size": max(graph_sizes) if graph_sizes else 0,
                    },
                )

    with _timed_step(state, "build_bundle_sidecars"):
        embeddings_map = tnb._vector_rows_to_map(raw_vectors)
        graph_metas = tnb._decompose_tc3_metadata(edge_list, canonical_ground_truth)
        tnb._validate_graph_meta_alignment(raw_graphs, graph_metas, f"tc3/{cfg.host}")
        base_edge_rows = edge_list.get("edge_list", edge_list) if isinstance(edge_list, dict) else edge_list
        selected_edge_list = [list(edge) for edge in base_edge_rows]
        bundle = {
            "family": "tc3",
            "dataset_name": cfg.host,
            "selected_dataset_name": cfg.host,
            "selected_graphs": raw_graphs,
            "selected_graph_metas": graph_metas,
            "selected_edge_list": selected_edge_list,
            "selected_embeddings": embeddings_map,
            "sequence_feature_dim": tnb._feature_dim_from_map(embeddings_map),
            "thread_merge_metadata": copy.deepcopy(parser_metadata),
            "parser_event_count": event_count if cfg.use_ocr_stat_features else None,
            "theia_temporal_split_summary": {},
        }
        label_counts = {
            "positive": sum(1 for meta in graph_metas if int(meta.get("label", 0)) == 1),
            "negative": sum(1 for meta in graph_metas if int(meta.get("label", 0)) == 0),
        }
        _write_json(
            CHECKPOINT_DIR / "bundle_sidecar_summary.json",
            {
                "embedding_count": len(embeddings_map),
                "graph_meta_count": len(graph_metas),
                "selected_edge_count": len(selected_edge_list),
                "label_counts": label_counts,
            },
        )

    gc.collect()
    if os.environ.get("FIVEDIRECTIONS_DISABLE_STATS_ON_RESUME", "").strip() == "1":
        with _timed_step(state, "append_stats_to_bundle_skipped_no_stats"):
            # Avoid _append_stats_to_bundle() here: it deep-copies the full
            # 15k-graph FiveDirections bundle before checking the no-stats flag,
            # which can be killed silently on this dataset scale.
            bundle["base_sequence_feature_dim"] = int(bundle["sequence_feature_dim"])
            bundle["stat_feature_columns"] = []
            bundle["selected_stat_embeddings"] = {}
            _dump_pickle("module1_bundle", bundle)
    else:
        with _timed_step(state, "append_stats_to_bundle"):
            bundle = tnb._append_stats_to_bundle(cfg, bundle)
            _dump_pickle("module1_bundle", bundle)

    with _timed_step(state, "save_module1_exports"):
        module1_outputs = tnb._save_module1_exports(cfg, cfg.module1_dir, bundle)
        _write_json(CHECKPOINT_DIR / "module1_outputs.json", {k: str(v) for k, v in module1_outputs.items()})

    with _timed_step(state, "run_module2"):
        module2_outputs = run_module2(
            cfg,
            embeddings_path=module1_outputs["process_embeddings"],
            task_path=module1_outputs["task_subgraphs"],
            segmentation_edges_path=module1_outputs["process_segmentation_edges"],
        )
        _write_json(CHECKPOINT_DIR / "module2_outputs.json", {k: str(v) for k, v in module2_outputs.items()})

    summary = {
        "status": "complete",
        "config_path": str(CONFIG_PATH),
        "artifacts_dir": str(cfg.artifacts_dir),
        "module1_dir": str(cfg.module1_dir),
        "module2_dir": str(cfg.module2_dir),
        "module1_outputs": {k: str(v) for k, v in module1_outputs.items()},
        "module2_outputs": {k: str(v) for k, v in module2_outputs.items()},
        "no_data_augmentation": True,
        "task_tapas_augmentation_enabled": bool(cfg.task_tapas_augmentation_enabled),
    }
    _write_json(OUT_DIR / "run_summary.json", summary)
    _record_step(state, "runner", "complete")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaseException:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "checkpoint_runner_exception.txt").write_text(traceback.format_exc(), encoding="utf-8")
        raise

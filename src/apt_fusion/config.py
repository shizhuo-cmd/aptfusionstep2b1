from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_ATTACK_EVAL_GT_JSON_FILENAME = "darpa_attack_eval_ground_truth_e3_report_enriched_20260618.json"


def resolve_attack_eval_gt_json(repo_root: Path, configured_path: Path | None = None) -> Path:
    if configured_path is not None:
        return configured_path if configured_path.is_absolute() else repo_root / configured_path
    return repo_root / "docs" / DEFAULT_ATTACK_EVAL_GT_JSON_FILENAME


@dataclass
class FusionConfig:
    ocr_apt_root: Path | None
    tapas_root: Path | None
    dataset_family: str
    host: str
    source_logs: Path
    artifacts_dir: Path
    ocr_runtime_root: Path
    ocr_exp_name: str
    ocr_model_name: str
    ocr_inv_exp_name: str
    use_sequence_embeddings: bool = True
    use_ocr_stat_features: bool = True
    graphsage_append_ocr_stat_features: bool = False
    task_tc3_event_stats_mode: str = "legacy_aggregate"
    ocr_stat_active_threshold_sec: float = 1.0
    task_graph_stat_late_fusion_enabled: bool = False
    task_graph_stat_fusion_weight: float = 0.25
    task_detection_backend: str = "tapas_native"
    task_detector_mode: str = "fit_predict"
    task_detector_model_input: Path | None = None
    task_detector_model_output: Path | None = None
    task_ground_truth_path: Path | None = None
    task_sequence_model_path: Path | None = None
    task_sequence_encoder_mode: str = "legacy"
    task_semantic_sequence_pretrained_path: Path | None = None
    task_semantic_sequence_epochs: int = 5
    task_semantic_sequence_batch_size: int = 512
    task_semantic_sequence_learning_rate: float = 0.001
    task_normal_only_train_fraction: float = 0.70
    task_normal_only_validation_fraction: float = 0.15
    task_normal_only_task_prototypes: int = 8
    task_normal_only_node_prototypes: int = 32
    task_normal_only_node_sample_limit: int = 100000
    # ``sequence_only`` evaluates the frozen TAPAS LSTM-GRU representation
    # without appended event-statistics features.
    task_normal_only_node_feature_mode: str = "all"
    task_normal_only_node_audit_enabled: bool = False
    task_normal_only_local_top_k: int = 3
    task_normal_only_local_top_k_mode: str = "fixed"
    task_normal_only_local_top_k_max: int = 16
    task_normal_only_global_model: str = "kmeans"
    task_normal_only_global_knn_neighbors: int = 5
    task_normal_only_global_weight: float = 0.40
    task_normal_only_detector: str = "prototype"
    task_normal_only_gnn_direction_mode: str = "undirected"
    task_normal_only_gnn_hidden_dim: int = 64
    task_normal_only_gnn_num_layers: int = 2
    task_normal_only_gnn_dropout: float = 0.10
    task_normal_only_gnn_epochs: int = 20
    task_normal_only_gnn_batch_size: int = 4
    task_normal_only_gnn_learning_rate: float = 0.001
    task_normal_only_gnn_weight_decay: float = 0.0001
    # A 2% benign calibration target avoided the overly conservative 1% operating point on TC3.
    task_normal_only_validation_fpr: float = 0.02
    random_seed: int = 42
    task_classifier_hidden_dim: int = 64
    task_classifier_num_layers: int = 2
    task_classifier_dropout: float = 0.5
    task_classifier_lr: float = 1e-3
    task_classifier_weight_decay: float = 5e-4
    task_classifier_epochs: int = 50
    task_classifier_batch_size: int = 64
    task_classifier_pooling: str = "max"
    task_decision_threshold: float = 0.5
    task_decision_threshold_mode: str = "fixed"
    task_fit_test_fraction: float = 0.0
    task_fit_split_strategy: str = "stratified_shuffle_split"
    task_fit_kfold_splits: int = 5
    task_fit_kfold_index: int = 0
    task_min_graph_nodes: int = 1
    task_graph_bidirectional_edges: bool = True
    task_graph_self_loops: bool = True
    task_tapas_augmentation_enabled: bool = False
    task_tapas_augmentation_divisor: int = 0
    task_tapas_trace_augmentation_bonus: int = 0
    task_tapas_augmentation_before_split: bool = False
    task_tapas_faithful_mode: bool = False
    number_of_hops: int = 1
    max_edges: int = 5000
    top_k: int = 15
    abnormality_level: str = "Moderate"
    llm_exp_name: str = "fusion_llm"
    llm_model_source: str = "openai"
    llm_model: str = "gpt-4o-mini"
    llm_embedding_model_source: str = "openai"
    llm_embedding_model: str = "text-embedding-3-large"
    llm_openai_api_key: str = ""
    llm_deepseek_api_key: str = ""
    llm_ollama_base_url: str = ""
    llm_request_timeout_sec: int = 600
    local_context_hops: int = 1
    module3_task_selection_mode: str = "predicted_positive"
    task_component_split_mode: str = "fanout"
    task_component_child_threshold: int = 2
    task_component_count_segmented_children_upstream: bool = False
    task_tapas_release_legacy_cut_logic: bool = False
    task_component_provgrp_behavior_partition_enabled: bool = False
    task_component_provgrp_min_direct_children: int = 10
    task_component_provgrp_min_cluster_size: int = 5
    task_component_provgrp_min_samples: int = 2
    task_component_provgrp_max_events_per_matrix: int = 512
    task_component_provgrp_batch_overlap_events: int = 64
    task_component_theia_temporal_split_enabled: bool = False
    task_component_theia_max_span_minutes: int = 45
    task_component_theia_branch_gap_minutes: int = 10
    task_component_root_temporal_split_enabled: bool = False
    task_component_root_temporal_min_task_nodes: int = 500
    task_component_root_temporal_min_direct_children: int = 64
    task_component_root_temporal_max_span_minutes: int = 45
    task_component_root_temporal_branch_gap_minutes: int = 10
    task_component_root_temporal_session_max_minutes: int = 60
    task_component_root_temporal_max_sessions: int = 0
    task_component_temporal_episode_split_enabled: bool = False
    task_component_temporal_episode_parent_missing_only: bool = False
    task_component_temporal_episode_min_task_nodes: int = 500
    task_component_temporal_episode_min_direct_children: int = 32
    task_component_temporal_episode_min_span_minutes: int = 60
    task_component_temporal_episode_gap_mode: str = "median_mad"
    task_component_temporal_episode_fixed_gap_minutes: int = 30
    task_component_temporal_episode_gap_quantile: float = 0.90
    task_component_temporal_episode_mad_multiplier: float = 3.0
    task_component_temporal_episode_min_children_per_episode: int = 8
    task_component_temporal_episode_max_episodes: int = 8
    task_component_temporal_episode_budget_strategy: str = "adjacent_greedy"
    task_component_synthetic_root_isolation_enabled: bool = False
    task_component_synthetic_root_isolation_min_task_nodes: int = 500
    task_component_synthetic_root_isolation_min_direct_children: int = 64
    task_component_synthetic_root_selective_isolation_enabled: bool = False
    task_component_synthetic_root_selective_max_exec_target_frequency: int = 3
    task_component_branch_object_overlap_split_enabled: bool = False
    attack_eval_gt_json_path: Path | None = None
    path_reason_gt_window_filter_mode: str = "none"
    path_reason_gt_window_filter_pad_minutes: int = 0
    path_reason_gt_time_offset_minutes: int = 0
    attack_kb_stix_path: Path | None = None
    attack_kb_candidate_limit: int = 12
    attack_kb_embedding_model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    attack_kb_sparse_top_k: int = 24
    attack_kb_vector_top_k: int = 24
    attack_kb_sparse_weight: float = 0.45
    attack_kb_vector_weight: float = 0.55
    attack_kb_claim_weight: float = 0.25
    attack_kb_enable_vector: bool = True
    path_reason_enabled: bool = True
    evidence_recover_include_object_side: bool = True
    evidence_recover_max_events_per_task: int = 300000
    evidence_recover_task_time_padding_minutes: int = 30
    evidence_recover_anchor_top_k: int = 3
    semantic_skip_enabled: bool = True
    semantic_skip_ttl_seconds: int = 600
    semantic_skip_max_table_size: int = 100000
    semantic_force_keep_external_network: bool = True
    semantic_force_keep_exec: bool = True
    semantic_force_keep_write_sensitive: bool = True
    episode_max_representative_events: int = 5
    episode_time_bucket_minutes: int = 1
    path_bridge_max_time_gap_minutes: int = 30
    path_max_depth: int = 6
    path_max_total_span_minutes: int = 180
    path_hot_process_threshold: float = 25.0
    path_top_k: int = 20
    path_require_execution_strong_for_high: bool = True
    path_allow_weak_execution_medium: bool = True
    reason_top_paths_per_task: int = 5
    reason_max_timeline_items_per_path: int = 24
    reason_max_bridge_edges_per_path: int = 8
    reason_max_objects_per_path: int = 12
    claim_attack_prior_mode: str = "full"
    attack_mapping_scope: str = "full"
    tactic_mapping_mode: str = "llm"
    path_reason_rules_path: Path | None = None

    @property
    def module1_dir(self) -> Path:
        return self.artifacts_dir / "module1"

    @property
    def module2_dir(self) -> Path:
        return self.artifacts_dir / "module2"

    @property
    def module3_evidence_dir(self) -> Path:
        return self.artifacts_dir / "module3_evidence"

    @property
    def module4_compact_dir(self) -> Path:
        return self.artifacts_dir / "module4_compact"

    @property
    def module5_paths_dir(self) -> Path:
        return self.artifacts_dir / "module5_paths"

    @property
    def module6_reason_dir(self) -> Path:
        return self.artifacts_dir / "module6_reason"

def _get(data: dict[str, Any], key: str, default: Any = None) -> Any:
    return data[key] if key in data else default


def _optional_path(raw: Any) -> Path | None:
    text = str(raw).strip() if raw is not None else ""
    return Path(text) if text else None


def load_config(path: str | Path) -> FusionConfig:
    cfg_path = Path(path)
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))

    cfg = FusionConfig(
        ocr_apt_root=_optional_path(_get(data, "ocr_apt_root", "")),
        tapas_root=_optional_path(_get(data, "tapas_root", "")),
        dataset_family=str(data["dataset_family"]),
        host=str(data["host"]),
        source_logs=Path(data["source_logs"]),
        artifacts_dir=Path(data["artifacts_dir"]),
        ocr_runtime_root=Path(data["ocr_runtime_root"]),
        ocr_exp_name=str(data["ocr_exp_name"]),
        ocr_model_name=str(data["ocr_model_name"]),
        ocr_inv_exp_name=str(data["ocr_inv_exp_name"]),
        use_sequence_embeddings=bool(_get(data, "use_sequence_embeddings", True)),
        use_ocr_stat_features=bool(_get(data, "use_ocr_stat_features", True)),
        graphsage_append_ocr_stat_features=bool(_get(data, "graphsage_append_ocr_stat_features", False)),
        task_tc3_event_stats_mode=str(_get(data, "task_tc3_event_stats_mode", "legacy_aggregate")),
        ocr_stat_active_threshold_sec=float(_get(data, "ocr_stat_active_threshold_sec", 1.0)),
        task_graph_stat_late_fusion_enabled=bool(_get(data, "task_graph_stat_late_fusion_enabled", False)),
        task_graph_stat_fusion_weight=float(_get(data, "task_graph_stat_fusion_weight", 0.25)),
        task_detection_backend=_normalize_task_detection_backend(
            str(_get(data, "task_detection_backend", "tapas_native"))
        ),
        task_detector_mode=str(_get(data, "task_detector_mode", "fit_predict")),
        task_detector_model_input=_optional_path(_get(data, "task_detector_model_input", "")),
        task_detector_model_output=_optional_path(_get(data, "task_detector_model_output", "")),
        task_ground_truth_path=_optional_path(_get(data, "task_ground_truth_path", "")),
        task_sequence_model_path=_optional_path(_get(data, "task_sequence_model_path", "")),
        task_sequence_encoder_mode=str(_get(data, "task_sequence_encoder_mode", "legacy")),
        task_semantic_sequence_pretrained_path=_optional_path(
            _get(data, "task_semantic_sequence_pretrained_path", "")
        ),
        task_semantic_sequence_epochs=int(_get(data, "task_semantic_sequence_epochs", 5)),
        task_semantic_sequence_batch_size=int(_get(data, "task_semantic_sequence_batch_size", 512)),
        task_semantic_sequence_learning_rate=float(_get(data, "task_semantic_sequence_learning_rate", 0.001)),
        task_normal_only_train_fraction=float(_get(data, "task_normal_only_train_fraction", 0.70)),
        task_normal_only_validation_fraction=float(_get(data, "task_normal_only_validation_fraction", 0.15)),
        task_normal_only_task_prototypes=int(_get(data, "task_normal_only_task_prototypes", 8)),
        task_normal_only_node_prototypes=int(_get(data, "task_normal_only_node_prototypes", 32)),
        task_normal_only_node_sample_limit=int(_get(data, "task_normal_only_node_sample_limit", 100000)),
        task_normal_only_node_feature_mode=str(_get(data, "task_normal_only_node_feature_mode", "all")),
        task_normal_only_node_audit_enabled=bool(_get(data, "task_normal_only_node_audit_enabled", False)),
        task_normal_only_local_top_k=int(_get(data, "task_normal_only_local_top_k", 3)),
        task_normal_only_local_top_k_mode=str(_get(data, "task_normal_only_local_top_k_mode", "fixed")),
        task_normal_only_local_top_k_max=int(_get(data, "task_normal_only_local_top_k_max", 16)),
        task_normal_only_global_model=str(_get(data, "task_normal_only_global_model", "kmeans")),
        task_normal_only_global_knn_neighbors=int(_get(data, "task_normal_only_global_knn_neighbors", 5)),
        task_normal_only_global_weight=float(_get(data, "task_normal_only_global_weight", 0.40)),
        task_normal_only_detector=str(_get(data, "task_normal_only_detector", "prototype")),
        task_normal_only_gnn_direction_mode=str(_get(data, "task_normal_only_gnn_direction_mode", "undirected")),
        task_normal_only_gnn_hidden_dim=int(_get(data, "task_normal_only_gnn_hidden_dim", 64)),
        task_normal_only_gnn_num_layers=int(_get(data, "task_normal_only_gnn_num_layers", 2)),
        task_normal_only_gnn_dropout=float(_get(data, "task_normal_only_gnn_dropout", 0.10)),
        task_normal_only_gnn_epochs=int(_get(data, "task_normal_only_gnn_epochs", 20)),
        task_normal_only_gnn_batch_size=int(_get(data, "task_normal_only_gnn_batch_size", 4)),
        task_normal_only_gnn_learning_rate=float(_get(data, "task_normal_only_gnn_learning_rate", 0.001)),
        task_normal_only_gnn_weight_decay=float(_get(data, "task_normal_only_gnn_weight_decay", 0.0001)),
        task_normal_only_validation_fpr=float(_get(data, "task_normal_only_validation_fpr", 0.02)),
        random_seed=int(_get(data, "random_seed", 42)),
        task_classifier_hidden_dim=int(_get(data, "task_classifier_hidden_dim", 64)),
        task_classifier_num_layers=int(_get(data, "task_classifier_num_layers", 2)),
        task_classifier_dropout=float(_get(data, "task_classifier_dropout", 0.5)),
        task_classifier_lr=float(_get(data, "task_classifier_lr", 1e-3)),
        task_classifier_weight_decay=float(_get(data, "task_classifier_weight_decay", 5e-4)),
        task_classifier_epochs=int(_get(data, "task_classifier_epochs", 50)),
        task_classifier_batch_size=int(_get(data, "task_classifier_batch_size", 64)),
        task_classifier_pooling=str(_get(data, "task_classifier_pooling", "max")),
        task_decision_threshold=float(_get(data, "task_decision_threshold", 0.5)),
        task_decision_threshold_mode=str(_get(data, "task_decision_threshold_mode", "fixed")),
        task_fit_test_fraction=float(_get(data, "task_fit_test_fraction", 0.0)),
        task_fit_split_strategy=str(_get(data, "task_fit_split_strategy", "stratified_shuffle_split")),
        task_fit_kfold_splits=int(_get(data, "task_fit_kfold_splits", 5)),
        task_fit_kfold_index=int(_get(data, "task_fit_kfold_index", 0)),
        task_min_graph_nodes=int(_get(data, "task_min_graph_nodes", 1)),
        task_graph_bidirectional_edges=bool(_get(data, "task_graph_bidirectional_edges", True)),
        task_graph_self_loops=bool(_get(data, "task_graph_self_loops", True)),
        task_tapas_augmentation_enabled=bool(_get(data, "task_tapas_augmentation_enabled", False)),
        task_tapas_augmentation_divisor=int(_get(data, "task_tapas_augmentation_divisor", 0)),
        task_tapas_trace_augmentation_bonus=int(_get(data, "task_tapas_trace_augmentation_bonus", 0)),
        task_tapas_augmentation_before_split=bool(_get(data, "task_tapas_augmentation_before_split", False)),
        task_tapas_faithful_mode=bool(_get(data, "task_tapas_faithful_mode", False)),
        number_of_hops=int(_get(data, "number_of_hops", 1)),
        max_edges=int(_get(data, "max_edges", 5000)),
        top_k=int(_get(data, "top_k", 15)),
        abnormality_level=str(_get(data, "abnormality_level", "Moderate")),
        llm_exp_name=str(_get(data, "llm_exp_name", "fusion_llm")),
        llm_model_source=str(_get(data, "llm_model_source", "openai")),
        llm_model=str(_get(data, "llm_model", "gpt-4o-mini")),
        llm_embedding_model_source=str(_get(data, "llm_embedding_model_source", "openai")),
        llm_embedding_model=str(_get(data, "llm_embedding_model", "text-embedding-3-large")),
        llm_openai_api_key=str(_get(data, "llm_openai_api_key", "")),
        llm_deepseek_api_key=str(_get(data, "llm_deepseek_api_key", "")),
        llm_ollama_base_url=str(_get(data, "llm_ollama_base_url", "")),
        llm_request_timeout_sec=int(_get(data, "llm_request_timeout_sec", 600)),
        local_context_hops=int(_get(data, "local_context_hops", 1)),
        module3_task_selection_mode=str(_get(data, "module3_task_selection_mode", "predicted_positive")),
        task_component_split_mode=str(_get(data, "task_component_split_mode", "fanout")),
        task_component_child_threshold=int(_get(data, "task_component_child_threshold", 2)),
        task_component_count_segmented_children_upstream=bool(
            _get(data, "task_component_count_segmented_children_upstream", False)
        ),
        task_tapas_release_legacy_cut_logic=bool(
            _get(data, "task_tapas_release_legacy_cut_logic", False)
        ),
        task_component_provgrp_behavior_partition_enabled=bool(
            _get(data, "task_component_provgrp_behavior_partition_enabled", False)
        ),
        task_component_provgrp_min_direct_children=int(
            _get(data, "task_component_provgrp_min_direct_children", 10)
        ),
        task_component_provgrp_min_cluster_size=int(
            _get(data, "task_component_provgrp_min_cluster_size", 5)
        ),
        task_component_provgrp_min_samples=int(
            _get(data, "task_component_provgrp_min_samples", 2)
        ),
        task_component_provgrp_max_events_per_matrix=int(
            _get(data, "task_component_provgrp_max_events_per_matrix", 512)
        ),
        task_component_provgrp_batch_overlap_events=int(
            _get(data, "task_component_provgrp_batch_overlap_events", 64)
        ),
        task_component_theia_temporal_split_enabled=bool(
            _get(data, "task_component_theia_temporal_split_enabled", False)
        ),
        task_component_theia_max_span_minutes=int(_get(data, "task_component_theia_max_span_minutes", 45)),
        task_component_theia_branch_gap_minutes=int(_get(data, "task_component_theia_branch_gap_minutes", 10)),
        task_component_root_temporal_split_enabled=bool(
            _get(data, "task_component_root_temporal_split_enabled", False)
        ),
        task_component_root_temporal_min_task_nodes=int(
            _get(data, "task_component_root_temporal_min_task_nodes", 500)
        ),
        task_component_root_temporal_min_direct_children=int(
            _get(data, "task_component_root_temporal_min_direct_children", 64)
        ),
        task_component_root_temporal_max_span_minutes=int(
            _get(data, "task_component_root_temporal_max_span_minutes", 45)
        ),
        task_component_root_temporal_branch_gap_minutes=int(
            _get(data, "task_component_root_temporal_branch_gap_minutes", 10)
        ),
        task_component_root_temporal_session_max_minutes=int(
            _get(data, "task_component_root_temporal_session_max_minutes", 60)
        ),
        task_component_root_temporal_max_sessions=int(
            _get(data, "task_component_root_temporal_max_sessions", 0)
        ),
        task_component_temporal_episode_split_enabled=bool(
            _get(data, "task_component_temporal_episode_split_enabled", False)
        ),
        task_component_temporal_episode_parent_missing_only=bool(
            _get(data, "task_component_temporal_episode_parent_missing_only", False)
        ),
        task_component_temporal_episode_min_task_nodes=int(
            _get(data, "task_component_temporal_episode_min_task_nodes", 500)
        ),
        task_component_temporal_episode_min_direct_children=int(
            _get(data, "task_component_temporal_episode_min_direct_children", 32)
        ),
        task_component_temporal_episode_min_span_minutes=int(
            _get(data, "task_component_temporal_episode_min_span_minutes", 60)
        ),
        task_component_temporal_episode_gap_mode=str(
            _get(data, "task_component_temporal_episode_gap_mode", "median_mad")
        ),
        task_component_temporal_episode_fixed_gap_minutes=int(
            _get(data, "task_component_temporal_episode_fixed_gap_minutes", 30)
        ),
        task_component_temporal_episode_gap_quantile=float(
            _get(data, "task_component_temporal_episode_gap_quantile", 0.90)
        ),
        task_component_temporal_episode_mad_multiplier=float(
            _get(data, "task_component_temporal_episode_mad_multiplier", 3.0)
        ),
        task_component_temporal_episode_min_children_per_episode=int(
            _get(data, "task_component_temporal_episode_min_children_per_episode", 8)
        ),
        task_component_temporal_episode_max_episodes=int(
            _get(data, "task_component_temporal_episode_max_episodes", 8)
        ),
        task_component_temporal_episode_budget_strategy=str(
            _get(data, "task_component_temporal_episode_budget_strategy", "adjacent_greedy")
        ),
        task_component_synthetic_root_isolation_enabled=bool(
            _get(data, "task_component_synthetic_root_isolation_enabled", False)
        ),
        task_component_synthetic_root_isolation_min_task_nodes=int(
            _get(data, "task_component_synthetic_root_isolation_min_task_nodes", 500)
        ),
        task_component_synthetic_root_isolation_min_direct_children=int(
            _get(data, "task_component_synthetic_root_isolation_min_direct_children", 64)
        ),
        task_component_synthetic_root_selective_isolation_enabled=bool(
            _get(data, "task_component_synthetic_root_selective_isolation_enabled", False)
        ),
        task_component_synthetic_root_selective_max_exec_target_frequency=int(
            _get(data, "task_component_synthetic_root_selective_max_exec_target_frequency", 3)
        ),
        task_component_branch_object_overlap_split_enabled=bool(
            _get(data, "task_component_branch_object_overlap_split_enabled", False)
        ),
        attack_eval_gt_json_path=_optional_path(_get(data, "attack_eval_gt_json_path", "")),
        path_reason_gt_window_filter_mode=str(_get(data, "path_reason_gt_window_filter_mode", "none")),
        path_reason_gt_window_filter_pad_minutes=int(_get(data, "path_reason_gt_window_filter_pad_minutes", 0)),
        path_reason_gt_time_offset_minutes=int(_get(data, "path_reason_gt_time_offset_minutes", 0)),
        attack_kb_stix_path=_optional_path(_get(data, "attack_kb_stix_path", "")),
        attack_kb_candidate_limit=int(_get(data, "attack_kb_candidate_limit", 12)),
        attack_kb_embedding_model_name=str(
            _get(data, "attack_kb_embedding_model_name", "sentence-transformers/all-MiniLM-L6-v2")
        ),
        attack_kb_sparse_top_k=int(_get(data, "attack_kb_sparse_top_k", 24)),
        attack_kb_vector_top_k=int(_get(data, "attack_kb_vector_top_k", 24)),
        attack_kb_sparse_weight=float(_get(data, "attack_kb_sparse_weight", 0.45)),
        attack_kb_vector_weight=float(_get(data, "attack_kb_vector_weight", 0.55)),
        attack_kb_claim_weight=float(_get(data, "attack_kb_claim_weight", 0.25)),
        attack_kb_enable_vector=bool(_get(data, "attack_kb_enable_vector", True)),
        path_reason_enabled=bool(_get(data, "path_reason_enabled", True)),
        evidence_recover_include_object_side=bool(_get(data, "evidence_recover_include_object_side", True)),
        evidence_recover_max_events_per_task=int(_get(data, "evidence_recover_max_events_per_task", 300000)),
        evidence_recover_task_time_padding_minutes=int(
            _get(data, "evidence_recover_task_time_padding_minutes", 30)
        ),
        evidence_recover_anchor_top_k=int(_get(data, "evidence_recover_anchor_top_k", 3)),
        semantic_skip_enabled=bool(_get(data, "semantic_skip_enabled", True)),
        semantic_skip_ttl_seconds=int(_get(data, "semantic_skip_ttl_seconds", 600)),
        semantic_skip_max_table_size=int(_get(data, "semantic_skip_max_table_size", 100000)),
        semantic_force_keep_external_network=bool(_get(data, "semantic_force_keep_external_network", True)),
        semantic_force_keep_exec=bool(_get(data, "semantic_force_keep_exec", True)),
        semantic_force_keep_write_sensitive=bool(_get(data, "semantic_force_keep_write_sensitive", True)),
        episode_max_representative_events=int(_get(data, "episode_max_representative_events", 5)),
        episode_time_bucket_minutes=int(_get(data, "episode_time_bucket_minutes", 1)),
        path_bridge_max_time_gap_minutes=int(_get(data, "path_bridge_max_time_gap_minutes", 30)),
        path_max_depth=int(_get(data, "path_max_depth", 6)),
        path_max_total_span_minutes=int(_get(data, "path_max_total_span_minutes", 180)),
        path_hot_process_threshold=float(_get(data, "path_hot_process_threshold", 25.0)),
        path_top_k=int(_get(data, "path_top_k", 20)),
        path_require_execution_strong_for_high=bool(
            _get(data, "path_require_execution_strong_for_high", True)
        ),
        path_allow_weak_execution_medium=bool(_get(data, "path_allow_weak_execution_medium", True)),
        reason_top_paths_per_task=int(_get(data, "reason_top_paths_per_task", 5)),
        reason_max_timeline_items_per_path=int(_get(data, "reason_max_timeline_items_per_path", 24)),
        reason_max_bridge_edges_per_path=int(_get(data, "reason_max_bridge_edges_per_path", 8)),
        reason_max_objects_per_path=int(_get(data, "reason_max_objects_per_path", 12)),
        claim_attack_prior_mode=str(_get(data, "claim_attack_prior_mode", "full")),
        attack_mapping_scope=str(_get(data, "attack_mapping_scope", "full")),
        tactic_mapping_mode=str(_get(data, "tactic_mapping_mode", "llm")),
        path_reason_rules_path=_optional_path(_get(data, "path_reason_rules_path", "")),
    )
    _validate(cfg)
    return cfg


def _normalize_task_detection_backend(value: str) -> str:
    text = str(value).strip()
    aliases = {
        "tapas_task_graph": "tapas_native",
        "task_graph_classifier": "tapas_native",
        "tapas_native": "tapas_native",
    }
    return aliases.get(text, text)


def _validate(cfg: FusionConfig) -> None:
    allowed_dataset = {"tc3", "optc", "nodlink"}
    if cfg.dataset_family not in allowed_dataset:
        raise ValueError(f"dataset_family must be one of {sorted(allowed_dataset)}")

    allowed_task_detection_backends = {"tapas_native"}
    if cfg.task_detection_backend not in allowed_task_detection_backends:
        raise ValueError(
            "task_detection_backend must be one of "
            f"{sorted(allowed_task_detection_backends)}"
        )

    allowed_task_detector_modes = {"fit_predict", "load_and_predict", "normal_only"}
    if cfg.task_detector_mode not in allowed_task_detector_modes:
        raise ValueError(
            f"task_detector_mode must be one of {sorted(allowed_task_detector_modes)}"
        )

    if cfg.task_classifier_hidden_dim <= 0:
        raise ValueError("task_classifier_hidden_dim must be > 0")

    if cfg.task_sequence_encoder_mode not in {"legacy", "semantic_v1"}:
        raise ValueError("task_sequence_encoder_mode must be 'legacy' or 'semantic_v1'")

    if cfg.task_semantic_sequence_epochs <= 0:
        raise ValueError("task_semantic_sequence_epochs must be > 0")

    if cfg.task_semantic_sequence_batch_size <= 0:
        raise ValueError("task_semantic_sequence_batch_size must be > 0")

    if cfg.task_semantic_sequence_learning_rate <= 0:
        raise ValueError("task_semantic_sequence_learning_rate must be > 0")

    if not (0.0 < cfg.task_normal_only_train_fraction < 1.0):
        raise ValueError("task_normal_only_train_fraction must be in (0, 1)")

    if not (0.0 < cfg.task_normal_only_validation_fraction < 1.0):
        raise ValueError("task_normal_only_validation_fraction must be in (0, 1)")

    if cfg.task_normal_only_train_fraction + cfg.task_normal_only_validation_fraction >= 1.0:
        raise ValueError("normal-only train and validation fractions must sum to less than 1")

    if cfg.task_normal_only_task_prototypes <= 0:
        raise ValueError("task_normal_only_task_prototypes must be > 0")

    if cfg.task_normal_only_node_prototypes <= 0:
        raise ValueError("task_normal_only_node_prototypes must be > 0")

    if cfg.task_normal_only_node_sample_limit <= 0:
        raise ValueError("task_normal_only_node_sample_limit must be > 0")

    if cfg.task_normal_only_node_feature_mode not in {"all", "sequence_only"}:
        raise ValueError("task_normal_only_node_feature_mode must be 'all' or 'sequence_only'")

    if cfg.task_normal_only_local_top_k <= 0:
        raise ValueError("task_normal_only_local_top_k must be > 0")

    if cfg.task_normal_only_local_top_k_mode not in {"fixed", "sqrt"}:
        raise ValueError("task_normal_only_local_top_k_mode must be 'fixed' or 'sqrt'")

    if cfg.task_normal_only_local_top_k_max <= 0:
        raise ValueError("task_normal_only_local_top_k_max must be > 0")

    if cfg.task_normal_only_global_model not in {"kmeans", "knn"}:
        raise ValueError("task_normal_only_global_model must be 'kmeans' or 'knn'")

    if cfg.task_normal_only_detector not in {"prototype", "gin_autoencoder"}:
        raise ValueError("task_normal_only_detector must be 'prototype' or 'gin_autoencoder'")

    if cfg.task_normal_only_gnn_direction_mode not in {"undirected", "directed"}:
        raise ValueError("task_normal_only_gnn_direction_mode must be 'undirected' or 'directed'")

    if cfg.task_normal_only_gnn_hidden_dim <= 0:
        raise ValueError("task_normal_only_gnn_hidden_dim must be > 0")

    if cfg.task_normal_only_gnn_num_layers <= 0:
        raise ValueError("task_normal_only_gnn_num_layers must be > 0")

    if not (0.0 <= cfg.task_normal_only_gnn_dropout < 1.0):
        raise ValueError("task_normal_only_gnn_dropout must be in [0, 1)")

    if cfg.task_normal_only_gnn_epochs <= 0:
        raise ValueError("task_normal_only_gnn_epochs must be > 0")

    if cfg.task_normal_only_gnn_batch_size <= 0:
        raise ValueError("task_normal_only_gnn_batch_size must be > 0")

    if cfg.task_normal_only_gnn_learning_rate <= 0:
        raise ValueError("task_normal_only_gnn_learning_rate must be > 0")

    if cfg.task_normal_only_gnn_weight_decay < 0:
        raise ValueError("task_normal_only_gnn_weight_decay must be >= 0")

    if cfg.task_normal_only_global_knn_neighbors <= 0:
        raise ValueError("task_normal_only_global_knn_neighbors must be > 0")

    if not (0.0 <= cfg.task_normal_only_global_weight <= 1.0):
        raise ValueError("task_normal_only_global_weight must be in [0, 1]")

    if not (0.0 < cfg.task_normal_only_validation_fpr < 1.0):
        raise ValueError("task_normal_only_validation_fpr must be in (0, 1)")

    if cfg.task_classifier_num_layers <= 0:
        raise ValueError("task_classifier_num_layers must be > 0")

    if not (0.0 <= cfg.task_classifier_dropout < 1.0):
        raise ValueError("task_classifier_dropout must be in [0, 1)")

    if cfg.task_classifier_lr <= 0:
        raise ValueError("task_classifier_lr must be > 0")

    if cfg.task_classifier_weight_decay < 0:
        raise ValueError("task_classifier_weight_decay must be >= 0")

    if not (0.0 <= cfg.task_graph_stat_fusion_weight <= 1.0):
        raise ValueError("task_graph_stat_fusion_weight must be in [0, 1]")

    if cfg.task_classifier_epochs <= 0:
        raise ValueError("task_classifier_epochs must be > 0")

    if cfg.task_classifier_batch_size <= 0:
        raise ValueError("task_classifier_batch_size must be > 0")

    if cfg.attack_kb_candidate_limit <= 0:
        raise ValueError("attack_kb_candidate_limit must be > 0")

    if cfg.evidence_recover_max_events_per_task <= 0:
        raise ValueError("evidence_recover_max_events_per_task must be > 0")

    if cfg.evidence_recover_task_time_padding_minutes < 0:
        raise ValueError("evidence_recover_task_time_padding_minutes must be >= 0")

    if cfg.evidence_recover_anchor_top_k <= 0:
        raise ValueError("evidence_recover_anchor_top_k must be > 0")

    if cfg.semantic_skip_ttl_seconds <= 0:
        raise ValueError("semantic_skip_ttl_seconds must be > 0")

    if cfg.semantic_skip_max_table_size <= 0:
        raise ValueError("semantic_skip_max_table_size must be > 0")

    if cfg.episode_max_representative_events <= 0:
        raise ValueError("episode_max_representative_events must be > 0")

    if cfg.episode_time_bucket_minutes <= 0:
        raise ValueError("episode_time_bucket_minutes must be > 0")

    if cfg.path_bridge_max_time_gap_minutes < 0:
        raise ValueError("path_bridge_max_time_gap_minutes must be >= 0")

    if cfg.path_max_depth <= 0:
        raise ValueError("path_max_depth must be > 0")

    if cfg.path_max_total_span_minutes <= 0:
        raise ValueError("path_max_total_span_minutes must be > 0")

    if cfg.path_hot_process_threshold <= 0:
        raise ValueError("path_hot_process_threshold must be > 0")

    if cfg.path_top_k <= 0:
        raise ValueError("path_top_k must be > 0")

    if cfg.reason_top_paths_per_task <= 0:
        raise ValueError("reason_top_paths_per_task must be > 0")

    if cfg.reason_max_timeline_items_per_path <= 0:
        raise ValueError("reason_max_timeline_items_per_path must be > 0")

    if cfg.reason_max_bridge_edges_per_path <= 0:
        raise ValueError("reason_max_bridge_edges_per_path must be > 0")

    if cfg.reason_max_objects_per_path <= 0:
        raise ValueError("reason_max_objects_per_path must be > 0")

    allowed_claim_attack_prior_modes = {"full", "disabled"}
    if cfg.claim_attack_prior_mode not in allowed_claim_attack_prior_modes:
        raise ValueError(
            "claim_attack_prior_mode must be one of "
            f"{sorted(allowed_claim_attack_prior_modes)}"
        )

    allowed_attack_mapping_scopes = {"full", "tactics_only"}
    if cfg.attack_mapping_scope not in allowed_attack_mapping_scopes:
        raise ValueError(
            "attack_mapping_scope must be one of "
            f"{sorted(allowed_attack_mapping_scopes)}"
        )

    allowed_tactic_mapping_modes = {"deterministic", "llm"}
    if cfg.tactic_mapping_mode not in allowed_tactic_mapping_modes:
        raise ValueError(
            "tactic_mapping_mode must be one of "
            f"{sorted(allowed_tactic_mapping_modes)}"
        )

    allowed_pooling = {"mean", "max"}
    if cfg.task_classifier_pooling not in allowed_pooling:
        raise ValueError(f"task_classifier_pooling must be one of {sorted(allowed_pooling)}")

    if not (0.0 <= cfg.task_decision_threshold <= 1.0):
        raise ValueError("task_decision_threshold must be in [0, 1]")

    allowed_threshold_modes = {"fixed", "train_best_f1"}
    if cfg.task_decision_threshold_mode not in allowed_threshold_modes:
        raise ValueError(
            f"task_decision_threshold_mode must be one of {sorted(allowed_threshold_modes)}"
        )

    if not (0.0 <= cfg.task_fit_test_fraction < 1.0):
        raise ValueError("task_fit_test_fraction must be in [0, 1)")

    allowed_task_fit_split_strategies = {"stratified_shuffle_split", "stratified_kfold"}
    if cfg.task_fit_split_strategy not in allowed_task_fit_split_strategies:
        raise ValueError(
            "task_fit_split_strategy must be one of "
            f"{sorted(allowed_task_fit_split_strategies)}"
        )

    if cfg.task_fit_kfold_splits < 2:
        raise ValueError("task_fit_kfold_splits must be >= 2")

    if cfg.task_fit_kfold_index < 0:
        raise ValueError("task_fit_kfold_index must be >= 0")

    if cfg.task_min_graph_nodes <= 0:
        raise ValueError("task_min_graph_nodes must be > 0")

    if cfg.task_tapas_augmentation_divisor < 0:
        raise ValueError("task_tapas_augmentation_divisor must be >= 0")

    if cfg.task_tapas_trace_augmentation_bonus < 0:
        raise ValueError("task_tapas_trace_augmentation_bonus must be >= 0")

    if cfg.llm_request_timeout_sec <= 0:
        raise ValueError("llm_request_timeout_sec must be > 0")

    if cfg.ocr_stat_active_threshold_sec <= 0:
        raise ValueError("ocr_stat_active_threshold_sec must be > 0")

    if cfg.local_context_hops not in {1, 2}:
        raise ValueError("local_context_hops must be 1 or 2")

    allowed_module3_task_selection_modes = {
        "predicted_positive",
        "ground_truth_positive",
        "ground_truth_positive_base_only",
        "module1_ground_truth_positive_base_only",
    }
    if cfg.module3_task_selection_mode not in allowed_module3_task_selection_modes:
        raise ValueError(
            "module3_task_selection_mode must be one of "
            f"{sorted(allowed_module3_task_selection_modes)}"
        )

    allowed_task_component_split_modes = {
        "fanout",
        "connected",
    }
    if cfg.task_component_split_mode not in allowed_task_component_split_modes:
        raise ValueError(
            "task_component_split_mode must be one of "
            f"{sorted(allowed_task_component_split_modes)}"
        )

    if cfg.task_component_child_threshold < 0:
        raise ValueError("task_component_child_threshold must be >= 0")

    if cfg.task_component_provgrp_min_direct_children < 1:
        raise ValueError("task_component_provgrp_min_direct_children must be >= 1")

    if cfg.task_component_provgrp_min_cluster_size < 2:
        raise ValueError("task_component_provgrp_min_cluster_size must be >= 2")

    if cfg.task_component_provgrp_min_samples < 1:
        raise ValueError("task_component_provgrp_min_samples must be >= 1")

    if cfg.task_component_provgrp_max_events_per_matrix < 2:
        raise ValueError("task_component_provgrp_max_events_per_matrix must be >= 2")
    if (
        cfg.task_component_provgrp_batch_overlap_events < 0
        or cfg.task_component_provgrp_batch_overlap_events >= cfg.task_component_provgrp_max_events_per_matrix
    ):
        raise ValueError(
            "task_component_provgrp_batch_overlap_events must be >= 0 and smaller than "
            "task_component_provgrp_max_events_per_matrix"
        )

    if cfg.task_component_theia_max_span_minutes <= 0:
        raise ValueError("task_component_theia_max_span_minutes must be > 0")

    if cfg.task_component_theia_branch_gap_minutes < 0:
        raise ValueError("task_component_theia_branch_gap_minutes must be >= 0")

    allowed_path_reason_gt_window_filter_modes = {"none", "confirmed_only"}
    if cfg.path_reason_gt_window_filter_mode not in allowed_path_reason_gt_window_filter_modes:
        raise ValueError(
            "path_reason_gt_window_filter_mode must be one of "
            f"{sorted(allowed_path_reason_gt_window_filter_modes)}"
        )

    if cfg.path_reason_gt_window_filter_pad_minutes < 0:
        raise ValueError("path_reason_gt_window_filter_pad_minutes must be >= 0")

    if cfg.path_reason_gt_time_offset_minutes < 0:
        raise ValueError("path_reason_gt_time_offset_minutes must be >= 0")

    if cfg.graphsage_append_ocr_stat_features and not cfg.use_ocr_stat_features:
        raise ValueError("graphsage_append_ocr_stat_features requires use_ocr_stat_features=true")

    allowed_tc3_event_stats_modes = {"legacy_aggregate", "core", "extended", "security_semantic"}
    if cfg.task_tc3_event_stats_mode not in allowed_tc3_event_stats_modes:
        raise ValueError(
            "task_tc3_event_stats_mode must be one of "
            f"{sorted(allowed_tc3_event_stats_modes)}"
        )

    if cfg.dataset_family in {"tc3", "optc"} and not cfg.use_sequence_embeddings and not cfg.use_ocr_stat_features:
        raise ValueError(
            "TAPAS-native module1/module2 require at least one node feature source: "
            "enable use_sequence_embeddings or use_ocr_stat_features."
        )

"""Normal-only graph autoencoders used by the G1 directionality experiment.

The model learns only from benign task graphs.  Its local anomaly signal is the
node feature reconstruction error and its global signal is the distance of a
pooled graph embedding from benign graph prototypes.  G1 deliberately uses the
same objective for the undirected and directed variants so the comparison only
tests whether preserving parent-to-child direction helps.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import torch
from sklearn.cluster import MiniBatchKMeans
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler
from torch import nn
from torch.nn import functional as F
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from torch_geometric.nn import DirGNNConv, GINConv, global_max_pool, global_mean_pool
from torch_geometric.utils import to_undirected

from ..common import ensure_parent
from ..config import FusionConfig


@dataclass
class NormalOnlyGNNResult:
    rows: list[dict[str, Any]]
    model: dict[str, Any]
    info: dict[str, Any]


def _mlp(input_dim: int, output_dim: int) -> nn.Sequential:
    return nn.Sequential(
        nn.Linear(input_dim, output_dim),
        nn.ReLU(),
        nn.Linear(output_dim, output_dim),
    )


class GINFeatureAutoencoder(nn.Module):
    """GIN encoder plus feature decoder, optionally preserving edge direction."""

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int,
        num_layers: int,
        dropout: float,
        direction_mode: str,
    ) -> None:
        super().__init__()
        self.direction_mode = direction_mode
        self.dropout = float(dropout)
        layers: list[nn.Module] = []
        current_dim = input_dim
        for _ in range(num_layers):
            base = GINConv(_mlp(current_dim, hidden_dim), train_eps=True)
            # GIN keeps each node's own state; DirGNN adds separate incoming and
            # outgoing aggregation without changing the GIN aggregation rule.
            layer: nn.Module = (
                DirGNNConv(base, alpha=0.5, root_weight=False)
                if direction_mode == "directed"
                else base
            )
            layers.append(layer)
            current_dim = hidden_dim
        self.layers = nn.ModuleList(layers)
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        if self.direction_mode == "undirected" and edge_index.numel() > 0:
            edge_index = to_undirected(edge_index, num_nodes=x.size(0))
        embedding = x
        for layer in self.layers:
            embedding = layer(embedding, edge_index)
            embedding = F.relu(embedding)
            embedding = F.dropout(embedding, p=self.dropout, training=self.training)
        return embedding, self.decoder(embedding)


def _sample_rows(matrix: np.ndarray, limit: int, seed: int) -> np.ndarray:
    if len(matrix) <= limit:
        return matrix
    rng = np.random.default_rng(seed)
    indices = np.sort(rng.choice(len(matrix), size=limit, replace=False))
    return matrix[indices]


def _fit_kmeans(matrix: np.ndarray, requested_clusters: int, seed: int) -> MiniBatchKMeans:
    return MiniBatchKMeans(
        n_clusters=max(1, min(int(requested_clusters), len(matrix))),
        random_state=int(seed),
        batch_size=min(4096, max(64, len(matrix))),
        n_init=10,
    ).fit(matrix)


def _fit_graph_model(
    matrix: np.ndarray,
    cfg: FusionConfig,
) -> tuple[MiniBatchKMeans | NearestNeighbors, str]:
    if cfg.task_normal_only_global_model == "knn":
        neighbors = min(max(1, int(cfg.task_normal_only_global_knn_neighbors)), len(matrix))
        return NearestNeighbors(n_neighbors=neighbors, metric="euclidean").fit(matrix), "knn"
    return _fit_kmeans(matrix, int(cfg.task_normal_only_task_prototypes), int(cfg.random_seed)), "kmeans"


def _graph_scores(
    matrix: np.ndarray,
    scaler: StandardScaler,
    model: MiniBatchKMeans | NearestNeighbors,
    mode: str,
) -> np.ndarray:
    transformed = scaler.transform(matrix)
    if mode == "knn":
        distances, _ = model.kneighbors(transformed)
        return distances.mean(axis=1).astype(np.float64)
    return model.transform(transformed).min(axis=1).astype(np.float64)


def _robust_scale(reference: np.ndarray) -> tuple[float, float]:
    center = float(np.median(reference))
    mad = float(np.median(np.abs(reference - center)))
    return center, max(1e-8, 1.4826 * mad)


def _top_k(cfg: FusionConfig, node_count: int) -> int:
    if cfg.task_normal_only_local_top_k_mode == "sqrt":
        requested = min(
            int(np.ceil(np.sqrt(max(1, node_count)))),
            int(cfg.task_normal_only_local_top_k_max),
        )
    else:
        requested = int(cfg.task_normal_only_local_top_k)
    return min(max(1, requested), max(1, node_count))


def _edge_index(graph: dict[str, Any], node_ids: Sequence[str]) -> torch.Tensor:
    index_by_node = {str(node): index for index, node in enumerate(node_ids)}
    edges: list[tuple[int, int]] = []
    for edge in graph.get("edges", []):
        if not isinstance(edge, (list, tuple)) or len(edge) < 2:
            continue
        source = index_by_node.get(str(edge[0]))
        target = index_by_node.get(str(edge[1]))
        if source is not None and target is not None:
            edges.append((source, target))
    if not edges:
        return torch.empty((2, 0), dtype=torch.long)
    return torch.tensor(edges, dtype=torch.long).t().contiguous()


def _as_data(graph: dict[str, Any], meta: dict[str, Any], scaler: StandardScaler) -> Data:
    node_ids = [str(node) for node in meta.get("node_ids", [])]
    nodes = np.asarray(graph.get("nodes", []), dtype=np.float32)
    if nodes.ndim != 2 or len(nodes) == 0:
        raise ValueError(f"task {meta.get('task_id', '')} has no usable node features")
    if len(node_ids) != len(nodes):
        raise ValueError(f"task {meta.get('task_id', '')} node ids and feature rows differ")
    return Data(
        x=torch.as_tensor(scaler.transform(nodes), dtype=torch.float32),
        edge_index=_edge_index(graph, node_ids),
    )


def _build_data(
    graphs: Sequence[dict[str, Any]],
    metas: Sequence[dict[str, Any]],
    indices: Sequence[int],
    scaler: StandardScaler,
) -> list[Data]:
    return [_as_data(graphs[index], metas[index], scaler) for index in indices]


def _device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _train_encoder(
    cfg: FusionConfig,
    train_data: Sequence[Data],
    input_dim: int,
) -> tuple[GINFeatureAutoencoder, list[float], str]:
    torch.manual_seed(int(cfg.random_seed))
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(int(cfg.random_seed))
    device = _device()
    model = GINFeatureAutoencoder(
        input_dim=input_dim,
        hidden_dim=int(cfg.task_normal_only_gnn_hidden_dim),
        num_layers=int(cfg.task_normal_only_gnn_num_layers),
        dropout=float(cfg.task_normal_only_gnn_dropout),
        direction_mode=cfg.task_normal_only_gnn_direction_mode,
    ).to(device)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=float(cfg.task_normal_only_gnn_learning_rate),
        weight_decay=float(cfg.task_normal_only_gnn_weight_decay),
    )
    loader = DataLoader(list(train_data), batch_size=int(cfg.task_normal_only_gnn_batch_size), shuffle=True)
    losses: list[float] = []
    for _ in range(int(cfg.task_normal_only_gnn_epochs)):
        model.train()
        epoch_losses: list[float] = []
        for batch in loader:
            batch = batch.to(device)
            _, reconstructed = model(batch.x, batch.edge_index)
            node_error = F.mse_loss(reconstructed, batch.x, reduction="none").mean(dim=1)
            # Each task has equal influence; a giant service tree cannot dominate
            # the normality model merely because it has more process nodes.
            task_error = global_mean_pool(node_error, batch.batch)
            loss = task_error.mean()
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()
            epoch_losses.append(float(loss.detach().cpu()))
        losses.append(float(np.mean(epoch_losses)) if epoch_losses else 0.0)
    return model, losses, str(device)


@torch.no_grad()
def _encode_and_score(
    model: GINFeatureAutoencoder,
    data: Sequence[Data],
    cfg: FusionConfig,
) -> tuple[np.ndarray, np.ndarray]:
    device = _device()
    model.eval().to(device)
    loader = DataLoader(list(data), batch_size=1, shuffle=False)
    local_scores: list[float] = []
    graph_embeddings: list[np.ndarray] = []
    for batch in loader:
        batch = batch.to(device)
        embedding, reconstructed = model(batch.x, batch.edge_index)
        errors = F.mse_loss(reconstructed, batch.x, reduction="none").mean(dim=1).detach().cpu().numpy()
        keep = _top_k(cfg, len(errors))
        local_scores.append(float(np.partition(errors, len(errors) - keep)[-keep:].mean()))
        mean = global_mean_pool(embedding, batch.batch)
        maximum = global_max_pool(embedding, batch.batch)
        graph_embeddings.append(torch.cat([mean, maximum], dim=1).squeeze(0).detach().cpu().numpy())
    return np.asarray(local_scores, dtype=np.float64), np.asarray(graph_embeddings, dtype=np.float64)


def run_normal_only_gin_autoencoder(
    cfg: FusionConfig,
    graphs: Sequence[dict[str, Any]],
    metas: Sequence[dict[str, Any]],
    split: dict[str, Any],
    model_path: Path,
) -> NormalOnlyGNNResult:
    """Fit the G1 detector and return scores only for the held-out evaluation set."""
    train_indices = list(split["train_indices"])
    validation_indices = list(split["validation_indices"])
    evaluation_indices = list(split["evaluation_indices"])
    raw_train_nodes = np.concatenate(
        [np.asarray(graphs[index]["nodes"], dtype=np.float64) for index in train_indices], axis=0
    )
    node_scaler = StandardScaler().fit(
        _sample_rows(raw_train_nodes, int(cfg.task_normal_only_node_sample_limit), int(cfg.random_seed))
    )
    train_data = _build_data(graphs, metas, train_indices, node_scaler)
    validation_data = _build_data(graphs, metas, validation_indices, node_scaler)
    evaluation_data = _build_data(graphs, metas, evaluation_indices, node_scaler)
    input_dim = int(train_data[0].x.size(1))
    encoder, losses, device_name = _train_encoder(cfg, train_data, input_dim)

    _, train_embeddings = _encode_and_score(encoder, train_data, cfg)
    graph_scaler = StandardScaler().fit(train_embeddings)
    graph_model, graph_model_mode = _fit_graph_model(graph_scaler.transform(train_embeddings), cfg)
    validation_local, validation_embeddings = _encode_and_score(encoder, validation_data, cfg)
    validation_global = _graph_scores(validation_embeddings, graph_scaler, graph_model, graph_model_mode)
    local_center, local_scale = _robust_scale(validation_local)
    global_center, global_scale = _robust_scale(validation_global)
    validation_scores = (
        (1.0 - float(cfg.task_normal_only_global_weight))
        * np.maximum(0.0, (validation_local - local_center) / local_scale)
        + float(cfg.task_normal_only_global_weight)
        * np.maximum(0.0, (validation_global - global_center) / global_scale)
    )
    threshold = float(np.quantile(validation_scores, 1.0 - float(cfg.task_normal_only_validation_fpr)))

    evaluation_local, evaluation_embeddings = _encode_and_score(encoder, evaluation_data, cfg)
    evaluation_global = _graph_scores(evaluation_embeddings, graph_scaler, graph_model, graph_model_mode)
    evaluation_scores = (
        (1.0 - float(cfg.task_normal_only_global_weight))
        * np.maximum(0.0, (evaluation_local - local_center) / local_scale)
        + float(cfg.task_normal_only_global_weight)
        * np.maximum(0.0, (evaluation_global - global_center) / global_scale)
    )
    rows: list[dict[str, Any]] = []
    for index, local, global_score, score in zip(
        evaluation_indices,
        evaluation_local.tolist(),
        evaluation_global.tolist(),
        evaluation_scores.tolist(),
    ):
        graph = graphs[index]
        meta = metas[index]
        rows.append(
            {
                "task_id": str(meta.get("task_id", f"task_{index:04d}")),
                "task_score": float(score),
                "task_probability": float(score),
                "graphsage_probability": None,
                "stats_probability": None,
                "normal_only_local_score": float(local),
                "normal_only_global_score": float(global_score),
                "fusion_weight_stats": 0.0,
                "task_label": int(graph.get("label", meta.get("label", 0))),
                "predicted_label": int(score >= threshold),
                "prediction_mode": "normal_only_validation_threshold",
                "task_score_basis": "gin_feature_reconstruction_plus_graph_prototype_distance",
                "threshold_used": threshold,
                "is_suspicious": bool(score >= threshold),
                "task_size": int(meta.get("task_size", len(graph.get("nodes", [])))),
                "internal_edge_count": int(meta.get("internal_edge_count", len(graph.get("edges", [])))),
                "process_ids": [str(node) for node in meta.get("node_ids", [])],
                "process_stat_overrides": dict(meta.get("process_stat_overrides", {})),
            }
        )
    rows.sort(key=lambda row: (float(row["task_score"]), row["task_id"]), reverse=True)

    checkpoint_path = model_path.with_name("normal_only_gin_autoencoder.pt")
    ensure_parent(checkpoint_path)
    torch.save(
        {
            "state_dict": encoder.cpu().state_dict(),
            "input_dim": input_dim,
            "hidden_dim": int(cfg.task_normal_only_gnn_hidden_dim),
            "num_layers": int(cfg.task_normal_only_gnn_num_layers),
            "dropout": float(cfg.task_normal_only_gnn_dropout),
            "direction_mode": cfg.task_normal_only_gnn_direction_mode,
        },
        checkpoint_path,
    )
    model = {
        "mode": "normal_only_gin_autoencoder",
        "checkpoint_path": str(checkpoint_path),
        "node_scaler": node_scaler,
        "graph_scaler": graph_scaler,
        "graph_model": graph_model,
        "graph_model_mode": graph_model_mode,
        "local_center": local_center,
        "local_scale": local_scale,
        "global_center": global_center,
        "global_scale": global_scale,
        "threshold": threshold,
    }
    ensure_parent(model_path)
    with model_path.open("wb") as handle:
        import pickle

        pickle.dump(model, handle)
    return NormalOnlyGNNResult(
        rows=rows,
        model=model,
        info={
            **dict(split["summary"]),
            "detector": "gin_autoencoder",
            "direction_mode": cfg.task_normal_only_gnn_direction_mode,
            "device": device_name,
            "input_dim": input_dim,
            "hidden_dim": int(cfg.task_normal_only_gnn_hidden_dim),
            "num_layers": int(cfg.task_normal_only_gnn_num_layers),
            "epochs": int(cfg.task_normal_only_gnn_epochs),
            "batch_size": int(cfg.task_normal_only_gnn_batch_size),
            "learning_rate": float(cfg.task_normal_only_gnn_learning_rate),
            "weight_decay": float(cfg.task_normal_only_gnn_weight_decay),
            "epoch_loss": losses,
            "node_training_sample_count": int(len(raw_train_nodes)),
            "graph_training_task_count": int(len(train_data)),
            "graph_prototype_count": int(graph_model.n_clusters) if graph_model_mode == "kmeans" else 0,
            "global_model": graph_model_mode,
            "global_weight": float(cfg.task_normal_only_global_weight),
            "threshold": threshold,
            "threshold_source": "benign_validation_quantile",
            "validation_fpr_target": float(cfg.task_normal_only_validation_fpr),
            "validation_score_min": float(validation_scores.min()),
            "validation_score_max": float(validation_scores.max()),
            "validation_score_median": float(np.median(validation_scores)),
            "checkpoint_path": str(checkpoint_path),
        },
    )

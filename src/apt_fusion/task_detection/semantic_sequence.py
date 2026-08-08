"""Benign-only semantic event-sequence encoder for TC3 task graphs.

This intentionally does not reuse TAPAS' legacy numeric event IDs.  The
parser supplies a versioned, canonical event vocabulary and compact
per-process histories; the encoder then learns next-summary prediction using
only process histories from temporally earlier benign task graphs.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import torch
from torch import Tensor, nn
from torch.nn import functional as functional


SEMANTIC_SEQUENCE_VERSION = "tc3_semantic_v1"
SEMANTIC_VOCAB_SIZE = 16  # 0 is padding; parser categories use 1..15.
OUTPUT_DIM = 42


class SemanticSequenceEncoder(nn.Module):
    """Encode semantic event summaries and predict the following category."""

    def __init__(self, vocab_size: int = SEMANTIC_VOCAB_SIZE, output_dim: int = OUTPUT_DIM) -> None:
        super().__init__()
        self.event_embedding = nn.Embedding(vocab_size, 24, padding_idx=0)
        self.count_projection = nn.Sequential(nn.Linear(1, 8), nn.ReLU())
        self.gru = nn.GRU(32, output_dim, batch_first=True)
        self.next_event_head = nn.Linear(output_dim, vocab_size)

    def forward(self, event_ids: Tensor, log_counts: Tensor, lengths: Tensor) -> tuple[Tensor, Tensor]:
        event_features = self.event_embedding(event_ids)
        count_features = self.count_projection(log_counts.unsqueeze(-1))
        encoded, _ = self.gru(torch.cat((event_features, count_features), dim=-1))
        batch_index = torch.arange(encoded.shape[0], device=encoded.device)
        last_index = torch.clamp(lengths - 1, min=0)
        return encoded[batch_index, last_index], self.next_event_head(encoded)


@dataclass(frozen=True)
class SemanticSequenceResult:
    vectors: dict[str, list[float]]
    prediction_errors: dict[str, float]
    metadata: dict[str, Any]


def _prepare_history(value: object) -> list[tuple[int, float]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    history: list[tuple[int, float]] = []
    for entry in value:
        if not isinstance(entry, Sequence) or isinstance(entry, (str, bytes)) or len(entry) < 2:
            continue
        try:
            event_id = int(entry[0])
            count = max(0.0, float(entry[1]))
        except (TypeError, ValueError):
            continue
        if 0 < event_id < SEMANTIC_VOCAB_SIZE:
            history.append((event_id, math.log1p(count)))
    return history


def _batch_tensors(
    histories: Sequence[list[tuple[int, float]]],
    device: torch.device,
) -> tuple[Tensor, Tensor, Tensor]:
    max_length = max(len(history) for history in histories)
    event_ids = torch.zeros((len(histories), max_length), dtype=torch.long, device=device)
    log_counts = torch.zeros((len(histories), max_length), dtype=torch.float32, device=device)
    lengths = torch.zeros((len(histories),), dtype=torch.long, device=device)
    for index, history in enumerate(histories):
        lengths[index] = len(history)
        event_ids[index, : len(history)] = torch.tensor([item[0] for item in history], dtype=torch.long, device=device)
        log_counts[index, : len(history)] = torch.tensor([item[1] for item in history], dtype=torch.float32, device=device)
    return event_ids, log_counts, lengths


def _prediction_loss(logits: Tensor, event_ids: Tensor, lengths: Tensor) -> Tensor:
    # Each retained summary predicts the semantic category of the next summary.
    if logits.shape[1] <= 1:
        return logits.sum() * 0.0
    targets = event_ids[:, 1:].clone()
    positions = torch.arange(targets.shape[1], device=targets.device).unsqueeze(0)
    targets[positions >= (lengths - 1).unsqueeze(1)] = -100
    return functional.cross_entropy(logits[:, :-1, :].reshape(-1, logits.shape[-1]), targets.reshape(-1), ignore_index=-100)


def _top_error(logits: Tensor, event_ids: Tensor, lengths: Tensor) -> list[float]:
    result: list[float] = []
    log_probs = functional.log_softmax(logits[:, :-1, :], dim=-1)
    for index, length in enumerate(lengths.tolist()):
        if length <= 1:
            result.append(0.0)
            continue
        targets = event_ids[index, 1:length]
        nll = -log_probs[index, : length - 1, :].gather(1, targets.unsqueeze(1)).squeeze(1)
        top_count = min(3, int(nll.numel()))
        result.append(float(torch.topk(nll, k=top_count).values.mean().item()))
    return result


def fit_benign_semantic_sequence_encoder(
    histories: Mapping[str, object],
    train_subject_ids: set[str],
    output_path: Path,
    *,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    seed: int,
    pretrained_path: Path | None = None,
) -> SemanticSequenceResult:
    """Fit on benign training subjects, then encode every observed process."""

    prepared = {str(subject): _prepare_history(history) for subject, history in histories.items()}
    train_rows = [(subject, history) for subject, history in prepared.items() if subject in train_subject_ids and len(history) >= 2]
    if len(train_rows) < 32:
        raise ValueError(f"semantic sequence training needs at least 32 benign histories with two summaries; found {len(train_rows)}")

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = SemanticSequenceEncoder().to(device)
    reused_checkpoint = False
    loss_history: list[float] = []
    if pretrained_path is not None and pretrained_path.exists():
        checkpoint = torch.load(pretrained_path, map_location=device, weights_only=False)
        if checkpoint.get("version") != SEMANTIC_SEQUENCE_VERSION:
            raise ValueError(f"semantic sequence checkpoint version mismatch: {pretrained_path}")
        model.load_state_dict(checkpoint["state_dict"])
        loss_history = [float(value) for value in checkpoint.get("loss_history", [])]
        reused_checkpoint = True
    else:
        optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-5)
        rng = random.Random(seed)
        for _ in range(epochs):
            order = list(range(len(train_rows)))
            rng.shuffle(order)
            epoch_loss = 0.0
            batch_count = 0
            model.train()
            for offset in range(0, len(order), batch_size):
                rows = [train_rows[index][1] for index in order[offset : offset + batch_size]]
                event_ids, log_counts, lengths = _batch_tensors(rows, device)
                _, logits = model(event_ids, log_counts, lengths)
                loss = _prediction_loss(logits, event_ids, lengths)
                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
                optimizer.step()
                epoch_loss += float(loss.detach().item())
                batch_count += 1
            loss_history.append(epoch_loss / max(1, batch_count))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "version": SEMANTIC_SEQUENCE_VERSION,
                "vocab_size": SEMANTIC_VOCAB_SIZE,
                "output_dim": OUTPUT_DIM,
                "state_dict": model.state_dict(),
                "train_subject_count": len(train_rows),
                "epochs": epochs,
                "batch_size": batch_size,
                "learning_rate": learning_rate,
                "loss_history": loss_history,
            },
            output_path,
        )

    vectors: dict[str, list[float]] = {}
    errors: dict[str, float] = {}
    subjects = list(prepared)
    model.eval()
    with torch.no_grad():
        for offset in range(0, len(subjects), batch_size):
            batch_subjects = subjects[offset : offset + batch_size]
            batch_histories = [prepared[subject] for subject in batch_subjects]
            nonempty = [(index, history) for index, history in enumerate(batch_histories) if history]
            for index, _ in enumerate(batch_histories):
                if not batch_histories[index]:
                    vectors[batch_subjects[index]] = [0.0] * OUTPUT_DIM
                    errors[batch_subjects[index]] = 0.0
            if not nonempty:
                continue
            retained_indices = [item[0] for item in nonempty]
            retained_histories = [item[1] for item in nonempty]
            event_ids, log_counts, lengths = _batch_tensors(retained_histories, device)
            embedding, logits = model(event_ids, log_counts, lengths)
            batch_errors = _top_error(logits, event_ids, lengths)
            for local_index, source_index in enumerate(retained_indices):
                subject = batch_subjects[source_index]
                vectors[subject] = [float(value) for value in embedding[local_index].cpu().tolist()]
                errors[subject] = batch_errors[local_index]

    return SemanticSequenceResult(
        vectors=vectors,
        prediction_errors=errors,
        metadata={
            "version": SEMANTIC_SEQUENCE_VERSION,
            "checkpoint": str(output_path),
            "vocab_size": SEMANTIC_VOCAB_SIZE,
            "embedding_dim": OUTPUT_DIM,
            "history_subject_count": sum(1 for value in prepared.values() if value),
            "train_subject_count": len(train_rows),
            "epochs": epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "loss_history": loss_history,
            "reused_checkpoint": reused_checkpoint,
            "pretrained_checkpoint": str(pretrained_path) if reused_checkpoint and pretrained_path is not None else "",
        },
    )

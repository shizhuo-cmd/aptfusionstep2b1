"""Pretrain the TAPAS LSTM-GRU on THEIA E5 next-event prediction.

The offline objective matches TAPAS: each process representation at event t
predicts the embedding vector of that process's event t + 1.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import os
import random
import shutil
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset


REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = REPO_ROOT / "vendor" / "tapas"


@contextmanager
def _temporary_cwd(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _copy_support_files(workspace: Path) -> None:
    for directory in ("data", "model"):
        target = workspace / directory
        target.mkdir(parents=True, exist_ok=True)
        for source in (VENDOR_ROOT / directory).glob("*"):
            if source.is_file():
                shutil.copy2(source, target / source.name)


def _load_vendor() -> Any:
    import importlib.util

    path = VENDOR_ROOT / "darpa.py"
    spec = importlib.util.spec_from_file_location("tapas_e5_next_event_20260725", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SequenceDataset(Dataset):
    def __init__(self, sequences: list[np.ndarray]):
        self.sequences = sequences

    def __len__(self) -> int:
        return len(self.sequences)

    def __getitem__(self, index: int) -> np.ndarray:
        return self.sequences[index]


def _collate(batch: list[np.ndarray]) -> tuple[torch.Tensor, torch.Tensor]:
    lengths = torch.tensor([item.shape[0] for item in batch], dtype=torch.long)
    result = np.zeros((len(batch), int(lengths.max()), 6), dtype=np.float32)
    for index, item in enumerate(batch):
        result[index, : item.shape[0], :] = item
    return torch.from_numpy(result), lengths


class StackedLSTMGRU(nn.Module):
    """Checkpoint-compatible TAPAS sequence encoder with training logits."""

    def __init__(self) -> None:
        super().__init__()
        self.lstm0 = nn.LSTMCell(6, hidden_size=16)
        self.gru = nn.GRUCell(input_size=16, hidden_size=10)
        self.dropout = nn.Dropout(p=0.4)
        self.linear = nn.Linear(10, 6)

    def forward_train(self, values: torch.Tensor) -> torch.Tensor:
        batch_size, sequence_length, _ = values.shape
        h0 = torch.zeros(batch_size, 16, device=values.device)
        c0 = torch.zeros(batch_size, 16, device=values.device)
        h1 = torch.zeros(batch_size, 10, device=values.device)
        predictions = []
        for time_index in range(sequence_length):
            h0, c0 = self.lstm0(values[:, time_index, :], (h0, c0))
            h0 = self.dropout(h0)
            c0 = self.dropout(c0)
            h1 = self.gru(h0, h1)
            h1 = self.dropout(h1)
            predictions.append(self.linear(h1))
        return torch.stack(predictions, dim=1)


def _numeric(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        try:
            return float(int(str(value).strip(), 0))
        except (TypeError, ValueError):
            return 0.0


def _normalize(values: torch.Tensor, scales: torch.Tensor) -> torch.Tensor:
    result = values.clone()
    result[..., 0] /= max(float(scales[0]), 1.0)
    result[..., 1] = torch.log1p(torch.clamp_min(result[..., 1], 0.0)) / math.log1p(max(float(scales[1]), 1.0))
    for index in range(2, 6):
        result[..., index] /= max(float(scales[index]), 1.0)
    return result


def _loss(prediction: torch.Tensor, target: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
    weights = torch.tensor([2.0, 0.25, 1.0, 1.0, 1.0, 1.0], device=prediction.device)
    values = F.smooth_l1_loss(prediction, target, reduction="none") * weights.view(1, 1, -1)
    values *= mask.unsqueeze(-1)
    return values.sum() / (mask.sum().clamp_min(1.0) * 6.0)


def run(args: argparse.Namespace) -> dict[str, Any]:
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    output_dir = args.output_dir.resolve()
    workspace = output_dir / "workspace"
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    _copy_support_files(workspace)

    vendor = _load_vendor()
    vendor.device = device
    with _temporary_cwd(workspace):
        history_map, parser_summary = vendor.filters_theia_e5(
            str(args.logs.resolve()) + os.sep,
            return_sequence_histories=True,
        )

    sequences = []
    for history in history_map.values():
        if len(history) < 2:
            continue
        values = np.asarray([[_numeric(value) for value in event] for event in history], dtype=np.float32)
        if values.shape[0] > args.max_seq_len:
            values = values[-args.max_seq_len :, :]
        sequences.append(values)
    random.Random(args.seed).shuffle(sequences)
    if args.max_sequences > 0:
        sequences = sequences[: args.max_sequences]
    if len(sequences) < 2:
        raise RuntimeError("E5 parser produced fewer than two process histories with next events")

    val_count = max(1, int(round(len(sequences) * args.val_fraction)))
    val_sequences, train_sequences = sequences[:val_count], sequences[val_count:]
    maxima = np.maximum.reduce([sequence.max(axis=0) for sequence in train_sequences])
    scales = torch.tensor(np.maximum(maxima, 1.0), dtype=torch.float32, device=device)
    train_loader = DataLoader(SequenceDataset(train_sequences), batch_size=args.batch_size, shuffle=True, collate_fn=_collate)
    val_loader = DataLoader(SequenceDataset(val_sequences), batch_size=args.batch_size, shuffle=False, collate_fn=_collate)

    model = StackedLSTMGRU().to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    best_state = copy.deepcopy(model.state_dict())
    best_val_loss = float("inf")
    history = []
    patience_left = args.patience

    def run_epoch(loader: DataLoader, training: bool) -> float:
        model.train(training)
        weighted_loss = 0.0
        steps = 0
        for values, lengths in loader:
            values = values.to(device)
            lengths = lengths.to(device)
            source, target = values[:, :-1, :], values[:, 1:, :]
            mask = (torch.arange(source.shape[1], device=device).unsqueeze(0) < (lengths - 1).unsqueeze(1)).float()
            prediction = model.forward_train(source)
            value = _loss(prediction, _normalize(target, scales), mask)
            if training:
                optimizer.zero_grad(set_to_none=True)
                value.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
            count = int(mask.sum().item())
            weighted_loss += float(value.detach().cpu()) * count
            steps += count
        return weighted_loss / max(steps, 1)

    for epoch in range(1, args.epochs + 1):
        train_loss = run_epoch(train_loader, True)
        validation_loss = run_epoch(val_loader, False)
        history.append({"epoch": epoch, "train_loss": train_loss, "validation_loss": validation_loss})
        if validation_loss < best_val_loss:
            best_val_loss = validation_loss
            best_state = copy.deepcopy(model.state_dict())
            patience_left = args.patience
        else:
            patience_left -= 1
            if patience_left == 0:
                break

    model_path = output_dir / "stackedlstm_theia_e5_next_event_20260725.pt"
    torch.save(best_state, model_path)
    summary = {
        "objective": "same_process_event_t_predicts_event_t_plus_1",
        "logs": str(args.logs),
        "device": str(device),
        "parser_summary": parser_summary,
        "eligible_sequence_count": len(history_map),
        "sampled_sequence_count": len(sequences),
        "train_sequence_count": len(train_sequences),
        "validation_sequence_count": len(val_sequences),
        "max_sequence_length": args.max_seq_len,
        "feature_scales": [float(value) for value in scales.detach().cpu().tolist()],
        "epochs": history,
        "best_validation_loss": best_val_loss,
        "model_path": str(model_path),
    }
    (output_dir / "training_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--max-seq-len", type=int, default=128)
    parser.add_argument("--max-sequences", type=int, default=250000)
    parser.add_argument("--val-fraction", type=float, default=0.1)
    parser.add_argument("--patience", type=int, default=2)
    parser.add_argument("--seed", type=int, default=173)
    print(json.dumps(run(parser.parse_args()), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

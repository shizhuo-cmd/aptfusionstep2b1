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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset


REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR_TAPAS_ROOT = REPO_ROOT / "vendor" / "tapas"


@contextmanager
def _temporary_cwd(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _copy_vendor_support_files(workspace: Path) -> None:
    data_dir = workspace / "data"
    model_dir = workspace / "model"
    data_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)
    for source in (VENDOR_TAPAS_ROOT / "data").glob("*"):
        if source.is_file():
            shutil.copy2(source, data_dir / source.name)
    for source in (VENDOR_TAPAS_ROOT / "model").glob("*"):
        if source.is_file():
            shutil.copy2(source, model_dir / source.name)


def _load_vendor_darpa():
    vendor_path = VENDOR_TAPAS_ROOT / "darpa.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("tapas_vendor_darpa_pretrain_20260707", vendor_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load vendor module from {vendor_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass
class SubjectSequence:
    host: str
    subject_id: str
    values: np.ndarray


class TC3SequenceDataset(Dataset):
    def __init__(self, items: list[SubjectSequence]):
        self.items = items

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, index: int) -> SubjectSequence:
        return self.items[index]


def _collate_sequences(batch: list[SubjectSequence]) -> dict[str, Any]:
    if not batch:
        raise ValueError("Empty batch")
    lengths = [int(item.values.shape[0]) for item in batch]
    max_len = max(lengths)
    feature_dim = int(batch[0].values.shape[1])
    inputs = np.zeros((len(batch), max_len, feature_dim), dtype=np.float32)
    for idx, item in enumerate(batch):
        length = lengths[idx]
        inputs[idx, :length, :] = item.values
    return {
        "inputs": torch.from_numpy(inputs),
        "lengths": torch.tensor(lengths, dtype=torch.long),
        "hosts": [item.host for item in batch],
        "subject_ids": [item.subject_id for item in batch],
    }


class TC3StackedLSTMPretrain(nn.Module):
    def __init__(self, input_size: int = 6, output_size: int = 6):
        super().__init__()
        self.input_size = input_size
        self.output_size = output_size
        self.lstm0 = nn.LSTMCell(input_size, hidden_size=16)
        self.gru = nn.GRUCell(input_size=16, hidden_size=10)
        self.dropout = nn.Dropout(p=0.4)
        self.linear = nn.Linear(10, output_size)

    def forward(self, input_seq: torch.Tensor) -> torch.Tensor:
        _, embedding = self.forward_train(input_seq)
        return embedding

    def forward_train(self, input_seq: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        batch_size, seq_len, _ = input_seq.shape
        device = input_seq.device
        c_l0 = torch.zeros(batch_size, 16, device=device)
        h_l0 = torch.zeros(batch_size, 16, device=device)
        h_l1 = torch.zeros(batch_size, 10, device=device)
        preds: list[torch.Tensor] = []
        for t in range(seq_len):
            h_l0, c_l0 = self.lstm0(input_seq[:, t, :], (h_l0, c_l0))
            h_l0 = self.dropout(h_l0)
            c_l0 = self.dropout(c_l0)
            h_l1 = self.gru(h_l0, h_l1)
            h_l1 = self.dropout(h_l1)
            preds.append(self.linear(h_l1))
        pred_tensor = torch.stack(preds, dim=1)
        embedding = torch.cat([h_l0, c_l0, h_l1], dim=1)
        return pred_tensor, embedding


def _weighted_regression_loss(
    pred: torch.Tensor,
    target: torch.Tensor,
    mask: torch.Tensor,
) -> torch.Tensor:
    """Mean squared next-event-vector error over non-padding positions."""
    loss = F.mse_loss(pred, target, reduction="none")
    loss = loss * mask.unsqueeze(-1)
    denom = mask.sum().clamp_min(1.0) * float(pred.shape[-1])
    return loss.sum() / denom


def _normalize_targets(values: torch.Tensor, scales: torch.Tensor) -> torch.Tensor:
    result = values.clone()
    result[..., 0] = result[..., 0] / max(float(scales[0].item()), 1.0)
    result[..., 1] = torch.log1p(torch.clamp_min(result[..., 1], 0.0)) / math.log1p(max(float(scales[1].item()), 1.0))
    for index in range(2, result.shape[-1]):
        result[..., index] = result[..., index] / max(float(scales[index].item()), 1.0)
    return result


def _prepare_sequences(
    host: str,
    subject_map: dict[str, list[list[float]]],
    *,
    max_seq_len: int,
    max_sequences: int | None,
    seed: int,
    allowed_subject_ids: set[str] | None = None,
) -> list[SubjectSequence]:
    items: list[SubjectSequence] = []
    for subject_id, history in subject_map.items():
        if allowed_subject_ids is not None and str(subject_id) not in allowed_subject_ids:
            continue
        if not history or len(history) < 2:
            continue
        values = np.asarray(history, dtype=np.float32)
        if values.ndim != 2 or values.shape[1] != 6:
            continue
        if max_seq_len > 0 and values.shape[0] > max_seq_len:
            values = values[-max_seq_len:, :]
        items.append(SubjectSequence(host=host, subject_id=str(subject_id), values=values))
    if max_sequences is not None and len(items) > max_sequences:
        rng = random.Random(seed)
        rng.shuffle(items)
        items = items[:max_sequences]
    return items


def _split_train_val(
    items: list[SubjectSequence],
    *,
    seed: int,
    val_fraction: float,
) -> tuple[list[SubjectSequence], list[SubjectSequence]]:
    if not items:
        return [], []
    rng = random.Random(seed)
    copied = list(items)
    rng.shuffle(copied)
    if len(copied) <= 2:
        return copied[:1], copied[1:]
    val_count = max(1, int(round(len(copied) * val_fraction)))
    val_count = min(val_count, len(copied) - 1)
    val_items = copied[:val_count]
    train_items = copied[val_count:]
    return train_items, val_items


def _collect_subject_histories(
    *,
    trace_logs: Path,
    cadets_logs: Path,
    workspace: Path,
    device: torch.device,
    hosts: tuple[str, ...],
) -> dict[str, dict[str, list[list[float]]]]:
    _copy_vendor_support_files(workspace)
    vendor = _load_vendor_darpa()
    vendor.device = device
    histories: dict[str, dict[str, list[list[float]]]] = {}
    with _temporary_cwd(workspace):
        if "trace" in hosts:
            trace_subjects, trace_objects, trace_events, _ = vendor.parser_trace(str(trace_logs) + os.sep)
            histories["trace"] = vendor.encode_trace(trace_subjects, trace_objects, trace_events)
        if "cadets" in hosts:
            cadets_subjects, cadets_objects, cadets_events, _ = vendor.parser_cadets(str(cadets_logs) + os.sep)
            histories["cadets"] = vendor.encode_cadets(cadets_subjects, cadets_objects, cadets_events)
    return histories


def _build_scales(items: list[SubjectSequence]) -> list[float]:
    max_values = np.ones(6, dtype=np.float32)
    for item in items:
        if item.values.size == 0:
            continue
        item_max = item.values.max(axis=0)
        max_values = np.maximum(max_values, item_max)
    return [float(x) for x in max_values.tolist()]


def run_pretraining(
    *,
    trace_logs: Path,
    cadets_logs: Path,
    output_dir: Path,
    hosts: tuple[str, ...] = ("trace", "cadets"),
    allowed_subject_ids_by_host: dict[str, set[str]] | None = None,
    epochs: int = 24,
    batch_size: int = 256,
    lr: float = 0.1,
    lr_decay_factor: float = 0.1,
    lr_decay_rate: int = 500,
    max_optimizer_steps: int = 1500,
    max_seq_len: int = 128,
    val_fraction: float = 0.1,
    max_trace_sequences: int | None = None,
    max_cadets_sequences: int | None = 50000,
    seed: int = 173,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    workspace = output_dir / "workspace"
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)
    workspace.mkdir(parents=True, exist_ok=True)

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    selected_hosts = tuple(host for host in hosts if host in {"trace", "cadets"})
    if not selected_hosts:
        raise ValueError("hosts must include trace and/or cadets")
    histories_by_host = _collect_subject_histories(
        trace_logs=trace_logs,
        cadets_logs=cadets_logs,
        workspace=workspace,
        device=device,
        hosts=selected_hosts,
    )
    items_by_host: dict[str, list[SubjectSequence]] = {}
    train_by_host: dict[str, list[SubjectSequence]] = {}
    val_by_host: dict[str, list[SubjectSequence]] = {}
    for host_index, host in enumerate(selected_hosts):
        items_by_host[host] = _prepare_sequences(
            host,
            histories_by_host.get(host, {}),
            max_seq_len=max_seq_len,
            max_sequences=max_trace_sequences if host == "trace" else max_cadets_sequences,
            seed=seed + host_index,
            allowed_subject_ids=(allowed_subject_ids_by_host or {}).get(host),
        )
        train_by_host[host], val_by_host[host] = _split_train_val(
            items_by_host[host],
            seed=seed + host_index,
            val_fraction=val_fraction,
        )
    train_items = [item for host in selected_hosts for item in train_by_host[host]]
    val_items = [item for host in selected_hosts for item in val_by_host[host]]
    if not train_items:
        raise RuntimeError("No training sequences available for TC3 pretraining")

    scales = _build_scales(train_items)
    scales_tensor = torch.tensor(scales, dtype=torch.float32, device=device)
    train_dataset = TC3SequenceDataset(train_items)
    val_dataset = TC3SequenceDataset(val_items)

    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        collate_fn=_collate_sequences,
        num_workers=0,
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=_collate_sequences,
        num_workers=0,
    )

    model = TC3StackedLSTMPretrain().to(device)
    # TAPAS reports lr=0.1, decay factor=0.1 and decay rate=500 for this encoder.
    # The paper does not define the optimizer or the decay unit, so we use Adam and
    # apply StepLR after every optimizer update; this makes "500" unambiguous.
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.StepLR(
        optimizer,
        step_size=int(lr_decay_rate),
        gamma=float(lr_decay_factor),
    )
    optimizer_steps = 0
    epoch_summaries: list[dict[str, Any]] = []

    def run_epoch(loader: DataLoader, train_mode: bool) -> tuple[float, bool]:
        nonlocal optimizer_steps
        if train_mode:
            model.train()
        else:
            model.eval()
        total_loss = 0.0
        total_steps = 0
        for batch in loader:
            if train_mode and optimizer_steps >= int(max_optimizer_steps):
                break
            inputs = batch["inputs"].to(device=device, dtype=torch.float32)
            lengths = batch["lengths"].to(device)
            if inputs.shape[1] < 2:
                continue
            source = inputs[:, :-1, :]
            target = inputs[:, 1:, :]
            target_norm = _normalize_targets(target, scales_tensor)
            pred_norm, _ = model.forward_train(source)
            step_count = source.shape[1]
            mask = (
                torch.arange(step_count, device=device)
                .unsqueeze(0)
                .expand(inputs.shape[0], step_count)
                < (lengths - 1).unsqueeze(1)
            ).to(dtype=torch.float32)
            loss = _weighted_regression_loss(pred_norm, target_norm, mask)
            if train_mode:
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()
                optimizer_steps += 1
            total_loss += float(loss.detach().cpu().item()) * int(mask.sum().item())
            total_steps += int(mask.sum().item())
        if total_steps <= 0:
            return 0.0, False
        return total_loss / float(total_steps), optimizer_steps >= int(max_optimizer_steps)

    for epoch in range(1, epochs + 1):
        train_loss, reached_max_steps = run_epoch(train_loader, True)
        val_loss, _ = run_epoch(val_loader, False) if len(val_dataset) > 0 else (train_loss, False)
        epoch_summary = {
            "epoch": epoch,
            "train_loss": train_loss,
            "val_loss": val_loss,
            "optimizer_steps": optimizer_steps,
            "learning_rate": float(optimizer.param_groups[0]["lr"]),
        }
        epoch_summaries.append(epoch_summary)
        if reached_max_steps:
            break

    best_model_path = output_dir / "stackedlstm_tc_retrained_trace_cadets_20260707.pt"
    torch.save(model.state_dict(), best_model_path)
    manifest = {
        "status": "completed",
        "seed": seed,
        "device": str(device),
        "trace_logs": str(trace_logs),
        "cadets_logs": str(cadets_logs),
        "workspace": str(workspace),
        "best_model_path": str(best_model_path),
        "epochs_requested": epochs,
        "epochs_ran": len(epoch_summaries),
        "batch_size": batch_size,
        "lr": lr,
        "lr_decay_factor": lr_decay_factor,
        "lr_decay_rate_optimizer_steps": lr_decay_rate,
        "max_optimizer_steps": max_optimizer_steps,
        "optimizer_steps_completed": optimizer_steps,
        "optimizer": "Adam",
        "loss": "masked_mse_on_normalized_next_event_vector",
        "max_seq_len": max_seq_len,
        "val_fraction": val_fraction,
        "max_trace_sequences": max_trace_sequences,
        "max_cadets_sequences": max_cadets_sequences,
        "feature_scales": scales,
        "sequence_counts": {
            **{
                f"{host}_total": len(items_by_host[host])
                for host in selected_hosts
            },
            **{
                f"{host}_train": len(train_by_host[host])
                for host in selected_hosts
            },
            **{
                f"{host}_val": len(val_by_host[host])
                for host in selected_hosts
            },
            "combined_train": len(train_items),
            "combined_val": len(val_items),
        },
        "hosts": list(selected_hosts),
        "allowed_subject_counts": {
            host: len((allowed_subject_ids_by_host or {}).get(host, set()))
            for host in selected_hosts
        },
        "epoch_summaries": epoch_summaries,
    }
    (output_dir / "training_summary.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return manifest


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pretrain the shared TC3 stacked LSTM-GRU encoder on TRACE and CADETS.")
    parser.add_argument("--trace-logs", type=Path, required=True)
    parser.add_argument("--cadets-logs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--hosts", default="trace,cadets")
    parser.add_argument("--epochs", type=int, default=24)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--lr", type=float, default=0.1)
    parser.add_argument("--lr-decay-factor", type=float, default=0.1)
    parser.add_argument("--lr-decay-rate", type=int, default=500)
    parser.add_argument("--max-optimizer-steps", type=int, default=1500)
    parser.add_argument("--max-seq-len", type=int, default=128)
    parser.add_argument("--val-fraction", type=float, default=0.1)
    parser.add_argument("--max-trace-sequences", type=int, default=0)
    parser.add_argument("--max-cadets-sequences", type=int, default=50000)
    parser.add_argument("--seed", type=int, default=173)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    result = run_pretraining(
        trace_logs=args.trace_logs,
        cadets_logs=args.cadets_logs,
        output_dir=args.output_dir,
        hosts=tuple(host.strip() for host in args.hosts.split(",") if host.strip()),
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        lr_decay_factor=args.lr_decay_factor,
        lr_decay_rate=args.lr_decay_rate,
        max_optimizer_steps=args.max_optimizer_steps,
        max_seq_len=args.max_seq_len,
        val_fraction=args.val_fraction,
        max_trace_sequences=None if args.max_trace_sequences <= 0 else args.max_trace_sequences,
        max_cadets_sequences=None if args.max_cadets_sequences <= 0 else args.max_cadets_sequences,
        seed=args.seed,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

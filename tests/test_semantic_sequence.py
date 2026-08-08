from __future__ import annotations

from pathlib import Path

import pytest


torch = pytest.importorskip("torch")

from apt_fusion.task_detection.semantic_sequence import (  # noqa: E402
    OUTPUT_DIM,
    SEMANTIC_SEQUENCE_VERSION,
    fit_benign_semantic_sequence_encoder,
)


def test_semantic_sequence_encoder_trains_on_benign_histories(tmp_path: Path) -> None:
    histories = {
        f"process-{index}": [[1, 1 + index], [2, 3], [5, 2], [11, 1]]
        for index in range(40)
    }
    result = fit_benign_semantic_sequence_encoder(
        histories,
        set(histories),
        tmp_path / "encoder.pt",
        epochs=1,
        batch_size=16,
        learning_rate=1e-3,
        seed=7,
    )

    assert result.metadata["version"] == SEMANTIC_SEQUENCE_VERSION
    assert result.metadata["train_subject_count"] == 40
    assert len(result.vectors) == 40
    assert all(len(vector) == OUTPUT_DIM for vector in result.vectors.values())
    assert all(score >= 0.0 for score in result.prediction_errors.values())

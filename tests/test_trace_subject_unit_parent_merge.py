from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

from apt_fusion.config import FusionConfig
from apt_fusion.path_reason.log_stream import _build_process_alias_state
from apt_fusion.task_detection.ocr_stat_features import _extract_tc3_stats


UUID_KEY = "com.bbn.tc.schema.avro.cdm18.UUID"
SUBJECT_KEY = "com.bbn.tc.schema.avro.cdm18.Subject"
EVENT_KEY = "com.bbn.tc.schema.avro.cdm18.Event"


def _subject(uuid: str, cid: str, subject_type: str, parent_uuid: str = "") -> dict[str, object]:
    payload: dict[str, object] = {
        "uuid": uuid,
        "cid": cid,
        "type": subject_type,
        "properties": {"map": {"name": f"proc-{cid}", "ppid": "1"}},
    }
    if parent_uuid:
        payload["parentSubject"] = {UUID_KEY: parent_uuid}
    return {"datum": {SUBJECT_KEY: payload}}


def _unit_event(subject_uuid: str) -> dict[str, object]:
    return {
        "datum": {
            EVENT_KEY: {
                "subject": {UUID_KEY: subject_uuid},
                "predicateObject": {UUID_KEY: "file-1"},
                "type": "EVENT_WRITE",
                "timestampNanos": 1_000_000_000,
            }
        }
    }


def _cfg(log_dir: Path) -> FusionConfig:
    return FusionConfig(
        ocr_apt_root=None,
        tapas_root=None,
        dataset_family="tc3",
        host="trace",
        source_logs=log_dir,
        artifacts_dir=log_dir / "artifacts",
        ocr_runtime_root=log_dir / "runtime",
        ocr_exp_name="test",
        ocr_model_name="test",
        ocr_inv_exp_name="test",
    )


def _write_trace_fixture(tmp_path: Path) -> FusionConfig:
    records = [
        _subject("unit-uuid", "999", "SUBJECT_UNIT", "process-uuid"),
        _unit_event("unit-uuid"),
        _subject("process-uuid", "100", "SUBJECT_PROCESS"),
    ]
    (tmp_path / "trace.json").write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    return _cfg(tmp_path)


def test_trace_unit_alias_and_statistics_follow_parent_subject(tmp_path: Path) -> None:
    cfg = _write_trace_fixture(tmp_path)

    aliases = _build_process_alias_state(cfg)
    assert aliases.raw_to_canonical["process-uuid"] == "100"
    assert aliases.raw_to_canonical["unit-uuid"] == "100"

    stats = _extract_tc3_stats(cfg, {"100"})
    assert stats["process_id"].tolist() == ["100"]
    assert stats.loc[0, "stat_out_write"] == pytest.approx(1.0)


def test_trace_tapas_parser_merges_unit_into_parent_process(tmp_path: Path) -> None:
    cfg = _write_trace_fixture(tmp_path)
    spec = importlib.util.spec_from_file_location(
        "trace_subject_unit_parent_merge_vendor",
        REPO_ROOT / "vendor" / "tapas" / "darpa.py",
    )
    assert spec is not None and spec.loader is not None
    vendor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vendor)

    subject_list, _, _, metadata = vendor.parser_trace(f"{cfg.source_logs}{os.sep}")

    assert [row[1] for row in subject_list] == ["100"]
    assert metadata["raw_subject_to_canonical_node"]["unit-uuid"] == "100"

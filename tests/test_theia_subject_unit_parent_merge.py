from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
UUID_KEY = "com.bbn.tc.schema.avro.cdm18.UUID"
SUBJECT_KEY = "com.bbn.tc.schema.avro.cdm18.Subject"
EVENT_KEY = "com.bbn.tc.schema.avro.cdm18.Event"
FILE_KEY = "com.bbn.tc.schema.avro.cdm18.FileObject"


def _subject(uuid: str, cid: str, subject_type: str, parent_uuid: str = "") -> dict[str, object]:
    payload: dict[str, object] = {
        "uuid": uuid,
        "cid": cid,
        "type": subject_type,
        "properties": {"map": {"name": f"proc-{cid}", "tgid": "100"}},
    }
    if parent_uuid:
        payload["parentSubject"] = {UUID_KEY: parent_uuid}
    return {"datum": {SUBJECT_KEY: payload}}


def _event(subject_uuid: str) -> dict[str, object]:
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


def _file() -> dict[str, object]:
    return {
        "datum": {
            FILE_KEY: {
                "uuid": "file-1",
                "baseObject": {"properties": {"map": {"filename": "/tmp/payload", "dev": "1"}}},
            }
        }
    }


def test_theia_filters_merge_unit_events_after_late_parent_definition(tmp_path: Path, monkeypatch) -> None:
    records = [
        _event("unit-uuid"),
        _subject("unit-uuid", "999", "SUBJECT_UNIT", "process-uuid"),
        _file(),
        _subject("process-uuid", "100", "SUBJECT_PROCESS"),
    ]
    (tmp_path / "theia.json").write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location(
        "theia_subject_unit_parent_merge_vendor",
        REPO_ROOT / "vendor" / "tapas" / "darpa.py",
    )
    assert spec is not None and spec.loader is not None
    vendor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vendor)
    monkeypatch.chdir(REPO_ROOT / "vendor" / "tapas")

    histories, summary = vendor.filters(
        f"{tmp_path}{os.sep}",
        return_sequence_histories=True,
    )

    assert set(histories) == {"process-uuid"}
    assert len(histories["process-uuid"]) == 1
    mapping = summary["parser_metadata"]["raw_subject_to_canonical_node"]
    assert mapping["unit-uuid"] == "process-uuid"
    assert summary["parser_metadata"]["thread_subjects_merged_by_tgid"] == 1

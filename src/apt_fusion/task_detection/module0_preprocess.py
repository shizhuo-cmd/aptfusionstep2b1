from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Tuple

import requests

from ..common import ensure_dir
from ..config import FusionConfig


def _iter_log_files(source_logs: Path) -> List[Path]:
    if source_logs.is_file():
        return [source_logs]
    files = [p for p in source_logs.rglob("*") if p.is_file()]
    files.sort()
    return files


def _iter_lines(path: Path) -> Iterator[str]:
    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
            yield from f
    else:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            yield from f


def _parse_darpa_line(obj: Dict[str, object]) -> Tuple[Dict[str, object] | None, List[str]]:
    datum = obj.get("datum")
    if not isinstance(datum, dict):
        return None, []

    event_key = "com.bbn.tc.schema.avro.cdm18.Event"
    subject_key = "com.bbn.tc.schema.avro.cdm18.Subject"
    uuid_key = "com.bbn.tc.schema.avro.cdm18.UUID"

    if event_key in datum:
        event = datum[event_key]
        if not isinstance(event, dict):
            return None, []
        event_type = str(event.get("type", "UNKNOWN"))
        subject = event.get("subject", {})
        subject_uuid = None
        if isinstance(subject, dict):
            subject_uuid = subject.get(uuid_key)
        obj_ref = event.get("predicateObject", {})
        object_uuid = None
        if isinstance(obj_ref, dict):
            object_uuid = obj_ref.get(uuid_key)
        timestamp = (
            event.get("timestampNanos")
            or event.get("timestampMicros")
            or event.get("timestamp")
            or ""
        )
        if subject_uuid is None or object_uuid is None:
            return None, []

        rec = {
            "record_type": "event",
            "event_type": event_type,
            "subject_uuid": str(subject_uuid),
            "object_uuid": str(object_uuid),
            "timestamp": str(timestamp),
        }
        triples = [
            f'<node/{subject_uuid}> <graph/node-type> "process" .',
            f'<node/{object_uuid}> <graph/node-type> "object" .',
            f'<node/{subject_uuid}> <graph/{event_type.lower()}> <node/{object_uuid}> .',
        ]
        return rec, triples

    if subject_key in datum:
        subject = datum[subject_key]
        if not isinstance(subject, dict):
            return None, []
        uuid = subject.get("uuid")
        if not uuid:
            return None, []
        parent = subject.get("parentSubject", {})
        parent_uuid = None
        if isinstance(parent, dict):
            parent_uuid = parent.get(uuid_key)
        rec = {
            "record_type": "subject",
            "subject_uuid": str(uuid),
            "parent_uuid": str(parent_uuid) if parent_uuid else "",
        }
        triples = [f'<node/{uuid}> <graph/node-type> "process" .']
        if parent_uuid:
            triples.append(f'<node/{uuid}> <graph/parent> <node/{parent_uuid}> .')
        return rec, triples

    return None, []


def _append_to_graphdb(
    repository_url: str,
    triples: List[str],
    username: str = "",
    password: str = "",
) -> None:
    if not repository_url or not triples:
        return
    payload = "\n".join(triples)
    endpoint = repository_url.rstrip("/") + "/statements"
    auth = (username, password) if username and password else None
    requests.post(
        endpoint,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/x-turtle; charset=utf-8"},
        auth=auth,
        timeout=30,
    ).raise_for_status()


def run_module0(cfg: FusionConfig) -> Dict[str, Path]:
    out_dir = cfg.module0_dir
    ensure_dir(out_dir)
    events_path = out_dir / "process_events.jsonl"
    rdf_path = out_dir / "rdf_stream.nt"

    events_path.write_text("", encoding="utf-8")
    rdf_path.write_text("", encoding="utf-8")

    pending_triples: List[str] = []
    with events_path.open("a", encoding="utf-8") as event_f, rdf_path.open(
        "a", encoding="utf-8"
    ) as rdf_f:
        for log_file in _iter_log_files(cfg.source_logs):
            for line in _iter_lines(log_file):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rec, triples = _parse_darpa_line(obj)
                if rec is None:
                    continue
                event_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                for triple in triples:
                    rdf_f.write(triple + "\n")
                pending_triples.extend(triples)

                if len(pending_triples) >= 2000 and cfg.graphdb_repository_url:
                    _append_to_graphdb(
                        cfg.graphdb_repository_url,
                        pending_triples,
                        cfg.graphdb_username,
                        cfg.graphdb_password,
                    )
                    pending_triples.clear()

    if pending_triples and cfg.graphdb_repository_url:
        _append_to_graphdb(
            cfg.graphdb_repository_url,
            pending_triples,
            cfg.graphdb_username,
            cfg.graphdb_password,
        )

    return {"process_events": events_path, "rdf_stream": rdf_path}



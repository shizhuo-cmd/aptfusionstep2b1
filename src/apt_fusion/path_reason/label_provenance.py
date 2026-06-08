from __future__ import annotations

from pathlib import Path
from typing import Any

from ..common import load_jsonl
from .path_schemas import LabelProvenanceRecord

_PROVENANCE_KEY_LABELS = {
    "P_UNTRUSTED_CTX",
    "P_HIGH_VALUE_CTX",
    "A_BRIDGED_BY_SUSPICIOUS_OBJECT",
}


def is_provenance_key_label(label: str) -> bool:
    text = str(label).strip()
    return bool(text) and (text.startswith("B_") or text in _PROVENANCE_KEY_LABELS)


def load_label_provenance_records(path: Path | str | None) -> list[LabelProvenanceRecord]:
    text = str(path or "").strip()
    if not text:
        return []
    file_path = Path(text)
    if not file_path.is_file():
        return []
    try:
        payload = load_jsonl(file_path)
    except Exception:
        return []
    records: list[LabelProvenanceRecord] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            records.append(LabelProvenanceRecord.from_dict(dict(item)))
        except Exception:
            continue
    return records


class LabelProvenanceBuilder:
    def __init__(self) -> None:
        self.records: list[LabelProvenanceRecord] = []
        self._by_id: dict[str, LabelProvenanceRecord] = {}
        self._holder_index: dict[tuple[str, str], list[str]] = {}
        self._event_index: dict[str, list[str]] = {}
        self._dedupe_index: dict[tuple[Any, ...], str] = {}
        self._label_counter = 0
        self._segment_counter = 0

    def new_segment_id(self) -> str:
        self._segment_counter += 1
        return f"seg_{self._segment_counter:06d}"

    def label_ids_for(self, holder_entity_type: str, holder_entity_id: str) -> list[str]:
        return list(self._holder_index.get((str(holder_entity_type).strip(), str(holder_entity_id).strip()), []))

    def add(
        self,
        *,
        task_id: str,
        label: str,
        label_type: str,
        holder_entity_type: str,
        holder_entity_id: str,
        created_at: Any = None,
        source_entity_type: str | None = None,
        source_entity_id: str | None = None,
        source_type: str,
        event_id: str | None = None,
        event_type: str | None = None,
        rule_id: str,
        context_id: str | None = None,
        prev_label_ids: list[str] | None = None,
        segment_id: str | None = None,
    ) -> str:
        prev_ids = [str(item).strip() for item in (prev_label_ids or []) if str(item).strip()]
        dedupe_key = (
            str(task_id).strip(),
            str(label).strip(),
            str(label_type).strip(),
            str(holder_entity_type).strip(),
            str(holder_entity_id).strip(),
            str(source_entity_type or "").strip(),
            str(source_entity_id or "").strip(),
            str(source_type).strip(),
            str(event_id or "").strip(),
            str(event_type or "").strip(),
            str(rule_id).strip(),
            str(context_id or "").strip(),
            tuple(prev_ids),
            str(segment_id or "").strip(),
        )
        existing = self._dedupe_index.get(dedupe_key)
        if existing:
            return existing
        self._label_counter += 1
        label_id = f"lp_{self._label_counter:06d}"
        record = LabelProvenanceRecord(
            label_id=label_id,
            task_id=str(task_id).strip(),
            label=str(label).strip(),
            label_type=str(label_type).strip(),
            holder_entity_type=str(holder_entity_type).strip(),
            holder_entity_id=str(holder_entity_id).strip(),
            created_at=created_at,
            source_entity_type=None if source_entity_type in (None, "") else str(source_entity_type).strip(),
            source_entity_id=None if source_entity_id in (None, "") else str(source_entity_id).strip(),
            source_type=str(source_type).strip(),
            event_id=None if event_id in (None, "") else str(event_id).strip(),
            event_type=None if event_type in (None, "") else str(event_type).strip(),
            rule_id=str(rule_id).strip(),
            context_id=None if context_id in (None, "") else str(context_id).strip(),
            prev_label_ids=prev_ids,
            segment_id=None if segment_id in (None, "") else str(segment_id).strip(),
        )
        self.records.append(record)
        self._by_id[label_id] = record
        self._holder_index.setdefault((record.holder_entity_type, record.holder_entity_id), []).append(label_id)
        if record.event_id:
            self._event_index.setdefault(record.event_id, []).append(label_id)
        self._dedupe_index[dedupe_key] = label_id
        return label_id

    def get(self, label_id: str) -> LabelProvenanceRecord | None:
        return self._by_id.get(str(label_id).strip())

    def records_by_event(self, event_id: str) -> list[LabelProvenanceRecord]:
        ids = self._event_index.get(str(event_id).strip(), [])
        return [self._by_id[label_id] for label_id in ids if label_id in self._by_id]

    def trace_back(self, label_id: str) -> list[LabelProvenanceRecord]:
        ordered: list[LabelProvenanceRecord] = []
        visited: set[str] = set()

        def _visit(current_id: str) -> None:
            key = str(current_id).strip()
            if not key or key in visited:
                return
            visited.add(key)
            record = self._by_id.get(key)
            if record is None:
                return
            for prev_id in record.prev_label_ids:
                _visit(prev_id)
            ordered.append(record)

        _visit(label_id)
        return ordered

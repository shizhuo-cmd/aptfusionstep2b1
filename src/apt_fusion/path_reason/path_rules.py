from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..config import FusionConfig

_LABEL_REQUIRED_KEYS = {"category", "stage_mapping", "bridge_allowed", "score"}
_PATH_REASON_DEFAULT_NAME = "path_reason_default.yaml"


def _default_rules_path() -> Path:
    return Path(__file__).resolve().parents[3] / "configs" / _PATH_REASON_DEFAULT_NAME


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(dict(merged[key]), value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _split_ref(ref: str) -> list[str]:
    return [part for part in str(ref).strip().split(".") if part]


def _get_ref(data: dict[str, Any], ref: str, default: Any = None) -> Any:
    current: Any = data
    for part in _split_ref(ref):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


@dataclass
class PathRules:
    raw: dict[str, Any]
    source_path: Path

    def get(self, ref: str, default: Any = None) -> Any:
        return _get_ref(self.raw, ref, default)

    @property
    def labels(self) -> dict[str, dict[str, Any]]:
        value = self.raw.get("labels", {})
        return value if isinstance(value, dict) else {}

    def get_label_meta(self, name: str) -> dict[str, Any]:
        meta = self.labels.get(str(name).strip(), {})
        return meta if isinstance(meta, dict) else {}

    def is_bridge_allowed_label(self, name: str) -> bool:
        return bool(self.get_label_meta(name).get("bridge_allowed", False))

    def label_has_init_rules(self, name: str) -> bool:
        meta = self.get_label_meta(name)
        return isinstance(meta.get("init_rules"), list)

    def resolve_ref(self, ref: str, default: Any = None) -> Any:
        return self.get(ref, default)

    def labels_by_category(self, category: str) -> dict[str, dict[str, Any]]:
        target = str(category).strip()
        return {
            name: meta
            for name, meta in self.labels.items()
            if isinstance(meta, dict) and str(meta.get("category", "")).strip() == target
        }


def _validate_label_registry(rules: PathRules) -> None:
    for name, meta in rules.labels.items():
        if not isinstance(meta, dict):
            raise ValueError(f"Label metadata for {name!r} must be a mapping")
        missing = [key for key in _LABEL_REQUIRED_KEYS if key not in meta]
        if missing:
            raise ValueError(f"Label {name!r} missing required keys: {missing}")
        category = str(meta.get("category", "")).strip()
        if category in {"context", "behavior", "object"} and "init_rules" not in meta:
            raise ValueError(f"Label {name!r} must define init_rules")
        if category not in {"context", "behavior", "object", "aggregate"}:
            raise ValueError(f"Label {name!r} has unsupported category: {category}")


def _apply_dataset_overrides(raw: dict[str, Any], cfg: FusionConfig) -> dict[str, Any]:
    merged = copy.deepcopy(raw)
    dataset_overrides = merged.pop("dataset_overrides", {})
    if isinstance(dataset_overrides, dict):
        host_key = str(cfg.host).strip().lower()
        # Dataset config is keyed by host names like trace/theia/cadets.
        host_override = dataset_overrides.get(host_key)
        if isinstance(host_override, dict):
            merged = _deep_merge(merged, host_override)
    host_overrides = merged.pop("host_overrides", {})
    if isinstance(host_overrides, dict):
        override = host_overrides.get(str(cfg.host).strip()) or host_overrides.get(str(cfg.host).strip().lower())
        if isinstance(override, dict):
            merged = _deep_merge(merged, override)
    return merged


def load_path_rules(cfg: FusionConfig) -> PathRules:
    raw_path = cfg.path_reason_rules_path or _default_rules_path()
    path = Path(raw_path)
    if not path.exists():
        raise FileNotFoundError(f"path reason rules not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"path reason rules must be a YAML mapping: {path}")
    merged = _apply_dataset_overrides(raw, cfg)
    rules = PathRules(raw=merged, source_path=path)
    _validate_label_registry(rules)
    return rules


def get_label_meta(rules: PathRules, name: str) -> dict[str, Any]:
    return rules.get_label_meta(name)


def is_bridge_allowed_label(rules: PathRules, name: str) -> bool:
    return rules.is_bridge_allowed_label(name)


def match_object_class(rules: PathRules, object_class: str, category: str) -> bool:
    if not object_class:
        return False
    classes = rules.get(f"object_classes.{category}", {})
    return isinstance(classes, dict) and object_class == category


def label_has_init_rules(rules: PathRules, name: str) -> bool:
    return rules.label_has_init_rules(name)


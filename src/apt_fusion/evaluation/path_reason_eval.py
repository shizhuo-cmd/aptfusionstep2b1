from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Any, Iterable

from ..common import ensure_dir, load_json, save_json
from ..config import resolve_attack_eval_gt_json

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_GT_JSON_PATH = resolve_attack_eval_gt_json(_REPO_ROOT)

_ATTACK_ID_PATTERN = re.compile(r"T\d{4}(?:[./]\d{3})?")
_TACTIC_SPLIT_PATTERN = re.compile(r"[|,，/+\s]+")
_STRICT_HOST_HEADING = re.compile(r"^#\s+\d+\.\s+([A-Za-z0-9._-]+)\s*$")
_BROAD_HOST_HEADING = re.compile(r"^#\s+\d+\.\s+([A-Za-z0-9._-]+)\s+涓绘満鍒嗘瀽\s*$")
_DATE_RANGE_PATTERN = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<start>\d{2}:\d{2})(?:-(?P<end>\d{2}:\d{2}))?"
)

_TACTIC_ID_TO_CANONICAL = {
    "TA0043": "RECONNAISSANCE",
    "TA0042": "RESOURCE_DEVELOPMENT",
    "TA0001": "INITIAL_ACCESS",
    "TA0002": "EXECUTION",
    "TA0003": "PERSISTENCE",
    "TA0004": "PRIVILEGE_ESCALATION",
    "TA0005": "DEFENSE_EVASION",
    "TA0006": "CREDENTIAL_ACCESS",
    "TA0007": "DISCOVERY",
    "TA0008": "LATERAL_MOVEMENT",
    "TA0009": "COLLECTION",
    "TA0010": "EXFILTRATION",
    "TA0011": "COMMAND_AND_CONTROL",
    "TA0040": "IMPACT",
}

_RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
_MEDIUM_OR_HIGH = {"MEDIUM", "HIGH"}
_HIGH_ONLY = {"HIGH"}
_CONFIRMED_CONTINUATION_MAX_GAP_MINUTES = 15


@dataclass
class GTWindow:
    window_id: str
    host: str
    source_doc: str
    source_ref: str
    status: str
    time_precision: str
    start_time: datetime | None
    end_time: datetime | None
    confirmed_techniques: list[str]
    attempted_techniques: list[str]
    confirmed_tactics: list[str]
    attempted_tactics: list[str]
    coarse_chain_tags: list[str]
    notes: str
    broad_techniques: list[str]
    attack_summary: str = ""
    source_report_pages: list[int] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "host": self.host,
            "source_doc": self.source_doc,
            "source_ref": self.source_ref,
            "status": self.status,
            "time_precision": self.time_precision,
            "start_time": _iso(self.start_time),
            "end_time": _iso(self.end_time),
            "confirmed_techniques": list(self.confirmed_techniques),
            "attempted_techniques": list(self.attempted_techniques),
            "confirmed_tactics": list(self.confirmed_tactics),
            "attempted_tactics": list(self.attempted_tactics),
            "coarse_chain_tags": list(self.coarse_chain_tags),
            "notes": self.notes,
            "broad_techniques": list(self.broad_techniques),
            "attack_summary": self.attack_summary,
            "source_report_pages": list(self.source_report_pages or []),
        }


@dataclass
class PredictedPath:
    host: str
    task_id: str
    path_id: str
    risk_score: float
    risk_level: str
    start_time: datetime | None
    end_time: datetime | None
    stage_coverage: list[str]
    process_chain: list[str]
    bridge_objects: list[str]
    candidate_tactics: list[str]
    predicted_tactics: list[str]
    predicted_techniques: list[str]
    attack_mapping_scope: str
    warnings: list[str]
    candidate_paths_path: str
    report_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "task_id": self.task_id,
            "path_id": self.path_id,
            "risk_score": float(self.risk_score),
            "risk_level": self.risk_level,
            "start_time": _iso(self.start_time),
            "end_time": _iso(self.end_time),
            "stage_coverage": list(self.stage_coverage),
            "process_chain": list(self.process_chain),
            "bridge_objects": list(self.bridge_objects),
            "candidate_tactics": list(self.candidate_tactics),
            "predicted_tactics": list(self.predicted_tactics),
            "predicted_techniques": list(self.predicted_techniques),
            "attack_mapping_scope": self.attack_mapping_scope,
            "warnings": list(self.warnings),
            "candidate_paths_path": self.candidate_paths_path,
            "report_path": self.report_path,
        }


@dataclass
class PathWindowMatch:
    path_id: str
    match_type: str
    path_in_window_ratio: float
    intersection_seconds: float
    midpoint_in_window: bool
    strict_time_match: bool
    primary_time_match: bool
    loose_time_match: bool
    near_miss_time: bool
    window_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "match_type": self.match_type,
            "path_in_window_ratio": float(self.path_in_window_ratio),
            "intersection_seconds": float(self.intersection_seconds),
            "midpoint_in_window": bool(self.midpoint_in_window),
            "strict_time_match": bool(self.strict_time_match),
            "primary_time_match": bool(self.primary_time_match),
            "loose_time_match": bool(self.loose_time_match),
            "near_miss_time": bool(self.near_miss_time),
            "window_id": self.window_id,
        }


def _iso(value: datetime | None) -> str:
    return value.isoformat() if isinstance(value, datetime) else ""


def _parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        pass
    for fmt, width in (
        ("%Y-%m-%d %H:%M:%S", 19),
        ("%Y-%m-%dT%H:%M:%S", 19),
        ("%Y-%m-%d %H:%M", 16),
    ):
        try:
            return datetime.strptime(text[:width], fmt)
        except ValueError:
            continue
    return None


def _canonical_attack_id(text: str) -> str:
    return str(text).strip().upper().replace("/", ".")


def _canonical_tactic_name(text: str) -> str:
    raw = str(text or "").strip().upper()
    if not raw:
        return ""
    if raw in _TACTIC_ID_TO_CANONICAL:
        return _TACTIC_ID_TO_CANONICAL[raw]
    normalized = re.sub(r"[^A-Z0-9]+", "_", raw).strip("_")
    return normalized


def _split_tactics(text: str) -> list[str]:
    output: list[str] = []
    for item in _TACTIC_SPLIT_PATTERN.split(str(text or "").strip()):
        tactic = _canonical_tactic_name(item)
        if tactic and tactic not in output:
            output.append(tactic)
    return output


def _extract_attack_ids(text: str) -> list[str]:
    output: list[str] = []
    for item in _ATTACK_ID_PATTERN.findall(str(text or "")):
        attack_id = _canonical_attack_id(item)
        if attack_id not in output:
            output.append(attack_id)
    return output


def _split_markdown_row(line: str) -> list[str]:
    text = str(line or "").strip()
    if not text.startswith("|") or text.count("|") < 2:
        return []
    cells = [cell.strip() for cell in text.strip().strip("|").split("|")]
    if not cells:
        return []
    if all(re.fullmatch(r"-{2,}:?", cell.replace(" ", "")) for cell in cells):
        return []
    return cells


def _parse_time_cell(cell: str) -> tuple[datetime | None, datetime | None, str]:
    text = str(cell or "").strip()
    if not text:
        return None, None, "unknown"
    if "未给出精确执行时间" in text or "未给出精确" in text:
        return None, None, "unknown"
    if "宸﹀彸" in text:
        match = _DATE_RANGE_PATTERN.search(text)
        if match is None:
            return None, None, "coarse_summary"
        date_text = match.group("date")
        start_text = match.group("start")
        start = _parse_datetime(f"{date_text} {start_text}")
        return start, start, "coarse_summary"
    match = _DATE_RANGE_PATTERN.search(text)
    if match is None:
        return None, None, "unknown"
    date_text = match.group("date")
    start_text = match.group("start")
    end_text = match.group("end") or start_text
    start = _parse_datetime(f"{date_text} {start_text}")
    end = _parse_datetime(f"{date_text} {end_text}")
    if start is None or end is None:
        return None, None, "unknown"
    if end < start:
        end = start
    return start, end, "minute_window"


def _source_ref_text(cells: list[str], default_index: int) -> str:
    if default_index < len(cells):
        return str(cells[default_index]).strip()
    return ""


def _parse_report_pages(source_ref: str) -> list[int]:
    pages: list[int] = []
    for match in re.finditer(r"Page\s+(\d+)(?:-(\d+))?", str(source_ref or ""), re.IGNORECASE):
        start = int(match.group(1))
        end = int(match.group(2) or start)
        for page in range(start, end + 1):
            if page not in pages:
                pages.append(page)
    return pages


def _parse_host_offsets(text: str) -> dict[str, int]:
    output: dict[str, int] = {}
    for item in str(text or "").split(","):
        token = str(item).strip()
        if not token or "=" not in token:
            continue
        host, value = token.split("=", 1)
        try:
            output[str(host).strip().upper()] = int(str(value).strip())
        except ValueError:
            continue
    return output


def _classify_window_status(
    technique_ids: list[str],
    notes: str,
) -> tuple[str, list[str], list[str]]:
    note_text = str(notes or "").strip()
    lowered = note_text.lower()
    attempted_from_note: list[str] = []
    for attack_id in technique_ids:
        pattern = re.compile(
            rf"{re.escape(attack_id)}(?:[^銆傦紱;,.]{{0,18}})(?:澶辫触|attempted|failed)",
            re.IGNORECASE,
        )
        if pattern.search(note_text):
            attempted_from_note.append(attack_id)
    semantic_attempt_hints = {
        "T1055": ("娉ㄥ叆澶辫触", "inject", "injection"),
        "T1068": ("鎻愭潈澶辫触", "elevate", "privilege escalation"),
    }
    for attack_id, markers in semantic_attempt_hints.items():
        if attack_id not in technique_ids or attack_id in attempted_from_note:
            continue
        if any(marker.lower() in lowered for marker in markers) and any(
            token in lowered for token in ("澶辫触", "attempted", "failed")
        ):
            attempted_from_note.append(attack_id)
    attempted = list(dict.fromkeys(attempted_from_note))
    has_global_attempt = any(
        marker in lowered
        for marker in (
            "attempted / failed",
            "attempted",
            "澶辫触灏濊瘯",
            "灏濊瘯澶辫触",
            "澶辫触/閮ㄥ垎鎴愬姛",
            "未执行",
        )
    )
    has_confirmed = any(marker in lowered for marker in ("confirmed", "其他确认", "确认", "成功"))
    if technique_ids and has_global_attempt and not has_confirmed and not attempted:
        return "attempted_failed", [], list(technique_ids)
    confirmed = [item for item in technique_ids if item not in attempted]
    if confirmed:
        return "confirmed", confirmed, attempted
    if attempted:
        return "attempted_failed", [], attempted
    if technique_ids:
        return "confirmed", list(technique_ids), []
    return "insufficient", [], []


def _technique_definitions_from_strict(lines: list[str]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for line in lines:
        cells = _split_markdown_row(line)
        if len(cells) < 3:
            continue
        if not re.fullmatch(r"T\d{4}(?:[./]\d{3})?", cells[0].strip(), re.IGNORECASE):
            continue
        attack_id = _canonical_attack_id(cells[0])
        output[attack_id] = _split_tactics(cells[2])
    return output


def _line_chain_tags(text: str) -> list[str]:
    tags: list[str] = []
    lowered = str(text or "").lower()
    mapping = {
        "browser_compromise": ("firefox", "browser", "缃戦〉", "骞垮憡閾捐矾", "鎭舵剰缃戠珯"),
        "phishing_link": ("閽撻奔閾炬帴", "phishing", "nasa.ng"),
        "phishing_attachment": ("闄勪欢", "tcexec", "xlsm"),
        "shell": ("shell", "sh ", "bash", "execfile"),
        "callback": ("callback", "鍥炶繛", "operator console", "c2", "drakon"),
        "scan": ("scan", "portscan", "netrecon", "绔彛鎵弿"),
        "cleanup": ("rm ", "鍒犻櫎", "娓呯悊", "file deletion"),
    }
    for tag, markers in mapping.items():
        if any(marker in lowered for marker in markers):
            tags.append(tag)
    return tags


def parse_gt_windows_strict(markdown_path: Path) -> tuple[list[GTWindow], dict[str, list[str]]]:
    text = markdown_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    technique_to_tactics = _technique_definitions_from_strict(lines)
    windows: list[GTWindow] = []
    current_host = ""
    per_host_counter: dict[str, int] = {}
    for line in lines:
        heading = _STRICT_HOST_HEADING.match(line.strip())
        if heading:
            current_host = heading.group(1).strip().upper()
            continue
        cells = _split_markdown_row(line)
        if not current_host or len(cells) < 4:
            continue
        if not re.search(r"\d{4}-\d{2}-\d{2}", cells[0]):
            continue
        start_time, end_time, time_precision = _parse_time_cell(cells[0])
        source_ref = _source_ref_text(cells, 1)
        attack_summary = str(cells[2]).strip() if len(cells) >= 3 else ""
        techniques_text = str(cells[3]).strip()
        notes_text = str(cells[4]).strip() if len(cells) >= 5 else ""
        all_techniques = _extract_attack_ids(techniques_text)
        status, confirmed_techniques, attempted_techniques = _classify_window_status(all_techniques, notes_text)
        confirmed_tactics = _sorted_unique(
            tactic
            for attack_id in confirmed_techniques
            for tactic in technique_to_tactics.get(attack_id, [])
        )
        attempted_tactics = _sorted_unique(
            tactic
            for attack_id in attempted_techniques
            for tactic in technique_to_tactics.get(attack_id, [])
        )
        per_host_counter[current_host] = per_host_counter.get(current_host, 0) + 1
        start_token = start_time.strftime("%Y%m%d_%H%M") if start_time else "unknown"
        end_token = end_time.strftime("%H%M") if end_time else "unknown"
        window_id = f"{current_host}_{start_token}_{end_token}_{per_host_counter[current_host]:02d}"
        windows.append(
            GTWindow(
                window_id=window_id,
                host=current_host,
                source_doc=markdown_path.name,
                source_ref=source_ref,
                status=status,
                time_precision=time_precision,
                start_time=start_time,
                end_time=end_time,
                confirmed_techniques=confirmed_techniques,
                attempted_techniques=attempted_techniques,
                confirmed_tactics=confirmed_tactics,
                attempted_tactics=attempted_tactics,
                coarse_chain_tags=_line_chain_tags(" ".join(cells)),
                notes=notes_text,
                broad_techniques=[],
                attack_summary=attack_summary,
                source_report_pages=_parse_report_pages(source_ref),
            )
        )
    return windows, technique_to_tactics


def parse_gt_windows_broad(markdown_path: Path) -> list[dict[str, Any]]:
    text = markdown_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    windows: list[dict[str, Any]] = []
    current_host = ""
    for line in lines:
        heading = _BROAD_HOST_HEADING.match(line.strip())
        if heading:
            current_host = heading.group(1).strip().upper()
            continue
        cells = _split_markdown_row(line)
        if not current_host or len(cells) < 5:
            continue
        if not re.search(r"\d{4}-\d{2}-\d{2}", cells[0]):
            continue
        start_time, end_time, time_precision = _parse_time_cell(cells[0])
        if start_time is None and end_time is None:
            continue
        technique_ids = _extract_attack_ids(" ".join(cells))
        if not technique_ids:
            continue
        windows.append(
            {
                "host": current_host,
                "start_time": start_time,
                "end_time": end_time,
                "time_precision": time_precision,
                "techniques": technique_ids,
                "line_text": " ".join(cells),
            }
        )
    return windows


def _overlap_seconds(
    a_start: datetime | None,
    a_end: datetime | None,
    b_start: datetime | None,
    b_end: datetime | None,
) -> float:
    if a_start is None or a_end is None or b_start is None or b_end is None:
        return 0.0
    start = max(a_start, b_start)
    end = min(a_end, b_end)
    if end < start:
        return 0.0
    return max(0.0, (end - start).total_seconds())


def merge_broad_techniques(
    strict_windows: list[GTWindow],
    broad_windows: list[dict[str, Any]],
) -> None:
    for window in strict_windows:
        if window.start_time is None or window.end_time is None:
            continue
        matches = [
            item
            for item in broad_windows
            if str(item.get("host", "")).upper() == window.host
            and _overlap_seconds(
                window.start_time,
                window.end_time,
                item.get("start_time"),
                item.get("end_time"),
            )
            > 0
        ]
        if not matches:
            continue
        best = sorted(
            matches,
            key=lambda item: (
                -_overlap_seconds(
                    window.start_time,
                    window.end_time,
                    item.get("start_time"),
                    item.get("end_time"),
                ),
                len(item.get("techniques", [])),
            ),
        )[0]
        window.broad_techniques = _sorted_unique(best.get("techniques", []))


def build_gt_reference(
    *,
    strict_windows: list[GTWindow],
    technique_to_tactics: dict[str, list[str]],
    strict_md_path: Path | None,
    broad_md_path: Path | None,
    primary_report_name: str,
    primary_report_path: str,
    recommended_gt_offsets: dict[str, int] | None = None,
) -> dict[str, Any]:
    host_summary: dict[str, dict[str, Any]] = {}
    for window in strict_windows:
        summary = host_summary.setdefault(
            window.host,
            {
                "window_count": 0,
                "confirmed_window_count": 0,
                "attempted_window_count": 0,
                "insufficient_window_count": 0,
                "confirmed_technique_union": [],
                "attempted_technique_union": [],
                "confirmed_tactic_union": [],
                "attempted_tactic_union": [],
            },
        )
        summary["window_count"] += 1
        if window.status == "confirmed":
            summary["confirmed_window_count"] += 1
        elif window.status == "attempted_failed":
            summary["attempted_window_count"] += 1
        else:
            summary["insufficient_window_count"] += 1
        summary["confirmed_technique_union"] = _sorted_unique(
            list(summary["confirmed_technique_union"]) + list(window.confirmed_techniques)
        )
        summary["attempted_technique_union"] = _sorted_unique(
            list(summary["attempted_technique_union"]) + list(window.attempted_techniques)
        )
        summary["confirmed_tactic_union"] = _sorted_unique(
            list(summary["confirmed_tactic_union"]) + list(window.confirmed_tactics)
        )
        summary["attempted_tactic_union"] = _sorted_unique(
            list(summary["attempted_tactic_union"]) + list(window.attempted_tactics)
        )
    return {
        "schema_version": "darpa_attack_eval_gt.v1",
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "source_documents": {
            "primary_attack_report_name": str(primary_report_name or "").strip(),
            "primary_attack_report_path": str(primary_report_path or "").strip(),
            "strict_mapping_path": str(strict_md_path) if strict_md_path is not None else "",
            "broad_mapping_path": str(broad_md_path) if broad_md_path is not None else "",
        },
        "recommended_gt_time_offset_minutes_by_host": {
            str(host).strip().upper(): int(minutes)
            for host, minutes in (recommended_gt_offsets or {}).items()
        },
        "host_summary": host_summary,
        "technique_to_tactics": technique_to_tactics,
        "windows": [window.to_dict() for window in strict_windows],
    }


def render_gt_reference_markdown(reference: dict[str, Any]) -> str:
    source_docs = reference.get("source_documents", {}) if isinstance(reference, dict) else {}
    technique_defs = reference.get("technique_to_tactics", {}) if isinstance(reference, dict) else {}
    windows = reference.get("windows", []) if isinstance(reference, dict) else []
    lines: list[str] = []
    lines.append("# DARPA 攻击评估基准文件")
    lines.append("")
    lines.append("## 说明")
    lines.append("")
    lines.append("- 这份文件用于后续 DARPA 数据集 ATT&CK 识别实验的统一评估输入。")
    lines.append("- 评估粒度是 `host + attack_window`。")
    lines.append("- 主评估口径以 `confirmed` 窗口和 `confirmed_techniques` 为准。")
    lines.append("- `attempted_failed` 单独统计，不计入主 recall/precision 分母。")
    lines.append("")
    lines.append("## 鏉ユ簮")
    lines.append("")
    lines.append(f"- 瀹樻柟鏀诲嚮鎶ュ憡: `{source_docs.get('primary_attack_report_name', '')}`")
    if source_docs.get("primary_attack_report_path"):
        lines.append(f"- 瀹樻柟鏀诲嚮鎶ュ憡璺緞: `{source_docs.get('primary_attack_report_path', '')}`")
    if source_docs.get("strict_mapping_path"):
        lines.append(f"- 涓ユ牸鏄犲皠鏂囦欢: `{source_docs.get('strict_mapping_path', '')}`")
    if source_docs.get("broad_mapping_path"):
        lines.append(f"- 瀹芥澗鏄犲皠鏂囦欢: `{source_docs.get('broad_mapping_path', '')}`")
    recommended_offsets = (
        reference.get("recommended_gt_time_offset_minutes_by_host", {})
        if isinstance(reference.get("recommended_gt_time_offset_minutes_by_host", {}), dict)
        else {}
    )
    if recommended_offsets:
        lines.append("- 鎺ㄨ崘 GT 鏃堕棿鍋忕Щ:")
        for host, minutes in sorted(recommended_offsets.items()):
            lines.append(f"  - `{host}`: `{minutes}` 鍒嗛挓")
    lines.append("")
    host_names = sorted({str(item.get("host", "")).upper() for item in windows if isinstance(item, dict) and item.get("host")})
    for host in host_names:
        host_windows = [item for item in windows if isinstance(item, dict) and str(item.get("host", "")).upper() == host]
        lines.append(f"## {host}")
        lines.append("")
        lines.append("| Window ID | 鏃堕棿 | 鐘舵€?| 鏀诲嚮鎽樿 | Confirmed Tactics | Confirmed Techniques | Attempted Techniques | 鏉ユ簮椤电爜 |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for item in host_windows:
            start_time = str(item.get("start_time", "")).replace("T", " ")
            end_time = str(item.get("end_time", "")).replace("T", " ")
            if start_time and end_time and start_time != end_time:
                time_text = f"{start_time} - {end_time}"
            else:
                time_text = start_time or end_time or ""
            pages = ",".join(str(value) for value in item.get("source_report_pages", []) or [])
            lines.append(
                "| {window_id} | {time_text} | {status} | {summary} | {tactics} | {techniques} | {attempted} | {pages} |".format(
                    window_id=str(item.get("window_id", "")),
                    time_text=time_text,
                    status=str(item.get("status", "")),
                    summary=str(item.get("attack_summary", "")).replace("|", "/"),
                    tactics=", ".join(item.get("confirmed_tactics", []) or []),
                    techniques=", ".join(item.get("confirmed_techniques", []) or []),
                    attempted=", ".join(item.get("attempted_techniques", []) or []),
                    pages=pages,
                )
            )
        lines.append("")
    if technique_defs:
        lines.append("## Technique 鍒?Tactic 瀵圭収")
        lines.append("")
        lines.append("| Technique | Tactics |")
        lines.append("|---|---|")
        for technique_id in sorted(technique_defs):
            lines.append(f"| {technique_id} | {', '.join(technique_defs[technique_id])} |")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def save_gt_reference_files(
    reference: dict[str, Any],
    *,
    output_json_path: Path | None,
    output_markdown_path: Path | None,
) -> dict[str, str]:
    outputs: dict[str, str] = {}
    if output_json_path is not None:
        ensure_dir(output_json_path.parent)
        save_json(output_json_path, reference)
        outputs["gt_reference_json"] = str(output_json_path)
    if output_markdown_path is not None:
        ensure_dir(output_markdown_path.parent)
        output_markdown_path.write_text(render_gt_reference_markdown(reference), encoding="utf-8")
        outputs["gt_reference_markdown"] = str(output_markdown_path)
    return outputs


def load_gt_reference(
    gt_json_path: Path,
    *,
    host_filter: str = "",
) -> tuple[list[GTWindow], dict[str, list[str]], dict[str, Any]]:
    payload = load_json(gt_json_path)
    if isinstance(payload, list):
        windows_payload = payload
        technique_defs: dict[str, list[str]] = {}
        metadata: dict[str, Any] = {}
    else:
        windows_payload = payload.get("windows", []) if isinstance(payload, dict) else []
        technique_defs = payload.get("technique_to_tactics", {}) if isinstance(payload, dict) else {}
        metadata = payload if isinstance(payload, dict) else {}
    host_name = str(host_filter or "").strip().upper()
    windows: list[GTWindow] = []
    for item in windows_payload:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host", "")).strip().upper()
        if host_name and host != host_name:
            continue
        windows.append(
            GTWindow(
                window_id=str(item.get("window_id", "")).strip(),
                host=host,
                source_doc=str(item.get("source_doc", "")).strip(),
                source_ref=str(item.get("source_ref", "")).strip(),
                status=str(item.get("status", "insufficient")).strip(),
                time_precision=str(item.get("time_precision", "unknown")).strip(),
                start_time=_parse_datetime(item.get("start_time")),
                end_time=_parse_datetime(item.get("end_time")),
                confirmed_techniques=[str(value) for value in item.get("confirmed_techniques", []) or []],
                attempted_techniques=[str(value) for value in item.get("attempted_techniques", []) or []],
                confirmed_tactics=[str(value) for value in item.get("confirmed_tactics", []) or []],
                attempted_tactics=[str(value) for value in item.get("attempted_tactics", []) or []],
                coarse_chain_tags=[str(value) for value in item.get("coarse_chain_tags", []) or []],
                notes=str(item.get("notes", "")).strip(),
                broad_techniques=[str(value) for value in item.get("broad_techniques", []) or []],
                attack_summary=str(item.get("attack_summary", "")).strip(),
                source_report_pages=[int(value) for value in item.get("source_report_pages", []) or []],
            )
        )
    return windows, technique_defs, metadata


def apply_gt_time_offset(windows: list[GTWindow], *, minutes: int) -> None:
    if not minutes:
        return
    delta = timedelta(minutes=int(minutes))
    for window in windows:
        if window.start_time is not None:
            window.start_time = window.start_time + delta
        if window.end_time is not None:
            window.end_time = window.end_time + delta


def _sorted_unique(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in output:
            output.append(text)
    return output


def _report_mapping_sets(report: dict[str, Any]) -> tuple[list[str], list[str]]:
    tactic_names: list[str] = []
    technique_ids: list[str] = []
    for item in report.get("attack_mappings", []) or []:
        if not isinstance(item, dict):
            continue
        tactic_id = _canonical_tactic_name(str(item.get("tactic_id", "")).strip())
        tactic_name = _canonical_tactic_name(str(item.get("tactic", "")).strip())
        technique_id = _canonical_attack_id(str(item.get("technique_id", "")).strip())
        if tactic_id:
            tactic_names.append(tactic_id)
        elif tactic_name:
            tactic_names.append(tactic_name)
        if technique_id:
            technique_ids.append(technique_id)
    return _sorted_unique(tactic_names), _sorted_unique(technique_ids)


def _candidate_tactic_set(report: dict[str, Any]) -> list[str]:
    tactic_names: list[str] = []
    for item in report.get("attack_candidates", {}).get("tactics", []) or []:
        if not isinstance(item, dict):
            continue
        tactic_id = _canonical_tactic_name(str(item.get("external_id", "")).strip())
        tactic_name = _canonical_tactic_name(str(item.get("name", "")).strip())
        if tactic_id:
            tactic_names.append(tactic_id)
        elif tactic_name:
            tactic_names.append(tactic_name)
    return _sorted_unique(tactic_names)


def extract_predicted_paths(artifacts_dir: Path, host: str) -> list[PredictedPath]:
    candidate_dir = artifacts_dir / "module5_paths" / "candidate_paths"
    reports_dir = artifacts_dir / "module6_reason" / "reports"
    report_by_path_id: dict[str, dict[str, Any]] = {}
    report_file_by_path_id: dict[str, str] = {}
    if reports_dir.exists():
        for path in reports_dir.glob("*.report.json"):
            payload = load_json(path)
            if not isinstance(payload, dict):
                continue
            path_id = str(payload.get("path_id", "")).strip()
            if not path_id:
                continue
            report_by_path_id[path_id] = payload
            report_file_by_path_id[path_id] = str(path)
    predicted: list[PredictedPath] = []
    if not candidate_dir.exists():
        return predicted
    for path in sorted(candidate_dir.glob("*.json")):
        payload = load_json(path)
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            path_id = str(item.get("path_id", "")).strip()
            task_id = str(item.get("task_id", "")).strip()
            if not path_id or not task_id:
                continue
            time_range = item.get("time_range", {}) if isinstance(item.get("time_range"), dict) else {}
            start_time = _parse_datetime(time_range.get("start"))
            end_time = _parse_datetime(time_range.get("end"))
            dossier = item.get("dossier", {}) if isinstance(item.get("dossier"), dict) else {}
            if start_time is None or end_time is None:
                start_time, end_time = _time_range_from_dossier(dossier)
            report = report_by_path_id.get(path_id, {})
            predicted_tactics, predicted_techniques = _report_mapping_sets(report)
            candidate_tactics = _candidate_tactic_set(report)
            predicted.append(
                PredictedPath(
                    host=str(host).upper(),
                    task_id=task_id,
                    path_id=path_id,
                    risk_score=float(item.get("risk_score", 0.0) or 0.0),
                    risk_level=str(item.get("risk_level", "")).strip().upper() or "INFO",
                    start_time=start_time,
                    end_time=end_time,
                    stage_coverage=[str(value) for value in item.get("stage_coverage", [])],
                    process_chain=[str(value) for value in item.get("process_chain", [])],
                    bridge_objects=_sorted_unique(
                        str(edge.get("object_key", "")).strip()
                        for edge in item.get("bridge_edges", []) or []
                        if isinstance(edge, dict)
                    ),
                    candidate_tactics=candidate_tactics,
                    predicted_tactics=predicted_tactics,
                    predicted_techniques=predicted_techniques,
                    attack_mapping_scope=str(report.get("attack_mapping_scope", "full")).strip().lower() or "full",
                    warnings=[str(value) for value in item.get("warnings", [])],
                    candidate_paths_path=str(path),
                    report_path=report_file_by_path_id.get(path_id, ""),
                )
            )
    predicted.sort(
        key=lambda item: (
            item.host,
            -item.risk_score,
            -_RISK_ORDER.get(item.risk_level, 0),
            item.path_id,
        )
    )
    return predicted


def _time_range_from_dossier(dossier: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    times = [
        _parse_datetime(item.get("timestamp"))
        for item in dossier.get("evidence_timeline", []) or []
        if isinstance(item, dict)
    ]
    values = [item for item in times if item is not None]
    if not values:
        return None, None
    return min(values), max(values)


def _padded_window(window: GTWindow, pad_minutes: int) -> tuple[datetime | None, datetime | None]:
    if window.start_time is None or window.end_time is None:
        return None, None
    padding = timedelta(minutes=int(pad_minutes))
    return window.start_time - padding, window.end_time + padding


def _midpoint(start_time: datetime | None, end_time: datetime | None) -> datetime | None:
    if start_time is None or end_time is None:
        return None
    return start_time + (end_time - start_time) / 2


def _path_duration_seconds(path: PredictedPath) -> float:
    if path.start_time is None or path.end_time is None:
        return 1.0
    value = (path.end_time - path.start_time).total_seconds()
    return max(1.0, float(value))


def time_match_for_window(
    path: PredictedPath,
    window: GTWindow,
    *,
    pad_minutes: int,
    near_miss_minutes: int,
) -> PathWindowMatch:
    padded_start, padded_end = _padded_window(window, pad_minutes)
    intersection = _overlap_seconds(path.start_time, path.end_time, padded_start, padded_end)
    point_like_path = bool(path.start_time is not None and path.end_time is not None and path.start_time == path.end_time)
    midpoint = _midpoint(path.start_time, path.end_time)
    midpoint_in_window = bool(
        midpoint is not None and padded_start is not None and padded_end is not None and padded_start <= midpoint <= padded_end
    )
    fully_inside = bool(
        path.start_time is not None
        and path.end_time is not None
        and padded_start is not None
        and padded_end is not None
        and padded_start <= path.start_time <= padded_end
        and padded_start <= path.end_time <= padded_end
    )
    if point_like_path and fully_inside and intersection <= 0:
        # Treat an in-window point event as one effective second so it can
        # participate in the same overlap logic as non-zero-duration paths.
        intersection = 1.0
    ratio = intersection / _path_duration_seconds(path)
    strict_time_match = bool(ratio >= 0.8 or fully_inside)
    primary_time_match = bool((intersection > 0 or fully_inside) and (ratio >= 0.5 or midpoint_in_window or fully_inside))
    loose_time_match = bool(intersection > 0 or fully_inside)
    near_miss = False
    if not loose_time_match and padded_start is not None and padded_end is not None and path.start_time and path.end_time:
        gap_seconds = min(
            abs((path.end_time - padded_start).total_seconds()),
            abs((path.start_time - padded_end).total_seconds()),
        )
        near_miss = gap_seconds <= float(near_miss_minutes * 60)
    return PathWindowMatch(
        path_id=path.path_id,
        match_type="UNASSIGNED",
        path_in_window_ratio=float(ratio),
        intersection_seconds=float(intersection),
        midpoint_in_window=midpoint_in_window,
        strict_time_match=strict_time_match,
        primary_time_match=primary_time_match,
        loose_time_match=loose_time_match,
        near_miss_time=near_miss,
        window_id=window.window_id,
    )


def assign_paths_to_windows(
    predicted_paths: list[PredictedPath],
    gt_windows: list[GTWindow],
    *,
    pad_minutes: int,
    near_miss_minutes: int,
) -> list[dict[str, Any]]:
    assignments: list[dict[str, Any]] = []
    for path in predicted_paths:
        confirmed_candidates: list[tuple[GTWindow, PathWindowMatch]] = []
        attempted_candidates: list[tuple[GTWindow, PathWindowMatch]] = []
        for window in gt_windows:
            if window.host != path.host:
                continue
            match = time_match_for_window(
                path,
                window,
                pad_minutes=pad_minutes,
                near_miss_minutes=near_miss_minutes,
            )
            if window.status == "confirmed" and match.primary_time_match:
                confirmed_candidates.append((window, match))
            elif window.status == "attempted_failed" and match.primary_time_match:
                attempted_candidates.append((window, match))
        chosen_window: GTWindow | None = None
        chosen_match: PathWindowMatch | None = None
        match_type = "OFF_WINDOW"
        if confirmed_candidates:
            chosen_window, chosen_match = sorted(
                confirmed_candidates,
                key=lambda item: (
                    -item[1].path_in_window_ratio,
                    -path.risk_score,
                    _midpoint_distance_seconds(path, item[0]),
                ),
            )[0]
            match_type = "CONFIRMED_MATCH"
        elif attempted_candidates:
            chosen_window, chosen_match = sorted(
                attempted_candidates,
                key=lambda item: (
                    -item[1].path_in_window_ratio,
                    -path.risk_score,
                    _midpoint_distance_seconds(path, item[0]),
                ),
            )[0]
            match_type = "ATTEMPT_MATCH"
        if chosen_match is None:
            best_near_miss = _best_near_miss(path, gt_windows, pad_minutes=pad_minutes, near_miss_minutes=near_miss_minutes)
            assignments.append(
                {
                    **path.to_dict(),
                    "path_in_window_ratio": 0.0,
                    "intersection_seconds": 0.0,
                    "midpoint_in_window": False,
                    "strict_time_match": False,
                    "primary_time_match": False,
                    "loose_time_match": False,
                    "near_miss_time": False,
                    "window_id": None,
                    **(best_near_miss.to_dict() if best_near_miss else {}),
                    "assigned_window_id": None,
                    "assigned_status": match_type,
                }
            )
            continue
        assignments.append(
            {
                **path.to_dict(),
                **{**chosen_match.to_dict(), "match_type": match_type},
                "assigned_window_id": chosen_window.window_id,
                "assigned_status": match_type,
            }
        )
    return _reattach_confirmed_continuations(assignments, predicted_paths, gt_windows)


def _reattach_confirmed_continuations(
    assignments: list[dict[str, Any]],
    predicted_paths: list[PredictedPath],
    gt_windows: list[GTWindow],
) -> list[dict[str, Any]]:
    if not assignments:
        return assignments
    path_by_id = {path.path_id: path for path in predicted_paths}
    window_by_id = {window.window_id: window for window in gt_windows}
    confirmed_by_task: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in assignments:
        if str(item.get("assigned_status", "")) != "CONFIRMED_MATCH":
            continue
        host = str(item.get("host", "")).strip().upper()
        task_id = str(item.get("task_id", "")).strip()
        if not host or not task_id:
            continue
        confirmed_by_task.setdefault((host, task_id), []).append(item)
    for item in assignments:
        if str(item.get("assigned_status", "")) != "OFF_WINDOW":
            continue
        path_id = str(item.get("path_id", "")).strip()
        task_id = str(item.get("task_id", "")).strip()
        host = str(item.get("host", "")).strip().upper()
        path = path_by_id.get(path_id)
        if path is None or not task_id or not host:
            continue
        anchor = _best_confirmed_continuation_anchor(
            path,
            confirmed_by_task.get((host, task_id), []),
            path_by_id=path_by_id,
            window_by_id=window_by_id,
        )
        if anchor is None:
            continue
        anchor_window_id = str(anchor.get("assigned_window_id") or "")
        anchor_path_id = str(anchor.get("path_id", "")).strip()
        item["window_id"] = anchor_window_id
        item["assigned_window_id"] = anchor_window_id
        item["assigned_status"] = "CONFIRMED_CONTINUATION"
        item["match_type"] = "CONFIRMED_CONTINUATION"
        item["continuation_anchor_path_id"] = anchor_path_id
        item["continuation_reason"] = "same_task_nearby_subset"
    return assignments


def _best_confirmed_continuation_anchor(
    path: PredictedPath,
    confirmed_items: list[dict[str, Any]],
    *,
    path_by_id: dict[str, PredictedPath],
    window_by_id: dict[str, GTWindow],
) -> dict[str, Any] | None:
    candidates: list[tuple[int, float, float, dict[str, Any]]] = []
    off_tactics = {_canonical_tactic_name(value) for value in path.predicted_tactics if _canonical_tactic_name(value)}
    off_processes = {str(value).strip() for value in path.process_chain if str(value).strip()}
    off_bridges = {str(value).strip() for value in path.bridge_objects if str(value).strip()}
    for item in confirmed_items:
        anchor_path = path_by_id.get(str(item.get("path_id", "")).strip())
        window = window_by_id.get(str(item.get("assigned_window_id") or "").strip())
        if anchor_path is None or window is None:
            continue
        if not _is_confirmed_continuation_candidate(
            path,
            anchor_path,
            window,
            off_tactics=off_tactics,
            off_processes=off_processes,
            off_bridges=off_bridges,
        ):
            continue
        shared_process_count = len(off_processes.intersection({str(value).strip() for value in anchor_path.process_chain if str(value).strip()}))
        overlap_seconds = _overlap_seconds(path.start_time, path.end_time, anchor_path.start_time, anchor_path.end_time)
        gap_seconds = _continuation_gap_seconds(path, window)
        candidates.append((shared_process_count, float(overlap_seconds), -float(gap_seconds), item))
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (-item[0], -item[1], -item[2], str(item[3].get("path_id", ""))))[0][3]


def _is_confirmed_continuation_candidate(
    path: PredictedPath,
    anchor_path: PredictedPath,
    window: GTWindow,
    *,
    off_tactics: set[str],
    off_processes: set[str],
    off_bridges: set[str],
) -> bool:
    if path.start_time is None or path.end_time is None or window.end_time is None:
        return False
    anchor_processes = {str(value).strip() for value in anchor_path.process_chain if str(value).strip()}
    anchor_bridges = {str(value).strip() for value in anchor_path.bridge_objects if str(value).strip()}
    if not off_processes.intersection(anchor_processes) and not off_bridges.intersection(anchor_bridges):
        return False
    if off_tactics:
        anchor_tactics = {_canonical_tactic_name(value) for value in anchor_path.predicted_tactics if _canonical_tactic_name(value)}
        if not anchor_tactics or not off_tactics.issubset(anchor_tactics):
            return False
    overlap_anchor = _overlap_seconds(path.start_time, path.end_time, anchor_path.start_time, anchor_path.end_time) > 0
    if overlap_anchor:
        return True
    return _continuation_gap_seconds(path, window) <= float(_CONFIRMED_CONTINUATION_MAX_GAP_MINUTES * 60)


def _continuation_gap_seconds(path: PredictedPath, window: GTWindow) -> float:
    if path.start_time is None or window.end_time is None:
        return math.inf
    return max(0.0, float((path.start_time - window.end_time).total_seconds()))


def _path_assignment_match(item: dict[str, Any]) -> PathWindowMatch:
    return PathWindowMatch(
        path_id=str(item.get("path_id", "")),
        match_type=str(item.get("assigned_status") or item.get("match_type") or "UNASSIGNED"),
        path_in_window_ratio=float(item.get("path_in_window_ratio", 0.0) or 0.0),
        intersection_seconds=float(item.get("intersection_seconds", 0.0) or 0.0),
        midpoint_in_window=bool(item.get("midpoint_in_window", False)),
        strict_time_match=bool(item.get("strict_time_match", False)),
        primary_time_match=bool(item.get("primary_time_match", False)),
        loose_time_match=bool(item.get("loose_time_match", False)),
        near_miss_time=bool(item.get("near_miss_time", False)),
        window_id=str(item.get("assigned_window_id") or item.get("window_id") or "") or None,
    )


def _assigned_confirmed_paths_by_window(
    predicted_paths: list[PredictedPath],
    path_assignments: list[dict[str, Any]],
) -> dict[str, list[tuple[PredictedPath, PathWindowMatch]]]:
    by_key = {(path.host, path.path_id): path for path in predicted_paths}
    grouped: dict[str, list[tuple[PredictedPath, PathWindowMatch]]] = {}
    for item in path_assignments:
        if str(item.get("assigned_status", "")) not in {"CONFIRMED_MATCH", "CONFIRMED_CONTINUATION"}:
            continue
        window_id = str(item.get("assigned_window_id") or "")
        if not window_id:
            continue
        path = by_key.get((str(item.get("host", "")), str(item.get("path_id", ""))))
        if path is None:
            continue
        grouped.setdefault(window_id, []).append((path, _path_assignment_match(item)))
    return grouped


def _best_near_miss(
    path: PredictedPath,
    windows: list[GTWindow],
    *,
    pad_minutes: int,
    near_miss_minutes: int,
) -> PathWindowMatch | None:
    candidates: list[tuple[GTWindow, PathWindowMatch]] = []
    for window in windows:
        if window.host != path.host:
            continue
        match = time_match_for_window(path, window, pad_minutes=pad_minutes, near_miss_minutes=near_miss_minutes)
        if match.near_miss_time:
            candidates.append((window, match))
    if not candidates:
        return None
    window, match = sorted(
        candidates,
        key=lambda item: (
            _midpoint_distance_seconds(path, item[0]),
            -item[1].path_in_window_ratio,
        ),
    )[0]
    match.window_id = window.window_id
    return match


def _midpoint_distance_seconds(path: PredictedPath, window: GTWindow) -> float:
    path_mid = _midpoint(path.start_time, path.end_time)
    window_mid = _midpoint(window.start_time, window.end_time)
    if path_mid is None or window_mid is None:
        return float("inf")
    return abs((path_mid - window_mid).total_seconds())


def evaluate_path_reason(
    *,
    strict_windows: list[GTWindow],
    predicted_paths: list[PredictedPath],
    path_assignments: list[dict[str, Any]],
    match_top_n: int,
    pad_minutes: int,
    near_miss_minutes: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    paths_by_host: dict[str, list[PredictedPath]] = {}
    for path in predicted_paths:
        paths_by_host.setdefault(path.host, []).append(path)
    confirmed_paths_by_window = _assigned_confirmed_paths_by_window(predicted_paths, path_assignments)
    confirmed_windows = [
        window
        for window in strict_windows
        if window.status == "confirmed" and window.time_precision == "minute_window"
    ]
    attempt_windows = [
        window
        for window in strict_windows
        if window.status == "attempted_failed" and window.time_precision == "minute_window"
    ]

    window_level: list[dict[str, Any]] = []
    technique_comparison: list[dict[str, Any]] = []
    tactic_comparison: list[dict[str, Any]] = []
    candidate_tactic_coverage: list[dict[str, Any]] = []
    confirmed_hits = 0
    strict_hits = 0
    high_risk_hits = 0
    attempt_flags = 0
    best_start_errors: list[float] = []
    best_end_errors: list[float] = []
    best_mid_errors: list[float] = []
    purity_values: list[float] = []
    split_counts: list[int] = []
    strict_recall_values: list[float] = []
    strict_precision_values: list[float] = []
    strict_tactic_recall_values: list[float] = []
    strict_tactic_precision_values: list[float] = []
    broad_recall_values: list[float] = []
    full_coverage_count = 0
    technique_tp_total = 0
    technique_gt_total = 0
    technique_pred_total = 0
    tactic_tp_total = 0
    tactic_gt_total = 0
    tactic_pred_total = 0

    for window in confirmed_windows:
        primary_paths = confirmed_paths_by_window.get(window.window_id, [])
        strict_paths = [item for item in primary_paths if item[1].strict_time_match]
        confirmed_recall_paths = [item for item in primary_paths if item[0].risk_level in _MEDIUM_OR_HIGH]
        strict_recall_paths = [item for item in strict_paths if item[0].risk_level in _MEDIUM_OR_HIGH]
        high_risk_paths = [item for item in primary_paths if item[0].risk_level in _HIGH_ONLY]
        if confirmed_recall_paths:
            confirmed_hits += 1
        if strict_recall_paths:
            strict_hits += 1
        if high_risk_paths:
            high_risk_hits += 1

        best_path_pair = _best_path(primary_paths, window)
        matched_top = _matched_path_set(primary_paths, limit=match_top_n)
        split_counts.append(len(primary_paths))
        pred_techniques = _sorted_unique(
            technique
            for path, _ in matched_top
            for technique in path.predicted_techniques
        )
        pred_tactics = _sorted_unique(
            tactic
            for path, _ in matched_top
            for tactic in path.predicted_tactics
        )
        candidate_tactics = _sorted_unique(
            tactic
            for path, _ in matched_top
            for tactic in path.candidate_tactics
        )
        gt_techniques = list(window.confirmed_techniques)
        gt_tactics = list(window.confirmed_tactics)
        overlap_techniques = sorted(set(pred_techniques).intersection(gt_techniques))
        overlap_tactics = sorted(set(pred_tactics).intersection(gt_tactics))
        strict_recall = len(overlap_techniques) / max(1, len(gt_techniques))
        strict_precision = len(overlap_techniques) / max(1, len(pred_techniques))
        strict_tactic_recall = len(overlap_tactics) / max(1, len(gt_tactics))
        strict_tactic_precision = len(overlap_tactics) / max(1, len(pred_tactics))
        strict_recall_values.append(strict_recall)
        if matched_top:
            strict_precision_values.append(strict_precision)
            strict_tactic_precision_values.append(strict_tactic_precision)
        strict_tactic_recall_values.append(strict_tactic_recall)
        broad_gt = window.broad_techniques or gt_techniques
        broad_overlap = sorted(set(pred_techniques).intersection(broad_gt))
        broad_recall = len(broad_overlap) / max(1, len(broad_gt))
        broad_recall_values.append(broad_recall)
        if set(gt_techniques).issubset(set(pred_techniques)):
            full_coverage_count += 1
        technique_tp_total += len(overlap_techniques)
        technique_gt_total += len(gt_techniques)
        technique_pred_total += len(pred_techniques)
        tactic_tp_total += len(overlap_tactics)
        tactic_gt_total += len(gt_tactics)
        tactic_pred_total += len(pred_tactics)

        best_path_id = ""
        best_match_type = ""
        best_purity = 0.0
        if best_path_pair is not None:
            best_path, best_match = best_path_pair
            best_path_id = best_path.path_id
            best_match_type = "strict" if best_match.strict_time_match else "primary"
            best_purity = float(best_match.path_in_window_ratio)
            purity_values.append(best_purity)
            if window.start_time and window.end_time and best_path.start_time and best_path.end_time:
                best_start_errors.append(abs((best_path.start_time - window.start_time).total_seconds()))
                best_end_errors.append(abs((best_path.end_time - window.end_time).total_seconds()))
                path_mid = _midpoint(best_path.start_time, best_path.end_time)
                window_mid = _midpoint(window.start_time, window.end_time)
                if path_mid and window_mid:
                    best_mid_errors.append(abs((path_mid - window_mid).total_seconds()))

        warnings: list[str] = []
        if not matched_top:
            warnings.append("no primary-time matched path")
        host_paths = paths_by_host.get(window.host, [])
        mapping_scope = matched_top[0][0].attack_mapping_scope if matched_top else (host_paths[0].attack_mapping_scope if host_paths else "full")
        if mapping_scope != "tactics_only" and not pred_techniques:
            warnings.append("no ATT&CK technique emitted for top matched paths")
        window_level.append(
            {
                "window_id": window.window_id,
                "host": window.host,
                "status": window.status,
                "start_time": _iso(window.start_time),
                "end_time": _iso(window.end_time),
                "best_path_id": best_path_id,
                "matched_path_ids": [path.path_id for path, _ in matched_top],
                "time_match_type": best_match_type,
                "path_purity": best_purity,
                "window_split_factor": len(primary_paths),
                "strict_technique_recall": strict_recall,
                "strict_technique_precision": strict_precision if matched_top else 0.0,
                "strict_tactic_recall": strict_tactic_recall,
                "strict_tactic_precision": strict_tactic_precision if matched_top else 0.0,
                "warnings": warnings,
            }
        )
        technique_comparison.append(
            {
                "window_id": window.window_id,
                "host": window.host,
                "gt_confirmed_techniques": gt_techniques,
                "gt_broad_techniques": list(broad_gt),
                "predicted_techniques_union_top_n": pred_techniques,
                "predicted_tactics_union_top_n": pred_tactics,
                "overlap_techniques": overlap_techniques,
                "missed_gt_techniques": [item for item in gt_techniques if item not in overlap_techniques],
                "extra_predicted_techniques": [item for item in pred_techniques if item not in overlap_techniques],
            }
        )
        matched_task_ids = _sorted_unique([path.task_id for path, _ in matched_top])
        tactic_comparison.append(
            {
                "window_id": window.window_id,
                "host": window.host,
                "matched_task_ids": matched_task_ids,
                "gt_tactics": gt_tactics,
                "predicted_tactics_union_top_n": pred_tactics,
                "matched_tactics": overlap_tactics,
                "missed_tactics": [item for item in gt_tactics if item not in overlap_tactics],
                "extra_tactics": [item for item in pred_tactics if item not in overlap_tactics],
            }
        )
        candidate_tactic_coverage.append(
            {
                "window_id": window.window_id,
                "host": window.host,
                "matched_task_ids": matched_task_ids,
                "gt_tactics": gt_tactics,
                "candidate_tactics_union_top_n": candidate_tactics,
                "covered_gt_tactics": [item for item in gt_tactics if item in candidate_tactics],
                "missing_candidate_tactics": [item for item in gt_tactics if item not in candidate_tactics],
            }
        )

    for window in attempt_windows:
        host_paths = paths_by_host.get(window.host, [])
        matches = [
            (
                path,
                time_match_for_window(
                    path,
                    window,
                    pad_minutes=pad_minutes,
                    near_miss_minutes=near_miss_minutes,
                ),
            )
            for path in host_paths
        ]
        flagged = any(
            match.loose_time_match and path.risk_level in _MEDIUM_OR_HIGH
            for path, match in matches
        )
        if flagged:
            attempt_flags += 1
        window_level.append(
            {
                "window_id": window.window_id,
                "host": window.host,
                "status": window.status,
                "start_time": _iso(window.start_time),
                "end_time": _iso(window.end_time),
                "best_path_id": "",
                "matched_path_ids": [path.path_id for path, match in matches if match.loose_time_match],
                "time_match_type": "loose" if flagged else "",
                "path_purity": 0.0,
                "window_split_factor": sum(1 for _, match in matches if match.primary_time_match),
                "strict_technique_recall": 0.0,
                "strict_technique_precision": 0.0,
                "strict_tactic_recall": 0.0,
                "warnings": [] if flagged else ["attempt window not flagged"],
            }
        )

    off_window_high_risk = [
        item
        for item in path_assignments
        if str(item.get("assigned_status", "")) == "OFF_WINDOW"
        and str(item.get("risk_level", "")).upper() == "HIGH"
    ]
    total_high_risk_paths = sum(1 for item in path_assignments if str(item.get("risk_level", "")).upper() == "HIGH")
    summary = {
        "confirmed_window_count": len(confirmed_windows),
        "attempt_window_count": len(attempt_windows),
        "predicted_path_count": len(predicted_paths),
        "predicted_path_with_report_count": sum(1 for item in predicted_paths if item.report_path),
        "confirmed_window_recall": _safe_ratio(confirmed_hits, len(confirmed_windows)),
        "strict_window_recall": _safe_ratio(strict_hits, len(confirmed_windows)),
        "high_risk_window_recall": _safe_ratio(high_risk_hits, len(confirmed_windows)),
        "attempt_window_flag_rate": _safe_ratio(attempt_flags, len(attempt_windows)),
        "off_window_high_risk_count": len(off_window_high_risk),
        "off_window_high_risk_rate": _safe_ratio(len(off_window_high_risk), total_high_risk_paths),
        "median_start_error_sec": _median_or_zero(best_start_errors),
        "median_end_error_sec": _median_or_zero(best_end_errors),
        "median_midpoint_error_sec": _median_or_zero(best_mid_errors),
        "mean_path_purity": _mean_or_zero(purity_values),
        "median_path_purity": _median_or_zero(purity_values),
        "mean_window_split_factor": _mean_or_zero(split_counts),
        "median_window_split_factor": _median_or_zero(split_counts),
        "p95_window_split_factor": _percentile_or_zero(split_counts, 95),
        "strict_technique_recall_macro": _mean_or_zero(strict_recall_values),
        "strict_technique_recall_micro": _safe_ratio(technique_tp_total, technique_gt_total),
        "strict_technique_precision_macro": _mean_or_zero(strict_precision_values),
        "strict_technique_precision_micro": _safe_ratio(technique_tp_total, technique_pred_total),
        "strict_tactic_recall_macro": _mean_or_zero(strict_tactic_recall_values),
        "strict_tactic_precision_macro": _mean_or_zero(strict_tactic_precision_values),
        "strict_tactic_precision_micro": _safe_ratio(tactic_tp_total, tactic_pred_total),
        "broad_technique_recall_macro": _mean_or_zero(broad_recall_values),
        "window_full_coverage_rate": _safe_ratio(full_coverage_count, len(confirmed_windows)),
        "window_pad_before_minutes": int(pad_minutes),
        "window_pad_after_minutes": int(pad_minutes),
        "near_miss_minutes": int(near_miss_minutes),
        "matched_path_top_n": int(match_top_n),
    }
    return summary, window_level, technique_comparison, tactic_comparison, candidate_tactic_coverage


def _best_path(
    primary_paths: list[tuple[PredictedPath, PathWindowMatch]],
    window: GTWindow,
) -> tuple[PredictedPath, PathWindowMatch] | None:
    if not primary_paths:
        return None
    return sorted(
        primary_paths,
        key=lambda item: (
            -item[1].path_in_window_ratio,
            -item[0].risk_score,
            _midpoint_distance_seconds(item[0], window),
        ),
    )[0]


def _matched_path_set(
    primary_paths: list[tuple[PredictedPath, PathWindowMatch]],
    *,
    limit: int,
) -> list[tuple[PredictedPath, PathWindowMatch]]:
    ordered = sorted(
        primary_paths,
        key=lambda item: (
            -item[0].risk_score,
            -_RISK_ORDER.get(item[0].risk_level, 0),
            -item[1].path_in_window_ratio,
            item[0].path_id,
        ),
    )
    return ordered[: max(1, int(limit))]


def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
    if not denominator:
        return 0.0
    return float(numerator) / float(denominator)


def _median_or_zero(values: list[float]) -> float:
    if not values:
        return 0.0
    return float(median(values))


def _mean_or_zero(values: list[int | float]) -> float:
    if not values:
        return 0.0
    return float(sum(float(value) for value in values) / len(values))


def _percentile_or_zero(values: list[int | float], percentile: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(float(value) for value in values)
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (float(percentile) / 100.0) * (len(sorted_values) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_values[low]
    fraction = rank - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * fraction


def run_evaluation(
    *,
    artifacts_dir: Path,
    strict_windows: list[GTWindow],
    technique_defs: dict[str, list[str]],
    output_dir: Path,
    host: str,
    match_top_n: int,
    pad_minutes: int,
    near_miss_minutes: int,
) -> dict[str, str]:
    ensure_dir(output_dir)
    predicted_paths = extract_predicted_paths(artifacts_dir, host=host)
    assignments = assign_paths_to_windows(
        predicted_paths,
        strict_windows,
        pad_minutes=pad_minutes,
        near_miss_minutes=near_miss_minutes,
    )
    summary, window_level, technique_comparison, tactic_comparison, candidate_tactic_coverage = evaluate_path_reason(
        strict_windows=strict_windows,
        predicted_paths=predicted_paths,
        path_assignments=assignments,
        match_top_n=match_top_n,
        pad_minutes=pad_minutes,
        near_miss_minutes=near_miss_minutes,
    )
    gt_windows_path = output_dir / "gt_windows_strict.json"
    predicted_paths_path = output_dir / "predicted_paths.json"
    metrics_summary_path = output_dir / "metrics_summary.json"
    window_level_path = output_dir / "window_level_metrics.json"
    path_assignment_path = output_dir / "path_assignment.json"
    technique_comparison_path = output_dir / "technique_comparison.json"
    tactic_comparison_path = output_dir / "tactic_comparison.json"
    tactic_diff_by_task_path = output_dir / "tactic_diff_by_task.json"
    candidate_tactic_coverage_path = output_dir / "candidate_tactic_coverage_by_task.json"
    technique_defs_path = output_dir / "technique_to_tactics.json"
    save_json(gt_windows_path, [item.to_dict() for item in strict_windows])
    save_json(predicted_paths_path, [item.to_dict() for item in predicted_paths])
    save_json(metrics_summary_path, summary)
    save_json(window_level_path, window_level)
    save_json(path_assignment_path, assignments)
    save_json(technique_comparison_path, technique_comparison)
    save_json(tactic_comparison_path, tactic_comparison)
    save_json(tactic_diff_by_task_path, tactic_comparison)
    save_json(candidate_tactic_coverage_path, candidate_tactic_coverage)
    save_json(technique_defs_path, technique_defs)
    return {
        "gt_windows_strict": str(gt_windows_path),
        "predicted_paths": str(predicted_paths_path),
        "metrics_summary": str(metrics_summary_path),
        "window_level_metrics": str(window_level_path),
        "path_assignment": str(path_assignment_path),
        "technique_comparison": str(technique_comparison_path),
        "tactic_comparison": str(tactic_comparison_path),
        "tactic_diff_by_task": str(tactic_diff_by_task_path),
        "candidate_tactic_coverage_by_task": str(candidate_tactic_coverage_path),
        "technique_to_tactics": str(technique_defs_path),
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate path_reason outputs against attack-report windows.")
    parser.add_argument("--artifacts-dir", default="", help="Artifact root containing module5_paths and module6_reason.")
    parser.add_argument("--strict-md", default="", help="Path to ALL_HOSTS_ATTCK_STRICT_MAPPING.md")
    parser.add_argument("--broad-md", default="", help="Optional path to ALL_HOSTS_ATTACK_ATTCK_MAPPING.md")
    parser.add_argument(
        "--gt-json",
        default=str(_DEFAULT_GT_JSON_PATH),
        help="Canonical GT JSON file used for attack-window evaluation. Defaults to the enriched E3-report GT.",
    )
    parser.add_argument("--output-dir", default="", help="Output directory. Defaults to <artifacts-dir>/path_reason_eval")
    parser.add_argument("--host", default="", help="Host name, for example TRACE/THEIA/CADETS.")
    parser.add_argument("--match-top-n", type=int, default=5, help="Top-N matched paths per window for ATT&CK union.")
    parser.add_argument("--pad-minutes", type=int, default=5, help="Padding minutes added before and after GT windows.")
    parser.add_argument("--near-miss-minutes", type=int, default=5, help="Near-miss threshold in minutes.")
    parser.add_argument("--export-gt-json", default="", help="Optional path to write a canonical GT JSON file.")
    parser.add_argument("--export-gt-md", default="", help="Optional path to write a human-readable GT markdown summary.")
    parser.add_argument(
        "--source-primary-doc",
        default="TC_Ground_Truth_Report_E3_Update.pdf",
        help="Primary official DARPA attack report name used when exporting GT reference files.",
    )
    parser.add_argument(
        "--source-primary-path",
        default="",
        help="Optional absolute path to the primary official DARPA attack report.",
    )
    parser.add_argument(
        "--recommended-gt-offsets",
        default="",
        help="Optional comma-separated HOST=MINUTES pairs stored into exported GT reference metadata, for example TRACE=240.",
    )
    parser.add_argument(
        "--gt-time-offset-minutes",
        default="",
        help="Optional GT window offset in minutes applied before evaluation. When omitted, evaluator will use the host-specific recommended offset from --gt-json if available.",
    )
    parser.add_argument(
        "--build-gt-only",
        action="store_true",
        help="Only build/export the canonical GT reference files and skip experiment evaluation.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    host = str(args.host).strip().upper()
    strict_md_text = str(args.strict_md).strip()
    broad_md_text = str(args.broad_md).strip()
    gt_json_text = str(args.gt_json).strip()
    export_gt_json_text = str(args.export_gt_json).strip()
    export_gt_md_text = str(args.export_gt_md).strip()
    recommended_gt_offsets = _parse_host_offsets(str(args.recommended_gt_offsets).strip())

    if args.build_gt_only:
        if not strict_md_text:
            parser.error("--build-gt-only requires --strict-md")
        strict_windows, technique_defs = parse_gt_windows_strict(Path(strict_md_text))
        broad_md_path = Path(broad_md_text) if broad_md_text else None
        if broad_md_path is not None and broad_md_path.exists():
            merge_broad_techniques(strict_windows, parse_gt_windows_broad(broad_md_path))
        reference = build_gt_reference(
            strict_windows=strict_windows,
            technique_to_tactics=technique_defs,
            strict_md_path=Path(strict_md_text),
            broad_md_path=broad_md_path,
            primary_report_name=str(args.source_primary_doc).strip(),
            primary_report_path=str(args.source_primary_path).strip(),
            recommended_gt_offsets=recommended_gt_offsets,
        )
        outputs = save_gt_reference_files(
            reference,
            output_json_path=Path(export_gt_json_text) if export_gt_json_text else None,
            output_markdown_path=Path(export_gt_md_text) if export_gt_md_text else None,
        )
        print(json.dumps(outputs, ensure_ascii=False, indent=2))
        return 0

    if not host:
        parser.error("--host is required unless --build-gt-only is set")
    if not str(args.artifacts_dir).strip():
        parser.error("--artifacts-dir is required unless --build-gt-only is set")

    gt_time_offset_text = str(args.gt_time_offset_minutes).strip()
    gt_time_offset_minutes: int | None = None
    gt_metadata: dict[str, Any] = {}
    if gt_json_text:
        strict_windows, technique_defs, gt_metadata = load_gt_reference(Path(gt_json_text), host_filter=host)
    else:
        if not strict_md_text:
            parser.error("Provide either --gt-json or --strict-md")
        strict_windows, technique_defs = parse_gt_windows_strict(Path(strict_md_text))
        broad_md_path = Path(broad_md_text) if broad_md_text else None
        if broad_md_path is not None and broad_md_path.exists():
            merge_broad_techniques(strict_windows, parse_gt_windows_broad(broad_md_path))
        strict_windows = [item for item in strict_windows if item.host == host]
        reference = build_gt_reference(
            strict_windows=strict_windows,
            technique_to_tactics=technique_defs,
            strict_md_path=Path(strict_md_text),
            broad_md_path=broad_md_path,
            primary_report_name=str(args.source_primary_doc).strip(),
            primary_report_path=str(args.source_primary_path).strip(),
            recommended_gt_offsets=recommended_gt_offsets,
        )
        if export_gt_json_text or export_gt_md_text:
            save_gt_reference_files(
                reference,
                output_json_path=Path(export_gt_json_text) if export_gt_json_text else None,
                output_markdown_path=Path(export_gt_md_text) if export_gt_md_text else None,
            )

    if gt_time_offset_text:
        gt_time_offset_minutes = int(gt_time_offset_text)
    else:
        recommended_offsets = (
            gt_metadata.get("recommended_gt_time_offset_minutes_by_host", {})
            if isinstance(gt_metadata.get("recommended_gt_time_offset_minutes_by_host", {}), dict)
            else {}
        )
        if host in recommended_offsets:
            gt_time_offset_minutes = int(recommended_offsets[host])
    if gt_time_offset_minutes:
        apply_gt_time_offset(strict_windows, minutes=gt_time_offset_minutes)

    artifacts_dir = Path(args.artifacts_dir)
    output_dir = Path(args.output_dir) if str(args.output_dir).strip() else artifacts_dir / "path_reason_eval"
    outputs = run_evaluation(
        artifacts_dir=artifacts_dir,
        strict_windows=strict_windows,
        technique_defs=technique_defs,
        output_dir=output_dir,
        host=host,
        match_top_n=max(1, int(args.match_top_n)),
        pad_minutes=max(0, int(args.pad_minutes)),
        near_miss_minutes=max(0, int(args.near_miss_minutes)),
    )
    print(json.dumps(outputs, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


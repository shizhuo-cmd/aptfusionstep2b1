from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from ..common import load_json
from ..config import FusionConfig
from .holmes_claims import HOLMES_ATTACK_PRIORS, HOLMES_QUERY_TERMS

try:  # pragma: no cover - optional runtime dependency
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover - defensive import
    SentenceTransformer = None  # type: ignore[assignment]


_TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,}")
_BASENAME_PATTERN = re.compile(r"(?:^|[/\\])([A-Za-z0-9_.-]{2,})$")
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_TOKEN_PATTERN = re.compile(r"^\d{1,5}$")
_STOPWORDS = {
    "about",
    "after",
    "against",
    "application",
    "attack",
    "attacker",
    "behavior",
    "between",
    "could",
    "from",
    "host",
    "hosts",
    "into",
    "more",
    "that",
    "their",
    "there",
    "these",
    "this",
    "through",
    "using",
    "with",
    "within",
    "process",
    "processes",
    "event",
    "events",
    "episode",
    "episodes",
}
_COMMAND_LEXEME_HINTS = {
    "bash",
    "sh",
    "python",
    "perl",
    "ruby",
    "php",
    "pwsh",
    "powershell",
    "cmd",
    "cmd.exe",
    "curl",
    "wget",
    "scp",
    "ssh",
    "sftp",
    "nc",
    "netcat",
    "cron",
    "crontab",
    "systemctl",
    "service",
    "at",
    "schtasks",
    "regsvr32",
    "rundll32",
    "mshta",
    "wmic",
    "osascript",
}
_WINDOWS_HINTS = {
    "registry",
    "regsvr32",
    "rundll32",
    "powershell",
    "cmd.exe",
    "schtasks",
    "wmic",
    "mshta",
    "startup folder",
    "wmi",
    "cmstp",
    "mmc",
}
_MAC_HINTS = {
    "applescript",
    "launch agent",
    "launchd",
    "osascript",
    "mach-o",
}
_LINUX_HINTS = {
    "bash",
    "cron",
    "systemd",
    "service",
    "/etc/",
    "linux",
    "unix",
    "shell profile",
}
_ACTION_FAMILY_TERMS = {
    "execution": ("execution", "command", "process", "shell", "interpreter", "script"),
    "network_c2": ("command and control", "remote connection", "network protocol", "beacon", "tunnel"),
    "file_persistence": ("persistence", "startup file", "shell profile", "scheduled task", "service"),
    "recon": ("discovery", "enumeration", "system information", "network service discovery", "file discovery"),
    "credential": ("credential access", "authentication material", "password"),
}
_BEHAVIOR_TYPE_TERMS = {
    "network_service_discovery": ("network service discovery", "port scan", "service scan", "discovery"),
    "short_lived_connection_burst": ("short lived connections", "connection burst", "rapid network connections"),
    "repeated_remote_endpoint_contact": ("command and control", "repeated remote contact", "web protocol"),
    "remote_tool_transfer": ("ingress tool transfer", "downloaded tool", "payload transfer"),
    "suspicious_interpreter_execution": ("command and scripting interpreter", "shell", "interpreter execution"),
    "process_spawning_chain": ("process execution chain", "process creation", "execution"),
    "temporary_file_write_or_delete": ("file deletion", "temporary file", "artifact cleanup"),
    "memory_mapped_file_access": ("memory mapped file", "library load"),
    "persistence_artifact_modification": ("persistence", "startup file", "service", "scheduled task"),
    "privilege_escalation_attempt": ("privilege escalation", "exploitation for privilege escalation"),
    "file_discovery_behavior": ("file and directory discovery", "file discovery"),
    "phishing_or_user_execution": ("spearphishing", "user execution", "malicious file"),
}
_BEHAVIOR_TYPE_TERMS.update(HOLMES_QUERY_TERMS)
_BEHAVIOR_TYPE_ATTACK_PRIORS = {
    "network_service_discovery": {"tactics": {"TA0007"}, "techniques": {"T1046"}},
    "repeated_remote_endpoint_contact": {"tactics": {"TA0011"}, "techniques": {"T1071.001"}},
    "remote_tool_transfer": {"tactics": {"TA0011"}, "techniques": {"T1105"}},
    "suspicious_interpreter_execution": {"tactics": {"TA0002"}, "techniques": {"T1059"}},
    "privilege_escalation_attempt": {"tactics": {"TA0004"}, "techniques": {"T1068"}},
    "temporary_file_write_or_delete": {"tactics": {"TA0005"}, "techniques": {"T1070.004"}},
    "phishing_or_user_execution": {"tactics": {"TA0001", "TA0002"}, "techniques": {"T1566.001", "T1566.002", "T1204.002"}},
}
_BEHAVIOR_TYPE_ATTACK_PRIORS.update(HOLMES_ATTACK_PRIORS)


@dataclass(frozen=True)
class AttackCandidate:
    candidate_id: str
    object_type: str
    name: str
    description: str
    external_id: str
    attack_url: str
    tactics: tuple[str, ...]
    tactic_ids: tuple[str, ...]
    score: float = 0.0
    matched_terms: tuple[str, ...] = ()


@dataclass(frozen=True)
class _QueryContext:
    terms: tuple[str, ...]
    action_families: tuple[str, ...]
    command_lexemes: tuple[str, ...]
    object_semantics: tuple[str, ...]
    os_hint: str
    claim_terms: tuple[str, ...]
    behavior_types: tuple[str, ...]


@dataclass
class _CandidateIndex:
    items: tuple[AttackCandidate, ...]
    texts: tuple[str, ...]
    vectorizer: TfidfVectorizer
    sparse_matrix: Any
    embeddings: np.ndarray | None


def _tokens(text: str) -> set[str]:
    values = set()
    for token in _TOKEN_PATTERN.findall(str(text)):
        lowered = token.lower()
        if lowered in _STOPWORDS:
            continue
        if _PORT_TOKEN_PATTERN.match(lowered):
            continue
        values.add(lowered)
    return values


def _normalize_name(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text).strip().lower()).strip()


def _external_attack_id(obj: Dict[str, Any]) -> str:
    for ref in obj.get("external_references", []) or []:
        if str(ref.get("source_name", "")).lower() == "mitre-attack":
            external_id = str(ref.get("external_id", "")).strip().upper()
            if external_id:
                return external_id
    return ""


def _attack_url(external_id: str) -> str:
    if not external_id:
        return ""
    if external_id.startswith("TA"):
        return f"https://attack.mitre.org/tactics/{external_id}/"
    if "." in external_id:
        parent, child = external_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{child}/"
    return f"https://attack.mitre.org/techniques/{external_id}/"


def _phase_to_tactic_id(name: str) -> str:
    text = str(name).strip().lower()
    mapping = {
        "reconnaissance": "TA0043",
        "resource development": "TA0042",
        "initial access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege escalation": "TA0004",
        "defense evasion": "TA0005",
        "credential access": "TA0006",
        "discovery": "TA0007",
        "lateral movement": "TA0008",
        "collection": "TA0009",
        "command and control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
    }
    return mapping.get(text, "")


def _parse_stix_bundle(path: Path) -> Dict[str, List[AttackCandidate]]:
    payload = load_json(path)
    objects = payload.get("objects", []) if isinstance(payload, dict) else []
    tactics_by_shortname: Dict[str, Dict[str, str]] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if str(obj.get("type", "")) != "x-mitre-tactic":
            continue
        shortname = str(obj.get("x_mitre_shortname", "")).strip().lower()
        external_id = _external_attack_id(obj)
        tactic_name = str(obj.get("name", "")).strip()
        if shortname or external_id or tactic_name:
            tactics_by_shortname[shortname] = {
                "name": tactic_name,
                "id": external_id or _phase_to_tactic_id(shortname),
            }

    techniques: List[AttackCandidate] = []
    tactics: List[AttackCandidate] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        obj_type = str(obj.get("type", ""))
        if obj_type == "attack-pattern":
            external_id = _external_attack_id(obj)
            if not external_id:
                continue
            phases = obj.get("kill_chain_phases", []) or []
            tactic_names: List[str] = []
            tactic_ids: List[str] = []
            for phase in phases:
                phase_name = str(phase.get("phase_name", "")).strip().lower()
                if not phase_name:
                    continue
                tactic_info = tactics_by_shortname.get(phase_name, {})
                tactic_name = tactic_info.get("name", phase_name.title())
                tactic_id = tactic_info.get("id", _phase_to_tactic_id(phase_name))
                if tactic_name and tactic_name not in tactic_names:
                    tactic_names.append(tactic_name)
                if tactic_id and tactic_id not in tactic_ids:
                    tactic_ids.append(tactic_id)
            techniques.append(
                AttackCandidate(
                    candidate_id=str(obj.get("id", external_id)),
                    object_type="technique",
                    name=str(obj.get("name", "")).strip(),
                    description=str(obj.get("description", "")).strip(),
                    external_id=external_id,
                    attack_url=_attack_url(external_id),
                    tactics=tuple(tactic_names),
                    tactic_ids=tuple(tactic_ids),
                )
            )
        elif obj_type == "x-mitre-tactic":
            external_id = _external_attack_id(obj)
            if not external_id:
                continue
            tactics.append(
                AttackCandidate(
                    candidate_id=str(obj.get("id", external_id)),
                    object_type="tactic",
                    name=str(obj.get("name", "")).strip(),
                    description=str(obj.get("description", "")).strip(),
                    external_id=external_id,
                    attack_url=_attack_url(external_id),
                    tactics=(str(obj.get("name", "")).strip(),),
                    tactic_ids=(external_id,),
                )
            )
    return {"techniques": techniques, "tactics": tactics}


@lru_cache(maxsize=4)
def _load_cached_stix(path_text: str) -> Dict[str, List[AttackCandidate]]:
    return _parse_stix_bundle(Path(path_text))


def load_attack_kb(cfg: FusionConfig) -> Dict[str, List[AttackCandidate]]:
    path = cfg.attack_kb_stix_path
    if path is None or not path.exists():
        return {"techniques": [], "tactics": []}
    return _load_cached_stix(str(path))


def _bundle_events(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    core = list(bundle.get("core_events", []))
    if core:
        return core
    filtered = list(bundle.get("filtered_events", []))
    if filtered:
        return filtered
    return list(bundle.get("events", []))


def _bundle_episodes(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    filtered = list(bundle.get("filtered_episodes", []))
    if filtered:
        return filtered
    return list(bundle.get("episodes", []))


def _bundle_ioc_candidates(bundle: Dict[str, Any]) -> Dict[str, Any]:
    filtered = dict(bundle.get("filtered_ioc_candidates", {}))
    if filtered:
        return filtered
    return dict(bundle.get("ioc_candidates", {}))


def _path_semantics(text: str) -> List[str]:
    lower = str(text).strip().lower()
    output: List[str] = []
    if not lower:
        return output
    if any(hint in lower for hint in (".bashrc", ".profile", "/etc/profile", "authorized_keys")):
        output.append("shell profile modification")
    if any(hint in lower for hint in ("/etc/cron", "crontab", "systemd", "service")):
        output.append("scheduled task or service artifact")
    if any(hint in lower for hint in ("/tmp/", "\\temp\\", "/var/tmp/")):
        output.append("temporary executable artifact")
    if any(hint in lower for hint in ("/etc/passwd", "/proc/", "/etc/shadow")):
        output.append("host discovery file")
    return output


def _detect_os_hint(bundle: Dict[str, Any]) -> str:
    blobs: List[str] = []
    for event in _bundle_events(bundle):
        for key in ("description", "subject_attr", "object_attr"):
            value = str(event.get(key, "")).strip().lower()
            if value:
                blobs.append(value)
    joined = "\n".join(blobs)
    if re.search(r"\b[a-z]:\\", joined) or any(term in joined for term in ("powershell", "cmd.exe", "wmic", "regsvr32")):
        return "windows"
    if any(term in joined for term in ("osascript", "launchd", "launch agent", "/users/")):
        return "macos"
    if any(term in joined for term in ("/bin/", "/etc/", "bash", "systemd", "cron")):
        return "linux"
    return "unknown"


def _event_action_families(bundle: Dict[str, Any], claim_texts: Sequence[str]) -> set[str]:
    families: set[str] = set()
    actions = {str(event.get("action", "")).strip().upper() for event in _bundle_events(bundle)}
    if actions & {"CONNECT", "SENDMSG", "SENDTO", "RECVMSG", "RECVFROM"}:
        families.add("network_c2")
    if actions & {"EXECUTE", "CREATE_OBJECT", "LOAD", "MMAP", "CLONE", "FORK"}:
        families.add("execution")
    if actions & {"WRITE", "RENAME", "TRUNCATE", "MODIFY_PROCESS"}:
        families.add("file_persistence")
    blobs = "\n".join(claim_texts + [str(ep.get("description", "")) for ep in _bundle_episodes(bundle)]).lower()
    if any(term in blobs for term in ("discover", "discovery", "enumerat", "whoami", "netstat", "scan", "find ", "ls ")):
        families.add("recon")
    if any(term in blobs for term in ("credential", "password", "token", "secret")):
        families.add("credential")
    if any(term in blobs for term in ("network_service_discovery", "short_lived_connection_burst")):
        families.add("recon")
        families.add("network_c2")
    if any(term in blobs for term in ("remote_tool_transfer", "phishing_or_user_execution")):
        families.add("execution")
    if any(term in blobs for term in ("temporary_file_write_or_delete", "persistence_artifact_modification")):
        families.add("file_persistence")
    return families


def _extract_command_lexemes(bundle: Dict[str, Any], claim_texts: Sequence[str]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for event in _bundle_events(bundle):
        for key in ("subject_attr", "object_attr", "description"):
            text = str(event.get(key, "")).strip()
            if not text:
                continue
            for token in _TOKEN_PATTERN.findall(text):
                lowered = token.lower()
                if lowered in _STOPWORDS or _PORT_TOKEN_PATTERN.match(lowered) or _IPV4_PATTERN.fullmatch(lowered):
                    continue
                match = _BASENAME_PATTERN.search(lowered)
                if match:
                    lowered = match.group(1).lower()
                if lowered in _COMMAND_LEXEME_HINTS or lowered.endswith((".exe", ".sh", ".py", ".pl")):
                    if lowered not in seen:
                        seen.add(lowered)
                        output.append(lowered)
    for text in claim_texts:
        for token in _TOKEN_PATTERN.findall(text):
            lowered = token.lower()
            if lowered in _COMMAND_LEXEME_HINTS and lowered not in seen:
                seen.add(lowered)
                output.append(lowered)
    return output[:24]


def _extract_object_semantics(bundle: Dict[str, Any], claim_texts: Sequence[str]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for event in _bundle_events(bundle):
        for key in ("subject_attr", "object_attr"):
            for semantic in _path_semantics(str(event.get(key, ""))):
                if semantic not in seen:
                    seen.add(semantic)
                    output.append(semantic)
        blob = " ".join(
            str(event.get(key, "")).strip().lower()
            for key in ("description", "subject_attr", "object_attr")
            if str(event.get(key, "")).strip()
        )
        if (_IPV4_PATTERN.search(blob) or "domain" in blob or "remote" in blob) and "remote endpoint" not in seen:
            seen.add("remote endpoint")
            output.append("remote endpoint")
    for text in claim_texts:
        lower = text.lower()
        if "remote connection" in lower and "remote endpoint" not in seen:
            seen.add("remote endpoint")
            output.append("remote endpoint")
        if "file discovery" in lower and "file discovery artifact" not in seen:
            seen.add("file discovery artifact")
            output.append("file discovery artifact")
    return output[:18]


def _claim_terms(claims: Sequence[Dict[str, Any]] | None) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for claim in claims or []:
        statement = str(claim.get("statement", "")).strip()
        if not statement:
            continue
        normalized = " ".join(sorted(_tokens(statement)))
        if normalized and normalized not in seen:
            seen.add(normalized)
            output.append(statement)
    return output[:12]


def _claim_behavior_types(claims: Sequence[Dict[str, Any]] | None) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for claim in claims or []:
        behavior_type = str(claim.get("behavior_type") or claim.get("category") or "").strip().lower()
        if behavior_type and behavior_type not in seen:
            seen.add(behavior_type)
            output.append(behavior_type)
    return output[:12]


def _build_query_context(bundle: Dict[str, Any], claims: Sequence[Dict[str, Any]] | None = None) -> _QueryContext:
    claim_texts = _claim_terms(claims)
    behavior_types = _claim_behavior_types(claims)
    action_families = sorted(_event_action_families(bundle, claim_texts))
    command_lexemes = _extract_command_lexemes(bundle, claim_texts)
    object_semantics = _extract_object_semantics(bundle, claim_texts)
    terms: List[str] = []
    seen: set[str] = set()
    for family in action_families:
        for term in _ACTION_FAMILY_TERMS.get(family, (family.replace("_", " "),)):
            if term not in seen:
                seen.add(term)
                terms.append(term)
    for behavior_type in behavior_types:
        for term in _BEHAVIOR_TYPE_TERMS.get(behavior_type, (behavior_type.replace("_", " "),)):
            lower = term.lower()
            if lower not in seen:
                seen.add(lower)
                terms.append(term)
    for value in command_lexemes + object_semantics + claim_texts:
        lower = value.lower()
        if lower not in seen:
            seen.add(lower)
            terms.append(value)
    return _QueryContext(
        terms=tuple(terms),
        action_families=tuple(action_families),
        command_lexemes=tuple(command_lexemes),
        object_semantics=tuple(object_semantics),
        os_hint=_detect_os_hint(bundle),
        claim_terms=tuple(claim_texts),
        behavior_types=tuple(behavior_types),
    )


def _candidate_text(candidate: AttackCandidate) -> str:
    parts = [candidate.name]
    if candidate.tactics:
        parts.append(" ".join(candidate.tactics))
    if candidate.description:
        parts.append(candidate.description)
    if candidate.external_id:
        parts.append(candidate.external_id)
    return " ".join(parts)


@lru_cache(maxsize=4)
def _load_sentence_transformer(model_name: str):
    if SentenceTransformer is None:
        return None
    try:
        return SentenceTransformer(model_name)
    except Exception:
        return None


def _encode_texts(model_name: str, texts: Sequence[str]) -> np.ndarray | None:
    model = _load_sentence_transformer(model_name)
    if model is None:
        return None
    try:
        embeddings = model.encode(
            list(texts),
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
    except Exception:
        return None
    return np.asarray(embeddings, dtype=np.float32)


def _build_candidate_index(
    items: Sequence[AttackCandidate],
    model_name: str,
    vector_enabled: bool,
) -> _CandidateIndex:
    texts = tuple(_candidate_text(item) for item in items)
    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1)
    sparse_matrix = vectorizer.fit_transform(texts or ["empty"])
    embeddings = None
    if vector_enabled and texts:
        embeddings = _encode_texts(model_name, texts)
    return _CandidateIndex(
        items=tuple(items),
        texts=texts,
        vectorizer=vectorizer,
        sparse_matrix=sparse_matrix,
        embeddings=embeddings,
    )


@lru_cache(maxsize=4)
def _load_retrieval_index(path_text: str, model_name: str, vector_enabled: bool) -> Dict[str, Any]:
    kb = _load_cached_stix(path_text)
    technique_index = _build_candidate_index(kb.get("techniques", []), model_name, vector_enabled)
    tactic_index = _build_candidate_index(kb.get("tactics", []), model_name, vector_enabled)
    tactic_name_map = {_normalize_name(item.name): item for item in kb.get("tactics", [])}
    technique_name_map = {_normalize_name(item.name): item for item in kb.get("techniques", [])}
    id_map = {item.external_id: item for item in kb.get("tactics", [])}
    id_map.update({item.external_id: item for item in kb.get("techniques", [])})
    return {
        "techniques": kb.get("techniques", []),
        "tactics": kb.get("tactics", []),
        "technique_index": technique_index,
        "tactic_index": tactic_index,
        "tactic_name_map": tactic_name_map,
        "technique_name_map": technique_name_map,
        "id_map": id_map,
    }


def _retrieval_index(cfg: FusionConfig) -> Dict[str, Any]:
    path = cfg.attack_kb_stix_path
    if path is None or not path.exists():
        return {
            "techniques": [],
            "tactics": [],
            "technique_index": _build_candidate_index([], cfg.attack_kb_embedding_model_name, False),
            "tactic_index": _build_candidate_index([], cfg.attack_kb_embedding_model_name, False),
            "tactic_name_map": {},
            "technique_name_map": {},
            "id_map": {},
        }
    return _load_retrieval_index(str(path), cfg.attack_kb_embedding_model_name, bool(cfg.attack_kb_enable_vector))


def _dense_query_embedding(cfg: FusionConfig, query_text: str) -> np.ndarray | None:
    if not cfg.attack_kb_enable_vector or not query_text.strip():
        return None
    embeddings = _encode_texts(cfg.attack_kb_embedding_model_name, [query_text])
    if embeddings is None or len(embeddings) == 0:
        return None
    return embeddings[0]


def _compatibility_bonus(candidate: AttackCandidate, query: _QueryContext) -> float:
    score = 0.0
    text = f"{candidate.name} {candidate.description} {' '.join(candidate.tactics)} {' '.join(candidate.tactic_ids)}".lower()
    for family in query.action_families:
        if family == "network_c2" and any(term in text for term in ("command and control", "remote", "connection", "network", "protocol", "tunnel", "service")):
            score += 0.28
        elif family == "execution" and any(term in text for term in ("execution", "script", "interpreter", "process", "shell", "command")):
            score += 0.26
        elif family == "file_persistence" and any(term in text for term in ("persistence", "startup", "profile", "service", "scheduled task", "cron", "systemd")):
            score += 0.28
        elif family == "recon" and any(term in text for term in ("discovery", "enumeration", "scan", "system information", "network service", "file and directory")):
            score += 0.28
        elif family == "credential" and any(term in text for term in ("credential", "password", "token", "authentication")):
            score += 0.28

    for semantic in query.object_semantics:
        semantic_tokens = _tokens(semantic)
        if semantic_tokens and semantic_tokens & _tokens(text):
            score += 0.10

    os_hint = query.os_hint
    if os_hint == "linux":
        if any(term in text for term in _WINDOWS_HINTS | _MAC_HINTS):
            score -= 0.45
        if any(term in text for term in _LINUX_HINTS):
            score += 0.14
    elif os_hint == "windows":
        if any(term in text for term in _LINUX_HINTS | _MAC_HINTS):
            score -= 0.35
        if any(term in text for term in _WINDOWS_HINTS):
            score += 0.14
    elif os_hint == "macos":
        if any(term in text for term in _WINDOWS_HINTS | _LINUX_HINTS):
            score -= 0.35
        if any(term in text for term in _MAC_HINTS):
            score += 0.14

    if query.claim_terms:
        claim_token_overlap = sum(1 for claim_text in query.claim_terms if _tokens(claim_text) & _tokens(text))
        score += min(0.30, cfg_claim_overlap_bonus(claim_token_overlap))
    for behavior_type in query.behavior_types:
        priors = _BEHAVIOR_TYPE_ATTACK_PRIORS.get(behavior_type, {})
        if candidate.external_id in set(priors.get("techniques", ())):
            score += 0.75
        if candidate.external_id in set(priors.get("tactics", ())):
            score += 0.45
    return score


def cfg_claim_overlap_bonus(count: int) -> float:
    return 0.08 * max(0, count)


def _prior_attack_ids(query: _QueryContext, object_type: str) -> set[str]:
    output: set[str] = set()
    key = "techniques" if object_type == "technique" else "tactics"
    for behavior_type in query.behavior_types:
        priors = _BEHAVIOR_TYPE_ATTACK_PRIORS.get(behavior_type, {})
        output.update({str(item).strip().upper() for item in priors.get(key, ()) if str(item).strip()})
    return output


def _rank_index(
    index: _CandidateIndex,
    query: _QueryContext,
    cfg: FusionConfig,
    top_k: int,
) -> List[AttackCandidate]:
    if not index.items:
        return []
    query_text = " ".join(query.terms).strip()
    if not query_text:
        return []

    sparse_query = index.vectorizer.transform([query_text])
    sparse_scores = (index.sparse_matrix @ sparse_query.T).toarray().ravel()
    sparse_max = float(np.max(sparse_scores)) if sparse_scores.size else 0.0

    dense_scores = np.zeros(len(index.items), dtype=np.float32)
    dense_query = _dense_query_embedding(cfg, query_text)
    if dense_query is not None and index.embeddings is not None and len(index.embeddings) == len(index.items):
        dense_scores = np.asarray(index.embeddings @ dense_query, dtype=np.float32)
    dense_max = float(np.max(dense_scores)) if dense_scores.size else 0.0

    sparse_rank = np.argsort(-sparse_scores)[: max(int(cfg.attack_kb_sparse_top_k), top_k)]
    dense_rank = np.argsort(-dense_scores)[: max(int(cfg.attack_kb_vector_top_k), top_k)] if dense_scores.size else np.array([], dtype=int)
    candidate_indices = list(dict.fromkeys([int(i) for i in sparse_rank.tolist() + dense_rank.tolist()]))
    prior_ids = _prior_attack_ids(query, index.items[0].object_type if index.items else "")
    if prior_ids:
        for idx, item in enumerate(index.items):
            if item.external_id in prior_ids and idx not in candidate_indices:
                candidate_indices.append(idx)

    scored: List[AttackCandidate] = []
    for idx in candidate_indices:
        sparse_score = float(sparse_scores[idx]) / sparse_max if sparse_max > 0 else 0.0
        dense_score = float(dense_scores[idx]) / dense_max if dense_max > 0 else 0.0
        bonus = _compatibility_bonus(index.items[idx], query)
        total = (
            float(cfg.attack_kb_sparse_weight) * sparse_score
            + float(cfg.attack_kb_vector_weight) * dense_score
            + bonus
        )
        if total <= 0:
            continue
        matched_terms = sorted(_tokens(query_text) & _candidate_terms(index.items[idx]))
        scored.append(
            AttackCandidate(
                candidate_id=index.items[idx].candidate_id,
                object_type=index.items[idx].object_type,
                name=index.items[idx].name,
                description=index.items[idx].description,
                external_id=index.items[idx].external_id,
                attack_url=index.items[idx].attack_url,
                tactics=index.items[idx].tactics,
                tactic_ids=index.items[idx].tactic_ids,
                score=round(total, 5),
                matched_terms=tuple(matched_terms[:12]),
            )
        )
    scored.sort(key=lambda item: (-item.score, item.external_id, item.name))
    return scored[:top_k]


def _candidate_terms(candidate: AttackCandidate) -> set[str]:
    terms = set()
    terms.update(_tokens(candidate.name))
    terms.update(_tokens(candidate.description))
    terms.update(_tokens(" ".join(candidate.tactics)))
    terms.update(_tokens(" ".join(candidate.tactic_ids)))
    terms.update(_tokens(candidate.external_id))
    return terms


def _candidate_to_dict(item: AttackCandidate) -> Dict[str, Any]:
    return {
        "external_id": item.external_id,
        "name": item.name,
        "description": item.description,
        "attack_url": item.attack_url,
        "tactics": list(item.tactics),
        "tactic_ids": list(item.tactic_ids),
        "score": item.score,
        "matched_terms": list(item.matched_terms),
        "object_type": item.object_type,
    }


def retrieve_attack_candidates(
    cfg: FusionConfig,
    bundle: Dict[str, Any],
    claims: Sequence[Dict[str, Any]] | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    index = _retrieval_index(cfg)
    query = _build_query_context(bundle, claims)
    candidate_limit = max(1, int(cfg.attack_kb_candidate_limit))
    techniques = _rank_index(index["technique_index"], query, cfg, candidate_limit)
    tactics = _rank_index(index["tactic_index"], query, cfg, max(5, min(candidate_limit, 8)))
    return {
        "techniques": [_candidate_to_dict(item) for item in techniques],
        "tactics": [_candidate_to_dict(item) for item in tactics],
        "query_terms": list(query.terms),
        "query_context": {
            "action_families": list(query.action_families),
            "command_lexemes": list(query.command_lexemes),
            "object_semantics": list(query.object_semantics),
            "os_hint": query.os_hint,
            "claim_terms": list(query.claim_terms),
            "behavior_types": list(query.behavior_types),
        },
        "kb_available": bool(index["techniques"] or index["tactics"]),
    }


def known_attack_ids(cfg: FusionConfig) -> set[str]:
    index = _retrieval_index(cfg)
    ids = {item.external_id for item in index.get("techniques", [])}
    ids.update({item.external_id for item in index.get("tactics", [])})
    return {item for item in ids if item}


def resolve_tactic_name(cfg: FusionConfig, tactic_name: str) -> AttackCandidate | None:
    if not tactic_name.strip():
        return None
    return _retrieval_index(cfg).get("tactic_name_map", {}).get(_normalize_name(tactic_name))


def resolve_technique_name(cfg: FusionConfig, technique_name: str) -> AttackCandidate | None:
    if not technique_name.strip():
        return None
    return _retrieval_index(cfg).get("technique_name_map", {}).get(_normalize_name(technique_name))


def technique_supports_tactic(technique: AttackCandidate, tactic: AttackCandidate) -> bool:
    if not technique or not tactic:
        return False
    if tactic.external_id and tactic.external_id in technique.tactic_ids:
        return True
    normalized_tactics = {_normalize_name(name) for name in technique.tactics}
    return _normalize_name(tactic.name) in normalized_tactics


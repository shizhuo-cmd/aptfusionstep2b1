from __future__ import annotations

import json
from typing import Any, Dict
from urllib import error, request

from ..config import FusionConfig


def _resolve_ollama_base_url(cfg: FusionConfig) -> str:
    base_url = str(cfg.llm_ollama_base_url).strip() or "http://127.0.0.1:11434"
    return base_url.rstrip("/")


def _ollama_timeout_seconds(cfg: FusionConfig, *, timeout_override: int | None = None) -> int:
    return max(60, int(timeout_override if timeout_override is not None else cfg.llm_request_timeout_sec))


def _ollama_request_body(
    cfg: FusionConfig,
    *,
    system_prompt: str,
    user_prompt: str,
) -> Dict[str, Any]:
    return {
        "model": cfg.llm_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "format": "json",
        "stream": False,
        "options": {"temperature": 0},
    }


def _llm_input_record(
    cfg: FusionConfig,
    *,
    stage: str,
    system_prompt: str,
    user_prompt: str,
    timeout_override: int | None = None,
    context: Dict[str, Any] | None = None,
    response: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    timeout_sec = _ollama_timeout_seconds(cfg, timeout_override=timeout_override)
    record: Dict[str, Any] = {
        "stage": stage,
        "model_source": cfg.llm_model_source,
        "model": cfg.llm_model,
        "base_url": _resolve_ollama_base_url(cfg),
        "timeout_sec": timeout_sec,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "request_body": _ollama_request_body(
            cfg,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        ),
    }
    if context is not None:
        record["context"] = context
    if response is not None:
        record["response"] = response
    return record


def _call_ollama_json(
    cfg: FusionConfig,
    system_prompt: str,
    user_prompt: str,
    *,
    timeout_override: int | None = None,
) -> Dict[str, Any]:
    if cfg.llm_model_source != "ollama":
        raise ValueError("path_reason reasoning currently supports llm_model_source='ollama' only.")
    body = _ollama_request_body(
        cfg,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
    )
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = request.Request(
        f"{_resolve_ollama_base_url(cfg)}/api/chat",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    timeout = _ollama_timeout_seconds(cfg, timeout_override=timeout_override)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Ollama HTTP error {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Unable to reach Ollama at {_resolve_ollama_base_url(cfg)}") from exc

    content = payload.get("message", {}).get("content") if isinstance(payload, dict) else None
    if not content:
        raise RuntimeError("Ollama returned an empty reasoning response")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Ollama returned non-JSON reasoning output: {content[:500]}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Ollama reasoning output must be a JSON object")
    return parsed

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Iterable, Iterator


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def ensure_parent(path: Path) -> None:
    ensure_dir(path.parent)


def save_json(path: Path, data: Any) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_jsonl(path: Path, rows: Iterable[Any]) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def iter_jsonl(path: Path) -> Iterator[Any]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            yield json.loads(text)


def load_jsonl(path: Path) -> list[Any]:
    return list(iter_jsonl(path))


def normalize_ocr_root(path: Path) -> str:
    """Some legacy external scripts expect a trailing slash in the runtime root."""
    raw = str(path).replace("\\", "/")
    return raw if raw.endswith("/") else raw + "/"


def run_command(cmd: Iterable[str], cwd: Path) -> None:
    process = subprocess.run(
        list(cmd),
        cwd=str(cwd),
        check=False,
        text=True,
        capture_output=True,
    )
    if process.stdout:
        print(process.stdout)
    if process.stderr:
        print(process.stderr)
    if process.returncode != 0:
        raise RuntimeError(f"Command failed ({process.returncode}): {' '.join(cmd)}")

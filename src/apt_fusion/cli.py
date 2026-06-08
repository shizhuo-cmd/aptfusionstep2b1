from __future__ import annotations

import argparse
import json

from .config import load_config
from .pipeline import run_pipeline

_ACTIVE_STAGES = [
    "module0",
    "module1",
    "module2",
    "module3_evidence",
    "module4_compact",
    "module5_paths",
    "module6_reason",
    "full_path_reason",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="APT-Fusion runner")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser(
        "run",
        help="Run the active task-detection and path-reason pipeline.",
    )
    run_parser.add_argument("--config", required=True, help="Path to YAML config")
    run_parser.add_argument(
        "--stage",
        default="full_path_reason",
        choices=_ACTIVE_STAGES,
        help="Pipeline stage to run. Recommended: full_path_reason.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "run":
        cfg = load_config(args.config)
        outputs = run_pipeline(cfg, args.stage)
        print(json.dumps(outputs, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
from pathlib import Path

from apt_fusion.task_detection.provgrp_paper_partition import _children_map, _collect_root_dependencies, _read_cdm18_metadata
from run_cadets_provgrp_paper_partition import _load_components


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-module1", required=True)
    parser.add_argument("--source-logs", required=True)
    parser.add_argument("--min-direct-children", type=int, default=10)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    components = _load_components(Path(args.baseline_module1))
    roots = {str(component["task_root"]) for component in components if len(_children_map(component).get(str(component["task_root"]), [])) > args.min_direct_children}
    owners, descriptors, object_names = _read_cdm18_metadata(args.source_logs)
    dependencies, stats, _ = _collect_root_dependencies(args.source_logs, roots, owners, descriptors, object_names)
    stats.update({"eligible_root_count": len(roots), "included_incoming_dependency_count": sum(len(value["in"]) for value in dependencies.values()), "included_outgoing_dependency_count": sum(len(value["out"]) for value in dependencies.values())})
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()

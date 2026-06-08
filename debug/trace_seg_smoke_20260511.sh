#!/usr/bin/env bash
set -euo pipefail
kill 9620 >/dev/null 2>&1 || true
mkdir -p /root/autodl-tmp/data/trace_train/logs_smoke_20260511
FIRST_LOG=$(find /root/autodl-tmp/data/trace_train/logs -maxdepth 1 -type f | sort | head -n 1)
test -n "${FIRST_LOG}"
head -n 200000 "${FIRST_LOG}" > /root/autodl-tmp/data/trace_train/logs_smoke_20260511/$(basename "${FIRST_LOG}")
rm -rf /root/autodl-tmp/APT-Fusion/artifacts_trace_train_seg_smoke_20260511
cd /root/autodl-tmp/APT-Fusion
source /root/miniconda3/etc/profile.d/conda.sh
conda activate fusion
python -m py_compile /root/autodl-tmp/APT-Fusion/vendor/tapas/darpa.py /root/autodl-tmp/APT-Fusion/src/apt_fusion/tapas_native_backend.py
python -m apt_fusion.cli run --config ./configs/trace_seg_smoke_20260511.yaml --stage module1
python - <<'PY'
import json
from collections import defaultdict
from pathlib import Path
root = Path('/root/autodl-tmp/APT-Fusion/artifacts_trace_train_seg_smoke_20260511/module1')
summary = json.loads((root / 'tapas_native_module1_summary.json').read_text())
subgraphs = json.loads((root / 'task_subgraphs.json').read_text())
proc_to_tasks = defaultdict(list)
for row in subgraphs:
    for pid in row.get('process_ids', []):
        proc_to_tasks[str(pid)].append(row['task_id'])
shared = {pid: tasks for pid, tasks in proc_to_tasks.items() if len(tasks) > 1}
print(json.dumps({
    'summary': summary,
    'task_count': len(subgraphs),
    'shared_process_count': len(shared),
    'shared_process_examples': dict(list(shared.items())[:10]),
}, ensure_ascii=False))
PY

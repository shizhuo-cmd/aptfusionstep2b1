from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class TaskSubgraph:
    task_id: str
    process_ids: List[str]


@dataclass
class ProcessScore:
    process_id: str
    score: float
    probability: float


@dataclass
class Module1Output:
    embeddings: Dict[str, List[float]]
    feature_names: List[str]
    task_subgraphs: List[TaskSubgraph]


@dataclass
class Module2Output:
    suspicious_tasks: List[TaskSubgraph]
    process_scores: Dict[str, ProcessScore]
    threshold: float


from __future__ import annotations

import unittest

from apt_fusion.path_reason.module5_path_finder import (
    _inherit_parent_split_labels,
    _parent_task_map,
)
from apt_fusion.path_reason.path_schemas import ProcessState, TaskPrior


class Module5SplitInheritanceTests(unittest.TestCase):
    def test_parent_task_map_links_boundary_root_to_child(self) -> None:
        priors = {
            "task_parent": TaskPrior(
                task_id="task_parent",
                task_score=0.9,
                task_probability=0.9,
                boundary_node_ids=["split_p"],
            ),
            "task_child": TaskPrior(
                task_id="task_child",
                task_score=0.8,
                task_probability=0.8,
                task_root_id="split_p",
            ),
        }
        parent_by_task = _parent_task_map({"task_parent", "task_child"}, priors)
        self.assertEqual(parent_by_task, {"task_child": "task_parent"})

    def test_split_root_inherits_parent_labels(self) -> None:
        priors = {
            "task_child": TaskPrior(
                task_id="task_child",
                task_score=0.8,
                task_probability=0.8,
                task_root_id="split_p",
            )
        }
        parent_states = {
            "split_p": ProcessState(
                task_id="task_parent",
                process_guid="split_p",
                process_name="bash",
                process_exe="/bin/bash",
                process_cmdline="/bin/bash /tmp/a.sh",
                start_time=None,
                end_time=None,
                status_labels={"P_UNTRUSTED_CTX"},
                behavior_labels={"execution_chain"},
                aggregate_labels={"A_BRIDGED_BY_SUSPICIOUS_OBJECT"},
                important_objects={"/tmp/a.sh"},
                prior_score=0.77,
                score=0.66,
            )
        }
        child_states = {
            "split_p": ProcessState(
                task_id="task_child",
                process_guid="split_p",
                process_name="bash",
                process_exe=None,
                process_cmdline=None,
                start_time=None,
                end_time=None,
            )
        }
        _inherit_parent_split_labels("task_child", child_states, priors, parent_states)
        child = child_states["split_p"]
        self.assertIn("P_UNTRUSTED_CTX", child.status_labels)
        self.assertIn("execution_chain", child.behavior_labels)
        self.assertIn("A_BRIDGED_BY_SUSPICIOUS_OBJECT", child.aggregate_labels)
        self.assertIn("/tmp/a.sh", child.important_objects)
        self.assertEqual(child.process_exe, "/bin/bash")
        self.assertEqual(child.process_cmdline, "/bin/bash /tmp/a.sh")
        self.assertGreaterEqual(child.prior_score, 0.77)
        self.assertGreaterEqual(child.score, 0.66)


if __name__ == "__main__":
    unittest.main()

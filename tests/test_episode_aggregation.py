from __future__ import annotations

import unittest

from apt_fusion.path_reason.episode_aggregation import aggregate_episodes


class EpisodeAggregationTests(unittest.TestCase):
    def test_epoch_change_splits_episode(self) -> None:
        episodes = aggregate_episodes(
            "task_1",
            [
                {
                    "event_id": "e1",
                    "raw_log_id": "raw1",
                    "timestamp": "2026-05-25T10:00:01",
                    "process_guid": "p1",
                    "event_type": "READ",
                    "object_type": "file",
                    "object_class": "file",
                    "object_key": "/tmp/a",
                    "semantic_flow_direction": "O_TO_P",
                    "process_label_signature": "",
                    "object_label_signature": "",
                    "object_semantic_epoch": 0,
                    "process_control_epoch": 0,
                    "labels_triggered": [],
                    "description": "first",
                },
                {
                    "event_id": "e2",
                    "raw_log_id": "raw2",
                    "timestamp": "2026-05-25T10:00:20",
                    "process_guid": "p1",
                    "event_type": "READ",
                    "object_type": "file",
                    "object_class": "file",
                    "object_key": "/tmp/a",
                    "semantic_flow_direction": "O_TO_P",
                    "process_label_signature": "",
                    "object_label_signature": "",
                    "object_semantic_epoch": 1,
                    "process_control_epoch": 0,
                    "labels_triggered": [],
                    "description": "second",
                },
            ],
            bucket_minutes=1,
            max_representative_events=5,
        )
        self.assertEqual(len(episodes), 2)


if __name__ == "__main__":
    unittest.main()


from types import SimpleNamespace

from apt_fusion.task_detection.ocr_stat_features import extract_process_stat_features_from_tc3_action_counts


def _config() -> SimpleNamespace:
    return SimpleNamespace(host="cadets", ocr_stat_active_threshold_sec=1.0)


def test_core_and_extended_event_statistics_have_fixed_schema_and_different_coverage() -> None:
    action_counts = {
        "proc_a": {
            "EVENT_EXECUTE": 2,
            "EVENT_READ": 5,
            "EVENT_UNLINK": 3,
            "EVENT_CHANGE_PRINCIPAL": 1,
        }
    }

    core = extract_process_stat_features_from_tc3_action_counts(
        _config(), {"proc_a"}, action_counts, "core"
    )
    extended = extract_process_stat_features_from_tc3_action_counts(
        _config(), {"proc_a"}, action_counts, "extended"
    )

    assert core.columns.tolist() == extended.columns.tolist()
    assert float(core.loc[0, "stat_out_unlink"]) == 0.0
    assert float(extended.loc[0, "stat_out_unlink"]) > 0.0
    assert float(core.loc[0, "stat_out_execute"]) > 0.0


def test_security_semantic_statistics_keep_security_actions_and_drop_catch_all_noise() -> None:
    action_counts = {
        "proc_a": {
            "EVENT_EXECUTE": 2,
            "EVENT_UNLINK": 3,
            "EVENT_CHANGE_PRINCIPAL": 1,
            "EVENT_OTHER": 1000,
        }
    }

    semantic = extract_process_stat_features_from_tc3_action_counts(
        _config(), {"proc_a"}, action_counts, "security_semantic"
    )

    assert "sem_file_mutation" in semantic.columns
    assert "sem_privilege" in semantic.columns
    assert "stat_out_other" not in semantic.columns
    assert float(semantic.loc[0, "sem_file_mutation"]) > 0.0
    assert float(semantic.loc[0, "sem_privilege"]) > 0.0
    assert float(semantic.loc[0, "sem_log_total_events"]) > float(semantic.loc[0, "sem_log_security_events"])

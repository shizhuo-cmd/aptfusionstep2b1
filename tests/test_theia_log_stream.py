from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from apt_fusion.path_reason.log_stream import _NodeAttr, _extract_darpa_node_records


def test_extract_darpa_node_records_prefers_theia_baseobject_filename() -> None:
    obj = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                "uuid": "FILE-1",
                "baseObject": {
                    "properties": {
                        "map": {
                            "filename": "/home/user/.mozilla/firefox/profiles.ini",
                        }
                    }
                },
            }
        }
    }

    records = _extract_darpa_node_records(obj)

    assert records == [("FILE-1", _NodeAttr(node_type="file", node_attr="/home/user/.mozilla/firefox/profiles.ini"))]


def test_extract_darpa_node_records_keeps_legacy_file_path_priority() -> None:
    obj = {
        "datum": {
            "com.bbn.tc.schema.avro.cdm18.FileObject": {
                "uuid": "FILE-2",
                "path": "/tmp/direct-path.bin",
                "baseObject": {
                    "properties": {
                        "map": {
                            "filename": "/tmp/fallback.bin",
                        }
                    }
                },
            }
        }
    }

    records = _extract_darpa_node_records(obj)

    assert records == [("FILE-2", _NodeAttr(node_type="file", node_attr="/tmp/direct-path.bin"))]
